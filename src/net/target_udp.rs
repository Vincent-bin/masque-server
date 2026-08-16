//! Batched datagram I/O for the per-tunnel target sockets.
//!
//! Relaying one datagram used to cost one `recvfrom` and one `sendto`, which
//! made the target sockets — not the QUIC listener — the largest syscall
//! consumer under load. These helpers move both directions to `recvmmsg`/
//! `sendmmsg` so a burst costs one syscall instead of one per datagram.
//!
//! The sockets are connected, so no address is carried per message.

/// Datagrams moved per syscall in either direction.
pub const TARGET_BATCH_SIZE: usize = 16;

/// Reusable storage for one batched read from a target socket.
pub struct TargetRecvBatch {
    buffers: Vec<Vec<u8>>,
    lengths: Vec<usize>,
    max_datagram_size: usize,
    #[cfg(target_os = "linux")]
    truncated: Vec<bool>,
}

impl TargetRecvBatch {
    /// Allocate one batch using the server's maximum QUIC datagram size.
    ///
    /// Matching the configured transport limit means every response that can
    /// fit on the client path can be received intact. One extra sentinel byte
    /// makes oversized datagrams detectable even where the portable `recv` API
    /// does not expose `MSG_TRUNC`.
    pub fn new(max_datagram_size: usize) -> Self {
        let max_datagram_size = max_datagram_size.max(1);
        let buffer_size = max_datagram_size.saturating_add(1);
        Self {
            buffers: vec![vec![0; buffer_size]; TARGET_BATCH_SIZE],
            lengths: vec![0; TARGET_BATCH_SIZE],
            max_datagram_size,
            #[cfg(target_os = "linux")]
            truncated: vec![false; TARGET_BATCH_SIZE],
        }
    }

    /// The datagrams from the last read, oversized ones already dropped.
    pub fn datagrams(&self, count: usize) -> impl Iterator<Item = &[u8]> {
        let count = count.min(TARGET_BATCH_SIZE);
        (0..count)
            .filter(move |index| self.is_deliverable(*index))
            .map(move |index| &self.buffers[index][..self.lengths[index]])
    }

    /// Whether this slot can be forwarded to the client.
    ///
    /// A response above the configured QUIC transport limit cannot reach the
    /// client intact. Drop both responses detected by the sentinel byte and
    /// responses the Linux kernel explicitly marked as truncated.
    fn is_deliverable(&self, index: usize) -> bool {
        if self.lengths[index] > self.max_datagram_size {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            !self.truncated[index]
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = index;
            true
        }
    }

    /// First buffer, for the portable single-datagram path.
    #[cfg(any(not(target_os = "linux"), test))]
    pub fn first_mut(&mut self) -> &mut [u8] {
        &mut self.buffers[0]
    }

    #[cfg(any(not(target_os = "linux"), test))]
    pub fn set_single(&mut self, len: usize) {
        self.lengths[0] = len;
        #[cfg(target_os = "linux")]
        {
            self.truncated[0] = false;
        }
    }
}

/// Read up to a batch of datagrams from a connected socket in one syscall.
///
/// # Safety
///
/// `fd` must be a live, connected, nonblocking UDP socket.
#[cfg(target_os = "linux")]
pub unsafe fn recv_mmsg(
    fd: std::os::fd::RawFd,
    batch: &mut TargetRecvBatch,
) -> std::io::Result<usize> {
    use std::os::raw::c_void;

    // Rebuilt per call because these hold raw pointers into `batch`.
    // SAFETY: Zero is a valid initial representation for these C I/O structs.
    let mut iovecs: [libc::iovec; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };
    // SAFETY: See above; every submitted header is filled in below.
    let mut headers: [libc::mmsghdr; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for index in 0..TARGET_BATCH_SIZE {
        batch.lengths[index] = 0;
        batch.truncated[index] = false;
        iovecs[index] = libc::iovec {
            iov_base: batch.buffers[index].as_mut_ptr().cast::<c_void>(),
            iov_len: batch.buffers[index].len(),
        };
        let header = &mut headers[index].msg_hdr;
        header.msg_iov = &mut iovecs[index];
        header.msg_iovlen = 1;
        header.msg_flags = 0;
    }

    // SAFETY: Every header points at live storage above for the duration of
    // this nonblocking call. `recvmmsg` is a real syscall in musl, but this
    // goes direct for the same reason the send side does.
    let result = unsafe {
        libc::syscall(
            libc::SYS_recvmmsg,
            fd as libc::c_long,
            headers.as_mut_ptr() as usize as libc::c_long,
            TARGET_BATCH_SIZE as libc::c_long,
            libc::MSG_DONTWAIT as libc::c_long,
            0_i64,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let received = (result as usize).min(TARGET_BATCH_SIZE);
    for (index, header) in headers.iter().take(received).enumerate() {
        batch.lengths[index] = (header.msg_len as usize).min(batch.buffers[index].len());
        batch.truncated[index] = header.msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
    }
    Ok(received)
}

/// Send a batch of datagrams on a connected socket in one syscall.
///
/// Returns how many were accepted; the caller re-queues or drops the rest.
///
/// # Safety
///
/// `fd` must be a live, connected, nonblocking UDP socket.
#[cfg(target_os = "linux")]
pub unsafe fn send_mmsg(fd: std::os::fd::RawFd, payloads: &[Vec<u8>]) -> std::io::Result<usize> {
    use std::os::raw::c_void;

    let count = payloads.len().min(TARGET_BATCH_SIZE);
    if count == 0 {
        return Ok(0);
    }

    // SAFETY: Zero is a valid initial representation for these C I/O structs.
    let mut iovecs: [libc::iovec; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };
    // SAFETY: See above.
    let mut headers: [libc::mmsghdr; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for (index, payload) in payloads.iter().take(count).enumerate() {
        iovecs[index] = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast::<c_void>(),
            iov_len: payload.len(),
        };
        let header = &mut headers[index].msg_hdr;
        // Connected socket, so the destination is implicit.
        header.msg_iov = &mut iovecs[index];
        header.msg_iovlen = 1;
        header.msg_flags = 0;
    }

    // SAFETY: Every header points at live storage above for the duration of
    // this nonblocking call. Issued as a raw syscall because musl's `sendmmsg`
    // wrapper degrades into a loop of `sendmsg`.
    let result = unsafe {
        libc::syscall(
            libc::SYS_sendmmsg,
            fd as libc::c_long,
            headers.as_mut_ptr() as usize as libc::c_long,
            count as libc::c_long,
            libc::MSG_DONTWAIT as libc::c_long,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_batch_reports_only_received_datagrams() {
        let mut batch = TargetRecvBatch::new(3);
        batch.first_mut()[..3].copy_from_slice(b"abc");
        batch.set_single(3);

        let collected: Vec<&[u8]> = batch.datagrams(1).collect();
        assert_eq!(collected, [b"abc".as_slice()]);
    }

    #[test]
    fn recv_batch_count_is_clamped_to_capacity() {
        let batch = TargetRecvBatch::new(64);
        assert_eq!(batch.datagrams(usize::MAX).count(), TARGET_BATCH_SIZE);
    }

    #[test]
    fn recv_batch_uses_the_configured_datagram_size() {
        let mut batch = TargetRecvBatch::new(9_000);
        assert_eq!(batch.first_mut().len(), 9_001);

        let mut minimum = TargetRecvBatch::new(0);
        assert_eq!(minimum.first_mut().len(), 2);
    }

    #[test]
    fn oversized_datagram_is_dropped_without_a_truncation_flag() {
        let mut batch = TargetRecvBatch::new(3);
        batch.first_mut().copy_from_slice(b"abcd");
        batch.set_single(4);

        assert_eq!(batch.datagrams(1).count(), 0);
    }

    /// A response too large for a QUIC DATAGRAM cannot reach the client, and
    /// forwarding the truncated prefix would corrupt it.
    #[cfg(target_os = "linux")]
    #[test]
    fn truncated_datagrams_are_dropped() {
        let mut batch = TargetRecvBatch::new(2_048);
        batch.set_single(2_048);
        batch.truncated[0] = true;
        assert_eq!(batch.datagrams(1).count(), 0);
    }
}
