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

#[cfg(target_os = "linux")]
const UDP_MAX_GSO_PAYLOAD: usize = 65_507;

/// `sendmmsg` already amortizes the syscall for small datagrams. Below this
/// size, building a UDP_SEGMENT message costs more than the kernel work it
/// saves on the Linux loopback path used by the benchmark suite.
#[cfg(target_os = "linux")]
const UDP_MIN_GSO_SEGMENT_SIZE: usize = 512;

#[cfg(target_os = "linux")]
const CONTROL_WORDS: usize = 4;

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct ControlBuffer {
    words: [usize; CONTROL_WORDS],
}

#[cfg(target_os = "linux")]
impl ControlBuffer {
    fn set_udp_segment(&mut self, segment_size: u16) -> usize {
        self.words.fill(0);

        // SAFETY: ControlBuffer is suitably aligned and large enough for one
        // cmsghdr plus a u16 payload, as asserted by the test below.
        unsafe {
            let header = self.words.as_mut_ptr().cast::<libc::cmsghdr>();
            (*header).cmsg_level = libc::IPPROTO_UDP;
            (*header).cmsg_type = libc::UDP_SEGMENT;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as _) as _;
            libc::CMSG_DATA(header).cast::<u16>().write(segment_size);

            libc::CMSG_SPACE(std::mem::size_of::<u16>() as _) as usize
        }
    }
}

/// One kernel message in a target-side UDP send batch.
///
/// With GSO, several payload vectors become scatter/gather segments of one
/// UDP super-packet. The kernel splits their concatenated contents back into
/// datagrams without a userspace copy.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SendGroup {
    first: usize,
    segments: usize,
    segment_size: usize,
}

#[cfg(target_os = "linux")]
fn plan_send(payloads: &[Vec<u8>], enable_gso: bool) -> ([SendGroup; TARGET_BATCH_SIZE], usize) {
    let mut groups = [SendGroup::default(); TARGET_BATCH_SIZE];
    let count = payloads.len().min(TARGET_BATCH_SIZE);
    let mut group_count = 0;
    let mut first = 0;

    while first < count {
        let segment_size = payloads[first].len();
        let mut segments = 1;
        let mut total = segment_size;

        if enable_gso
            && segment_size >= UDP_MIN_GSO_SEGMENT_SIZE
            && segment_size <= u16::MAX as usize
        {
            while first + segments < count && segments < TARGET_BATCH_SIZE {
                let next = payloads[first + segments].len();
                if next == 0 || next > segment_size || total + next > UDP_MAX_GSO_PAYLOAD {
                    break;
                }

                // Equal segments may continue the aggregate. One shorter
                // segment is a legal tail, but it must end this message so the
                // following datagram cannot be merged behind it.
                segments += 1;
                total += next;
                if next < segment_size {
                    break;
                }
            }
        }

        groups[group_count] = SendGroup {
            first,
            segments,
            segment_size,
        };
        group_count += 1;
        first += segments;
    }

    (groups, group_count)
}

/// Probe whether Linux accepts UDP segmentation offload on this socket.
///
/// The option is reset immediately: actual super-packets carry a per-message
/// `UDP_SEGMENT` control message.
#[cfg(target_os = "linux")]
pub fn detect_udp_gso(fd: std::os::fd::RawFd, segment_size: usize) -> bool {
    let segment_size = segment_size.min(u16::MAX as usize) as libc::c_int;
    let disabled: libc::c_int = 0;

    // SAFETY: Both values are valid integer socket-option payloads and `fd`
    // belongs to a live UDP socket.
    unsafe {
        if libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            libc::UDP_SEGMENT,
            (&segment_size as *const libc::c_int).cast(),
            std::mem::size_of_val(&segment_size) as libc::socklen_t,
        ) != 0
        {
            return false;
        }

        libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            libc::UDP_SEGMENT,
            (&disabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&disabled) as libc::socklen_t,
        ) == 0
    }
}

#[cfg(target_os = "linux")]
pub fn is_udp_gso_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL)
            | Some(libc::EIO)
            | Some(libc::EMSGSIZE)
            | Some(libc::ENOPROTOOPT)
            | Some(libc::EOPNOTSUPP)
    )
}

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

#[cfg(target_os = "linux")]
unsafe fn raw_send_mmsg(
    fd: std::os::fd::RawFd,
    headers: &mut [libc::mmsghdr; TARGET_BATCH_SIZE],
    count: usize,
) -> std::io::Result<usize> {
    // SAFETY: The caller keeps every buffer referenced by `headers` alive for
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
        Ok((result as usize).min(count))
    }
}

#[cfg(target_os = "linux")]
unsafe fn send_mmsg_plain(fd: std::os::fd::RawFd, payloads: &[Vec<u8>]) -> std::io::Result<usize> {
    use std::os::raw::c_void;

    // Keep the disabled and small-datagram path equivalent to the original
    // sendmmsg adapter: one setup pass and no GSO planning or control buffers.
    // SAFETY: Zero is a valid initial representation for these C I/O structs.
    let mut iovecs: [libc::iovec; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };
    // SAFETY: See above.
    let mut headers: [libc::mmsghdr; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for (index, payload) in payloads.iter().enumerate() {
        iovecs[index] = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast::<c_void>(),
            iov_len: payload.len(),
        };
        headers[index].msg_hdr.msg_iov = &mut iovecs[index];
        headers[index].msg_hdr.msg_iovlen = 1;
    }

    // SAFETY: Every header points at the live iovec and payload storage above.
    unsafe { raw_send_mmsg(fd, &mut headers, payloads.len()) }
}

/// Send a batch of datagrams on a connected socket in one syscall.
///
/// Returns how many logical datagrams were accepted; the caller drops the
/// rest. With GSO enabled, several logical datagrams can be accepted as one
/// kernel message.
///
/// # Safety
///
/// `fd` must be a live, connected, nonblocking UDP socket.
#[cfg(target_os = "linux")]
pub unsafe fn send_mmsg(
    fd: std::os::fd::RawFd,
    payloads: &[Vec<u8>],
    enable_gso: bool,
) -> std::io::Result<usize> {
    use std::os::raw::c_void;

    let count = payloads.len().min(TARGET_BATCH_SIZE);
    if count == 0 {
        return Ok(0);
    }
    let payloads = &payloads[..count];

    // Batches normally carry one traffic shape. If the first segment is small,
    // retain the exact low-overhead sendmmsg path for the whole batch; a later
    // large datagram can start a GSO batch on the next event-loop round.
    if !enable_gso || payloads[0].len() < UDP_MIN_GSO_SEGMENT_SIZE {
        // SAFETY: This function carries the same live-socket contract.
        return unsafe { send_mmsg_plain(fd, payloads) };
    }

    let (groups, group_count) = plan_send(payloads, true);

    // SAFETY: Zero is a valid initial representation for these C I/O structs.
    let mut iovecs: [libc::iovec; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };
    // SAFETY: See above.
    let mut headers: [libc::mmsghdr; TARGET_BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut controls = [ControlBuffer::default(); TARGET_BATCH_SIZE];

    for (index, payload) in payloads.iter().take(count).enumerate() {
        iovecs[index] = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast::<c_void>(),
            iov_len: payload.len(),
        };
    }

    for (index, group) in groups.iter().take(group_count).enumerate() {
        let header = &mut headers[index].msg_hdr;
        // Connected socket, so the destination is implicit.
        header.msg_iov = &mut iovecs[group.first];
        header.msg_iovlen = group.segments;
        if group.segments > 1 {
            let control_len = controls[index].set_udp_segment(group.segment_size as u16);
            header.msg_control = controls[index].words.as_mut_ptr().cast::<c_void>();
            header.msg_controllen = control_len as _;
        }
        header.msg_flags = 0;
    }

    // SAFETY: Every header points at live iovec, payload, and control storage.
    let sent_messages = unsafe { raw_send_mmsg(fd, &mut headers, group_count) }?;
    Ok(groups[..sent_messages]
        .iter()
        .map(|group| group.segments)
        .sum())
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

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_plan_groups_equal_segments_and_a_short_tail() {
        let payloads = vec![vec![1; 1_200], vec![2; 1_200], vec![3; 600], vec![4; 1_200]];
        let (groups, count) = plan_send(&payloads, true);

        assert_eq!(
            &groups[..count],
            &[
                SendGroup {
                    first: 0,
                    segments: 3,
                    segment_size: 1_200,
                },
                SendGroup {
                    first: 3,
                    segments: 1,
                    segment_size: 1_200,
                },
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_gso_plan_keeps_every_datagram_separate() {
        let payloads = vec![vec![1; 1_200], vec![2; 1_200], vec![3; 600]];
        let (groups, count) = plan_send(&payloads, false);

        assert_eq!(count, 3);
        assert!(groups[..count].iter().all(|group| group.segments == 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_plan_keeps_small_datagrams_on_the_sendmmsg_path() {
        let payloads = vec![vec![1; 64], vec![2; 64], vec![3; 32]];
        let (groups, count) = plan_send(&payloads, true);

        assert_eq!(count, 3);
        assert!(groups[..count].iter().all(|group| group.segments == 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_plan_keeps_an_empty_datagram_separate() {
        let payloads = vec![vec![1; 1_200], vec![], vec![2; 1_200]];
        let (groups, count) = plan_send(&payloads, true);

        assert_eq!(count, 3);
        assert!(groups[..count].iter().all(|group| group.segments == 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn control_buffer_fits_udp_segment_message() {
        // SAFETY: The argument is a small constant payload length.
        let required = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as _) as usize };
        assert!(std::mem::size_of::<ControlBuffer>() >= required);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn gso_scatter_gather_preserves_datagram_boundaries() {
        use std::os::fd::AsRawFd as _;

        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        sender.set_nonblocking(true).unwrap();
        if !detect_udp_gso(sender.as_raw_fd(), 1_200) {
            return;
        }

        let payloads = vec![vec![1; 1_200], vec![2; 1_200], vec![3; 600]];
        // SAFETY: `sender` is live, connected, and nonblocking.
        let sent = unsafe { send_mmsg(sender.as_raw_fd(), &payloads, true) }.unwrap();
        assert_eq!(sent, payloads.len());

        let expected = [(1_200, 1), (1_200, 2), (600, 3)];
        let mut buffer = [0; 1_500];
        for (len, byte) in expected {
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                receiver.recv(&mut buffer),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(received, len);
            assert!(buffer[..received].iter().all(|value| *value == byte));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn gso_enabled_small_datagrams_use_plain_sendmmsg() {
        use std::os::fd::AsRawFd as _;

        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        sender.set_nonblocking(true).unwrap();

        let payloads = vec![vec![1; 64], vec![2; 64], vec![3; 32]];
        // SAFETY: `sender` is live, connected, and nonblocking.
        let sent = unsafe { send_mmsg(sender.as_raw_fd(), &payloads, true) }.unwrap();
        assert_eq!(sent, payloads.len());

        let expected = [(64, 1), (64, 2), (32, 3)];
        let mut buffer = [0; 128];
        for (len, byte) in expected {
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                receiver.recv(&mut buffer),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(received, len);
            assert!(buffer[..received].iter().all(|value| *value == byte));
        }
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
