//! Socket I/O for the synchronous benchmark workers.

use std::io;
use std::net::UdpSocket;
use std::time::Instant;

use anyhow::{Result, bail, ensure};

#[cfg(not(target_os = "linux"))]
use super::BUF_SIZE;
use super::MAX_DATAGRAM_SIZE;

const RECEIVE_BUDGET: usize = 2048;
#[cfg(target_os = "linux")]
const BATCH_SIZE: usize = 16;
#[cfg(not(target_os = "linux"))]
const BATCH_SIZE: usize = 1;

struct Packet {
    buffer: [u8; MAX_DATAGRAM_SIZE],
    len: usize,
    at: Instant,
}

impl Packet {
    fn data(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

/// A bounded burst of ready packets and at most one future packet. Retain
/// the unsent suffix on a partial write: quiche already accounted for it.
pub(super) struct Sender {
    packets: Vec<Packet>,
    first: usize,
    end: usize,
    blocked: bool,
}

impl Sender {
    pub(super) fn new() -> Self {
        Self {
            packets: Vec::new(),
            first: 0,
            end: 0,
            blocked: false,
        }
    }

    pub(super) fn writable(&self) -> bool {
        self.blocked
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        (self.first < self.end && !self.blocked).then(|| self.packets[self.first].at)
    }

    pub(super) fn flush(
        &mut self,
        socket: &UdpSocket,
        quic: &mut quiche::Connection,
    ) -> Result<bool> {
        let mut sent = false;
        let mut now = Instant::now();
        loop {
            let mut exhausted = false;
            if self.first == self.end {
                self.first = 0;
                self.end = 0;
                if self.packets.is_empty() {
                    self.packets.reserve_exact(BATCH_SIZE);
                }
                for index in 0..BATCH_SIZE {
                    if index == self.packets.len() {
                        self.packets.push(Packet {
                            buffer: [0; MAX_DATAGRAM_SIZE],
                            len: 0,
                            at: now,
                        });
                    }
                    let packet = &mut self.packets[index];
                    match quic.send(&mut packet.buffer) {
                        Ok((len, info)) => {
                            packet.len = len;
                            packet.at = info.at;
                            self.end += 1;
                            if packet.at > now {
                                now = Instant::now();
                                if packet.at > now {
                                    break;
                                }
                            }
                        }
                        Err(quiche::Error::Done) => {
                            exhausted = true;
                            break;
                        }
                        Err(error) => bail!("QUIC send: {error}"),
                    }
                }
            }

            let pending = &self.packets[self.first..self.end];
            let ready = pending.iter().take_while(|packet| packet.at <= now).count();
            if ready == 0 {
                break;
            }
            match send_ready(socket, &pending[..ready]) {
                Ok(count) => {
                    ensure!(count > 0, "UDP socket accepted no packets");
                    self.first += count;
                    self.blocked = false;
                    sent = true;
                    if exhausted && self.first == self.end {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.blocked = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(sent)
    }

    /// Leave a reusable client in blocking mode after its measurement.
    pub(super) fn finish(&mut self, socket: &UdpSocket) -> Result<()> {
        socket.set_nonblocking(false)?;
        for packet in &self.packets[self.first..self.end] {
            let delay = packet.at.saturating_duration_since(Instant::now());
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            send_ready(socket, std::slice::from_ref(packet))?;
        }
        self.first = 0;
        self.end = 0;
        self.blocked = false;
        Ok(())
    }
}

fn send_ready(socket: &UdpSocket, packets: &[Packet]) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    if packets.len() > 1 {
        return linux::send(socket, packets);
    }
    let bytes = packets[0].data();
    if socket.send(bytes)? != bytes.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"));
    }
    Ok(1)
}

pub(super) struct Receiver {
    #[cfg(target_os = "linux")]
    batch: linux::ReceiveBatch,
    #[cfg(not(target_os = "linux"))]
    buffer: Vec<u8>,
}

impl Receiver {
    pub(super) fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            batch: linux::ReceiveBatch::new(),
            #[cfg(not(target_os = "linux"))]
            buffer: vec![0; BUF_SIZE],
        }
    }

    pub(super) fn drain(
        &mut self,
        socket: &UdpSocket,
        mut handle: impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<bool> {
        let mut received = 0;
        while received < RECEIVE_BUDGET {
            #[cfg(target_os = "linux")]
            let result = self.batch.receive(socket);
            #[cfg(not(target_os = "linux"))]
            let result = socket.recv(&mut self.buffer);
            match result {
                Ok(count) => {
                    #[cfg(target_os = "linux")]
                    {
                        for packet in self.batch.packets(count) {
                            handle(packet)?;
                        }
                        received += count;
                        if count < BATCH_SIZE {
                            break;
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        handle(&mut self.buffer[..count])?;
                        received += 1;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(received > 0)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use super::{BATCH_SIZE, MAX_DATAGRAM_SIZE, Packet};

    pub(super) struct ReceiveBatch {
        buffers: Vec<[u8; MAX_DATAGRAM_SIZE]>,
        lengths: [Option<usize>; BATCH_SIZE],
    }

    impl ReceiveBatch {
        pub(super) fn new() -> Self {
            Self {
                buffers: vec![[0; MAX_DATAGRAM_SIZE]; BATCH_SIZE],
                lengths: [None; BATCH_SIZE],
            }
        }

        pub(super) fn receive(&mut self, socket: &UdpSocket) -> io::Result<usize> {
            let mut buffers = self.buffers.iter_mut();
            let mut iovecs: [libc::iovec; BATCH_SIZE] = std::array::from_fn(|_| {
                let buffer = buffers.next().expect("one buffer per receive slot");
                libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: buffer.len(),
                }
            });
            let mut messages = headers(&mut iovecs);
            // SAFETY: Each header points to one initialized iovec with a
            // distinct live writable buffer. The socket stays borrowed.
            let result = unsafe {
                libc::recvmmsg(
                    socket.as_raw_fd(),
                    messages.as_mut_ptr(),
                    BATCH_SIZE as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            let count = result as usize;
            for (length, message) in self.lengths.iter_mut().zip(&messages[..count]) {
                *length = (message.msg_hdr.msg_flags & libc::MSG_TRUNC == 0)
                    .then_some(message.msg_len as usize);
            }
            Ok(count)
        }

        pub(super) fn packets(&mut self, count: usize) -> impl Iterator<Item = &mut [u8]> {
            self.buffers[..count]
                .iter_mut()
                .zip(&self.lengths[..count])
                .filter_map(|(buffer, length)| length.map(|len| &mut buffer[..len]))
        }
    }

    pub(super) fn send(socket: &UdpSocket, packets: &[Packet]) -> io::Result<usize> {
        let mut iovecs: [libc::iovec; BATCH_SIZE] = std::array::from_fn(|index| {
            let packet = packets.get(index).map_or(&[][..], Packet::data);
            libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast(),
                iov_len: packet.len(),
            }
        });
        let mut messages = headers(&mut iovecs);
        // SAFETY: The first packets.len() headers reference live read-only
        // payloads. sendmmsg only updates the message headers synchronously.
        // Use the raw syscall to avoid musl's per-message sendmsg wrapper.
        let result = unsafe {
            libc::syscall(
                libc::SYS_sendmmsg,
                socket.as_raw_fd(),
                messages.as_mut_ptr(),
                packets.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn headers(iovecs: &mut [libc::iovec; BATCH_SIZE]) -> [libc::mmsghdr; BATCH_SIZE] {
        // SAFETY: A zeroed header has null optional pointers and zero lengths.
        let mut messages: [libc::mmsghdr; BATCH_SIZE] = unsafe { std::mem::zeroed() };
        for (message, iovec) in messages.iter_mut().zip(iovecs) {
            message.msg_hdr.msg_iov = iovec;
            message.msg_hdr.msg_iovlen = 1;
        }
        messages
    }
}

pub(super) fn wait(
    first: (&UdpSocket, bool),
    second: Option<(&UdpSocket, bool)>,
    deadline: Instant,
) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let interest = |(socket, write): (&UdpSocket, bool)| libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN | if write { libc::POLLOUT } else { 0 },
            revents: 0,
        };
        let mut fds = [
            interest(first),
            second.map_or(
                libc::pollfd {
                    fd: -1,
                    events: 0,
                    revents: 0,
                },
                interest,
            ),
        ];
        let result = wait_unix(&mut fds, remaining);
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (first, second);
        std::thread::yield_now();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_unix(fds: &mut [libc::pollfd], remaining: std::time::Duration) -> libc::c_int {
    let timeout = libc::timespec {
        tv_sec: remaining.as_secs() as _,
        tv_nsec: remaining.subsec_nanos() as _,
    };
    // SAFETY: The descriptor array and finite timeout live through ppoll.
    // The sockets are borrowed by wait(), and the signal mask is unchanged.
    unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as _, &timeout, std::ptr::null()) }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn wait_unix(fds: &mut [libc::pollfd], remaining: std::time::Duration) -> libc::c_int {
    #[cfg(target_os = "macos")]
    if fds.iter().all(|fd| fd.fd < libc::FD_SETSIZE as libc::c_int) {
        let timeout = libc::timespec {
            tv_sec: remaining.as_secs() as _,
            tv_nsec: remaining.subsec_nanos() as _,
        };
        // SAFETY: FD_ZERO initializes each live fd_set. Each nonnegative fd
        // fits the set, and all sets and the timeout outlive pselect.
        return unsafe {
            let mut read = std::mem::zeroed::<libc::fd_set>();
            let mut write = std::mem::zeroed::<libc::fd_set>();
            libc::FD_ZERO(&mut read);
            libc::FD_ZERO(&mut write);
            let mut nfds = 0;
            for fd in fds.iter().filter(|fd| fd.fd >= 0) {
                libc::FD_SET(fd.fd, &mut read);
                if fd.events & libc::POLLOUT != 0 {
                    libc::FD_SET(fd.fd, &mut write);
                }
                nfds = nfds.max(fd.fd + 1);
            }
            libc::pselect(
                nfds,
                &mut read,
                &mut write,
                std::ptr::null_mut(),
                &timeout,
                std::ptr::null(),
            )
        };
    }
    let timeout_ms = remaining
        .as_nanos()
        .div_ceil(1_000_000)
        .min(libc::c_int::MAX as u128) as libc::c_int;
    // SAFETY: The array holds live, borrowed descriptors throughout poll.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout_ms) }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use super::*;

    #[test]
    fn readiness_wait_observes_the_second_socket() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"ready", second.local_addr().unwrap())
            .unwrap();
        let mut fds = [&first, &second].map(|socket| libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        assert_eq!(wait_unix(&mut fds, Duration::from_secs(1)), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_batches_keep_packet_boundaries_and_discard_truncation() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(socket.local_addr().unwrap()).unwrap();
        let now = Instant::now();
        let packets = [(7, 1), (MAX_DATAGRAM_SIZE, 2)].map(|(len, byte)| Packet {
            buffer: [byte; MAX_DATAGRAM_SIZE],
            len,
            at: now,
        });
        assert_eq!(send_ready(&sender, &packets).unwrap(), 2);
        sender.send(&[3; MAX_DATAGRAM_SIZE + 1]).unwrap();
        sender.send(&[4; 9]).unwrap();

        let mut seen = Vec::new();
        let mut rx = Receiver::new();
        assert!(
            rx.drain(&socket, |data| {
                seen.push(data.to_vec());
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(seen, [vec![1; 7], vec![2; MAX_DATAGRAM_SIZE], vec![4; 9]]);
    }
}
