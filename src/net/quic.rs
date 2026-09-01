//! Platform-aware UDP I/O for the QUIC listener.
//!
//! Linux uses `recvmmsg(2)` and `sendmmsg(2)` to amortize syscall overhead.
//! When available, UDP GRO coalesces received datagrams and UDP GSO segments
//! outgoing aggregates. Other platforms retain the Tokio per-datagram path.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

pub(crate) const MAX_DATAGRAM_SIZE: usize = 65_535;
pub(crate) const MAX_BATCH_PACKETS: usize = 64;

#[cfg(target_os = "linux")]
const UDP_MAX_GSO_PAYLOAD: usize = 65_507;
#[cfg(target_os = "linux")]
const CONTROL_WORDS: usize = 4;

/// A reusable receive batch. One kernel datagram can contain multiple logical
/// datagrams when UDP GRO is enabled.
pub(crate) struct RecvPacketBatch {
    slots: Vec<RecvSlot>,
}

struct RecvSlot {
    buffer: Box<[u8]>,
    len: usize,
    segment_size: usize,
    from: Option<SocketAddr>,
    #[cfg(target_os = "linux")]
    address: libc::sockaddr_storage,
    #[cfg(target_os = "linux")]
    control: ControlBuffer,
}

impl RecvPacketBatch {
    pub(crate) fn new(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(RecvSlot {
                buffer: vec![0; MAX_DATAGRAM_SIZE].into_boxed_slice(),
                len: 0,
                segment_size: 0,
                from: None,
                #[cfg(target_os = "linux")]
                // SAFETY: An all-zero sockaddr_storage is a valid empty value
                // that the kernel fills before it is inspected.
                address: unsafe { std::mem::zeroed() },
                #[cfg(target_os = "linux")]
                control: ControlBuffer::default(),
            });
        }
        Self { slots }
    }

    /// Visit every logical UDP datagram in a received kernel batch. GRO
    /// aggregates are split according to the segment size control message.
    pub(crate) fn for_each_packet_mut(
        &mut self,
        received: usize,
        mut visit: impl FnMut(&mut [u8], SocketAddr),
    ) {
        for slot in self.slots.iter_mut().take(received) {
            let Some(from) = slot.from else {
                continue;
            };
            if slot.len == 0 {
                continue;
            }

            let segment_size = match slot.segment_size {
                1..=MAX_DATAGRAM_SIZE => slot.segment_size.min(slot.len),
                _ => slot.len,
            };

            for packet in slot.buffer[..slot.len].chunks_mut(segment_size) {
                visit(packet, from);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_mmsg(&mut self, fd: std::os::fd::RawFd) -> io::Result<usize> {
        use std::os::raw::c_void;

        // These contain raw pointers into `self.slots`, so they are rebuilt on
        // the stack for every syscall and never survive this function.
        // SAFETY: Zero is a valid initial representation for iovec/mmsghdr.
        let mut iovecs: [libc::iovec; MAX_BATCH_PACKETS] = unsafe { std::mem::zeroed() };
        // SAFETY: See above; every header submitted to the kernel is filled in
        // below before the syscall.
        let mut messages: [libc::mmsghdr; MAX_BATCH_PACKETS] = unsafe { std::mem::zeroed() };

        let count = self.slots.len().min(MAX_BATCH_PACKETS);
        for (index, slot) in self.slots.iter_mut().take(count).enumerate() {
            slot.len = 0;
            slot.segment_size = 0;
            slot.from = None;
            // SAFETY: These are plain C storage values whose zero state is
            // used only as output storage for the kernel.
            slot.address = unsafe { std::mem::zeroed() };
            slot.control = ControlBuffer::default();

            iovecs[index] = libc::iovec {
                iov_base: slot.buffer.as_mut_ptr().cast::<c_void>(),
                iov_len: slot.buffer.len(),
            };

            let header = &mut messages[index].msg_hdr;
            header.msg_name = (&mut slot.address as *mut libc::sockaddr_storage).cast::<c_void>();
            header.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
            header.msg_iov = &mut iovecs[index];
            header.msg_iovlen = 1;
            header.msg_control = slot.control.as_mut_ptr().cast::<c_void>();
            header.msg_controllen = slot.control.len() as _;
            header.msg_flags = 0;
        }

        // SAFETY: Every mmsghdr points to live, writable storage for the
        // duration of the syscall. The socket is nonblocking.
        let result = unsafe {
            libc::recvmmsg(
                fd,
                messages.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        let received = (result as usize).min(count);
        for (message, slot) in messages.iter().zip(self.slots.iter_mut()).take(received) {
            if message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                continue;
            }

            slot.len = (message.msg_len as usize).min(slot.buffer.len());
            slot.from = raw_to_socket_addr(&slot.address, message.msg_hdr.msg_namelen);
            slot.segment_size = gro_segment_size(&message.msg_hdr)
                .filter(|size| *size > 0)
                .unwrap_or(slot.len);
        }

        Ok(received)
    }
}

/// Reusable outgoing storage. Each message is either one UDP datagram or a
/// GSO aggregate containing equal-sized segments and an optional short tail.
pub(crate) struct SendPacketBatch {
    messages: Vec<SendMessage>,
    used: usize,
    packet_count: usize,
    byte_count: usize,
}

struct SendMessage {
    data: Vec<u8>,
    segment_size: usize,
    segments: usize,
    from: SocketAddr,
    to: SocketAddr,
}

impl SendMessage {
    fn empty() -> Self {
        Self {
            data: Vec::new(),
            segment_size: 0,
            segments: 0,
            from: SocketAddr::from(([0, 0, 0, 0], 0)),
            to: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }

    fn reset(&mut self, packet: &[u8], info: quiche::SendInfo) {
        self.data.clear();
        self.data.extend_from_slice(packet);
        self.segment_size = packet.len();
        self.segments = 1;
        self.from = info.from;
        self.to = info.to;
    }

    fn can_append(
        &self,
        packet_len: usize,
        info: quiche::SendInfo,
        aggregate_limit: usize,
    ) -> bool {
        self.segment_size > 0
            && self.segments < MAX_BATCH_PACKETS
            && self.from == info.from
            && self.to == info.to
            && self.data.len().is_multiple_of(self.segment_size)
            && packet_len <= self.segment_size
            && self.data.len() + packet_len <= aggregate_limit
    }
}

impl SendPacketBatch {
    pub(crate) fn new() -> Self {
        Self {
            messages: Vec::new(),
            used: 0,
            packet_count: 0,
            byte_count: 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.used = 0;
        self.packet_count = 0;
        self.byte_count = 0;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.packet_count == 0
    }

    pub(crate) fn packet_count(&self) -> usize {
        self.packet_count
    }

    pub(crate) fn byte_count(&self) -> usize {
        self.byte_count
    }

    pub(crate) fn push(
        &mut self,
        packet: &[u8],
        info: quiche::SendInfo,
        enable_gso: bool,
        aggregate_limit: usize,
    ) {
        let aggregate_limit = aggregate_limit.max(packet.len()).min(udp_max_gso_payload());

        if enable_gso && self.used > 0 {
            let last = &mut self.messages[self.used - 1];
            if last.can_append(packet.len(), info, aggregate_limit) {
                last.data.extend_from_slice(packet);
                last.segments += 1;
                self.packet_count += 1;
                self.byte_count += packet.len();
                return;
            }
        }

        if self.used == self.messages.len() {
            self.messages.push(SendMessage::empty());
        }
        self.messages[self.used].reset(packet, info);
        self.used += 1;
        self.packet_count += 1;
        self.byte_count += packet.len();
    }

    fn active(&self) -> &[SendMessage] {
        &self.messages[..self.used]
    }
}

pub(crate) struct QuicUdpSocket {
    socket: UdpSocket,
    udp_gso: bool,
    udp_gro: bool,
    reuseport_cid_steering: bool,
}

#[cfg(target_os = "linux")]
fn bpf_statement(code: u32, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k: value,
    }
}

#[cfg(target_os = "linux")]
fn bpf_jump(code: u32, value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

/// Route a QUIC packet to the socket index encoded in the first byte of its
/// destination CID. The UDP reuseport hook sees transport payload bytes:
/// short-header DCIDs start at byte 1, while long-header DCIDs start at byte 6.
#[cfg(target_os = "linux")]
fn attach_reuseport_cid_selector(fd: std::os::fd::RawFd, shards: usize) -> io::Result<()> {
    debug_assert!(shards > 1 && shards <= u8::MAX as usize);

    let mut filter = [
        // A = first QUIC header byte.
        bpf_statement(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0),
        // Header Form is the high bit. Long headers load byte 6; short
        // headers skip to byte 1.
        bpf_jump(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K, 0x80, 0, 2),
        bpf_statement(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 6),
        bpf_jump(libc::BPF_JMP | libc::BPF_JA, 1, 0, 0),
        bpf_statement(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 1),
        bpf_statement(libc::BPF_ALU | libc::BPF_MOD | libc::BPF_K, shards as u32),
        bpf_statement(libc::BPF_RET | libc::BPF_A, 0),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    // SAFETY: `program` points to a live, verifier-safe classic BPF program
    // for the duration of setsockopt, and `fd` is a live reuseport UDP socket.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_REUSEPORT_CBPF,
            (&program as *const libc::sock_fprog).cast(),
            std::mem::size_of_val(&program) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bind a UDP socket, optionally with `SO_REUSEPORT` so several sockets can
/// share one address and the kernel can spread arriving datagrams across them
/// by 4-tuple hash.
///
/// The option has to be set between `socket()` and `bind()`, which
/// `UdpSocket::bind` does not expose, so this goes through the raw syscalls.
#[cfg(target_os = "linux")]
fn bind_reuseport(addr: SocketAddr, shards: usize) -> io::Result<(std::net::UdpSocket, bool)> {
    use std::os::fd::FromRawFd;

    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    // SAFETY: A plain socket creation with constant arguments.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `fd` is a fresh descriptor this function owns; wrapping it here
    // means every early return below closes it.
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    let enable: libc::c_int = 1;
    for option in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        // SAFETY: `enable` is a valid integer socket-option payload and `fd`
        // is a live socket.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&enable as *const libc::c_int).cast(),
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let (storage, len) = socket_addr_to_raw(addr);
    // SAFETY: `storage` is a valid sockaddr of length `len` for this family.
    let result = unsafe {
        libc::bind(
            fd,
            (&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr>(),
            len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let cid_steering = match attach_reuseport_cid_selector(fd, shards) {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, shards, "QUIC CID reuseport steering unavailable; using cross-shard fallback");
            false
        }
    };

    Ok((socket, cid_steering))
}

impl QuicUdpSocket {
    /// Bind one socket for a server shard.
    ///
    /// With more than one `reuseport_shards`, several sockets bind the same
    /// address. Linux steers QUIC packets by the shard byte encoded in the
    /// destination CID, so a changed four-tuple still reaches its owner.
    pub(crate) async fn bind_shared(
        addr: SocketAddr,
        max_segment_size: usize,
        enable_gso: bool,
        enable_gro: bool,
        reuseport_shards: usize,
    ) -> io::Result<Self> {
        let (socket, reuseport_cid_steering) = if reuseport_shards > 1 {
            #[cfg(target_os = "linux")]
            {
                let (socket, cid_steering) = bind_reuseport(addr, reuseport_shards)?;
                (UdpSocket::from_std(socket)?, cid_steering)
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SO_REUSEPORT sharding requires Linux",
                ));
            }
        } else {
            (UdpSocket::bind(addr).await?, false)
        };

        #[cfg(target_os = "linux")]
        let (udp_gso, udp_gro) = {
            use std::os::fd::AsRawFd;

            let fd = socket.as_raw_fd();
            (
                enable_gso && detect_udp_gso(fd, max_segment_size),
                enable_gro && set_udp_gro(fd, true),
            )
        };

        #[cfg(not(target_os = "linux"))]
        let (udp_gso, udp_gro) = {
            let _ = (max_segment_size, enable_gso, enable_gro);
            (false, false)
        };

        Ok(Self {
            socket,
            udp_gso,
            udp_gro,
            reuseport_cid_steering,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) fn udp_gso_enabled(&self) -> bool {
        self.udp_gso
    }

    pub(crate) fn udp_gro_enabled(&self) -> bool {
        self.udp_gro
    }

    pub(crate) fn reuseport_cid_steering_enabled(&self) -> bool {
        self.reuseport_cid_steering
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn recv_batch(&self, batch: &mut RecvPacketBatch) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        use tokio::io::Interest;

        self.socket
            .async_io(Interest::READABLE, || {
                batch.recv_mmsg(self.socket.as_raw_fd())
            })
            .await
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) async fn recv_batch(&self, batch: &mut RecvPacketBatch) -> io::Result<usize> {
        if batch.slots.is_empty() {
            return Ok(0);
        }

        let (len, from) = self.socket.recv_from(&mut batch.slots[0].buffer).await?;
        batch.slots[0].len = len;
        batch.slots[0].segment_size = len;
        batch.slots[0].from = Some(from);

        let mut received = 1;
        while received < batch.slots.len() {
            let slot = &mut batch.slots[received];
            match self.socket.try_recv_from(&mut slot.buffer) {
                Ok((len, from)) => {
                    slot.len = len;
                    slot.segment_size = len;
                    slot.from = Some(from);
                    received += 1;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        Ok(received)
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn send_batch(&mut self, batch: &SendPacketBatch) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        use tokio::io::Interest;

        let messages = batch.active();
        let mut sent = 0;

        while sent < messages.len() {
            let use_gso = self.udp_gso;
            let result = self
                .socket
                .async_io(Interest::WRITABLE, || {
                    send_mmsg(self.socket.as_raw_fd(), &messages[sent..], use_gso)
                })
                .await;

            match result {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sendmmsg sent no datagrams",
                    ));
                }
                Ok(count) => sent += count,
                Err(error) if use_gso && is_udp_gso_error(&error) => {
                    self.udp_gso = false;
                    tracing::warn!(%error, "UDP GSO unavailable, falling back to individual datagrams");
                    self.send_individually(&messages[sent..]).await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) async fn send_batch(&mut self, batch: &SendPacketBatch) -> io::Result<()> {
        self.send_individually(batch.active()).await
    }

    async fn send_individually(&self, messages: &[SendMessage]) -> io::Result<()> {
        for message in messages {
            for packet in message.data.chunks(message.segment_size) {
                let written = self.socket.send_to(packet, message.to).await?;
                if written != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial UDP datagram send",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn udp_max_gso_payload() -> usize {
    #[cfg(target_os = "linux")]
    {
        UDP_MAX_GSO_PAYLOAD
    }
    #[cfg(not(target_os = "linux"))]
    {
        MAX_DATAGRAM_SIZE
    }
}

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct ControlBuffer {
    words: [usize; CONTROL_WORDS],
}

#[cfg(target_os = "linux")]
impl ControlBuffer {
    fn as_mut_ptr(&mut self) -> *mut usize {
        self.words.as_mut_ptr()
    }

    fn len(&self) -> usize {
        std::mem::size_of_val(&self.words)
    }

    fn set_udp_segment(&mut self, segment_size: u16) -> usize {
        self.words.fill(0);

        // SAFETY: ControlBuffer is suitably aligned and large enough for one
        // cmsghdr plus a u16 payload, as asserted by the test below.
        unsafe {
            let header = self.as_mut_ptr().cast::<libc::cmsghdr>();
            (*header).cmsg_level = libc::IPPROTO_UDP;
            (*header).cmsg_type = libc::UDP_SEGMENT;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as _) as _;
            libc::CMSG_DATA(header).cast::<u16>().write(segment_size);

            libc::CMSG_SPACE(std::mem::size_of::<u16>() as _) as usize
        }
    }
}

#[cfg(target_os = "linux")]
fn set_udp_gro(fd: std::os::fd::RawFd, enabled: bool) -> bool {
    let value: libc::c_int = enabled.into();
    // SAFETY: `value` is a valid integer socket-option payload and fd belongs
    // to a live UDP socket.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            libc::UDP_GRO,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        ) == 0
    }
}

#[cfg(target_os = "linux")]
fn detect_udp_gso(fd: std::os::fd::RawFd, segment_size: usize) -> bool {
    let segment_size = segment_size.min(u16::MAX as usize) as libc::c_int;
    let disabled: libc::c_int = 0;

    // Probe the socket-level option, then immediately reset it because actual
    // aggregates carry a per-message UDP_SEGMENT control message.
    // SAFETY: Both values are valid integer socket-option payloads.
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
fn gro_segment_size(header: &libc::msghdr) -> Option<usize> {
    // SAFETY: The kernel initialized the control buffer described by header.
    // CMSG_FIRSTHDR validates that it contains at least a cmsghdr.
    unsafe {
        let control = libc::CMSG_FIRSTHDR(header);
        let required = libc::CMSG_LEN(std::mem::size_of::<u16>() as _) as usize;
        // libc models socklen_t as u32 for musl and usize for glibc. Keep the
        // conversion explicit only where the source type actually differs so
        // both static release builds and the GNU Clippy gate agree.
        #[cfg(target_env = "musl")]
        let control_len = header.msg_controllen as usize;
        #[cfg(not(target_env = "musl"))]
        let control_len = header.msg_controllen;
        if control.is_null()
            || control_len < required
            || (*control).cmsg_level != libc::IPPROTO_UDP
            || (*control).cmsg_type != libc::UDP_GRO
            || ((*control).cmsg_len as usize) < required
            || ((*control).cmsg_len as usize) > control_len
        {
            return None;
        }

        Some(libc::CMSG_DATA(control).cast::<u16>().read() as usize)
    }
}

#[cfg(target_os = "linux")]
fn raw_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    match storage.ss_family as libc::c_int {
        libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: Family and kernel-provided length identify sockaddr_in.
            let address =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: Family and kernel-provided length identify sockaddr_in6.
            let address = unsafe {
                &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn socket_addr_to_raw(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain C storage initialized below according
    // to the address family.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    match address {
        SocketAddr::V4(address) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in.
            unsafe {
                (&mut storage as *mut libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in>()
                    .write(raw);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(address) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in6.
            unsafe {
                (&mut storage as *mut libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in6>()
                    .write(raw);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn send_mmsg(
    fd: std::os::fd::RawFd,
    messages: &[SendMessage],
    enable_gso: bool,
) -> io::Result<usize> {
    use std::mem::MaybeUninit;
    use std::os::raw::c_void;

    let count = messages.len().min(MAX_BATCH_PACKETS);
    // The common non-GSO batch contains about a dozen messages, well below
    // the hard ceiling. Leaving the backing arrays uninitialized avoids
    // clearing every unused sockaddr/header/control slot on every sendmmsg.
    // Each element exposed to the kernel is fully initialized in the loop.
    let mut addresses: [MaybeUninit<libc::sockaddr_storage>; MAX_BATCH_PACKETS] =
        [const { MaybeUninit::uninit() }; MAX_BATCH_PACKETS];
    let mut iovecs: [MaybeUninit<libc::iovec>; MAX_BATCH_PACKETS] =
        [const { MaybeUninit::uninit() }; MAX_BATCH_PACKETS];
    let mut headers: [MaybeUninit<libc::mmsghdr>; MAX_BATCH_PACKETS] =
        [const { MaybeUninit::uninit() }; MAX_BATCH_PACKETS];
    let mut controls: [MaybeUninit<ControlBuffer>; MAX_BATCH_PACKETS] =
        [const { MaybeUninit::uninit() }; MAX_BATCH_PACKETS];

    for (index, message) in messages.iter().take(count).enumerate() {
        let (address, address_len) = socket_addr_to_raw(message.to);
        let address = addresses[index].write(address);
        let iovec = iovecs[index].write(libc::iovec {
            iov_base: message.data.as_ptr().cast_mut().cast::<c_void>(),
            iov_len: message.data.len(),
        });

        let (control, control_len) = if enable_gso && message.segments > 1 {
            let mut value = ControlBuffer::default();
            let len = value.set_udp_segment(message.segment_size as u16);
            let value = controls[index].write(value);
            (value.as_mut_ptr().cast::<c_void>(), len)
        } else {
            (std::ptr::null_mut(), 0)
        };

        // Zero one live header rather than the entire maximum-sized array.
        // All fields read by sendmmsg are then assigned explicitly.
        // SAFETY: Zero is a valid initial representation for mmsghdr.
        let mut message_header: libc::mmsghdr = unsafe { std::mem::zeroed() };
        let header = &mut message_header.msg_hdr;
        header.msg_name = (address as *mut libc::sockaddr_storage).cast::<c_void>();
        header.msg_namelen = address_len;
        header.msg_iov = iovec;
        header.msg_iovlen = 1;
        header.msg_control = control;
        header.msg_controllen = control_len as _;
        header.msg_flags = 0;
        headers[index].write(message_header);
    }

    // SAFETY: All pointers in the first `count` headers refer to live storage
    // above for the duration of this nonblocking syscall.
    let result = unsafe {
        raw_sendmmsg(
            fd,
            headers.as_mut_ptr().cast::<libc::mmsghdr>(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT as _,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((result as usize).min(count))
    }
}

/// Issue `sendmmsg(2)` directly instead of through the libc wrapper.
///
/// musl implements `sendmmsg` as a loop of `sendmsg`, so linking against it
/// silently turns a batched send back into one syscall per packet — and the
/// release artifacts for this project are musl static binaries. Going straight
/// to the syscall keeps the batching that the whole `SendPacketBatch` design
/// exists for. `mmsghdr` is laid out the same for userspace and the kernel on
/// the 64-bit targets built here, so the array is passed through unchanged.
///
/// # Safety
///
/// `headers` must point to at least `count` initialized `mmsghdr` values whose
/// interior pointers stay live for the call.
#[cfg(target_os = "linux")]
unsafe fn raw_sendmmsg(
    fd: std::os::fd::RawFd,
    headers: *mut libc::mmsghdr,
    count: libc::c_uint,
    flags: libc::c_int,
) -> libc::c_int {
    // SAFETY: Delegated to this function's contract; the argument types match
    // the kernel's sendmmsg signature.
    let result = unsafe {
        libc::syscall(
            libc::SYS_sendmmsg,
            fd as libc::c_long,
            headers as usize as libc::c_long,
            count as libc::c_long,
            flags as libc::c_long,
        )
    };
    result as libc::c_int
}

#[cfg(target_os = "linux")]
fn is_udp_gso_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL)
            | Some(libc::EIO)
            | Some(libc::EMSGSIZE)
            | Some(libc::ENOPROTOOPT)
            | Some(libc::EOPNOTSUPP)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn send_info(to: SocketAddr) -> quiche::SendInfo {
        quiche::SendInfo {
            from: "127.0.0.1:8443".parse().unwrap(),
            to,
            at: Instant::now(),
        }
    }

    #[test]
    fn gso_groups_equal_segments_and_short_tail() {
        let target = "127.0.0.1:4433".parse().unwrap();
        let mut batch = SendPacketBatch::new();
        batch.push(&[1; 1200], send_info(target), true, 10_000);
        batch.push(&[2; 1200], send_info(target), true, 10_000);
        batch.push(&[3; 600], send_info(target), true, 10_000);

        assert_eq!(batch.packet_count(), 3);
        assert_eq!(batch.active().len(), 1);
        assert_eq!(batch.active()[0].segment_size, 1200);
        assert_eq!(batch.active()[0].segments, 3);
        assert_eq!(batch.active()[0].data.len(), 3000);
    }

    #[test]
    fn packet_after_short_tail_starts_new_message() {
        let target = "127.0.0.1:4433".parse().unwrap();
        let mut batch = SendPacketBatch::new();
        batch.push(&[1; 1200], send_info(target), true, 10_000);
        batch.push(&[2; 600], send_info(target), true, 10_000);
        batch.push(&[3; 1200], send_info(target), true, 10_000);

        assert_eq!(batch.active().len(), 2);
        assert_eq!(batch.active()[0].segments, 2);
        assert_eq!(batch.active()[1].segments, 1);
    }

    #[test]
    fn sendmmsg_mode_keeps_packets_separate_without_gso() {
        let target = "127.0.0.1:4433".parse().unwrap();
        let mut batch = SendPacketBatch::new();
        batch.push(&[1; 1200], send_info(target), false, 10_000);
        batch.push(&[2; 1200], send_info(target), false, 10_000);

        assert_eq!(batch.active().len(), 2);
        assert!(batch.active().iter().all(|message| message.segments == 1));
    }

    #[test]
    fn different_destination_starts_new_message() {
        let mut batch = SendPacketBatch::new();
        batch.push(
            &[1; 1200],
            send_info("127.0.0.1:4433".parse().unwrap()),
            true,
            10_000,
        );
        batch.push(
            &[2; 1200],
            send_info("127.0.0.1:4434".parse().unwrap()),
            true,
            10_000,
        );

        assert_eq!(batch.active().len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn control_buffer_fits_udp_segment_message() {
        // SAFETY: The argument is a small constant payload length.
        let required = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as _) as usize };
        assert!(std::mem::size_of::<ControlBuffer>() >= required);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gro_control_message_requires_a_bounded_u16_payload() {
        use std::os::raw::c_void;

        let mut control = ControlBuffer::default();
        let control_header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        // SAFETY: `control` is aligned and large enough for this header and
        // u16 payload, as checked by the preceding test.
        unsafe {
            (*control_header).cmsg_level = libc::IPPROTO_UDP;
            (*control_header).cmsg_type = libc::UDP_GRO;
            (*control_header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as _) as _;
            libc::CMSG_DATA(control_header).cast::<u16>().write(1_200);
        }

        // SAFETY: Zero is a valid initial representation for msghdr; the
        // control pointer and length are filled before inspection.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_control = control.as_mut_ptr().cast::<c_void>();
        // SAFETY: The argument is a small constant payload length.
        let required = unsafe { libc::CMSG_LEN(std::mem::size_of::<u16>() as _) as usize };
        message.msg_controllen = required as _;
        assert_eq!(gro_segment_size(&message), Some(1_200));

        // A kernel- or ABI-supplied cmsg length may never authorize a read
        // beyond the actual control buffer described by msghdr.
        // SAFETY: Only the initialized cmsghdr field is changed.
        unsafe { (*control_header).cmsg_len = (required + 1) as _ };
        assert_eq!(gro_segment_size(&message), None);

        // Restore the header, then truncate the outer buffer description.
        // SAFETY: Only the initialized cmsghdr field is changed.
        unsafe { (*control_header).cmsg_len = required as _ };
        message.msg_controllen = (required - 1) as _;
        assert_eq!(gro_segment_size(&message), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_address_round_trip() {
        for address in [
            "127.0.0.1:4433".parse().unwrap(),
            "[::1]:4433".parse().unwrap(),
        ] {
            let (raw, len) = socket_addr_to_raw(address);
            assert_eq!(raw_to_socket_addr(&raw, len), Some(address));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn batched_socket_preserves_datagram_boundaries() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = receiver.local_addr().unwrap();
        let mut sender =
            QuicUdpSocket::bind_shared("127.0.0.1:0".parse().unwrap(), 1350, true, true, 1)
                .await
                .unwrap();

        let mut batch = SendPacketBatch::new();
        batch.push(&[1; 1200], send_info(target), sender.udp_gso, 10_000);
        batch.push(&[2; 1200], send_info(target), sender.udp_gso, 10_000);
        batch.push(&[3; 600], send_info(target), sender.udp_gso, 10_000);
        sender.send_batch(&batch).await.unwrap();

        let expected = [(1200, 1), (1200, 2), (600, 3)];
        let mut buffer = [0; 1500];
        for (len, byte) in expected {
            let (received, _) = receiver.recv_from(&mut buffer).await.unwrap();
            assert_eq!(received, len);
            assert!(buffer[..received].iter().all(|value| *value == byte));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sendmmsg_initializes_every_live_slot() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = receiver.local_addr().unwrap();
        let mut sender =
            QuicUdpSocket::bind_shared("127.0.0.1:0".parse().unwrap(), 1350, false, false, 1)
                .await
                .unwrap();

        let mut batch = SendPacketBatch::new();
        for sequence in 0..MAX_BATCH_PACKETS {
            batch.push(
                &(sequence as u64).to_be_bytes(),
                send_info(target),
                false,
                65_535,
            );
        }
        sender.send_batch(&batch).await.unwrap();

        let mut seen = vec![false; MAX_BATCH_PACKETS];
        let mut buffer = [0_u8; 8];
        for _ in 0..MAX_BATCH_PACKETS {
            let (received, _) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                receiver.recv_from(&mut buffer),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(received, buffer.len());
            let sequence = u64::from_be_bytes(buffer) as usize;
            assert!(sequence < MAX_BATCH_PACKETS);
            assert!(!std::mem::replace(&mut seen[sequence], true));
        }
        assert!(seen.into_iter().all(|received| received));
    }

    /// Established packets must follow their encoded CID shard after their
    /// four-tuple changes. Cover both QUIC header forms because handshake
    /// packets use the long offset before 1-RTT switches to the short one.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reuseport_routes_long_and_short_headers_by_destination_cid() {
        const SHARDS: usize = 4;
        const PACKETS_PER_HEADER: usize = 8;

        let first =
            QuicUdpSocket::bind_shared("127.0.0.1:0".parse().unwrap(), 1350, false, false, SHARDS)
                .await
                .unwrap();
        let target = first.local_addr().unwrap();

        let mut shards = vec![first];
        for _ in 1..SHARDS {
            shards.push(
                QuicUdpSocket::bind_shared(target, 1350, false, false, SHARDS)
                    .await
                    .unwrap(),
            );
        }
        assert!(
            shards
                .iter()
                .all(QuicUdpSocket::reuseport_cid_steering_enabled)
        );

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for shard in 0..SHARDS {
            for sequence in 0..PACKETS_PER_HEADER {
                let mut short = [0u8; 16];
                short[0] = 0x40;
                short[1] = shard as u8;
                short[2] = sequence as u8;
                sender.send_to(&short, target).await.unwrap();

                let mut long = [0u8; 16];
                long[0] = 0xc0;
                long[6] = shard as u8;
                long[7] = sequence as u8;
                sender.send_to(&long, target).await.unwrap();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut delivered = 0;
        for (expected_shard, shard) in shards.iter().enumerate() {
            let mut batch = RecvPacketBatch::new(PACKETS_PER_HEADER * 2);
            let received = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                shard.recv_batch(&mut batch),
            )
            .await
            .unwrap()
            .unwrap();
            let mut shard_delivered = 0;
            batch.for_each_packet_mut(received, |packet, _| {
                let encoded_shard = if packet[0] & 0x80 == 0 {
                    packet[1]
                } else {
                    packet[6]
                };
                assert_eq!(encoded_shard as usize, expected_shard);
                shard_delivered += 1;
            });
            assert_eq!(shard_delivered, PACKETS_PER_HEADER * 2);
            delivered += shard_delivered;
        }

        assert_eq!(delivered, SHARDS * PACKETS_PER_HEADER * 2);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recvmmsg_and_gro_restore_logical_packets() {
        let receiver =
            QuicUdpSocket::bind_shared("127.0.0.1:0".parse().unwrap(), 1350, true, true, 1)
                .await
                .unwrap();
        let target = receiver.local_addr().unwrap();
        let mut sender =
            QuicUdpSocket::bind_shared("127.0.0.1:0".parse().unwrap(), 1350, true, true, 1)
                .await
                .unwrap();

        let mut outgoing = SendPacketBatch::new();
        outgoing.push(&[1; 1200], send_info(target), sender.udp_gso, 10_000);
        outgoing.push(&[2; 1200], send_info(target), sender.udp_gso, 10_000);
        outgoing.push(&[3; 600], send_info(target), sender.udp_gso, 10_000);
        sender.send_batch(&outgoing).await.unwrap();

        let mut incoming = RecvPacketBatch::new(8);
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_batch(&mut incoming),
        )
        .await
        .unwrap()
        .unwrap();

        let mut packets = Vec::new();
        incoming.for_each_packet_mut(received, |packet, _| {
            packets.push((packet.len(), packet[0]));
        });
        assert_eq!(packets, [(1200, 1), (1200, 2), (600, 3)]);
    }
}
