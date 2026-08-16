// TUN device management for CONNECT-IP tunnels.
//
// Creates and manages a shared TUN device. All IP tunnels share a single
// device; routing between tunnels is handled by the routing table.
//
// On Linux the device can be opened with `IFF_VNET_HDR` ("offload"), which
// lets the kernel hand over a whole GSO aggregate in one read and accept one
// in one write. That mode changes the wire format on the device fd — every
// datagram is prefixed with a `virtio_net_hdr` — so it is all-or-nothing:
// the plain `send`/`recv` helpers must not be used once it is on, and every
// caller goes through [`TunManager::recv_batch`] and [`TunManager::send_batch`].

use std::sync::Arc;

use tracing::info;
use tun_rs::AsyncDevice;

/// Headroom every send buffer reserves for the `virtio_net_hdr` that
/// `send_multiple` writes immediately before the IP packet.
#[cfg(target_os = "linux")]
pub const TUN_SEND_OFFSET: usize = tun_rs::VIRTIO_NET_HDR_LEN;
#[cfg(not(target_os = "linux"))]
pub const TUN_SEND_OFFSET: usize = 0;

/// Segments one read can be split into. A 64 KiB aggregate over a 1280-byte
/// MTU is ~51 packets, so this covers the largest split the kernel can hand us.
pub const TUN_BATCH_SIZE: usize = 64;

/// Storage for one batched TUN read: the raw aggregate plus the segments it is
/// split into.
pub struct TunRecvBatch {
    /// Raw device read, including the virtio header and the unsplit packet.
    /// Only the offload path reads through it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    original: Vec<u8>,
    /// Segmented IP packets.
    packets: Vec<Vec<u8>>,
    /// Length of each segment in `packets`.
    sizes: Vec<usize>,
}

impl TunRecvBatch {
    pub fn new(mtu: usize) -> Self {
        Self {
            // The kernel can hand back a full 64 KiB aggregate regardless of MTU.
            original: vec![0; TUN_SEND_OFFSET + 65_535],
            packets: vec![vec![0; mtu.max(1_500)]; TUN_BATCH_SIZE],
            sizes: vec![0; TUN_BATCH_SIZE],
        }
    }

    /// One segment produced by the last read.
    pub fn packet(&self, index: usize) -> Option<&[u8]> {
        let len = *self.sizes.get(index)?;
        self.packets.get(index).map(|packet| &packet[..len])
    }
}

/// Read one device datagram into `batch`, splitting a GRO aggregate into its
/// segments. Returns how many segments it produced.
///
/// Takes the device directly rather than a [`TunManager`] so the event loop can
/// poll it without borrowing the whole server.
pub async fn recv_batch(device: &AsyncDevice, batch: &mut TunRecvBatch) -> std::io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        device
            .recv_multiple(&mut batch.original, &mut batch.packets, &mut batch.sizes, 0)
            .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let len = device.recv(&mut batch.packets[0]).await?;
        batch.sizes[0] = len;
        Ok(1)
    }
}

/// Outgoing IP packets staged for one batched write.
///
/// Each buffer carries its packet at [`TUN_SEND_OFFSET`], leaving room for the
/// virtio header that the offload path writes in front of it. Buffers are
/// reused across batches so staging a packet costs a copy, not an allocation.
pub struct TunSendBatch {
    packets: Vec<Vec<u8>>,
    used: usize,
    #[cfg(target_os = "linux")]
    gro_table: tun_rs::GROTable,
}

impl TunSendBatch {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            used: 0,
            #[cfg(target_os = "linux")]
            gro_table: tun_rs::GROTable::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    pub fn is_full(&self) -> bool {
        self.used >= TUN_BATCH_SIZE
    }

    pub fn clear(&mut self) {
        self.used = 0;
    }

    /// Stage one IP packet for the next write.
    pub fn push(&mut self, packet: &[u8]) {
        if self.used == self.packets.len() {
            self.packets
                .push(Vec::with_capacity(TUN_SEND_OFFSET + 1_500));
        }
        let buffer = &mut self.packets[self.used];
        buffer.clear();
        buffer.resize(TUN_SEND_OFFSET, 0);
        buffer.extend_from_slice(packet);
        self.used += 1;
    }
}

impl Default for TunSendBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps the async TUN device with server-specific configuration.
pub struct TunManager {
    device: Arc<AsyncDevice>,
    mtu: usize,
    offload: bool,
}

impl TunManager {
    /// Create and configure a new TUN device.
    ///
    /// Requires root/CAP_NET_ADMIN privileges. The device is created with the
    /// given name and MTU, and assigned the gateway addresses for the pool
    /// ranges (the network address + 1 offset is used as the device IP; clients
    /// get subsequent addresses from the pool).
    pub fn new(
        name: &str,
        mtu: u16,
        v4_gateway: Option<std::net::Ipv4Addr>,
        v4_prefix: u8,
        v6_gateway: Option<std::net::Ipv6Addr>,
        v6_prefix: u8,
        offload: bool,
    ) -> std::io::Result<Self> {
        let mut builder = tun_rs::DeviceBuilder::new().name(name).mtu(mtu);

        if let Some(v4) = v4_gateway {
            builder = builder.ipv4(v4, v4_prefix, None);
        }
        if let Some(v6) = v6_gateway {
            builder = builder.ipv6(v6, v6_prefix);
        }

        #[cfg(target_os = "linux")]
        {
            builder = builder.offload(offload);
        }

        let device = builder.build_async()?;

        // The request can be refused, and the send path has to match what the
        // device actually negotiated rather than what was asked for.
        #[cfg(target_os = "linux")]
        let offload = offload && device.tcp_gso();
        #[cfg(not(target_os = "linux"))]
        let offload = {
            let _ = offload;
            false
        };

        info!(name = name, mtu = mtu, offload, "TUN device created");

        Ok(Self {
            device: Arc::new(device),
            mtu: mtu as usize,
            offload,
        })
    }

    /// Whether the device negotiated GSO/GRO offload.
    pub fn offload(&self) -> bool {
        self.offload
    }

    /// Write a staged batch of IP packets, coalescing them where the device
    /// supports it. The batch is left empty.
    pub async fn send_batch(&self, batch: &mut TunSendBatch) -> std::io::Result<usize> {
        if batch.used == 0 {
            return Ok(0);
        }

        let result = {
            #[cfg(target_os = "linux")]
            {
                let packets = &mut batch.packets[..batch.used];
                self.device
                    .send_multiple(&mut batch.gro_table, packets, TUN_SEND_OFFSET)
                    .await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let mut total = 0;
                let mut result = Ok(0);
                for packet in batch.packets[..batch.used].iter() {
                    match self.device.try_send(&packet[TUN_SEND_OFFSET..]) {
                        Ok(written) => total += written,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => {
                            result = Err(error);
                            break;
                        }
                    }
                }
                result.map(|_: usize| total)
            }
        };

        batch.clear();
        result
    }

    /// The configured MTU.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Get a clone of the underlying device Arc (for use in separate tasks).
    pub fn device(&self) -> Arc<AsyncDevice> {
        Arc::clone(&self.device)
    }
}
