use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use aya::{
    maps::MapData,
    maps::perf::AsyncPerfEventArray,
    programs::{Xdp, SchedClassifier, tc, TcAttachType, xdp::XdpLinkId, tc::SchedClassifierLinkId},
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{self, Duration};

#[cfg(feature = "pnet-backend")]
use pnet_datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};

use crate::backend::{BackendConfig, BackendFactory, PacketSink, PacketSource, PacketWithContext};
use crate::constants::{buffer, ebpf, network, timing};
use crate::interface_utils;

/// Packet event structure - must match the eBPF side definition
///
/// The eBPF program parses headers in-kernel and extracts only the
/// fields needed for host discovery and bandwidth monitoring.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketEvent {
    /// Source MAC address
    pub src_mac: [u8; 6],
    /// Destination MAC address
    pub dst_mac: [u8; 6],
    /// EtherType (IPv4, ARP, etc.)
    pub ether_type: u16,
    /// Source IP (if IPv4)
    pub src_ip: u32,
    /// Destination IP (if IPv4)
    pub dst_ip: u32,
    /// Packet length in bytes
    pub len: u32,
    /// Protocol (TCP/UDP/ICMP, if IPv4)
    pub protocol: u8,
    /// Valid flags: bit 0 = has_ip, bit 1 = has_arp
    pub flags: u8,
    /// Which hook captured this: 0=XDP, 1=TC ingress, 2=TC egress
    pub hook_source: u8,
}

/// Safely parse a PacketEvent from a raw buffer received from eBPF kernel space.
///
/// # Safety
/// The unsafe block inside this function is safe because:
/// 1. We validate the buffer size matches `sizeof(PacketEvent)` before dereferencing
/// 2. `PacketEvent` is marked with `#[repr(C)]`, guaranteeing stable memory layout
/// 3. The eBPF program writes the same struct definition (ensured by build-time inclusion)
/// 4. We only create a reference (`&*event_ptr`) with the same lifetime as the input buffer
///
/// # Arguments
/// * `packet_buf` - Buffer containing raw bytes from the perf event array
///
/// # Returns
/// * `Some(&PacketEvent)` if the buffer is valid and contains a complete PacketEvent
/// * `None` if the buffer is too small or malformed
fn parse_packet_event(packet_buf: &mut BytesMut) -> Option<&PacketEvent> {
    let event_size = std::mem::size_of::<PacketEvent>();
    if packet_buf.len() < event_size {
        tracing::warn!(
            "Buffer too small for PacketEvent: got {} bytes, need {} bytes",
            packet_buf.len(),
            event_size
        );
        return None;
    }

    // Safety: The buffer size is validated above, and PacketEvent is #[repr(C)]
    // which guarantees the layout matches the eBPF side definition.
    // The eBPF program uses the exact same struct definition (included at build time).
    unsafe {
        let event_ptr = packet_buf.as_ptr() as *const PacketEvent;
        Some(&*event_ptr)
    }
}

/// Reconstruct an Ethernet packet from eBPF-extracted metadata.
///
/// The eBPF program extracts only the headers it needs for statistics. To maintain
/// compatibility with the existing packet parser, we reconstruct a minimal Ethernet
/// packet with proper IP header length fields.
///
/// # Arguments
/// * `event` - The PacketEvent containing extracted metadata from eBPF
///
/// # Returns
/// A vector of bytes representing the reconstructed Ethernet packet
fn reconstruct_ethernet_packet(event: &PacketEvent) -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&event.dst_mac);
    packet.extend_from_slice(&event.src_mac);
    packet.extend_from_slice(&event.ether_type.to_be_bytes());

    // Add IP header with correct total_length and padding (if IP flag is set)
    if event.flags & 1 != 0 {
        // Calculate IP total length (excluding 14-byte Ethernet header)
        // Clamp to u16::MAX for safety
        let ip_total_len = (event.len.saturating_sub(network::ETHERNET_HEADER_SIZE as u32) as u16)
            .min(u16::MAX);

        // Minimum IPv4 header (20 bytes)
        let mut ip_header = [0u8; network::MIN_IPV4_HEADER_SIZE];
        ip_header[0] = 0x45; // Version=4, IHL=5 (20 bytes)
        // Bytes 2-3: Total Length (big-endian)
        ip_header[2] = (ip_total_len >> 8) as u8;
        ip_header[3] = ip_total_len as u8;
        // Byte 9: Protocol
        ip_header[9] = event.protocol;
        // Bytes 12-15: Source IP
        ip_header[12..16].copy_from_slice(&event.src_ip.to_be_bytes());
        // Bytes 16-19: Destination IP
        ip_header[16..20].copy_from_slice(&event.dst_ip.to_be_bytes());

        packet.extend_from_slice(&ip_header);

        // Pad packet to match the IP total_length
        // This ensures the parser sees correct payload size for bandwidth calculation
        let current_len = packet.len();
        let target_total_len = ip_total_len as usize + network::ETHERNET_HEADER_SIZE as usize;
        if current_len < target_total_len {
            let padding_size = target_total_len - current_len;
            packet.resize(current_len + padding_size, 0);
        }
    }

    packet
}

/// Spawns async tasks to read packets from the PerfEventArray.
///
/// This function spawns one task per CPU to read from that CPU's perf event buffer.
/// Each task continuously reads packets and sends them to the channel.
///
/// # Returns
/// A receiver that can be used to get packets with context from all CPU buffers
fn spawn_packet_readers(
    perf_array: &mut AsyncPerfEventArray<MapData>,
) -> mpsc::UnboundedReceiver<PacketWithContext> {
    let (tx, rx) = mpsc::unbounded_channel();

    // Get the number of online CPUs
    let cpus = match aya::util::online_cpus() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to get online CPUs: {:?}", e);
            // Return empty receiver if we can't get CPUs
            return rx;
        }
    };

    let mut spawned_count = 0;

    for cpu_id in cpus {
        // Open the perf buffer for this CPU
        let buf = match perf_array.open(cpu_id, None) {
            Ok(b) => b,
            Err(_e) => {
                // Silently skip CPUs that fail to open (reduces flickering)
                continue;
            }
        };

        spawned_count += 1;
        let tx = tx.clone();

        // Spawn a task to read from this CPU's buffer
        task::spawn(async move {
            let mut buf = buf;
            let mut packets = vec![
                BytesMut::with_capacity(std::mem::size_of::<PacketEvent>());
                buffer::PERF_PACKET_BUFFER_CAPACITY
            ];
            let mut error_count = 0;
            let cpu_id_usize = cpu_id as usize;

            loop {
                match buf.read_events(&mut packets).await {
                    Ok(events) => {
                        error_count = 0;

                        for packet_buf in packets.iter_mut().take(events.read) {
                            if let Some(event) = parse_packet_event(packet_buf) {
                                let hook_name = match event.hook_source {
                                    ebpf::HOOK_XDP => "XDP",
                                    ebpf::HOOK_TC_INGRESS => "TC_INGRESS",
                                    ebpf::HOOK_TC_EGRESS => "TC_EGRESS",
                                    _ => "UNKNOWN",
                                };
                                tracing::debug!(
                                    "CPU {}: Packet from {}: src_ip={:?} dst_ip={:?} len={}",
                                    cpu_id_usize,
                                    hook_name,
                                    event.src_ip,
                                    event.dst_ip,
                                    event.len
                                );

                                let packet = reconstruct_ethernet_packet(event);
                                let packet_ctx = PacketWithContext {
                                    data: packet,
                                    hook_source: Some(event.hook_source),
                                    original_len: Some(event.len),
                                };

                                if tx.send(packet_ctx).is_err() {
                                    tracing::debug!("CPU {}: Channel closed, stopping reader", cpu_id_usize);
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error_count += 1;
                        if error_count >= buffer::MAX_CONSECUTIVE_ERRORS {
                            tracing::error!(
                                "CPU {}: Too many consecutive errors ({}), stopping reader: {:?}",
                                cpu_id_usize,
                                error_count,
                                e
                            );
                            return;
                        }
                        time::sleep(Duration::from_millis(timing::READER_ERROR_RETRY_DELAY_MS)).await;
                    }
                }
            }
        });
    }

    // Drop the original tx - the cloned ones are held by the tasks
    drop(tx);

    if spawned_count == 0 {
        eprintln!("Warning: No packet reader tasks were spawned successfully");
    }

    rx
}

/// Packet source that reads from eBPF PerfEventArray via an unbounded channel
///
/// Packets are delivered to this source through a channel that's populated by
/// async tasks reading from the per-CPU perf event buffers.
pub struct EbpfPacketSource {
    /// Channel receiver for packets from the async readers
    packet_rx: mpsc::UnboundedReceiver<PacketWithContext>,
    /// Keep the BPF object alive to prevent program detachment
    _bpf: Ebpf,
    /// Keep the XDP link alive to prevent program detachment
    _xdp_link_id: Option<XdpLinkId>,
    /// Keep the TC egress link alive to prevent program detachment
    _tc_egress_link_id: Option<SchedClassifierLinkId>,
}

impl PacketSource for EbpfPacketSource {
    fn next_packet(&mut self) -> Option<PacketWithContext> {
        // Try to receive a packet from the channel without blocking
        // The channel is populated by async tasks reading from PerfEventArray
        self.packet_rx.try_recv().ok()
    }
}

/// Packet sink - eBPF XDP is receive-only, so we use pnet for sending
///
/// This hybrid approach allows us to:
/// - Use eBPF XDP for efficient packet capture
/// - Use pnet for sending packets (ARP scanning, etc.)
#[cfg(feature = "pnet-backend")]
pub struct EbpfPacketSink {
    sender: Option<Box<dyn DataLinkSender>>,
    interface: Option<NetworkInterface>,
}

#[cfg(feature = "pnet-backend")]
impl EbpfPacketSink {
    /// Create a new packet sink using pnet for sending
    fn new(interface_name: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Find the network interface
        let interface = interface_utils::find_interface(interface_name)
            .ok_or_else(|| format!("Interface not found: {}", interface_name))?;

        // Create a pnet channel for sending only
        match pnet_datalink::channel(&interface, Config::default()) {
            Ok(Channel::Ethernet(tx, _rx)) => Ok(Self {
                sender: Some(tx),
                interface: Some(interface),
            }),
            Ok(_) => Err("Unsupported channel type".into()),
            Err(e) => Err(format!("Channel creation failed: {}", e).into()),
        }
    }
}

#[cfg(feature = "pnet-backend")]
impl PacketSink for EbpfPacketSink {
    fn send_packet(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(sender) = &mut self.sender {
            match sender.send_to(data, self.interface.clone()) {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(format!("Send failed: {}", e).into()),
                None => Err("Failed to send packet".into()),
            }
        } else {
            Err("Packet sink not initialized".into())
        }
    }
}

/// Fallback implementation when pnet-backend is not available
#[cfg(not(feature = "pnet-backend"))]
pub struct EbpfPacketSink;

#[cfg(not(feature = "pnet-backend"))]
impl PacketSink for EbpfPacketSink {
    fn send_packet(&mut self, _data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("eBPF packet sending requires the 'pnet-backend' feature to be enabled".into())
    }
}

pub struct EbpfBackendFactory;

impl BackendFactory for EbpfBackendFactory {
    fn create(
        &self,
        config: BackendConfig,
    ) -> Result<(Box<dyn PacketSource>, Box<dyn PacketSink>), Box<dyn Error + Send + Sync>> {
        eprintln!("Initializing eBPF backend for interface: {}", config.interface_name);

        // Find and load the eBPF binary
        let bpf_binary = find_ebpf_binary()
            .ok_or("Could not find netui-ebpf binary. Run 'cargo build' first.")?;
        eprintln!("Loading eBPF program from: {:?}", bpf_binary);

        let mut bpf = Ebpf::load_file(&bpf_binary)
            .map_err(|e| format!("Failed to load eBPF file: {}", e))?;

        // Initialize logging (optional, for debugging)
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            eprintln!("Warning: Failed to initialize eBPF logger: {}", e);
        }

        // Load and attach the XDP program
        let program: &mut Xdp = bpf.program_mut("xdp_netui")
            .ok_or("XDP program 'xdp_netui' not found in eBPF bytecode")?
            .try_into()
            .map_err(|_| "Failed to convert program to Xdp")?;

        program.load()
            .map_err(|e| format!("Failed to load XDP program: {}", e))?;

        // Attach XDP to the interface (using interface name, not index)
        // Use SKB_MODE for better compatibility with virtualized environments (virtio_net, Lima, etc.)
        // SKB mode works on any interface at the cost of slightly less performance than native mode
        let xdp_link_id = program.attach(
            &config.interface_name,
            aya::programs::XdpFlags::SKB_MODE,
        ).map_err(|e| format!("Failed to attach XDP program to interface {}: {}", config.interface_name, e))?;

        eprintln!("Successfully attached XDP program to interface: {}", config.interface_name);

        // ======== TC Egress Program for Upload Bandwidth ========
        // XDP captures ingress (download). TC egress captures upload traffic.
        // We DON'T use TC ingress because XDP already handles ingress,
        // and using both would count download packets twice!

        // 1. Set up clsact qdisc (required for TC egress attachment)
        eprintln!("Setting up clsact qdisc for TC egress...");
        if let Err(e) = tc::qdisc_add_clsact(&config.interface_name) {
            // clsact may already exist - log but continue
            eprintln!("Note: clsact qdisc setup (may already exist): {}", e);
        }

        // 2. Load and attach TC egress program - THIS CAPTURES UPLOAD!
        eprintln!("Loading TC egress program...");
        let tc_egress: &mut SchedClassifier = bpf
            .program_mut("tc_egress_netui")
            .ok_or("TC egress program 'tc_egress_netui' not found in eBPF bytecode")?
            .try_into()
            .map_err(|_| "Failed to convert program to SchedClassifier")?;

        tc_egress
            .load()
            .map_err(|e| format!("Failed to load TC egress program: {}", e))?;

        eprintln!("Attaching TC egress program (captures upload bandwidth)...");
        // Attach TC egress and keep the link ID to prevent program detachment
        let tc_egress_link_id = tc_egress
            .attach(&config.interface_name, TcAttachType::Egress)
            .map_err(|e| format!("Failed to attach TC egress program: {}", e))?;

        // Verify TC egress attachment
        eprintln!("Successfully attached TC egress program (captures upload bandwidth)");
        tracing::info!("TC egress attached - this program captures packets leaving the interface (upload)");
        // ======== End TC Programs ========

        // Take the PerfEventArray map from the BPF object and convert to async
        let perf_map = bpf
            .take_map("EVENTS")
            .ok_or("PerfEventArray 'EVENTS' not found in eBPF bytecode")?;

        let mut async_perf = AsyncPerfEventArray::try_from(perf_map)
            .map_err(|e| format!("Failed to create async perf array: {}", e))?;

        // Spawn packet readers (this is synchronous, just spawns background tasks)
        let packet_rx = spawn_packet_readers(&mut async_perf);

        // Create packet source with link IDs to keep programs attached
        let packet_source = Box::new(EbpfPacketSource {
            packet_rx,
            _bpf: bpf,
            _xdp_link_id: Some(xdp_link_id),
            _tc_egress_link_id: Some(tc_egress_link_id),
        });

        // Create packet sink (hybrid: eBPF for receive, pnet for send)
        #[cfg(feature = "pnet-backend")]
        let packet_sink: Box<dyn PacketSink> = {
            eprintln!("Initializing pnet-based packet sink for sending");
            Box::new(EbpfPacketSink::new(&config.interface_name)?)
        };

        #[cfg(not(feature = "pnet-backend"))]
        let packet_sink: Box<dyn PacketSink> = {
            eprintln!("Warning: Packet sending disabled (pnet-backend feature not enabled)");
            Box::new(EbpfPacketSink)
        };

        eprintln!("eBPF backend initialization complete");
        Ok((packet_source, packet_sink))
    }

    fn name(&self) -> &'static str {
        "ebpf"
    }
}

/// Find the eBPF binary in the build directory.
///
/// The build script copies the compiled eBPF program to:
/// target/<profile>/build/netui-<hash>/out/netui-ebpf.bpf
///
/// We search both debug and release directories to find it.
fn find_ebpf_binary() -> Option<PathBuf> {
    // Try release first, then debug
    for profile in ["release", "debug"] {
        let build_dir = Path::new("target").join(profile).join("build");
        if !build_dir.exists() {
            continue;
        }

        let entries = fs::read_dir(&build_dir).ok()?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let dir_name = path.file_name()?.to_str()?;
            if !dir_name.starts_with("netui-") {
                continue;
            }

            let bpf_path = path.join("out/netui-ebpf.bpf");
            if bpf_path.exists() {
                return Some(bpf_path);
            }
        }
    }

    None
}
