use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use aya::{
    maps::MapData,
    maps::perf::AsyncPerfEventArray,
    programs::Xdp,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task;

#[cfg(feature = "pnet-backend")]
use pnet_datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};

use crate::backend::{BackendConfig, BackendFactory, PacketSink, PacketSource};

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
}

/// Packet source that reads from eBPF PerfEventArray via an unbounded channel
///
/// Packets are delivered to this source through a channel that's populated by
/// async tasks reading from the per-CPU perf event buffers.
pub struct EbpfPacketSource {
    /// Channel receiver for packets from the async readers
    packet_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Keep the BPF object alive to prevent program detachment
    _bpf: Ebpf,
}

impl PacketSource for EbpfPacketSource {
    fn next_packet(&mut self) -> Option<Vec<u8>> {
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
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .rev()
            .find(|n| {
                n.is_up()
                    && n.is_running()
                    && !n.is_loopback()
                    && n.name
                        .to_lowercase()
                        .contains(&interface_name.to_lowercase())
            })
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

/// Spawns async tasks to read packets from the PerfEventArray
///
/// This function spawns one task per CPU to read from that CPU's perf event buffer.
/// Each task continuously reads packets and sends them to the channel.
///
/// # Returns
/// A receiver that can be used to get packets from all CPU buffers
fn spawn_packet_readers(
    perf_array: &mut AsyncPerfEventArray<MapData>,
) -> mpsc::UnboundedReceiver<Vec<u8>> {
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
        let tx_clone = tx.clone();

        // Open the perf buffer for this CPU
        let mut buf = match perf_array.open(cpu_id, None) {
            Ok(b) => b,
            Err(_e) => {
                // Silently skip CPUs that fail to open (reduces flickering)
                continue;
            }
        };

        spawned_count += 1;

        // Spawn a task to read from this CPU's buffer
        task::spawn(async move {
            // Each PacketEvent struct is now smaller (6+6+2+4+4+4+1+1 = 28 bytes)
            // We need buffers that can hold multiple packets
            let mut packets = vec![BytesMut::with_capacity(std::mem::size_of::<PacketEvent>()); 10];
            let mut error_count = 0;
            const MAX_CONSECUTIVE_ERRORS: u32 = 10;

            loop {
                // Read events from the perf buffer
                match buf.read_events(&mut packets).await {
                    Ok(events) => {
                        error_count = 0; // Reset error counter on success
                        // Process each read packet
                        for packet_buf in packets.iter_mut().take(events.read) {
                            // The buffer contains the PacketEvent struct serialized
                            if packet_buf.len() >= std::mem::size_of::<PacketEvent>() {
                                // Parse the PacketEvent struct from the buffer
                                // We use unsafe because we're deserializing from raw bytes
                                // that were serialized by the eBPF program
                                unsafe {
                                    let event_ptr = packet_buf.as_ptr() as *const PacketEvent;
                                    let event = &*event_ptr;

                                    // Reconstruct Ethernet packet from extracted metadata
                                    // We need to set the IP total_length field and pad to match,
                                    // so the parser calculates correct payload size for bandwidth.
                                    let mut packet = Vec::new();

                                    // Destination MAC
                                    packet.extend_from_slice(&event.dst_mac);
                                    // Source MAC
                                    packet.extend_from_slice(&event.src_mac);
                                    // EtherType (big-endian)
                                    packet.extend_from_slice(&event.ether_type.to_be_bytes());

                                    // Add IP header with correct total_length and padding
                                    if event.flags & 1 != 0 {
                                        // Calculate IP total length (excluding 14-byte Ethernet header)
                                        // Clamp to u16::MAX for safety
                                        let ip_total_len = (event.len.saturating_sub(14) as u16).min(u16::MAX);

                                        // Minimum IPv4 header (20 bytes)
                                        let mut ip_header = [0u8; 20];
                                        ip_header[0] = 0x45; // Version+IHL
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
                                        // This ensures the parser sees correct payload size
                                        let current_len = packet.len();
                                        let target_ip_len = ip_total_len as usize;
                                        if current_len < target_ip_len + 14 {
                                            let padding_size = (target_ip_len + 14) - current_len;
                                            packet.resize(current_len + padding_size, 0);
                                        }
                                    }

                                    // Send reconstructed packet to channel
                                    if tx_clone.send(packet).is_err() {
                                        // Channel closed, stop reading gracefully
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Err(_e) => {
                        error_count += 1;
                        if error_count >= MAX_CONSECUTIVE_ERRORS {
                            return;
                        }
                        // Brief pause before retrying
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
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
        program.attach(
            &config.interface_name,
            aya::programs::XdpFlags::default(),
        ).map_err(|e| format!("Failed to attach XDP program to interface {}: {}", config.interface_name, e))?;

        eprintln!("Successfully attached XDP program to interface: {}", config.interface_name);

        // Take the PerfEventArray map from the BPF object and convert to async
        let perf_map = bpf
            .take_map("EVENTS")
            .ok_or("PerfEventArray 'EVENTS' not found in eBPF bytecode")?;

        let mut async_perf = AsyncPerfEventArray::try_from(perf_map)
            .map_err(|e| format!("Failed to create async perf array: {}", e))?;

        // Spawn packet readers (this is synchronous, just spawns background tasks)
        let packet_rx = spawn_packet_readers(&mut async_perf);

        // Create packet source
        let packet_source = Box::new(EbpfPacketSource {
            packet_rx,
            _bpf: bpf,
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
