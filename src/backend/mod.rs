use clap::ValueEnum;
use std::error::Error;

/// Type alias for backend creation result
pub type BackendResult =
    Result<(Box<dyn PacketSource>, Box<dyn PacketSink>), Box<dyn Error + Send + Sync>>;

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum BackendType {
    #[default]
    Pnet,
    Ebpf,
}

/// Packet with optional hook source context from eBPF
///
/// When using the eBPF backend, packets include `hook_source` to indicate
/// where they were captured:
/// - 0 = XDP (ingress/download)
/// - 1 = TC ingress (not used - XDP handles ingress)
/// - 2 = TC egress (egress/upload)
///
/// For the pnet backend, `hook_source` is None and direction is determined
/// from IP addresses.
///
/// For eBPF TCP/UDP packets, `direct_event` contains pre-extracted data for
/// direct processing, bypassing packet reconstruction. When Some, the `data`
/// field may be empty or contain only ARP packet data.
#[derive(Debug, Clone)]
pub struct PacketWithContext {
    pub data: Vec<u8>,
    /// Hook source: Some(0)=XDP/ingress, Some(2)=TC egress/upload, None=unknown/pnet
    pub hook_source: Option<u8>,
    /// Original packet length from wire (for eBPF, this comes from the kernel)
    /// When None, calculate from data.len() or parsed headers
    pub original_len: Option<u32>,
    /// Direct event data for eBPF TCP/UDP packets (bypasses reconstruction)
    /// When Some, contains pre-extracted fields: src_ip, dst_ip, src_port, dst_port,
    /// protocol, tcp_flags. When None, parse from data field.
    pub direct_event: Option<DirectEventData>,
    /// Kernel timestamp in nanoseconds (for RTT calculation)
    pub timestamp_ns: Option<u64>,
}

/// Pre-extracted packet data from eBPF for direct processing.
///
/// This structure holds the fields that eBPF extracts in-kernel, allowing
/// userspace to process packets without reconstructing and re-parsing.
#[derive(Debug, Clone, Copy)]
pub struct DirectEventData {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
}

/// Source of network packets - can receive packets
pub trait PacketSource: Send + 'static {
    fn next_packet(&mut self) -> Option<PacketWithContext>;
}

/// Sink for network packets - can send packets
pub trait PacketSink: Send + 'static {
    fn send_packet(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>>;
}

/// Configuration for backend creation
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub interface_name: String,
    pub read_timeout_ms: Option<u64>,
}

impl BackendConfig {
    pub fn new(interface_name: String) -> Self {
        Self {
            interface_name,
            read_timeout_ms: Some(500),
        }
    }
}

/// Factory for creating packet source/sink pairs
pub trait BackendFactory: Send + Sync {
    fn create(&self, config: BackendConfig) -> BackendResult;

    fn name(&self) -> &'static str;
}

#[cfg(feature = "pnet-backend")]
pub mod pnet_backend;

#[cfg(feature = "pnet-backend")]
pub use pnet_backend::PnetBackendFactory;

#[cfg(feature = "ebpf-backend")]
pub mod ebpf;

#[cfg(feature = "ebpf-backend")]
pub use ebpf::EbpfBackendFactory;
