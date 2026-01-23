use clap::ValueEnum;
use std::error::Error;

/// Type alias for backend creation result
pub type BackendResult = Result<(Box<dyn PacketSource>, Box<dyn PacketSink>), Box<dyn Error + Send + Sync>>;

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
#[derive(Debug, Clone)]
pub struct PacketWithContext {
    pub data: Vec<u8>,
    /// Hook source: Some(0)=XDP/ingress, Some(2)=TC egress/upload, None=unknown/pnet
    pub hook_source: Option<u8>,
    /// Original packet length from wire (for eBPF, this comes from the kernel)
    /// When None, calculate from data.len() or parsed headers
    pub original_len: Option<u32>,
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
pub mod ebpf_backend;

#[cfg(feature = "ebpf-backend")]
pub use ebpf_backend::EbpfBackendFactory;
