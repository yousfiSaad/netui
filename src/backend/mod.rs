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

/// Source of network packets - can receive packets
pub trait PacketSource: Send + 'static {
    fn next_packet(&mut self) -> Option<Vec<u8>>;
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
