use std::error::Error;

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
    type Source: PacketSource;
    type Sink: PacketSink;

    fn create(
        &self,
        config: BackendConfig,
    ) -> Result<(Self::Source, Self::Sink), Box<dyn Error + Send + Sync>>;

    fn name(&self) -> &'static str;
}

#[cfg(feature = "pnet-backend")]
pub mod pnet_backend;

#[cfg(feature = "pnet-backend")]
pub use pnet_backend::PnetBackendFactory;
