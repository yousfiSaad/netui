//! NetUI library exports for integration testing.
//!
//! This library re-exports the main modules needed for integration tests
//! while keeping the binary entry point in main.rs.

// Public modules
pub mod backend;
pub mod constants;
pub mod error;
pub mod event;
pub mod host;
pub mod interface_utils;
pub mod mac_vendor;
pub mod stats;
pub mod types;

// Private modules (not exposed in library API, but needed for compilation)
pub mod resolver;
mod trace;
mod utils;

// Re-export scanner for benchmarking
pub mod scanner;

// Re-export commonly used types at the crate root
pub use backend::{BackendConfig, BackendFactory, PacketSink, PacketSource, PacketWithContext};
pub use error::{AppResult, NetuiError};
pub use event::{Event, ScannerEvent, SecurityAlert, SecurityAlertType};
pub use interface_utils::find_interface;
pub use mac_vendor::lookup_vendor;
pub use resolver::resolve_hostname;
pub use stats::{
    ports::{format_port_stats, PortStats},
    session::SessionStats,
    speed::format_size,
    Direction, IpPair, Speed, StatKey, StatValues, StatsMap, TcpState,
};
pub use types::MacAddr;
