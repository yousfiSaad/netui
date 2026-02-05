//! Global constants for the NetUI application.
//!
//! This module centralizes magic numbers and configuration values
//! used throughout the codebase, organized by feature domain.

mod app;
pub mod network_values;
mod quality;
mod stats;
mod tcp;
mod ui;

// Re-export all constants for convenient access
pub use app::*;
pub use network_values::*;
pub use quality::*;
pub use stats::*;
pub use tcp::*;
pub use ui::*;

// Backward compatibility: re-export as nested modules
pub mod buffer;
pub mod ebpf;
pub mod network;
pub mod security;
pub mod timing;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_constants() {
        // Ethernet + ARP should equal expected buffer size
        assert_eq!(
            ETHERNET_ARP_BUFFER_SIZE,
            ETHERNET_HEADER_SIZE as usize + ARP_PACKET_SIZE
        );
        assert_eq!(ETHERNET_ARP_BUFFER_SIZE, 42);
    }

    #[test]
    fn test_ebpf_hook_constants() {
        // Hook constants should be unique
        assert_ne!(HOOK_XDP, HOOK_TC_INGRESS);
        assert_ne!(HOOK_TC_INGRESS, HOOK_TC_EGRESS);
        assert_ne!(HOOK_XDP, HOOK_TC_EGRESS);
    }

    #[test]
    fn test_security_constants() {
        // MAX_ALERTS should be reasonable
        assert!(MAX_ALERTS > 0);
        assert!(MAX_ALERTS <= 1000);
    }

    #[test]
    fn test_ui_width_constants() {
        // Width constants should be in descending order
        assert!(WIDTH_FULL_DETAIL > WIDTH_NO_RTT);
        assert!(WIDTH_NO_RTT > WIDTH_COMPACT);
    }

    #[test]
    fn test_quality_constants() {
        // RTT thresholds should be in correct order
        assert!(RTT_EXCELLENT_US < RTT_POOR_US);

        // Retransmission thresholds should be in correct order
        assert!(RETRANSMIT_EXCELLENT < RETRANSMIT_POOR);

        // Quality weights should sum to approximately 1.0
        let total_weight = RTT_WEIGHT + RETRANSMIT_WEIGHT;
        assert!((total_weight - 1.0).abs() < 0.01);
    }
}
