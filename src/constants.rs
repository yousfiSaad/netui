//! Global constants for the NetUI application.
//!
//! This module centralizes magic numbers and configuration values
//! used throughout the codebase.

/// Network protocol constants
pub mod network {
    /// Size of Ethernet header in bytes
    pub const ETHERNET_HEADER_SIZE: u8 = 14;

    /// Size of ARP packet in bytes
    pub const ARP_PACKET_SIZE: usize = 28;

    /// Total buffer size for Ethernet + ARP packets
    pub const ETHERNET_ARP_BUFFER_SIZE: usize = ETHERNET_HEADER_SIZE as usize + ARP_PACKET_SIZE;

    /// Minimum IPv4 header size in bytes
    pub const MIN_IPV4_HEADER_SIZE: usize = 20;
}

/// Timing constants
pub mod timing {
    /// Delay between ARP scan requests in milliseconds
    /// This non-standard delay helps avoid flooding the network
    pub const ARP_SCAN_DELAY_MS: u64 = 37;

    /// Interval between stats aggregation ticks in seconds
    pub const STATS_TICK_INTERVAL_SECS: u64 = 1;

    /// Delay before retrying when packet reader encounters an error
    pub const READER_ERROR_RETRY_DELAY_MS: u64 = 100;
}

/// Buffer sizes
pub mod buffer {
    /// Default window size for stats aggregation (number of samples)
    pub const DEFAULT_STATS_WINDOW_SIZE: usize = 10;

    /// Default buffer size for stat keys
    pub const DEFAULT_STATS_KEYS_BUFFER_SIZE: usize = 100;

    /// Buffer capacity for perf packet reads
    pub const PERF_PACKET_BUFFER_CAPACITY: usize = 10;

    /// Maximum consecutive errors before giving up on a packet reader
    pub const MAX_CONSECUTIVE_ERRORS: u32 = 10;
}

/// eBPF hook source identifiers
pub mod ebpf {
    /// XDP hook - captures ingress packets (download)
    pub const HOOK_XDP: u8 = 0;

    /// TC ingress hook - not currently used by NetUI
    pub const HOOK_TC_INGRESS: u8 = 1;

    /// TC egress hook - captures egress packets (upload)
    pub const HOOK_TC_EGRESS: u8 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_constants() {
        // Ethernet + ARP should equal expected buffer size
        assert_eq!(
            network::ETHERNET_ARP_BUFFER_SIZE,
            network::ETHERNET_HEADER_SIZE as usize + network::ARP_PACKET_SIZE
        );
        assert_eq!(network::ETHERNET_ARP_BUFFER_SIZE, 42);
    }

    #[test]
    fn test_ebpf_hook_constants() {
        // Hook constants should be unique
        assert_ne!(ebpf::HOOK_XDP, ebpf::HOOK_TC_INGRESS);
        assert_ne!(ebpf::HOOK_TC_INGRESS, ebpf::HOOK_TC_EGRESS);
        assert_ne!(ebpf::HOOK_XDP, ebpf::HOOK_TC_EGRESS);
    }
}
