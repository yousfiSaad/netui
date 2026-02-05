//! Network protocol constants.

/// Size of Ethernet header in bytes
pub const ETHERNET_HEADER_SIZE: u8 = 14;

/// Size of ARP packet in bytes
pub const ARP_PACKET_SIZE: usize = 28;

/// Total buffer size for Ethernet + ARP packets
pub const ETHERNET_ARP_BUFFER_SIZE: usize = ETHERNET_HEADER_SIZE as usize + ARP_PACKET_SIZE;

/// Minimum IPv4 header size in bytes
pub const MIN_IPV4_HEADER_SIZE: usize = 20;

/// eBPF hook source identifiers

/// XDP hook - captures ingress packets (download)
pub const HOOK_XDP: u8 = 0;

/// TC ingress hook - not currently used by NetUI
pub const HOOK_TC_INGRESS: u8 = 1;

/// TC egress hook - captures egress packets (upload)
pub const HOOK_TC_EGRESS: u8 = 2;

/// IP protocol numbers
pub const PROTOCOL_ICMP: u8 = 1;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
