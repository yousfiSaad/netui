//! Packet processing and statistics extraction logic.
//!
//! This module handles parsing of network packets and extracting
//! statistics for bandwidth monitoring.
//!
//! # Scope
//! This module processes both LAN and Internet traffic. Internet traffic
//! is detected when packets are sent to/received from the default gateway.

use crate::constants::network_values::{PROTOCOL_TCP, PROTOCOL_UDP};
use crate::constants::{ebpf, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::stats::{Direction, StatItem, StatKey, StatValues};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet,
};
use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Determine the direction of a packet based on hook source, IP addresses, and gateway.
///
/// # Arguments
/// * `src_ip` - Source IP address
/// * `dst_ip` - Destination IP address
/// * `local_ips` - Set of local IP addresses
/// * `gateway_ip` - Optional gateway IP for Internet traffic detection
/// * `hook_source` - Optional hook source from eBPF (0=XDP, 1=TC ingress, 2=TC egress)
///
/// # Returns
/// The detected direction (Incoming, Outgoing, Local, Internet, or None)
pub fn determine_packet_direction(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    local_ips: &HashSet<Ipv4Addr>,
    gateway_ip: Option<Ipv4Addr>,
    hook_source: Option<u8>,
) -> Direction {
    match hook_source {
        Some(hook) if hook == ebpf::HOOK_XDP => direction_from_xdp(src_ip, dst_ip, gateway_ip),
        Some(hook) if hook == ebpf::HOOK_TC_EGRESS => {
            direction_from_tc_egress(src_ip, dst_ip, gateway_ip)
        }
        _ => direction_from_ip_fallback(src_ip, dst_ip, local_ips, gateway_ip),
    }
}

/// Determine direction from XDP (ingress) hook.
///
/// XDP captures packets coming INTO the interface.
fn direction_from_xdp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    gateway_ip: Option<Ipv4Addr>,
) -> Direction {
    let log_msg = if gateway_ip == Some(src_ip) {
        format!("INTERNET DOWNLOAD (from gateway) src={src_ip} dst={dst_ip}")
    } else {
        format!("DOWNLOAD (XDP hook) src={src_ip} dst={dst_ip}")
    };
    tracing::debug!("Direction: {log_msg}");
    Direction::Incoming
}

/// Determine direction from TC egress hook.
///
/// TC egress captures packets leaving the interface.
fn direction_from_tc_egress(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    gateway_ip: Option<Ipv4Addr>,
) -> Direction {
    let log_msg = if gateway_ip == Some(dst_ip) {
        format!("INTERNET UPLOAD (to gateway) src={src_ip} dst={dst_ip}")
    } else {
        format!("UPLOAD (TC egress hook) src={src_ip} dst={dst_ip}")
    };
    tracing::debug!("Direction: {log_msg}");
    Direction::Outgoing
}

/// Determine direction using IP-based fallback detection.
///
/// Used for pnet backend or unknown hooks.
fn direction_from_ip_fallback(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    local_ips: &HashSet<Ipv4Addr>,
    gateway_ip: Option<Ipv4Addr>,
) -> Direction {
    let src_is_local = local_ips.contains(&src_ip);
    let dst_is_local = local_ips.contains(&dst_ip);

    // Check for Internet traffic via gateway
    if let Some(gw) = gateway_ip {
        if src_is_local && dst_ip == gw {
            tracing::debug!(
                "Direction: INTERNET UPLOAD (IP-based) src={} -> dst={} (gateway)",
                src_ip,
                dst_ip
            );
            return Direction::Outgoing;
        }
        if src_ip == gw && dst_is_local {
            tracing::debug!(
                "Direction: INTERNET DOWNLOAD (IP-based) src={} (gateway) -> dst={}",
                src_ip,
                dst_ip
            );
            return Direction::Incoming;
        }
    }

    if src_is_local && dst_is_local {
        tracing::debug!(
            "LOCAL: src_ip={} (local) -> dst_ip={} (local)",
            src_ip,
            dst_ip
        );
        Direction::Local
    } else if src_is_local {
        tracing::debug!(
            "UPLOAD (IP-based): src_ip={} (local) -> dst_ip={} (remote)",
            src_ip,
            dst_ip
        );
        Direction::Outgoing
    } else if dst_is_local {
        tracing::debug!(
            "DOWNLOAD (IP-based): src_ip={} (remote) -> dst_ip={} (local)",
            src_ip,
            dst_ip
        );
        Direction::Incoming
    } else {
        Direction::None
    }
}

/// Calculate packet size in bits for bandwidth measurement.
///
/// # Arguments
/// * `ipv4_packet` - The IPv4 packet
/// * `original_len` - Optional original packet length from eBPF (kernel wire length)
///
/// # Returns
/// Packet size in bits
pub fn calculate_packet_size_bits(ipv4_packet: &Ipv4Packet, original_len: Option<u32>) -> u128 {
    use crate::constants::network;
    if let Some(len) = original_len {
        // eBPF path: use the accurate packet length from kernel
        // This is the full packet size as seen on the wire
        8 * len as u128
    } else {
        // pnet path: calculate from parsed payload
        // Use IPv4 total length (includes IP header + data) plus Ethernet header (14 bytes)
        // This ensures we count the full packet size on wire, matching eBPF behavior
        ((ipv4_packet.get_total_length() as u128) + network::ETHERNET_HEADER_SIZE as u128) * 8
    }
}

/// Create a TCP stat entry from an IPv4 packet.
///
/// # Arguments
/// * `ipv4_packet` - The IPv4 packet containing TCP data
/// * `direction` - The packet direction
/// * `size_bits` - Packet size in bits
///
/// # Returns
/// A StatItem if the TCP packet is valid, None otherwise
pub fn create_tcp_stat(
    ipv4_packet: &Ipv4Packet,
    direction: Direction,
    size_bits: u128,
) -> Option<StatItem> {
    let message = TcpPacket::new(ipv4_packet.payload())?;
    let flags = message.get_flags();

    Some(StatItem {
        key: StatKey {
            direction,
            src_port: message.get_source(),
            dst_port: message.get_destination(),
            src_ip: ipv4_packet.get_source(),
            dst_ip: ipv4_packet.get_destination(),
            protocol: PROTOCOL_TCP,
            tcp_syn: (flags & TCP_SYN) != 0,
            tcp_ack: (flags & TCP_ACK) != 0,
            tcp_fin: (flags & TCP_FIN) != 0,
            tcp_rst: (flags & TCP_RST) != 0,
        },
        value: StatValues {
            size: size_bits,
            last_timestamp: None, // Filled by listener_task
            last_seq: Some(message.get_sequence()),
            last_ack: Some(message.get_acknowledgement()),
        },
    })
}

/// Create a UDP stat entry from an IPv4 packet.
///
/// # Arguments
/// * `ipv4_packet` - The IPv4 packet containing UDP data
/// * `direction` - The packet direction
/// * `size_bits` - Packet size in bits
///
/// # Returns
/// A StatItem if the UDP packet is valid, None otherwise
pub fn create_udp_stat(
    ipv4_packet: &Ipv4Packet,
    direction: Direction,
    size_bits: u128,
) -> Option<StatItem> {
    let datagram = UdpPacket::new(ipv4_packet.payload())?;
    Some(StatItem {
        key: StatKey {
            direction,
            src_port: datagram.get_source(),
            dst_port: datagram.get_destination(),
            src_ip: ipv4_packet.get_source(),
            dst_ip: ipv4_packet.get_destination(),
            protocol: PROTOCOL_UDP,
            tcp_syn: false, // UDP doesn't have TCP flags
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        },
        value: StatValues {
            size: size_bits,
            last_timestamp: None,
            last_seq: None,
            last_ack: None,
        },
    })
}

/// Extract statistics from an IPv4 packet.
///
/// # Arguments
/// * `ethernet_packet` - The Ethernet packet containing IPv4 data
/// * `local_ips` - Set of local IP addresses for direction detection
/// * `gateway_ip` - Optional gateway IP for Internet traffic detection
/// * `hook_source` - Optional hook source from eBPF:
///   - Some(0) = XDP (ingress) → Download
///   - Some(2) = TC egress → Upload
///   - None = pnet backend (use IP-based direction detection)
/// * `original_len` - Original packet length from wire (eBPF provides this from kernel)
pub fn get_stats(
    ethernet_packet: &EthernetPacket,
    local_ips: &HashSet<Ipv4Addr>,
    gateway_ip: Option<Ipv4Addr>,
    hook_source: Option<u8>,
    original_len: Option<u32>,
) -> Option<StatItem> {
    let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
    let src_ip = ipv4_packet.get_source();
    let dst_ip = ipv4_packet.get_destination();
    let next_level_protocol = ipv4_packet.get_next_level_protocol();

    // Determine direction based on hook source (authoritative for eBPF)
    // or fall back to IP-based detection (for pnet backend)
    let direction = determine_packet_direction(src_ip, dst_ip, local_ips, gateway_ip, hook_source);

    // Calculate packet size in bits for bandwidth
    let size_bits = calculate_packet_size_bits(&ipv4_packet, original_len);

    // Log bandwidth calculation for eBPF path
    if let Some(len) = original_len {
        tracing::info!(
            "BANDWIDTH: original_len={} bytes -> {} bits direction={:?}",
            len,
            size_bits,
            direction
        );
    }

    // Only create stat for TCP/UDP (need ports for the key)
    match next_level_protocol {
        IpNextHeaderProtocols::Tcp => create_tcp_stat(&ipv4_packet, direction, size_bits),
        IpNextHeaderProtocols::Udp => create_udp_stat(&ipv4_packet, direction, size_bits),
        _ => None,
    }
}
