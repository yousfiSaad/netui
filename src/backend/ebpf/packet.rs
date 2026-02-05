//! eBPF packet event parsing and reconstruction.
//!
//! This module handles safe parsing of packet events received from the eBPF
//! PerfEventArray and reconstruction of Ethernet packets for compatibility
//! with the existing packet processor.

use crate::constants::network;
use bytes::BytesMut;

/// Packet event structure - must match the eBPF side definition.
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
    /// Which hook captured this: 0=XDP, 1=TC ingress, 2=TC egress
    pub hook_source: u8,
    /// Transport layer: source port (TCP/UDP)
    pub src_port: u16,
    /// Transport layer: destination port (TCP/UDP)
    pub dst_port: u16,
    /// TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04)
    pub tcp_flags: u8,
    /// Reserved/padding
    pub _padding: u8,
    /// Kernel timestamp in nanoseconds (for RTT calculation)
    pub timestamp_ns: u64,
    /// TCP sequence number
    pub tcp_seq: u32,
    /// TCP acknowledgment number
    pub tcp_ack: u32,
}

impl PacketEvent {
    /// Check if this event has IP header data.
    pub fn has_ip(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Check if this event has ARP data.
    pub fn has_arp(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// Safely parse a PacketEvent from a raw buffer received from eBPF kernel space.
///
/// # Safety
/// The unsafe block inside this function is safe because:
/// 1. We validate the buffer size matches `sizeof(PacketEvent)` before dereferencing
/// 2. `PacketEvent` is marked with `#[repr(C)]`, guaranteeing stable memory layout
/// 3. The eBPF program writes the same struct definition (ensured by build-time inclusion)
/// 4. We only create a reference (`&*event_ptr`) with the same lifetime as the input buffer
///
/// # Arguments
/// * `packet_buf` - Buffer containing raw bytes from the perf event array
///
/// # Returns
/// * `Some(&PacketEvent)` if the buffer is valid and contains a complete PacketEvent
/// * `None` if the buffer is too small or malformed
pub fn parse_packet_event(packet_buf: &mut BytesMut) -> Option<&PacketEvent> {
    let event_size = std::mem::size_of::<PacketEvent>();
    if packet_buf.len() < event_size {
        tracing::warn!(
            "Buffer too small for PacketEvent: got {} bytes, need {} bytes",
            packet_buf.len(),
            event_size
        );
        return None;
    }

    // Safety: The buffer size is validated above, and PacketEvent is #[repr(C)]
    // which guarantees the layout matches the eBPF side definition.
    // The eBPF program uses the exact same struct definition (included at build time).
    unsafe {
        let event_ptr = packet_buf.as_ptr() as *const PacketEvent;
        Some(&*event_ptr)
    }
}

/// Reconstruct an Ethernet packet from eBPF-extracted metadata.
///
/// The eBPF program extracts only the headers it needs for statistics. To maintain
/// compatibility with the existing packet parser, we reconstruct a minimal Ethernet
/// packet with proper IP header length fields or ARP header for ARP packets.
///
/// # Arguments
/// * `event` - The PacketEvent containing extracted metadata from eBPF
///
/// # Returns
/// A vector of bytes representing the reconstructed Ethernet packet
pub fn reconstruct_ethernet_packet(event: &PacketEvent) -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&event.dst_mac);
    packet.extend_from_slice(&event.src_mac);
    packet.extend_from_slice(&event.ether_type.to_be_bytes());

    // Add IP header with correct total_length and padding (if IP flag is set)
    if event.has_ip() {
        // Calculate IP total length (excluding 14-byte Ethernet header)
        // Clamp to u16::MAX for safety
        let ip_total_len = (event
            .len
            .saturating_sub(network::ETHERNET_HEADER_SIZE as u32)
            as u16)
            .min(u16::MAX);

        // Minimum IPv4 header (20 bytes)
        let mut ip_header = [0u8; network::MIN_IPV4_HEADER_SIZE];
        ip_header[0] = 0x45; // Version=4, IHL=5 (20 bytes)
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

        // Add TCP/UDP headers if present
        if event.protocol == 6 {
            // TCP header (20 bytes minimum)
            let mut tcp_header = [0u8; 20];

            // Bytes 0-1: Source port
            tcp_header[0] = (event.src_port >> 8) as u8;
            tcp_header[1] = event.src_port as u8;

            // Bytes 2-3: Destination port
            tcp_header[2] = (event.dst_port >> 8) as u8;
            tcp_header[3] = event.dst_port as u8;

            // Bytes 4-7: Sequence number
            tcp_header[4..8].copy_from_slice(&event.tcp_seq.to_be_bytes());

            // Bytes 8-11: Acknowledgment number
            tcp_header[8..12].copy_from_slice(&event.tcp_ack.to_be_bytes());

            // Byte 12: Data offset (5 * 4 = 20 bytes)
            tcp_header[12] = 5 << 4;

            // Byte 13: TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04)
            tcp_header[13] = event.tcp_flags;

            // Bytes 14-15: Window size (placeholder)
            tcp_header[14..16].copy_from_slice(&65535u16.to_be_bytes());

            // Bytes 16-17: Checksum (placeholder - would need proper calculation)
            tcp_header[16] = 0;
            tcp_header[17] = 0;

            // Bytes 18-19: Urgent pointer (unused)
            tcp_header[18] = 0;
            tcp_header[19] = 0;

            packet.extend_from_slice(&tcp_header);
        }

        // Pad packet to match the IP total_length
        // This ensures the parser sees correct payload size for bandwidth calculation
        let current_len = packet.len();
        let target_total_len = ip_total_len as usize + network::ETHERNET_HEADER_SIZE as usize;
        if current_len < target_total_len {
            let padding_size = target_total_len - current_len;
            packet.resize(current_len + padding_size, 0);
        }
    } else if event.has_arp() {
        // Reconstruct ARP header for host discovery
        // ARP header format (28 bytes minimum):
        // Hardware type (2) | Protocol type (2) | HW addr len (1) | Proto addr len (1) | Operation (2)
        // Sender HW addr (6) | Sender IP (4) | Target HW addr (6) | Target IP (4)

        // Hardware type: Ethernet (1)
        packet.extend_from_slice(&1u16.to_be_bytes());
        // Protocol type: IPv4 (0x0800)
        packet.extend_from_slice(&0x0800u16.to_be_bytes());
        // Hardware address length: 6 (MAC)
        packet.push(6);
        // Protocol address length: 4 (IPv4)
        packet.push(4);
        // Operation: Reply (2) - we only care about replies for host discovery
        packet.extend_from_slice(&2u16.to_be_bytes());
        // Sender MAC address
        packet.extend_from_slice(&event.src_mac);
        // Sender IP address
        packet.extend_from_slice(&event.src_ip.to_be_bytes());
        // Target MAC address (broadcast for requests, but we use what we have)
        packet.extend_from_slice(&event.dst_mac);
        // Target IP address
        packet.extend_from_slice(&event.dst_ip.to_be_bytes());
    }

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_event_has_ip() {
        let event = PacketEvent {
            flags: 1, // has_ip flag set
            ..Default::default()
        };
        assert!(event.has_ip());
        assert!(!event.has_arp());
    }

    #[test]
    fn test_packet_event_has_arp() {
        let event = PacketEvent {
            flags: 2, // has_arp flag set
            ..Default::default()
        };
        assert!(!event.has_ip());
        assert!(event.has_arp());
    }

    #[test]
    fn test_parse_packet_event_too_small() {
        let mut buf = BytesMut::with_capacity(10);
        assert!(parse_packet_event(&mut buf).is_none());
    }

    #[test]
    fn test_reconstruct_ethernet_packet_basic() {
        let event = PacketEvent {
            dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            src_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ether_type: 0x0800, // IPv4
            len: 100,
            flags: 0,
            ..Default::default()
        };

        let packet = reconstruct_ethernet_packet(&event);

        // Should have Ethernet header (14 bytes)
        assert!(packet.len() >= 14);
        assert_eq!(packet[0..6], event.dst_mac);
        assert_eq!(packet[6..12], event.src_mac);
    }

    #[test]
    fn test_reconstruct_arp_packet() {
        let event = PacketEvent {
            dst_mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // Broadcast
            src_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ether_type: 0x0806, // ARP
            src_ip: u32::from_be_bytes([192, 168, 1, 10]),
            dst_ip: u32::from_be_bytes([192, 168, 1, 1]),
            len: 42,  // Ethernet (14) + ARP (28)
            flags: 2, // has_arp
            ..Default::default()
        };

        let packet = reconstruct_ethernet_packet(&event);

        // Should have Ethernet header (14 bytes) + ARP header (28 bytes) = 42 bytes
        assert_eq!(packet.len(), 42);

        // Verify Ethernet header
        assert_eq!(packet[0..6], event.dst_mac);
        assert_eq!(packet[6..12], event.src_mac);

        // Verify ARP header starts at offset 14
        // Hardware type (1 = Ethernet)
        assert_eq!(packet[14], 0);
        assert_eq!(packet[15], 1);
        // Protocol type (0x0800 = IPv4)
        assert_eq!(packet[16], 0x08);
        assert_eq!(packet[17], 0);
        // Hardware address length (6)
        assert_eq!(packet[18], 6);
        // Protocol address length (4)
        assert_eq!(packet[19], 4);
        // Operation (2 = Reply)
        assert_eq!(packet[20], 0);
        assert_eq!(packet[21], 2);

        // Verify sender MAC at offset 22
        assert_eq!(packet[22..28], event.src_mac);
        // Verify sender IP at offset 28
        assert_eq!(packet[28..32], event.src_ip.to_be_bytes());
    }
}

impl Default for PacketEvent {
    fn default() -> Self {
        Self {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ether_type: 0,
            src_ip: 0,
            dst_ip: 0,
            len: 0,
            protocol: 0,
            flags: 0,
            hook_source: 0,
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            _padding: 0,
            timestamp_ns: 0,
            tcp_seq: 0,
            tcp_ack: 0,
        }
    }
}
