#![no_std]
#![no_main]

use aya_ebpf::programs::TcContext;
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_boot_ns,
    macros::{classifier, map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{arp::ArpHdr, eth::EthHdr, ip::IpProto, ip::Ipv4Hdr, tcp::TcpHdr};

// TC action return codes (not in bindings, define directly)
const TC_ACT_PIPE: i32 = 3;

/// Packet metadata extracted from headers
///
/// We parse headers in-kernel and extract only the fields needed
/// for host discovery and bandwidth monitoring.
#[repr(C)]
#[derive(Copy, Clone)]
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
    /// Valid flags: has_ip, has_arp
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

#[map]
static mut EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

/// Shared packet parsing logic - works with byte offsets (usize)
///
/// Returns None if packet is too short or headers can't be parsed.
unsafe fn parse_packet_from_bytes(data: usize, data_end: usize) -> Option<PacketEvent> {
    // Basic bounds check
    if data >= data_end {
        return None;
    }

    let packet_len = (data_end - data) as u32;

    // Default event values
    let mut event = PacketEvent {
        src_mac: [0; 6],
        dst_mac: [0; 6],
        ether_type: 0,
        src_ip: 0,
        dst_ip: 0,
        len: packet_len,
        protocol: 0,
        flags: 0,
        hook_source: 0, // Will be set by the caller
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        _padding: 0,
        timestamp_ns: 0,
        tcp_seq: 0,
        tcp_ack: 0,
    };

    // Parse Ethernet header at constant offset 0
    let eth_len = core::mem::size_of::<EthHdr>();
    if data + eth_len > data_end {
        return None;
    }
    let eth_hdr_ptr = data as *const EthHdr;
    let eth_hdr = &*eth_hdr_ptr;

    event.src_mac = eth_hdr.src_addr;
    event.dst_mac = eth_hdr.dst_addr;
    event.ether_type = u16::from_be(eth_hdr.ether_type);

    // Parse based on EtherType (constant offset: EthHdr::LEN = 14)
    match event.ether_type {
        // IPv4 (0x0800)
        0x0800 => {
            let ip_offset = 14; // EthHdr::LEN
            let ip_len = core::mem::size_of::<Ipv4Hdr>();
            if data + ip_offset + ip_len <= data_end {
                let ip_hdr_ptr = (data + ip_offset) as *const Ipv4Hdr;
                let ip_hdr = &*ip_hdr_ptr;
                event.src_ip = u32::from_be_bytes(ip_hdr.src_addr);
                event.dst_ip = u32::from_be_bytes(ip_hdr.dst_addr);
                event.protocol = ip_hdr.proto as u8;
                event.flags |= 1; // has_ip

                // Validate IP Header Length field (IHL)
                // IHL is the lower 4 bits, in 4-byte units. Valid range: 5-15
                let ihl_raw = ip_hdr.vihl & 0x0F;
                if ihl_raw < 5 || ihl_raw > 15 {
                    // Invalid IHL, skip this packet
                    return Some(event);
                }

                // Phase 1: Only support standard IP headers (no options)
                // Standard IPv4 header is 20 bytes (IHL=5)
                if ihl_raw != 5 {
                    // IP header has options - skip transport layer parsing
                    // Still count the packet for bandwidth monitoring
                    return Some(event);
                }

                // Use constant transport offset for BPF verifier compliance
                // Ethernet (14) + Standard IPv4 header (20) = 34
                const TRANSPORT_OFFSET: usize = 34;

                // TCP (protocol 6)
                if ip_hdr.proto == IpProto::Tcp {
                    // Minimum TCP header is 20 bytes
                    const TCP_MIN_HDR_SIZE: usize = 20;
                    if data + TRANSPORT_OFFSET + TCP_MIN_HDR_SIZE <= data_end {
                        let tcp_hdr = &*((data + TRANSPORT_OFFSET) as *const TcpHdr);

                        // Extract ports (stored as [u8; 2] in network_types)
                        event.src_port = u16::from_be_bytes(tcp_hdr.source);
                        event.dst_port = u16::from_be_bytes(tcp_hdr.dest);

                        // Extract sequence numbers
                        event.tcp_seq = u32::from_be_bytes(tcp_hdr.seq);
                        event.tcp_ack = u32::from_be_bytes(tcp_hdr.ack_seq);

                        // Extract TCP flags from byte 13 of TCP header
                        // TCP header structure: ports(4) + seq(4) + ack(4) + doff_res(1) + flags(1) + ...
                        // Flags are at offset 13 from start of TCP header
                        let tcp_bytes = (data + TRANSPORT_OFFSET) as *const u8;
                        if data + TRANSPORT_OFFSET + 14 <= data_end {
                            event.tcp_flags = unsafe { *tcp_bytes.add(13) };
                        }
                    }
                }
                // UDP (protocol 17)
                else if ip_hdr.proto == IpProto::Udp {
                    const UDP_HDR_SIZE: usize = 8;
                    if data + TRANSPORT_OFFSET + UDP_HDR_SIZE <= data_end {
                        // UDP header: src_port (2) + dst_port (2) + length (2) + checksum (2)
                        let src_port_ptr = (data + TRANSPORT_OFFSET) as *const u16;
                        let dst_port_ptr = (data + TRANSPORT_OFFSET + 2) as *const u16;
                        event.src_port = u16::from_be(unsafe { *src_port_ptr });
                        event.dst_port = u16::from_be(unsafe { *dst_port_ptr });
                    }
                }
            }
        }
        // ARP (0x0806)
        0x0806 => {
            let arp_offset = 14; // EthHdr::LEN
            let arp_len = core::mem::size_of::<ArpHdr>();
            if data + arp_offset + arp_len <= data_end {
                let arp_hdr_ptr = (data + arp_offset) as *const ArpHdr;
                let arp_hdr = &*arp_hdr_ptr;
                event.src_ip = u32::from_be_bytes(arp_hdr.spa);
                event.dst_ip = u32::from_be_bytes(arp_hdr.tpa);
                event.flags |= 2; // has_arp
            }
        }
        _ => {}
    }

    // Capture kernel timestamp for RTT calculation
    event.timestamp_ns = bpf_ktime_get_boot_ns();

    Some(event)
}

#[xdp]
pub fn xdp_netui(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_netui(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// XDP program entry point
unsafe fn try_xdp_netui(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse packet using shared logic
    let mut event = match parse_packet_from_bytes(data, data_end) {
        Some(e) => e,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // Set hook source to XDP
    event.hook_source = 0;

    // Log for debugging
    info!(
        &ctx,
        "XDP: len={} src_ip={:x} dst_ip={:x} proto={}",
        event.len,
        event.src_ip,
        event.dst_ip,
        event.protocol
    );

    // Send event to userspace via PerfEventArray
    // SAFETY: BPF verifier ensures single-threaded access to maps
    #[allow(static_mut_refs)]
    EVENTS.output(&ctx, &event, 0);

    // Pass all packets through to the network stack
    Ok(xdp_action::XDP_PASS)
}

/// TC ingress program entry point
///
/// Captures packets arriving at the interface (additional ingress coverage
/// beyond XDP, and works on systems where XDP may not be available).
#[classifier]
pub fn tc_ingress_netui(ctx: TcContext) -> i32 {
    match unsafe { try_tc_netui(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

/// TC egress program entry point
///
/// Captures packets leaving the interface - THIS IS THE KEY FOR UPLOAD BANDWIDTH!
/// XDP only sees ingress (download), so we need TC egress to capture upload traffic.
#[classifier]
pub fn tc_egress_netui(ctx: TcContext) -> i32 {
    match unsafe { try_tc_netui(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

/// TC program handler that uses shared packet parsing
///
/// # Safety
/// Uses parse_packet_from_bytes with constant offsets for BPF verifier compliance.
unsafe fn try_tc_netui(ctx: TcContext) -> Result<i32, i32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse packet using shared logic
    let mut event = match parse_packet_from_bytes(data, data_end) {
        Some(e) => e,
        None => return Ok(TC_ACT_PIPE),
    };

    // Set hook source to TC egress (2) - we only use egress for upload bandwidth
    event.hook_source = 2;

    // IMPORTANT: For TC programs (SKB), data_end - data only covers the linear part
    // of the packet. For correct bandwidth calculation, we MUST use ctx.len()
    // which includes the full length of the packet (including paged data).
    event.len = ctx.len();

    // Log for debugging (disabled for production)
    // info!(
    //     &ctx,
    //     "TC: len={} src_ip={:x} dst_ip={:x} proto={}",
    //     event.len,
    //     event.src_ip,
    //     event.dst_ip,
    //     event.protocol
    // );

    // Send event to userspace via PerfEventArray
    // SAFETY: BPF verifier ensures single-threaded access to maps
    #[allow(static_mut_refs)]
    EVENTS.output(&ctx, &event, 0);

    // Allow packet to continue processing
    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
