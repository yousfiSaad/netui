#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp, classifier},
    maps::PerfEventArray,
    programs::XdpContext,
};
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, arp::ArpHdr};

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
}

#[map]
static mut EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

/// Shared packet parsing logic - works with byte offsets (usize)
///
/// Returns None if packet is too short or headers can't be parsed.
unsafe fn parse_packet_from_bytes(
    data: usize,
    data_end: usize,
) -> Option<PacketEvent> {
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
    let packet_len = event.len;

    // Log for debugging
    info!(
        &ctx,
        "XDP: len={} src_ip={:x} dst_ip={:x} proto={}",
        packet_len,
        event.src_ip,
        event.dst_ip,
        event.protocol
    );

    // Send event to userspace via PerfEventArray
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
    let packet_len = event.len;

    // Log for debugging
    info!(
        &ctx,
        "TC: len={} src_ip={:x} dst_ip={:x} proto={}",
        packet_len,
        event.src_ip,
        event.dst_ip,
        event.protocol
    );

    // Send event to userspace via PerfEventArray
    EVENTS.output(&ctx, &event, 0);

    // Allow packet to continue processing
    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
