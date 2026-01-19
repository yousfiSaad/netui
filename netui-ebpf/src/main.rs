#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, arp::ArpHdr};

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
}

#[map]
static mut EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[xdp]
pub fn xdp_netui(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_netui(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Helper function for bounds-checked pointer access
///
/// This generic version works with any type T and uses constant offsets,
/// which the BPF verifier can prove safe.
///
/// # Arguments
/// * `ctx` - The XDP context
/// * `offset` - Byte offset from start of packet (must be constant)
///
/// # Returns
/// * `Ok(*const T)` - Pointer to type T at offset if in bounds
/// * `Err(())` - Offset would exceed packet bounds
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/// XDP program that extracts packet headers and sends metadata to userspace
///
/// This parses Ethernet, IPv4, and ARP headers at constant offsets
/// to extract MAC and IP addresses for host discovery and bandwidth tracking.
///
/// # Safety
/// Uses ptr_at helper with constant offsets for BPF verifier compliance.
unsafe fn try_xdp_netui(ctx: XdpContext) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    let data = ctx.data();

    // Basic bounds check
    if data >= data_end {
        return Ok(xdp_action::XDP_PASS);
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
    };

    // Parse Ethernet header at constant offset 0
    // If packet is too short, just pass it through
    let eth_hdr_ptr = match ptr_at::<EthHdr>(&ctx, 0) {
        Ok(ptr) => ptr,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };
    let eth_hdr = &*eth_hdr_ptr;

    event.src_mac = eth_hdr.src_addr;
    event.dst_mac = eth_hdr.dst_addr;
    event.ether_type = u16::from_be(eth_hdr.ether_type);

    // Parse based on EtherType (constant offset: EthHdr::LEN = 14)
    match event.ether_type {
        // IPv4 (0x0800)
        0x0800 => {
            if let Ok(ip_hdr_ptr) = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN) {
                let ip_hdr = &*ip_hdr_ptr;
                event.src_ip = u32::from_be_bytes(ip_hdr.src_addr);
                event.dst_ip = u32::from_be_bytes(ip_hdr.dst_addr);
                // Convert IpProto enum to u8
                event.protocol = ip_hdr.proto as u8;
                event.flags |= 1; // has_ip
            }
        }
        // ARP (0x0806)
        0x0806 => {
            if let Ok(arp_hdr_ptr) = ptr_at::<ArpHdr>(&ctx, EthHdr::LEN) {
                let arp_hdr = &*arp_hdr_ptr;
                event.src_ip = u32::from_be_bytes(arp_hdr.spa);
                event.dst_ip = u32::from_be_bytes(arp_hdr.tpa);
                event.flags |= 2; // has_arp
            }
        }
        _ => {}
    }

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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
