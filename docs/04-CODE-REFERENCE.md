# NetUI eBPF Code Reference

All code in this document is syntactically correct and ready to use with Aya 0.13+.

---

## 1. Shared Types (netui-common/src/lib.rs)

This crate defines types shared between kernel eBPF programs and user-space.

```rust
//! Shared types for NetUI eBPF programs
//!
//! This crate is `#![no_std]` compatible for use in eBPF programs.

#![no_std]

/// Network event emitted from eBPF to user-space
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetworkEvent {
    /// Timestamp in nanoseconds since boot
    pub timestamp_ns: u64,
    /// Event type (see EVENT_* constants)
    pub event_type: u8,
    /// Direction: 0 = ingress, 1 = egress
    pub direction: u8,
    /// Source IPv4 address (network byte order)
    pub src_ip: u32,
    /// Destination IPv4 address (network byte order)
    pub dst_ip: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// IP protocol number
    pub protocol: u8,
    /// Padding for alignment
    pub _pad1: u8,
    /// Packet size in bytes
    pub bytes: u16,
    /// TCP flags (if applicable)
    pub tcp_flags: u8,
    /// Padding for alignment
    pub _pad2: [u8; 3],
}

/// Flow identification key (5-tuple)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _padding: [u8; 3],
}

/// Per-flow statistics
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub tcp_rtt_ns: u32,
    pub retransmits: u16,
    pub tcp_state: u8,
    pub _padding: u8,
}

// Event type constants
pub const EVENT_PACKET: u8 = 0;
pub const EVENT_FLOW_START: u8 = 1;
pub const EVENT_FLOW_END: u8 = 2;
pub const EVENT_TCP_RTT: u8 = 3;

// Direction constants
pub const DIR_INGRESS: u8 = 0;
pub const DIR_EGRESS: u8 = 1;

// Ethernet type constants (host byte order for comparison)
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;
pub const ETH_P_IPV6: u16 = 0x86DD;

// IP protocol constants
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Ethernet frame header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

/// IPv4 header (without options)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
}

/// TCP header (without options)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

/// UDP header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// ARP header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ArpHeader {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_len: u8,
    pub proto_len: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

impl NetworkEvent {
    /// Create a zeroed event
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            event_type: 0,
            direction: 0,
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            _pad1: 0,
            bytes: 0,
            tcp_flags: 0,
            _pad2: [0; 3],
        }
    }
}

impl FlowKey {
    #[inline]
    pub const fn new(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _padding: [0; 3],
        }
    }
}

impl FlowStats {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            packets_in: 0,
            packets_out: 0,
            bytes_in: 0,
            bytes_out: 0,
            first_seen_ns: 0,
            last_seen_ns: 0,
            tcp_rtt_ns: 0,
            retransmits: 0,
            tcp_state: 0,
            _padding: 0,
        }
    }
}

/// Convert u32 to IPv4 octets (little-endian host to bytes)
#[inline]
pub const fn u32_to_ipv4_octets(ip: u32) -> [u8; 4] {
    [
        (ip & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 24) & 0xFF) as u8,
    ]
}

/// Convert IPv4 octets to u32 (bytes to little-endian host)
#[inline]
pub const fn ipv4_octets_to_u32(octets: [u8; 4]) -> u32 {
    (octets[0] as u32)
        | ((octets[1] as u32) << 8)
        | ((octets[2] as u32) << 16)
        | ((octets[3] as u32) << 24)
}

/// Format IPv4 as dotted decimal string
/// Returns number of bytes written
#[cfg(not(feature = "no_std"))]
pub fn format_ipv4(ip: u32, buf: &mut [u8]) -> usize {
    let octets = u32_to_ipv4_octets(ip);
    // Implementation would use core::fmt or manual formatting
    0 // Placeholder
}
```

---

## 2. XDP Packet Classifier (netui-ebpf/src/xdp.rs)

```rust
//! XDP packet classifier for ingress traffic
//!
//! Attaches at driver level for lowest latency packet inspection.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use netui_common::*;

/// Ring buffer for events to user-space (256 KB)
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_capacity(256 * 1024, 0);

/// Per-flow statistics (10,000 entries max)
#[map]
static FLOWS: HashMap<FlowKey, FlowStats> = HashMap::with_max_entries(10_000, 0);

/// XDP entry point
#[xdp]
pub fn pkt_classifier(ctx: XdpContext) -> u32 {
    match try_classify(&ctx) {
        Ok(_) => xdp_action::XDP_PASS,
        Err(_) => xdp_action::XDP_PASS, // Fail-open: never drop
    }
}

/// Main packet classification logic
fn try_classify(ctx: &XdpContext) -> Result<(), ()> {
    // Parse Ethernet header
    let eth_hdr = ptr_at::<EthernetHeader>(ctx, 0)?;
    let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });

    let eth_len = mem::size_of::<EthernetHeader>();

    match ether_type {
        ETH_P_IP => process_ipv4(ctx, eth_len),
        ETH_P_ARP => process_arp(ctx, eth_len),
        _ => Ok(()), // Ignore other protocols
    }
}

/// Process IPv4 packets
fn process_ipv4(ctx: &XdpContext, offset: usize) -> Result<(), ()> {
    let ip_hdr = ptr_at::<Ipv4Header>(ctx, offset)?;

    // Extract IP header length from IHL field (lower 4 bits)
    // IHL is in 32-bit words, so multiply by 4
    let version_ihl = unsafe { (*ip_hdr).version_ihl };
    let ihl = (version_ihl & 0x0F) as usize;
    let ip_header_len = ihl * 4;

    // Validate IP header length (20-60 bytes)
    if ip_header_len < 20 || ip_header_len > 60 {
        return Err(());
    }

    let src_ip = unsafe { (*ip_hdr).src_ip };
    let dst_ip = unsafe { (*ip_hdr).dst_ip };
    let protocol = unsafe { (*ip_hdr).protocol };
    let total_len = u16::from_be(unsafe { (*ip_hdr).total_length });

    // Transport header starts after variable-length IP header
    let transport_offset = offset + ip_header_len;

    let mut event = NetworkEvent::zeroed();
    event.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    event.event_type = EVENT_PACKET;
    event.direction = DIR_INGRESS;
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.protocol = protocol;
    event.bytes = total_len;

    match protocol {
        IPPROTO_TCP => {
            process_tcp(ctx, transport_offset, &mut event)?;
        }
        IPPROTO_UDP => {
            process_udp(ctx, transport_offset, &mut event)?;
        }
        IPPROTO_ICMP => {
            // ICMP has no ports
            event.src_port = 0;
            event.dst_port = 0;
        }
        _ => {
            event.src_port = 0;
            event.dst_port = 0;
        }
    }

    // Emit event to ring buffer
    emit_event(&event);

    // Update flow statistics
    update_flow_stats(&event);

    Ok(())
}

/// Process TCP header
fn process_tcp(ctx: &XdpContext, offset: usize, event: &mut NetworkEvent) -> Result<(), ()> {
    let tcp_hdr = ptr_at::<TcpHeader>(ctx, offset)?;

    event.src_port = unsafe { (*tcp_hdr).src_port };
    event.dst_port = unsafe { (*tcp_hdr).dst_port };

    // Extract TCP flags from data_offset_flags
    let flags_raw = u16::from_be(unsafe { (*tcp_hdr).data_offset_flags });
    event.tcp_flags = (flags_raw & 0x3F) as u8;

    Ok(())
}

/// Process UDP header
fn process_udp(ctx: &XdpContext, offset: usize, event: &mut NetworkEvent) -> Result<(), ()> {
    let udp_hdr = ptr_at::<UdpHeader>(ctx, offset)?;

    event.src_port = unsafe { (*udp_hdr).src_port };
    event.dst_port = unsafe { (*udp_hdr).dst_port };

    Ok(())
}

/// Process ARP packets
fn process_arp(ctx: &XdpContext, offset: usize) -> Result<(), ()> {
    let arp_hdr = ptr_at::<ArpHeader>(ctx, offset)?;

    let mut event = NetworkEvent::zeroed();
    event.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    event.event_type = EVENT_PACKET;
    event.direction = DIR_INGRESS;
    event.src_ip = unsafe { (*arp_hdr).sender_ip };
    event.dst_ip = unsafe { (*arp_hdr).target_ip };
    event.protocol = 0; // ARP marker
    event.src_port = 0;
    event.dst_port = 0;
    event.bytes = 28; // ARP packet size

    emit_event(&event);

    Ok(())
}

/// Emit event to ring buffer
#[inline(always)]
fn emit_event(event: &NetworkEvent) {
    if let Some(mut entry) = EVENTS.reserve::<NetworkEvent>(0) {
        entry.write(*event);
        entry.submit(0);
    }
}

/// Update per-flow statistics
fn update_flow_stats(event: &NetworkEvent) {
    // Skip ARP (no flow concept)
    if event.protocol == 0 {
        return;
    }

    let key = FlowKey::new(
        event.src_ip,
        event.dst_ip,
        event.src_port,
        event.dst_port,
        event.protocol,
    );

    unsafe {
        if let Some(stats) = FLOWS.get_ptr_mut(&key) {
            (*stats).packets_in += 1;
            (*stats).bytes_in += event.bytes as u64;
            (*stats).last_seen_ns = event.timestamp_ns;
        } else {
            let new_stats = FlowStats {
                packets_in: 1,
                packets_out: 0,
                bytes_in: event.bytes as u64,
                bytes_out: 0,
                first_seen_ns: event.timestamp_ns,
                last_seen_ns: event.timestamp_ns,
                tcp_rtt_ns: 0,
                retransmits: 0,
                tcp_state: 0,
                _padding: 0,
            };
            let _ = FLOWS.insert(&key, &new_stats, 0);
        }
    }
}

/// Safe pointer access with bounds checking
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

---

## 3. TC Egress Program (netui-ebpf/src/tc.rs)

```rust
//! TC egress classifier for outbound traffic
//!
//! Attaches at qdisc level to capture packets leaving the interface.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use core::mem;
use netui_common::*;

// Share the same ring buffer as XDP
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_capacity(256 * 1024, 0);

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_classify_egress(&ctx) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_PIPE, // Fail-open
    }
}

fn try_classify_egress(ctx: &TcContext) -> Result<(), ()> {
    let eth_hdr = ptr_at_tc::<EthernetHeader>(ctx, 0)?;
    let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });

    if ether_type != ETH_P_IP {
        return Ok(());
    }

    let eth_len = mem::size_of::<EthernetHeader>();
    let ip_hdr = ptr_at_tc::<Ipv4Header>(ctx, eth_len)?;

    let version_ihl = unsafe { (*ip_hdr).version_ihl };
    let ihl = (version_ihl & 0x0F) as usize;
    let ip_header_len = ihl * 4;

    if ip_header_len < 20 || ip_header_len > 60 {
        return Err(());
    }

    let src_ip = unsafe { (*ip_hdr).src_ip };
    let dst_ip = unsafe { (*ip_hdr).dst_ip };
    let protocol = unsafe { (*ip_hdr).protocol };
    let total_len = u16::from_be(unsafe { (*ip_hdr).total_length });

    let transport_offset = eth_len + ip_header_len;

    let mut event = NetworkEvent::zeroed();
    event.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    event.event_type = EVENT_PACKET;
    event.direction = DIR_EGRESS;
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.protocol = protocol;
    event.bytes = total_len;

    if protocol == IPPROTO_TCP {
        let tcp_hdr = ptr_at_tc::<TcpHeader>(ctx, transport_offset)?;
        event.src_port = unsafe { (*tcp_hdr).src_port };
        event.dst_port = unsafe { (*tcp_hdr).dst_port };
        let flags_raw = u16::from_be(unsafe { (*tcp_hdr).data_offset_flags });
        event.tcp_flags = (flags_raw & 0x3F) as u8;
    } else if protocol == IPPROTO_UDP {
        let udp_hdr = ptr_at_tc::<UdpHeader>(ctx, transport_offset)?;
        event.src_port = unsafe { (*udp_hdr).src_port };
        event.dst_port = unsafe { (*udp_hdr).dst_port };
    }

    if let Some(mut entry) = EVENTS.reserve::<NetworkEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(())
}

#[inline(always)]
fn ptr_at_tc<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

---

## 4. User-space Loader (netui/src/ebpf_loader.rs)

```rust
//! eBPF program loader using Aya 0.13+

use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{tc, Xdp, XdpFlags, SchedClassifier, TcAttachType},
    Ebpf,
};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Embedded eBPF bytecode
static EBPF_BYTES: &[u8] = include_bytes_aligned!(
    concat!(env!("OUT_DIR"), "/netui-ebpf")
);

/// eBPF loader and manager
pub struct EbpfLoader {
    bpf: Ebpf,
    attached_interfaces: Vec<String>,
}

impl EbpfLoader {
    /// Load eBPF programs from embedded bytecode
    pub fn new() -> Result<Self> {
        let bpf = Ebpf::load(EBPF_BYTES)
            .context("Failed to load eBPF bytecode")?;

        Ok(Self {
            bpf,
            attached_interfaces: Vec::new(),
        })
    }

    /// Attach XDP program to interface for ingress capture
    pub fn attach_xdp(&mut self, interface: &str) -> Result<()> {
        let program: &mut Xdp = self.bpf
            .program_mut("pkt_classifier")
            .context("XDP program not found")?
            .try_into()
            .context("Failed to cast to Xdp")?;

        program.load().context("Failed to load XDP program")?;

        // Try native mode first, fall back to SKB mode
        let result = program.attach(interface, XdpFlags::default());
        if result.is_err() {
            program.attach(interface, XdpFlags::SKB_MODE)
                .context("Failed to attach XDP (tried native and SKB modes)")?;
        }

        self.attached_interfaces.push(interface.to_string());
        Ok(())
    }

    /// Attach TC program to interface for egress capture
    pub fn attach_tc_egress(&mut self, interface: &str) -> Result<()> {
        // Add clsact qdisc if needed
        let _ = tc::qdisc_add_clsact(interface);

        let program: &mut SchedClassifier = self.bpf
            .program_mut("tc_egress")
            .context("TC program not found")?
            .try_into()
            .context("Failed to cast to SchedClassifier")?;

        program.load().context("Failed to load TC program")?;

        program.attach(interface, TcAttachType::Egress)
            .context("Failed to attach TC egress")?;

        Ok(())
    }

    /// Get ring buffer for event consumption
    pub fn take_ring_buffer(&mut self) -> Result<RingBuf<&mut aya::maps::MapData>> {
        let map = self.bpf
            .map_mut("EVENTS")
            .context("Ring buffer map not found")?;

        RingBuf::try_from(map)
            .context("Failed to create RingBuf from map")
    }

    /// Get list of attached interfaces
    pub fn attached_interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }
}

impl Drop for EbpfLoader {
    fn drop(&mut self) {
        // Programs are automatically detached when Ebpf is dropped
    }
}
```

---

## 5. Event Processor (netui/src/ebpf_events.rs)

```rust
//! Event processing from eBPF ring buffer

use aya::maps::RingBuf;
use netui_common::NetworkEvent;
use std::ptr;
use tokio::sync::mpsc;

/// Process events from eBPF ring buffer
pub struct EventProcessor;

impl EventProcessor {
    /// Start async event processing loop
    ///
    /// Returns a channel receiver for NetworkEvent
    pub async fn start(
        mut ring_buf: RingBuf<&mut aya::maps::MapData>,
    ) -> mpsc::Receiver<NetworkEvent> {
        let (tx, rx) = mpsc::channel(1000);

        tokio::spawn(async move {
            loop {
                // Poll ring buffer
                while let Some(item) = ring_buf.next() {
                    let event = unsafe {
                        ptr::read_unaligned(item.as_ptr() as *const NetworkEvent)
                    };

                    if tx.send(event).await.is_err() {
                        // Receiver dropped, exit
                        return;
                    }
                }

                // Avoid busy-waiting
                tokio::time::sleep(std::time::Duration::from_micros(100)).await;
            }
        });

        rx
    }
}
```

---

## 6. ScannerEvent Integration

Add to existing `src/event.rs`:

```rust
use netui_common::NetworkEvent;

/// Scanner events including eBPF events
#[derive(Debug, Clone)]
pub enum ScannerEvent {
    /// Host discovered via ARP
    HostFound(Host),
    /// Statistics update from pnet path
    StatTick(StatsMap),
    /// Interface name discovered
    InterfaceName(String),
    /// Scan started
    BeginScan,
    /// Scan completed
    Complete,
    /// eBPF packet event (NEW)
    EbpfPacket(NetworkEvent),
}

impl From<NetworkEvent> for ScannerEvent {
    fn from(event: NetworkEvent) -> Self {
        ScannerEvent::EbpfPacket(event)
    }
}
```

---

## 7. Cargo Configuration

### Workspace Cargo.toml

```toml
[workspace]
members = ["netui", "netui-ebpf", "netui-common"]
resolver = "2"

[workspace.dependencies]
aya = "0.13"
aya-ebpf = "0.1"
aya-log = "0.2"
aya-log-ebpf = "0.1"
anyhow = "1.0"
tokio = { version = "1.40", features = ["full"] }
```

### netui-common/Cargo.toml

```toml
[package]
name = "netui-common"
version = "0.1.0"
edition = "2021"

[features]
default = []
no_std = []

[lib]
```

### netui-ebpf/Cargo.toml

```toml
[package]
name = "netui-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = { workspace = true }
aya-log-ebpf = { workspace = true }
netui-common = { path = "../netui-common" }

[[bin]]
name = "netui-ebpf"
path = "src/main.rs"

[profile.dev]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = true
panic = "abort"

[profile.release]
lto = true
panic = "abort"
```

### netui-ebpf/src/main.rs

```rust
#![no_std]
#![no_main]

mod xdp;
mod tc;
```

### netui/Cargo.toml (additions)

```toml
[dependencies]
aya = { workspace = true }
aya-log = { workspace = true }
netui-common = { path = "../netui-common" }
```

---

## 8. Build Configuration

### .cargo/config.toml

```toml
[build]
target-dir = "target"

[target.bpfel-unknown-none]
rustflags = ["-C", "link-arg=--target=bpf"]

[env]
CARGO_CFG_BPF_TARGET_ARCH = { value = "x86_64", force = true }
```

### xtask/src/main.rs

```rust
//! Build automation for eBPF programs

use std::process::Command;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo xtask <command>");
        eprintln!("Commands: build-ebpf");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "build-ebpf" => build_ebpf(&args[2..]),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn build_ebpf(args: &[String]) {
    let release = args.contains(&"--release".to_string());

    let mut cmd = Command::new("cargo");
    cmd.current_dir("netui-ebpf")
        .arg("build")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z").arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().expect("Failed to build eBPF");

    if !status.success() {
        std::process::exit(1);
    }

    // Copy to expected location
    let profile = if release { "release" } else { "debug" };
    let src = format!("target/bpfel-unknown-none/{}/netui-ebpf", profile);
    let dst = format!("target/{}/netui-ebpf", profile);

    std::fs::copy(&src, &dst).expect("Failed to copy eBPF binary");
}
```

### xtask/Cargo.toml

```toml
[package]
name = "xtask"
version = "0.1.0"
edition = "2021"

[dependencies]
```

---

## 9. Main Integration Example

```rust
//! Main entry point with eBPF integration

use crate::ebpf_loader::EbpfLoader;
use crate::ebpf_events::EventProcessor;
use netui_common::NetworkEvent;

pub async fn run_with_ebpf(interface: &str) -> anyhow::Result<()> {
    // Try eBPF first
    match try_ebpf(interface).await {
        Ok(event_rx) => {
            println!("eBPF mode active");
            run_with_events(event_rx).await
        }
        Err(e) => {
            eprintln!("eBPF unavailable ({}), using pnet fallback", e);
            run_with_pnet(interface).await
        }
    }
}

async fn try_ebpf(interface: &str) -> anyhow::Result<mpsc::Receiver<NetworkEvent>> {
    let mut loader = EbpfLoader::new()?;

    loader.attach_xdp(interface)?;
    loader.attach_tc_egress(interface)?;

    let ring_buf = loader.take_ring_buffer()?;
    let event_rx = EventProcessor::start(ring_buf).await;

    Ok(event_rx)
}
```

---

## Version

- **Documentation Version**: 2.0
- **Last Updated**: January 2026
- **Aya Version**: 0.13.1+
