# NetUI eBPF Implementation - Starter Kit

## Project Setup

### 1. Create Workspace Structure

```bash
cargo new --name netui-ebpf netui-enhanced
cd netui-enhanced

# Create eBPF program crate
cargo generate https://github.com/aya-rs/aya-template \
  --path aya-ebpf-programs

# Create shared types
cargo new --lib netui-common
```

### 2. Workspace Cargo.toml

```toml
[workspace]
members = ["netui", "netui-ebpf", "netui-common"]

[workspace.dependencies]
aya = "0.12"
aya-bpf = "0.1"
tokio = { version = "1.35", features = ["full"] }
ratatui = "0.26"
```

---

## Shared Data Structures (netui-common/src/lib.rs)

```rust
#![no_std]

use core::mem;

// Network event that flows from kernel to user-space
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    // Timestamp in nanoseconds since boot
    pub timestamp_ns: u64,

    // Event classification
    pub event_type: u8,  // 0=packet, 1=flow_start, 2=flow_end, 3=tcp_rtt
    pub direction: u8,   // 0=ingress, 1=egress

    // 5-tuple identification
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,    // IPPROTO_TCP=6, IPPROTO_UDP=17, etc.

    // Packet/Flow data
    pub bytes: u64,      // Bytes in this packet/flow
    pub packets: u32,    // Packet count
    pub tcp_flags: u8,   // TCP flags if applicable

    // TCP metrics
    pub rtt_ns: u32,     // RTT in nanoseconds (for tcp_rtt events)
    pub retransmits: u16, // Retransmission count
    pub window_size: u16, // TCP window size
}

// Flow identification
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FlowKey {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub _padding: [u8; 3],
}

// Flow statistics maintained in kernel
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub start_ts_ns: u64,
    pub last_activity_ts_ns: u64,
    pub tcp_state: u8,
    pub tcp_rtt_ns: u32,
    pub retransmit_count: u32,
}

// Constants
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;
pub const ETH_P_IPV6: u16 = 0x86DD;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub const EVENT_PACKET: u8 = 0;
pub const EVENT_FLOW_START: u8 = 1;
pub const EVENT_FLOW_END: u8 = 2;
pub const EVENT_TCP_RTT: u8 = 3;

// Ethernet frame header
#[repr(C)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

// IPv4 header
#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_frag_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
}

// TCP header
#[repr(C)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

// UDP header
#[repr(C)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

// ARP header
#[repr(C)]
pub struct ArpHeader {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub opcode: u16,
    pub src_mac: [u8; 6],
    pub src_ip: u32,
    pub dst_mac: [u8; 6],
    pub dst_ip: u32,
}

impl NetworkEvent {
    pub fn new() -> Self {
        unsafe { mem::zeroed() }
    }
}

impl FlowKey {
    pub fn new(saddr: u32, daddr: u32, sport: u16, dport: u16, protocol: u8) -> Self {
        Self {
            saddr,
            daddr,
            sport,
            dport,
            protocol,
            _padding: [0; 3],
        }
    }
}

pub fn u32_to_ipv4(ip: u32) -> [u8; 4] {
    [
        (ip & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 24) & 0xFF) as u8,
    ]
}

pub fn ipv4_to_u32(octets: [u8; 4]) -> u32 {
    (octets as u32)
        | ((octets [github](https://github.com/yousfisaad/netui) as u32) << 8)
        | ((octets [blog.redsift](https://blog.redsift.com/labs/ebpf-ingrained-in-rust/) as u32) << 16)
        | ((octets [eunomia](https://eunomia.dev/tutorials/14-tcpstates/) as u32) << 24)
}
```

---

## eBPF XDP Program (netui-ebpf/src/xdp_classifier.rs)

```rust
#![no_std]

use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
    maps::RingBuf,
};
use core::mem;
use netui_common::*;

// Ring buffer for sending events to user-space
#[map(name = "packet_events")]
pub static mut PACKET_EVENTS: RingBuf = RingBuf::with_byte_capacity(256 * 1024, 0);

// Per-flow statistics tracking
#[map(name = "flows")]
pub static mut FLOWS: aya_bpf::maps::HashMap<FlowKey, FlowStats> =
    aya_bpf::maps::HashMap::with_max_entries(10_000, 0);

#[xdp]
pub fn pkt_classifier(ctx: XdpContext) -> u32 {
    match classify_packet(&ctx) {
        Ok(event) => {
            // Send event to user-space via ring buffer
            let _ = unsafe {
                PACKET_EVENTS.output(&ctx, &event, 0);
            };

            // Update flow statistics
            update_flow_stats(&event);

            xdp_action::XDP_PASS
        }
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn classify_packet(ctx: &XdpContext) -> Result<NetworkEvent, i32> {
    let mut event = NetworkEvent::new();
    event.timestamp_ns = unsafe { aya_bpf::helpers::bpf_ktime_get_ns() };
    event.direction = 0; // Ingress

    // Parse Ethernet frame
    let eth_hdr = ptr_at::<EthernetHeader>(ctx, 0)?;
    let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });

    // Handle IPv4
    if ether_type == ETH_P_IP {
        parse_ipv4(ctx, &mut event, mem::size_of::<EthernetHeader>())?;
    }
    // Handle ARP
    else if ether_type == ETH_P_ARP {
        parse_arp(ctx, &mut event, mem::size_of::<EthernetHeader>())?;
    }

    Ok(event)
}

fn parse_ipv4(
    ctx: &XdpContext,
    event: &mut NetworkEvent,
    offset: usize,
) -> Result<(), i32> {
    let ip_hdr = ptr_at::<Ipv4Header>(ctx, offset)?;

    event.src_ip = unsafe { (*ip_hdr).src_ip };
    event.dst_ip = unsafe { (*ip_hdr).dst_ip };
    event.protocol = unsafe { (*ip_hdr).protocol };

    let ip_proto = event.protocol;

    // Parse TCP
    if ip_proto == IPPROTO_TCP {
        parse_tcp(ctx, event, offset + 20)?;
    }
    // Parse UDP
    else if ip_proto == IPPROTO_UDP {
        parse_udp(ctx, event, offset + 20)?;
    }

    Ok(())
}

fn parse_tcp(
    ctx: &XdpContext,
    event: &mut NetworkEvent,
    offset: usize,
) -> Result<(), i32> {
    let tcp_hdr = ptr_at::<TcpHeader>(ctx, offset)?;

    event.src_port = unsafe { (*tcp_hdr).src_port };
    event.dst_port = unsafe { (*tcp_hdr).dst_port };
    event.tcp_flags = (unsafe { (*tcp_hdr).data_offset_flags } & 0xFF) as u8;
    event.window_size = unsafe { (*tcp_hdr).window_size };

    event.event_type = EVENT_PACKET;

    Ok(())
}

fn parse_udp(
    ctx: &XdpContext,
    event: &mut NetworkEvent,
    offset: usize,
) -> Result<(), i32> {
    let udp_hdr = ptr_at::<UdpHeader>(ctx, offset)?;

    event.src_port = unsafe { (*udp_hdr).src_port };
    event.dst_port = unsafe { (*udp_hdr).dst_port };
    event.event_type = EVENT_PACKET;

    Ok(())
}

fn parse_arp(
    ctx: &XdpContext,
    event: &mut NetworkEvent,
    offset: usize,
) -> Result<(), i32> {
    let arp_hdr = ptr_at::<ArpHeader>(ctx, offset)?;

    event.src_ip = unsafe { (*arp_hdr).src_ip };
    event.dst_ip = unsafe { (*arp_hdr).dst_ip };
    event.protocol = 0; // Special marker for ARP
    event.event_type = EVENT_PACKET;

    Ok(())
}

fn update_flow_stats(event: &NetworkEvent) {
    if event.protocol == 0 {
        // Skip ARP flows
        return;
    }

    let flow_key = FlowKey::new(
        event.src_ip,
        event.dst_ip,
        event.src_port,
        event.dst_port,
        event.protocol,
    );

    unsafe {
        if let Some(stats) = FLOWS.get_mut(&flow_key) {
            stats.packets_sent += 1;
            stats.bytes_sent += event.bytes;
            stats.last_activity_ts_ns = event.timestamp_ns;
        } else {
            let new_stats = FlowStats {
                packets_sent: 1,
                packets_received: 0,
                bytes_sent: event.bytes,
                bytes_received: 0,
                start_ts_ns: event.timestamp_ns,
                last_activity_ts_ns: event.timestamp_ns,
                tcp_state: 0,
                tcp_rtt_ns: 0,
                retransmit_count: 0,
            };
            let _ = FLOWS.insert(&flow_key, &new_stats, 0);
        }
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(-1);
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

---

## User-space Event Processing (netui/src/ebpf_loader.rs)

```rust
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use netui_common::NetworkEvent;
use std::error::Error;
use tokio::sync::mpsc;

pub struct EbpfLoader {
    bpf: Bpf,
    interfaces: Vec<String>,
}

impl EbpfLoader {
    pub fn new() -> Self {
        Self {
            bpf: Bpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/netui-ebpf"
            )))
            .expect("Failed to load eBPF bytecode"),
            interfaces: vec![],
        }
    }

    pub fn load(&mut self) -> Result<(), Box<dyn Error>> {
        // Already loaded in new()
        Ok(())
    }

    pub fn attach_xdp(&mut self, interface: &str) -> Result<(), Box<dyn Error>> {
        let program: &mut Xdp = self.bpf.program_mut("pkt_classifier")
            .ok_or("XDP program not found")?
            .try_into()?;

        program.load()?;
        program.attach(interface, XdpFlags::SKB)?;

        self.interfaces.push(interface.to_string());

        println!("✓ Attached XDP program to {}", interface);
        Ok(())
    }

    pub fn get_ring_buffer(&mut self) -> Result<RingBuf, Box<dyn Error>> {
        let rb = RingBuf::try_from(self.bpf.take_map("packet_events")?)?;
        Ok(rb)
    }
}

pub struct EventProcessor;

impl EventProcessor {
    pub async fn start(
        mut ring_buf: RingBuf,
    ) -> mpsc::Receiver<NetworkEvent> {
        let (tx, rx) = mpsc::channel(1000);

        tokio::spawn(async move {
            loop {
                while let Ok(Some(buf)) = ring_buf.next() {
                    let event = unsafe {
                        *(buf.as_ptr() as *const NetworkEvent)
                    };

                    if tx.send(event).await.is_err() {
                        // Receiver dropped, exit loop
                        return;
                    }
                }

                // Yield to other tasks
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        rx
    }
}
```

---

## Statistics Aggregation (netui/src/statistics.rs)

```rust
use netui_common::*;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct FlowStatistics {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol_name: String,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_secs: u64,
    pub bitrate_kbps: f64,
}

pub struct StatisticsCollector {
    flows: HashMap<FlowKey, FlowStats>,
    last_update: u64,
}

impl StatisticsCollector {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            last_update: 0,
        }
    }

    pub fn process_event(&mut self, event: &NetworkEvent) {
        let flow_key = FlowKey::new(
            event.src_ip,
            event.dst_ip,
            event.src_port,
            event.dst_port,
            event.protocol,
        );

        self.flows
            .entry(flow_key)
            .or_insert_with(|| FlowStats {
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                start_ts_ns: event.timestamp_ns,
                last_activity_ts_ns: event.timestamp_ns,
                tcp_state: 0,
                tcp_rtt_ns: 0,
                retransmit_count: 0,
            })
            .bytes_sent += event.bytes;

        self.last_update = event.timestamp_ns;
    }

    pub fn get_active_flows(&self) -> Vec<FlowStatistics> {
        self.flows
            .iter()
            .map(|(key, stats)| {
                let duration_ns = self.last_update - stats.start_ts_ns;
                let duration_secs = duration_ns / 1_000_000_000;
                let bitrate_kbps = if duration_secs > 0 {
                    (stats.bytes_sent * 8) as f64 / (duration_secs as f64 * 1000.0)
                } else {
                    0.0
                };

                FlowStatistics {
                    src_ip: ipv4_to_octets(key.saddr),
                    dst_ip: ipv4_to_octets(key.daddr),
                    src_port: key.sport,
                    dst_port: key.dport,
                    protocol_name: protocol_name(key.protocol),
                    packets_sent: stats.packets_sent,
                    packets_received: stats.packets_received,
                    bytes_sent: stats.bytes_sent,
                    bytes_received: stats.bytes_received,
                    duration_secs,
                    bitrate_kbps,
                }
            })
            .collect()
    }
}

fn ipv4_to_octets(ip: u32) -> [u8; 4] {
    [
        (ip & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 24) & 0xFF) as u8,
    ]
}

fn protocol_name(proto: u8) -> String {
    match proto {
        IPPROTO_TCP => "TCP".to_string(),
        IPPROTO_UDP => "UDP".to_string(),
        IPPROTO_ICMP => "ICMP".to_string(),
        _ => format!("P{}", proto),
    }
}
```

---

## Integration with NetUI TUI (netui/src/main.rs)

```rust
mod ebpf_loader;
mod statistics;

use ebpf_loader::{EbpfLoader, EventProcessor};
use statistics::StatisticsCollector;
use netui_common::NetworkEvent;
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Table, Row, Cell},
    layout::{Layout, Constraint, Direction},
    Terminal, Frame,
};
use std::io::stdout;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize eBPF
    let mut ebpf_loader = EbpfLoader::new();
    ebpf_loader.load()?;

    // Attach to default interface
    let interface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| !iface.is_loopback())
        .ok_or("No network interface found")?;

    ebpf_loader.attach_xdp(&interface.name)?;

    // Start event processor
    let ring_buf = ebpf_loader.get_ring_buffer()?;
    let mut event_rx = EventProcessor::start(ring_buf).await;

    // Initialize TUI
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;

    // Initialize statistics collector
    let mut stats = StatisticsCollector::new();

    // Main loop
    loop {
        // Process incoming events
        while let Ok(event) = event_rx.try_recv() {
            stats.process_event(&event);
        }

        // Draw TUI
        terminal.draw(|f| draw_ui(f, &stats))?;

        // Sleep briefly to avoid busy-waiting
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

fn draw_ui<B: ratatui::backend::Backend>(f: &mut Frame<B>, stats: &StatisticsCollector) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(100)])
        .split(f.size());

    let flows = stats.get_active_flows();

    let header = Row::new(vec![
        Cell::from("Source IP"),
        Cell::from("Dest IP"),
        Cell::from("Protocol"),
        Cell::from("Bytes"),
        Cell::from("Rate (kbps)"),
    ]);

    let rows = flows.iter().map(|flow| {
        Row::new(vec![
            Cell::from(format!("{}.{}.{}.{}",
                flow.src_ip, flow.src_ip, flow.src_ip, flow.src_ip)), [github](https://github.com/yousfisaad/netui)
            Cell::from(format!("{}.{}.{}.{}",
                flow.dst_ip, flow.dst_ip, flow.dst_ip, flow.dst_ip)), [blog.redsift](https://blog.redsift.com/labs/ebpf-ingrained-in-rust/)
            Cell::from(flow.protocol_name.clone()),
            Cell::from(flow.bytes_sent.to_string()),
            Cell::from(format!("{:.2}", flow.bitrate_kbps)),
        ])
    });

    let table = Table::new(rows)
        .header(header)
        .block(Block::default().title("Network Flows").borders(Borders::ALL));

    f.render_widget(table, chunks);
}
```

---

## Cargo Configuration Files

### netui-ebpf/Cargo.toml

```toml
[package]
name = "netui-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-bpf = "0.1"
netui-common = { path = "../netui-common", features = ["no_std"] }

[[bin]]
name = "netui-ebpf"
path = "src/lib.rs"

[lib]
crate-type = ["cdylib"]
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

[dependencies]

[lib]
```

### Build Script (Makefile or .cargo/config.toml)

```makefile
.PHONY: build clean run

build:
	cargo xtask build-ebpf
	cargo build --release

run: build
	sudo ./target/release/netui

clean:
	cargo clean
```

---

## Testing and Validation

```bash
# Build everything
cargo build --release

# Check eBPF program
sudo bpftool prog show

# Test with traffic generation
iperf3 -c 192.168.1.100 &

# Run NetUI (requires root for XDP)
sudo ./target/release/netui

# Monitor in another terminal
sudo bpftool map dump name flows
```

---

## Next Steps After Basic Implementation

1. **Add TC hooks** for egress traffic
2. **Implement TCP probes** for RTT measurements
3. **Add histogram support** for latency distribution
4. **Create flow timeout logic** for inactive connections
5. **Implement L7 classification** for DNS/HTTP/TLS
6. **Add historical statistics storage**
7. **Create alerting rules** for anomalies

This starter implementation provides a solid foundation for building a production-grade eBPF-powered network monitor integrated with NetUI.
