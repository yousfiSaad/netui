# NetUI eBPF Implementation Guide

Technical deep-dive for implementing eBPF integration with NetUI.

---

## 1. Current NetUI Architecture

### Event-Driven Model

NetUI uses an event-driven architecture with three main components:

```
EventHandler (hub)
    ├── Crossterm events (keyboard/mouse)
    ├── Tick events (250ms)
    └── Scanner events (ScannerEvent)
              ↓
         App.handle_events()
              ↓
         StatsAggregator.tick()
              ↓
         UI rendering
```

### Key Files

| File | Purpose |
|------|---------|
| `src/event.rs` | Event types and handler |
| `src/scanner.rs` | Packet capture with pnet |
| `src/stats_aggregator.rs` | Flow statistics collection |
| `src/app.rs` | Application state and logic |

### Scanner Event Flow

```rust
// Current: pnet packet capture loop
loop {
    let packet = receiver.next()?;
    let event = parse_packet(packet)?;
    tx.send(ScannerEvent::StatTick(stats))?;
}
```

### StatsAggregator Interface

```rust
pub struct StatsAggregator {
    stats_buffer: HeapRb<StatsMap>,
    // ...
}

impl StatsAggregator {
    pub fn tick(&mut self, stats: StatsMap) {
        // Aggregate into ring buffer
    }

    pub fn get_speed(&self) -> Speed {
        // Calculate from buffer
    }
}
```

---

## 2. eBPF Integration Strategy

### Minimal Changes Approach

The integration preserves existing patterns:

1. **Keep ScannerEvent enum** - Add new variant for eBPF events
2. **Preserve StatsAggregator** - Convert eBPF events to StatsMap
3. **No TUI changes** - Same display logic

### New Components

```
New files:
├── src/ebpf_loader.rs    # Load and attach eBPF
├── src/ebpf_events.rs    # Ring buffer consumer
└── src/ebpf_stats.rs     # Convert to StatsMap

netui-ebpf/
├── src/xdp.rs            # XDP classifier
├── src/tc.rs             # TC egress
└── src/main.rs           # Entry points

netui-common/
└── src/lib.rs            # Shared types
```

### Event Flow with eBPF

```
                    eBPF Ring Buffer
                          ↓
EventProcessor ──→ NetworkEvent
                          ↓
                   ScannerEvent::EbpfPacket
                          ↓
                     EventHandler
                          ↓
                   StatsAggregator.tick()
                          ↓
                     UI rendering
```

---

## 3. eBPF Program Types

### XDP Classifier

**Purpose**: Capture ingress packets at driver level

**Attachment Point**: Network driver (before kernel stack)

**Advantages**:
- Lowest latency (< 1 us)
- Line-rate processing (10+ Gbps)
- Zero-copy packet access

**Limitations**:
- Ingress only (no egress)
- Limited packet modification
- Some drivers require SKB mode

**Implementation**:
```rust
#[xdp]
pub fn pkt_classifier(ctx: XdpContext) -> u32 {
    // Parse packet
    // Emit to ring buffer
    // Always return XDP_PASS (never drop)
    xdp_action::XDP_PASS
}
```

### TC Hooks

**Purpose**: Capture egress packets at qdisc level

**Attachment Point**: Traffic control classifier

**Advantages**:
- Full bidirectional capture
- Works with all drivers
- Full packet access

**Limitations**:
- Slightly higher latency than XDP
- Requires qdisc setup

**Implementation**:
```rust
#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    // Parse packet
    // Emit to ring buffer
    TC_ACT_PIPE // Continue processing
}
```

### Kprobes (Advanced)

**Purpose**: TCP state tracking and metrics

**Attachment Point**: Kernel function entry/exit

**Functions to probe**:
- `tcp_rcv_established`: RTT measurement
- `tcp_retransmit_skb`: Retransmission counting
- `tcp_set_state`: Connection state changes

**Implementation**:
```rust
#[kprobe]
pub fn tcp_rcv_established(ctx: ProbeContext) -> u32 {
    // Extract socket info
    // Update flow stats with RTT
    0
}
```

---

## 4. Variable IP Header Handling

**Critical**: IP headers can be 20-60 bytes due to options.

### Wrong Approach (Fixed 20 bytes)

```rust
// DO NOT DO THIS
let transport_offset = eth_offset + 20; // Assumes no IP options
```

### Correct Approach (Parse IHL)

```rust
fn parse_ipv4(ctx: &XdpContext, eth_offset: usize) -> Result<TransportInfo, ()> {
    let ip_hdr = ptr_at::<Ipv4Header>(ctx, eth_offset)?;

    // Extract IHL from version_ihl field
    // Lower 4 bits = IHL in 32-bit words
    let version_ihl = unsafe { (*ip_hdr).version_ihl };
    let ihl = (version_ihl & 0x0F) as usize;
    let ip_header_len = ihl * 4;

    // Validate: 20 <= header_len <= 60
    if ip_header_len < 20 || ip_header_len > 60 {
        return Err(());
    }

    // Transport header starts after variable IP header
    let transport_offset = eth_offset + ip_header_len;

    // Continue parsing at transport_offset
    Ok(TransportInfo {
        offset: transport_offset,
        protocol: unsafe { (*ip_hdr).protocol },
        src_ip: unsafe { (*ip_hdr).src_ip },
        dst_ip: unsafe { (*ip_hdr).dst_ip },
    })
}
```

### Why This Matters

IP options are rare but can appear in:
- ICMP redirects
- Source routing
- Timestamp options
- Security options

Without proper IHL handling, parsing will read garbage bytes.

---

## 5. Ring Buffer Design

### Aya 0.13 API

```rust
// Kernel side (eBPF program)
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_capacity(256 * 1024, 0);

// Emit event
if let Some(mut entry) = EVENTS.reserve::<NetworkEvent>(0) {
    entry.write(event);
    entry.submit(0);
}
```

```rust
// User-space side
let ring_buf = loader.take_ring_buffer()?;

while let Some(item) = ring_buf.next() {
    let event = unsafe {
        ptr::read_unaligned(item.as_ptr() as *const NetworkEvent)
    };
    // Process event
}
```

### Sizing Guidelines

| Traffic Rate | Buffer Size | Events/sec |
|--------------|-------------|------------|
| 10 Mbps | 64 KB | ~1,000 |
| 100 Mbps | 128 KB | ~10,000 |
| 1 Gbps | 256 KB | ~100,000 |
| 10 Gbps | 1 MB | ~1,000,000 |

### Backpressure Handling

When buffer is full, `reserve()` returns `None`:

```rust
if let Some(mut entry) = EVENTS.reserve::<NetworkEvent>(0) {
    entry.write(event);
    entry.submit(0);
} else {
    // Buffer full - event dropped
    // Increment drop counter
}
```

---

## 6. Integration with NetUI

### Step 1: Add ScannerEvent Variant

```rust
// src/event.rs
pub enum ScannerEvent {
    HostFound(Host),
    StatTick(StatsMap),
    InterfaceName(String),
    BeginScan,
    Complete,
    EbpfPacket(NetworkEvent), // NEW
}
```

### Step 2: Convert NetworkEvent to StatsMap

```rust
// src/ebpf_stats.rs
pub fn network_event_to_stats(event: &NetworkEvent) -> StatsMap {
    let mut stats = StatsMap::new();

    let key = StatKey {
        src_ip: Ipv4Addr::from(u32_to_ipv4_octets(event.src_ip)),
        dst_ip: Ipv4Addr::from(u32_to_ipv4_octets(event.dst_ip)),
        src_port: u16::from_be(event.src_port),
        dst_port: u16::from_be(event.dst_port),
        direction: match event.direction {
            DIR_INGRESS => Direction::Incoming,
            DIR_EGRESS => Direction::Outgoing,
            _ => Direction::None,
        },
    };

    let values = StatValues {
        bytes: event.bytes as u64,
        packets: 1,
    };

    stats.insert(key, values);
    stats
}
```

### Step 3: Wire into Event Loop

```rust
// src/app.rs
pub async fn handle_worker_events(&mut self, event: ScannerEvent) {
    match event {
        ScannerEvent::EbpfPacket(net_event) => {
            let stats = network_event_to_stats(&net_event);
            self.stats_aggregator.tick(stats);
        }
        // ... existing handlers
    }
}
```

### Step 4: Initialize eBPF in Main

```rust
// src/main.rs
async fn main() -> Result<()> {
    let interface = get_interface()?;

    // Try eBPF, fall back to pnet
    let scanner = match EbpfLoader::new() {
        Ok(mut loader) => {
            loader.attach_xdp(&interface.name)?;
            loader.attach_tc_egress(&interface.name)?;
            Scanner::with_ebpf(loader)
        }
        Err(e) => {
            eprintln!("eBPF unavailable: {}", e);
            Scanner::with_pnet(&interface)
        }
    };

    run_app(scanner).await
}
```

---

## 7. Project Structure

```
netui/
├── Cargo.toml              # Workspace root
├── .cargo/
│   └── config.toml         # eBPF target config
│
├── netui/                   # User-space application
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── app.rs
│       ├── scanner.rs
│       ├── stats_aggregator.rs
│       ├── event.rs
│       ├── ebpf_loader.rs   # NEW
│       ├── ebpf_events.rs   # NEW
│       ├── ebpf_stats.rs    # NEW
│       ├── tui.rs
│       ├── ui.rs
│       └── hosts_table.rs
│
├── netui-ebpf/              # eBPF programs
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # Entry point
│       ├── xdp.rs           # XDP classifier
│       └── tc.rs            # TC egress
│
├── netui-common/            # Shared types
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
│
└── xtask/                   # Build automation
    ├── Cargo.toml
    └── src/
        └── main.rs
```

---

## 8. Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

- [ ] Create workspace structure
- [ ] Implement shared types (netui-common)
- [ ] Basic XDP classifier
- [ ] Ring buffer event emission
- [ ] User-space loader
- [ ] Verify events received

**Milestone**: See packets in debug output

### Phase 2: Traffic Monitoring (Week 3-4)

- [ ] Add TC egress hook
- [ ] Implement flow statistics map
- [ ] Convert events to StatsMap
- [ ] Integrate with StatsAggregator
- [ ] Update TUI to show eBPF status

**Milestone**: Bandwidth display working with eBPF

### Phase 3: TCP Analysis (Week 5-6)

- [ ] Add TCP kprobes
- [ ] RTT measurement
- [ ] Retransmission tracking
- [ ] Connection state events
- [ ] Display TCP metrics in TUI

**Milestone**: RTT and retransmit stats visible

### Phase 4: ARP Enhancement (Week 7)

- [ ] eBPF ARP filtering
- [ ] Per-target ARP statistics
- [ ] ARP anomaly detection
- [ ] Integrate with host discovery

**Milestone**: Enhanced ARP monitoring

### Phase 5: Advanced Features (Week 8+)

- [ ] L7 protocol classification
- [ ] DDoS pattern detection
- [ ] Historical statistics storage
- [ ] Alerting system
- [ ] Performance optimization

**Milestone**: Production-ready monitoring

---

## 9. Testing Strategy

### Unit Tests (User-space)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_conversion() {
        let octets = [192, 168, 1, 1];
        let u32_val = ipv4_octets_to_u32(octets);
        assert_eq!(u32_to_ipv4_octets(u32_val), octets);
    }

    #[test]
    fn test_flow_key_creation() {
        let key = FlowKey::new(
            0x0100A8C0, // 192.168.0.1
            0x0200A8C0, // 192.168.0.2
            443,
            12345,
            IPPROTO_TCP,
        );
        assert_eq!(key.protocol, IPPROTO_TCP);
    }
}
```

### Integration Tests

```bash
# Load program
sudo ./target/release/netui --interface eth0

# In another terminal, generate traffic
iperf3 -c localhost -t 5

# Verify events
sudo bpftool map dump name EVENTS | head
sudo bpftool map dump name FLOWS
```

### Stress Testing

```bash
# High packet rate test
iperf3 -u -b 10G -c localhost -t 60

# Monitor for drops
sudo bpftool prog stat | grep pkt_classifier
```

---

## 10. Debugging

### Kernel Trace Output

```rust
// In eBPF program
use aya_log_ebpf::info;

#[xdp]
pub fn pkt_classifier(ctx: XdpContext) -> u32 {
    info!(&ctx, "Packet received, protocol: {}", protocol);
    // ...
}
```

```bash
# View trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### bpftool Commands

```bash
# List loaded programs
sudo bpftool prog list

# Show program stats
sudo bpftool prog stat

# Dump map contents
sudo bpftool map dump name FLOWS

# Show map info
sudo bpftool map show name EVENTS
```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "Permission denied" | Missing capabilities | Add CAP_BPF, CAP_PERFMON |
| "Invalid mem access" | Bounds check failed | Add proper ptr_at() checks |
| "Program too large" | Exceeds verifier limit | Split into tail calls |
| "Map full" | Too many flows | Increase max_entries or use LRU |

---

## Version

- **Documentation Version**: 2.0
- **Last Updated**: January 2026
- **Aya Version**: 0.13.1+
