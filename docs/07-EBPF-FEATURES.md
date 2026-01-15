# NetUI eBPF Feature Roadmap

Features unlocked after completing the eBPF migration.

---

## Performance Improvements

| Metric | pnet (current) | eBPF (after migration) |
|--------|----------------|------------------------|
| Max throughput | 1-2 Gbps | 10+ Gbps |
| Packet accuracy | 95-99% | 100% |
| CPU @ 1 Gbps | 25% | <1% |
| Latency | ~100 us | <1 us |

---

## TCP Metrics via Kprobes

eBPF can attach to kernel functions to extract metrics pnet has no access to.

### Available Metrics

| Metric | Kernel Function | Description |
|--------|-----------------|-------------|
| RTT | `tcp_rcv_established` | Round-trip time (smoothed) |
| Retransmits | `tcp_retransmit_skb` | Packet retransmission count |
| Connection state | `tcp_set_state` | SYN_SENT, ESTABLISHED, TIME_WAIT, etc. |
| Congestion window | `tcp_cong_control` | cwnd size, congestion algorithm |
| Bytes acked | `tcp_ack` | Acknowledged byte count |

### Example TUI Display

```
┌─────────────────────────────────────────────────┐
│  TCP Flow: 192.168.1.5:443 → 10.0.0.1:52341    │
│  ─────────────────────────────────────────────  │
│  RTT:          23ms (smoothed)                  │
│  Retransmits:  2 packets                        │
│  State:        ESTABLISHED                      │
│  Congestion:   cubic, cwnd=42                   │
│  Bytes acked:  1.2 MB                           │
└─────────────────────────────────────────────────┘
```

### New TUI Columns

- RTT (min/avg/max)
- Retransmit count & rate
- Connection state
- Congestion window size

---

## L7 Protocol Detection

Kernel-side signature matching with sampling for performance.

### Supported Protocols

| Protocol | Detection Method | Port Hint |
|----------|------------------|-----------|
| DNS | Query structure validation | 53 |
| HTTP | `GET /`, `POST /`, `HTTP/1.1` signatures | 80 |
| HTTPS/TLS | ClientHello handshake pattern | 443 |
| SSH | `SSH-2.0` banner detection | 22 |
| QUIC | UDP + connection ID pattern | 443 |
| MySQL | Protocol handshake | 3306 |
| PostgreSQL | Startup message | 5432 |
| Redis | RESP protocol commands | 6379 |

### Example TUI Display

```
┌─ Flows ─────────────────────────────────────────┐
│ Protocol   Source          Dest         Speed   │
│ HTTPS      192.168.1.5     142.250.x.x  2.3 MB/s│
│ DNS        192.168.1.5     8.8.8.8      1.2 KB/s│
│ SSH        10.0.0.50       192.168.1.5  45 KB/s │
│ QUIC       192.168.1.5     172.217.x.x  1.8 MB/s│
└─────────────────────────────────────────────────┘
```

### Implementation Strategy

Tiered classification for performance:

| Tier | Location | Method | Accuracy |
|------|----------|--------|----------|
| 1 | Kernel | Port-based lookup | 70% |
| 2 | Kernel | Signature (sampled 1%) | 85% |
| 3 | User-space | Deep inspection | 95% |

---

## Real-Time Anomaly Detection

Kernel-side pattern detection before events reach user-space.

### Detection Capabilities

| Anomaly | Detection Method | Alert Threshold |
|---------|------------------|-----------------|
| Port scan | Unique dst_ports per src_ip | >20 ports/10s |
| SYN flood | SYN count without ACK | >100 SYN/s per IP |
| DNS amplification | Large DNS responses | Response > 10x query |
| ARP spoofing | MAC/IP binding changes | Any change |
| ICMP flood | ICMP packet rate | >1000 pps |
| Bandwidth spike | Per-flow byte rate | >2x baseline |

### Example TUI Alerts

```
┌─ Alerts ────────────────────────────────────────┐
│ ⚠ 12:00:01 Port scan from 10.0.0.99 (47 ports) │
│ ⚠ 12:00:05 ARP: 192.168.1.1 MAC changed        │
│ ⚠ 12:00:12 SYN flood to 192.168.1.5:80         │
└─────────────────────────────────────────────────┘
```

### Implementation

```rust
// BPF map for tracking
#[map]
static PORT_SCAN_TRACKER: HashMap<u32, PortScanState> =
    HashMap::with_max_entries(10_000, 0);

struct PortScanState {
    unique_ports: [u16; 64],  // Bloom filter or small set
    port_count: u16,
    first_seen: u64,
}
```

---

## Connection Tracking

Full TCP state machine visibility with lifecycle tracking.

### Connection Lifecycle

```
Connection Timeline:
  12:00:01.234  SYN      → 142.250.185.14:443
  12:00:01.256  SYN-ACK  ← 142.250.185.14:443  (22ms RTT)
  12:00:01.257  ACK      → ESTABLISHED
  12:00:05.891  FIN      →
  12:00:05.913  FIN-ACK  ←
  12:00:05.914  TIME_WAIT (60s remaining)
```

### State Distribution View

```
┌─ Connection States ─────────────────────────────┐
│ ESTABLISHED   ████████████████████████  156     │
│ TIME_WAIT     ████████████              72      │
│ SYN_SENT      ███                       18      │
│ CLOSE_WAIT    ██                        12      │
│ FIN_WAIT_1    █                         6       │
└─────────────────────────────────────────────────┘
```

### Use Cases

- Identify connection leaks (stuck in CLOSE_WAIT)
- Debug connection establishment issues
- Monitor connection pool health
- Detect half-open connection attacks

---

## Per-Flow Kernel Statistics

Efficient aggregation in BPF HashMap.

### Flow Key Structure

```rust
struct FlowKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}
```

### Flow Statistics

```rust
struct FlowStats {
    bytes_in: u64,
    bytes_out: u64,
    packets_in: u64,
    packets_out: u64,
    first_seen: u64,
    last_seen: u64,
    tcp_flags_seen: u8,
}
```

### Benefits

- Aggregation happens in kernel (zero user-space CPU for counting)
- Atomic updates (no race conditions)
- LRU eviction for bounded memory
- Periodic export to user-space

---

## Historical Statistics

With kernel-side aggregation, efficient long-term storage becomes feasible.

### Data to Store

| Metric | Granularity | Retention |
|--------|-------------|-----------|
| Bandwidth per flow | 1 minute | 24 hours |
| Top talkers | 5 minutes | 7 days |
| Protocol distribution | 1 hour | 30 days |
| Connection durations | Per connection | 7 days |
| Anomaly events | Per event | 90 days |

### Storage Options

| Option | Use Case |
|--------|----------|
| SQLite | Local storage, simple queries |
| InfluxDB | Time-series, Grafana integration |
| Prometheus | Metrics export, alerting |
| CSV export | External analysis |

---

## Feature Implementation Effort

Post-migration effort estimates.

| Feature | Effort | eBPF Component | Priority |
|---------|--------|----------------|----------|
| RTT display | 2-3 days | Kprobe: `tcp_rcv_established` | High |
| Retransmit counter | 1-2 days | Kprobe: `tcp_retransmit_skb` | High |
| Protocol column | 3-4 days | XDP signature matching | Medium |
| Connection states | 2-3 days | Kprobe: `tcp_set_state` | Medium |
| Port scan alerts | 2-3 days | BPF map + threshold | Medium |
| ARP spoof detection | 1-2 days | XDP ARP tracking | Medium |
| Historical stats | 3-4 days | Ring buffer + SQLite | Low |
| Grafana export | 2-3 days | Prometheus metrics | Low |

---

## Feature Comparison Summary

| Feature | pnet (current) | eBPF (after migration) |
|---------|----------------|------------------------|
| Max throughput | 1-2 Gbps | 10+ Gbps |
| CPU @ 1Gbps | 25% | <1% |
| RTT measurement | No | Yes |
| Retransmit tracking | No | Yes |
| L7 classification | No | Yes |
| Connection states | No | Yes |
| Port scan detection | No | Yes |
| ARP spoof detection | No | Yes |
| Per-flow kernel stats | No | Yes |
| Historical storage | Limited | Efficient |

---

## Implementation Phases

### Phase 1: Core Monitoring (Week 1-2)
- XDP ingress classifier
- TC egress hook
- Ring buffer events
- Basic flow statistics

### Phase 2: TCP Metrics (Week 3-4)
- RTT measurement kprobe
- Retransmit tracking kprobe
- Connection state tracking
- TUI column updates

### Phase 3: Protocol Detection (Week 5-6)
- Port-based classification
- Signature-based detection (sampled)
- Protocol column in TUI
- Unknown protocol handling

### Phase 4: Anomaly Detection (Week 7-8)
- Port scan detection
- ARP spoofing detection
- Alert system in TUI
- Configurable thresholds

### Phase 5: Historical & Export (Week 9+)
- SQLite storage
- Prometheus metrics
- CSV export
- Grafana dashboard templates

---

## Prerequisites

Before implementing these features:

1. Complete refactoring plan (`docs/00-REFACTORING-PLAN.md`)
2. Implement core eBPF backend (`docs/03-IMPLEMENTATION-GUIDE.md`)
3. Verify basic packet capture works
4. Add feature flags for incremental rollout

---

## Version

- **Documentation Version**: 1.0
- **Last Updated**: January 2026
