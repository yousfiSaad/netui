# NetUI eBPF Enhancement - Architecture Decision Records

## ADR-001: XDP vs TC for Primary Hook

### Decision

**Use XDP (eXpress Data Path) as primary hook, TC as secondary**

### Context

NetUI needs to capture network traffic with minimal overhead. Two main eBPF attachment points are available:

- **XDP**: Driver-level, before kernel network stack
- **TC (qdisc)**: Network stack level, after protocol processing

### Options Evaluated

| Aspect                 | XDP                     | TC                 | Raw Socket |
| ---------------------- | ----------------------- | ------------------ | ---------- |
| **Performance**        | ⭐⭐⭐⭐⭐ Excellent    | ⭐⭐⭐ Good        | ⭐ Poor    |
| **Latency**            | <1μs                    | <10μs              | >100μs     |
| **Ingress Coverage**   | Full                    | Full               | Filtered   |
| **Egress Coverage**    | Limited (NIC dependent) | Full               | No         |
| **Programmability**    | Context limitations     | Full packet access | Full       |
| **Kernel Requirement** | 4.8+                    | 4.11+              | All        |
| **Complexity**         | Medium                  | Medium             | Low        |

### Decision Rationale

1. **XDP for Ingress**: Processes packets at the driver before kernel stack
   - ✅ Line-rate performance (10Gbps+)
   - ✅ Zero-copy packet access
   - ✅ Early classification and filtering
   - ⚠️ Limited payload access (first bytes only in practice)

2. **TC for Egress**: Captures outbound traffic
   - ✅ Full packet visibility
   - ✅ Bidirectional statistics
   - ✅ Works with all NIC drivers
   - ⚠️ Slightly higher latency (acceptable for monitoring)

### Consequences

**Positive:**

- Exceptional performance for bandwidth monitoring
- Can detect or drop attacks before stack processing
- Future expansion to XDP-based mitigation is possible

**Negative:**

- Requires Linux 4.8+ (4.11+ for full features)
- XDP doesn't work with all NICs (fallback to SKB mode)
- L7 inspection limited on XDP path (delegate to TC/user-space)

### Implementation Strategy

```
Packet Flow:
┌─────────────────────────┐
│ Driver/NIC              │
└────────────┬────────────┘
             │
             ▼ (XDP attachment)
     ┌───────────────┐
     │ XDP Program   │ ← Basic classification, aggregation
     └───────┬───────┘
             │
             ▼
     ┌───────────────┐
     │ Kernel Stack  │
     └───────┬───────┘
             │
             ▼ (TC ingress)
     ┌───────────────┐
     │ TC Program    │ ← Enhanced stats, L7 hints
     └───────────────┘
```

---

## ADR-002: Ring Buffer vs Perf Buffer

### Decision

**Use Ring Buffer for event streaming**

### Context

Events from kernel eBPF programs must be efficiently delivered to user-space. Two mechanisms exist:

- **Perf Buffers**: Legacy, per-CPU ring buffers
- **Ring Buffers**: Modern, single shared buffer

### Comparison

| Aspect                    | Ring Buffer     | Perf Buffer      |
| ------------------------- | --------------- | ---------------- |
| **Throughput**            | Higher (shared) | Per-CPU bounded  |
| **Latency**               | Lower           | Higher           |
| **Memory Overhead**       | Lower           | Higher (per-CPU) |
| **Backpressure Handling** | Better          | Loses events     |
| **Ordering**              | Global ordering | Per-CPU only     |
| **Kernel Version**        | 5.8+            | 4.4+             |
| **Aya Support**           | Excellent       | Good             |

### Decision Rationale

1. **Shared Buffer Model**
   - Single ring buffer vs per-CPU allows efficient event correlation
   - Critical for NetUI’s flow-tracking (needs ordering)

2. **Backpressure Handling**
   - Ring buffer can block producers briefly or drop gracefully
   - Perf buffer tends to lose events under load
   - NetUI prefers accuracy for observability

3. **Memory Efficiency**
   - 256 KB ring buffer vs 1 MB per-CPU (8 CPUs → 8 MB)
   - Important for resource-constrained systems

### Consequences

**Positive:**

- Cleaner event handling
- Better for debugging (single stream)
- Lower memory footprint

**Negative:**

- Requires Linux 5.8+
- Single logical buffer for high-CPU systems (still OK in practice)

### Configuration

```rust
// Default: 256 KB ring buffer
#[map(name = "packet_events")]
pub static mut PACKET_EVENTS: RingBuf = RingBuf::with_byte_capacity(256 * 1024, 0);

// Tuning guideline:
// buffer_size ≈ pps * event_size * window
// window ≈ 0.1s, event_size ≈ 64 bytes
```

---

## ADR-003: HashMap Size for Flow Tracking

### Decision

**10,000 concurrent flows with LRU eviction**

### Context

NetUI must track flows (5-tuple connections) efficiently.

### Analysis

Typical workloads:

- Host: 100–1,000 flows
- Small gateway: 1,000–10,000 flows
- Large router: 100,000+ flows (out of scope for NetUI)

Memory impact (approx):

- FlowKey ≈ 14 bytes
- FlowStats ≈ 40–50 bytes
- Total ≈ 60 bytes/flow
- 10,000 flows ≈ 600 KB
- 100,000 flows ≈ 6 MB

### Decision Rationale

1. **10,000 as Default**
   - Covers typical host / small-gateway monitoring
   - Keeps kernel memory usage under ~1 MB

2. **LRU Eviction Strategy**

```rust
#[map(name = "flows")]
pub static mut FLOWS: HashMap<FlowKey, FlowStats> =
    HashMap::with_max_entries(10_000, 0);
```

- eBPF map can be configured as LRU (if desired)
- Automatic eviction of least-recently-used entries

### Configuration Options

```rust
// For host-level monitoring
const FLOW_TABLE_SIZE: u32 = 10_000;

// For higher cardinality
const FLOW_TABLE_SIZE_GATEWAY: u32 = 100_000;
```

### Monitoring Evictions

```bash
# Check current entries
sudo bpftool map dump name flows | wc -l
```

---

## ADR-004: Flow Timeout and Cleanup

### Decision

**Lazy deletion with periodic export of statistics**

### Context

The kernel doesn’t provide efficient per-entry TTL in maps. Need a way to keep flows bounded while preserving stats.

### Options Evaluated

| Strategy                | Kernel Overhead | Memory Behavior | Stats Correctness |
| ----------------------- | --------------- | --------------- | ----------------- |
| Kernel TTL              | High            | Controlled      | Risky             |
| Lazy + LRU              | Low             | Controlled      | Good              |
| User-space cleanup only | Low             | Possible leaks  | Good              |

### Decision Rationale

1. **No kernel-wide TTL scanning**
   - Inefficient to iterate entire map in eBPF
   - Verifier and complexity constraints

2. **LRU in Kernel + Export in User-space**
   - Kernel evicts oldest flows when map is full
   - User-space periodically snapshots flows for long-term stats

### Implementation Sketch

```rust
// User-space background task
pub async fn export_stats(interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let flows = read_all_flows_from_kernel();
        archive_to_storage(&flows).await;
    }
}
```

---

## ADR-005: L7 Protocol Classification Strategy

### Decision

**Tiered classification: ports → signatures → user-space**

### Context

Full DPI in eBPF is expensive and verifier-hostile. Need a pragmatic L7 detection strategy.

### Tiered Approach

1. **Tier 1: Port-based (Kernel)**
   - :53 → DNS
   - :80 → HTTP
   - :443 → HTTPS/TLS
   - :22 → SSH
2. **Tier 2: Light Signature (Kernel, sampled)**
   - Check first few bytes for `HTTP/`
   - TLS handshake record byte
   - DNS header layout
3. **Tier 3: Context (User-space)**
   - Flow duration, packet sizes, patterns

### Implementation Example

```rust
#[xdp]
pub fn classify_l7(ctx: XdpContext) -> u32 {
    // Tier 1: port
    if sport == 53 || dport == 53 {
        event.l7_type = L7_DNS;
    }

    // Tier 2: lightweight payload sampling
    if sample_packet() {
        if peek_http_signature(&ctx) {
            event.l7_type = L7_HTTP;
        }
        if peek_tls_handshake(&ctx) {
            event.l7_type = L7_TLS;
        }
    }

    xdp_action::XDP_PASS
}

#[inline(always)]
fn sample_packet() -> bool {
    static mut COUNTER: u32 = 0;
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        COUNTER % 100 == 0
    }
}
```

---

## ADR-006: Real-time vs Aggregated Statistics

### Decision

**Emit raw per-packet/per-event data from kernel, aggregate in user-space**

### Context

Trade-off between kernel complexity and statistics flexibility.

### Options

| Approach               | Kernel Complexity | Flexibility | Latency |
| ---------------------- | ----------------- | ----------- | ------- |
| Kernel aggregation     | High              | Low         | Higher  |
| User-space aggregation | Low               | High        | Low     |
| Hybrid                 | Medium            | Medium      | Medium  |

### Decision Rationale

- Keep kernel logic simple; do not implement heavy aggregation inside eBPF
- Allow multiple aggregation views (1s, 10s, 1min windows)
- Easier to evolve metrics without changing kernel code

### Implementation Sketch

Kernel:

```rust
// Emit NetworkEvent for each packet or flow event
PACKET_EVENTS.output(&ctx, &event, 0);
```

User-space:

```rust
while let Some(event) = read_event() {
    stats_collector.process_event(&event);
}

// stats_collector can expose views:
// - current window
// - historical summaries
// - percentile metrics
```

---

## ADR-007: Multi-interface Support

### Decision

**Single eBPF program, attached to multiple interfaces, shared maps**

### Context

NetUI may monitor multiple NICs; design must be efficient.

### Design

- Load program once
- Attach XDP to each monitored interface
- Use shared maps:
  - `packet_events` ring buffer
  - `flows` HashMap

### Example

```rust
let interfaces = vec!["eth0", "eth1", "wlan0"];
let program: &mut Xdp = bpf.program_mut("pkt_classifier")?.try_into()?;

program.load()?;
for iface in interfaces {
    program.attach(iface, XdpFlags::SKB)?;
}
```

**Benefits:**

- Maps shared across all interfaces
- Lower memory usage
- Centralized aggregation

---

## ADR-008: Privilege Requirements and Capabilities

### Decision

**Use CAP_BPF + CAP_PERFMON where available; fallback to CAP_SYS_ADMIN**

### Context

eBPF program loading and attaching requires elevated permissions.

### Modern (Linux 5.8+)

```bash
# Allow running NetUI with eBPF without full root:
sudo setcap cap_bpf,cap_perfmon=ep /usr/local/bin/netui

# Check
getcap /usr/local/bin/netui
```

### Legacy (Pre-5.8)

```bash
sudo setcap cap_sys_admin=ep /usr/local/bin/netui
```

### Implementation Check

```rust
#[cfg(target_os = "linux")]
fn check_capabilities() -> Result<()> {
    use caps::{Capability, read};

    let required = vec![
        Capability::CAP_BPF,
        Capability::CAP_PERFMON,
    ];

    for cap in required {
        if !read(None, cap)? {
            eprintln!("Missing capability: {:?}", cap);
            return Err(anyhow::anyhow!("Missing capability"));
        }
    }

    Ok(())
}
```

---

## ADR-009: Error Handling in eBPF Programs

### Decision

**Fail-open: always return XDP_PASS on error; never drop packets by default**

### Context

Monitoring should not impact network reliability.

### Strategy

- On any parsing or internal error: pass packet unchanged
- Do not drop by default; dropping should only be explicit

### Example

```rust
#[xdp]
pub fn pkt_classifier(ctx: XdpContext) -> u32 {
    match classify_packet(&ctx) {
        Ok(event) => {
            let _ = PACKET_EVENTS.output(&ctx, &event, 0);
            xdp_action::XDP_PASS
        }
        Err(_) => {
            // Silently pass packet
            xdp_action::XDP_PASS
        }
    }
}
```

### Rationale

- Ensures NetUI cannot break connectivity
- Easier debugging (no hidden drops)
- Policy changes (like dropping) can be opt-in

---

## ADR-010: Testing Strategy for eBPF

### Decision

**Combination of unit tests (logic) + integration tests (real kernel)**

### Context

eBPF programs are harder to test than normal Rust code.

### Strategy

1. **Unit Tests (User-space logic)**
   - Test parsing functions (on byte slices)
   - Test aggregation logic
   - Test mapping between events and stats

2. **Integration Tests**
   - Load program with `bpftool` or Aya in test harness
   - Attach to dummy interface or veth
   - Generate traffic with `iperf3` or `tcpreplay`
   - Assert map contents and event counts

### Example Unit Test

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_generation() {
        let key = FlowKey::new(
            ipv4_to_u32(), [github](https://github.com/yousfisaad/netui)
            ipv4_to_u32(), [middleware](https://middleware.io/blog/ebpf-observability/)
            12345,
            53,
            IPPROTO_UDP,
        );

        assert_eq!(key.sport, 12345);
        assert_eq!(key.dport, 53);
    }
}
```

---

## Summary of Key Decisions

| ADR | Decision                 | Rationale                 |
| --- | ------------------------ | ------------------------- |
| 001 | XDP + TC                 | Performance + coverage    |
| 002 | Ring Buffer              | Efficiency + ordering     |
| 003 | 10k flows + LRU          | Balanced memory/coverage  |
| 004 | Lazy deletion            | Zero kernel overhead      |
| 005 | Tiered L7 classification | Practical DPI             |
| 006 | Per-event emission       | User-space flexibility    |
| 007 | Shared maps              | Efficient multi-interface |
| 008 | CAP_BPF + CAP_PERFMON    | Least privilege           |
| 009 | Fail-open (XDP_PASS)     | Network stability         |
| 010 | Unit + integration tests | Reliability               |

These decisions provide a robust, performant, and maintainable architecture for NetUI’s eBPF integration.
