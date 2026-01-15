# NetUI eBPF Architecture Decision Records

This document contains Architecture Decision Records (ADRs) documenting key design decisions for the NetUI eBPF integration.

---

## ADR-001: XDP + TC Dual-Hook Strategy

### Status
Accepted

### Context
NetUI needs to capture both ingress and egress traffic for complete bandwidth monitoring. eBPF offers multiple attachment points with different trade-offs.

### Options Considered

| Option | Ingress | Egress | Performance | Complexity |
|--------|---------|--------|-------------|------------|
| XDP only | Yes | No | Excellent | Low |
| TC only | Yes | Yes | Good | Medium |
| XDP + TC | Yes | Yes | Excellent/Good | Medium |
| Raw socket | Yes | No | Poor | Low |

### Decision
Use **XDP for ingress** and **TC for egress**.

### Rationale
- XDP provides best-in-class ingress performance (< 1 us latency)
- TC covers egress which XDP cannot see
- Shared maps between programs avoid duplication
- Fallback: TC can handle both if XDP unavailable

### Consequences

**Positive:**
- Line-rate ingress capture
- Complete bidirectional visibility
- Optimal performance for each path

**Negative:**
- Two programs to maintain
- TC requires qdisc setup
- Slightly higher egress latency

---

## ADR-002: Ring Buffer over Perf Buffer

### Status
Accepted

### Context
Events must flow from kernel eBPF programs to user-space efficiently. Linux offers two mechanisms: Perf Buffers (older) and Ring Buffers (5.8+).

### Comparison

| Aspect | Ring Buffer | Perf Buffer |
|--------|-------------|-------------|
| Memory | Single shared | Per-CPU |
| Ordering | Global | Per-CPU only |
| Backpressure | Better | Drops events |
| API | Simple | Complex |
| Kernel | 5.8+ | 4.4+ |

### Decision
Use **Ring Buffer** with Linux 5.8+ requirement.

### Rationale
- Global ordering simplifies flow correlation
- Lower memory footprint (256 KB vs 8 MB for 8 CPUs)
- Better backpressure handling
- Simpler Aya API

### Consequences

**Positive:**
- Cleaner event processing
- Lower memory usage
- Better debugging (single stream)

**Negative:**
- Requires Linux 5.8+
- Cannot support older kernels

### Fallback
If Ring Buffer unavailable, fall back to pnet (not Perf Buffer).

---

## ADR-003: Flow Table Sizing

### Status
Accepted

### Context
Per-flow statistics require a HashMap in kernel memory. Size affects memory usage and coverage.

### Analysis

| Workload | Typical Flows | Memory @ 60 bytes/flow |
|----------|---------------|------------------------|
| Desktop | 100-500 | 30 KB |
| Server | 1,000-5,000 | 300 KB |
| Gateway | 10,000-50,000 | 3 MB |
| Router | 100,000+ | 6 MB+ |

### Decision
**10,000 entries** as default with LRU eviction.

### Rationale
- Covers desktop and server workloads
- ~600 KB kernel memory (acceptable)
- LRU eviction prevents overflow
- Configurable for gateways

### Configuration

```rust
// Default
HashMap::with_max_entries(10_000, 0)

// High-cardinality (gateway)
HashMap::with_max_entries(100_000, 0)
```

### Consequences

**Positive:**
- Reasonable memory footprint
- Automatic eviction of stale flows
- No manual cleanup needed

**Negative:**
- May lose long-lived idle flows under pressure
- Large workloads need configuration

---

## ADR-004: Lazy Flow Cleanup

### Status
Accepted

### Context
eBPF HashMaps don't support TTL. Stale flows must be cleaned up somehow.

### Options

| Strategy | Kernel Overhead | Complexity | Data Loss |
|----------|-----------------|------------|-----------|
| Kernel TTL scan | High | High | Low |
| User-space cleanup | Low | Medium | Medium |
| LRU eviction | Zero | Low | Medium |
| Lazy + Export | Zero | Medium | Low |

### Decision
**LRU eviction in kernel** + **periodic export in user-space**.

### Rationale
- LRU is automatic (no kernel overhead)
- User-space exports preserve statistics
- No complex kernel iteration

### Implementation

```rust
// User-space: export every 10 seconds
pub async fn export_stats(interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let flows = read_all_flows();
        archive_to_storage(&flows).await;
    }
}
```

### Consequences

**Positive:**
- Zero kernel cleanup overhead
- Statistics preserved before eviction
- Simple implementation

**Negative:**
- May lose stats for short-lived flows
- Export interval affects accuracy

---

## ADR-005: Tiered L7 Classification

### Status
Accepted

### Context
Full deep packet inspection (DPI) in eBPF is expensive and hits verifier limits. Need pragmatic L7 detection.

### Tiered Approach

| Tier | Location | Method | Accuracy |
|------|----------|--------|----------|
| 1 | Kernel | Port-based | 70% |
| 2 | Kernel | Signature (sampled) | 85% |
| 3 | User-space | Context/Pattern | 95% |

### Decision
Implement **tiered classification** with port-based as default.

### Implementation

```rust
// Tier 1: Port-based (always)
fn classify_by_port(port: u16) -> Protocol {
    match port {
        53 => Protocol::DNS,
        80 => Protocol::HTTP,
        443 => Protocol::HTTPS,
        22 => Protocol::SSH,
        _ => Protocol::Unknown,
    }
}

// Tier 2: Signature (sampled at 1%)
if should_sample() {
    if peek_http_signature(ctx) {
        return Protocol::HTTP;
    }
}
```

### Consequences

**Positive:**
- Low CPU overhead
- Passes verifier
- Extensible

**Negative:**
- Port-based misses non-standard ports
- Sampling may miss short flows

---

## ADR-006: Per-Event Emission

### Status
Accepted

### Context
Trade-off between kernel aggregation (less data, more complexity) and per-event emission (more data, simpler kernel).

### Options

| Approach | Kernel Complexity | Flexibility | Ring Buffer Load |
|----------|-------------------|-------------|------------------|
| Per-packet event | Low | High | High |
| Per-flow aggregate | High | Low | Low |
| Hybrid | Medium | Medium | Medium |

### Decision
**Per-packet events** from kernel, aggregate in user-space.

### Rationale
- Keeps kernel code simple
- Allows multiple aggregation views (1s, 10s, 1min)
- Easier to add new metrics
- User-space has more CPU budget

### Consequences

**Positive:**
- Simple kernel programs
- Flexible aggregation
- Easier debugging

**Negative:**
- Higher ring buffer throughput
- More user-space CPU

### Mitigation
- Increase ring buffer size for high traffic
- Use sampling for very high rates

---

## ADR-007: Shared Maps Multi-Interface

### Status
Accepted

### Context
NetUI may monitor multiple network interfaces. Maps can be per-interface or shared.

### Options

| Approach | Memory | Complexity | Aggregation |
|----------|--------|------------|-------------|
| Per-interface maps | Higher | Higher | Harder |
| Shared maps | Lower | Lower | Automatic |

### Decision
**Shared maps** across all interfaces.

### Implementation

```rust
// Single program, multiple attachments
let program: &mut Xdp = bpf.program_mut("pkt_classifier")?;
program.load()?;

for interface in interfaces {
    program.attach(&interface, XdpFlags::default())?;
}
// EVENTS and FLOWS maps are shared
```

### Consequences

**Positive:**
- Lower memory usage
- Unified flow view
- Simpler user-space

**Negative:**
- Cannot distinguish interface per-event (unless added to struct)
- Single ring buffer may bottleneck

### Enhancement
Add `interface_index` field to NetworkEvent if per-interface stats needed.

---

## ADR-008: Capability-Based Privileges

### Status
Accepted

### Context
eBPF loading requires elevated privileges. Running as root is undesirable.

### Linux Capability Model

| Kernel | Required Capabilities |
|--------|----------------------|
| < 5.8 | CAP_SYS_ADMIN |
| >= 5.8 | CAP_BPF + CAP_PERFMON |

### Decision
Use **CAP_BPF + CAP_PERFMON** on Linux 5.8+, with fallback to CAP_SYS_ADMIN.

### Implementation

```bash
# Set capabilities on binary
sudo setcap cap_bpf,cap_perfmon=ep ./target/release/netui

# Run without sudo
./netui --interface eth0
```

```rust
// Runtime check
fn check_capabilities() -> Result<()> {
    use caps::{CapSet, Capability, has_cap};

    if !has_cap(None, CapSet::Effective, Capability::CAP_BPF)? {
        return Err(anyhow!("Missing CAP_BPF"));
    }
    if !has_cap(None, CapSet::Effective, Capability::CAP_PERFMON)? {
        return Err(anyhow!("Missing CAP_PERFMON"));
    }
    Ok(())
}
```

### Consequences

**Positive:**
- Minimal privilege
- Can run without root
- Better security posture

**Negative:**
- Requires capability setup
- Old kernels need CAP_SYS_ADMIN

---

## ADR-009: Fail-Open Error Handling

### Status
Accepted

### Context
eBPF programs must not disrupt network connectivity. Error handling strategy is critical.

### Principle
**Monitoring should never break the network.**

### Implementation

```rust
#[xdp]
pub fn pkt_classifier(ctx: XdpContext) -> u32 {
    match try_classify(&ctx) {
        Ok(_) => xdp_action::XDP_PASS,
        Err(_) => xdp_action::XDP_PASS, // NEVER XDP_DROP
    }
}
```

### Rules

1. **Always return XDP_PASS on error** - Never drop packets
2. **Silent failures** - Don't crash on parse errors
3. **Graceful degradation** - Fall back to pnet if eBPF fails
4. **No blocking** - Ring buffer full? Skip event, don't block

### Consequences

**Positive:**
- Network always works
- Safe for production
- Easy debugging

**Negative:**
- May miss events silently
- Need separate monitoring for drops

### Monitoring
Add drop counter to track silent failures:

```rust
#[map]
static STATS: Array<u64> = Array::with_max_entries(4, 0);

const STAT_PACKETS: u32 = 0;
const STAT_DROPS: u32 = 1;
const STAT_ERRORS: u32 = 2;
```

---

## ADR-010: Variable IP Header Support

### Status
Accepted

### Context
IP headers can be 20-60 bytes due to options. Assuming fixed 20 bytes causes parsing errors.

### Problem

```rust
// WRONG: Assumes 20-byte header
let transport_offset = eth_offset + 20;

// Fails when IP options present:
// - Timestamp option
// - Record route
// - Security options
```

### Decision
**Always parse IHL field** to determine actual header length.

### Implementation

```rust
fn parse_ipv4(ctx: &XdpContext, eth_offset: usize) -> Result<usize, ()> {
    let ip_hdr = ptr_at::<Ipv4Header>(ctx, eth_offset)?;

    // IHL = lower 4 bits of version_ihl
    // Value is in 32-bit words, so multiply by 4
    let version_ihl = unsafe { (*ip_hdr).version_ihl };
    let ihl = (version_ihl & 0x0F) as usize;
    let ip_header_len = ihl * 4;

    // Validate: minimum 20, maximum 60
    if ip_header_len < 20 || ip_header_len > 60 {
        return Err(());
    }

    Ok(eth_offset + ip_header_len)
}
```

### Consequences

**Positive:**
- Correct parsing for all packets
- Handles options gracefully
- Future-proof

**Negative:**
- Slightly more complex code
- Extra bounds check

### Testing
Verify with packets containing IP options:
```bash
# Generate packet with timestamp option
ping -T tsonly 192.168.1.1
```

---

## Summary

| ADR | Decision | Key Benefit |
|-----|----------|-------------|
| 001 | XDP + TC | Best of both worlds |
| 002 | Ring Buffer | Efficient, ordered events |
| 003 | 10k flows | Balanced memory/coverage |
| 004 | Lazy cleanup | Zero kernel overhead |
| 005 | Tiered L7 | Practical DPI |
| 006 | Per-event | User-space flexibility |
| 007 | Shared maps | Simple multi-interface |
| 008 | CAP_BPF | Minimal privilege |
| 009 | Fail-open | Network stability |
| 010 | Variable IHL | Correct parsing |

---

## Version

- **Documentation Version**: 2.0
- **Last Updated**: January 2026
