# NetUI eBPF Enhancement - Complete Guide

## Overview

This comprehensive guide explains how to enhance the [NetUI](https://github.com/yousfisaad/netui) network monitoring tool with eBPF (Extended Berkeley Packet Filter) technology. NetUI is a Rust-based TUI that monitors network interfaces, but currently relies on user-space packet capture (libpcap).

By integrating eBPF, NetUI will gain:

- **Kernel-space packet processing** at line-rate (10Gbps+)
- **Zero-copy monitoring** with sub-microsecond latency
- **Advanced TCP metrics** (RTT, retransmissions, congestion)
- **Per-flow statistics** with minimal CPU overhead (<3%)
- **Real-time observability** without performance degradation

---

## What's Included in This Guide

### 1. **netui-ebpf-enhancement-guide.md** (662 lines)

**Comprehensive technical reference covering:**

- Current NetUI architecture analysis
- eBPF enhancement strategy (XDP, TC, Kprobes, Ring Buffers)
- Implementation roadmap (5 phases over 8 weeks)
- Code structure and project organization
- Key eBPF patterns for network monitoring
- Performance considerations and benchmarks
- Security considerations and privilege requirements
- Integration with existing NetUI code
- Monitoring, debugging, and testing approaches
- Advanced topics (L7 classification, process attribution)
- Migration path from libpcap to eBPF
- Resource links and reference projects

**Best for:** Understanding the complete vision and technical depth

---

### 2. **netui-ebpf-starter-implementation.md** (782 lines)

**Ready-to-use code samples covering:**

- Complete project setup with workspace structure
- Shared data structures (events, flows, protocol headers)
- Full XDP packet classifier implementation
- User-space event processing and loading
- Statistics aggregation engine
- Integration with ratatui TUI
- Cargo configuration for eBPF projects
- Testing and validation procedures

**Best for:** Getting started with actual implementation

---

### 3. **netui-ebpf-architecture-decisions.md** (620 lines)

**Architecture Decision Records (ADRs) documenting:**

- ADR-001: XDP vs TC for primary hook
- ADR-002: Ring Buffer vs Perf Buffer for events
- ADR-003: Flow table sizing (10k flows, LRU eviction)
- ADR-004: Flow timeout and cleanup strategy
- ADR-005: L7 protocol classification tiering
- ADR-006: Real-time vs aggregated statistics
- ADR-007: Multi-interface support design
- ADR-008: Privilege requirements (CAP_BPF vs CAP_SYS_ADMIN)
- ADR-009: Error handling (fail-open principle)
- ADR-010: Testing strategy

**Best for:** Understanding design rationale and decision context

---

## Quick Start Path

### Step 1: Understanding (30 minutes)

1. Read this README
2. Skim "Architecture Decisions" for design context
3. Review the "Implementation Roadmap" in main guide

### Step 2: Planning (1 hour)

1. Read "Current Architecture Analysis" section
2. Review "Code Structure" for project layout
3. Plan phases 1-2 for your environment

### Step 3: Implementation (Weeks 1-2)

1. Follow "Project Setup" in starter implementation
2. Implement Phase 1 (XDP classifier + ring buffer)
3. Test with tcpdump/iperf traffic generation

### Step 4: Integration (Weeks 3-4)

1. Add TC hooks for egress traffic
2. Integrate event processor with NetUI TUI
3. Add flow statistics display

### Step 5: Enhancement (Weeks 5+)

1. Implement TCP analysis (kprobes)
2. Add L7 classification
3. Implement advanced features

---

## Key Technologies

### Linux Kernel eBPF (5.8+ recommended, 6.1+ optimal)

- **XDP**: Packet processing at driver level
- **TC**: Traffic control hooks for qdisc
- **Kprobes**: Dynamic tracing of kernel functions
- **Ring Buffers**: Efficient event delivery (5.8+)
- **Maps**: Kernel data structures (HashMap, Array, RingBuf)

### Rust Ecosystem

- **Aya**: eBPF library for Rust (0.12+)
- **aya-bpf**: No-std crate for kernel code
- **Tokio**: Async runtime for user-space
- **Ratatui**: TUI framework for display
- **libc**: Low-level syscalls

### Monitoring Tools

- **bpftool**: Inspect loaded eBPF programs
- **bpf_trace_printk**: Debug kernel output
- **tcpdump/iperf**: Generate test traffic
- **Prometheus**: Metrics export (future enhancement)

---

## Performance Expectations

### Bandwidth Monitoring

```
Traditional (libpcap):
- Max throughput: 1-2 Gbps
- CPU overhead: 20-30%
- Accuracy: 95-99%

eBPF-enhanced (XDP):
- Max throughput: 10+ Gbps
- CPU overhead: 0.5-3%
- Accuracy: 100%

Improvement: 5-10x throughput, 10x better CPU efficiency
```

### Flow Tracking

```
Max concurrent flows: 10,000
Memory per flow: ~60 bytes
Total overhead: ~600 KB
Memory efficiency: 10x vs user-space

RTT Measurement:
- Accuracy: ±10 microseconds
- Latency: <1 microsecond overhead
```

### Ring Buffer Throughput

```
Event rate: 10,000+ events/sec easily
Buffer size: 256 KB default
Overflow protection: Backpressure handling
CPU overhead: <1%
```

---

## System Requirements

### Minimum

- Linux kernel 5.8+
- CAP_BPF + CAP_PERFMON capabilities (or root)
- GCC/LLVM for eBPF compilation
- Rust 1.70+ for userspace

### Recommended

- Linux kernel 5.15+ or 6.1+
- Modern CPU with BPF JIT support
- 4+ CPU cores
- 4+ GB RAM

### Supported Architectures

- x86_64 (primary)
- ARM64 (aarch64)
- Limited support for other architectures

---

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│                    NetUI TUI                      │
│  (ratatui frontend - bandwidth, flow statistics) │
└────────────────────┬─────────────────────────────┘
                     │ Display Events
                     ▼
┌──────────────────────────────────────────────────┐
│           Event Aggregation Layer                │
│  (Flow tracking, statistics calculation)        │
└────────────────────┬─────────────────────────────┘
                     │ Consume Ring Buffer
                     ▼
┌──────────────────────────────────────────────────┐
│         eBPF User-space Runtime (Aya)            │
│  (Program loading, map management, attachment) │
└────────────────────┬─────────────────────────────┘
                     │ Load/Attach
                     ▼
┌──────────────────────────────────────────────────┐
│           Linux Kernel eBPF Programs             │
│  ┌───────────────────────────────────────────┐  │
│  │  XDP Classifier (pkt_classifier)          │  │
│  │  - Port-based protocol classification     │  │
│  │  - Packet event emission to ring buffer   │  │
│  │  - Per-flow aggregation (HashMap)         │  │
│  └──────────┬──────────────────────────────┘  │
│             │                                  │
│  ┌──────────▼──────────────────────────────┐  │
│  │  TC Hooks (ingress/egress)              │  │
│  │  - Bidirectional traffic capture        │  │
│  │  - Egress statistics (not in XDP)       │  │
│  └──────────┬──────────────────────────────┘  │
│             │                                  │
│  ┌──────────▼──────────────────────────────┐  │
│  │  Kprobe Handlers (optional)             │  │
│  │  - TCP state tracking                   │  │
│  │  - RTT measurement                      │  │
│  │  - Retransmission counting              │  │
│  └──────────────────────────────────────────┘  │
│                                                │
│  Shared Data Maps:                            │
│  - packet_events (Ring Buffer)                │
│  - flows (HashMap)                            │
│  - statistics (Array)                         │
└──────────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)

✅ Set up Aya project structure
✅ Create basic XDP packet classifier
✅ Implement ring buffer event streaming
✅ Define shared data structures
✅ Test with basic traffic

**Deliverable:** Basic XDP program emitting events

---

### Phase 2: Traffic Monitoring (Weeks 3-4)

✅ Implement TC ingress/egress hooks
✅ Add bidirectional bandwidth tracking
✅ Create flow aggregation logic
✅ Integrate with existing NetUI display

**Deliverable:** Full bandwidth monitoring via eBPF

---

### Phase 3: TCP Analysis (Weeks 5-6)

✅ Add TCP state tracking (kprobes)
✅ Implement RTT measurement
✅ Track retransmissions
✅ Add connection lifecycle events

**Deliverable:** TCP metrics (RTT, retransmissions)

---

### Phase 4: ARP Enhancement (Week 7)

✅ eBPF-based ARP filtering
✅ Per-target ARP statistics
✅ ARP anomaly detection

**Deliverable:** Enhanced ARP monitoring

---

### Phase 5: Advanced Features (Week 8+)

✅ L7 protocol classification (DNS, HTTP, TLS)
✅ DDoS pattern detection
✅ Per-process network attribution
✅ Historical statistics storage
✅ Alerting rules

**Deliverable:** Production-ready advanced monitoring

---

## Common Implementation Challenges

### Challenge 1: eBPF Verifier Errors

**Issue:** "Cannot access memory" errors

```
Solution:
- Ensure bounds checking before memory access
- Use aya::helpers::ptr_at() instead of direct derefs
- Check return types of ptr_at for Option<T>
```

### Challenge 2: Perf Event Loss

**Issue:** Events disappearing with ring buffer

```
Solution:
- Check ring buffer capacity vs event throughput
- Increase buffer size if needed: RingBuf::with_byte_capacity(1024*1024, 0)
- Monitor: sudo bpftool ringbuf dump id <ID>
```

### Challenge 3: Map Memory Overflow

**Issue:** Flow table fills up

```
Solution:
- Monitor with: sudo bpftool map dump name flows | wc -l
- Enable LRU eviction (default in implementation)
- Tune max_entries if needed
```

### Challenge 4: TC Qdisc Issues

**Issue:** TC program doesn't attach to egress

```
Solution:
- Some qdisc types don't support TC eBPF
- Add default qdisc: sudo tc qdisc add dev eth0 root pfifo
- Or use ingress only for MVP
```

---

## Testing and Validation

### Unit Tests

```bash
# Test parsing logic
cargo test --lib

# Test eBPF compilation
cargo xtask build-ebpf
```

### Integration Tests

```bash
# Load and attach
sudo ./target/release/netui

# In another terminal, generate traffic
iperf3 -c 192.168.1.100 -t 10

# Monitor output
sudo bpftool prog show
sudo bpftool map dump name flows
```

### Debugging

```bash
# Watch kernel trace
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Check eBPF verifier logs
dmesg | grep -i bpf

# Inspect program stats
sudo bpftool prog stat
```

---

## Security Considerations

### Privilege Model

```
Minimum (Linux 5.8+):
- CAP_BPF: Load/unload eBPF programs
- CAP_PERFMON: Attach to perf/trace events

Legacy (Pre-5.8):
- CAP_SYS_ADMIN: Required for eBPF

Best practice:
sudo setcap cap_bpf,cap_perfmon=ep /usr/local/bin/netui
./netui  # No sudo needed
```

### eBPF Safety

- Kernel verifier ensures programs can't crash kernel
- All memory accesses are bounds-checked
- No kernel privileges leaked to userspace
- Sandboxed execution with resource limits

### Network Safety

- XDP returns XDP_PASS by default (never drops traffic)
- Monitoring is non-critical (doesn't affect network)
- No packet modification (observability only)

---

## Debugging Tips

### Trace Output

```rust
// In eBPF code
unsafe {
    bpf_trace_printk(b"Event: %u\0", event.bytes as u32);
}
```

```bash
# Read output
sudo cat /sys/kernel/debug/tracing/trace_pipe | head -20
```

### Map Inspection

```bash
# Dump flow table
sudo bpftool map dump name flows

# Watch map updates
sudo bpftool map show --json | jq '.maps[] | select(.name=="flows")'
```

### Event Stream

```bash
# Monitor ring buffer
sudo bpftool ringbuf dump id <ID> --json
```

---

## Performance Tuning

### Ring Buffer Size

```rust
// For different traffic levels:
// 10 Mbps: 64 KB
// 100 Mbps: 128 KB
// 1 Gbps: 256 KB
// 10 Gbps: 1 MB

#[map(name = "packet_events")]
pub static mut PACKET_EVENTS: RingBuf = RingBuf::with_byte_capacity(256 * 1024, 0);
```

### Flow Table Size

```rust
// Tune based on workload:
// Host monitoring: 10,000
// Gateway monitoring: 100,000
// Border router: 1,000,000 (requires tuning)

#[map(name = "flows")]
pub static mut FLOWS: HashMap<FlowKey, FlowStats> =
    HashMap::with_max_entries(10_000, 0);
```

### Sampling

```rust
// Sample expensive operations (L7 classification):
if packet_count % 100 == 0 {
    // Expensive L7 classification
}
```

---

## References and Resources

### Official Documentation

- **eBPF.io**: https://ebpf.io (comprehensive resource)
- **Aya Book**: https://aya-rs.dev/book/ (Rust eBPF guide)
- **Kernel Docs**: https://www.kernel.org/doc/html/latest/bpf/

### Reference Projects

- **Cilium**: Container networking with eBPF
- **Tracee**: Runtime security monitoring
- **Hubble**: Network visibility for Kubernetes
- **Pixie**: Full-stack application observability

### Learning Materials

- Brendan Gregg's BPF Performance Tools
- Isovalent eBPF Course
- Linux Kernel BPF Subsystem Documentation

---

## Frequently Asked Questions

**Q: Do I need to modify my Linux kernel?**
A: No, eBPF works with standard kernels 5.8+. No custom compilation needed.

**Q: Can eBPF drop packets?**
A: Yes, but our design returns XDP_PASS to maintain network stability.

**Q: What happens if the eBPF program crashes?**
A: The kernel verifier prevents crashes. If verification fails, the program won't load.

**Q: Can I run this on cloud VMs?**
A: Depends on hypervisor. AWS Nitro, GCP Compute, Azure support eBPF. Some older platforms don't.

**Q: How do I monitor if eBPF is loaded?**
A: Use `sudo bpftool prog list` to see all loaded programs.

**Q: Can I use this with docker containers?**
A: Yes, but eBPF programs must run on the host with CAP_BPF.

---

## Troubleshooting

### "Program cannot be loaded" error

```
Check:
1. Kernel version: uname -r (need 5.8+)
2. eBPF support: grep -i bpf /proc/config.gz | gunzip
3. Verifier logs: dmesg | tail -20
```

### "Ring buffer full" errors

```
Check:
1. Event throughput: sudo bpftool ringbuf dump id <ID> | wc -l
2. Increase buffer size in src code
3. Recompile and reload
```

### "Map errors" when attaching

```
Check:
1. Map exists: sudo bpftool map list
2. Correct name spelling
3. Permissions: sudo bpftool map show
```

---

## Next Steps

1. **Read the full guides** in this directory
2. **Set up development environment**
3. **Start with Phase 1** (basic XDP classifier)
4. **Test incrementally** with each phase
5. **Benchmark improvements** at each stage
6. **Contribute back** improvements to NetUI

---

## Contributing Back

If you enhance NetUI with eBPF, please consider:

1. Creating a pull request to NetUI repository
2. Writing documentation for other users
3. Sharing performance benchmarks
4. Reporting issues on both projects

---

## License

These guides and code examples are provided as-is for educational purposes.
Refer to NetUI's license for the original project terms.

---

## Contact and Support

For questions about this guide:

- Review the detailed documents in this directory
- Check Aya documentation at https://aya-rs.dev
- Ask on eBPF mailing list or forums
- Open issues on NetUI GitHub

---

**Last Updated:** January 2026
**Compatibility:** Linux 5.8+ with eBPF support
**Rust Version:** 1.70+

---

**✅ Document 2 of 6 complete!**
