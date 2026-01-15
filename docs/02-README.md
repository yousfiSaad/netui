# NetUI eBPF Enhancement Guide

## Introduction

NetUI is a Rust-based TUI (Terminal User Interface) for network monitoring, built with ratatui. It currently uses `pnet` for user-space packet capture. This guide covers enhancing NetUI with eBPF (Extended Berkeley Packet Filter) for kernel-space packet processing.

### What eBPF Adds

| Capability | Current (pnet) | With eBPF |
|------------|----------------|-----------|
| Throughput | 1-2 Gbps | 10+ Gbps |
| CPU overhead | 20-30% | < 3% |
| Latency | ~100 us | < 1 us |
| Packet accuracy | 95-99% | 100% |
| TCP metrics | None | RTT, retransmissions |
| L7 classification | None | DNS, HTTP, TLS |

### How It Works

eBPF programs run in the Linux kernel, processing packets before they reach user-space. NetUI loads these programs using the Aya library and receives events through a ring buffer.

---

## Technology Stack

### Core Components

| Component | Version | Purpose |
|-----------|---------|---------|
| Aya | 0.13.1+ | eBPF loader and management |
| aya-ebpf | 0.1+ | Kernel-space eBPF macros |
| Linux Kernel | 5.8+ (5.15+ recommended) | eBPF runtime |
| Rust | 1.75+ | User-space and eBPF programs |
| LLVM/Clang | 15+ | eBPF compilation |

### eBPF Program Types Used

1. **XDP (eXpress Data Path)**: Ingress packet classification at driver level
2. **TC (Traffic Control)**: Egress packet capture at qdisc level
3. **Kprobes**: TCP state tracking and RTT measurement

---

## Architecture

```
+------------------------------------------+
|              NetUI TUI                   |
|          (ratatui 0.29)                  |
+------------------+-----------------------+
                   |
                   v
+------------------------------------------+
|         Event Aggregation                |
|    (StatsAggregator, FlowTracker)        |
+------------------+-----------------------+
                   |
                   v
+------------------------------------------+
|       eBPF User-space (Aya 0.13)         |
|  - Program loading                       |
|  - Ring buffer consumer                  |
|  - Map management                        |
+------------------+-----------------------+
                   |
        +----------+----------+
        |                     |
        v                     v
+---------------+    +------------------+
| Ring Buffer   |    | Flow HashMap     |
| (events)      |    | (statistics)     |
+---------------+    +------------------+
        ^                     ^
        |                     |
+------------------------------------------+
|        Linux Kernel eBPF Programs        |
|  +----------------+  +----------------+  |
|  | XDP Classifier |  | TC Egress      |  |
|  | (ingress)      |  | (outbound)     |  |
|  +----------------+  +----------------+  |
|  +----------------+                      |
|  | TCP Kprobes    |                      |
|  | (RTT, state)   |                      |
|  +----------------+                      |
+------------------------------------------+
                   |
                   v
+------------------------------------------+
|           Network Interface              |
+------------------------------------------+
```

---

## Quick Start

### Step 1: Verify Environment

```bash
# Check kernel version (need 5.8+)
uname -r

# Verify eBPF support
cat /boot/config-$(uname -r) | grep CONFIG_BPF

# Check for required tools
which clang llvm-strip bpftool
```

### Step 2: Install Toolchain

```bash
# Install bpf-linker
cargo install bpf-linker

# Install cargo-generate (for templates)
cargo install cargo-generate
```

### Step 3: Create eBPF Workspace

```bash
# From NetUI project root
mkdir -p netui-ebpf netui-common

# Create workspace Cargo.toml
cat > Cargo.toml.workspace << 'EOF'
[workspace]
members = ["netui", "netui-ebpf", "netui-common"]
resolver = "2"

[workspace.dependencies]
aya = "0.13"
aya-ebpf = "0.1"
aya-log = "0.2"
aya-log-ebpf = "0.1"
tokio = { version = "1.40", features = ["full"] }
EOF
```

### Step 4: Build and Load

```bash
# Build eBPF programs
cargo xtask build-ebpf --release

# Build user-space
cargo build --release

# Run (requires root or CAP_BPF)
sudo ./target/release/netui
```

### Step 5: Verify

```bash
# Check loaded programs
sudo bpftool prog list | grep netui

# Monitor events
sudo bpftool map dump name EVENTS | head -20
```

---

## macOS Development Workflow

eBPF requires a Linux kernel. macOS developers must use one of these approaches:

### Option A: Linux VM (Recommended)

Best for: Full development with debugging support

**Setup with UTM (Apple Silicon):**
```bash
# 1. Download Ubuntu 22.04 ARM64 image
# 2. Create VM with:
#    - 4+ GB RAM
#    - 2+ CPU cores
#    - Shared folder for project

# 3. In VM, install dependencies
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev \
    linux-headers-$(uname -r) bpftool

# 4. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install bpf-linker
```

**Project sharing:**
```bash
# Mount shared folder
sudo mount -t 9p -o trans=virtio share /mnt/shared

# Or use rsync
rsync -avz --exclude target/ ./netui/ user@vm:~/netui/
```

### Option B: Docker with Privileged Mode

Best for: Quick testing (limited XDP support)

```bash
# Create container with eBPF support
docker run -it --privileged \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v $(pwd):/workspace \
    ubuntu:22.04

# Inside container
apt update && apt install -y build-essential clang llvm \
    libelf-dev linux-tools-common linux-tools-generic
```

**Limitations:**
- XDP may not work (depends on host kernel)
- TC hooks work in most cases
- Kprobes require matching kernel headers

### Option C: Remote Linux Development

Best for: Teams with existing Linux infrastructure

```bash
# Configure SSH
ssh-copy-id user@linux-dev-server

# Sync project
rsync -avz --exclude target/ ./netui/ user@linux-dev:~/netui/

# Build remotely
ssh user@linux-dev "cd ~/netui && cargo xtask build-ebpf --release"

# VS Code Remote SSH
# Install "Remote - SSH" extension
# Connect to linux-dev-server
```

### Cross-Compilation Notes

eBPF programs compile to BPF bytecode (architecture-independent), but:
- User-space code must match target architecture
- Testing requires actual Linux kernel
- Debugging tools (bpftool) are Linux-only

---

## Performance Expectations

### Throughput Comparison

```
pnet (current):
  Max sustainable: 1-2 Gbps
  Packet drop rate: 5-10% at saturation

XDP (with eBPF):
  Max sustainable: 10+ Gbps
  Packet drop rate: 0%

Improvement: 5-10x throughput
```

### CPU Overhead

| Scenario | pnet | XDP | TC |
|----------|------|-----|-----|
| 100 Mbps | 5% | 0.1% | 0.2% |
| 1 Gbps | 25% | 0.5% | 1% |
| 10 Gbps | Drops | 2% | 3% |

### Memory Usage

| Component | Memory |
|-----------|--------|
| Ring buffer | 256 KB default |
| Flow table (10k entries) | ~600 KB |
| Per-CPU arrays | ~64 KB |
| **Total kernel** | **~1 MB** |

---

## Common Challenges

### Challenge 1: Verifier Errors

**Symptom**: "invalid mem access" or "R1 type=ctx expected=fp"

**Solution**: Ensure bounds checking before memory access:

```rust
// Wrong - direct access
let data = unsafe { *ptr };

// Correct - bounds checked
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}
```

### Challenge 2: Ring Buffer Full

**Symptom**: Events missing or "ring buffer full" in logs

**Solution**: Increase buffer size or reduce event rate:

```rust
// Increase from 256KB to 1MB
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_capacity(1024 * 1024, 0);
```

### Challenge 3: XDP Not Attaching

**Symptom**: "Operation not supported" on attach

**Solutions**:
1. Try SKB mode instead of native: `XdpFlags::SKB_MODE`
2. Check driver support: `ethtool -i eth0`
3. Some virtual NICs (virtio, veth) need SKB mode

### Challenge 4: TC Qdisc Issues

**Symptom**: "RTNETLINK answers: Invalid argument"

**Solution**: Add clsact qdisc first:

```bash
sudo tc qdisc add dev eth0 clsact
sudo tc filter add dev eth0 egress bpf obj ./program.o sec tc_egress
```

---

## FAQs

**Q: Does eBPF require kernel modification?**
A: No. eBPF programs load dynamically into unmodified kernels 5.8+.

**Q: Can eBPF crash the kernel?**
A: No. The verifier rejects unsafe programs before loading.

**Q: What happens if eBPF loading fails?**
A: NetUI should fall back to pnet. Check implementation for fallback logic.

**Q: Can I use eBPF in containers?**
A: Yes, with `--privileged` or specific capabilities (CAP_BPF, CAP_PERFMON).

**Q: How do I debug eBPF programs?**
A: Use `bpf_printk()` for trace output:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Q: Is eBPF supported on cloud VMs?**
A: Most modern clouds support eBPF:
- AWS: Nitro instances (5.x+ kernels)
- GCP: All instances (5.4+ kernels)
- Azure: Most instances (check kernel version)

---

## Next Steps

1. Read [03-IMPLEMENTATION-GUIDE.md](03-IMPLEMENTATION-GUIDE.md) for technical details
2. Review [04-CODE-REFERENCE.md](04-CODE-REFERENCE.md) for working code
3. Check [06-COMMANDS.md](06-COMMANDS.md) for command reference

---

## Version

- **Documentation Version**: 2.0
- **Last Updated**: January 2026
- **Aya Version**: 0.13.1+
- **Linux Kernel**: 5.8+
