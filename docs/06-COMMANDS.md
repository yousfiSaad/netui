# NetUI eBPF Command Reference

Quick reference for all eBPF-related commands.

---

## 1. Environment Verification

### Check Kernel Version

```bash
# Need 5.8+ for ring buffers
uname -r

# Check kernel config for BPF support
cat /boot/config-$(uname -r) | grep CONFIG_BPF

# Or on systems with /proc/config.gz
zcat /proc/config.gz | grep CONFIG_BPF
```

### Expected BPF Config

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
```

### Check Capabilities

```bash
# Current process capabilities
capsh --print

# Check specific capabilities
getpcaps $$

# Verify CAP_BPF available (5.8+)
grep -i cap_bpf /usr/include/linux/capability.h
```

### Verify Tools

```bash
# Required tools
which clang llvm-strip rustc cargo bpftool

# Versions
clang --version
rustc --version
bpftool version
```

---

## 2. macOS Development Setup

### Option A: Linux VM (UTM)

```bash
# Download Ubuntu 22.04 ARM64 for Apple Silicon
# Or Ubuntu 22.04 x86_64 for Intel Macs

# In VM, install dependencies
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    bpftool \
    pkg-config

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install eBPF tooling
cargo install bpf-linker
rustup component add rust-src
```

### Option B: Docker

```bash
# Run privileged container
docker run -it --privileged \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v $(pwd):/workspace \
    --workdir /workspace \
    ubuntu:22.04

# Inside container
apt update && apt install -y \
    build-essential clang llvm libelf-dev \
    linux-tools-common linux-tools-generic \
    pkg-config curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Option C: Remote Linux

```bash
# Setup SSH key
ssh-copy-id user@linux-host

# Sync project
rsync -avz --exclude target/ \
    ./netui/ user@linux-host:~/netui/

# Build remotely
ssh user@linux-host "cd ~/netui && cargo xtask build-ebpf --release"

# Pull results
rsync -avz user@linux-host:~/netui/target/ ./target/
```

---

## 3. Project Setup

### Install Toolchain

```bash
# Install bpf-linker
cargo install bpf-linker

# Install cargo-generate
cargo install cargo-generate

# Add Rust source for eBPF compilation
rustup component add rust-src

# Verify
cargo install --list | grep bpf-linker
```

### Create eBPF Project

```bash
# Using aya template
cargo generate aya-rs/aya-template

# Or manually create workspace
mkdir netui-ebpf netui-common xtask
```

### Add Target Configuration

```bash
# Create .cargo/config.toml
mkdir -p .cargo
cat > .cargo/config.toml << 'EOF'
[build]
target-dir = "target"

[target.bpfel-unknown-none]
rustflags = ["-C", "link-arg=--target=bpf"]

[alias]
xtask = "run --package xtask --"
EOF
```

---

## 4. Build Commands

### Build eBPF Programs

```bash
# Debug build
cargo xtask build-ebpf

# Release build (recommended)
cargo xtask build-ebpf --release

# Manual build (without xtask)
cd netui-ebpf
cargo build --target=bpfel-unknown-none -Z build-std=core --release
```

### Build User-space

```bash
# Debug
cargo build

# Release
cargo build --release

# Combined
cargo xtask build-ebpf --release && cargo build --release
```

### Check Compilation

```bash
# Verify eBPF binary exists
ls -la target/bpfel-unknown-none/release/

# Check binary type
file target/bpfel-unknown-none/release/netui-ebpf
# Should show: ELF 64-bit LSB relocatable, eBPF
```

---

## 5. Loading and Attaching

### Run NetUI

```bash
# With sudo
sudo ./target/release/netui --interface eth0

# With capabilities (after setcap)
./target/release/netui --interface eth0
```

### Set Capabilities

```bash
# Set capabilities on binary
sudo setcap cap_bpf,cap_perfmon=ep ./target/release/netui

# Verify
getcap ./target/release/netui

# Clear capabilities
sudo setcap -r ./target/release/netui
```

### Manual Loading (Testing)

```bash
# Load with bpftool
sudo bpftool prog load ./target/bpfel-unknown-none/release/netui-ebpf /sys/fs/bpf/netui

# Attach XDP
sudo bpftool net attach xdp name pkt_classifier dev eth0

# Attach TC
sudo tc qdisc add dev eth0 clsact
sudo tc filter add dev eth0 egress bpf obj ./program.o sec tc_egress
```

---

## 6. Monitoring with bpftool

### List Programs

```bash
# All loaded programs
sudo bpftool prog list

# Specific program details
sudo bpftool prog show name pkt_classifier

# JSON output
sudo bpftool prog list --json | jq '.[] | select(.name == "pkt_classifier")'
```

### Program Statistics

```bash
# Runtime stats (instructions, cycles)
sudo bpftool prog stat

# Detailed profile
sudo bpftool prog profile name pkt_classifier duration 5

# CPU time breakdown
sudo bpftool prog run_time
```

### List Maps

```bash
# All maps
sudo bpftool map list

# Specific map info
sudo bpftool map show name EVENTS
sudo bpftool map show name FLOWS
```

### Dump Map Contents

```bash
# Dump all entries
sudo bpftool map dump name FLOWS

# Dump with pretty printing
sudo bpftool map dump name FLOWS --json | jq

# Count entries
sudo bpftool map dump name FLOWS | grep -c "key:"

# Lookup specific key
sudo bpftool map lookup name FLOWS key hex 01 02 03 04 ...
```

### Network Attachments

```bash
# Show all network eBPF attachments
sudo bpftool net list

# XDP attachments
sudo bpftool net show dev eth0

# TC attachments
sudo tc filter show dev eth0 egress
```

---

## 7. Debugging

### Kernel Trace Output

```bash
# Enable trace pipe
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Filter by program
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep netui

# Clear trace buffer
sudo sh -c 'echo > /sys/kernel/debug/tracing/trace'
```

### Verifier Logs

```bash
# Check kernel messages
dmesg | grep -i bpf | tail -20

# Follow kernel messages
dmesg -w | grep -i bpf

# Verbose verifier output
sudo bpftool prog load ./program.o /sys/fs/bpf/test 2>&1
```

### Debug with aya-log

```bash
# In eBPF code, use:
# info!(&ctx, "packet received");

# View logs
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Inspect Ring Buffer

```bash
# Show ring buffer info
sudo bpftool map show name EVENTS

# Dump pending events
sudo bpftool map dump name EVENTS

# Monitor event rate
watch -n 1 'sudo bpftool map show name EVENTS | grep value'
```

---

## 8. Testing with Traffic

### Generate TCP Traffic

```bash
# Start iperf3 server
iperf3 -s &

# TCP test
iperf3 -c localhost -t 10

# High bandwidth test
iperf3 -c localhost -t 10 -P 4
```

### Generate UDP Traffic

```bash
# UDP test
iperf3 -u -c localhost -b 1G -t 10

# High PPS test
iperf3 -u -c localhost -b 10G -l 64 -t 10
```

### HTTP Traffic

```bash
# Simple request
curl -s https://example.com > /dev/null

# Multiple requests
for i in {1..100}; do curl -s https://example.com > /dev/null; done
```

### ARP Traffic

```bash
# Scan network (generates ARP)
nmap -sn 192.168.1.0/24

# Single ARP request
arping -c 1 192.168.1.1
```

### Stress Test

```bash
# High packet rate
hping3 -1 -i u100 localhost  # ICMP flood

# Many connections
ab -n 10000 -c 100 http://localhost/
```

---

## 9. Cleanup

### Detach Programs

```bash
# Detach XDP
sudo bpftool net detach xdp dev eth0

# Or with ip
sudo ip link set eth0 xdp off

# Detach TC
sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact
```

### Remove Pinned Programs

```bash
# List pinned
ls /sys/fs/bpf/

# Remove
sudo rm /sys/fs/bpf/netui
```

### Clear Maps

```bash
# Delete all entries from map
sudo bpftool map delete name FLOWS all

# Or iterate and delete
for key in $(sudo bpftool map dump name FLOWS -j | jq -r '.[].key'); do
    sudo bpftool map delete name FLOWS key hex $key
done
```

### Full Cleanup

```bash
# One-liner cleanup
sudo ip link set eth0 xdp off 2>/dev/null; \
sudo tc qdisc del dev eth0 clsact 2>/dev/null; \
sudo rm -rf /sys/fs/bpf/netui* 2>/dev/null; \
echo "Cleanup complete"
```

---

## 10. One-Liners

### Quick Status Check

```bash
# Show all eBPF programs with stats
sudo bpftool prog list | head -20

# Count active flows
sudo bpftool map dump name FLOWS 2>/dev/null | grep -c "key:" || echo "0"

# Check if XDP attached
ip link show eth0 | grep -q xdp && echo "XDP attached" || echo "XDP not attached"
```

### Development Workflow

```bash
# Build and run cycle
cargo xtask build-ebpf --release && cargo build --release && sudo ./target/release/netui

# Watch for changes and rebuild
cargo watch -x "xtask build-ebpf" -x "build"
```

### Performance Monitoring

```bash
# Monitor CPU usage of eBPF
sudo perf stat -e cycles,instructions -p $(pgrep netui) -- sleep 5

# Check ring buffer utilization
watch -n 1 'sudo bpftool map show name EVENTS'
```

### Troubleshooting

```bash
# Check everything at once
echo "=== Kernel ===" && uname -r && \
echo "=== Programs ===" && sudo bpftool prog list 2>/dev/null | head -5 && \
echo "=== Maps ===" && sudo bpftool map list 2>/dev/null | head -5 && \
echo "=== Network ===" && sudo bpftool net list 2>/dev/null | head -5
```

---

## Common Error Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| "Operation not permitted" | Missing CAP_BPF | `sudo setcap cap_bpf,cap_perfmon=ep ./binary` |
| "Invalid argument" | Wrong XDP mode | Try `XdpFlags::SKB_MODE` |
| "Program too large" | Exceeds instruction limit | Split into tail calls |
| "Cannot allocate memory" | Map too large | Reduce `max_entries` |
| "Resource busy" | Program already attached | Detach first, then attach |
| "No such file" | eBPF not built | Run `cargo xtask build-ebpf` |

---

## Version

- **Documentation Version**: 2.0
- **Last Updated**: January 2026
