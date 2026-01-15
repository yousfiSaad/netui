# NetUI eBPF Enhancement - Quick Reference Commands

## Environment Setup

### Check Kernel Version & eBPF Support

```bash
# Check kernel version
uname -r
# Need 5.8+

# Check eBPF configuration
grep -i bpf /boot/config-$(uname -r)
# Should see: CONFIG_BPF=y, CONFIG_BPF_JIT=y

# Verify eBPF is enabled
sudo sysctl kernel.unprivileged_bpf_disabled
# 0 = enabled (good), 1 = disabled (can't run unprivileged)
```

### Install Development Tools

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  clang \
  llvm \
  libelf-dev \
  libpcap-dev \
  pkg-config

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Rust targets
rustup target add x86_64-unknown-linux-musl

# Install bpf-linker
cargo install bpf-linker

# Install aya-tool for generating bindings
cargo install aya-tool
```

### Set Capabilities for Non-root Execution

```bash
# After building, set capabilities
sudo setcap cap_bpf,cap_perfmon=ep /usr/local/bin/netui

# Verify
getcap /usr/local/bin/netui

# Run without sudo
./netui
```

---

## Project Creation

### Create New eBPF Project

```bash
# Using Aya template
cargo generate https://github.com/aya-rs/aya-template
# Choose project name and XDP as program type

# Or create workspace manually
cargo new --name netui-enhanced netui-enhanced
cd netui-enhanced

# Create subcrates
cargo new --lib netui-ebpf-sys
cargo new --lib netui-common
cargo new netui
```

### Build eBPF Programs

```bash
# Build kernel-space programs
cargo xtask build-ebpf

# Build release version (optimized)
cargo xtask build-ebpf --release

# Check compilation output
ls -la target/bpfel-unknown-none/release/*.o
```

---

## Compilation & Loading

### Compile Everything

```bash
# Full build (eBPF + userspace)
cargo build --release

# Build only eBPF
cargo xtask build-ebpf --release

# Build only userspace
cargo build --release -p netui

# Check binary size
ls -lh target/release/netui
```

### Load eBPF Programs

```bash
# Load and attach (requires proper permissions)
sudo ./target/release/netui

# Or with capabilities (no sudo needed)
./target/release/netui

# Detach on exit (programs unload automatically)
```

---

## Monitoring eBPF Programs

### List Loaded Programs

```bash
# Show all loaded eBPF programs
sudo bpftool prog list

# Show with more details
sudo bpftool prog list -json | jq '.[] | {id, name, type, tag}'

# Show by type (xdp, tc, etc.)
sudo bpftool prog list type xdp
```

### Show Program Statistics

```bash
# CPU time and call count
sudo bpftool prog stat

# Detailed stats
sudo bpftool prog stat --json

# Watch stats in real-time
watch -n 1 'sudo bpftool prog stat'
```

### Check Attached Programs

```bash
# Show XDP program on interface
sudo bpftool net show

# Show TC programs
sudo tc filter show dev eth0 ingress
sudo tc filter show dev eth0 egress

# Remove if needed
sudo tc filter del dev eth0 ingress
sudo tc filter del dev eth0 egress
```

---

## Map Operations

### Inspect Maps

```bash
# List all maps
sudo bpftool map list

# Show map details
sudo bpftool map show

# Get map info by ID
sudo bpftool map show id <ID>

# Show with JSON
sudo bpftool map list -json

# Watch map size
watch -n 1 'sudo bpftool map list'
```

### Dump Map Contents

```bash
# Dump entire map
sudo bpftool map dump name flows

# Dump specific map by ID
sudo bpftool map dump id <ID>

# Format as JSON
sudo bpftool map dump name flows -j | jq '.'

# Count entries
sudo bpftool map dump name flows | wc -l

# Find max entries
sudo bpftool map show name flows | grep max_entries
```

### Monitor Map Updates

```bash
# Watch map size (simple loop)
while true; do
  count=$(sudo bpftool map dump name flows 2>/dev/null | wc -l)
  echo "Active flows: $count"
  sleep 1
done
```

---

## Ring Buffer Operations

### Monitor Events

```bash
# Dump ring buffer contents
sudo bpftool ringbuf dump id <RINGBUF_ID>

# Find ring buffer ID first
sudo bpftool map list | grep ringbuf

# Watch in real-time
sudo bpftool ringbuf dump id <ID> --json | jq '.'

# Count events
sudo bpftool ringbuf dump id <ID> | wc -l
```

### Monitor Ring Buffer Performance

```bash
# Get ring buffer stats
sudo bpftool map show id <RINGBUF_ID> -j | jq '.[] | {name, value_size, max_entries}'

# Check for overflow
dmesg | grep -i "ring buffer\|overflow"

# Monitor kernel logs for errors
sudo journalctl -k | grep -i bpf
```

---

## Testing & Traffic Generation

### Generate Test Traffic

```bash
# Using iperf3 (continuous traffic)
iperf3 -s                    # Start server
iperf3 -c localhost -t 10    # Client, 10 second test

# Using ping (ICMP)
ping -c 100 8.8.8.8

# Using curl (HTTP)
while true; do
  curl -s https://example.com > /dev/null
  sleep 1
done

# Using ncat (TCP connections)
ncat -l localhost 8888 &
for i in {1..100}; do
  (echo "test" | ncat localhost 8888) &
done
wait
```

### Packet Capture Validation

```bash
# Capture packets for comparison
tcpdump -i eth0 -w traffic.pcap 'tcp or udp' &
TCPDUMP_PID=$!

# Run eBPF program
./target/release/netui

# Stop capture
kill $TCPDUMP_PID

# Analyze capture
tcpdump -r traffic.pcap | head -20

# Count packets by protocol
tcpdump -r traffic.pcap -n | awk '{print $NF}' | sort | uniq -c
```

---

## Debugging

### Kernel Trace Output

```bash
# Enable tracing
echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on

# Watch trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# In another terminal, run program
./target/release/netui

# Clear trace buffer
echo > /sys/kernel/debug/tracing/trace

# Disable tracing when done
echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_on
```

### Check Kernel Logs

```bash
# Watch kernel messages
dmesg -w

# Filter for eBPF errors
dmesg | grep -i bpf | tail -20

# Check for verification failures
dmesg | grep "verifier\|verify"

# Export all messages to file
dmesg > kernel_messages.txt
```

### Verifier Output

```bash
# Get detailed verifier output when loading
sudo bpftool prog load /path/to/program.o type xdp verbose

# Check latest kernel error
sudo dmesg | tail -50 | grep -A 10 "verifier\|rejected"
```

---

## Performance Analysis

### Monitor eBPF CPU Usage

```bash
# Watch program stats
watch -n 0.5 'sudo bpftool prog stat'

# Use perf to profile
sudo perf stat -e bpf:* ./target/release/netui

# Detailed performance counters
perf record -F 997 -e \
  cycles,instructions,L1-dcache-load-misses,LLC-loads,node-load \
  ./target/release/netui

# Show results
perf report
```

### Measure Throughput

```bash
# Start eBPF program
./target/release/netui &
APP_PID=$!

# Generate traffic
iperf3 -c localhost -t 30 &

# Monitor ring buffer throughput
watch -n 0.1 'sudo bpftool ringbuf dump id <ID> | wc -l'

# Cleanup
kill $APP_PID
```

### Memory Usage

```bash
# Check eBPF map memory
sudo bpftool map show -j | \
  jq '.[] | select(.type=="hash") | {name, value_size, max_entries}'

# Monitor netui process
watch -n 1 'ps aux | grep netui'
```

---

## Troubleshooting

### Program Won't Load

```bash
# Check kernel version
uname -r  # Need 5.8+

# Check capabilities
getcap /usr/local/bin/netui
# Set if needed:
sudo setcap cap_bpf,cap_perfmon=ep /usr/local/bin/netui

# Check verifier logs
dmesg | tail -20 | grep -i "bpf\|verif"

# Try with verbose flag
sudo bpftool prog load program.o type xdp verbose

# Check unprivileged BPF state
cat /proc/sys/kernel/unprivileged_bpf_disabled  # 0 preferred
```

### Map Full Errors

```bash
# Check current map size
sudo bpftool map dump name flows | wc -l

# Check max size
sudo bpftool map show name flows | grep max_entries

# Increase (requires code + rebuild)
# Example:
# HashMap::with_max_entries(20_000, 0)
cargo xtask build-ebpf --release
cargo build --release
```

### Ring Buffer Overflow

```bash
# Check buffer size
sudo bpftool map show name packet_events

# Monitor for drops
dmesg | grep "ring buffer\|overflow"

# Increase capacity (code change)
# RingBuf::with_byte_capacity(512 * 1024, 0)
cargo xtask build-ebpf --release
cargo build --release
```

### Interface Won't Attach

```bash
# Check interface exists
ip link show eth0

# List all interfaces
ip link show

# Check if XDP already attached
sudo bpftool net show

# Remove existing XDP
sudo ip link set dev eth0 xdp off

# Try attaching again
./target/release/netui
```

---

## Cleanup

### Remove Programs

```bash
# List loaded programs
sudo bpftool prog list

# Delete by ID
sudo bpftool prog del id <ID>

# Or just detach from interface
sudo ip link set dev eth0 xdp off
sudo tc filter del dev eth0 ingress
```

### Clear Maps

```bash
# In normal operation, maps are removed when programs unload.
# Only do manual cleanup if necessary (e.g., pinned maps left behind).

sudo rm -rf /sys/fs/bpf/netui_*
```

### Remove Build Artifacts

```bash
# Clean build directory
cargo clean

# Remove just eBPF objects
rm -rf target/bpfel-unknown-none
rm -rf target/x86_64-unknown-linux-gnu
```

---

## Development Workflow

### Quick Edit-Compile-Test Cycle

```bash
# 1. Edit eBPF code
vim netui-ebpf/src/xdp_classifier.rs

# 2. Build
cargo xtask build-ebpf --release && cargo build --release

# 3. Stop old program
pkill -f netui || true

# 4. Start new program
sudo ./target/release/netui

# 5. Test with traffic
iperf3 -c localhost -t 5

# 6. Monitor
sudo bpftool prog stat
sudo bpftool map dump name flows | head -5
```

### Automated Build Script

```bash
#!/bin/bash
set -e

echo "[*] Building eBPF programs..."
cargo xtask build-ebpf --release

echo "[*] Building userspace..."
cargo build --release

echo "[*] Killing old instance..."
pkill -f netui || true
sleep 1

echo "[*] Loading new instance..."
sudo ./target/release/netui &
APP_PID=$!

echo "[*] Waiting for attachment..."
sleep 2

echo "[*] Current stats:"
sudo bpftool prog stat

echo "[*] Ready! PID: $APP_PID"
```

---

## References & Help

### Online Documentation

```bash
# eBPF.io guide
xdg-open https://ebpf.io

# Aya documentation
xdg-open https://aya-rs.dev/book/

# Linux kernel eBPF guide
man bpf  # Local man page

# bpftool manual
man bpftool
```

### Get Help

```bash
# bpftool general help
sudo bpftool -h

# Program-specific help
sudo bpftool prog -h

# Map-specific help
sudo bpftool map -h

# Net help
sudo bpftool net -h
```

---

## Common One-Liners

### Monitor Everything

```bash
watch -n 0.5 '
  echo "=== Programs ===" &&
  sudo bpftool prog stat &&
  echo "=== Maps ===" &&
  sudo bpftool map list | head -5 &&
  echo "=== Active Flows ===" &&
  sudo bpftool map dump name flows 2>/dev/null | wc -l
'
```

### Quick End-to-End Test

```bash
(sudo ./target/release/netui &) && \
  sleep 2 && \
  iperf3 -c 127.0.0.1 -t 5 && \
  sudo bpftool prog stat && \
  pkill netui
```

### Performance Snapshot

```bash
echo "=== System Info ===" &&
  uname -r &&
  lscpu | grep "CPU(s)" &&
  echo "=== eBPF Support ===" &&
  zgrep BPF /proc/config.gz | head -5 &&
  echo "=== Running Programs ===" &&
  sudo bpftool prog stat
```

---

**Last Updated:** January 2026  
**Compatible with:** Linux 5.8+, Aya 0.12+, Rust 1.70+
