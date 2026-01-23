# Lima eBPF Development Setup

## Overview

This document describes the Lima VM configuration for eBPF/XDP development on macOS. The setup uses Ubuntu 24.04 with kernel 6.8 for full XDP support.

## Status: ✅ COMPLETE

The Lima VM is configured and working. XDP attachment succeeds with SKB_MODE.

## Lima Configuration File

Location: `~/.lima/enetui/lima.yaml`

```yaml
# Lima config for enetui eBPF development
# Uses default QEMU user-mode networking for XDP support

# Ubuntu 24.04 has newer kernel with better XDP support
images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    arch: "x86_64"

# Mount only the project directory
mounts:
  - location: "/Volumes/SSD-NVMe/Dev/enetui"
    writable: true
    mountPoint: "{{.Home}}/enetui"

# SSH configuration
ssh:
  localPort: 60022
  loadDotSSHPubKeys: false

# Host resolver for DNS
hostResolver:
  enabled: true

# Provisioning script to configure VM for eBPF development
provision:
  # Update system and install eBPF tools
  - mode: system
    script: |
      #!/bin/bash
      set -eux -o pipefail
      apt-get update
      apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        linux-headers-$(uname -r) \
        bpftrace \
        bpfcc-tools \
        bpftool \
        ethtool \
        tcpdump \
        curl \
        wget \
        git \
        build-essential \
        pkg-config

  # Disable LRO/GRO on network interfaces (required for XDP on virtio)
  - mode: system
    script: |
      #!/bin/bash
      set -eux -o pipefail
      # Find the primary network interface
      INTERFACE=$(ip route | grep default | awk '{print $5}')
      if [ -n "$INTERFACE" ]; then
        echo "Disabling LRO/GRO on $INTERFACE"
        ethtool -K "$INTERFACE" lro off 2>/dev/null || true
        ethtool -K "$INTERFACE" gro off 2>/dev/null || true
      fi

# Resource allocation
cpus: 4
memory: 8GiB
disk: 100GiB

# Note: Using default QEMU user-mode networking (SLIRP)
# XDP with SKB_MODE works fine with this configuration
```

## Running netui in Lima

### Quick Start

Use the provided script:
```bash
./run-lima-ebpf.sh
```

This drops you into an interactive Lima shell where you can run netui directly.

### Manual Execution

```bash
# SSH into Lima (interactive shell - TTY is auto-allocated)
limactl shell enetui

# Build the project
cd ~/enetui
cargo build --features ebpf-backend

# Run with eBPF backend (no wrapper needed - interactive shell has TTY)
sudo ./target/debug/netui --name eth0 --backend ebpf
```

**Note**: The `script` command workaround is only needed for non-interactive execution. Since `limactl shell` provides an interactive shell with proper TTY allocation, you can run netui directly.

## Verification

### Check VM Status
```bash
limactl list
```

Expected output:
```
NAME    STATUS    SSH                CPUS    MEMORY    DISK      DIR
enetui  Running   127.0.0.1:60022    4       8GiB      100GiB    ~/.lima/enetui
```

### Check XDP Attachment (while netui is running)
```bash
# In another terminal
limactl shell enetui

sudo ip link show dev eth0 | grep xdp
# Should show: prog/xdp id <N> name xdp_netui

sudo tc filter show dev eth0 egress
# Should show TC egress program
```

### Check Network Interface
```bash
limactl shell enetui -- ip link show dev eth0
```

### Check LRO/GRO Settings
```bash
limactl shell enetui -- sudo ethtool -k eth0 | grep -E "large-receive-offload|generic-receive-offload"
```

## Troubleshooting

### Orphaned BPF Programs

If XDP attachment fails with "bpf_link_create failed", previous runs may have left BPF programs attached:

**Option 1: Clean up BPF programs**
```bash
limactl shell enetui -- sudo bpftool link show
limactl shell enetui -- sudo bpftool link detach id <ID>
```

**Option 2: Restart Lima VM (Recommended)**
```bash
limactl stop enetui
limactl start enetui
```

### Terminal Issues

**Not an issue for interactive shells**: When you run `limactl shell enetui`, you get an interactive shell with proper TTY allocation. Just run netui directly:

```bash
limactl shell enetui
cd ~/enetui && sudo ./target/debug/netui --name eth0 --backend ebpf
```

**For non-interactive automation only**: If you need to run netui non-interactively (e.g., in CI/CD), use `script` to allocate a pseudo-terminal:

```bash
limactl shell enetui -- bash -c 'cd ~/enetui && script -q /dev/null -c "sudo -E ./target/debug/netui --name eth0 --backend ebpf"'
```

### If XDP Attachment Still Fails

1. **Verify network offloads are disabled:**
```bash
limactl shell enetui -- sudo ethtool -K eth0 lro off gro off tso off gso off
```

2. **Check interface name:**
```bash
limactl shell enetui -- ip link show
# Update --name argument if interface is not eth0
```

3. **Check kernel version:**
```bash
limactl shell enetui -- uname -r
# Should be 6.x for best XDP support
```

## Results Comparison

| Metric | colima | Lima (SKB_MODE) |
|--------|--------|-----------------|
| XDP Attachment | ❌ bpf_link_create error | ✅ Works |
| TC Egress Attachment | ✅ Works | ✅ Works |
| Upload Bandwidth | ❌ 0 (no XDP) | ✅ Shows correctly |
| Download Bandwidth | ❌ 0 (no XDP) | ✅ Shows correctly |

## Key Implementation Details

### SKB_MODE in eBPF Backend

The XDP program is attached with `XdpFlags::SKB_MODE` for compatibility with virtualized NICs:

```rust
// src/backend/ebpf_backend.rs:327
let xdp_link_id = program.attach(
    &config.interface_name,
    aya::programs::XdpFlags::SKB_MODE,
).map_err(...)?;
```

SKB_MODE works on any interface at the cost of slightly less performance than native XDP mode.

### VM Configuration Notes

1. **Default networking works**: Lima's QEMU user-mode networking (SLIRP) is sufficient for eBPF development with SKB_MODE
2. **SSH key loading**: Only `loadDotSSHPubKeys` exists (singular, not plural `loadDotSSHAuthorizedKeys`)
3. **No socket_vmnet required**: Default networking doesn't need additional installation
4. **Mount template variables**: Use `{{.Home}}`, `{{.Name}}`, etc. for paths inside the VM

## References

- Lima Documentation: https://lima-vm.io/
- Aya (Rust eBPF Framework): https://aya-rs.dev/
- XDP SKB Mode: https://www.iovisor.org/technology/xdp
