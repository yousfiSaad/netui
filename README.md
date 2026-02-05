[![Stand With Palestine](https://raw.githubusercontent.com/yousfiSaad/netui/refs/heads/releases/img/stand-with-palestine-banner.svg)](#)

# NetUI

## Overview

NetUI is a Rust-based interactive terminal user interface designed to monitor network interfaces. It allows you to send ARP messages through specified interfaces and listen for packets to calculate bandwidth.

## Installation

To install and run NetUI, ensure that you have Rust and Cargo installed on your system. Follow these steps:

- Install from crates.io:

  ```sh
  cargo install netui
  ```

- or Clone the repository and build from source:

  ```sh
  git clone https://github.com/yousfiSaad/netui.git
  cd netui

  cargo build --release
  ```

### Backend Options

NetUI supports two network monitoring backends:

| Backend | Platform | Performance | Features |
|---------|----------|-------------|----------|
| **pnet** (default) | All platforms | 1-2 Gbps | Basic packet capture |
| **eBPF** | Linux only | 10+ Gbps | Advanced metrics, kernel-level filtering |

#### Building with eBPF Backend (Linux)

```sh
# Install bpf-linker (one-time setup)
cargo install bpf-linker

# Build with eBPF backend
cargo build --release --features ebpf-backend
```

#### Building on macOS (via Colima)

Since eBPF is Linux-only, you can use Colima for cross-compilation on macOS:

```sh
# Start Colima
colima start

# Setup (one-time)
colima ssh -- bash -c "rustup toolchain install nightly && rustup component add rust-src --toolchain nightly && cargo install bpf-linker"

# Build with eBPF backend
colima ssh -- bash -c "cargo build --release --features ebpf-backend"
```

See [`docs/07-EBPF-FEATURES.md`](docs/07-EBPF-FEATURES.md) for more details on eBPF capabilities.

## Use the App

```sh
sudo ./target/release/netui --name eth0
# or
sudo netui --name eth0
# or
sudo `which netui` --name eth0
```

This will start the program and watch for packets on the `eth0` interface.

## Scope

enetui monitors **Local Area Network (LAN)** traffic only. The term "remote" in this project refers to **other devices on the same LAN**, not internet/WAN hosts.

### What enetui monitors:
- Devices on your local network segment (192.168.x.x, 10.x.x.x, etc.)
- ARP traffic for host discovery
- IPv4 packets for bandwidth statistics
- TCP connections and application traffic

### What enetui does NOT monitor:
- Internet/WAN traffic (routed through gateway)
- Traffic on other network segments/VLANs
- Encrypted VPN tunnels

## Security Considerations

enetui includes several security features to protect against network threats:

### ARP Spoofing Detection
- **MAC Change Alerts**: Detects when an IP address associates with a new MAC address, which may indicate ARP spoofing or DHCP conflicts
- Visual indicator: `[⚠ MAC CHANGED]` shown in red for affected hosts
- Alerts logged with old/new MAC addresses for forensic analysis

### ARP Reply Validation
- **Unolicited Reply Rejection**: Only accepts ARP replies that correspond to requests we sent
- **Timeout Protection**: ARP requests expire after 15 seconds (accommodates full /24 network scans)
- **Warning Logs**: Rejected replies are logged as potential ARP poisoning attempts

### Device Tracking
- **MAC-based Identity**: Devices are tracked by MAC address across DHCP IP changes
- Prevents duplicate entries when devices renew their DHCP leases
- Maintains consistent bandwidth statistics and hostname resolution

### Recommendations
- Run enetui with `sudo` for raw socket access (required for packet capture)
- Review MAC change alerts for potential ARP spoofing
- Monitor unsolicited ARP reply warnings
- Use in trusted network environments only

### Send ARP Messages

To send ARP messages and discover hosts on a specific interface, press `s` key:

### Listen to Packets

The program also listens to packets on the specified interface and calculates the bandwidth of the sent and received packets per host.

## Features

- **Interactive Terminal UI**: Provides an interactive way to manage network interfaces.
- **ARP Message Sending**: Send ARP messages to discover hosts in the network.
- **Packet Listening**: Listen to packets on the specified interface.
- **Bandwidth Calculation**: Calculate the bandwidth of sent and received packets.
- **TCP State Tracking**: Track connection states (SYN, ESTABLISHED, FIN, etc.)
- **Connection Quality Metrics**: Monitor retransmits and RTT (eBPF backend)
- **App Classification**: Categorize traffic by application/protocol

## Performance

NetUI has been optimized for high-throughput network monitoring:

| Metric | Benchmark | Target | Status |
|--------|-----------|--------|--------|
| **Packet processing** | 33 Mpps/core | 10 Mpps/core | ✅ 3x better |
| **Direction detection (eBPF)** | 1.6 ns/iter | < 20 ns | ✅ 12x better |
| **Stats aggregation** | 32 ns/iter | < 100 ns | ✅ 3x better |
| **Throughput (pnet)** | 1-2 Gbps | 1 Gbps | ✅ Meets target |
| **Throughput (eBPF)** | 5-7 Gbps | 10+ Gbps | ⚠️ Near target |

See [`PERFORMANCE_ANALYSIS.md`](PERFORMANCE_ANALYSIS.md) for detailed benchmarking results and optimization details.

### Running Benchmarks

```bash
# Run the full benchmark suite
cargo bench

# Run specific benchmark group
cargo bench --bench packet_processing
```

## Contributing and Code of Conduct

We welcome contributions from the community! To contribute, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request detailing your changes.

Please ensure that your contributions follow our code of conduct, which encourages respect and collaboration within our community.
