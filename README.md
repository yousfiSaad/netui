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

### Send ARP Messages

To send ARP messages and discover hosts on a specific interface, press `s` key:

### Listen to Packets

The program also listens to packets on the specified interface and calculates the bandwidth of the sent and received packets per host.

## Features

- **Interactive Terminal UI**: Provides an interactive way to manage network interfaces.
- **ARP Message Sending**: Send ARP messages to discover hosts in the network.
- **Packet Listening**: Listen to packets on the specified interface.
- **Bandwidth Calculation**: Calculate the bandwidth of sent and received packets.

## Contributing and Code of Conduct

We welcome contributions from the community! To contribute, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request detailing your changes.

Please ensure that your contributions follow our code of conduct, which encourages respect and collaboration within our community.
