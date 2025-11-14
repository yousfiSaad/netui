[![Stand With Palestine](https://raw.githubusercontent.com/yousfiSaad/netui/refs/heads/releases/img/stand-with-palestine-banner.svg)](#)

# NetUI

## Overview

NetUI is a Rust-based interactive terminal user interface designed to monitor network interfaces. It allows you to send ARP messages through specified interfaces and listen for packets to calculate bandwidth.

## Installation

To install and run NetUI, ensure that you have Rust and Cargo installed on your system.

### Install from GitHub

```sh
cargo install --git https://github.com/yousfiSaad/netui.git
```

### Build from Source

```sh
git clone https://github.com/yousfiSaad/netui.git
cd netui

cargo build --release
```

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

## License

**Copyright © 2024 YOUSFI Saad. All rights reserved.**

This software is proprietary and protected by copyright laws and international treaties. Unauthorized reproduction or distribution of this software, or any portion of it, may result in severe civil and criminal penalties, and will be prosecuted to the maximum extent possible under the law.

This software is provided "as is" without warranty of any kind. See [license.txt](license.txt) for full terms.

For licensing inquiries or permissions, please contact: **yousfi.saad@gmail.com**
