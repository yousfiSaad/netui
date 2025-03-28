# NetUI

## Overview

NetUI is a Rust-based interactive terminal user interface designed to monitor network interfaces. It allows you to send ARP messages through specified interfaces and listen for packets to calculate bandwidth.

## Installation

To install and run NetUI, ensure that you have Rust and Cargo installed on your system. Follow these steps:

1. Clone the repository:

   ```sh
   git clone https://github.com/yousfiSaad/netui.git
   cd netui
   ```

2. Build the project using Cargo:

   ```sh
   cargo build --release
   ```

3. Run the compiled binary:
   ```sh
   sudo ./target/release/netui
   ```

## Use the App

```sh
./target/release/netui --name eth0
```

This will start the program and watch for ARP packets on the `eth0` interface.

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
