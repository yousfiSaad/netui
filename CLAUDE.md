# CLAUDE.md - NetUI Project Documentation for AI Assistants

## Project Overview

**NetUI** is a Rust-based interactive Terminal User Interface (TUI) application designed for network monitoring. It enables real-time monitoring of network interfaces, sending ARP messages, discovering hosts, and calculating bandwidth statistics per host.

- **Version**: 0.1.1
- **License**: MIT
- **Repository**: https://github.com/yousfiSaad/netui
- **Language**: Rust (Edition 2021)
- **Main Author**: yousfi saad <yousfi.saad@gmail.com>

## Project Purpose

NetUI monitors network interfaces by:
1. Sending ARP packets to discover hosts on the network
2. Listening to network packets on specified interfaces
3. Calculating and displaying bandwidth statistics (upload/download speeds) per host
4. Providing an interactive terminal UI for network monitoring

## Architecture Overview

### Core Components

```
netui/
├── src/
│   ├── main.rs              # Application entry point, CLI parsing, main loop
│   ├── app.rs               # Application state, business logic, event handlers
│   ├── scanner.rs           # Network scanning, ARP packet sending/receiving
│   ├── event.rs             # Event system (keyboard, mouse, scanner events)
│   ├── ui.rs                # UI rendering using Ratatui
│   ├── tui.rs               # Terminal UI setup and lifecycle
│   ├── stats_aggregator.rs  # Bandwidth statistics calculation with ring buffers
│   ├── hosts_table.rs       # Host table widget for displaying discovered hosts
│   └── logging.rs           # Logging configuration using tracing
├── Cargo.toml               # Dependencies and package metadata
├── README.md                # User-facing documentation
└── .github/workflows/
    └── rust.yml             # CI/CD workflow
```

### Key Data Structures

#### `App` (src/app.rs:18-31)
The main application state containing:
- `running`: Boolean flag for application lifecycle
- `sending_arps`: Flag indicating if ARP scanning is in progress
- `hosts`: Vector of discovered hosts
- `table_state`: UI table state for navigation
- `scanner`: Network scanner instance
- `stats_aggregator`: Bandwidth statistics aggregator

#### `Host` (src/app.rs:33-41)
Represents a discovered network host:
- `time`: Discovery timestamp
- `ipv4`: IPv4 address
- `mac`: MAC address
- `hostname`: Optional hostname
- `is_my_device_mac`: Flag for local device
- `speed`: Optional bandwidth statistics

#### `Event` (src/event.rs:14-25)
Event types handled by the application:
- `Tick`: Regular timer tick
- `Key(KeyEvent)`: Keyboard input
- `Mouse(MouseEvent)`: Mouse input
- `Resize(u16, u16)`: Terminal resize
- `Scanner(ScannerEvent)`: Network scanner events

#### `ScannerEvent` (src/event.rs:27-34)
Scanner-specific events:
- `HostFound(Host)`: New host discovered
- `StatTick(StatsMap)`: Statistics update
- `InterfaceName(String)`: Interface name notification
- `BeginScan`: Scan started
- `Complete`: Scan completed

### Technology Stack

#### Core Dependencies
- **tokio** (1.40.0): Async runtime with full features
- **ratatui** (0.29.0): Terminal UI framework
- **crossterm** (0.28.1): Cross-platform terminal manipulation
- **pnet/pnet_datalink** (0.35.0): Low-level network packet manipulation
- **clap** (4.5.34): Command-line argument parsing with derive macros
- **tracing/tracing-subscriber** (0.1.41/0.3.19): Structured logging and diagnostics

#### Supporting Libraries
- **color-eyre** (0.6.3): Enhanced error reporting
- **chrono** (0.4.39): Date and time handling
- **futures** (0.3.31): Future combinators
- **ringbuf** (0.4.7): Ring buffer for statistics aggregation
- **itertools** (0.14.0): Iterator utilities
- **lazy_static** (1.5.0): Static initialization
- **directories** (6.0.0): System directory paths
- **unicode-width** (0.2.0): Unicode text width calculation

## Development Workflows

### Building the Project

```bash
# Standard build
cargo build

# Release build (optimized)
cargo build --release

# Clean build artifacts
cargo clean
```

### Running the Application

**IMPORTANT**: NetUI requires root/sudo privileges to access network interfaces in promiscuous mode.

```bash
# Run from source (after building)
sudo ./target/release/netui --name eth0

# Run installed version
sudo netui --name eth0

# Or with full path
sudo `which netui` --name eth0
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocaptures

# Run specific test
cargo test test_name
```

### Installing from Source

```bash
# Clone the repository
git clone https://github.com/yousfiSaad/netui.git
cd netui

# Build and install locally
cargo install --path .

# Install from crates.io
cargo install netui
```

### CI/CD Pipeline

The project uses GitHub Actions for continuous integration:

- **Workflow File**: `.github/workflows/rust.yml`
- **Trigger**: Push or PR to `releases` branch
- **Jobs**:
  1. Build with `cargo build --verbose`
  2. Test with `cargo test --verbose`
- **Platform**: ubuntu-latest

## Code Conventions and Best Practices

### Rust Edition and Style

- **Edition**: Rust 2021
- **Formatting**: Use `cargo fmt` for consistent formatting
- **Linting**: Use `cargo clippy` for best practices

### Error Handling

- **Type**: Custom `AppResult<T>` type defined in `src/app.rs:15`
- **Framework**: Uses `color-eyre` for enhanced error messages
- **Pattern**: All fallible operations return `AppResult<T>`
- **Initialization**: Error reporting initialized in `main.rs` via `initialize_logging()`

```rust
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;
```

### Logging and Tracing

- **Framework**: `tracing` for structured logging
- **Configuration**: Set up in `src/logging.rs`
- **Usage**: Use `tracing` macros (`trace!`, `debug!`, `info!`, `warn!`, `error!`)
- **Custom macro**: `trace_dbg!` available for debug tracing

### Async Programming

- **Runtime**: Tokio with full features enabled
- **Entry Point**: `#[tokio::main]` in `src/main.rs:32`
- **Channels**: `mpsc::unbounded_channel` for event communication
- **Pattern**: Event-driven architecture with message passing

### Module Organization

Each module has a clear responsibility:
- Keep UI logic in `ui.rs` and `hosts_table.rs`
- Keep network logic in `scanner.rs`
- Keep application state in `app.rs`
- Keep event routing in `event.rs`
- Follow Rust's privacy conventions (use `pub` deliberately)

### Event Loop Pattern

The application uses a centralized event loop in `main.rs:51-62`:

```rust
while app.running {
    tui.draw(&mut app)?;
    match events.next().await? {
        Event::Tick => app.tick(),
        Event::Key(key_event) => app.handle_key_events(key_event)?,
        Event::Mouse(_) => {}
        Event::Resize(_, _) => {}
        Event::Scanner(worker_event) => app.handle_worker_events(worker_event)?,
    }
}
```

## User Interface and Keybindings

### Keyboard Controls (src/app.rs:162-212)

- **`q`** or **`ESC`**: Quit application (close help screen if open)
- **`Ctrl+C`**: Quit application
- **`?`** or **`F1`**: Show/hide help screen
- **`s`**: Send ARP packets to scan network (if not already scanning)
- **`e`** or **`E`**: Export discovered hosts to CSV file
- **`j`**: Navigate to next row (vim-style)
- **`k`**: Navigate to previous row (vim-style)
- **`l`**: Navigate to next column (vim-style)
- **`h`**: Navigate to previous column (vim-style)
- **`c`** or **`C`**: Clean selected host and older entries

### UI Layout (src/ui.rs:11-24)

The interface is divided into:
1. **Table Area**: Hosts table showing discovered devices (100% height)
2. **Footer Area**: Status information (3 lines)

### Host Table Columns

Each host displays:
- Timestamp of discovery
- IPv4 address
- MAC address
- Hostname (if available)
- Upload/Download speed statistics

## Network Operations

### ARP Scanning

- Triggered by pressing `s` key
- Sends ARP requests to discover hosts on the network
- Scanner runs in background using Tokio tasks
- Events sent back through mpsc channel

### Packet Listening

- Continuously listens on specified network interface
- Captures IPv4 packets (TCP, UDP)
- Tracks packet sizes per host
- Calculates bandwidth using ring buffer with sliding window

### Statistics Aggregation (src/stats_aggregator.rs)

- Uses `ringbuf::HeapRb` for sliding window statistics
- Default window size: 10 samples
- Tracks four directions:
  - Outgoing (upload)
  - Incoming (download)
  - Local (loopback)
  - None (other)
- Calculates speed per host from accumulated packet sizes

## Recent Improvements (2024)

### Code Quality
- **Fixed critical bugs**: Replaced 6 `process::exit()` calls with proper error handling
- **Fixed typos**: `sdt_port` → `dst_port`, `Incomming` → `Incoming`
- **Fixed integer overflow**: In `format_size()` function
- **Removed all `.unwrap()` calls**: Replaced with proper error handling and logging
- **Removed commented-out code**: Cleaned up codebase
- **Zero clippy warnings**: All code quality checks pass

### New Features
- **Help Screen**: Interactive help overlay with `?` or `F1`
- **CSV Export**: Export hosts to timestamped CSV files with `e` key
- **Test Suite**: 9 unit tests covering core components

### Security & Dependencies
- **Updated 121 dependencies**: Latest compatible versions
- **Fixed vulnerabilities**: Addressed GitHub-reported security issues

## Common Tasks for AI Assistants

### Adding a New Feature

1. **Identify the component**: Determine which module needs modification
2. **Update data structures**: Modify `App` or `Host` if needed
3. **Add event handling**: Update `handle_key_events` or `handle_worker_events`
4. **Update UI**: Modify `ui.rs` or `hosts_table.rs` for display changes
5. **Add tests**: Create tests in `tests/` directory
6. **Test thoroughly**: Ensure async operations work correctly
7. **Update documentation**: Keep README.md and this file current

### Debugging

1. **Enable tracing**: Set `RUST_LOG=debug` or `RUST_LOG=trace` environment variable
2. **Check logs**: Logs are stored in directories specified by `directories` crate
3. **Use `trace_dbg!` macro**: For temporary debug output
4. **Check permissions**: Many issues relate to insufficient privileges for network access

### Modifying Network Behavior

- **Scanner logic**: Edit `src/scanner.rs`
- **Packet handling**: Look for `Ipv4Packet`, `TcpPacket`, `UdpPacket` usage
- **ARP operations**: Check `ArpPacket` and `MutableArpPacket` handling
- **Interface selection**: See `find_interface_or_get_default` function

### Updating Dependencies

```bash
# Update Cargo.lock
cargo update

# Update specific dependency
cargo update -p dependency_name

# Check for outdated dependencies
cargo outdated  # requires cargo-outdated
```

### Performance Considerations

- **Ring buffers**: Statistics use fixed-size ring buffers for memory efficiency
- **Async operations**: Network scanning runs in background tasks
- **Event batching**: Events processed sequentially in main loop
- **Host deduplication**: Hosts identified by IP+MAC combination (src/app.rs:43-47)

## Security Considerations

1. **Requires root privileges**: Application needs elevated permissions for raw socket access
2. **Network interface access**: Directly accesses network hardware in promiscuous mode
3. **ARP packets**: Sends ARP requests that can be detected on the network
4. **No authentication**: Application doesn't implement any authentication mechanism
5. **Local use only**: Designed for local network monitoring, not remote access

## Git Workflow

### Branching Strategy

- **Main development**: `releases` branch
- **CI triggers**: Push or PR to `releases` branch
- **Feature branches**: Branch from `releases` for new features

### Contributing Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -am 'Add some feature'`
4. Push to branch: `git push origin feature/your-feature`
5. Open pull request to `releases` branch

## Common Pitfalls and Solutions

### Issue: Permission Denied

**Symptom**: Application fails to start or can't access network interface

**Solution**: Run with `sudo` - raw socket access requires root privileges

### Issue: Interface Not Found

**Symptom**: Error about interface not existing

**Solution**:
- List available interfaces: `ip link show` or `ifconfig`
- Use exact interface name: `eth0`, `wlan0`, `enp0s3`, etc.

### Issue: Build Failures

**Symptom**: Compilation errors

**Common causes**:
- Outdated Rust version (requires stable Rust)
- Missing system libraries for `pnet` (libpcap-dev on Debian/Ubuntu)

**Solution**:
```bash
# Update Rust
rustup update

# Install system dependencies (Debian/Ubuntu)
sudo apt-get install libpcap-dev

# Install system dependencies (Fedora/RHEL)
sudo dnf install libpcap-devel
```

### Issue: Stats Not Updating

**Symptom**: Bandwidth statistics show zero or don't update

**Possible causes**:
- No network traffic on interface
- Firewall blocking promiscuous mode
- Interface not in promiscuous mode

## File Patterns to Ignore

As specified in `.gitignore`:
- `/target` - Build artifacts
- `todos.txt` - Personal todo file

## Additional Resources

- **Ratatui Documentation**: https://ratatui.rs/
- **pnet Documentation**: https://docs.rs/pnet/
- **Tokio Tutorial**: https://tokio.rs/tokio/tutorial
- **Rust Book**: https://doc.rust-lang.org/book/

## Questions to Ask Before Making Changes

1. Does this change affect network packet handling? (Consider security implications)
2. Does this add new dependencies? (Check license compatibility and maintenance status)
3. Does this change the UI layout? (Test on different terminal sizes)
4. Does this affect async operations? (Ensure proper error handling and cancellation)
5. Does this require documentation updates? (Update README.md and this file)
6. Does this work on all platforms? (Consider Linux, macOS, Windows compatibility)

## Project Metadata

- **crates.io**: Published package available
- **Keywords**: cli, tui, network, monitor, ARP
- **Repository**: https://github.com/yousfiSaad/netui.git
- **Minimum Rust Version**: Not specified (use latest stable)

---

*This document is maintained for AI assistants working on the NetUI project. Keep it updated when making significant architectural changes.*
