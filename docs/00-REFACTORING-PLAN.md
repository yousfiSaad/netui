# NetUI Refactoring Plan for eBPF Integration

This refactoring should be completed **before** implementing eBPF support.

---

## Overview

Targeted refactoring to decouple the codebase from pnet, making eBPF integration seamless. Focus on high-impact, low-risk changes.

---

## Analysis Summary

### Current State

| Component | pnet Coupling | Refactoring Needed |
|-----------|---------------|-------------------|
| `src/scanner.rs` | **High** | Yes - trait extraction |
| `src/event.rs` | **None** | No - already generic |
| `src/stats_aggregator.rs` | **None** | No - already abstracted |
| `src/app.rs` | **Medium** | Yes - `MacAddr` type |
| `Cargo.toml` | **Fixed** | Yes - feature flags |

### Key Pain Points

1. **`process::exit(1)`** calls (lines 80, 83, 251, 257, 270, 301) - prevents error propagation
2. **pnet types leak** into `Host` struct (`MacAddr` from pnet)
3. **No abstraction** over packet capture backend
4. **Hardcoded pnet** initialization in `Scanner::new()`

---

## Refactoring Strategy

### Phase 1: Error Handling Fix (Low Risk)

Replace all `process::exit(1)` with proper `Result` returns.

**Files:**
- `src/scanner.rs` lines 79-84, 249-252, 255-258, 267-270, 299-302

**Changes:**
```rust
// BEFORE:
Ok(_) => { process::exit(1); }

// AFTER:
Ok(_) => Err("Unsupported channel type".into()),
```

---

### Phase 2: Type Abstraction (Low Risk)

Create custom types to remove pnet dependency from public API.

**New file: `src/types.rs`**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn broadcast() -> Self {
        MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

// Conversion from pnet MacAddr
impl From<pnet_datalink::MacAddr> for MacAddr {
    fn from(mac: pnet_datalink::MacAddr) -> Self {
        MacAddr([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5])
    }
}
```

**Update `src/app.rs`:**
- Replace `pnet::util::MacAddr` import with `crate::types::MacAddr`
- Update `Host` struct to use custom `MacAddr`

---

### Phase 3: Backend Trait Extraction (Medium Risk)

Create abstraction layer for packet capture.

**New file: `src/backend/mod.rs`**
```rust
pub mod pnet_backend;
#[cfg(feature = "ebpf")]
pub mod ebpf_backend;

pub trait PacketSource: Send + 'static {
    fn next_packet(&mut self) -> Option<Vec<u8>>;
}

pub trait PacketSink: Send + 'static {
    fn send_packet(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
}

pub enum CaptureBackend {
    Pnet(pnet_backend::PnetCapture),
    #[cfg(feature = "ebpf")]
    Ebpf(ebpf_backend::EbpfCapture),
}
```

**New file: `src/backend/pnet_backend.rs`**
- Move `create_datalink_channel` logic here
- Implement `PacketSource` and `PacketSink` traits

---

### Phase 4: Scanner Refactoring (Medium Risk)

Generalize `Scanner` to work with any backend.

**Changes to `src/scanner.rs`:**

1. Constructor accepts backend type:
```rust
pub fn new(
    scanner_outputs: mpsc::UnboundedSender<Event>,
    interface_name: String,
    backend: BackendType,  // NEW
) -> AppResult<Self>
```

2. Replace direct pnet calls with trait methods:
```rust
// BEFORE:
if let Ok(buffer) = datalink_rx.next() { ... }

// AFTER:
if let Some(buffer) = packet_source.next_packet() { ... }
```

3. Move ARP transmission behind `PacketSink` trait (eBPF won't need this - passive monitoring only)

---

### Phase 5: Feature Flags (Low Risk)

**Update `Cargo.toml`:**
```toml
[features]
default = ["pnet-backend"]
pnet-backend = ["pnet", "pnet_datalink"]
ebpf-backend = ["aya", "aya-log"]

[dependencies]
# Existing (make optional)
pnet = { version = "0.35.0", optional = true }
pnet_datalink = { version = "0.35.0", optional = true }

# eBPF core
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }

# Packet parsing (replaces manual parsing, works in both backends)
etherparse = "0.15"

# L7 protocol detection (user-space, avoids reinventing DPI)
parse_layer7 = "0.3"
```

---

## Leveraged Libraries

Instead of building from scratch, we leverage existing tools:

| Feature | Library | Benefit |
|---------|---------|---------|
| eBPF loader | `aya` 0.13 | Pure Rust, excellent API |
| Packet parsing | `etherparse` | Fast, `no_std` compatible, replaces manual parsing |
| L7 detection | `parse_layer7` | DNS, TLS, HTTP, DHCP, NTP detection |
| Ring buffer | Aya `RingBuf` | Built into Aya |
| Interface discovery | `pnet_datalink` or `netlink-packet-route` | Already available |

### Why These Choices

**etherparse** instead of manual parsing:
- Zero-copy packet parsing
- Works in both pnet and eBPF backends
- `no_std` compatible (could use in eBPF if needed)
- Actively maintained

**parse_layer7** instead of building DPI:
- Supports DNS, TLS (with SNI), HTTP, DHCP, Modbus, NTP, Bitcoin
- User-space only (eBPF sends payload samples)
- Avoids complex signature matching in kernel

### Reference Projects

Similar projects to study for architecture patterns:

| Project | Description |
|---------|-------------|
| **RustiFlow** | Aya + flow extraction for IDS |
| **RustNet** | TUI + eBPF network monitor (very similar to NetUI) |
| **Huginn Net** | TLS/HTTP passive fingerprinting |

---

## File Changes Summary

| File | Action |
|------|--------|
| `src/types.rs` | **Create** - Custom `MacAddr` type |
| `src/backend/mod.rs` | **Create** - Trait definitions |
| `src/backend/pnet_backend.rs` | **Create** - pnet implementation |
| `src/scanner.rs` | **Modify** - Use traits, fix errors |
| `src/app.rs` | **Modify** - Use custom `MacAddr` |
| `src/main.rs` | **Modify** - Add module declarations |
| `Cargo.toml` | **Modify** - Add feature flags |

---

## Implementation Order

1. **Phase 1** (Error handling) - 30 mins
   - No breaking changes, immediate benefit

2. **Phase 2** (Types) - 45 mins
   - Isolates pnet from public API

3. **Phase 3** (Backend traits) - 1 hour
   - Creates extension point for eBPF

4. **Phase 4** (Scanner refactor) - 1.5 hours
   - Wires everything together

5. **Phase 5** (Feature flags) - 30 mins
   - Enables conditional compilation

---

## Verification

After refactoring:

1. **Build test** - `cargo build` should work unchanged
2. **Run test** - `./target/debug/netui` should work as before
3. **Feature test** - `cargo build --no-default-features` should fail gracefully
4. **eBPF stub** - Can add empty `ebpf_backend.rs` that compiles

---

## Benefits for eBPF Integration

| Benefit | Impact |
|---------|--------|
| Trait-based capture | eBPF can implement `PacketSource` |
| Feature flags | Conditional compilation for eBPF deps |
| Custom types | No pnet types in event/app layer |
| Proper errors | eBPF load failures handled gracefully |
| Modular scanner | Can swap backends at runtime |

---

## What This Doesn't Change

- UI code (`src/ui.rs`, `src/tui.rs`) - unchanged
- Stats aggregation (`src/stats_aggregator.rs`) - already abstract
- Event system (`src/event.rs`) - already generic
- Host table (`src/hosts_table.rs`) - unchanged

---

## Estimated Effort

| Phase | Time |
|-------|------|
| Phase 1 | 30 mins |
| Phase 2 | 45 mins |
| Phase 3 | 1 hour |
| Phase 4 | 1.5 hours |
| Phase 5 | 30 mins |
| **Total** | **~4 hours** |

---

## Next Steps After Refactoring

With refactoring complete, eBPF integration becomes straightforward:

1. Create `src/backend/ebpf_backend.rs`
2. Implement `PacketSource` using Aya ring buffer
3. Add `--backend ebpf` CLI flag
4. Build eBPF programs in `netui-ebpf/` workspace

---

## Version

- **Documentation Version**: 1.0
- **Last Updated**: January 2026
