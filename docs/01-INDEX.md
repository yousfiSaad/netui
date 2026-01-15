# NetUI eBPF Enhancement - Documentation Index

## Overview

This documentation covers enhancing NetUI with eBPF (Extended Berkeley Packet Filter) for kernel-space network monitoring. The enhancement replaces user-space packet capture (pnet) with XDP/TC hooks for 5-10x performance improvement.

---

## Documents

### 02-README.md - Start Here

**Purpose**: Overview, quick start, and development setup

**Covers**:
- What eBPF adds to NetUI
- Technology stack (Aya 0.13+, Linux 5.8+)
- Architecture diagram
- 5-step quick start
- macOS development workflow
- Performance expectations

**Reading time**: 30-45 minutes

---

### 03-IMPLEMENTATION-GUIDE.md - Technical Reference

**Purpose**: Detailed technical guide for implementation

**Covers**:
- Current NetUI architecture analysis
- eBPF program types (XDP, TC, Kprobes)
- Variable IP header handling
- Ring buffer design
- Integration with ScannerEvent and StatsAggregator
- Project structure
- 5-phase implementation roadmap

**Reading time**: 90-120 minutes

---

### 04-CODE-REFERENCE.md - Working Code

**Purpose**: Copy-paste ready, syntactically correct code samples

**Covers**:
- Shared types (netui-common crate)
- XDP packet classifier
- TC egress hooks
- User-space loader (Aya 0.13 API)
- ScannerEvent integration
- Cargo configuration
- Build system (xtask)

**Reading time**: 60-90 minutes

---

### 05-ARCHITECTURE-DECISIONS.md - Design Rationale

**Purpose**: Architecture Decision Records (ADRs) documenting trade-offs

**Covers 10 ADRs**:
1. XDP + TC dual-hook strategy
2. Ring buffer over perf buffer
3. Flow table sizing
4. Lazy flow cleanup
5. Tiered L7 classification
6. Per-event emission
7. Shared maps multi-interface
8. Capability-based privileges
9. Fail-open error handling
10. Variable IP header support

**Reading time**: 60-90 minutes

---

### 06-COMMANDS.md - Cheatsheet

**Purpose**: Quick reference for all commands

**Covers**:
- Environment verification
- macOS development setup
- Project creation and build
- Loading and attaching programs
- Monitoring with bpftool
- Debugging
- Testing with traffic generation
- Cleanup

**Reading time**: 20-30 minutes (reference)

---

### 07-EBPF-FEATURES.md - Feature Roadmap

**Purpose**: New capabilities unlocked by eBPF migration

**Covers**:
- Performance improvements (10x throughput, <1% CPU)
- TCP metrics via kprobes (RTT, retransmits, connection states)
- L7 protocol detection (DNS, HTTP, TLS, SSH, QUIC)
- Real-time anomaly detection (port scans, ARP spoofing, SYN floods)
- Connection tracking with full TCP state machine visibility
- Per-flow kernel statistics
- Historical statistics and export options
- Implementation effort estimates

**Reading time**: 30-45 minutes

---

### 00-REFACTORING-PLAN.md - Pre-Migration Work

**Purpose**: Required refactoring before eBPF implementation

**Covers**:
- Error handling fixes (remove `process::exit` calls)
- Type abstraction (custom `MacAddr`)
- Backend trait extraction (`PacketSource`/`PacketSink`)
- Scanner refactoring for backend flexibility
- Feature flags for conditional compilation

**Reading time**: 20-30 minutes

**Note**: Complete this plan before starting eBPF implementation.

---

## Reading Paths

### Quick Start (2 hours)

1. 02-README.md (full)
2. 04-CODE-REFERENCE.md (sections 1-3)
3. 06-COMMANDS.md (sections 1-4)

**Outcome**: Get eBPF compiling and running

---

### Developer (5-7 hours)

1. 02-README.md (full)
2. 03-IMPLEMENTATION-GUIDE.md (full)
3. 04-CODE-REFERENCE.md (full)
4. 06-COMMANDS.md (full)

**Outcome**: Implement full eBPF integration

---

### Architect (3 hours)

1. 02-README.md (full)
2. 05-ARCHITECTURE-DECISIONS.md (full)
3. 03-IMPLEMENTATION-GUIDE.md (sections 1-3)

**Outcome**: Understand design decisions and trade-offs

---

### macOS Developer (special path)

1. 02-README.md section 5 (macOS Development Workflow)
2. 06-COMMANDS.md section 2 (macOS Development Setup)
3. Continue with Developer path on Linux VM

**Outcome**: Set up cross-platform development environment

---

## Version Compatibility

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Linux Kernel | 5.8 | 5.15+ |
| Aya | 0.13.1 | 0.13.1+ |
| aya-ebpf | 0.1 | 0.1+ |
| Rust | 1.75 | 1.80+ |
| LLVM/Clang | 15 | 17+ |

### Kernel Feature Matrix

| Feature | Kernel Version |
|---------|----------------|
| XDP (basic) | 4.8+ |
| Ring Buffer | 5.8+ |
| BTF/CO-RE | 5.2+ |
| CAP_BPF | 5.8+ |
| BPF LSM | 5.7+ |

---

## Prerequisites Checklist

Before starting:

- [ ] Linux kernel 5.8+ (`uname -r`)
- [ ] Rust 1.75+ (`rustc --version`)
- [ ] Clang/LLVM 15+ (`clang --version`)
- [ ] bpf-linker installed (`cargo install bpf-linker`)
- [ ] Root or CAP_BPF capability
- [ ] Network interface available (`ip link show`)

For macOS developers:
- [ ] Linux VM or remote Linux machine
- [ ] SSH access configured
- [ ] Project sync mechanism (rsync, sshfs, or shared folder)

---

## Document Statistics

| Document | Est. Lines | Code Samples |
|----------|------------|--------------|
| 00-REFACTORING-PLAN.md | ~260 | 10+ |
| 02-README.md | ~400 | 15+ |
| 03-IMPLEMENTATION-GUIDE.md | ~500 | 20+ |
| 04-CODE-REFERENCE.md | ~600 | 30+ |
| 05-ARCHITECTURE-DECISIONS.md | ~500 | 15+ |
| 06-COMMANDS.md | ~350 | 80+ |
| 07-EBPF-FEATURES.md | ~350 | 10+ |
| **Total** | **~2,960** | **180+** |

---

## Quick Links

- [Quick Start](02-README.md#quick-start)
- [macOS Development](02-README.md#macos-development-workflow)
- [XDP Classifier Code](04-CODE-REFERENCE.md#xdp-packet-classifier)
- [Ring Buffer API](03-IMPLEMENTATION-GUIDE.md#ring-buffer-design)
- [All Commands](06-COMMANDS.md)

---

## Version

- **Documentation Version**: 2.0
- **Last Updated**: January 2026
- **Target Aya**: 0.13.1+
- **Target Linux**: 5.8 - 6.x
