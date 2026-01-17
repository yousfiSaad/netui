use std::error::Error;
use std::path::{Path, PathBuf};
use std::fs;
use aya::Ebpf;
use crate::backend::{BackendConfig, BackendFactory, PacketSink, PacketSource};

pub struct EbpfPacketSource {
    // In a real implementation, this would hold the Bpf instance and maybe a PerfEventArray/RingBuf
    // For now, it's a placeholder
    _bpf: Ebpf,
}

impl PacketSource for EbpfPacketSource {
    fn next_packet(&mut self) -> Option<Vec<u8>> {
        // TODO: Implement reading from PerfEventArray/RingBuf
        // For now, return None
        None
    }
}

pub struct EbpfPacketSink;

impl PacketSink for EbpfPacketSink {
    fn send_packet(&mut self, _data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("eBPF packet sending not yet supported".into())
    }
}

pub struct EbpfBackendFactory;

impl BackendFactory for EbpfBackendFactory {
    fn create(
        &self,
        _config: BackendConfig,
    ) -> Result<(Box<dyn PacketSource>, Box<dyn PacketSink>), Box<dyn Error + Send + Sync>> {
        // Load the eBPF program
        // Note: In a real deployment, we'd embed the bytecode or load from a specific path.
        // For development, we might expect it in target/bpf...
        // But to keep it simple, let's assume we have the bytes.
        // Wait, aya usually loads from file.

        // Build script copies the eBPF binary to target/debug/build/netui-<hash>/out/netui-ebpf.bpf
        // We need to find it by searching the build directory
        let bpf_binary = find_ebpf_binary().ok_or("Could not find netui-ebpf binary.")?;

        let bpf = Ebpf::load_file(&bpf_binary)?;

        // TODO(human): Attach the XDP program to the interface here.

        Ok((
            Box::new(EbpfPacketSource { _bpf: bpf }),
            Box::new(EbpfPacketSink),
        ))
    }

    fn name(&self) -> &'static str {
        "ebpf"
    }
}

/// Find the eBPF binary in the build directory.
///
/// The build script copies the compiled eBPF program to:
/// target/debug/build/netui-<hash>/out/netui-ebpf.bpf
///
/// We search the build directory to find it.
fn find_ebpf_binary() -> Option<PathBuf> {
    let build_dir = Path::new("target/debug/build");
    if !build_dir.exists() {
        return None;
    }

    // Read the build directory and find the netui-* subdirectory
    let entries = fs::read_dir(build_dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Check if this looks like our build directory (starts with "netui-")
        let dir_name = path.file_name()?.to_str()?;
        if !dir_name.starts_with("netui-") {
            continue;
        }

        // Check for netui-ebpf.bpf in the out/ subdirectory
        let bpf_path = path.join("out/netui-ebpf.bpf");
        if bpf_path.exists() {
            return Some(bpf_path);
        }
    }

    None
}
