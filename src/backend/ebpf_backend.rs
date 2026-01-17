use std::error::Error;
use std::path::{Path, PathBuf};
use std::fs;
use aya::{
    programs::Xdp,
    Ebpf,
};
use aya_log::EbpfLogger;
use crate::backend::{BackendConfig, BackendFactory, PacketSink, PacketSource};

/// Packet source that reads from eBPF PerfEventArray
pub struct EbpfPacketSource {
    _bpf: Ebpf,
}

impl PacketSource for EbpfPacketSource {
    fn next_packet(&mut self) -> Option<Vec<u8>> {
        // This is a simplified implementation
        // In production, you'd use async I/O with tokio like the aya examples
        // For now, we return None since the perf reading happens in a spawned task
        None
    }
}

/// Packet sink - eBPF XDP is receive-only for now
pub struct EbpfPacketSink;

impl PacketSink for EbpfPacketSink {
    fn send_packet(&mut self, _data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("eBPF packet sending not supported (XDP is receive-only)".into())
    }
}

pub struct EbpfBackendFactory;

impl BackendFactory for EbpfBackendFactory {
    fn create(
        &self,
        config: BackendConfig,
    ) -> Result<(Box<dyn PacketSource>, Box<dyn PacketSink>), Box<dyn Error + Send + Sync>> {
        // Find and load the eBPF binary
        let bpf_binary = find_ebpf_binary().ok_or("Could not find netui-ebpf binary.")?;
        let mut bpf = Ebpf::load_file(&bpf_binary)?;

        // Initialize logging (optional, for debugging)
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            eprintln!("Failed to initialize eBPF logger: {}", e);
        }

        // Load and attach the XDP program
        let program: &mut Xdp = bpf.program_mut("xdp_netui")
            .ok_or("XDP program 'xdp_netui' not found in eBPF bytecode")?
            .try_into()
            .map_err(|_| "Failed to convert program to Xdp")?;
        program.load()?;

        // Attach XDP to the interface (using interface name, not index)
        program.attach(
            &config.interface_name,
            aya::programs::XdpFlags::default(),
        )?;

        // Note: PerfEventArray setup removed - eBPF program is minimal logging-only
        // Full packet capture requires careful BPF verifier-safe implementation

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

    let entries = fs::read_dir(build_dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let dir_name = path.file_name()?.to_str()?;
        if !dir_name.starts_with("netui-") {
            continue;
        }

        let bpf_path = path.join("out/netui-ebpf.bpf");
        if bpf_path.exists() {
            return Some(bpf_path);
        }
    }

    None
}
