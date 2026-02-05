//! eBPF program loading and attachment.
//!
//! This module handles finding the compiled eBPF binary and loading/attaching
//! XDP and TC programs to network interfaces.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use aya::{
    programs::{tc, tc::SchedClassifierLinkId, xdp::XdpLinkId, SchedClassifier, TcAttachType, Xdp},
    Ebpf,
};
use aya_log::EbpfLogger;

use crate::backend::BackendConfig;

/// Result type for eBPF loading operations.
pub type EbpfLoadResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Attachment result containing the loaded eBPF instance and link IDs.
pub struct EbpfAttachment {
    /// The loaded eBPF object
    pub bpf: Ebpf,
    /// XDP program link ID (if attached)
    pub xdp_link_id: Option<XdpLinkId>,
    /// TC egress program link ID (if attached)
    pub tc_egress_link_id: Option<SchedClassifierLinkId>,
}

/// Find the eBPF binary in the build directory.
///
/// The build script copies the compiled eBPF program to:
/// target/<profile>/build/netui-<hash>/out/netui-ebpf.bpf
///
/// We search both debug and release directories to find it.
///
/// # Returns
/// * `Some(PathBuf)` pointing to the eBPF binary if found
/// * `None` if the binary cannot be found
pub fn find_ebpf_binary() -> Option<PathBuf> {
    // Try release first, then debug
    for profile in ["release", "debug"] {
        let build_dir = Path::new("target").join(profile).join("build");
        if !build_dir.exists() {
            continue;
        }

        let entries = fs::read_dir(&build_dir).ok()?;

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
    }

    None
}

/// Load the eBPF program from a file and initialize logging.
///
/// # Arguments
/// * `bpf_binary_path` - Path to the compiled eBPF binary
///
/// # Returns
/// The loaded Ebpf object
pub fn load_ebpf_program(bpf_binary_path: &Path) -> EbpfLoadResult<Ebpf> {
    tracing::info!("Loading eBPF program from: {:?}", bpf_binary_path);

    let mut bpf =
        Ebpf::load_file(bpf_binary_path).map_err(|e| format!("Failed to load eBPF file: {}", e))?;

    // Initialize logging (optional, for debugging)
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        tracing::warn!("Failed to initialize eBPF logger: {}", e);
    }

    Ok(bpf)
}

/// Attach XDP program to an interface.
///
/// # Arguments
/// * `bpf` - Mutable reference to the loaded Ebpf object
/// * `interface_name` - Name of the network interface
///
/// # Returns
/// The XDP link ID
pub fn attach_xdp(bpf: &mut Ebpf, interface_name: &str) -> EbpfLoadResult<XdpLinkId> {
    let program: &mut Xdp = bpf
        .program_mut("xdp_netui")
        .ok_or("XDP program 'xdp_netui' not found in eBPF bytecode")?
        .try_into()
        .map_err(|_| "Failed to convert program to Xdp")?;

    program
        .load()
        .map_err(|e| format!("Failed to load XDP program: {}", e))?;

    // Attach XDP to the interface (using interface name, not index)
    // Use SKB_MODE for better compatibility with virtualized environments (virtio_net, Lima, etc.)
    // SKB mode works on any interface at the cost of slightly less performance than native mode
    let xdp_link_id = program
        .attach(interface_name, aya::programs::XdpFlags::SKB_MODE)
        .map_err(|e| {
            format!(
                "Failed to attach XDP program to interface {}: {}",
                interface_name, e
            )
        })?;

    tracing::info!(
        "Successfully attached XDP program to interface: {}",
        interface_name
    );

    Ok(xdp_link_id)
}

/// Attach TC egress program to an interface for upload bandwidth tracking.
///
/// # Arguments
/// * `bpf` - Mutable reference to the loaded Ebpf object
/// * `interface_name` - Name of the network interface
///
/// # Returns
/// The TC egress link ID
pub fn attach_tc_egress(
    bpf: &mut Ebpf,
    interface_name: &str,
) -> EbpfLoadResult<SchedClassifierLinkId> {
    // XDP captures ingress (download). TC egress captures upload traffic.
    // We DON'T use TC ingress because XDP already handles ingress,
    // and using both would count download packets twice!

    // 1. Set up clsact qdisc (required for TC egress attachment)
    tracing::info!("Setting up clsact qdisc for TC egress...");
    if let Err(e) = tc::qdisc_add_clsact(interface_name) {
        // clsact may already exist - log but continue
        tracing::info!("Note: clsact qdisc setup (may already exist): {}", e);
    }

    // 2. Load and attach TC egress program - THIS CAPTURES UPLOAD!
    tracing::info!("Loading TC egress program...");
    let tc_egress: &mut SchedClassifier = bpf
        .program_mut("tc_egress_netui")
        .ok_or("TC egress program 'tc_egress_netui' not found in eBPF bytecode")?
        .try_into()
        .map_err(|_| "Failed to convert program to SchedClassifier")?;

    tc_egress
        .load()
        .map_err(|e| format!("Failed to load TC egress program: {}", e))?;

    tracing::info!("Attaching TC egress program (captures upload bandwidth)...");
    // Attach TC egress and keep the link ID to prevent program detachment
    let tc_egress_link_id = tc_egress
        .attach(interface_name, TcAttachType::Egress)
        .map_err(|e| format!("Failed to attach TC egress program: {}", e))?;

    // Verify TC egress attachment
    tracing::info!("Successfully attached TC egress program (captures upload bandwidth)");
    tracing::info!(
        "TC egress attached - this program captures packets leaving the interface (upload)"
    );

    Ok(tc_egress_link_id)
}

/// Load and attach all eBPF programs (XDP and TC egress).
///
/// This is the main entry point for eBPF backend initialization.
///
/// # Arguments
/// * `config` - Backend configuration containing the interface name
///
/// # Returns
/// An EbpfAttachment containing the loaded programs and link IDs
pub fn load_and_attach_programs(config: &BackendConfig) -> EbpfLoadResult<EbpfAttachment> {
    // Find and load the eBPF binary
    let bpf_binary =
        find_ebpf_binary().ok_or("Could not find netui-ebpf binary. Run 'cargo build' first.")?;

    let mut bpf = load_ebpf_program(&bpf_binary)?;

    // Load and attach XDP program
    let xdp_link_id = Some(attach_xdp(&mut bpf, &config.interface_name)?);

    // Load and attach TC egress program
    let tc_egress_link_id = Some(attach_tc_egress(&mut bpf, &config.interface_name)?);

    Ok(EbpfAttachment {
        bpf,
        xdp_link_id,
        tc_egress_link_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ebpf_binary_none() {
        // With no build directory, should return None
        let result = find_ebpf_binary();
        // We can't assert None here as it may exist in a real build
        // Just verify it doesn't panic
        drop(result);
    }

    #[test]
    fn test_ebpf_attachment_creation() {
        // Test that we can create the attachment structure
        // This doesn't require actual eBPF programs
        let attachment = EbpfAttachment {
            bpf: unsafe { std::mem::zeroed() }, // Dummy for testing
            xdp_link_id: None,
            tc_egress_link_id: None,
        };
        assert!(attachment.xdp_link_id.is_none());
        assert!(attachment.tc_egress_link_id.is_none());
    }
}
