use aya_build::{Package, Toolchain};
use std::fs;

fn main() -> anyhow::Result<()> {
    // Only build eBPF on Linux (eBPF is a Linux kernel technology)
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.contains("linux") {
        let out_dir = std::env::var("OUT_DIR")?;

        // Determine BPF target based on endian
        let endian = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
        let bpf_target = if endian == "big" {
            "bpfeb"
        } else {
            "bpfel"
        };

        // Source binary path from the build
        let src = format!(
            "{}/netui-ebpf/{}-unknown-none/release/netui-ebpf",
            out_dir, bpf_target
        );

        // Run aya-build
        let result = aya_build::build_ebpf(
            [Package {
                name: "netui-ebpf",
                root_dir: "netui-ebpf",
                no_default_features: false,
                features: &[],
            }],
            Toolchain::Nightly,
        );

        // Handle the known bug in aya-build v0.1.3 where it fails to copy due to dir conflict
        // Check if the build actually succeeded by verifying the source binary exists
        if result.is_err() && std::path::Path::new(&src).exists() {
            // The build succeeded but the copy failed - manually copy to OUT_DIR
            let dst = format!("{}/netui-ebpf.bpf", out_dir);
            fs::copy(&src, &dst)?;
            println!("cargo:warning=aya-build workaround: copied eBPF binary to {}", dst);
            return Ok(());
        }

        result
    } else {
        println!("cargo:warning=eBPF backend is Linux-only and will not be built on this platform ({})", target);
        Ok(())
    }
}
