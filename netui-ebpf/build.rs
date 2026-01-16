fn main() {
    // Tell cargo to rerun this build script if the Rust source code changes.
    println!("cargo:rerun-if-changed=src");

    // Emit cfg flags that describe the desired BPF target architecture.
    aya_build::emit_bpf_target_arch_cfg();
}
