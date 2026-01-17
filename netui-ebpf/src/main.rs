#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[xdp]
pub fn xdp_netui(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_netui(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Simple XDP program that logs packet info and passes through
/// Packet capture via PerfEventArray is complex and requires careful bounds checking
/// that the BPF verifier can understand. For now, just log and pass.
unsafe fn try_xdp_netui(ctx: XdpContext) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    let data = ctx.data();

    // Basic bounds check
    if data >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let len = data_end - data;
    info!(&ctx, "XDP: packet len={}", len);

    // Pass all packets through to the network stack
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
