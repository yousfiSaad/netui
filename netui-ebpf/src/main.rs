#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

#[xdp]
pub fn xdp_netui(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_netui(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// TODO(human): Implement the XDP program logic here
// The try_xdp_netui function should inspect the packet context and return an XDP action.
// For now, simply logging the packet length and passing the packet is a good start.
unsafe fn try_xdp_netui(ctx: XdpContext) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    let data = ctx.data();
    let len = data_end - data;

    info!(&ctx, "packet len: {}", len);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
