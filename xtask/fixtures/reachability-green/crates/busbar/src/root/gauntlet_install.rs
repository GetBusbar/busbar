// The #28 rider's install, in miniature: each plane's capability key is flipped onto a kernel-loop
// runner through the kernel's two registrations, and `main.rs` calls `install()`. The gate credits a
// plane's unit path only when this chain holds link by link.
use crate::root::gauntlet_kernel::{open_gauntlet_via_kernel, run_gauntlet_via_kernel};

fn kernel_one_shot(key: u64) -> u64 {
    run_gauntlet_via_kernel(key)
}

pub fn flip_one_shot_to_kernel(capability_key: &'static str) {
    register_gauntlet_runner(capability_key, kernel_one_shot);
}

pub fn flip_session_to_kernel(capability_key: &'static str) {
    register_session_runner(capability_key, open_gauntlet_via_kernel);
}

pub fn install() {
    flip_one_shot_to_kernel(busbar_llm::PLANE_DECLARATION.key);
    flip_one_shot_to_kernel(busbar_mcp::PLANE_KEY);
    flip_one_shot_to_kernel(busbar_a2a::PLANE_KEY);
    flip_session_to_kernel(busbar_voice::PLANE_KEY);
}
