mod root;

// The real root includes the generated `LINKED` table (`include!(concat!(env!("OUT_DIR"),
// "/linked.rs"))`); its rows are the manifest's `[package.metadata.busbar.linked]`.
fn register_planes() {
    install_planes(Vec::from(LINKED));
}

fn install_planes(_installed: Vec<&'static str>) {}

fn seal() -> usize {
    root::registry::plane_claims().len()
}

fn serve() -> u64 {
    root::plane_node::answer()
        + root::units_mcp::answer()
        + root::units_a2a::answer()
        + root::units_voice::answer()
        + root::units_decision::answer()
}

fn main() {
    register_planes();
    root::gauntlet_install::install();
    let _ = seal();
    let _ = serve();
}
