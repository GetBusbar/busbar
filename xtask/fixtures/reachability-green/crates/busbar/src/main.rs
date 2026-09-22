mod root;

fn register_planes() {
    let mut installed: Vec<&'static str> = Vec::new();
    installed.push(busbar_llm::PLANE_DECL);
    installed.push(busbar_mcp::PLANE_DECL);
    installed.push(busbar_a2a::PLANE_DECL);
    installed.push(busbar_voice::PLANE_DECL);
    installed.push(busbar_decision::PLANE_DECL);
    install_planes(installed);
}

fn install_planes(_installed: Vec<&'static str>) {}

fn seal() -> usize {
    root::registry::plane_claims().len()
}

fn serve() -> u64 {
    root::units_llm::answer()
        + root::units_mcp::answer()
        + root::units_a2a::answer()
        + root::units_voice::answer()
        + root::units_decision::answer()
}

fn main() {
    register_planes();
    let _ = seal();
    let _ = serve();
}
