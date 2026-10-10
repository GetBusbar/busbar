// The composition root of the ALL-RED fixture: it registers nothing and reaches nothing.
mod root;

// A doc comment naming every plane, which is exactly what must NOT count as a registration or as a
// reach: `busbar_llm::PLANE_DECL`, `McpPlane`, `busbar_a2a::PLANE_DECL`, `StreamingPlane`,
// `DecisionPlane`, and `root::plane_node`, `root::units_mcp`, `root::units_a2a`, `root::units_voice`,
// `root::money_book` — and a flip of every key onto the kernel loop,
// `flip_one_shot_to_kernel(busbar_mcp::PLANE_KEY)`, `register_gauntlet_runner(busbar_a2a::PLANE_KEY,
// kernel_one_shot)`. Doc comments lie; this gate reads code.
fn register_planes() {
    let installed: Vec<u8> = Vec::new();
    install_planes(installed);
}

fn install_planes(_installed: Vec<u8>) {}

// A STRING LITERAL naming a module is not a reach either — the edge scan reads the blanked copy.
fn banner() -> &'static str {
    "money_book plane_node units_a2a units_mcp units_voice units_decision registry"
}

fn main() {
    register_planes();
    let _ = banner();
}
