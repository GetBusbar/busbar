// The mcp plane's linked entry (the plugin crate's `linked` module): its unit path is a `Units` impl
// built in an item its `linked-axes` row puts in the generated table (`PLANE_HOOKS`, on the plane
// axis).
pub struct McpLinkedUnit {
    n: u64,
}

impl busbar_kernel::teller::Units for McpLinkedUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

fn serve_mcp() -> u64 {
    let unit = McpLinkedUnit { n: 1 };
    unit.drive()
}

pub const PLANE_DECLARATION: &str = "mcp";

pub const PLANE_HOOKS: fn() -> u64 = serve_mcp;
