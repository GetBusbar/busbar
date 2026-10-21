// The llm plane's linked entry (the plugin crate's `linked` module): its unit path is a `Units` impl
// built in an item its `linked-axes` row puts in the generated table (`PLANE_HOOKS`, on the plane
// axis).
pub struct LlmLinkedUnit {
    n: u64,
}

impl busbar_kernel::teller::Units for LlmLinkedUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

fn serve_llm() -> u64 {
    let unit = LlmLinkedUnit { n: 1 };
    unit.drive()
}

pub const PLANE_DECLARATION: &str = "llm";

pub const PLANE_HOOKS: fn() -> u64 = serve_llm;
