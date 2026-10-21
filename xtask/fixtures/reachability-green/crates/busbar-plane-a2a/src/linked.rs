// The a2a plane's linked entry (the plugin crate's `linked` module): its unit path is a `Units` impl
// built in an item its `linked-axes` row puts in the generated table (`PLANE_HOOKS`, on the plane
// axis).
pub struct A2aLinkedUnit {
    n: u64,
}

impl busbar_kernel::teller::Units for A2aLinkedUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

fn serve_a2a() -> u64 {
    let unit = A2aLinkedUnit { n: 1 };
    unit.drive()
}

pub const PLANE_DECLARATION: &str = "a2a";

pub const PLANE_HOOKS: fn() -> u64 = serve_a2a;
