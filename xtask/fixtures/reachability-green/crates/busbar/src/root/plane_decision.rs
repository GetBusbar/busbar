// The decision plane's linked entry, inside the composition root (the manifest's `linked-entry`
// row). Its unit path is the second kind the gate credits: a `Units` impl the entry exports, built
// in an item its `linked-axes` row puts in the generated table (`PLANE_HOOKS`, on the plane axis).
pub struct DecisionHooksUnit {
    n: u64,
}

impl busbar_kernel::teller::Units for DecisionHooksUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

fn serve_decision() -> u64 {
    let unit = DecisionHooksUnit { n: 1 };
    unit.drive()
}

pub const PLANE_DECLARATION: &str = "decision";

pub const PLANE_HOOKS: fn() -> u64 = serve_decision;
