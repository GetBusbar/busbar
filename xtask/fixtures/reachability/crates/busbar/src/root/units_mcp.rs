// A unit path with no caller: the only non-test construction is inside its own constructor.
pub struct McpUnit {
    n: u64,
}

impl McpUnit {
    pub fn new(n: u64) -> Self {
        McpUnit { n }
    }
}

impl busbar_kernel::teller::Units for McpUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

#[cfg(test)]
#[path = "tests/units_mcp.rs"]
mod tests;
