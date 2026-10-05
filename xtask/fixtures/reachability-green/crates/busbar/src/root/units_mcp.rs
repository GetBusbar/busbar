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

/// The reached caller: `main` -> `serve` -> here. It returns something OTHER than the unit, so
/// the construction below is a CALL of the constructor rather than the constructor's own body.
pub fn answer() -> u64 {
    let unit = McpUnit::new(1);
    unit.drive()
}

#[cfg(test)]
#[path = "tests/units_mcp.rs"]
mod tests;

/// The root unit the generated table reaches when the manifest lists this module under
/// `[package.metadata.busbar.root-units]` — the self-test's generated-table cases plant that row.
pub const ROOT_UNIT: fn() -> u64 = answer;
