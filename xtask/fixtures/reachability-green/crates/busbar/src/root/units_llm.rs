pub struct LlmUnit {
    n: u64,
}

impl LlmUnit {
    pub fn new(n: u64) -> Self {
        LlmUnit { n }
    }
}

impl busbar_kernel::teller::Units for LlmUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

/// The reached caller: `main` -> `serve` -> here. It returns something OTHER than the unit, so
/// the construction below is a CALL of the constructor rather than the constructor's own body.
pub fn answer() -> u64 {
    let unit = LlmUnit::new(1);
    unit.drive()
}

#[cfg(test)]
#[path = "tests/units_llm.rs"]
mod tests;
