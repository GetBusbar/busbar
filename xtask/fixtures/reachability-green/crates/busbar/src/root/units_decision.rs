pub struct DecisionUnit {
    n: u64,
}

impl DecisionUnit {
    pub fn new(n: u64) -> Self {
        DecisionUnit { n }
    }
}

impl busbar_kernel::teller::Units for DecisionUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

/// The reached caller: `main` -> `serve` -> here. It returns something OTHER than the unit, so
/// the construction below is a CALL of the constructor rather than the constructor's own body.
pub fn answer() -> u64 {
    let unit = DecisionUnit::new(1);
    unit.drive()
}

#[cfg(test)]
#[path = "tests/units_decision.rs"]
mod tests;
