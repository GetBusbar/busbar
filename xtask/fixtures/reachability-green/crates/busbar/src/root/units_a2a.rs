pub struct A2aUnits {
    n: u64,
}

impl A2aUnits {
    pub fn new(n: u64) -> Self {
        A2aUnits { n }
    }
}

impl busbar_kernel::teller::Units for A2aUnits {
    fn drive(&self) -> u64 {
        self.n
    }
}

/// The reached caller: `main` -> `serve` -> here. It returns something OTHER than the unit, so
/// the construction below is a CALL of the constructor rather than the constructor's own body.
pub fn answer() -> u64 {
    let unit = A2aUnits::new(1);
    unit.drive()
}

#[cfg(test)]
#[path = "tests/units_a2a.rs"]
mod tests;
