// A unit path with no caller: the only non-test construction is inside its own constructor.
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

#[cfg(test)]
#[path = "tests/units_decision.rs"]
mod tests;
