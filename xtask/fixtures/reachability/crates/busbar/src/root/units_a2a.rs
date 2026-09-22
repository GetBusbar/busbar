// A unit path with no caller: the only non-test construction is inside its own constructor.
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

#[cfg(test)]
#[path = "tests/units_a2a.rs"]
mod tests;
