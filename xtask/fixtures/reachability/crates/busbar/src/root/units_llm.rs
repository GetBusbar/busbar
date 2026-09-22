// A unit path with no caller: the only non-test construction is inside its own constructor.
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

#[cfg(test)]
#[path = "tests/units_llm.rs"]
mod tests;
