// A unit path with no caller: the only non-test construction is inside its own constructor.
pub struct VoiceUnit {
    n: u64,
}

impl VoiceUnit {
    pub fn new(n: u64) -> Self {
        VoiceUnit { n }
    }
}

impl busbar_kernel::teller::Units for VoiceUnit {
    fn drive(&self) -> u64 {
        self.n
    }
}

#[cfg(test)]
#[path = "tests/units_voice.rs"]
mod tests;
