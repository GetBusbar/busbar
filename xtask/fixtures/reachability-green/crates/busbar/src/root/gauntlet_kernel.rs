// The kernel-loop runner: one `Units` type, built by both runners the install registers. Neither
// runner returns the unit, so each construction is a CALL of it, not a constructor's own body.
struct GauntletKernelUnit {
    key: u64,
}

impl busbar_kernel::teller::Units for GauntletKernelUnit {
    fn drive(&self) -> u64 {
        self.key
    }
}

pub fn run_gauntlet_via_kernel(key: u64) -> u64 {
    let unit = GauntletKernelUnit { key };
    unit.drive()
}

pub fn open_gauntlet_via_kernel(key: u64) -> Result<u64, u64> {
    let unit = GauntletKernelUnit { key };
    Ok(unit.drive())
}
