// FIXTURE for plane-pricing-blindness. A crate the #83 roster places at defs 16-20 (the SPLIT
// row), carrying ONE planted violation per banned act. Every census row must go RED and name
// this file.
pub fn resolves_a_card(&self) -> u64 {
    // RESOLVES A CARD, and BRANCHES ON BILLING STATE in the same line.
    if self.host.cost_pricing_enabled(&self.cost) {
        return self.rate_card_version();
    }
    0
}

pub fn prices(&self, usage: &Usage) -> u64 {
    // PRICES: a money lease, a money-nanos quantity, and the stamp a posting carries.
    let lease: CostLeaseId = self.host.cost_reserve(1_000, 0, Some(5_000));
    let settled = self.lease.settled_nanos();
    let stamp = PostingStamp { rate_card_version: 0, wall: 0, mono: 0 };
    self.lease.price_usage(&self.model, usage) + settled + stamp.wall + lease.0
}

pub fn mints_a_key(&self) -> AuditInputs {
    // MINTS A KEY: a unit identity the kernel owns.
    AuditInputs { unit_key: busbar_contract::ids::UnitKey::new(0) }
}

pub fn arithmetics_a_hold(&self, meter: &AccrualMeter) -> Option<Hold> {
    // ARITHMETICS A HOLD.
    let estimate = Estimate { per_class: Vec::new(), fee_nanos: 0 };
    meter.accrue(estimate.hold_nanos());
    Some(Hold::open(self.token, self.principal.clone(), 0))
}
