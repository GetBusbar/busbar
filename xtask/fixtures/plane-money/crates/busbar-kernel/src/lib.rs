// FIXTURE: a NON-plane crate carrying the SAME acts. The kernel is exactly where they belong,
// so none of this may appear in any census row. This is what proves the scope is the roster's
// plane set and not the whole tree.
pub fn kernel_prices(&self, usage: &Usage) -> Option<Hold> {
    if self.host.cost_pricing_enabled(&self.cost) {
        let _v = self.rate_card_version();
    }
    let _lease: CostLeaseId = self.host.cost_reserve(1_000, 0, Some(5_000));
    let _settled = self.lease.settled_nanos();
    let _k = busbar_contract::ids::UnitKey::new(0);
    let meter = AccrualMeter::new();
    meter.accrue(Estimate::zero().hold_nanos());
    Some(Hold::open(self.token, self.principal.clone(), 0))
}
