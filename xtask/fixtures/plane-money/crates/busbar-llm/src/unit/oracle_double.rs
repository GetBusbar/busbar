// FIXTURE: a money DOUBLE compiled only under cfg(test), living beside its parent rather than
// under a tests/ directory — the exact shape of
// crates/busbar-voice/src/runtime/voice_d2_billing_oracle.rs. Nothing about the path says "test",
// so only the `#[cfg(test)]` on its DECLARATION can tell the scanner what it is.
pub fn drive_the_lease(&self) -> u64 {
    let lease: CostLeaseId = self.host.cost_reserve(1_000, 0, Some(5_000));
    let _ = self.lease.price_usage(&self.model, &usage);
    self.lease.settled_nanos() + lease.0
}
