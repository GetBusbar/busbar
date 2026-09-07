//! Tests for `rate_apply.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// With nothing installed the seam is silent, and that is the whole of what a build without a
/// root ledger should do with a rate change.
#[test]
fn an_uninstalled_seam_swallows_the_apply() {
    rates_applied(&RawRates {
        lanes: &[],
        fee_cents: 7,
        present: false,
    });
}
