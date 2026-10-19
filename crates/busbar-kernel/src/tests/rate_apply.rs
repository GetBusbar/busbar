//! Tests for `rate_apply.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// A holder that states only the apply: the defaults the seam promises for the rest.
struct ApplyOnly;

impl RateApply for ApplyOnly {
    fn rates_applied(&self, _rates: &RawRates<'_>) {}
}

/// A dater that states only the date.
struct DateOnly;

impl RateEpoch for DateOnly {
    fn effective_from_at(&self, _at_ms: u64) -> u64 {
        7
    }
}

/// A holder with no journal stages nothing and so refuses nothing; a dater with no history prices
/// every era at the live card.
#[test]
fn a_holder_that_states_only_the_apply_stages_nothing_and_a_bare_dater_holds_no_history() {
    let rates = RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 7,
        present: false,
        plane_fees: &Default::default(),
    };
    assert_eq!(ApplyOnly.rates_staged(&rates), Ok(()));
    ApplyOnly.rates_withdrawn();
    assert_eq!(DateOnly.effective_from_at(1_000), 7);
    assert!(DateOnly.history().is_none());
}
