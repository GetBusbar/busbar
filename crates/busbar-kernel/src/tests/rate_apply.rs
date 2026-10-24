//! Tests for `rate_apply.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use std::sync::Mutex;

/// A holder that writes down what it was handed, so "the seam delivered the neutral view" is an
/// assertion about the figures rather than about the call not panicking.
struct Recorder(Mutex<Vec<Seen>>);

/// One apply, as the holder saw it: the lanes with their four tier rates, the open-class rates,
/// the fee, the flag.
type Seen = (
    Vec<(String, RawTierRates)>,
    Vec<(String, String, u64)>,
    i64,
    bool,
);

impl RateApply for Recorder {
    fn rates_applied(&self, rates: &RawRates<'_>) {
        self.0.lock().unwrap().push((
            rates.lanes.to_vec(),
            rates.units.to_vec(),
            rates.flat_minor,
            rates.present,
        ));
    }
}

/// A governance book over an empty store, answering to `holder`.
fn book(holder: Option<&'static dyn RateApply>) -> GovState {
    GovState::new(
        std::sync::Arc::new(crate::governance::MemoryStore::new()),
        None,
    )
    .expect("governance builds")
    .with_rates(holder, None)
}

/// The whole of the seam: silent for a book lent no holder, and delivering the raw view verbatim to
/// the holder a book is lent.
#[test]
fn the_seam_is_silent_for_a_book_lent_no_holder_and_delivers_the_view_verbatim_to_its_own() {
    // NO HOLDER: a build with no root ledger in it swallows the apply rather than refusing it, and
    // nothing is recorded because there is nothing to record to.
    let unlent = book(None);
    assert!(
        holder(&unlent).is_none(),
        "a book lent no holder answers to none"
    );
    rates_applied(
        Some(&unlent),
        &RawRates {
            lanes: &[],
            units: &[],
            flat_minor: 7,
            present: false,
            plane_fees: &Default::default(),
        },
    );

    // LENT ONE: the holder receives the figures the engine resolved, unchanged.
    let recorder: &'static Recorder = Box::leak(Box::new(Recorder(Mutex::new(Vec::new()))));
    let lent = book(Some(recorder));
    // Four DISTINCT tier rates per lane, so a seam that carried the right lane names with the wrong
    // (or a defaulted) card is red rather than green.
    let fast = RawTierRates {
        input: Some(1_000),
        output: Some(2_000),
        cache_read: Some(3_000),
        cache_write: Some(4_000),
    };
    let slow = RawTierRates {
        input: Some(5_000),
        output: Some(6_000),
        cache_read: Some(7_000),
        cache_write: Some(8_000),
    };
    let lanes = [("fast".to_string(), fast), ("slow".to_string(), slow)];
    // An open-class rate (item 123) travels beside the four, verbatim.
    let units = [("slow".to_string(), "search_units".to_string(), 5_000)];
    rates_applied(
        Some(&lent),
        &RawRates {
            lanes: &lanes,
            units: &units,
            flat_minor: 11,
            present: true,
            plane_fees: &Default::default(),
        },
    );

    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(lanes.to_vec(), units.to_vec(), 11, true)],
        "exactly the one apply raised after the install, with the lanes in the deployment's own \
         order, every tier rate, the fee and the present flag as they were resolved — the apply \
         raised to the book lent no holder reached nobody, which is what an unlent seam owes"
    );

    // PRESENCE IS NOT EMPTINESS. A card that names no lane is a different statement from no card at
    // all, and collapsing the two would turn one deployment's configuration into another's.
    rates_applied(
        Some(&lent),
        &RawRates {
            lanes: &[],
            units: &[],
            flat_minor: 11,
            present: true,
            plane_fees: &Default::default(),
        },
    );
    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(
        seen.last(),
        Some(&(Vec::new(), Vec::new(), 11, true)),
        "an empty lane list under a PRESENT card is carried as present, not folded into absent"
    );
}
