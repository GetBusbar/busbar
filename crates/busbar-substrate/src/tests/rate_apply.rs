//! Tests for `rate_apply.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use std::sync::Mutex;

/// A holder that writes down what it was handed, so "the seam delivered the neutral view" is an
/// assertion about the figures rather than about the call not panicking.
struct Recorder(Mutex<Vec<Seen>>);

/// One apply, as the holder saw it: the lanes with their four tier rates, the whole fee terms, the
/// flag.
type Seen = (
    Vec<(String, RawTierRates)>,
    busbar_contract::tariff::FeeTerms,
    bool,
);

impl RateApply for Recorder {
    fn rates_applied(&self, rates: &RawRates<'_>) {
        self.0
            .lock()
            .unwrap()
            .push((rates.lanes.to_vec(), rates.terms.clone(), rates.present));
    }
}

/// Terms with one figure on them, used on both sides of the comparison so that the assertion is
/// about what the seam CARRIED rather than about a literal written twice.
fn eleven() -> busbar_contract::tariff::FeeTerms {
    busbar_contract::tariff::FeeTerms {
        transaction: 11,
        ..busbar_contract::tariff::FeeTerms::default()
    }
}

/// The whole of the seam, in the order the process actually sees it: silent before an install, and
/// delivering the raw view verbatim after one.
///
/// ONE test, not two, because [`APPLY`] is a process-wide `OnceLock` and the install is
/// irreversible: split across two `#[test]`s the two halves would race, and whichever ran second
/// would be asserting the other one's state. Within one test the order is the language's.
#[test]
fn the_seam_is_silent_until_a_holder_installs_and_then_delivers_the_view_verbatim() {
    // BEFORE: a build with no root ledger in it swallows the apply rather than refusing it, and
    // nothing is recorded because there is nothing to record to.
    assert!(
        APPLY.get().is_none(),
        "this is the only test that installs a holder, so the seam must still be empty here"
    );
    rates_applied(&RawRates {
        lanes: &[],
        terms: busbar_contract::tariff::FeeTerms {
            transaction: 7,
            ..busbar_contract::tariff::FeeTerms::default()
        },
        present: false,
    });

    // AFTER: the holder receives the figures the engine resolved, unchanged.
    let recorder: &'static Recorder = Box::leak(Box::new(Recorder(Mutex::new(Vec::new()))));
    install_rate_apply(recorder);
    // Four DISTINCT tier rates per lane, so a seam that carried the right lane names with the wrong
    // (or a defaulted) card is red rather than green.
    let fast = RawTierRates {
        input: 1.0,
        output: 2.0,
        cache_read: 3.0,
        cache_write: 4.0,
    };
    let slow = RawTierRates {
        input: 5.0,
        output: 6.0,
        cache_read: 7.0,
        cache_write: 8.0,
    };
    let lanes = [("fast".to_string(), fast), ("slow".to_string(), slow)];
    rates_applied(&RawRates {
        lanes: &lanes,
        terms: eleven(),
        present: true,
    });

    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(lanes.to_vec(), eleven(), true)],
        "exactly the one apply raised after the install, with the lanes in the deployment's own \
         order, every tier rate, the fee and the present flag as they were resolved — the apply \
         raised BEFORE it reached nobody, which is what an uninstalled seam owes"
    );

    // PRESENCE IS NOT EMPTINESS. A card that names no lane is a different statement from no card at
    // all, and collapsing the two would turn one deployment's configuration into another's.
    rates_applied(&RawRates {
        lanes: &[],
        terms: eleven(),
        present: true,
    });
    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(
        seen.last(),
        Some(&(Vec::new(), eleven(), true)),
        "an empty lane list under a PRESENT card is carried as present, not folded into absent"
    );
}
