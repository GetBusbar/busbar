//! Tests for `reverify.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{settle, Ledger, Policy};
use crate::trust::{Approval, Observation, PinnedArtifact, Sighting};
use std::collections::BTreeMap;

/// One opaque pin, the smallest artifact the machine will take.
#[derive(Clone, Debug, PartialEq)]
struct Pin(&'static str);

impl PinnedArtifact for Pin {
    fn mechanism(&self) -> &'static str {
        "cert_spki"
    }
    fn digest(&self) -> String {
        self.0.to_string()
    }
}

fn clean() -> Sighting<Pin> {
    Sighting::Seen(Observation {
        pin: None,
        capabilities: BTreeMap::new(),
    })
}

/// A clock that has run backwards since the drift was stamped cannot say how much of the
/// backoff has elapsed, and the answer to "unknown" is to keep holding. Reading it as an
/// elapsed backoff would let an upstream that can nudge our clock have its next clean answer
/// believed at once -- the opposite of what the same unreadable clock buys it on the freshness
/// path, which fails closed.
#[test]
fn a_backwards_clock_does_not_cancel_the_recovery_backoff() {
    let approval: Approval<Pin> = Approval::registered();
    let policy = Policy {
        ttl_ms: 60_000,
        recovery_backoff_ms: 30_000,
    };
    let mut ledger = Ledger {
        last_checked_ms: Some(10_000),
        last_drift_ms: Some(10_000),
        drift_observations: 1,
    };
    let recorded = Sighting::Demoted("pin changed".to_string());
    let settled = settle(&approval, &recorded, clean(), &mut ledger, &policy, 9_000);
    assert!(
        settled.recovery_held,
        "a clean answer read on a clock behind the drift stamp is not believed"
    );
    assert_eq!(settled.sighting, recorded);
}

/// The forward cases are unchanged: inside the window the clean answer is held, past it the
/// clean answer is believed.
#[test]
fn a_forward_clock_still_holds_inside_the_window_and_believes_past_it() {
    let approval: Approval<Pin> = Approval::registered();
    let policy = Policy {
        ttl_ms: 60_000,
        recovery_backoff_ms: 30_000,
    };
    let recorded = Sighting::Demoted("pin changed".to_string());
    let mut ledger = Ledger {
        last_checked_ms: Some(10_000),
        last_drift_ms: Some(10_000),
        drift_observations: 1,
    };
    let held = settle(&approval, &recorded, clean(), &mut ledger, &policy, 20_000);
    assert!(held.recovery_held);

    let believed = settle(&approval, &recorded, clean(), &mut ledger, &policy, 41_000);
    assert!(!believed.recovery_held);
    assert_eq!(believed.sighting, clean());
}
