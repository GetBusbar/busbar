// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's trust state (`trust/book.rs`): one test per rule of the lifecycle.

use std::sync::Arc;

use super::*;
use crate::trust::reverify::Policy;
use crate::trust::section::DeclaredPin;

fn entry(fingerprint: Option<&str>, ttl_ms: u64, backoff_ms: u64) -> TrustEntry {
    TrustEntry {
        pin: fingerprint.map(|f| DeclaredPin {
            mechanism: "fingerprint".into(),
            root: false,
            peer_key: false,
            key: None,
            fingerprint: Some(f.into()),
        }),
        policy: Policy {
            ttl_ms,
            recovery_backoff_ms: backoff_ms,
        },
    }
}

fn book(e: TrustEntry) -> (TrustBook, Arc<str>) {
    let b = TrustBook::default();
    let i: Arc<str> = Arc::from("inst");
    b.admit(&i, [("cp".to_string(), e)], []);
    (b, i)
}

#[test]
fn an_instance_never_admitted_or_a_counterparty_it_does_not_declare_is_not_judged() {
    let (b, _) = book(entry(None, 0, 0));
    assert_eq!(
        b.sight("other", "cp", "h", 1),
        Err(Unjudged::UnknownInstance)
    );
    assert_eq!(
        b.sight("inst", "nobody", "h", 1),
        Err(Unjudged::UnknownCounterparty)
    );
    assert_eq!(b.due("other"), None);
}

#[test]
fn the_first_sighting_with_no_declared_pin_pins_what_it_reports() {
    let (b, _) = book(entry(None, 0, 0));
    assert_eq!(
        b.sight("inst", "cp", "h1", 1),
        Ok((Sight::New, Effect::None))
    );
    assert_eq!(
        b.sight("inst", "cp", "h1", 2),
        Ok((Sight::Same, Effect::None))
    );
}

#[test]
fn a_declared_fingerprint_is_the_pin_from_the_start() {
    let (b, _) = book(entry(Some("fp"), 0, 0));
    assert_eq!(
        b.sight("inst", "cp", "fp", 1),
        Ok((Sight::Same, Effect::None))
    );
    let (b, _) = book(entry(Some("fp"), 0, 0));
    assert_eq!(
        b.sight("inst", "cp", "other", 1),
        Ok((Sight::Drifted, Effect::Demote))
    );
}

#[test]
fn drift_answers_drifted_once_then_quarantined() {
    let (b, _) = book(entry(None, 0, 0));
    b.sight("inst", "cp", "h1", 1).unwrap();
    assert_eq!(
        b.sight("inst", "cp", "h2", 2),
        Ok((Sight::Drifted, Effect::Demote))
    );
    assert_eq!(
        b.sight("inst", "cp", "h2", 3),
        Ok((Sight::Quarantined, Effect::None))
    );
}

#[test]
fn a_resighting_of_the_pin_clears_the_quarantine() {
    let (b, _) = book(entry(None, 0, 0));
    b.sight("inst", "cp", "h1", 1).unwrap();
    b.sight("inst", "cp", "h2", 2).unwrap();
    assert_eq!(
        b.sight("inst", "cp", "h1", 3),
        Ok((Sight::Same, Effect::Clear))
    );
    assert_eq!(
        b.sight("inst", "cp", "h1", 4),
        Ok((Sight::Same, Effect::None))
    );
}

#[test]
fn a_clean_sighting_inside_the_recovery_backoff_is_held() {
    let (b, _) = book(entry(None, 0, 100));
    b.sight("inst", "cp", "h1", 1).unwrap();
    b.sight("inst", "cp", "h2", 10).unwrap();
    assert_eq!(
        b.sight("inst", "cp", "h1", 50),
        Ok((Sight::Quarantined, Effect::None))
    );
    // A clock that went backwards past the drift holds it too.
    assert_eq!(
        b.sight("inst", "cp", "h1", 5),
        Ok((Sight::Quarantined, Effect::None))
    );
    assert_eq!(
        b.sight("inst", "cp", "h1", 110),
        Ok((Sight::Same, Effect::Clear))
    );
}

#[test]
fn a_replayed_demotion_quarantines_at_admit() {
    let b = TrustBook::default();
    let i: Arc<str> = Arc::from("inst");
    b.admit(
        &i,
        [("cp".to_string(), entry(Some("fp"), 0, 0))],
        [("cp", 1), ("gone", 1)],
    );
    assert_eq!(
        b.sight("inst", "cp", "other", 2),
        Ok((Sight::Quarantined, Effect::None))
    );
    assert_eq!(
        b.sight("inst", "cp", "fp", 3),
        Ok((Sight::Same, Effect::Clear))
    );
}

#[test]
fn a_readmit_keeps_state_unless_the_declared_pin_changed() {
    let (b, i) = book(entry(Some("fp"), 0, 0));
    b.sight("inst", "cp", "other", 1).unwrap();
    b.admit(&i, [("cp".to_string(), entry(Some("fp"), 0, 0))], []);
    assert_eq!(
        b.sight("inst", "cp", "other", 2),
        Ok((Sight::Quarantined, Effect::None))
    );
    b.admit(&i, [("cp".to_string(), entry(Some("other"), 0, 0))], []);
    assert_eq!(
        b.sight("inst", "cp", "other", 3),
        Ok((Sight::Same, Effect::None))
    );
}

#[test]
fn the_tick_marks_by_the_declared_cadence_and_a_sighting_clears_the_mark() {
    let (b, _) = book(entry(None, 100, 0));
    b.mark_due(0);
    assert_eq!(b.due("inst"), Some(vec!["cp".to_string()]));
    // Answering the marks does not spend them.
    assert_eq!(b.due("inst"), Some(vec!["cp".to_string()]));
    b.sight("inst", "cp", "h", 10).unwrap();
    assert_eq!(b.due("inst"), Some(vec![]));
    b.mark_due(50);
    assert_eq!(b.due("inst"), Some(vec![]));
    b.mark_due(110);
    assert_eq!(b.due("inst"), Some(vec!["cp".to_string()]));
}

#[test]
fn a_zero_cadence_is_never_marked_by_the_timer() {
    let (b, _) = book(entry(None, 0, 0));
    b.mark_due(1_000_000);
    assert_eq!(b.due("inst"), Some(vec![]));
}

#[test]
fn a_replayed_demotion_with_no_declared_pin_stays_until_one_is_declared() {
    let b = TrustBook::default();
    let i: Arc<str> = Arc::from("inst");
    b.admit(&i, [("cp".to_string(), entry(None, 0, 0))], [("cp", 1)]);
    assert_eq!(
        b.sight("inst", "cp", "h", 2),
        Ok((Sight::Quarantined, Effect::None))
    );
    b.admit(&i, [("cp".to_string(), entry(Some("h"), 0, 0))], []);
    assert_eq!(
        b.sight("inst", "cp", "h", 3),
        Ok((Sight::Same, Effect::None))
    );
}

/// THE KERNEL'S APPROVE (ARCHITECT 2026-10-06): a unit's stated trust facts are judged here, never
/// by the plane. RED arms, one per refusal: an undeclared counterparty, one never sighted, one
/// quarantined, an item never sighted (unknown: a 404's case) apart from one sighted and never
/// approved (known, ungranted: a 403's case), and one offered at another digest than approved.
#[test]
fn the_kernels_approve_judges_counterparty_and_item_by_sighting_and_approval() {
    let (b, i) = book(entry(None, 0, 0));
    let facts = |item: Option<&'static str>, digest: Option<&'static str>| TrustFacts {
        counterparty: "cp",
        item,
        digest,
    };
    let other = TrustFacts {
        counterparty: "other",
        item: None,
        digest: None,
    };
    assert_eq!(b.judge(&i, &other), Err(Distrust::Unknown));
    assert_eq!(
        b.judge("nowhere", &facts(None, None)),
        Err(Distrust::Unknown)
    );
    assert_eq!(b.judge(&i, &facts(None, None)), Err(Distrust::Unsighted));
    b.sight(&i, "cp", "h1", 1).expect("judged");
    assert_eq!(
        b.judge(&i, &facts(None, None)),
        Ok(()),
        "pinned: trusted whole"
    );

    // An unknown item, then known and ungranted, then granted at its digest alone.
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::UnknownItem)
    );
    assert_eq!(b.sight_item(&i, "cp", "t", "d1"), Ok(Sight::New));
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::NotApproved)
    );
    b.approve(&i, "cp", [("t".to_string(), "d1".to_string())])
        .expect("declared");
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Ok(()),
        "its last sighting"
    );
    assert_eq!(b.judge(&i, &facts(Some("t"), Some("d1"))), Ok(()));
    assert_eq!(
        b.judge(&i, &facts(Some("t"), Some("d2"))),
        Err(Distrust::Changed)
    );
    // A re-fetch that sees it drift: the last sighting no longer matches what was approved.
    assert_eq!(b.sight_item(&i, "cp", "t", "d2"), Ok(Sight::Drifted));
    assert_eq!(b.sight_item(&i, "cp", "t", "d2"), Ok(Sight::Same));
    assert_eq!(b.judge(&i, &facts(Some("t"), None)), Err(Distrust::Changed));
    // Approval replaces the set: an item no longer handed is no longer approved.
    b.approve(&i, "cp", []).expect("declared");
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::NotApproved)
    );

    // The counterparty drifts: quarantined, whatever was approved.
    b.approve(&i, "cp", [("t".to_string(), "d2".to_string())])
        .expect("declared");
    assert_eq!(b.judge(&i, &facts(Some("t"), None)), Ok(()));
    b.sight(&i, "cp", "h2", 2).expect("judged");
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::Quarantined)
    );
    assert_eq!(b.sight_item(&i, "cp", "t", "d2"), Ok(Sight::Quarantined));
    assert_eq!(
        b.sight_item(&i, "other", "t", "d2"),
        Err(Unjudged::UnknownCounterparty)
    );
}
