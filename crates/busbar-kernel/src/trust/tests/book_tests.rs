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
        approved: Default::default(),
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

/// A FIRST SIGHTING PINS NOTHING (ARCHITECT 2026-10-06): with no declared pin a counterparty is
/// NEW, and refused, until the operator approves what it reports; RED was trust on first sight.
#[test]
fn the_first_sighting_with_no_declared_pin_is_new_until_approved() {
    let (b, i) = book(entry(None, 0, 0));
    let whole = TrustFacts {
        counterparty: "cp",
        item: None,
        digest: None,
    };
    assert_eq!(
        b.sight("inst", "cp", "h1", 1),
        Ok((Sight::New, Effect::None))
    );
    assert_eq!(
        b.sight("inst", "cp", "h1", 2),
        Ok((Sight::New, Effect::None)),
        "still unapproved"
    );
    assert_eq!(b.judge(&i, &whole), Err(Distrust::NotApproved));
    b.decide(&i, "cp", None, Decision::Approve).expect("a key");
    assert_eq!(b.judge(&i, &whole), Ok(()));
    assert_eq!(
        b.sight("inst", "cp", "h1", 3),
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
    let (b, _) = book(entry(Some("h1"), 0, 0));
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
    let (b, _) = book(entry(Some("h1"), 0, 0));
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
    let (b, _) = book(entry(Some("h1"), 0, 100));
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
/// sighted and never approved, one quarantined, an item never sighted (unknown: a 404's case) apart
/// from one sighted and never approved (known, ungranted: a 403's case), and one offered at another
/// digest than approved.
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
    assert_eq!(b.judge(&i, &facts(None, None)), Err(Distrust::NotApproved));
    b.decide(&i, "cp", None, Decision::Approve).expect("a key");
    assert_eq!(
        b.judge(&i, &facts(None, None)),
        Ok(()),
        "approved: trusted whole"
    );

    // An unknown item, then known and ungranted, then granted at its digest alone.
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::UnknownItem)
    );
    assert_eq!(
        b.decide(&i, "cp", Some("t"), Decision::Approve),
        Err(Undecided::NoSuchKey),
        "an item never sighted is no key"
    );
    assert_eq!(b.sight_item(&i, "cp", "t", "d1"), Ok(Sight::New));
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::NotApproved)
    );
    b.decide(&i, "cp", Some("t"), Decision::Approve)
        .expect("a key");
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
    // Revoked, it is refused; approved again, at its new digest.
    b.decide(&i, "cp", Some("t"), Decision::Revoke)
        .expect("a key");
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::NotApproved)
    );
    b.decide(&i, "cp", Some("t"), Decision::Approve)
        .expect("a key");
    assert_eq!(b.judge(&i, &facts(Some("t"), None)), Ok(()));

    // The counterparty drifts: quarantined, whatever was approved.
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

/// A CONFIGURED ITEM APPROVAL (`TRUST_ITEM_APPROVALS`) serves its item on its first call at the
/// configured digest, with no counterparty approval; another digest is changed; an operator revoke
/// wins over the configuration; and a counterparty revoke refuses every item there.
#[test]
fn a_configured_item_approval_serves_until_the_operator_revokes_it() {
    let mut e = entry(None, 0, 0);
    e.approved.insert("t".to_string(), "d1".to_string());
    let (b, i) = book(e);
    let at = |digest: Option<&'static str>| TrustFacts {
        counterparty: "cp",
        item: Some("t"),
        digest,
    };
    assert_eq!(b.judge(&i, &at(Some("d1"))), Ok(()), "first call, no pin");
    assert_eq!(b.judge(&i, &at(Some("d2"))), Err(Distrust::Changed));
    b.decide(&i, "cp", Some("t"), Decision::Revoke)
        .expect("a configured item is a key");
    assert_eq!(b.judge(&i, &at(Some("d1"))), Err(Distrust::NotApproved));
    b.decide(&i, "cp", Some("t"), Decision::Approve)
        .expect("a key");
    assert_eq!(
        b.judge(&i, &at(Some("d1"))),
        Ok(()),
        "approved at its configured digest"
    );
    b.decide(&i, "cp", None, Decision::Revoke).expect("a key");
    assert_eq!(b.judge(&i, &at(Some("d1"))), Err(Distrust::NotApproved));
}

/// THE ADMINISTRATIVE STATES (`GET /api/v1/admin/trust`): new until approved, approved, same once
/// re-sighted as approved, drifted when a sighting moves from it (quarantined again until
/// re-approved), and idempotent decisions: the same decision twice answers the same row.
#[test]
fn the_keys_list_their_states_and_decisions_are_idempotent() {
    let (b, i) = book(entry(None, 0, 0));
    let state = |key: &str| {
        b.rows()
            .into_iter()
            .find(|r| r.key() == key)
            .map(|r| r.state)
    };
    assert_eq!(state("inst/cp"), Some(KeyState::New));
    assert_eq!(
        b.decide(&i, "cp", None, Decision::Approve),
        Err(Undecided::NothingSighted)
    );
    b.sight(&i, "cp", "h1", 1).unwrap();
    let first = b.decide(&i, "cp", None, Decision::Approve).expect("a key");
    let again = b.decide(&i, "cp", None, Decision::Approve).expect("a key");
    assert_eq!(first, again, "idempotent");
    assert_eq!(first.0.state, KeyState::Approved);
    b.sight(&i, "cp", "h1", 2).unwrap();
    assert_eq!(state("inst/cp"), Some(KeyState::Same));
    assert_eq!(
        b.sight(&i, "cp", "h2", 3),
        Ok((Sight::Drifted, Effect::Demote))
    );
    assert_eq!(state("inst/cp"), Some(KeyState::Drifted));
    // Re-approved at what it now reports: served again, and the drift is the new pin.
    let (row, fact) = b.decide(&i, "cp", None, Decision::Approve).expect("a key");
    assert_eq!(row.approved.as_deref(), Some("h2"));
    assert_eq!(fact.approved.as_deref(), Some("h2"));
    assert_eq!(b.sight(&i, "cp", "h2", 4), Ok((Sight::Same, Effect::None)));
    // Revoked: new (refused) until approved again; the revoke is idempotent too.
    let r1 = b.decide(&i, "cp", None, Decision::Revoke).expect("a key");
    let r2 = b.decide(&i, "cp", None, Decision::Revoke).expect("a key");
    assert_eq!(r1, r2);
    assert_eq!(r1.0.state, KeyState::New);
    assert_eq!(r1.1.approved, None);
    // Items list under their counterparty.
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    assert_eq!(state("inst/cp/t"), Some(KeyState::New));
    assert_eq!(b.rows().len(), 2);
}

/// THE OPERATOR'S DECISIONS ARE DURABLE: replayed onto a fresh book they leave the state they
/// left; a row for a counterparty no longer declared is ignored.
#[test]
fn kept_decisions_replay_at_admit() {
    let (b, i) = book(entry(None, 0, 0));
    b.sight(&i, "cp", "h1", 1).unwrap();
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    let (_, whole) = b.decide(&i, "cp", None, Decision::Approve).unwrap();
    let (_, item) = b.decide(&i, "cp", Some("t"), Decision::Approve).unwrap();
    let gone = DecisionRow {
        counterparty: "gone".into(),
        ..whole.clone()
    };

    let (fresh, i) = book(entry(None, 0, 0));
    fresh.admit_decided(&i, [&whole, &item, &gone]);
    let facts = |item| TrustFacts {
        counterparty: "cp",
        item,
        digest: Some("d1"),
    };
    assert_eq!(
        fresh.judge(
            &i,
            &TrustFacts {
                counterparty: "cp",
                item: None,
                digest: None
            }
        ),
        Ok(())
    );
    assert_eq!(fresh.judge(&i, &facts(Some("t"))), Ok(()));
}

/// UNREACHABLE (`TRUST_UNREACHABLE`): the last verdict, and nothing changes: no drift, no clear,
/// the re-verification mark stands.
#[test]
fn an_unreachable_sighting_answers_the_last_verdict_and_changes_nothing() {
    let (b, i) = book(entry(Some("h1"), 100, 0));
    assert_eq!(b.last_verdict(&i, "cp"), Ok(Sight::Same));
    b.mark_due(0);
    assert_eq!(b.last_verdict(&i, "cp"), Ok(Sight::Same));
    assert_eq!(b.due("inst"), Some(vec!["cp".to_string()]), "still due");
    b.sight(&i, "cp", "h2", 1).unwrap();
    assert_eq!(b.last_verdict(&i, "cp"), Ok(Sight::Quarantined));
    assert_eq!(
        b.last_verdict(&i, "nobody"),
        Err(Unjudged::UnknownCounterparty)
    );
    let (unpinned, i) = book(entry(None, 0, 0));
    assert_eq!(unpinned.last_verdict(&i, "cp"), Ok(Sight::New));
}
