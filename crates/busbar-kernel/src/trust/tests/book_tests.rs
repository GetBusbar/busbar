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
    b.decide(&i, "cp", None, Ruling::Approve, None)
        .expect("a key");
    assert_eq!(b.judge(&i, &whole), Ok(()));
    assert_eq!(
        b.sight("inst", "cp", "h1", 3),
        Ok((Sight::Same, Effect::None))
    );
}

/// A DECLARED FINGERPRINT IS INTENT, NOT AN APPROVAL (coordinator ruling 2026-10-07, OWNER
/// 2026-09-28: the baseline is predev's behaviour). Ported from predev's plane cell
/// `plane_tests.rs::a_declared_fingerprint_does_not_become_an_approval_at_boot`: an operator may
/// write the fingerprint they intend to approve, but an approval is a statement about a document
/// that was actually SEEN, so a registration lowered from config is PENDING until an operator
/// approves it. The kernel's Approve refuses it (`NotApproved`) and the admin surface lists it NEW,
/// whatever the config declared. RED was the declared fingerprint taken as the pin from the start,
/// which `judge` answered `Ok` before any approval.
#[test]
fn a_declared_fingerprint_does_not_become_an_approval_at_boot() {
    let (b, i) = book(entry(Some("fp"), 0, 0));
    let whole = TrustFacts {
        counterparty: "cp",
        item: None,
        digest: None,
    };
    let state = |b: &TrustBook| {
        b.rows()
            .into_iter()
            .find(|r| r.key() == "inst/cp")
            .map(|r| r.state)
    };
    assert_eq!(
        b.judge(&i, &whole),
        Err(Distrust::NotApproved),
        "a registration lowered from config is pending, never approved"
    );
    assert_eq!(state(&b), Some(KeyState::New), "listed pending");
    assert_eq!(
        b.last_verdict(&i, "cp"),
        Ok(Sight::New),
        "unreached, it is pending (coordinator 2026-10-07, #555 round 3; predev \
         crates/busbar-kernel/src/trust/mod.rs:289-290)"
    );
    assert_eq!(
        b.sight("inst", "cp", "other", 1),
        Ok((Sight::New, Effect::None)),
        "another hash before the approval is pending too: no drift, no quarantine (coordinator \
         2026-10-07, #555 round 3; predev crates/busbar-kernel/src/trust/mod.rs:289-290)"
    );
    assert_eq!(state(&b), Some(KeyState::New));
    assert_eq!(
        b.sight("inst", "cp", "fp", 1),
        Ok((Sight::New, Effect::None)),
        "a sighting of the declared fingerprint reports pending (coordinator 2026-10-07, #555 \
         point ii; predev crates/busbar-kernel/src/trust/mod.rs:289-290)"
    );
    assert_eq!(
        b.judge(&i, &whole),
        Err(Distrust::NotApproved),
        "and approves nothing either"
    );
    let (_, kept) = b
        .decide(&i, "cp", None, Ruling::Approve, Some("fp"))
        .expect("a key");
    assert_eq!(
        b.judge(&i, &whole),
        Ok(()),
        "only the operator's approval admits it"
    );
    assert_eq!(state(&b), Some(KeyState::Same));
    assert_eq!(
        b.sight("inst", "cp", "fp", 2),
        Ok((Sight::Same, Effect::None)),
        "approved, the pin is the pinned catalogue"
    );
    // The kept approval outlives a restart: replayed, the declared fingerprint is approved.
    let (fresh, f) = book(entry(Some("fp"), 0, 0));
    assert_eq!(fresh.judge(&f, &whole), Err(Distrust::NotApproved));
    fresh.admit_decided(&f, [&kept]);
    assert_eq!(fresh.judge(&f, &whole), Ok(()));
    // A re-admit with the same declaration keeps the approval; a changed one is pending again.
    b.admit(&i, [("cp".to_string(), entry(Some("fp"), 0, 0))], []);
    assert_eq!(b.judge(&i, &whole), Ok(()));
    b.admit(&i, [("cp".to_string(), entry(Some("fp2"), 0, 0))], []);
    assert_eq!(b.judge(&i, &whole), Err(Distrust::NotApproved));
    // Every item there waits on the counterparty's approval, a configured one included
    // (coordinator 2026-10-07, #555 point iii; predev crates/busbar-kernel/src/trust/mod.rs:336-337,
    // `serves` is false while nothing is pinned).
    let mut e = entry(Some("fp"), 0, 0);
    e.approved.insert("t".to_string(), "d1".to_string());
    let (b, i) = book(e);
    let item = TrustFacts {
        counterparty: "cp",
        item: Some("t"),
        digest: Some("d1"),
    };
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    assert_eq!(b.judge(&i, &item), Err(Distrust::NotApproved));
    b.decide(&i, "cp", None, Ruling::Approve, None)
        .expect("a key");
    assert_eq!(
        b.judge(&i, &item),
        Ok(()),
        "the counterparty approved, it serves"
    );
}

#[test]
fn drift_answers_drifted_once_then_quarantined() {
    let (b, i) = book(entry(Some("h1"), 0, 0));
    b.sight("inst", "cp", "h1", 1).unwrap();
    // Approved first: before an approval a declared fingerprint drifts nothing (coordinator
    // 2026-10-07, #555 round 3; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is
    // Pending, and :312, only a pin can change; the retired agent engine's registry).
    b.decide(&i, "cp", None, Ruling::Approve, None).unwrap();
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
    let (b, i) = book(entry(Some("h1"), 0, 0));
    b.sight("inst", "cp", "h1", 1).unwrap();
    // Approved first: before an approval a declared fingerprint drifts nothing (coordinator
    // 2026-10-07, #555 round 3; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is
    // Pending, and :312, only a pin can change; the retired agent engine's registry).
    b.decide(&i, "cp", None, Ruling::Approve, None).unwrap();
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
    let (b, i) = book(entry(Some("h1"), 0, 100));
    b.sight("inst", "cp", "h1", 1).unwrap();
    // Approved first: before an approval a declared fingerprint drifts nothing (coordinator
    // 2026-10-07, #555 round 3; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is
    // Pending, and :312, only a pin can change; the retired agent engine's registry).
    b.decide(&i, "cp", None, Ruling::Approve, None).unwrap();
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
    // Pending, never Same: the declared fingerprint was never approved (coordinator 2026-10-07,
    // #555 point ii; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is Pending).
    assert_eq!(
        b.sight("inst", "cp", "fp", 3),
        Ok((Sight::New, Effect::Clear))
    );
}

#[test]
fn a_readmit_keeps_state_unless_the_declared_pin_changed() {
    let (b, i) = book(entry(Some("fp"), 0, 0));
    // Approved first: before an approval a declared fingerprint drifts nothing (coordinator
    // 2026-10-07, #555 round 3; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is
    // Pending, and :312, only a pin can change; the retired agent engine's registry).
    b.decide(&i, "cp", None, Ruling::Approve, None).unwrap();
    b.sight("inst", "cp", "other", 1).unwrap();
    b.admit(&i, [("cp".to_string(), entry(Some("fp"), 0, 0))], []);
    assert_eq!(
        b.sight("inst", "cp", "other", 2),
        Ok((Sight::Quarantined, Effect::None))
    );
    b.admit(&i, [("cp".to_string(), entry(Some("other"), 0, 0))], []);
    // Pending, never Same: the declared fingerprint was never approved (coordinator 2026-10-07,
    // #555 point ii; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is Pending).
    assert_eq!(
        b.sight("inst", "cp", "other", 3),
        Ok((Sight::New, Effect::None))
    );
}

/// NO BACKGROUND TIMER (tool-and-agent-trust.md:61-62): whatever the declared cadence, and however
/// long since the last sighting, no counterparty is ever due; one never admitted has no answer.
#[test]
fn no_counterparty_is_ever_due_by_the_clock() {
    let (b, _) = book(entry(None, 100, 0));
    assert_eq!(b.due("inst"), Some(vec![]));
    b.sight("inst", "cp", "h", 10).unwrap();
    assert_eq!(b.due("inst"), Some(vec![]));
    assert_eq!(b.due("nowhere"), None);
    let (b, _) = book(entry(None, 0, 0));
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
    // Pending, never Same: the declared fingerprint was never approved (coordinator 2026-10-07,
    // #555 point ii; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is Pending).
    assert_eq!(
        b.sight("inst", "cp", "h", 3),
        Ok((Sight::New, Effect::None))
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
    b.decide(&i, "cp", None, Ruling::Approve, None)
        .expect("a key");
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
        b.decide(&i, "cp", Some("t"), Ruling::Approve, None),
        Err(Undecided::NoSuchKey),
        "an item never sighted is no key"
    );
    assert_eq!(b.sight_item(&i, "cp", "t", "d1"), Ok(Sight::New));
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::NotApproved)
    );
    b.decide(&i, "cp", Some("t"), Ruling::Approve, None)
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
    b.decide(&i, "cp", Some("t"), Ruling::Revoke, None)
        .expect("a key");
    assert_eq!(
        b.judge(&i, &facts(Some("t"), None)),
        Err(Distrust::NotApproved)
    );
    b.decide(&i, "cp", Some("t"), Ruling::Approve, None)
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
    b.decide(&i, "cp", Some("t"), Ruling::Revoke, None)
        .expect("a configured item is a key");
    assert_eq!(b.judge(&i, &at(Some("d1"))), Err(Distrust::NotApproved));
    b.decide(&i, "cp", Some("t"), Ruling::Approve, None)
        .expect("a key");
    assert_eq!(
        b.judge(&i, &at(Some("d1"))),
        Ok(()),
        "approved at its configured digest"
    );
    b.decide(&i, "cp", None, Ruling::Revoke, None)
        .expect("a key");
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
        b.decide(&i, "cp", None, Ruling::Approve, None),
        Err(Undecided::NothingSighted)
    );
    b.sight(&i, "cp", "h1", 1).unwrap();
    let first = b
        .decide(&i, "cp", None, Ruling::Approve, None)
        .expect("a key");
    let again = b
        .decide(&i, "cp", None, Ruling::Approve, None)
        .expect("a key");
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
    let (row, fact) = b
        .decide(&i, "cp", None, Ruling::Approve, None)
        .expect("a key");
    assert_eq!(row.approved.as_deref(), Some("h2"));
    assert_eq!(fact.approved.as_deref(), Some("h2"));
    assert_eq!(b.sight(&i, "cp", "h2", 4), Ok((Sight::Same, Effect::None)));
    // Revoked: new (refused) until approved again; the revoke is idempotent too.
    let r1 = b
        .decide(&i, "cp", None, Ruling::Revoke, None)
        .expect("a key");
    let r2 = b
        .decide(&i, "cp", None, Ruling::Revoke, None)
        .expect("a key");
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
    let (_, whole) = b.decide(&i, "cp", None, Ruling::Approve, None).unwrap();
    let (_, item) = b
        .decide(&i, "cp", Some("t"), Ruling::Approve, None)
        .unwrap();
    let gone = RulingRow {
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
    // A declared fingerprint never approved is pending, reached or not (coordinator 2026-10-07,
    // #555 round 3; predev crates/busbar-kernel/src/trust/mod.rs:289-290, no pin is Pending).
    assert_eq!(b.last_verdict(&i, "cp"), Ok(Sight::New));
    assert_eq!(
        b.last_verdict(&i, "cp"),
        Ok(Sight::New),
        "answering changes nothing"
    );
    b.decide(&i, "cp", None, Ruling::Approve, None).unwrap();
    assert_eq!(b.last_verdict(&i, "cp"), Ok(Sight::Same), "approved");
    b.sight(&i, "cp", "h2", 1).unwrap();
    assert_eq!(b.last_verdict(&i, "cp"), Ok(Sight::Quarantined));
    assert_eq!(
        b.last_verdict(&i, "nobody"),
        Err(Unjudged::UnknownCounterparty)
    );
    let (unpinned, i) = book(entry(None, 0, 0));
    assert_eq!(unpinned.last_verdict(&i, "cp"), Ok(Sight::New));
}

/// A REGISTRATION WITH NO AUTHENTICITY ROOT (a declared pin of the plane's no-root spelling, no
/// fingerprint) APPROVES NOTHING: the operator's approval is refused at the counterparty and at its
/// items (a revoke still stands), so nothing at it is ever served.
#[test]
fn a_rootless_registration_approves_nothing() {
    let mut e = entry(None, 0, 0);
    e.pin = Some(DeclaredPin {
        mechanism: "open".into(),
        root: false,
        peer_key: false,
        key: None,
        fingerprint: None,
    });
    assert!(e.rootless());
    let (b, i) = book(e);
    b.sight(&i, "cp", "h1", 1).unwrap();
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    assert_eq!(
        b.decide(&i, "cp", None, Ruling::Approve, None),
        Err(Undecided::Rootless)
    );
    assert_eq!(
        b.decide(&i, "cp", Some("t"), Ruling::Approve, None),
        Err(Undecided::Rootless)
    );
    assert!(b.decide(&i, "cp", Some("t"), Ruling::Revoke, None).is_ok());
    assert_eq!(
        b.judge(
            &i,
            &TrustFacts {
                counterparty: "cp",
                item: Some("t"),
                digest: Some("d1")
            }
        ),
        Err(Distrust::NotApproved)
    );
}

/// AN APPROVED ITEM NEVER SIGHTED IS PENDING (ARCHITECT 2026-10-06): a configured approval exists
/// before the plane's first re-fetch, and has nothing to be compared against: unsighted, not
/// changed and not serving. The first sighting compares: a match serves, a mismatch is changed
/// (the item's quarantine, until re-approved).
#[test]
fn an_approved_item_never_sighted_is_pending_until_its_first_sighting_compares() {
    let mut e = entry(None, 0, 0);
    e.approved.insert("t".to_string(), "d1".to_string());
    let at = |item| TrustFacts {
        counterparty: "cp",
        item: Some(item),
        digest: None,
    };
    let (b, i) = book(e.clone());
    assert_eq!(b.judge(&i, &at("t")), Err(Distrust::Unsighted));
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    assert_eq!(b.judge(&i, &at("t")), Ok(()), "a matching sighting serves");
    let (b, i) = book(e);
    b.sight_item(&i, "cp", "t", "d9").unwrap();
    assert_eq!(
        b.judge(&i, &at("t")),
        Err(Distrust::Changed),
        "a mismatching first sighting is refused until re-approved"
    );
}

/// A FLAPPING UPSTREAM GETS ONE PERSISTENT QUARANTINE, AND EVERY FLAP IS STILL COUNTED (the served
/// engine's verify battery, on the book that now holds drift): the quarantine persists across the
/// clean answers inside the recovery backoff (one demotion, no storm), and the ledger records every
/// drift observed (the operator sees the flapping, not only what survived the filter). Past the
/// backoff a clean answer is believed: the hold delays recovery, it never refuses it. Four flaps
/// count four here; the engine counted five because its first capture of an unruled skill was
/// itself drift, where the book pins a declared fingerprint from the start.
#[test]
fn a_flapping_upstream_gets_one_persistent_quarantine_and_every_flap_is_still_counted() {
    let (b, i) = book(entry(Some("good"), 60_000, 300_000));
    let whole = TrustFacts {
        counterparty: "cp",
        item: None,
        digest: None,
    };
    // A declared fingerprint is intent, not an approval (coordinator ruling 2026-10-07, the
    // predev baseline): the first sighting is new until the operator approves what was seen.
    assert_eq!(
        b.sight(&i, "cp", "good", 1_000),
        Ok((Sight::New, Effect::None))
    );
    b.decide(&i, "cp", None, Ruling::Approve, None)
        .expect("a key");
    let mut now = 1_000;
    let mut demotions = 0;
    for flap in 0..4 {
        now += 61_000;
        let (sight, effect) = b.sight(&i, "cp", "bad", now).expect("judged");
        assert!(
            matches!(sight, Sight::Drifted | Sight::Quarantined),
            "flap {flap}: {sight:?}"
        );
        demotions += usize::from(effect == Effect::Demote);
        assert!(b.judge(&i, &whole).is_err(), "flap {flap}: quarantined");

        now += 61_000;
        assert_eq!(
            b.sight(&i, "cp", "good", now),
            Ok((Sight::Quarantined, Effect::None)),
            "flap {flap}: a clean answer inside the backoff is not believed"
        );
        assert!(
            b.judge(&i, &whole).is_err(),
            "flap {flap}: the quarantine persists rather than storming"
        );
    }
    assert_eq!(
        demotions, 1,
        "one persistent quarantine, not a demotion per flap"
    );
    let observed = b
        .lock()
        .get("inst")
        .and_then(|book| book.subjects.get("cp"))
        .map(|s| s.ledger.drift_observations);
    assert_eq!(
        observed,
        Some(4),
        "DETECTION IS NEVER RATE-LIMITED: every drift is counted even when the demotion is what \
         persists"
    );

    now += 400_000;
    assert_eq!(
        b.sight(&i, "cp", "good", now),
        Ok((Sight::Same, Effect::Clear)),
        "past the backoff a clean answer IS believed"
    );
    assert_eq!(b.judge(&i, &whole), Ok(()));
}

/// A pin of the kind-neutral `mechanism`: an authenticity root holding `key`, or the no-root
/// spelling (no root, no material, no fingerprint).
fn pinned_by(mechanism: &str, root: bool, key: Option<&str>) -> TrustEntry {
    TrustEntry {
        pin: Some(DeclaredPin {
            mechanism: mechanism.into(),
            root,
            peer_key: false,
            key: key.map(Into::into),
            fingerprint: None,
        }),
        ..entry(None, 0, 0)
    }
}

/// AN IDENTITY CHANGE NEVER RIDES THE OLD APPROVAL (Q128 p8#1; `section.rs`: a registration with
/// no authenticity root approves nothing). A counterparty approved, with an item, under a root is
/// re-admitted with its pin changed to the no-root spelling, and then to another root: neither
/// keeps the approvals. RED arm: the re-admit compared only the declared fingerprint, which is
/// absent on both sides, so the subject was kept and `judge` answered `Ok` for both facts.
#[test]
fn a_pin_changed_to_no_root_or_another_root_keeps_no_approval() {
    let whole = TrustFacts {
        counterparty: "cp",
        item: None,
        digest: None,
    };
    let item = TrustFacts {
        counterparty: "cp",
        item: Some("t"),
        digest: Some("d1"),
    };
    let approved = |b: &TrustBook, i: &Arc<str>| {
        b.sight(i, "cp", "h1", 1).unwrap();
        b.decide(i, "cp", None, Ruling::Approve, None).unwrap();
        b.sight_item(i, "cp", "t", "d1").unwrap();
        b.decide(i, "cp", Some("t"), Ruling::Approve, None).unwrap();
        assert_eq!(b.judge(i, &whole), Ok(()));
        assert_eq!(b.judge(i, &item), Ok(()));
    };

    let (b, i) = book(pinned_by("root-kind", true, Some("K")));
    approved(&b, &i);
    b.admit(&i, [("cp".to_string(), pinned_by("none", false, None))], []);
    assert_ne!(b.judge(&i, &whole), Ok(()), "rootless now");
    assert_ne!(b.judge(&i, &item), Ok(()), "its item too");
    assert_eq!(
        b.sight(&i, "cp", "h1", 2),
        Ok((Sight::New, Effect::None)),
        "nothing is pinned at a rootless counterparty"
    );

    let (b, i) = book(pinned_by("root-kind", true, Some("K")));
    approved(&b, &i);
    b.admit(
        &i,
        [("cp".to_string(), pinned_by("root-kind", true, Some("K2")))],
        [],
    );
    assert_ne!(b.judge(&i, &whole), Ok(()), "another root starts afresh");
    assert_ne!(b.judge(&i, &item), Ok(()));
    // The same declaration keeps them.
    let (b, i) = book(pinned_by("root-kind", true, Some("K")));
    approved(&b, &i);
    b.admit(
        &i,
        [("cp".to_string(), pinned_by("root-kind", true, Some("K")))],
        [],
    );
    assert_eq!(b.judge(&i, &whole), Ok(()));
    assert_eq!(b.judge(&i, &item), Ok(()));
}

/// NO APPROVAL REPLAYS ONTO A ROOTLESS REGISTRATION (Q128 p8#1): even a kept row recorded under
/// the very same no-root declaration replays as nothing, while a kept revocation still holds.
#[test]
fn a_kept_approval_never_replays_onto_a_rootless_registration() {
    let rootless = pinned_by("none", false, None);
    let (b, i) = book(rootless.clone());
    let row = |item: Option<&str>, approved: Option<&str>| RulingRow {
        instance: "inst".into(),
        counterparty: "cp".into(),
        item: item.map(Into::into),
        approved: approved.map(Into::into),
        declared: rootless.pin.clone(),
        demoted: false,
    };
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    b.admit_decided(&i, [&row(None, Some("h1")), &row(Some("t"), Some("d1"))]);
    let whole = TrustFacts {
        counterparty: "cp",
        item: None,
        digest: None,
    };
    let item = TrustFacts {
        counterparty: "cp",
        item: Some("t"),
        digest: Some("d1"),
    };
    assert_ne!(b.judge(&i, &whole), Ok(()));
    assert_ne!(b.judge(&i, &item), Ok(()));
    b.admit_decided(&i, [&row(None, None)]);
    assert_eq!(b.judge(&i, &whole), Err(Distrust::NotApproved));
}

/// A RESTART AGREES WITH A RELOAD (Q128 p8#2): a declared fingerprint edited while the process was
/// down starts the counterparty afresh, pending until the operator approves again, exactly as the
/// same edit applied in-process does. RED arm: the kept approval was replayed whatever the
/// declaration, so the fresh book served the counterparty at the old fingerprint.
#[test]
fn a_kept_approval_does_not_replay_over_a_declaration_changed_while_down() {
    let whole = TrustFacts {
        counterparty: "cp",
        item: None,
        digest: None,
    };
    let (b, i) = book(entry(Some("fp"), 0, 0));
    b.sight(&i, "cp", "fp", 1).unwrap();
    let (_, kept) = b
        .decide(&i, "cp", None, Ruling::Approve, Some("fp"))
        .unwrap();
    assert_eq!(b.judge(&i, &whole), Ok(()));

    let (same, s) = book(entry(Some("fp"), 0, 0));
    same.admit_decided(&s, [&kept]);
    assert_eq!(
        same.judge(&s, &whole),
        Ok(()),
        "the same declaration replays"
    );

    let (moved, m) = book(entry(Some("fp2"), 0, 0));
    moved.admit_decided(&m, [&kept]);
    assert_eq!(
        moved.judge(&m, &whole),
        Err(Distrust::NotApproved),
        "a changed declaration is pending again"
    );
    // ... as the in-process re-admit has it.
    b.admit(&i, [("cp".to_string(), entry(Some("fp2"), 0, 0))], []);
    assert_eq!(b.judge(&i, &whole), Err(Distrust::NotApproved));
}

/// A RULING TAKES NOTHING UNTIL IT IS APPLIED (Q128 p5#2): `rule` answers the fact to keep and
/// leaves the book as it was; `apply` takes it.
#[test]
fn a_ruling_changes_nothing_until_it_is_applied() {
    let whole = TrustFacts {
        counterparty: "cp",
        item: None,
        digest: None,
    };
    let (b, i) = book(entry(None, 0, 0));
    b.sight(&i, "cp", "h1", 1).unwrap();
    let fact = b.rule(&i, "cp", None, Ruling::Approve, Some("h1")).unwrap();
    assert_eq!(fact.approved.as_deref(), Some("h1"));
    assert_eq!(b.judge(&i, &whole), Err(Distrust::NotApproved));
    let row = b.apply(&fact).unwrap();
    assert_eq!(row.approved.as_deref(), Some("h1"));
    assert_eq!(b.judge(&i, &whole), Ok(()));
    // A fact whose declaration moved under it is not taken.
    b.admit(&i, [("cp".to_string(), entry(Some("fp"), 0, 0))], []);
    assert_eq!(b.apply(&fact), Err(Undecided::Stale));
}

/// A DRIFTED ITEM IS DEMOTED AT ITEM LEVEL, AND A REVERT DOES NOT LIFT IT (tool-and-agent-trust.md
/// 34-37: a changed fingerprint is quarantined; mcp.astro:374 "until a person approves"). An item
/// approved in config or by the operator, re-sighted at another digest, is refused; sighted back at
/// its approved digest it is STILL refused, until the operator approves it again. RED before: the
/// revert served, the drift a per-call refusal and nothing more.
#[test]
fn a_drifted_item_reverted_stays_refused_until_reapproved() {
    let at = |item| TrustFacts {
        counterparty: "cp",
        item: Some(item),
        digest: None,
    };
    let mut e = entry(None, 0, 0);
    e.approved.insert("t".to_string(), "d1".to_string());
    let (b, i) = book(e);
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    assert_eq!(b.judge(&i, &at("t")), Ok(()), "configured, sighted at it");
    b.sight_item(&i, "cp", "t", "d2").unwrap();
    assert_eq!(b.judge(&i, &at("t")), Err(Distrust::Changed), "drifted");
    b.sight_item(&i, "cp", "t", "d1").unwrap();
    assert_eq!(
        b.judge(&i, &at("t")),
        Err(Distrust::Changed),
        "reverted, it stays refused"
    );
    let state = |b: &TrustBook| {
        b.rows()
            .into_iter()
            .find(|r| r.item.as_deref() == Some("t"))
            .map(|r| r.state)
    };
    assert_eq!(state(&b), Some(KeyState::Quarantined), "listed demoted");
    // A re-admit (a config reload) is no person's approval of the drift.
    let mut e = entry(None, 0, 0);
    e.approved.insert("t".to_string(), "d1".to_string());
    b.admit(&i, [("cp".to_string(), e)], []);
    assert_eq!(b.judge(&i, &at("t")), Err(Distrust::Changed));
    // The operator approves what it is offered at now: it serves.
    b.decide(&i, "cp", Some("t"), Ruling::Approve, None)
        .expect("a key");
    assert_eq!(b.judge(&i, &at("t")), Ok(()));
    assert_eq!(state(&b), Some(KeyState::Same));
}
