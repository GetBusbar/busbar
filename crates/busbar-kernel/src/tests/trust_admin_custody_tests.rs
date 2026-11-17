// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST-ADMIN-PRODUCER-DESIGN r3 §4.1–§4.2: decisions need bound durable custody, approve needs a
//! current review on every path, and revoke accepts the current sighting or the current approval.

use std::sync::Arc;

use busbar_contract::abi::host::service as svc;
use busbar_contract::services::{Caller, HostServices, Later, Ran, Stored, TrustKeyRef};

use super::{InstanceFacts, KernelServices};
use crate::trust::book::{Reviewed, Ruling, TrustBook};
use crate::trust::reverify::Policy;
use crate::trust::section::TrustEntry;

fn entry() -> TrustEntry {
    TrustEntry {
        pin: None,
        policy: Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
        approved: Default::default(),
    }
}

fn caller() -> Caller {
    Caller::for_test(
        Arc::from("inst"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    )
}

fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    use futures::FutureExt;
    future
        .now_or_never()
        .expect("the pure trust fixture completes in one poll")
}

fn immediate(operation: impl FnOnce(Later) -> Ran) -> Stored {
    match operation(Box::new(|_| panic!("the pure trust fixture cannot pend"))) {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("the pure trust fixture cannot pend"),
    }
}

/// A kernel with no durable decision record: no trust custody.
fn recordless() -> KernelServices {
    let k = KernelServices::new();
    ready(k.admit(
        "inst",
        InstanceFacts {
            trust: vec![("cp".to_string(), entry())],
            ..InstanceFacts::default()
        },
    ))
    .expect("admitted");
    let later: Later = Box::new(|_| {});
    match k.trust_sight(&caller(), "cp", "h1", later) {
        Ran::Now(_) => {}
        Ran::Later => panic!("no durable record: the sighting answers now"),
    }
    k
}

#[test]
fn an_admin_decision_without_bound_custody_is_refused_and_changes_nothing() {
    let k = recordless();
    assert!(
        ready(k.trust_rule_by("inst/cp", Ruling::Approve, Reviewed::Seen("h1"), "op", None))
            .result
            .is_err(),
        "a decision that cannot be kept durably is never made in memory only"
    );
    let row = k
        .trust_rows()
        .into_iter()
        .find(|r| r.key() == "inst/cp")
        .expect("the key");
    assert_eq!(row.approved, None, "nothing was approved");
}

#[test]
fn a_plane_relayed_approve_without_a_reviewed_digest_is_refused() {
    let k = recordless();
    let me = caller();
    let ticket = busbar_contract::abi::mechanism::ticket::Ticket {
        slot: 1,
        generation: 1,
    };
    let _grant = k
        .grant_trust_decision(
            &me,
            ticket,
            "cp",
            crate::host_services::TrustDecisionAuthority::for_test(),
        )
        .unwrap();
    let key = TrustKeyRef {
        counterparty: "cp",
        item: None,
    };
    let decided = immediate(|later| k.trust_decide(&me, ticket, key, None, true, later));
    assert_ne!(
        decided.value,
        svc::TRUST_DECIDED_SERVING,
        "no key-only approve through the plugin interface either"
    );
    assert!(
        k.trust_rows()
            .into_iter()
            .find(|r| r.key() == "inst/cp")
            .is_some_and(|r| r.approved.is_none()),
        "nothing was approved"
    );
}

#[test]
fn a_revoke_reviewed_at_the_current_approval_survives_a_newer_sighting() {
    let b = TrustBook::default();
    let i: Arc<str> = Arc::from("inst");
    b.admit(&i, [("cp".to_string(), entry())], []);
    b.sight(&i, "cp", "h1", 1).unwrap();
    b.decide(&i, "cp", None, Ruling::Approve, None).unwrap();
    // The counterparty's catalogue moves after the operator reviewed it at its approval `h1`.
    b.sight(&i, "cp", "h2", 2).unwrap();
    let revoked = b.rule(&i, "cp", None, Ruling::Revoke, Some(Reviewed::Seen("h1")));
    assert!(
        revoked.is_ok(),
        "a protective revoke reviewed at the current approval is not starved by churn: {revoked:?}"
    );
}

#[test]
fn an_approve_reviewed_at_a_digest_that_is_not_the_current_sighting_is_stale() {
    let b = TrustBook::default();
    let i: Arc<str> = Arc::from("inst");
    b.admit(&i, [("cp".to_string(), entry())], []);
    assert_eq!(
        b.rule(&i, "cp", None, Ruling::Approve, Some(Reviewed::Seen("h1"))),
        Err(crate::trust::book::Undecided::Stale),
        "a review that names a digest the key was never sighted at is stale, not 'nothing sighted'"
    );
}
