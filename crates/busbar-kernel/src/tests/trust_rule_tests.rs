// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::host::service as svc;
use busbar_contract::services::{Caller, HostServices, Later, Ran, Stored, TrustKeyRef};

use super::{BlockingPool, InstanceFacts, KernelServices, TrustDecisionAuthority};
use crate::trust::book::{Distrust, Reviewed, Ruling, TrustFacts};
use crate::trust::reverify::Policy;
use crate::trust::section::TrustEntry;

const UNVERIFIED: &str = "unverified";

fn caller() -> Caller {
    Caller::for_test(
        Arc::from("inst"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    )
}

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

/// A kernel with trust custody (a bound decision record) and a host pool, as production has
/// (TRUST-ADMIN-PRODUCER-DESIGN r3 §6, condition A-C1).
async fn kernel_with(trust: Vec<(String, TrustEntry)>) -> KernelServices {
    let k = KernelServices::new()
        .with_pool(Arc::new(BlockingPool::new(
            tokio::runtime::Handle::current(),
            8,
        )))
        .with_test_custody()
        .await;
    k.admit(
        &"inst".into(),
        InstanceFacts {
            trust,
            ..InstanceFacts::default()
        },
    )
    .await
    .expect("admitted");
    k
}

async fn kernel() -> KernelServices {
    kernel_with(vec![("cp".to_string(), entry())]).await
}

/// One host call's answer, now or later: bound custody makes durable trust effects answer later.
async fn answered(operation: impl FnOnce(Later) -> Ran) -> Stored {
    let (tx, rx) = tokio::sync::oneshot::channel();
    match operation(Box::new(move |stored| {
        let _ = tx.send(stored);
    })) {
        Ran::Now(stored) => stored,
        Ran::Later => rx.await.expect("the host answers"),
    }
}

async fn sight(k: &KernelServices, hash: &str) -> Stored {
    answered(|later| k.trust_sight(&caller(), "cp", hash, later)).await
}

fn served(k: &KernelServices) -> Result<(), Distrust> {
    k.trust_judge(
        "inst",
        &TrustFacts {
            counterparty: "cp",
            item: None,
            digest: None,
        },
    )
}

fn pinned(k: &KernelServices) -> Option<String> {
    k.trust_rows()
        .into_iter()
        .find(|r| r.key() == "inst/cp")
        .and_then(|r| r.approved)
}

fn ticket(slot: u32) -> busbar_contract::abi::mechanism::ticket::Ticket {
    busbar_contract::abi::mechanism::ticket::Ticket {
        slot,
        generation: 1,
    }
}

#[tokio::test]
async fn generic_approve_never_pins_an_unverified_sighting() {
    let k = kernel().await;
    assert_eq!(sight(&k, UNVERIFIED).await.value, svc::TRUST_NEW);

    assert!(
        k.trust_rule_reviewed("inst/cp", Ruling::Approve)
            .await
            .is_err(),
        "the generic approve refuses a sighting that failed verification"
    );
    assert_eq!(pinned(&k), None, "nothing is pinned");
    assert!(served(&k).is_err(), "and nothing serves");

    let key = TrustKeyRef {
        counterparty: "cp",
        item: None,
    };
    // Test-Change (TST-3, r3 §4.2c): a plane approve with no reviewed digest is refused as stale;
    // one reviewed at the unverified sighting is refused as unpinned, as before.
    for (slot, expected, refusal) in [
        (1, None, svc::UNDECIDED_STALE),
        (2, Some(UNVERIFIED), svc::UNDECIDED_UNPINNED),
    ] {
        let me = caller();
        let _grant = k
            .grant_trust_decision(&me, ticket(slot), "cp", TrustDecisionAuthority::for_test())
            .unwrap();
        let decided =
            answered(|later| k.trust_decide(&me, ticket(slot), key, expected, true, later)).await;
        assert_eq!(
            decided.value, refusal,
            "expected {expected:?}: the typed approve refuses it too"
        );
        assert_eq!(pinned(&k), None);
    }

    assert_eq!(sight(&k, "fp").await.value, svc::TRUST_NEW);
    let row = k
        .trust_rule_reviewed("inst/cp", Ruling::Approve)
        .await
        .expect("approvable");
    assert_eq!(row.approved.as_deref(), Some("fp"));
    assert_eq!(served(&k), Ok(()));

    assert_eq!(sight(&k, UNVERIFIED).await.value, svc::TRUST_DRIFTED);
    assert!(k
        .trust_rule_reviewed("inst/cp", Ruling::Approve)
        .await
        .is_err());
    assert_eq!(served(&k), Err(Distrust::Quarantined));
}

#[tokio::test]
async fn guarded_trust_rulings_compare_the_current_sighting_for_both_decisions() {
    use super::TrustRefused;
    let k = kernel().await;
    let rule = |key: &'static str, ruling, digest: &'static str| {
        let k = &k;
        async move {
            k.trust_rule_by(key, ruling, Reviewed::Seen(digest), "op", None)
                .await
                .result
        }
    };
    // Test-Change (TST-3, r3 §4.1): a review naming a digest the key was never sighted at is
    // stale, not "nothing sighted".
    for ruling in [Ruling::Approve, Ruling::Revoke] {
        assert_eq!(
            rule("inst/cp", ruling, "old").await,
            Err(TrustRefused::Stale)
        );
    }
    sight(&k, "old").await;
    let approved = rule("inst/cp", Ruling::Approve, "old").await.unwrap();
    assert_eq!(approved.approved.as_deref(), Some("old"));
    sight(&k, "new").await;
    let before = k.trust_rows();
    // Test-Change (TST-3, r3 §4.1): approve must review the current sighting; revoke accepts the
    // current sighting or the current approval, so its stale review names neither.
    for (ruling, stale) in [(Ruling::Approve, "old"), (Ruling::Revoke, "other")] {
        assert_eq!(
            rule("inst/cp", ruling, stale).await,
            Err(TrustRefused::Stale)
        );
        assert_eq!(
            k.trust_rows(),
            before,
            "a stale review changes no trust row"
        );
    }
    let revoked = rule("inst/cp", Ruling::Revoke, "new").await.unwrap();
    // A whole-key revoke retains its historical pin; its serving state carries the refusal.
    assert_eq!(revoked.approved.as_deref(), Some("old"));
    assert_eq!(revoked.seen.as_deref(), Some("new"));
    assert_eq!(served(&k), Err(Distrust::Quarantined));
    // Test-Change (TST-3, r3 §4.1): key-only approval no longer exists; the operator reviews the
    // current sighting and approves it.
    let approved = rule("inst/cp", Ruling::Approve, "new").await.unwrap();
    assert_eq!(approved.approved.as_deref(), Some("new"));
    let revoked = rule("inst/cp", Ruling::Revoke, "new").await.unwrap();
    assert_eq!(revoked.approved.as_deref(), Some("new"));
    assert_eq!(revoked.state, crate::trust::book::KeyState::New);
    assert_eq!(served(&k), Err(Distrust::NotApproved));
}

#[tokio::test]
async fn guarded_item_rulings_compare_the_item_digest() {
    use super::TrustRefused;
    let k = kernel().await;
    let rule = |key: &'static str, ruling, digest: &'static str| {
        let k = &k;
        async move {
            k.trust_rule_by(key, ruling, Reviewed::Seen(digest), "op", None)
                .await
                .result
        }
    };
    sight(&k, "catalogue").await;
    k.trust_rule_reviewed("inst/cp", Ruling::Approve)
        .await
        .unwrap();
    answered(|later| k.trust_sight_item(&caller(), "cp", "tool", "old", later)).await;
    rule("inst/cp/tool", Ruling::Approve, "old").await.unwrap();
    answered(|later| k.trust_sight_item(&caller(), "cp", "tool", "new", later)).await;
    let before = k.trust_rows();
    // Test-Change (TST-3, r3 §4.1): the item's current approval `old` is a valid revoke review,
    // so only `catalogue` is stale for both rulings.
    for (ruling, wrongs) in [
        (Ruling::Approve, &["old", "catalogue"][..]),
        (Ruling::Revoke, &["catalogue"][..]),
    ] {
        for wrong in wrongs {
            assert_eq!(
                rule("inst/cp/tool", ruling, wrong).await,
                Err(TrustRefused::Stale)
            );
            assert_eq!(k.trust_rows(), before);
        }
    }
    let row = rule("inst/cp/tool", Ruling::Approve, "new").await.unwrap();
    assert_eq!(row.approved.as_deref(), Some("new"));
    assert_eq!(row.seen.as_deref(), Some("new"));
    assert_eq!(
        rule("inst/cp/tool", Ruling::Revoke, "new")
            .await
            .unwrap()
            .approved,
        None
    );
}

/// Test-Change (TST-3, r3 §4.2c): the plane-relayed revoke now applies the revoke review rule to a
/// supplied digest (current sighting or current approval); without one it stays unconditional.
#[tokio::test]
async fn plugin_revoke_applies_the_revoke_review_rule() {
    let k = kernel().await;
    sight(&k, "current").await;
    k.trust_rule_reviewed("inst/cp", Ruling::Approve)
        .await
        .unwrap();
    let key = TrustKeyRef {
        counterparty: "cp",
        item: None,
    };
    let me = caller();
    let _grant = k
        .grant_trust_decision(&me, ticket(1), "cp", TrustDecisionAuthority::for_test())
        .unwrap();
    let decided =
        answered(|later| k.trust_decide(&me, ticket(1), key, Some("obsolete"), false, later)).await;
    assert_eq!(decided.value, svc::UNDECIDED_STALE);
    assert_eq!(pinned(&k).as_deref(), Some("current"));
    assert_eq!(served(&k), Ok(()), "a stale review revokes nothing");

    let _grant = k
        .grant_trust_decision(&me, ticket(2), "cp", TrustDecisionAuthority::for_test())
        .unwrap();
    let decided = answered(|later| k.trust_decide(&me, ticket(2), key, None, false, later)).await;
    assert_eq!(decided.value, svc::TRUST_DECIDED_PENDING);
    assert_eq!(pinned(&k).as_deref(), Some("current"));
    assert_eq!(served(&k), Err(Distrust::NotApproved));
}

/// A plane-relayed decision needs the admin gate's authority for that ruling (r3 §4.2a, R8).
#[tokio::test]
async fn a_grant_without_the_ruling_decides_nothing() {
    let k = kernel().await;
    sight(&k, "current").await;
    let key = TrustKeyRef {
        counterparty: "cp",
        item: None,
    };
    let me = caller();
    let revoke_only = TrustDecisionAuthority {
        principal: "op".to_string(),
        approve: false,
        revoke: true,
    };
    let _grant = k
        .grant_trust_decision(&me, ticket(1), "cp", revoke_only)
        .unwrap();
    let decided =
        answered(|later| k.trust_decide(&me, ticket(1), key, Some("current"), true, later)).await;
    assert_ne!(decided.value, svc::TRUST_DECIDED_SERVING);
    assert_eq!(pinned(&k), None, "nothing was approved");
}

/// Aikido 1074596877 (#103): a flattened `instance/counterparty[/item]` key can name two rows
/// when a registration name contains `/` (registration `cp/tool` and item `tool` on `cp` both
/// flatten to `inst/cp/tool`). An admin ruling on such a key must decide nothing, never land on
/// whichever row sorts first, which an upstream can choose by naming a tool.
#[tokio::test]
async fn an_ambiguous_flattened_trust_key_is_refused() {
    use super::TrustRefused;
    let k = kernel_with(vec![
        ("cp".to_string(), entry()),
        ("cp/tool".to_string(), entry()),
    ])
    .await;
    answered(|later| k.trust_sight(&caller(), "cp/tool", "registration", later)).await;
    sight(&k, "catalogue").await;
    k.trust_rule_reviewed("inst/cp", Ruling::Approve)
        .await
        .unwrap();
    answered(|later| k.trust_sight_item(&caller(), "cp", "tool", "upstream", later)).await;
    assert_eq!(
        k.trust_rows()
            .iter()
            .filter(|r| r.key() == "inst/cp/tool")
            .count(),
        2,
        "two rows flatten to one key"
    );
    let before = k.trust_rows();
    for ruling in [Ruling::Approve, Ruling::Revoke] {
        assert_eq!(
            k.trust_rule_by("inst/cp/tool", ruling, Reviewed::Unsighted, "op", None)
                .await
                .result,
            Err(TrustRefused::Ambiguous)
        );
        assert_eq!(k.trust_rows(), before, "an ambiguous key decides nothing");
    }
}
