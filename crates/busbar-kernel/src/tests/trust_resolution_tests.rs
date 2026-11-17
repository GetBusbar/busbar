// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST-ADMIN-PRODUCER-DESIGN r3 §4.4 and §4.6, tests R7, G20, G21 and G22 at the kernel: an
//! ambiguous durable write is unknown, and a replay resolves it only from what the record's own
//! settlement proves.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use busbar_contract::services::{Caller, HostServices, Later, Ran};

use super::{InstanceFacts, KernelServices, Resolution, TrustRefused};
use crate::persistence::test_backend::{attach, Backend};
use crate::trust::book::{Reviewed, Ruling};
use crate::trust::demotion::DemotionRecord;
use crate::trust::reverify::Policy;
use crate::trust::section::TrustEntry;

const KEY: &str = "inst/cp";

async fn custody(backend: &Arc<Backend>) -> Arc<DemotionRecord> {
    let record = Arc::new(DemotionRecord::new());
    record
        .set_store(Arc::new(attach(Arc::clone(backend)).await))
        .expect("a fresh record attaches");
    record
}

/// A kernel whose decision record writes through `backend`, with `cp` sighted at `h1`.
async fn kernel(record: Arc<DemotionRecord>) -> KernelServices {
    // Production custody comes with the host pool its durable trust effects run on.
    let k = KernelServices::new()
        .with_pool(Arc::new(super::BlockingPool::new(
            tokio::runtime::Handle::current(),
            8,
        )))
        .with_demotions(record, "");
    k.admit(
        "inst",
        InstanceFacts {
            trust: vec![(
                "cp".to_string(),
                TrustEntry {
                    pin: None,
                    policy: Policy {
                        ttl_ms: 0,
                        recovery_backoff_ms: 0,
                    },
                    approved: Default::default(),
                },
            )],
            ..InstanceFacts::default()
        },
    )
    .await
    .expect("admitted");
    let later: Later = Box::new(|_| {});
    let caller = Caller::for_test(
        Arc::from("inst"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    assert!(matches!(
        k.trust_sight(&caller, "cp", "h1", later),
        Ran::Now(_)
    ));
    k
}

fn approved(k: &KernelServices) -> Option<String> {
    k.trust_rows()
        .into_iter()
        .find(|row| row.key() == KEY)
        .and_then(|row| row.approved)
}

async fn unknown_approve(k: &KernelServices) -> ([u8; 16], u64) {
    let decided = k
        .trust_rule_by(
            KEY,
            Ruling::Approve,
            Reviewed::Seen("h1"),
            "op",
            Some("op-1"),
        )
        .await;
    assert!(decided.audited, "the attempt wrote its typed row");
    match decided.result {
        Err(TrustRefused::Unknown { op_id, decided_at }) => (op_id, decided_at),
        other => panic!("an ambiguous write is unknown, never applied or refused: {other:?}"),
    }
}

/// R7 (kernel half) and G22: a lost reply is unknown and changes nothing in RAM; a replay finds
/// the attempt landed, puts the kept row in force, and only then answers applied.
#[tokio::test]
async fn a_lost_reply_is_unknown_and_resolves_to_applied_once_in_force() {
    let backend = Arc::new(Backend::default());
    let k = kernel(custody(&backend).await).await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    let (op_id, decided_at) = unknown_approve(&k).await;
    assert_eq!(
        approved(&k),
        None,
        "an unknown outcome is not applied in RAM"
    );

    match k
        .trust_resolve_attempt(op_id, KEY, decided_at, Some("op-1"))
        .await
    {
        Resolution::Applied(row) => assert_eq!(row.approved.as_deref(), Some("h1")),
        other => panic!("the landed attempt resolves to applied: {other:?}"),
    }
    assert_eq!(
        approved(&k).as_deref(),
        Some("h1"),
        "applied only once the kept row is in force here"
    );
}

/// G20: a write the store proves never applied resolves to not applied, and nothing was kept.
#[tokio::test]
async fn a_write_proven_never_applied_resolves_to_not_applied() {
    let backend = Arc::new(Backend::default());
    let record = custody(&backend).await;
    let k = kernel(Arc::clone(&record)).await;
    backend.never_applies.store(true, Ordering::SeqCst);
    let (op_id, decided_at) = unknown_approve(&k).await;
    assert_eq!(
        k.trust_resolve_attempt(op_id, KEY, decided_at, Some("op-1"))
            .await,
        Resolution::NotApplied
    );
    assert_eq!(approved(&k), None);
    assert!(
        record.kept().await.expect("readable").decisions.is_empty(),
        "nothing was kept"
    );
    // The proof is remembered: a second ask answers the same without a new crossing.
    assert_eq!(
        k.trust_resolve_attempt(op_id, KEY, decided_at, Some("op-1"))
            .await,
        Resolution::NotApplied
    );
}

/// G21: after a restart the attempt is gone and nothing proves either outcome: unknown, never a
/// guess from absence.
#[tokio::test]
async fn without_proof_an_unknown_stays_unknown() {
    let backend = Arc::new(Backend::default());
    let k = kernel(custody(&backend).await).await;
    backend.never_applies.store(true, Ordering::SeqCst);
    let (op_id, decided_at) = unknown_approve(&k).await;
    drop(k);
    let restarted = kernel(custody(&backend).await).await;
    assert_eq!(
        restarted
            .trust_resolve_attempt(op_id, KEY, decided_at, Some("op-1"))
            .await,
        Resolution::Unknown
    );
    assert_eq!(approved(&restarted), None);
}
