// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::store::plane_view::KIND_DEMOTION;
use busbar_contract::records::RecordStoreResult;

fn demotion_rows(r: &Rig) -> Vec<Vec<u8>> {
    RecordStore::list_plane_records(&*r.store, KIND_DEMOTION, &PlaneSelector::All).unwrap()
}

#[test]
fn a_queued_drift_cannot_resurrect_quarantine_after_a_completed_approval() {
    let r = rig();
    let held = Arc::new(Held::default());
    let node = node(&r, &Arc::new(Probe::default()), Arc::new(Arc::clone(&held)));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    let (slot, later) = recorder();
    assert!(matches!(
        node.trust_sight(&caller(INSTANCE), COUNTERPARTY, CHANGED, later),
        Ran::Later
    ));
    let approval = node.trust_rule(WHOLE_KEY, Ruling::Approve);
    let typed = node.trust_decide(
        &caller(INSTANCE),
        busbar_contract::services::TrustKeyRef {
            counterparty: COUNTERPARTY,
            item: None,
        },
        Some(CHANGED),
        true,
    );

    node.decide_key(
        INSTANCE,
        COUNTERPARTY,
        Some(OTHER_ITEM),
        Ruling::Revoke,
        None,
    )
    .unwrap();
    assert!(demotion_rows(&r).is_empty(), "the drift is still queued");
    assert_eq!(judged(&node, None), Err(Distrust::Quarantined));
    assert_eq!(held.drain(), 1);
    assert_eq!(
        slot.lock().unwrap().take().unwrap().value,
        svc::TRUST_DRIFTED
    );
    assert_eq!(approval, Err(TrustRefused::Stale));
    assert_eq!(typed.value, svc::UNDECIDED_STALE);
    assert_eq!(demotion_rows(&r).len(), 1);
    let before_approval = super::node(&r, &Arc::new(Probe::default()), Arc::new(Inline));
    assert_eq!(judged(&before_approval, None), Err(Distrust::Quarantined));

    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    assert!(demotion_rows(&r).is_empty());
    assert_eq!(judged(&node, None), Ok(()));
    let restarted = super::node(&r, &Arc::new(Probe::default()), Arc::new(Inline));
    assert_eq!(
        judged(&restarted, None),
        Ok(()),
        "restart cannot resurrect the retired drift"
    );
    assert_eq!(kept(&r, None).approved.as_deref(), Some(CHANGED));
}

#[test]
fn dropping_an_unrun_drift_retires_ownership_before_answering_its_caller() {
    let r = rig();
    let held = Arc::new(Held::default());
    let node = node(&r, &Arc::new(Probe::default()), Arc::new(Arc::clone(&held)));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    let answered = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&answered);
    let retry = Arc::clone(&node);
    assert!(matches!(
        node.trust_sight(
            &caller(INSTANCE),
            COUNTERPARTY,
            CHANGED,
            Box::new(move |answer| {
                assert_eq!(
                    (answer.outcome, answer.error),
                    (Outcome::Failed, POOL_REFUSED)
                );
                assert_eq!(
                    judged(&retry, None),
                    Err(Distrust::Quarantined),
                    "abandoning the Store work does not undo RAM quarantine"
                );
                retry.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
                seen.store(true, Ordering::SeqCst);
            }),
        ),
        Ran::Later
    ));
    let jobs = std::mem::take(&mut *held.0.lock().unwrap());
    assert_eq!(jobs.len(), 1);

    drop(jobs);
    assert!(answered.load(Ordering::SeqCst));
    assert_eq!(judged(&node, None), Ok(()));
    assert!(demotion_rows(&r).is_empty());
}

#[test]
fn an_unwinding_drift_store_retires_ownership_before_the_failed_answer() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    assert!(probe
        .demotion_write
        .set(Arc::new(|_| -> RecordStoreResult<()> {
            panic!("the demotion Store unwound");
        }))
        .is_ok());
    let held = Arc::new(Held::default());
    let node = node(&r, &probe, Arc::new(Arc::clone(&held)));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    let (slot, later) = recorder();
    let reentered = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&reentered);
    let retry = Arc::clone(&node);
    assert!(matches!(
        node.trust_sight(
            &caller(INSTANCE),
            COUNTERPARTY,
            CHANGED,
            Box::new(move |answer| {
                *seen.lock().unwrap() = Some(retry.trust_rule(WHOLE_KEY, Ruling::Revoke));
                later(answer);
            }),
        ),
        Ran::Later
    ));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| held.drain())).is_err());
    let answer = slot.lock().unwrap().take().unwrap();
    assert_eq!(
        (answer.outcome, answer.error),
        (Outcome::Failed, POOL_REFUSED)
    );
    reentered.lock().unwrap().take().unwrap().unwrap();
    assert_eq!(kept(&r, None).approved, None);
    assert_eq!(judged(&node, None), Err(Distrust::Quarantined));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    assert_eq!(judged(&node, None), Ok(()));
}

#[test]
fn a_refused_demotion_store_keeps_ram_quarantine_and_retires_ownership() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    assert!(probe
        .demotion_write
        .set(Arc::new(|_| Err("the demotion Store is down".into())))
        .is_ok());
    let held = Arc::new(Held::default());
    let node = node(&r, &probe, Arc::new(Arc::clone(&held)));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    let (slot, later) = recorder();
    assert!(matches!(
        node.trust_sight(&caller(INSTANCE), COUNTERPARTY, CHANGED, later),
        Ran::Later
    ));
    assert_eq!(held.drain(), 1);
    let answer = slot.lock().unwrap().take().unwrap();
    assert_eq!(
        (answer.outcome, answer.value),
        (Outcome::Ready, svc::TRUST_DRIFTED)
    );
    assert_eq!(judged(&node, None), Err(Distrust::Quarantined));
    assert!(
        demotion_rows(&r).is_empty(),
        "failure costs durability, as before"
    );
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    assert_eq!(judged(&node, None), Ok(()));
}
