// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store-backed WORK custody (IF §12.24): rows over `host_work/`, the recovery binding governance captures.

use busbar_plugin_abi::fail::refused::{
    R_DENIED, R_INVALID, R_NOT_FOUND, R_RATE_LIMITED, R_UNSUPPORTED,
};
use busbar_plugin_abi::plane::{WORK_LIVE, WORK_SETTLED};

use super::*;
use crate::host_work::{Work, WorkBounds, WORK_SCHEMA};
use crate::persistence::facade::CoreStore;
use crate::persistence::scoped::ScopedStore;
use crate::plane_driver::port_auth::subject_identity;
use crate::plane_driver::port_intents::Namespace;

fn who() -> Namespace {
    Namespace {
        plugin: "plane-llm".into(),
        name: "llm".into(),
        instance: 1,
        slot: 0,
    }
}

fn binding_of(subject: &str, _now_s: u64) -> Result<RecoveryBinding, &'static str> {
    Ok(RecoveryBinding {
        principal: subject.to_owned(),
        generation: "g1".into(),
        created_at: 7,
        expires_at: None,
    })
}

fn no_standing(_: &str, _: u64) -> Result<RecoveryBinding, &'static str> {
    Err("recovery principal has no current standing")
}

struct Fixture {
    store: LateStore,
    binder: LateBinder,
    work: StoreWork,
    core: Arc<CoreStore>,
}

async fn fixture() -> Fixture {
    let core = crate::real_store::core().await;
    let store = LateStore::default();
    store.install(Arc::clone(&core));
    let binder = LateBinder::default();
    binder.install(Arc::new(binding_of));
    let work = StoreWork::new(store.clone(), binder.clone(), Arc::new(|| 1_000_000));
    work.set_recovery_ready(true);
    Fixture {
        store,
        binder,
        work,
        core,
    }
}

fn rows(core: &Arc<CoreStore>) -> ScopedStore {
    ScopedStore::host_private(Arc::clone(core), "llm", [WORK_SCHEMA.as_str().to_string()]).unwrap()
}

async fn stored(core: &Arc<CoreStore>, reference: &str) -> Option<Work> {
    let key = crate::host_work::parse_reference(reference.as_bytes())?;
    let row = rows(core).get(WORK_SCHEMA.as_str(), &key).await.unwrap()?;
    Work::read(&Arc::from("llm"), key, row.expose(&crate::seal::lend()))
}

#[tokio::test]
async fn open_binds_the_principal_governance_captured_and_find_answers_live_with_the_target() {
    let f = fixture().await;
    let who = who();
    let alice = subject_identity("alice");
    let reference = f
        .work
        .open(&who.caller(), &alice, "/jobs/1?cursor=2")
        .await
        .unwrap();
    assert_eq!(reference.len(), 32);
    let row = stored(&f.core, &reference)
        .await
        .expect("the row is durable before open answers");
    assert!(row.live);
    assert_eq!(row.recovery, Some(binding_of("alice", 0).unwrap()));
    assert_eq!(
        busbar_contract::abi::sdk::recovery::poll_target(&row.record),
        Ok(Some("/jobs/1?cursor=2"))
    );
    let (state, target) = f
        .work
        .find(&who.caller(), &alice, &reference)
        .await
        .unwrap();
    assert_eq!((state, &*target), (WORK_LIVE, "/jobs/1?cursor=2"));
}

#[tokio::test]
async fn another_principals_reference_is_denied_for_find_and_settle_and_stays_live() {
    let f = fixture().await;
    let who = who();
    let reference = f
        .work
        .open(&who.caller(), &subject_identity("alice"), "/jobs/1")
        .await
        .unwrap();
    let bob = subject_identity("bob");
    assert_eq!(
        f.work
            .find(&who.caller(), &bob, &reference)
            .await
            .unwrap_err(),
        R_DENIED
    );
    assert_eq!(
        f.work
            .settle(&who.caller(), &bob, &reference)
            .await
            .unwrap_err(),
        R_DENIED
    );
    assert!(stored(&f.core, &reference).await.unwrap().live);
}

#[tokio::test]
async fn settle_is_durable_idempotent_and_drops_the_recovery_binding() {
    let f = fixture().await;
    let who = who();
    let alice = subject_identity("alice");
    let reference = f.work.open(&who.caller(), &alice, "/jobs/1").await.unwrap();
    f.work
        .settle(&who.caller(), &alice, &reference)
        .await
        .unwrap();
    f.work
        .settle(&who.caller(), &alice, &reference)
        .await
        .unwrap();
    let row = stored(&f.core, &reference).await.unwrap();
    assert!(!row.live);
    assert_eq!(row.recovery, None, "a settled row is never recovered");
    let (state, target) = f
        .work
        .find(&who.caller(), &alice, &reference)
        .await
        .unwrap();
    assert_eq!((state, &*target), (WORK_SETTLED, ""));
}

#[tokio::test]
async fn a_new_process_finds_what_the_old_one_opened() {
    let f = fixture().await;
    let who = who();
    let alice = subject_identity("alice");
    let reference = f.work.open(&who.caller(), &alice, "/jobs/9").await.unwrap();
    let restarted = StoreWork::new(f.store.clone(), f.binder.clone(), Arc::new(|| 1_000_001));
    let (state, target) = restarted
        .find(&who.caller(), &alice, &reference)
        .await
        .unwrap();
    assert_eq!((state, &*target), (WORK_LIVE, "/jobs/9"));
}

#[tokio::test]
async fn an_unknown_or_malformed_reference_is_not_found() {
    let f = fixture().await;
    let who = who();
    let alice = subject_identity("alice");
    for reference in ["not hex", "00000000000000000000000000000000"] {
        assert_eq!(
            f.work
                .find(&who.caller(), &alice, reference)
                .await
                .unwrap_err(),
            R_NOT_FOUND
        );
        assert_eq!(
            f.work
                .settle(&who.caller(), &alice, reference)
                .await
                .unwrap_err(),
            R_NOT_FOUND
        );
    }
}

#[tokio::test]
async fn core_that_cannot_recover_answers_unsupported_and_writes_nothing() {
    let who = who();
    let alice = subject_identity("alice");
    // The recovery scheduler is not ready.
    let f = fixture().await;
    f.work.set_recovery_ready(false);
    assert_eq!(
        f.work
            .open(&who.caller(), &alice, "/jobs/1")
            .await
            .unwrap_err(),
        R_UNSUPPORTED
    );
    // No binder installed (governance not attached).
    let bare = StoreWork::new(f.store.clone(), LateBinder::default(), Arc::new(|| 1));
    bare.set_recovery_ready(true);
    assert_eq!(
        bare.open(&who.caller(), &alice, "/jobs/1")
            .await
            .unwrap_err(),
        R_UNSUPPORTED
    );
    // Governance has no live standing for the principal.
    let refused = LateBinder::default();
    refused.install(Arc::new(no_standing));
    let denied = StoreWork::new(f.store.clone(), refused, Arc::new(|| 1));
    denied.set_recovery_ready(true);
    assert_eq!(
        denied
            .open(&who.caller(), &alice, "/jobs/1")
            .await
            .unwrap_err(),
        R_UNSUPPORTED
    );
    // No store open yet.
    let early = StoreWork::new(LateStore::default(), f.binder.clone(), Arc::new(|| 1));
    early.set_recovery_ready(true);
    assert_eq!(
        early
            .open(&who.caller(), &alice, "/jobs/1")
            .await
            .unwrap_err(),
        R_UNSUPPORTED
    );
    let page = rows(&f.core)
        .page(WORK_SCHEMA.as_str(), &[], None)
        .await
        .unwrap();
    assert!(page.rows.is_empty(), "no refused open left a row");
}

#[tokio::test]
async fn a_target_that_is_not_a_local_get_path_is_invalid() {
    let f = fixture().await;
    let who = who();
    let alice = subject_identity("alice");
    for target in ["https://example.test/job", "//example.test/job", "jobs/1"] {
        assert_eq!(
            f.work
                .open(&who.caller(), &alice, target)
                .await
                .unwrap_err(),
            R_INVALID
        );
    }
}

#[tokio::test]
async fn the_instances_live_work_is_bounded() {
    let f = fixture().await;
    let work = f.work.with_bounds(WorkBounds {
        max_live: 1,
        retain_ms: 300_000,
    });
    let who = who();
    let alice = subject_identity("alice");
    let first = work.open(&who.caller(), &alice, "/jobs/1").await.unwrap();
    assert_eq!(
        work.open(&who.caller(), &alice, "/jobs/2")
            .await
            .unwrap_err(),
        R_RATE_LIMITED
    );
    work.settle(&who.caller(), &alice, &first).await.unwrap();
    work.open(&who.caller(), &alice, "/jobs/2").await.unwrap();
}

#[tokio::test]
async fn work_without_a_verified_subject_is_denied() {
    let f = fixture().await;
    let who = who();
    assert_eq!(
        f.work
            .open(&who.caller(), &[], "/jobs/1")
            .await
            .unwrap_err(),
        R_DENIED
    );
}
