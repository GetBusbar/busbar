// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::connections::grant::*;
use crate::governance::at_rest::AtRestKeys;
use crate::persistence::{
    boot_identity::WriterRetirements,
    facade::{CoreStore, Limits, WriterAuthority},
    host_records::tests::Backend,
};
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::{fail::CallError, host_side::caller::BoxFut};
use busbar_ports::{auth::*, CallCx, PortError};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

async fn owner(backend: Arc<Backend>, writer: u8) -> Arc<CallerGrantOwner> {
    let store = Arc::new(
        CoreStore::attach(
            backend,
            WriterAuthority {
                writer_epoch: 2,
                writer: [writer; 16],
                execution_epoch: 3,
            },
            Limits {
                pending_operations: 32,
                conflict_retries: 2,
                scan_items: 2,
                scan_bytes: 262144,
            },
        )
        .await
        .unwrap(),
    );
    let owner = CallerGrantOwner::new(
        store,
        &AtRestKeys::new(&[7; 32], None),
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    while !owner.recover_page().await.unwrap() {}
    owner
}
fn key() -> GrantKey {
    GrantKey::new("plane", "instance", "subject", "upstream").unwrap()
}
async fn install(owner: &Arc<CallerGrantOwner>) -> GrantEpoch {
    owner
        .begin_connection(key())
        .await
        .unwrap()
        .complete(SecureVec::from(b"G0".as_slice()))
        .await
        .unwrap()
}
fn cx() -> CallCx {
    CallCx {
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        request_id: 7,
        stack: Default::default(),
        mono_ns: 0,
    }
}
fn request() -> UpstreamIn<'static> {
    UpstreamIn {
        method: "GET",
        url: "https://provider.invalid/path",
        headers: &[],
        body_sha256: None,
        caller_cred: &[],
        scope: Some("scope-a"),
        caller_grant: None,
        min_valid_s: 30,
    }
}
fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async { Err(PortError::Call(CallError::NotDeclared)) })
}
struct Rotating {
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    park: bool,
    update: bool,
}
impl Rotating {
    fn new(park: bool, update: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            entered: Default::default(),
            release: Default::default(),
            park,
            update,
        }
    }
}
impl AuthPort for Rotating {
    fn facts(&self) -> u64 {
        0
    }
    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(&'a self, _: CallCx, _: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
        Verify::Done(Ok(VerifyAnswer::NotMine))
    }
    fn login<'a>(
        &'a self,
        _: CallCx,
        _: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        unsupported()
    }
    fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }
    fn serve<'a>(
        &'a self,
        _: CallCx,
        _: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
    fn outbound<'a>(
        &'a self,
        _: CallCx,
        req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        Box::pin(async move {
            assert_eq!(req.caller_grant, Some(b"G0".as_slice()));
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            if self.park {
                self.release.notified().await;
            }
            Ok(OutboundAnswer {
                headers: vec![(
                    "authorization".into(),
                    SecureVec::from(b"credential".as_slice()),
                )],
                query: vec![],
                cache_s: 60,
                grant_update: self.update.then(|| SecureVec::from(b"G1".as_slice())),
            })
        })
    }
}

#[tokio::test]
async fn distinct_replicas_and_scopes_cannot_lend_the_same_rotating_grant() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let backend = Arc::new(Backend::default());
    let a = owner(backend.clone(), 4).await;
    let b = owner(backend, 5).await;
    let epoch = install(&a).await;
    let (first, second) = tokio::join!(a.acquire_mint(&epoch), b.acquire_mint(&epoch));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let winner = first.or(second).unwrap();
    let port = Arc::new(Rotating::new(true, true));
    let task_port = port.clone();
    let mint = tokio::spawn(async move { winner.mint(task_port.as_ref(), cx(), request()).await });
    port.entered.notified().await;
    assert!(a.load(&key()).await.is_err());
    assert!(b.load(&key()).await.is_err());
    // A second selected scope/replica cannot reach even a grace-period issuer.
    assert!(b.acquire_mint(&epoch).await.is_err());
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    port.release.notify_one();
    assert!(mint.await.unwrap().is_ok());
}

#[tokio::test]
async fn remote_rotation_then_cancellation_never_reuses_the_predecessor() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let backend = Arc::new(Backend::default());
    let a = owner(backend.clone(), 4).await;
    let b = owner(backend, 5).await;
    let epoch = install(&a).await;
    let permit = a.acquire_mint(&epoch).await.unwrap();
    let port = Arc::new(Rotating::new(true, true));
    let task_port = port.clone();
    let task = tokio::spawn(async move { permit.mint(task_port.as_ref(), cx(), request()).await });
    port.entered.notified().await;
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(a.load(&key()).await.is_err());
    assert!(b.acquire_mint(&epoch).await.is_err());
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    let fresh = a
        .begin_connection(key())
        .await
        .unwrap()
        .complete(SecureVec::from(b"new-connect".as_slice()))
        .await
        .unwrap();
    assert!(fresh.epoch() > epoch.epoch());
    assert!(a
        .admit_delivery(&epoch, DeliveryIdentity::new())
        .await
        .is_err());
}

#[tokio::test]
async fn revoke_wins_while_remote_mint_is_parked_without_resurrection() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let backend = Arc::new(Backend::default());
    let a = owner(backend.clone(), 4).await;
    let b = owner(backend, 5).await;
    let epoch = install(&a).await;
    let permit = a.acquire_mint(&epoch).await.unwrap();
    let port = Arc::new(Rotating::new(true, true));
    let task_port = port.clone();
    let task = tokio::spawn(async move { permit.mint(task_port.as_ref(), cx(), request()).await });
    port.entered.notified().await;
    b.revoke(&key()).await.unwrap();
    port.release.notify_one();
    assert!(task.await.unwrap().is_err());
    assert!(a.load(&key()).await.is_err());
    assert!(a
        .admit_delivery(&epoch, DeliveryIdentity::new())
        .await
        .is_err());
}

#[tokio::test]
async fn no_update_success_still_settles_exclusion_before_credential_delivery() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let backend = Arc::new(Backend::default());
    let a = owner(backend, 4).await;
    let epoch = install(&a).await;
    let permit = a.acquire_mint(&epoch).await.unwrap();
    let answer = permit
        .mint(&Rotating::new(false, false), cx(), request())
        .await
        .unwrap();
    assert_eq!(answer.epoch.epoch(), epoch.epoch());
    assert!(answer.answer.grant_update.is_none());
    let identity = DeliveryIdentity::new();
    let delivery = a
        .admit_delivery(&answer.epoch, identity.clone())
        .await
        .unwrap();
    assert!(!delivery.matches(&DeliveryIdentity::new()));
    assert!(delivery.consume(&identity).is_ok());
}

#[tokio::test]
async fn failed_store_completion_never_returns_a_credential() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let backend = Arc::new(Backend::default());
    let a = owner(backend.clone(), 4).await;
    let epoch = install(&a).await;
    let permit = a.acquire_mint(&epoch).await.unwrap();
    let port = Arc::new(Rotating::new(true, true));
    let task_port = port.clone();
    let task = tokio::spawn(async move { permit.mint(task_port.as_ref(), cx(), request()).await });
    port.entered.notified().await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    port.release.notify_one();
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn explicit_revoke_of_absence_blocks_the_actual_pending_first_callback() {
    let backend = Arc::new(Backend::default());
    let a = owner(backend, 4).await;
    let first = a.begin_connection(key()).await.unwrap();
    a.revoke(&key()).await.unwrap();
    assert!(first
        .complete(SecureVec::from(b"late".as_slice()))
        .await
        .is_err());
    assert!(a.load(&key()).await.is_err());
}

#[tokio::test]
async fn restart_after_lost_remote_rotation_never_replays_mint_or_reuses_old_grant() {
    use crate::persistence::caller_intents::fixture::Backend as NativeBackend;
    let backend = Arc::new(NativeBackend::new());
    let first = CallerGrantOwner::new(
        backend.attach(1).await,
        &AtRestKeys::new(&[7; 32], None),
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    while !first.recover_page().await.unwrap() {}
    let epoch = install(&first).await;
    let permit = first.acquire_mint(&epoch).await.unwrap();
    let port = Arc::new(Rotating::new(true, true));
    let task_port = port.clone();
    let task = tokio::spawn(async move { permit.mint(task_port.as_ref(), cx(), request()).await });
    port.entered.notified().await;
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    drop(first);
    let restarted = CallerGrantOwner::new(
        backend.attach(2).await,
        &AtRestKeys::new(&[7; 32], None),
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    while !restarted.recover_page().await.unwrap() {}
    assert!(restarted.load(&key()).await.is_err());
    assert!(restarted.acquire_mint(&epoch).await.is_err());
    assert!(restarted
        .admit_delivery(&epoch, DeliveryIdentity::new())
        .await
        .is_err());
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    let fresh = restarted
        .begin_connection(key())
        .await
        .unwrap()
        .complete(SecureVec::from(b"fresh-CONNECT".as_slice()))
        .await
        .unwrap();
    assert!(fresh.epoch() > epoch.epoch());
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
}
