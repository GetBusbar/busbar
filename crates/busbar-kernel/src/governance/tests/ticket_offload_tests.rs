// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

pub(super) struct PausedStore {
    op: &'static str,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    active: AtomicBool,
    released: AtomicBool,
    changed: tokio::sync::Notify,
    busy: AtomicBool,
    pub(super) attempts: Mutex<Vec<[u8; 32]>>,
}
impl PausedStore {
    pub(super) async fn wait(&self, op: &str) {
        if op != self.op || !self.active.load(Ordering::SeqCst) {
            return;
        }
        self.busy.store(true, Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        while !self.released.load(Ordering::SeqCst) {
            self.changed.notified().await;
        }
        self.busy.store(false, Ordering::SeqCst);
    }
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.changed.notify_one();
    }
}
pub(crate) struct Release(Arc<PausedStore>);
impl Release {
    pub(crate) fn release(&self) {
        self.0.release();
    }
    pub(crate) fn is_busy(&self) -> bool {
        self.0.busy.load(Ordering::SeqCst)
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn paused(
    op: &'static str,
) -> (
    Arc<GovState>,
    String,
    String,
    Release,
    tokio::sync::oneshot::Receiver<()>,
) {
    paused_at(op, crate::store::now()).await
}

impl GovState {
    pub(crate) async fn paused_ticket_for_test(
        op: &'static str,
        now: u64,
    ) -> (
        Arc<Self>,
        String,
        String,
        Release,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        paused_at(op, now).await
    }
}

async fn paused_at(
    op: &'static str,
    now: u64,
) -> (
    Arc<GovState>,
    String,
    String,
    Release,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (entered, heard) = tokio::sync::oneshot::channel();
    let pause = Arc::new(PausedStore {
        op,
        entered: Mutex::new(Some(entered)),
        active: AtomicBool::new(false),
        released: AtomicBool::new(false),
        changed: tokio::sync::Notify::new(),
        busy: AtomicBool::new(false),
        attempts: Mutex::new(Vec::new()),
    });
    let backend = Arc::new(TicketBackend {
        inner: crate::real_store::native_backend().await,
        pause: Some(pause.clone()),
        fault: None,
        published: AtomicBool::new(false),
    });
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_core(
            crate::real_store::core_over(backend).await,
            None,
            Some(signer),
        )
        .await
        .unwrap(),
    );
    let (binding, _) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "caller".into(),
                ..Default::default()
            },
            now + 86_400,
            now,
        )
        .await
        .unwrap();
    let id = binding.id;
    let (ticket, _) = gov
        .mint_ticket(&id, PREFIX, 600, None, b"record", now)
        .await
        .unwrap();
    pause.active.store(true, Ordering::SeqCst);
    (gov, id, ticket, Release(pause), heard)
}

#[tokio::test(flavor = "current_thread")]
async fn ticket_store_waits_leave_the_scheduler_live_and_admission_is_one_shot() {
    for op in ["live", "get"] {
        let (gov, id, ticket, release, entered) = paused(op).await;
        let running = tokio::spawn({
            let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
            async move {
                if op == "live" {
                    gov.peek_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                        .await
                        .map(|key| (key.id.clone(), Vec::new()))
                } else {
                    gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                        .await
                        .map(|(key, record)| (key.id.clone(), record))
                }
            }
        });
        entered.await.unwrap();
        assert!(
            release.0.busy.load(Ordering::SeqCst),
            "the Store is still blocked while this reactor runs"
        );
        tokio::spawn(async {}).await.unwrap();
        release.0.release();
        let (got, record) = running.await.unwrap().unwrap();
        assert_eq!(got, id);
        assert_eq!(
            record,
            if op == "get" {
                b"record".to_vec()
            } else {
                Vec::new()
            }
        );
        if op == "live" {
            assert!(
                gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                    .await
                    .is_some()
            );
        }
        assert!(
            gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                .await
                .is_none()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn revocation_while_ticket_store_waits_is_checked_before_accepting_identity() {
    for op in ["live", "get"] {
        let (gov, id, ticket, release, entered) = paused(op).await;
        let running = tokio::spawn({
            let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
            async move {
                if op == "live" {
                    gov.peek_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                        .await
                        .is_some()
                } else {
                    gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                        .await
                        .is_some()
                }
            }
        });
        entered.await.unwrap();
        gov.revoke_async(&id, "revoked while the Store answered")
            .await
            .unwrap();
        release.0.release();
        assert!(!running.await.unwrap());
        assert!(
            gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                .await
                .is_none()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_a_started_ticket_store_wait_does_not_reopen_redemption() {
    for op in ["live", "get"] {
        let (gov, _, ticket, release, entered) = paused(op).await;
        let running = tokio::spawn({
            let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
            async move {
                if op == "live" {
                    gov.peek_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                        .await
                        .is_some()
                } else {
                    gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                        .await
                        .is_some()
                }
            }
        });
        entered.await.unwrap();
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());
        assert!(release.0.busy.load(Ordering::SeqCst));
        release.0.release();
        assert!(
            gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                .await
                .is_some(),
            "a cancelled waiter retains its original spend; one eligible retry delivers once"
        );
        if op == "get" {
            let attempts = release.0.attempts.lock().unwrap();
            assert!(
                attempts.len() >= 2,
                "the retained spend reached exact receipt replay"
            );
            assert!(
                attempts.iter().all(|attempt| attempt == &attempts[0]),
                "retry preserves the same native candidate fingerprint"
            );
        }
        assert!(
            gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
                .await
                .is_none()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_expired_ticket_peek_wait_cannot_accept_the_late_store_answer() {
    let (gov, _, ticket, release, entered) = paused("live").await;
    let running = tokio::spawn({
        let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
        async move {
            tokio::time::timeout(
                Duration::from_millis(1),
                gov.peek_ticket_async(PREFIX, &ticket, crate::store::now() + 1),
            )
            .await
        }
    });
    entered.await.unwrap();
    assert!(running.await.unwrap().is_err());
    assert!(release.0.busy.load(Ordering::SeqCst));
    release.0.release();
    assert!(
        gov.admit_ticket_async(PREFIX, &ticket, crate::store::now() + 1)
            .await
            .is_some()
    );
}
