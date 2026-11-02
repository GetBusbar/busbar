// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Condvar, Mutex,
};
use std::time::Duration;

pub(super) struct PausedStore {
    op: &'static str,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    released: Mutex<bool>,
    changed: Condvar,
    busy: AtomicBool,
}

impl PausedStore {
    pub(super) fn wait(&self, op: &str) {
        if op != self.op {
            return;
        }
        self.busy.store(true, Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        let (guard, timed) = self
            .changed
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap();
        drop(guard);
        self.busy.store(false, Ordering::SeqCst);
        assert!(
            !timed.timed_out(),
            "the scheduler must release the Store while it is pending"
        );
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
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

fn paused(
    op: &'static str,
) -> (
    Arc<GovState>,
    String,
    String,
    Release,
    tokio::sync::oneshot::Receiver<()>,
) {
    paused_at(op, NOW)
}

impl GovState {
    pub(crate) fn paused_ticket_for_test(
        op: &'static str,
        now: u64,
    ) -> (
        Arc<Self>,
        String,
        String,
        Release,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        paused_at(op, now)
    }
}

fn paused_at(
    op: &'static str,
    now: u64,
) -> (
    Arc<GovState>,
    String,
    String,
    Release,
    tokio::sync::oneshot::Receiver<()>,
) {
    let memory = Arc::new(MemoryStore::new());
    memory.pin_token_clock(now);
    let (entered, heard) = tokio::sync::oneshot::channel();
    let pause = Arc::new(PausedStore {
        op,
        entered: Mutex::new(Some(entered)),
        released: Mutex::new(false),
        changed: Condvar::new(),
        busy: AtomicBool::new(false),
    });
    let signer = TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(
            Arc::new(RuleCarryingOnly(memory, Some(Arc::clone(&pause)))),
            None,
            Some(signer),
        )
        .unwrap(),
    );
    let (binding, _) = gov
        .mint_signed(
            NewKeySpec {
                name: "caller".into(),
                ..Default::default()
            },
            now + 86_400,
            now,
        )
        .unwrap();
    let id = binding.id;
    let (ticket, _) = gov
        .mint_ticket(&id, PREFIX, 600, None, b"record", now)
        .unwrap();
    (gov, id, ticket, Release(pause), heard)
}

#[tokio::test(flavor = "current_thread")]
async fn ticket_store_waits_leave_the_scheduler_live_and_admission_is_one_shot() {
    for op in ["live", "get"] {
        let (gov, id, ticket, release, entered) = paused(op);
        let running = tokio::spawn({
            let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
            async move {
                if op == "live" {
                    gov.peek_ticket_async(PREFIX, &ticket, NOW + 1)
                        .await
                        .map(|key| (key.id.clone(), Vec::new()))
                } else {
                    gov.admit_ticket_async(PREFIX, &ticket, NOW + 1)
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
            assert!(gov
                .admit_ticket_async(PREFIX, &ticket, NOW + 1)
                .await
                .is_some());
        }
        assert!(gov
            .admit_ticket_async(PREFIX, &ticket, NOW + 1)
            .await
            .is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn revocation_while_ticket_store_waits_is_checked_before_accepting_identity() {
    for op in ["live", "get"] {
        let (gov, id, ticket, release, entered) = paused(op);
        let running = tokio::spawn({
            let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
            async move {
                if op == "live" {
                    gov.peek_ticket_async(PREFIX, &ticket, NOW + 1)
                        .await
                        .is_some()
                } else {
                    gov.admit_ticket_async(PREFIX, &ticket, NOW + 1)
                        .await
                        .is_some()
                }
            }
        });
        entered.await.unwrap();
        gov.revoke(&id, "revoked while the Store answered").unwrap();
        release.0.release();
        assert!(!running.await.unwrap());
        assert!(gov.admit_ticket(PREFIX, &ticket, NOW + 1).is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_a_started_ticket_store_wait_does_not_reopen_redemption() {
    for op in ["live", "get"] {
        let (gov, _, ticket, release, entered) = paused(op);
        let running = tokio::spawn({
            let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
            async move {
                if op == "live" {
                    gov.peek_ticket_async(PREFIX, &ticket, NOW + 1)
                        .await
                        .is_some()
                } else {
                    gov.admit_ticket_async(PREFIX, &ticket, NOW + 1)
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
        assert_eq!(
            gov.admit_ticket_async(PREFIX, &ticket, NOW + 1)
                .await
                .is_some(),
            op == "live"
        );
        assert!(gov
            .admit_ticket_async(PREFIX, &ticket, NOW + 1)
            .await
            .is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_expired_ticket_peek_wait_cannot_accept_the_late_store_answer() {
    let (gov, _, ticket, release, entered) = paused("live");
    let running = tokio::spawn({
        let (gov, ticket) = (Arc::clone(&gov), ticket.clone());
        async move {
            tokio::time::timeout(
                Duration::from_millis(1),
                gov.peek_ticket_async(PREFIX, &ticket, NOW + 1),
            )
            .await
        }
    });
    entered.await.unwrap();
    assert!(running.await.unwrap().is_err());
    assert!(release.0.busy.load(Ordering::SeqCst));
    release.0.release();
    assert!(gov
        .admit_ticket_async(PREFIX, &ticket, NOW + 1)
        .await
        .is_some());
}
