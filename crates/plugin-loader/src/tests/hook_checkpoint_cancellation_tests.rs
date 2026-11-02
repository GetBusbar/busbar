// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::hook_calls::HookCalls;
use std::task::{Context, Wake, Waker};

struct ReplyReady(std::sync::mpsc::Sender<()>);
impl Wake for ReplyReady {
    fn wake(self: Arc<Self>) {
        let _ = self.0.send(());
    }
}

async fn signal(receiver: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(BUDGET).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_configure_result_lost_before_or_after_ready_cannot_restore_an_older_checkpoint() {
    for queued_ready in [false, true] {
        let (instance, _) = checkpoint_instance(Way::Linked, "block_drop");
        instance
            .configure("checkpoint", r#"{"reject_over_messages":2}"#, 2, BUDGET)
            .await
            .unwrap();
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (committed, committed_rx) = std::sync::mpsc::channel();
        *checkpoint_plugin::DROP_CONFIGURE.lock().unwrap() = Some((entered, released, committed));
        let (ready, ready_rx) = std::sync::mpsc::channel();
        let waker = Waker::from(Arc::new(ReplyReady(ready)));
        let mut configure =
            instance.configure("checkpoint", r#"{"reject_over_messages":1}"#, 3, BUDGET);
        assert!(configure
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        signal(entered_rx).await;
        if queued_ready {
            release.send(()).unwrap();
            signal(ready_rx).await;
            drop(configure);
        } else {
            drop(configure);
            release.send(()).unwrap();
        }
        signal(committed_rx).await;
        let live = instance.decide(frame(2), BUDGET).await;
        assert!(
            matches!(live, Answered::Answer {out, ..} if out.reject_status == REJECT_STATUS),
            "the abandoned configure actually committed"
        );
        regenerate(&instance);
        assert!(
            matches!(instance.decide(frame(2), BUDGET).await, Answered::Broken(_)),
            "queued_ready={queued_ready}: an unknown configure result reopened stale state"
        );
    }
}

#[tokio::test]
async fn dropping_an_unpolled_configure_keeps_the_known_checkpoint_recoverable() {
    let (instance, _) = checkpoint_instance(Way::Linked, "valid");
    instance
        .configure("checkpoint", r#"{"reject_over_messages":1}"#, 2, BUDGET)
        .await
        .unwrap();
    drop(instance.configure("checkpoint", r#"{"reject_over_messages":8}"#, 3, BUDGET));
    regenerate(&instance);
    let answer = instance.decide(frame(2), BUDGET).await;
    assert!(matches!(answer, Answered::Answer {out, ..} if out.reject_status == REJECT_STATUS));
}

#[tokio::test]
async fn a_detached_trial_panic_releases_the_trial_claim() {
    use crate::dispatch::{ConnTable, NoSink};
    let axis = rows(checkpoint_plugin::door, "hook_checkpoint_door", Way::Linked);
    let candidate = axis.find(checkpoint_plugin::NAME).unwrap().clone();
    let dispatcher = Arc::clone(&axis.dispatcher);
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let panic_gate = Arc::new(std::sync::Mutex::new(Some((entered, released))));
    let binds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bind = {
        let dispatcher = Arc::clone(&dispatcher);
        move || {
            if binds.fetch_add(1, std::sync::atomic::Ordering::SeqCst) != 0 {
                let gate = panic_gate.lock().unwrap().take();
                if let Some((entered, released)) = gate {
                    entered.send(()).unwrap();
                    released.recv_timeout(BUDGET).unwrap();
                    panic!("scripted rebind panic after the waiting caller was dropped");
                }
            }
            HookRows::bind(
                &candidate,
                &dispatcher,
                "hooks.checkpoint-panic",
                Arc::new(NoSink),
                ConnTable::NoNeeds,
            )
        }
    };
    let instance = super::super::HookInstance::open(
        bind().unwrap(),
        dispatcher,
        br#"{"reject_over_messages":3}"#,
        bind,
    )
    .unwrap();
    regenerate(&instance);
    let (ready, _) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(ReplyReady(ready)));
    let mut trial = instance.decide(frame(2), BUDGET);
    assert!(trial
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    signal(entered_rx).await;
    drop(trial);
    release.send(()).unwrap();
    tokio::time::timeout(BUDGET, async {
        loop {
            if !matches!(*instance.inner.lock(), super::super::State::Trialing) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached trial panic left the recovery claim held forever");
    regenerate(&instance);
    assert!(matches!(
        instance.decide(frame(2), BUDGET).await,
        Answered::Answer { .. }
    ));
}

#[tokio::test]
async fn a_configure_refused_at_the_full_cap_until_timeout_keeps_recovery_available() {
    let (instance, _) = checkpoint_instance(Way::Linked, "cap_timeout");
    instance
        .configure("checkpoint", r#"{"reject_over_messages":1}"#, 2, BUDGET)
        .await
        .unwrap();
    let plugin = match &*instance.inner.lock() {
        super::super::State::Live(plugin) => Arc::clone(plugin),
        _ => panic!("opened"),
    };
    let (wake, _) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(ReplyReady(wake)));
    let mut pending = Vec::new();
    for _ in 0..plugin.max_inflight() {
        let mut notify = instance.notify(
            busbar_contract::abi::host::hook::NotifyFrame::build(&request(1), None, false),
            BUDGET,
        );
        assert!(notify
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        pending.push(notify);
    }
    assert_eq!(
        plugin.inflight(),
        plugin.max_inflight(),
        "the admission cap is actually full"
    );
    assert!(instance
        .configure(
            "checkpoint",
            r#"{"reject_over_messages":8}"#,
            3,
            Duration::from_millis(20)
        )
        .await
        .is_err());
    drop(pending);
    regenerate(&instance);
    let answer = instance.decide(frame(2), BUDGET).await;
    assert!(
        matches!(answer, Answered::Answer {out, ..} if out.reject_status == REJECT_STATUS),
        "a configure that never crossed poisoned the saved checkpoint"
    );
}
