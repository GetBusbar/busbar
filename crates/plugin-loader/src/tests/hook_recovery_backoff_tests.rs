// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Recovery OPEN and administrative READY replies do not prove a hook can serve requests.

use super::super::{HookInstance, State, QUARANTINE_FIRST, QUARANTINE_MAX};
use super::*;
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{ConnTable, NoSink, Plugin};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::hook_calls::HookCalls;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn panicking_instance() -> (HookInstance, Arc<AtomicUsize>) {
    let axis = rows(hook_door_plugin::panicking::door, "hook_door", Way::Linked);
    let candidate = axis.find(PANICKING_NAME).unwrap().clone();
    let dispatcher = Arc::clone(&axis.dispatcher);
    let binds = Arc::new(AtomicUsize::new(0));
    let bind = {
        let dispatcher = Arc::clone(&dispatcher);
        let binds = Arc::clone(&binds);
        move || {
            binds.fetch_add(1, Ordering::SeqCst);
            HookRows::bind(
                &candidate,
                &dispatcher,
                "hooks.recovery-backoff",
                Arc::new(NoSink),
                ConnTable::NoNeeds,
            )
        }
    };
    let instance = HookInstance::open(
        bind().expect("the existing panicking door binds"),
        dispatcher,
        br#"{"reject_over_messages":3}"#,
        bind,
    )
    .expect("the existing panicking door opens; DECIDE is its real fault");
    (instance, binds)
}

fn window(instance: &HookInstance) -> Duration {
    match &*instance.inner.lock() {
        State::Quarantined { window, .. } => *window,
        _ => panic!("the actual serving fault must leave the hook quarantined"),
    }
}

fn make_trial_due(instance: &HookInstance) {
    let mut state = instance.inner.lock();
    let State::Quarantined { trial_at, .. } = &mut *state else {
        panic!("only a quarantined hook can become due for its next trial");
    };
    // Advance only eligibility; never replace the window whose growth the test observes.
    *trial_at = Instant::now();
}

fn fault_current(instance: &HookInstance, plugin: &Plugin<Hook>) {
    crate::dispatch::plugin::quarantine(plugin.inner.wake, "HD1 controlled serving fault");
    assert!(
        plugin.is_faulted(),
        "the real dispatch instance was revoked"
    );
    instance.inner.faulted(plugin);
    assert!(instance.quarantined());
}

#[tokio::test]
async fn repeated_first_serving_faults_keep_growing_the_recovery_window_to_its_cap() {
    let (instance, binds) = panicking_instance();
    for (attempt, expected) in [
        QUARANTINE_FIRST,
        Duration::from_secs(2),
        Duration::from_secs(4),
        Duration::from_secs(8),
        Duration::from_secs(16),
        QUARANTINE_MAX,
        QUARANTINE_MAX,
    ]
    .into_iter()
    .enumerate()
    {
        let answer = instance.decide(frame(2), BUDGET).await;
        assert!(
            matches!(&answer, Answered::Broken(why) if why.contains("FAULT")),
            "the real panicking DECIDE must fail, attempt {attempt}: {answer:?}"
        );
        assert!(instance.quarantined());
        assert_eq!(
            binds.load(Ordering::SeqCst),
            attempt + 1,
            "each due trial opens exactly one fresh instance"
        );
        assert_eq!(
            window(&instance),
            expected,
            "attempt {attempt}: an OPEN followed by another serving FAULT must not reset backoff"
        );
        if attempt != 6 {
            make_trial_due(&instance);
        }
    }
}

#[tokio::test]
async fn administrative_ready_preserves_backoff_and_a_serving_governance_rejection_resets_it() {
    let (instance, binds) = checkpoint_instance(Way::Linked, "valid");
    // Retire the fixture's first instance through its existing helper, then claim an ordinary
    // trial. The explicit prior eight-second window is setup; later windows are observed faults.
    regenerate(&instance);
    *instance.inner.lock() = State::Trialing;
    let recovered = instance
        .inner
        .trial(Duration::from_secs(8))
        .expect("the actual checkpoint door opens on the claimed trial");
    assert_eq!(binds.load(Ordering::SeqCst), 2);

    instance
        .configure("checkpoint", r#"{"reject_over_messages":1}"#, 2, BUDGET)
        .await
        .expect("the actual CONFIGURE acknowledges the stricter checkpoint");
    let status = instance
        .status(BUDGET)
        .await
        .expect("the actual STATUS is READY");
    let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
    assert!(status
        .get("held")
        .and_then(serde_json::Value::as_u64)
        .is_some());
    assert!(!instance.quarantined());
    assert_eq!(
        binds.load(Ordering::SeqCst),
        2,
        "administrative calls did not rebind"
    );
    let current = instance.inner.live(Instant::now() + BUDGET).await.unwrap();
    assert!(Arc::ptr_eq(&current, &recovered));
    fault_current(&instance, &current);
    assert_eq!(
        window(&instance),
        Duration::from_secs(16),
        "OPEN, CONFIGURE and STATUS cannot reset a recovered hook's next serving-fault window"
    );

    make_trial_due(&instance);
    let serving = instance.inner.live(Instant::now() + BUDGET).await.unwrap();
    assert_eq!(binds.load(Ordering::SeqCst), 3);
    let answer = instance.decide(frame(2), BUDGET).await;
    assert!(
        matches!(&answer, Answered::Answer { outcome: Outcome::Ready, out, .. }
            if out.reject_status == REJECT_STATUS),
        "a valid governance rejection is a healthy serving reply: {answer:?}"
    );
    assert!(!instance.quarantined());
    let current = instance.inner.live(Instant::now() + BUDGET).await.unwrap();
    assert!(Arc::ptr_eq(&current, &serving));
    fault_current(&instance, &current);
    assert_eq!(
        window(&instance),
        QUARANTINE_FIRST,
        "a real READY serving decision resets the next fault to the first window"
    );
    assert_eq!(binds.load(Ordering::SeqCst), 3);
}
