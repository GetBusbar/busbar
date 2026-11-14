// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! (b) A secret instance re-lends its own rotated credential: through the plugin's `refresh`, or,
//! for a plugin with no `refresh`, a successor opened from the BUILD'S OWN candidate. Plus the
//! PENDING open and the secret tick driver. Neutral rotating witness only (never the shared one).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::redacted::Secret as SecretValue;
use busbar_contract::secret::{RelendCause, SecretAxis, SecretCalls, SecretRelent};
use busbar_contract::secret_ref::SecretRef;

use super::SecretRows;
use crate::boot::{Candidate, Origin};
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};
use crate::neutral_rotating_secret as witness;

fn dispatcher() -> Arc<Dispatcher> {
    static ONE: std::sync::OnceLock<Arc<Dispatcher>> = std::sync::OnceLock::new();
    ONE.get_or_init(|| {
        Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ))
    })
    .clone()
}

/// A source the cell rotates by hand: every reference resolves to its current value.
#[derive(Clone)]
struct Source(Arc<Mutex<&'static str>>);

impl Source {
    fn new(value: &'static str) -> Self {
        Self(Arc::new(Mutex::new(value)))
    }

    fn rotate(&self, value: &'static str) {
        *self.0.lock().unwrap() = value;
    }

    fn resolve(&self) -> impl Fn(&SecretRef) -> Result<SecretValue<Vec<u8>>, String> + '_ {
        move |_| Ok(SecretValue::new(self.0.lock().unwrap().as_bytes().to_vec()))
    }
}

fn settings(extra: serde_json::Value) -> busbar_contract::plugin_settings::Settings {
    let mut value = serde_json::json!({
        witness::CREDENTIAL: {"module": "rotation-cell-source", "settings": {}},
    });
    if let (Some(obj), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
        obj.extend(extra.clone());
    }
    crate::dispatch::test_authored_settings(&value)
}

fn answers(calls: &dyn SecretCalls) -> String {
    let held = calls.resolve(b"{}").expect("the witness answers");
    String::from_utf8(
        held.expose(&busbar_contract::plugin::TestKernelSeal)
            .clone(),
    )
    .unwrap()
}

fn linked_rows() -> SecretRows {
    let mut rows = SecretRows::new(dispatcher, || None);
    rows.link(witness::door)
        .expect("the rotating witness links");
    rows
}

fn dropped_candidate() -> Candidate {
    let stated = rendering_of(witness::door).expect("the door renders its Statement");
    let bytes = std::fs::read(witness::cdylib()).expect("the witness's cdylib reads");
    Candidate::from_rendering(
        stated,
        None,
        Origin::Dropped {
            file: format!("{}.tar.gz", witness::NAME),
            bytes: Arc::new(bytes),
        },
    )
    .expect("the rendering reads back")
}

// T-B1
#[test]
fn a_rotated_source_credential_is_taken_by_the_plugins_refresh() {
    let rows = linked_rows();
    let source = Source::new("token-1");
    let opened = rows
        .open(
            witness::NAME,
            Some(&settings(serde_json::json!({}))),
            &source.resolve(),
        )
        .expect("it opens over its lent credential");
    assert!(
        opened.relends(),
        "an instance that lends a reference is polled"
    );
    assert_eq!(answers(&*opened), witness::answer_for(b"token-1"));

    assert!(matches!(
        opened.relend(&source.resolve()),
        Ok(SecretRelent::Unchanged)
    ));
    source.rotate("token-2");
    assert!(matches!(
        opened.relend(&source.resolve()),
        Ok(SecretRelent::Refreshed)
    ));
    assert_eq!(
        answers(&*opened),
        witness::answer_for(b"token-2"),
        "the same instance answers with the rotated credential"
    );
    assert!(
        matches!(
            opened.relend(&source.resolve()),
            Ok(SecretRelent::Unchanged)
        ),
        "and an unchanged credential is never handed over again"
    );
}

// T-B2
#[test]
fn a_refused_rotation_keeps_the_running_instance() {
    let rows = linked_rows();
    let source = Source::new("token-1");
    let opened = rows
        .open(
            witness::NAME,
            Some(&settings(serde_json::json!({"refresh": "refuse"}))),
            &source.resolve(),
        )
        .expect("it opens");
    source.rotate("token-2");
    let refused = match opened.relend(&source.resolve()) {
        Err(refused) => refused,
        Ok(_) => panic!("the witness refuses rotations"),
    };
    assert_eq!(refused.cause, RelendCause::Refused);
    assert_eq!(answers(&*opened), witness::answer_for(b"token-1"), "kept");
    let unresolvable = opened
        .relend(&|_| Err("the source is down".to_string()))
        .expect_err("a reference that does not resolve refuses");
    assert_eq!(unresolvable.cause, RelendCause::Unresolvable);
    assert!(
        !unresolvable.text.contains("token"),
        "{}",
        unresolvable.text
    );
}

// T-B5/T-B6 (B3): a plugin with no refresh is re-opened from the build's own candidate, even after
// the global dropped set moved on; the old instance keeps answering its in-flight callers.
#[test]
fn a_plugin_without_refresh_is_reopened_from_the_builds_own_candidate() {
    let rows = SecretRows::new(dispatcher, || None);
    rows.set_dropped([dropped_candidate()]);
    let source = Source::new("token-1");
    let first = rows
        .open(
            witness::NAME,
            Some(&settings(serde_json::json!({"refresh": "none"}))),
            &source.resolve(),
        )
        .expect("the dropped witness opens");
    source.rotate("token-2");
    let Ok(SecretRelent::Reopened(second)) = first.relend(&source.resolve()) else {
        panic!("a plugin with no refresh is re-opened");
    };
    assert_eq!(answers(&*second), witness::answer_for(b"token-2"));
    assert_eq!(
        answers(&*first),
        witness::answer_for(b"token-1"),
        "the old instance still answers whoever holds it"
    );

    rows.set_dropped(Vec::<Candidate>::new());
    assert!(!rows.answers(witness::NAME), "the global set moved on");
    source.rotate("token-3");
    let Ok(SecretRelent::Reopened(third)) = second.relend(&source.resolve()) else {
        panic!("the build's own artifact still re-opens: nothing strands it");
    };
    assert_eq!(answers(&*third), witness::answer_for(b"token-3"));

    source.rotate("refuse");
    let refused = third
        .relend(&source.resolve())
        .expect_err("a successor that does not open refuses");
    assert_eq!(refused.cause, RelendCause::ReopenFailed);
    assert_eq!(
        answers(&*third),
        witness::answer_for(b"token-3"),
        "and the running one is kept"
    );
}

// T-C1 (R7): a PENDING open is resumed until READY.
#[test]
fn a_pending_open_is_resumed_until_it_is_ready() {
    let rows = linked_rows();
    let source = Source::new("token-1");
    let opened = rows
        .open(
            witness::NAME,
            Some(&settings(serde_json::json!({"open": "pending"}))),
            &source.resolve(),
        )
        .expect("a two-step open completes");
    assert_eq!(answers(&*opened), witness::answer_for(b"token-1"));
}

// (c) R8: a secret instance's tick is driven.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_instance_is_ticked_on_its_schedule() {
    let rows = linked_rows();
    let source = Source::new("token-1");
    let before = witness::TICKED.load(Ordering::SeqCst);
    let opened = rows
        .open(
            witness::NAME,
            Some(&settings(serde_json::json!({}))),
            &source.resolve(),
        )
        .expect("it opens");
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while witness::TICKED.load(Ordering::SeqCst) < before + 3 && std::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        witness::TICKED.load(Ordering::SeqCst) >= before + 3,
        "the secret instance asked to be ticked every 5 ms and was"
    );
    drop(opened);
}
