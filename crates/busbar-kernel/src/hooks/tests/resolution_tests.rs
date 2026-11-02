// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::hook::{DecideOut, TransformOut};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, Pending, Probed};
use busbar_contract::redacted::Secret;
use busbar_contract::secret::SecretResolve;
use busbar_contract::secret_ref::SecretRef;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const HOOK_NAME: &str = "rotating-hook";
const SOURCE_NAME: &str = "rotating-source";
const ORIGINAL_VALUE: &str = "fixture-original-credential";
const ROTATED_VALUE: &str = "fixture-rotated-credential";
const SOURCE_UNAVAILABLE: &str = "fixture secret source unavailable";
const SECRET_PATH: &str = "servers.*.env.*";
const REFERENCE_PATH: &str = "servers.*.url";

struct RotatingSource {
    value: Mutex<Option<&'static str>>,
    reads: AtomicUsize,
}

impl SecretResolve for RotatingSource {
    fn resolve(&self, _: &SecretRef) -> Result<Secret<Vec<u8>>, String> {
        self.read()
            .map(|value| Secret::new(value.as_bytes().to_vec()))
    }

    fn resolve_string(&self, _: &SecretRef) -> Result<Secret<String>, String> {
        self.read().map(|value| Secret::new(value.to_string()))
    }
}

impl RotatingSource {
    fn read(&self) -> Result<&'static str, String> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.value
            .lock()
            .unwrap()
            .ok_or_else(|| SOURCE_UNAVAILABLE.into())
    }
}

#[derive(Default)]
struct Received {
    opened: Mutex<Vec<Value>>,
    configured: Mutex<Vec<(u64, Value)>>,
}

struct RecordingAxis {
    inner: Arc<dyn HookAxis>,
    received: Arc<Received>,
}

impl HookAxis for RecordingAxis {
    fn probe(&self, module: &str, name: &str, settings: &Value) -> Option<Probed> {
        self.inner.probe(module, name, settings)
    }

    fn open(
        &self,
        module: &str,
        name: &str,
        settings: &Value,
        budget: Duration,
    ) -> Result<Arc<dyn HookCalls>, String> {
        let inner = self.inner.open(module, name, settings, budget)?;
        self.received.opened.lock().unwrap().push(settings.clone());
        Ok(Arc::new(RecordingCalls {
            inner,
            received: self.received.clone(),
        }))
    }

    fn linked(&self, module: &str) -> bool {
        self.inner.linked(module)
    }
    fn call_budget(&self) -> Duration {
        self.inner.call_budget()
    }
    fn first_party(&self, module: &str) -> bool {
        self.inner.first_party(module)
    }
}

struct RecordingCalls {
    inner: Arc<dyn HookCalls>,
    received: Arc<Received>,
}

impl HookCalls for RecordingCalls {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn decide(&self, frame: Arc<DecideFrame>, budget: Duration) -> Pending<Answered<DecideOut>> {
        self.inner.decide(frame, budget)
    }

    fn transform(
        &self,
        frame: Arc<DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<TransformOut>> {
        self.inner.transform(frame, budget)
    }

    fn notify(&self, frame: Arc<NotifyFrame>, budget: Duration) -> Pending<()> {
        self.inner.notify(frame, budget)
    }

    fn configure(
        &self,
        name: &str,
        settings: &str,
        version: u64,
        budget: Duration,
    ) -> Pending<Result<(), String>> {
        let value = serde_json::from_str(settings).expect("configure receives valid settings JSON");
        self.received
            .configured
            .lock()
            .unwrap()
            .push((version, value));
        self.inner.configure(name, settings, version, budget)
    }

    fn status(&self, budget: Duration) -> Pending<Option<Vec<u8>>> {
        self.inner.status(budget)
    }
    fn describe(&self, budget: Duration) -> Pending<Option<Vec<u8>>> {
        self.inner.describe(budget)
    }
}

fn environment(
    secret: &[&str],
    reference: &[&str],
) -> (HookEnv, Arc<RotatingSource>, Arc<Received>) {
    let hook = base_gate();
    let row = || {
        crate::test_support::rows::row(
            HOOK_NAME,
            &hook.plugin,
            busbar_contract::abi::mechanism::kind::HOOK,
        )
    };

    assert!(secret.is_empty() || reference.is_empty());
    let rows = if reference.is_empty() {
        crate::test_support::rows::linked_only().with_dropped_secret_slots(row(), secret)
    } else {
        crate::test_support::rows::linked_only().with_dropped_reference_slots(row(), reference)
    };
    let source = Arc::new(RotatingSource {
        value: Mutex::new(Some(ORIGINAL_VALUE)),
        reads: AtomicUsize::new(0),
    });
    let received = Arc::new(Received::default());
    let axis = RecordingAxis {
        inner: crate::test_support::hook_double::HookAxisDouble::new(&[&hook.plugin]),
        received: received.clone(),
    };
    (
        HookEnv::with_axis(rows.into_rows(), Arc::new(axis), source.clone()),
        source,
        received,
    )
}

fn source_reference() -> Value {
    serde_json::to_value(SecretRef {
        module: SOURCE_NAME.into(),
        settings: Default::default(),
    })
    .expect("a source reference serializes")
}

fn settings(value: Value) -> HookCfg {
    let mut hook = base_gate();
    hook.settings = value
        .as_object()
        .expect("fixture settings are an object")
        .clone();
    hook
}

#[tokio::test]
async fn nested_references_refresh_on_every_configure_push() {
    let reference = source_reference();
    for (declared_secret, declared_reference, value, pointer) in [
        (
            vec![SECRET_PATH],
            vec![],
            json!({"servers": [{"env": {"TOKEN": reference}}]}),
            "/servers/0/env/TOKEN",
        ),
        (
            vec![SECRET_PATH],
            vec![],
            json!({"servers": {"worker": {"env": [reference]}}}),
            "/servers/worker/env/0",
        ),
        (
            vec!["servers.0.env.TOKEN"],
            vec![],
            json!({"servers": [{"env": {"TOKEN": reference}}]}),
            "/servers/0/env/TOKEN",
        ),
        (
            vec![],
            vec![REFERENCE_PATH],
            json!({"servers": [{"url": reference}]}),
            "/servers/0/url",
        ),
        (
            vec!["payload.token"],
            vec![],
            json!({"payload": {"literal": "label", "token": reference}}),
            "/payload/token",
        ),
        (
            vec!["payload.literal.token"],
            vec![],
            json!({"payload": {"literal": {"token": reference}}}),
            "/payload/token",
        ),
        (
            vec![],
            vec!["payload.literal.token"],
            json!({"payload": {"literal": {"token": reference}}}),
            "/payload/token",
        ),
    ] {
        let (env, source, received) = environment(&declared_secret, &declared_reference);
        let hook = settings(value);
        let initial_version = 1;
        let rotated_version = initial_version + 1;
        assert!(crate::hooks::resolution::key(HOOK_NAME, &hook, &env).is_none());
        assert!(
            source.reads.load(Ordering::SeqCst) == 0,
            "cache admission must not read the source"
        );
        assert!(push_configure(&hook, HOOK_NAME, initial_version, &env)
            .await
            .is_ok());
        *source.value.lock().unwrap() = Some(ROTATED_VALUE);
        assert!(push_configure(&hook, HOOK_NAME, rotated_version, &env)
            .await
            .is_ok());
        {
            let opened = received.opened.lock().unwrap();
            let configured = received.configured.lock().unwrap();

            assert!(opened.len() == 2, "rotation must open a fresh transport");
            assert!(opened[0].pointer(pointer) == Some(&json!(ORIGINAL_VALUE)));
            assert!(opened[1].pointer(pointer) == Some(&json!(ROTATED_VALUE)));
            assert!(configured.len() == 2);
            assert!(configured[0].0 == initial_version && configured[0].1 == opened[0]);
            assert!(configured[1].0 == rotated_version && configured[1].1 == opened[1]);
        }
        *source.value.lock().unwrap() = None;
        let refused = push_configure(&hook, HOOK_NAME, rotated_version, &env)
            .await
            .expect_err("a missing source must refuse the push instead of reusing old settings");
        assert!(!refused.contains(ORIGINAL_VALUE) && !refused.contains(ROTATED_VALUE));
        assert!(received.opened.lock().unwrap().len() == 2);
        assert!(received.configured.lock().unwrap().len() == 2);
        *source.value.lock().unwrap() = Some(ORIGINAL_VALUE);
        assert!(push_configure(&hook, HOOK_NAME, rotated_version, &env)
            .await
            .is_ok());
        assert!(received.opened.lock().unwrap().len() == 3);
        assert!(source.reads.load(Ordering::SeqCst) == 4);
    }
}

#[tokio::test]
async fn opaque_and_literal_settings_still_reuse_the_opened_transport() {
    let reference = source_reference();
    for (value, expected) in [
        (
            json!({"servers": [{"env": {"TOKEN": "ordinary plugin data"}}]}),
            json!({"servers": [{"env": {"TOKEN": "ordinary plugin data"}}]}),
        ),
        (
            json!({"payload": {"literal": [reference]}}),
            json!({"payload": [reference]}),
        ),
        (
            json!({"servers": [{"env": {"TOKEN": {"literal": reference}}}]}),
            json!({"servers": [{"env": {"TOKEN": {"literal": reference}}}]}),
        ),
        (
            json!({"payload": {"literal": "label", "other": ["ordinary plugin data"]}}),
            json!({"payload": {"literal": "label", "other": ["ordinary plugin data"]}}),
        ),
    ] {
        let (env, source, received) = environment(&[], &[]);
        let hook = settings(value);
        let (first, _) = gate_transport_named(HOOK_NAME, &hook, &env, 0).expect("first open");
        let (second, _) = gate_transport_named(HOOK_NAME, &hook, &env, 0).expect("cached open");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(push_configure(&hook, HOOK_NAME, 1, &env).await.is_ok());
        assert!(push_configure(&hook, HOOK_NAME, 2, &env).await.is_ok());
        assert!(received.opened.lock().unwrap().len() == 1);
        assert!(received.configured.lock().unwrap().len() == 2);
        assert!(received.opened.lock().unwrap()[0] == expected);
        assert!(received
            .configured
            .lock()
            .unwrap()
            .iter()
            .all(|(_, value)| value == &expected));
        assert!(source.reads.load(Ordering::SeqCst) == 0);
    }
}

#[test]
fn nested_reference_resolution_diagnostics_do_not_contain_credentials() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = WarnCapture::capturing_debug();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let (env, source, _) = environment(&[SECRET_PATH], &[]);
    let hook = settings(json!({"servers": [{"env": {"TOKEN": source_reference()}}]}));
    tracing::subscriber::with_default(subscriber, || {
        assert!(gate_transport_named(HOOK_NAME, &hook, &env, 0).is_some());
        *source.value.lock().unwrap() = Some(ROTATED_VALUE);
        assert!(gate_transport_named(HOOK_NAME, &hook, &env, 0).is_some());
        *source.value.lock().unwrap() = None;
        assert!(gate_transport_named(HOOK_NAME, &hook, &env, 0).is_none());
    });
    assert!(capture.contains("servers.0.env.TOKEN"));
    assert!(capture.contains(SOURCE_UNAVAILABLE));
    assert!(!capture.contains(ORIGINAL_VALUE) && !capture.contains(ROTATED_VALUE));
}

#[tokio::test]
async fn replacing_the_public_registry_cannot_reuse_a_stale_path_snapshot() {
    let (mut env, source, received) = environment(&[], &[]);
    let (replacement, _, _) = environment(&["payload.literal.token"], &[]);
    env.registry = replacement.registry;
    let hook = settings(json!({"payload": {"literal": {"token": source_reference()}}}));
    assert!(push_configure(&hook, HOOK_NAME, 1, &env).await.is_ok());
    *source.value.lock().unwrap() = Some(ROTATED_VALUE);
    assert!(push_configure(&hook, HOOK_NAME, 2, &env).await.is_ok());
    let opened = received.opened.lock().unwrap();
    assert!(opened.len() == 2);
    assert!(opened[0]["payload"]["token"] == ORIGINAL_VALUE);
    assert!(opened[1]["payload"]["token"] == ROTATED_VALUE);
    assert!(received.configured.lock().unwrap().len() == 2);
    assert!(source.reads.load(Ordering::SeqCst) == 2);
}
