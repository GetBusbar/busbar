// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::redacted::Secret;
use busbar_contract::secret::SecretResolve;
use busbar_contract::secret_ref::SecretRef;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

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
        let source = RotatingSource {
            value: Mutex::new(Some(ORIGINAL_VALUE)),
            reads: AtomicUsize::new(0),
        };
        let declared_secret: Vec<String> = declared_secret.into_iter().map(str::to_owned).collect();
        let declared_reference: Vec<String> =
            declared_reference.into_iter().map(str::to_owned).collect();
        let paths = [declared_secret.clone(), declared_reference.clone()].concat();
        let hook = settings(value);
        assert!(resolution::key_for_settings(1, HOOK_NAME, &hook, &paths).is_none());
        assert!(
            source.reads.load(Ordering::SeqCst) == 0,
            "cache admission must not read the source"
        );
        let resolve = || {
            crate::config::secret::resolve_settings(
                &hook.settings,
                &declared_secret,
                &declared_reference,
                &hook.plugin,
                &source,
                &busbar_contract::config_time::ConfigScope::config_time(),
            )
        };
        let mut opened = Vec::new();
        let mut configured = Vec::new();
        for (version, credential) in [(1, ORIGINAL_VALUE), (2, ROTATED_VALUE)] {
            *source.value.lock().unwrap() = Some(credential);
            let loaded = open_resolved(HOOK_NAME, &hook, resolve(), |resolved| {
                opened.push(resolved.as_value().clone());
                Ok(())
            });
            assert!(configure_resolved(loaded, |(), resolved| {
                configured.push((version, resolved.as_value().clone()));
                std::future::ready(Ok(()))
            })
            .await
            .is_ok());
        }
        assert!(opened.len() == 2, "rotation must open a fresh transport");
        assert!(opened[0].pointer(pointer) == Some(&json!(ORIGINAL_VALUE)));
        assert!(opened[1].pointer(pointer) == Some(&json!(ROTATED_VALUE)));
        assert!(configured.len() == 2);
        assert!(configured[0].0 == 1 && configured[0].1 == opened[0]);
        assert!(configured[1].0 == 2 && configured[1].1 == opened[1]);
        *source.value.lock().unwrap() = None;
        let loaded = open_resolved(HOOK_NAME, &hook, resolve(), |resolved| {
            opened.push(resolved.as_value().clone());
            Ok(())
        });
        let refused = configure_resolved(loaded, |(), resolved| {
            configured.push((2, resolved.as_value().clone()));
            std::future::ready(Ok(()))
        })
        .await
        .expect_err("a missing source must refuse the push instead of reusing old settings");
        assert!(!refused.contains(ORIGINAL_VALUE) && !refused.contains(ROTATED_VALUE));
        assert!(opened.len() == 2);
        assert!(configured.len() == 2);
        *source.value.lock().unwrap() = Some(ORIGINAL_VALUE);
        let loaded = open_resolved(HOOK_NAME, &hook, resolve(), |resolved| {
            opened.push(resolved.as_value().clone());
            Ok(())
        });
        assert!(configure_resolved(loaded, |(), resolved| {
            configured.push((2, resolved.as_value().clone()));
            std::future::ready(Ok(()))
        })
        .await
        .is_ok());
        assert!(opened.len() == 3);
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
        let source = RotatingSource {
            value: Mutex::new(Some(ORIGINAL_VALUE)),
            reads: AtomicUsize::new(0),
        };
        let hook = settings(value);
        let first =
            resolution::key_for_settings(1, HOOK_NAME, &hook, &[]).expect("cacheable settings");
        let second = resolution::key_for_settings(1, HOOK_NAME, &hook, &[])
            .expect("same cacheable settings");
        assert_eq!(
            first, second,
            "opaque/literal settings retain the same actual cache identity"
        );
        let loaded = open_resolved(
            HOOK_NAME,
            &hook,
            crate::config::secret::resolve_settings(
                &hook.settings,
                &[],
                &[],
                &hook.plugin,
                &source,
                &busbar_contract::config_time::ConfigScope::config_time(),
            ),
            |resolved| {
                assert_eq!(resolved.as_value(), &expected);
                Ok(())
            },
        )
        .expect("ordinary settings resolve");
        let mut configured = Vec::new();
        for version in [1, 2] {
            assert!(configure_resolved(Some(loaded.clone()), |(), resolved| {
                configured.push((version, resolved.as_value().clone()));
                std::future::ready(Ok(()))
            })
            .await
            .is_ok());
        }
        assert!(configured.len() == 2);
        assert!(configured.iter().all(|(_, value)| value == &expected));
        assert!(source.reads.load(Ordering::SeqCst) == 0);
    }
}

#[test]
fn nested_reference_resolution_diagnostics_do_not_contain_credentials() {
    let output = Arc::new(Mutex::new(Vec::<u8>::new()));
    struct Output(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let writing = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || Output(writing.clone()))
        .finish();
    let source = RotatingSource {
        value: Mutex::new(Some(ORIGINAL_VALUE)),
        reads: AtomicUsize::new(0),
    };
    let hook = settings(json!({"servers": [{"env": {"TOKEN": source_reference()}}]}));
    let resolve = || {
        open_resolved(
            HOOK_NAME,
            &hook,
            crate::config::secret::resolve_settings(
                &hook.settings,
                &[SECRET_PATH.into()],
                &[],
                &hook.plugin,
                &source,
                &busbar_contract::config_time::ConfigScope::config_time(),
            ),
            |_| Ok(()),
        )
    };
    tracing::subscriber::with_default(subscriber, || {
        assert!(resolve().is_some());
        *source.value.lock().unwrap() = Some(ROTATED_VALUE);
        assert!(resolve().is_some());
        *source.value.lock().unwrap() = None;
        assert!(resolve().is_none());
    });
    let capture = String::from_utf8(output.lock().unwrap().clone()).expect("UTF-8 diagnostics");
    assert!(capture.contains("servers.0.env.TOKEN"));
    assert!(capture.contains(SOURCE_UNAVAILABLE));
    assert!(!capture.contains(ORIGINAL_VALUE) && !capture.contains(ROTATED_VALUE));
}

#[tokio::test]
async fn replacing_the_public_registry_cannot_reuse_a_stale_path_snapshot() {
    let mut env = empty_env();
    assert!(env.resolution_paths.matches(&env.registry));
    env.registry = Arc::new(busbar_plugin_loader::PluginRegistry::empty());
    assert!(!env.resolution_paths.matches(&env.registry));
    let source = RotatingSource {
        value: Mutex::new(Some(ORIGINAL_VALUE)),
        reads: AtomicUsize::new(0),
    };
    let hook = settings(json!({"payload": {"literal": {"token": source_reference()}}}));
    assert!(
        resolution::key(HOOK_NAME, &hook, &env).is_none(),
        "a replaced registry cannot reuse its old path snapshot"
    );
    let mut opened = Vec::new();
    let mut configured = Vec::new();
    for (version, credential) in [(1, ORIGINAL_VALUE), (2, ROTATED_VALUE)] {
        *source.value.lock().unwrap() = Some(credential);
        let loaded = open_resolved(
            HOOK_NAME,
            &hook,
            crate::config::secret::resolve_settings(
                &hook.settings,
                &["payload.literal.token".into()],
                &[],
                &hook.plugin,
                &source,
                &busbar_contract::config_time::ConfigScope::config_time(),
            ),
            |resolved| {
                opened.push(resolved.as_value().clone());
                Ok(())
            },
        );
        assert!(configure_resolved(loaded, |(), resolved| {
            configured.push((version, resolved.as_value().clone()));
            std::future::ready(Ok(()))
        })
        .await
        .is_ok());
    }
    assert!(opened.len() == 2);
    assert!(opened[0]["payload"]["token"] == ORIGINAL_VALUE);
    assert!(opened[1]["payload"]["token"] == ROTATED_VALUE);
    assert!(configured.len() == 2);
    assert!(source.reads.load(Ordering::SeqCst) == 2);
}
