// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-STOREKIT r2 §2.5, at the runner level: the fixture's strict schema and its two tokens, the
//! command line, and the kit run over core's in-tree memory store through the runner's own
//! fixture. A correct store passes. Two negative controls must fail: a store whose every open is
//! a new, empty dataset, and a store whose open hangs. The hang must fail at its deadline, naming
//! the case.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::persistence::PersistenceBackend;
use busbar_plugin_abi::host_side::caller::BoxFut;

use super::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

const SHARED: &str = r#"{"schema":"busbar.store-kit/1","config":{"dataset":"{dataset}","name":"{instance}"},"dataset_scope":"shared"}"#;

/// The dataset token the shared template put in a config.
fn dataset_of(config: &[u8]) -> String {
    let text = std::str::from_utf8(config).unwrap();
    let start = text.find("kit-").expect("a dataset token");
    text[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}

/// The in-tree memory store, one backend per dataset token: what a shared store does.
#[derive(Default)]
struct PerDataset(Mutex<HashMap<String, Arc<dyn PersistenceBackend>>>);

impl Opener for PerDataset {
    fn open<'a>(
        &'a self,
        _: &'a str,
        config: Vec<u8>,
    ) -> BoxFut<'a, Result<Arc<dyn PersistenceBackend>, String>> {
        Box::pin(async move {
            let dataset = dataset_of(&config);
            if let Some(held) = self.0.lock().unwrap().get(&dataset) {
                return Ok(Arc::clone(held));
            }
            let fresh = crate::root::real_store::native_backend().await;
            Ok(Arc::clone(
                self.0.lock().unwrap().entry(dataset).or_insert(fresh),
            ))
        })
    }
}

/// Negative control: every open is a new, empty dataset, whatever the config names.
struct EveryOpenFresh;

impl Opener for EveryOpenFresh {
    fn open<'a>(
        &'a self,
        _: &'a str,
        _: Vec<u8>,
    ) -> BoxFut<'a, Result<Arc<dyn PersistenceBackend>, String>> {
        Box::pin(async { Ok(crate::root::real_store::native_backend().await) })
    }
}

/// Negative control: the second open of any dataset never answers.
#[derive(Default)]
struct SecondOpenHangs(PerDataset, Mutex<HashMap<String, u32>>);

impl Opener for SecondOpenHangs {
    fn open<'a>(
        &'a self,
        instance: &'a str,
        config: Vec<u8>,
    ) -> BoxFut<'a, Result<Arc<dyn PersistenceBackend>, String>> {
        Box::pin(async move {
            let dataset = dataset_of(&config);
            let opens = {
                let mut opens = self.1.lock().unwrap();
                let n = opens.entry(dataset).or_default();
                *n += 1;
                *n
            };
            if opens > 1 {
                std::future::pending::<()>().await;
            }
            self.0.open(instance, config).await
        })
    }
}

#[test]
fn a_correct_store_passes_every_case_through_the_runner_fixture() {
    let rt = runtime();
    let fixture = KitFixture::new(
        PerDataset::default(),
        Template::parse(SHARED.as_bytes()).unwrap(),
    );
    assert_eq!(run_kit(&rt, &fixture, CASE_DEADLINE, RUN_DEADLINE), Ok(()));
}

#[test]
fn a_store_whose_every_open_is_a_fresh_dataset_fails_the_runner() {
    let rt = runtime();
    let fixture = KitFixture::new(EveryOpenFresh, Template::parse(SHARED.as_bytes()).unwrap());
    let failure = run_kit(&rt, &fixture, CASE_DEADLINE, RUN_DEADLINE).unwrap_err();
    assert!(failure.contains("k1_first_start_publication"), "{failure}");
}

#[test]
fn the_instance_scope_hands_every_open_the_first_instance() {
    let rt = runtime();
    let template = Template::parse(
        br#"{"schema":"busbar.store-kit/1","config":{},"dataset_scope":"instance"}"#,
    )
    .unwrap();
    // Every opened instance is a fresh store, as memory's is: only the scope keeps a dataset whole.
    let fixture = KitFixture::new(EveryOpenFresh, template);
    assert_eq!(run_kit(&rt, &fixture, CASE_DEADLINE, RUN_DEADLINE), Ok(()));
}

#[test]
fn a_hanging_open_fails_at_the_case_deadline_naming_the_case() {
    let rt = runtime();
    let fixture = KitFixture::new(
        SecondOpenHangs::default(),
        Template::parse(SHARED.as_bytes()).unwrap(),
    );
    let failure = run_kit(&rt, &fixture, Duration::from_secs(2), RUN_DEADLINE).unwrap_err();
    assert!(
        failure.contains("TIMEOUT k1_first_start_publication"),
        "{failure}"
    );
}

#[test]
fn the_run_deadline_bounds_the_whole_kit() {
    let rt = runtime();
    let fixture = KitFixture::new(
        SecondOpenHangs::default(),
        Template::parse(SHARED.as_bytes()).unwrap(),
    );
    let failure = run_kit(&rt, &fixture, RUN_DEADLINE, Duration::from_secs(2)).unwrap_err();
    assert!(failure.contains("TIMEOUT the run"), "{failure}");
}

#[test]
fn the_fixture_schema_is_strict() {
    for (bad, why) in [
        (
            r#"{"schema":"busbar.store-kit/1","config":{"d":"{dataset}"},"dataset_scope":"shared","durable":true}"#,
            "unknown key",
        ),
        (
            r#"{"schema":"busbar.store-kit/2","config":{"d":"{dataset}"},"dataset_scope":"shared"}"#,
            "another schema",
        ),
        (
            r#"{"schema":"busbar.store-kit/1","config":["{dataset}"],"dataset_scope":"shared"}"#,
            "config not an object",
        ),
        (
            r#"{"schema":"busbar.store-kit/1","config":{"path":"/tmp/one.db"},"dataset_scope":"shared"}"#,
            "shared without {dataset}",
        ),
        (
            r#"{"schema":"busbar.store-kit/1","config":{},"dataset_scope":"global"}"#,
            "unknown scope",
        ),
        (r#"{"schema":"busbar.store-kit/1","config":{}}"#, "no scope"),
    ] {
        assert!(Template::parse(bad.as_bytes()).is_err(), "{why}: {bad}");
    }
}

#[test]
fn the_tokens_are_replaced_in_the_config_text() {
    let template = Template::parse(
        br#"{"schema":"busbar.store-kit/1","config":{"path":"/tmp/{dataset}.db","prefix":"{dataset}:{instance}"},"dataset_scope":"shared"}"#,
    )
    .unwrap();
    let config = template.config("kit-7", "store-kit-9");
    let value: busbar_contract::json::Value = busbar_contract::json::parse(&config).unwrap();
    use busbar_contract::json::JsonValueTrait;
    assert_eq!(
        value.get("path").and_then(|v| v.as_str()),
        Some("/tmp/kit-7.db")
    );
    assert_eq!(
        value.get("prefix").and_then(|v| v.as_str()),
        Some("kit-7:store-kit-9")
    );
}

#[test]
fn the_command_line_takes_pack_fixture_and_out_once_each() {
    let words = |w: &[&str]| w.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        Args::parse(&words(&[
            "--pack",
            "p.tar.gz",
            "--fixture=f.json",
            "--out",
            "o"
        ])),
        Ok(Args {
            pack: "p.tar.gz".into(),
            fixture: "f.json".into(),
            out: Some("o".into()),
        })
    );
    for bad in [
        &["--fixture", "f.json"][..],
        &["--pack", "p", "--fixture", "f", "--pack", "q"],
        &["--pack", "p", "--fixture", "f", "--extra", "x"],
        &["--pack", "--fixture", "f"],
        &["--pack", "p", "--fixture"],
    ] {
        assert!(Args::parse(&words(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn a_refused_command_exits_2_before_any_case() {
    let words = ["--pack".to_owned(), "/nonexistent.tar.gz".to_owned()];
    assert_eq!(command(&words), 2);
}
