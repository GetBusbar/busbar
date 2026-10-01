// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`AuthInstance`] over a linked safe auth door (`auth_verify_door!`), opened through
//! [`crate::auth_axis::AuthRows`] on a real dispatcher: every verdict on the spot and submitted, the
//! short answer's one re-call, refresh's flushed count, a refused setting, and the instance label.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{AuthTail, METRIC_CACHE_FLUSHED};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{MetricFamily, Statement, FAMILY_COUNTER};
use busbar_contract::abi::sdk::auth_door::{
    verify_tail, with_tail, Verdict, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::auth_calls::{AuthCalls, Verified, VerifiedIdentity, VerifyRequest};

use crate::auth_axis::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::{LinkedPlugin, PluginRegistry};

/// Identifies `good` (or the `x-alt` carrier `good`, or the query `good`), rejects `bad`, passes
/// the rest; `wide` identifies with more groups than the host's default buffer holds. Settings must
/// be `"ok"`.
pub(super) struct Judge;

static FLUSHES: AtomicU64 = AtomicU64::new(0);

impl VerifyPlugin for Judge {
    const CACHE_FAMILY: Option<u32> = Some(0);

    fn open(settings: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        (settings == b"\"ok\"")
            .then_some(Judge)
            .ok_or("settings: not this plugin's")
    }

    fn verify(&self, r: &VerifyView<'_>) -> Verdict {
        match r
            .credential()
            .or_else(|| r.carrier("x-alt"))
            .or_else(|| r.query())
        {
            Some(b"good") => Verdict::Identity(VerifiedIdentity {
                subject: "alice".into(),
                name: Some("Alice".into()),
                groups: vec!["ops".into()],
                ttl_secs: Some(60),
                ..VerifiedIdentity::default()
            }),
            Some(b"wide") => Verdict::Identity(VerifiedIdentity {
                subject: "wide".into(),
                groups: (0..300).map(|i| format!("g{i}")).collect(),
                ..VerifiedIdentity::default()
            }),
            Some(b"bad") => Verdict::Reject,
            _ => Verdict::Pass,
        }
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]]) -> u64 {
        FLUSHES.fetch_add(1, Ordering::Relaxed);
        3
    }
}

mod judge {
    use super::*;

    const CARRIERS: &[AbiStr] = &[abi_str("X-Alt")];
    const TAIL: &AuthTail = &verify_tail(0, CARRIERS);
    const FAMILIES: &[MetricFamily] = &[MetricFamily {
        name: abi_str(METRIC_CACHE_FLUSHED),
        help: abi_str("inbound cache entries dropped by refresh"),
        unit: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        label_keys: std::ptr::null(),
        label_keys_len: 0,
        kind: FAMILY_COUNTER,
        _reserved: [0; 7],
    }];

    busbar_contract::auth_verify_door!(
        Judge,
        with_tail(
            Statement {
                families: FAMILIES.as_ptr(),
                families_len: FAMILIES.len(),
                ..statement("judge", "1.0.0", 8)
            },
            TAIL
        )
    );
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
    }))
}

fn rows() -> AuthRows {
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door("judge", judge::door)])
        .expect("the linked door registers");
    AuthRows::new(Box::leak(Box::new(registry)), dispatcher())
}

fn opened(label: &str) -> Arc<dyn AuthCalls> {
    rows()
        .open("judge", label, &serde_json::json!("ok"))
        .expect("the linked door opens")
}

/// The host's request carries no credential and no carrier, so the token the script presents
/// (`credential`, else `alt`) reaches the judge as the query.
fn request(credential: Option<&str>, alt: Option<&str>) -> VerifyRequest {
    VerifyRequest {
        query: credential.or(alt).map(str::to_string),
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        ..VerifyRequest::default()
    }
}

fn alice() -> Verified {
    Verified::Identity(VerifiedIdentity {
        subject: "alice".into(),
        name: Some("Alice".into()),
        groups: vec!["ops".into()],
        ttl_secs: Some(60),
        ..VerifiedIdentity::default()
    })
}

/// The script: every verdict, on a credential and on the carrier.
fn script() -> Vec<(VerifyRequest, Verified)> {
    vec![
        (request(Some("good"), None), alice()),
        (request(None, Some("good")), alice()),
        (request(Some("bad"), None), Verified::Reject),
        (request(Some("other"), None), Verified::Pass),
        (request(None, None), Verified::Pass),
    ]
}

#[test]
fn the_tail_states_its_name_and_facts() {
    let a = opened("judge-a");
    assert_eq!(a.name(), "judge");
    assert_eq!(a.facts(), 0);
}

#[test]
fn every_verdict_on_the_spot() {
    let a = opened("judge-a");
    for (req, want) in script() {
        assert_eq!(a.verify_now(&req), Some(want), "{req:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_verdict_submitted_and_awaited() {
    let a = opened("judge-a");
    for (req, want) in script() {
        let got = Box::into_pin(a.verify(req)).await;
        assert_eq!(got, want);
    }
}

#[test]
fn a_sync_caller_reads_a_submitted_answer_without_a_runtime() {
    let a = opened("judge-a");
    let mut v = a.verify(request(Some("good"), None));
    let mut answer = None;
    for _ in 0..500 {
        answer = v.settled();
        if answer.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(answer, Some(alice()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_answer_is_recalled_once_with_the_buffers_it_named() {
    let a = opened("judge-a");
    let now = a.verify_now(&request(Some("wide"), None));
    let Some(Verified::Identity(id)) = now else {
        panic!("the re-called answer identifies: {now:?}");
    };
    assert_eq!(id.groups.len(), 300);
    assert_eq!(id.groups[299], "g299");
    let submitted = Box::into_pin(a.verify(request(Some("wide"), None))).await;
    assert_eq!(submitted, Verified::Identity(id));
}

#[test]
fn refresh_answers_the_count_the_plugin_reported() {
    let a = opened("judge-a");
    let before = FLUSHES.load(Ordering::Relaxed);
    assert_eq!(a.refresh(), Ok(3));
    assert_eq!(a.refresh(), Ok(3));
    assert!(FLUSHES.load(Ordering::Relaxed) >= before + 2);
    // Still serving after two generations.
    assert_eq!(a.verify_now(&request(Some("good"), None)), Some(alice()));
}

#[test]
fn a_refused_setting_names_the_module_and_the_plugins_words() {
    let err = rows()
        .open("judge", "judge-a", &serde_json::json!("nope"))
        .err()
        .expect("refused");
    assert!(err.contains("'judge'"), "{err}");
    assert!(err.contains("settings: not this plugin's"), "{err}");
}

#[test]
fn two_instances_of_one_plugin_are_two_callers() {
    use crate::auth_door::{AuthInstance, AuthSink};
    use crate::dispatch::{load_linked, Bind};
    let d = dispatcher();
    let open = |label: &str| {
        let sink = AuthSink::new("judge");
        let bind = Bind {
            max_inflight_cap: 8,
            sink: sink.bind(),
            dispatcher: d.adopter(),
        };
        let p = load_linked::<crate::dispatch::kinds::auth::Auth>(judge::door, bind).unwrap();
        AuthInstance::open(p, sink, d.clone(), label, b"\"ok\"", Vec::new()).unwrap()
    };
    let (a, b) = (open("admin-a"), open("admin-b"));
    assert_eq!((a.label(), b.label()), ("admin-a", "admin-b"));
    assert_eq!(a.verify_now(&request(Some("good"), None)), Some(alice()));
    assert_eq!(
        b.verify_now(&request(Some("bad"), None)),
        Some(Verified::Reject)
    );
}

/// A plugin with a service credential: its Statement names `token` as a secret-ref; it opens only
/// when handed that credential as `secrets` and settings that no longer carry it.
struct Keyed;

impl VerifyPlugin for Keyed {
    fn open(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str> {
        let doc: serde_json::Value = serde_json::from_slice(settings).map_err(|_| "not json")?;
        if doc.get("token").is_some() {
            return Err("the secret travelled in the settings");
        }
        if secrets != [b"s3cret".as_slice()] {
            return Err("no service credential");
        }
        Ok(Keyed)
    }

    fn verify(&self, _: &VerifyView<'_>) -> Verdict {
        Verdict::Pass
    }
}

mod keyed {
    use super::*;

    const TAIL: &AuthTail = &verify_tail(0, &[]);
    const SECRET_REFS: &[AbiStr] = &[abi_str("token")];

    busbar_contract::auth_verify_door!(
        Keyed,
        with_tail(
            Statement {
                secret_refs: SECRET_REFS.as_ptr(),
                secret_refs_len: SECRET_REFS.len(),
                ..statement("keyed", "1.0.0", 8)
            },
            TAIL
        )
    );
}

#[test]
fn a_statement_secret_ref_is_handed_to_open_as_a_secret_not_a_setting() {
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door("keyed", keyed::door)])
        .unwrap();
    let rows = AuthRows::new(Box::leak(Box::new(registry)), dispatcher());
    let settings = serde_json::json!({ "token": "s3cret", "other": 1 });
    rows.open("keyed", "keyed", &settings)
        .expect("the credential reaches open as its secret");
    // RED: without the credential the plugin refuses.
    let err = rows
        .open("keyed", "keyed", &serde_json::json!({ "other": 1 }))
        .err()
        .expect("refused");
    assert!(err.contains("no service credential"), "{err}");
}
