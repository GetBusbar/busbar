// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`AuthInstance`] over a linked safe auth door (`auth_verify_door!`), opened through
//! [`crate::auth_axis::AuthRows`] on a real dispatcher: every verdict on the spot and submitted, with
//! its decision and strips, the lent lines and body, the short answer's one re-call, the overloaded
//! instance, refresh's flushed count, a refused setting, and the instance label.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{AuthPoint, AuthPoints, AuthTail, METRIC_CACHE_FLUSHED};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{MarkWord, MetricFamily, Statement, FAMILY_COUNTER};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_tail, Answer, Strip, Verdict, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::auth_calls::{
    AuthCalls, Decision, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest,
};
use busbar_contract::Redacted;

use crate::auth_axis::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::{LinkedPlugin, PluginRegistry};

/// Identifies `good` (or the `x-alt` line `good`, or the query `good`), rejects `bad`, passes
/// the rest; `wide` identifies with more groups than the host's default buffer holds; `slow` passes
/// after holding its crossing for 200 ms; `body` identifies only at `HeadBody` on connection 3,
/// unit 4, over the body `signed`. Every answer names the `x-alt` line to strip. Settings must be
/// `"ok"`.
pub(super) struct Judge;

static FLUSHES: AtomicU64 = AtomicU64::new(0);

impl VerifyPlugin for Judge {
    const CACHE_FAMILY: Option<u32> = Some(0);

    fn open(settings: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        (settings == b"\"ok\"")
            .then_some(Judge)
            .ok_or("settings: not this plugin's")
    }

    fn verify(&self, r: &VerifyView<'_>) -> Answer {
        let verdict = match r
            .credential()
            .or_else(|| r.line("x-alt"))
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
            Some(b"slow") => {
                std::thread::sleep(Duration::from_millis(200));
                Verdict::Pass
            }
            Some(b"body")
                if r.point() == Some(AuthPoint::HeadBody)
                    && (r.conn(), r.unit()) == (3, 4)
                    && r.body() == Some(&b"signed"[..]) =>
            {
                Verdict::Identity(VerifiedIdentity {
                    subject: "signed".into(),
                    ..VerifiedIdentity::default()
                })
            }
            Some(b"body") => Verdict::Reject,
            _ => Verdict::Pass,
        };
        Answer {
            strips: vec![Strip::field("x-alt")],
            ..verdict.into()
        }
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]]) -> u64 {
        FLUSHES.fetch_add(1, Ordering::Relaxed);
        3
    }
}

mod judge {
    use super::*;

    const CARRIERS: &[MarkWord] = &[carrier("X-Alt")];
    const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD);
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
                mark_words: CARRIERS.as_ptr(),
                mark_words_len: CARRIERS.len(),
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
    AuthRows::new(Arc::new(registry), dispatcher())
}

fn opened(label: &str) -> Arc<dyn AuthCalls> {
    rows()
        .open("judge", label, &serde_json::json!("ok"))
        .expect("the linked door opens")
}

/// The host's request carries no credential of its own: the script's `credential` reaches the
/// judge as the query, and `alt` as the `X-Alt` field line.
fn request(credential: Option<&str>, alt: Option<&str>) -> VerifyRequest {
    VerifyRequest {
        query: credential.map(str::to_string),
        lines: alt
            .map(|a| vec![("X-Alt".to_string(), Redacted::new(a.as_bytes().to_vec()))])
            .unwrap_or_default(),
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        ..VerifyRequest::default()
    }
}

fn alice() -> VerifyAnswer {
    answered(Verified::Identity(VerifiedIdentity {
        subject: "alice".into(),
        name: Some("Alice".into()),
        groups: vec!["ops".into()],
        ttl_secs: Some(60),
        ..VerifiedIdentity::default()
    }))
}

/// `verified` as the host reads the judge's answer: its default decision, and the `x-alt` strip.
fn answered(verified: Verified) -> VerifyAnswer {
    VerifyAnswer {
        strips: vec![Strip::field("x-alt")],
        ..verified.into()
    }
}

/// The script: every verdict, on the query and on the field line.
fn script() -> Vec<(VerifyRequest, VerifyAnswer)> {
    vec![
        (request(Some("good"), None), alice()),
        (request(None, Some("good")), alice()),
        (request(Some("bad"), None), answered(Verified::Reject)),
        (request(Some("other"), None), answered(Verified::Pass)),
        (request(None, None), answered(Verified::Pass)),
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
    let Some(Verified::Identity(id)) = now.map(|a| a.verified) else {
        panic!("the re-called answer identifies");
    };
    assert_eq!(id.groups.len(), 300);
    assert_eq!(id.groups[299], "g299");
    let submitted = Box::into_pin(a.verify(request(Some("wide"), None))).await;
    assert_eq!(submitted, answered(Verified::Identity(id)));
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
    use crate::dispatch::{load_linked, Bind, LinkedRow};
    let d = dispatcher();
    let open = |label: &str| {
        let sink = AuthSink::new("judge");
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: 8,
            sink: sink.bind(),
            dispatcher: d.adopter(),
            conns: None,
        };
        let row = LinkedRow::of(judge::door).unwrap();
        let p = load_linked::<crate::dispatch::kinds::auth::Auth>(&row, bind).unwrap();
        AuthInstance::open(p, sink, d.clone(), label, b"\"ok\"", Vec::new()).unwrap()
    };
    let (a, b) = (open("admin-a"), open("admin-b"));
    assert_eq!((a.label(), b.label()), ("admin-a", "admin-b"));
    assert_eq!(a.verify_now(&request(Some("good"), None)), Some(alice()));
    assert_eq!(
        b.verify_now(&request(Some("bad"), None)),
        Some(answered(Verified::Reject))
    );
}

/// THE DECISION AND THE STRIPS reach the host whatever the verdict: CONTINUE for an identity or a
/// pass, STOP for a reject, and the `x-alt` line named each time (THE DESIGN, "Auth points and
/// guest lists", step 3).
#[test]
fn every_answer_carries_its_decision_and_strips() {
    let a = opened("judge-a");
    for (cred, decision) in [
        ("good", Decision::Continue),
        ("other", Decision::Continue),
        ("bad", Decision::Stop),
    ] {
        let got = a.verify_now(&request(Some(cred), None)).expect("answered");
        assert_eq!(got.decision, decision, "{cred}");
        assert_eq!(got.strips, vec![Strip::field("x-alt")], "{cred}");
    }
}

/// HEADBODY: the host lends the point, the connection, the unit and the body, so a mechanism that
/// signs the body verifies it. RED: the same request at `Head` (no body), or over another body, is
/// not identified.
#[test]
fn the_body_reaches_the_plugin_at_head_body_only() {
    let a = opened("judge-a");
    let at = |point: AuthPoint, body: Option<&[u8]>| VerifyRequest {
        point,
        conn: 3,
        unit: 4,
        body: body.map(<[u8]>::to_vec),
        ..request(Some("body"), None)
    };
    let signed = a.verify_now(&at(AuthPoint::HeadBody, Some(b"signed")));
    assert!(
        matches!(signed.map(|s| s.verified), Some(Verified::Identity(ref id)) if id.subject == "signed")
    );
    for req in [
        at(AuthPoint::Head, None),
        at(AuthPoint::HeadBody, Some(b"forged")),
    ] {
        let got = a.verify_now(&req).expect("answered");
        assert_eq!(got.verified, Verified::Reject, "{req:?}");
    }
}

/// OVERLOAD (THE DESIGN's accepted differences): a `verify` past the instance's `max_inflight`
/// is never queued and never crosses: it answers [`Verified::Overloaded`] at once, with the decision
/// to stop and nothing to strip, and the host answers the request 503. RED: a second `verify` while
/// the first holds the instance's one unit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verify_past_max_inflight_is_overloaded_and_never_queued() {
    use crate::auth_door::{AuthInstance, AuthSink};
    use crate::dispatch::{load_linked, Bind, LinkedRow};
    let d = dispatcher();
    let sink = AuthSink::new("judge");
    let bind = Bind {
        instance: Arc::from("judge-1"),
        max_inflight_cap: 1,
        sink: sink.bind(),
        dispatcher: d.adopter(),
        conns: None,
    };
    let row = LinkedRow::of(judge::door).unwrap();
    let p = load_linked::<crate::dispatch::kinds::auth::Auth>(&row, bind).unwrap();
    let a = AuthInstance::open(p, sink, d.clone(), "judge-1", b"\"ok\"", Vec::new()).unwrap();
    assert_eq!(a.plugin().max_inflight(), 1);
    let slow = a.verify(request(Some("slow"), None));
    let mut over = a.verify(request(Some("good"), None));
    let answer = over.settled().expect("answered before any crossing");
    assert_eq!(answer, VerifyAnswer::from(Verified::Overloaded));
    assert_eq!(answer.decision, Decision::Stop);
    assert!(answer.strips.is_empty());
    // The first finishes; the unit is back, and the instance serves again.
    assert_eq!(
        Box::into_pin(slow).await.verified,
        Verified::Pass,
        "the held verify completes"
    );
    assert_eq!(
        Box::into_pin(a.verify(request(Some("good"), None))).await,
        alice()
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

    fn verify(&self, _: &VerifyView<'_>) -> Answer {
        Verdict::Pass.into()
    }
}

mod keyed {
    use super::*;

    const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD);
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
    let rows = AuthRows::new(Arc::new(registry), dispatcher());
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

/// A linked auth plugin whose Statement states one alias rewrite.
mod aliased {
    use super::*;
    use busbar_contract::abi::mechanism::door::{Rewrite, REWRITE_ALIAS};

    const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD);
    const SECRET_REFS: &[AbiStr] = &[abi_str("token")];
    const REWRITES: &[Rewrite] = &[Rewrite {
        class: REWRITE_ALIAS,
        _reserved: 0,
        from: abi_str("keyed-too"),
        to: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
    }];

    busbar_contract::auth_verify_door!(
        Keyed,
        with_tail(
            Statement {
                secret_refs: SECRET_REFS.as_ptr(),
                secret_refs_len: SECRET_REFS.len(),
                rewrites: REWRITES.as_ptr(),
                rewrites_len: REWRITES.len(),
                ..statement("aliased", "1.0.0", 8)
            },
            TAIL
        )
    );
}

/// THE ALIAS IS A STATEMENT REWRITE (the design's One Statement: an auth provider's alias is its
/// Statement's `REWRITE_ALIAS` rewrite, never a tail fact): the auth rows answer, link and open a
/// row by the alias its Statement states, beside its own name; a word no row states stays refused.
#[test]
fn an_auth_row_answers_to_its_statements_alias_rewrite() {
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door("aliased", aliased::door)])
        .unwrap();
    let rows = AuthRows::new(Arc::new(registry), dispatcher());
    assert!(rows.answers("aliased"));
    assert!(rows.answers("keyed-too"), "the Statement's alias answers");
    assert!(rows.linked("keyed-too"), "and names a linked row");
    assert!(!rows.answers("keyed-three"));
    let settings = serde_json::json!({ "token": "s3cret" });
    rows.open("keyed-too", "by-alias", &settings)
        .expect("the row opens by its Statement's alias");
}

/// Two auth doors declaring they read the `sigv4` credential kind, and one declaring `bearer`.
mod readers {
    use busbar_contract::abi::sdk::auth_door::with_credential_kinds;

    use super::*;

    const SIGV4: &[AbiStr] = &[abi_str("sigv4")];
    const BEARER: &[AbiStr] = &[abi_str("bearer")];
    const SIGV4_TAIL: &AuthTail = &with_credential_kinds(verify_tail(0, AuthPoints::HEAD), SIGV4);
    const BEARER_TAIL: &AuthTail =
        &with_credential_kinds(verify_tail(0, AuthPoints::HEAD), BEARER);

    pub(super) mod a {
        use super::*;
        busbar_contract::auth_verify_door!(
            Judge,
            with_tail(statement("reader-a", "1.0.0", 8), SIGV4_TAIL)
        );
    }
    pub(super) mod b {
        use super::*;
        busbar_contract::auth_verify_door!(
            Judge,
            with_tail(statement("reader-b", "1.0.0", 8), SIGV4_TAIL)
        );
    }
    pub(super) mod c {
        use super::*;
        busbar_contract::auth_verify_door!(
            Judge,
            with_tail(statement("reader-c", "1.0.0", 8), BEARER_TAIL)
        );
    }
}

/// ONE VERIFIER PER CREDENTIAL KIND (ARCHITECT 2026-10-01, Q2 ruling B): a row declaring a
/// credential kind another auth row also declares refuses to open, naming both rows and the kind;
/// a row whose kinds no other row declares opens. RED: without the check both readers opened.
#[test]
fn two_auth_rows_reading_one_credential_kind_refuse_to_open() {
    let registry = PluginRegistry::empty()
        .link(vec![
            LinkedPlugin::auth_door("reader-a", readers::a::door),
            LinkedPlugin::auth_door("reader-b", readers::b::door),
            LinkedPlugin::auth_door("reader-c", readers::c::door),
        ])
        .expect("the linked doors register");
    let rows = AuthRows::new(Arc::new(registry), dispatcher());
    let err = rows
        .open("reader-a", "reader-a", &serde_json::json!("ok"))
        .err()
        .expect("a second reader of sigv4 refuses");
    assert_eq!(
        err,
        "auth plugins 'reader-a' and 'reader-b' both declare they read the credential kind \
         'sigv4'; one verifier reads a credential kind"
    );
    assert!(rows
        .open("reader-c", "reader-c", &serde_json::json!("ok"))
        .is_ok());

    let alone = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door("reader-a", readers::a::door)])
        .expect("the linked door registers");
    let rows = AuthRows::new(Arc::new(alone), dispatcher());
    assert!(rows
        .open("reader-a", "reader-a", &serde_json::json!("ok"))
        .is_ok());
}
