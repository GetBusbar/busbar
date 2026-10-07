// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The previous release's engine tests whose behaviour the kernel now owns: the admission door and
//! its budget downgrade, the unit's request-family outcome label, the money settled under a member
//! whose wire name differs from its configured one, the session hash, the configuration's literal
//! defaults and refusals, the hooks' refusal words, the error envelope of an ingress no plane
//! resolves, and the data plane's auth gate when the chain does not name the keys verifier.
//!
//! Each test names the legacy test it carries over and keeps that test's inputs and expected
//! values; only the harness is new. Each drives the kernel entry point the composition root calls on
//! the door path (the admission check, the request-family emit, the money seam, the router's auth
//! gate), not a copy of it.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use busbar_contract::records::{PlaneRequestCtx, ScopeRef, VirtualKey};

use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow, OnExhaust};
use crate::cost::CostModel;
use crate::governance::{GovState, MemoryStore, NewKeySpec, RecordStore};
use crate::test_support::{LaneSpec, TestApp};

const AT: u64 = 1_700_000_000;

fn caller(key: &VirtualKey) -> PlaneRequestCtx {
    PlaneRequestCtx {
        key: Some(Arc::new(key.clone())),
    }
}

/// A deployment over `pools`, each on the one lane, governed by `gov` under `cost`. The lane's
/// protocol is a neutral name: no test here dispatches.
fn governed(pools: &[&str], gov: &Arc<GovState>, cost: CostModel) -> Arc<crate::state::App> {
    crate::test_support::register_neutral_test_plane();
    crate::metrics::init();
    let mut builder = TestApp::new().lane(LaneSpec::new(
        "ported-lane",
        "ported-lane-proto",
        "http://127.0.0.1:1",
    ));
    for pool in pools {
        builder = builder.pool(pool, &[(0, 1)]);
    }
    builder.governance(Arc::clone(gov)).cost(cost).build()
}

fn body_text(resp: axum::response::Response) -> String {
    let bytes = futures::executor::block_on(axum::body::to_bytes(resp.into_body(), 1 << 20))
        .expect("the body");
    String::from_utf8_lossy(&bytes).into_owned()
}

// ── the admission door ───────────────────────────────────────────────────────────────────────────

/// Ports legacy `ingress_integration_tests.rs::test_ungrouped_key_is_authed_but_unlimited_admission_never_blocks`:
/// a key bound to no group is authenticated but carries no cap of any kind, so the admission door
/// never blocks it however much it has spent; its spend accrues without bound.
#[test]
fn an_ungrouped_key_is_never_blocked_at_the_admission_door() {
    let gov =
        Arc::new(GovState::new(Arc::new(MemoryStore::new()), Some("admintok".into())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            AT,
        )
        .unwrap();
    assert!(key.group.is_none(), "the key under test carries no group");
    let app = governed(&["p"], &gov, CostModel::flat(30));
    const ADMITS: i64 = 500;
    for i in 0..ADMITS {
        let admitted = crate::ingress::admit_check(
            &app,
            &caller(&key),
            crate::test_support::NEUTRAL_WIRE_FORMATS[1],
            "",
            AT,
        );
        assert!(
            matches!(admitted, Ok((Some(_), None))),
            "an ungrouped key is authenticated but unlimited: admission #{i} must not block"
        );
    }
    let spend = gov
        .usage_for(&app.cost, &key.id, AT)
        .unwrap()
        .map_or(0, |u| u.spend_cents);
    assert_eq!(
        spend,
        ADMITS * 30,
        "an ungrouped key accrues spend without any budget cap ever blocking admission"
    );
}

/// A budget limit on `pool` of `amount` cents a day that downgrades to `to` when spent.
fn downgrading(pool: &str, amount: u64, to: &str) -> LimitCfg {
    LimitCfg {
        metric: LimitMetric::Budget,
        amount,
        per: Some(LimitWindow::Day),
        scope: Some(ScopeRef::pool(pool)),
        on_exhaust: Some(OnExhaust::Downgrade),
        downgrade_to: Some(ScopeRef::pool(to)),
        admission: None,
        on_exhaustion: None,
    }
}

/// Ports legacy `ingress_integration_tests.rs::test_downgrade_cycle_terminates_via_the_revisit_guard`:
/// a downgrade chain `a -> b -> c -> b` walks all the way to `c` before the revisit of `b` is
/// refused, and ends in the plain quota refusal naming `c`'s bucket, never a loop, a panic or an
/// admission.
#[test]
fn a_cyclic_budget_downgrade_ends_at_the_revisit_guard_naming_the_last_pool() {
    let gov =
        Arc::new(GovState::new(Arc::new(MemoryStore::new()), Some("admintok".into())).unwrap());
    let groups = BTreeMap::from([(
        "team".to_string(),
        GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![
                // a: one 10-cent request, then down to b.
                downgrading("a", 10, "b"),
                // b: already spent, down to c.
                downgrading("b", 0, "c"),
                // c: already spent, back to b: the cycle.
                downgrading("c", 0, "b"),
            ],
            ..Default::default()
        },
    )]);
    let cost = CostModel::resolve_parts(None, 10, &groups);
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "dev".to_string(),
                allowed_pools: None,
                group: Some("team".to_string()),
                labels: Default::default(),
                ..Default::default()
            },
            AT,
        )
        .unwrap();
    let app = governed(&["a", "b", "c"], &gov, cost);
    let now = crate::store::now();

    let (grant, effective) = crate::ingress::admit_check(
        &app,
        &caller(&key),
        crate::test_support::NEUTRAL_WIRE_FORMATS[1],
        "a",
        now,
    )
    .expect("the first admission is under a's cap");
    assert!(grant.is_some());
    assert_eq!(effective, None);

    let refused = crate::ingress::admit_check(
        &app,
        &caller(&key),
        crate::test_support::NEUTRAL_WIRE_FORMATS[1],
        "a",
        now,
    )
    .expect_err("a cyclic downgrade chain must terminate in a refusal, not an admission");
    assert_eq!(
        refused.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the caller sees the plain quota refusal once the cycle is detected"
    );
    let text = body_text(*refused);
    assert!(
        text.contains("pool 'c'"),
        "the chain walks a -> b -> c before the revisit of b is refused, so the refusal names \
         pool 'c': {text}"
    );
}

// ── the unit's outcome label ─────────────────────────────────────────────────────────────────────

/// Ports legacy `ingress_integration_tests.rs::test_finish_outcome_mapping_503_is_exhausted`: a unit
/// that ends 503 is counted under the `exhausted` outcome on the request family.
#[test]
fn a_unit_ending_503_is_counted_as_exhausted() {
    let app = governed(
        &["p2"],
        &Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).unwrap()),
        CostModel::flat(0),
    );
    assert_eq!(crate::telemetry::outcome_of(503), "exhausted");
    // A protocol label nothing else in this binary uses, so the delta is this test's alone.
    let proto = "ported-outcome-proto";
    let count = || {
        crate::test_support::metric_sum(
            crate::metrics::REQUESTS_TOTAL,
            &[("ingress_protocol", proto), ("outcome", "exhausted")],
        )
    };
    let before = count();
    crate::telemetry::model_request_finished(&app, proto, "p2", 503, 0.0);
    assert_eq!(
        count() - before,
        1.0,
        "a 503 end is one request under outcome=exhausted"
    );
}

// ── the money settled under an aliased member ────────────────────────────────────────────────────

#[derive(Default)]
struct Posted;

impl crate::plane_driver::EndPost for Posted {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
}

/// Ports legacy `usage_tap_tests.rs::ledger_prices_an_aliased_lane_at_the_rate_card`: a member
/// configured as `gpt-4o` whose provider is sent `glm-4.6` ledgers and prices its tokens under the
/// configured name the rate card is keyed by, so its spend derives at the card's rate and a
/// budget-capped group is not left uncapped on token cost.
#[test]
fn a_member_whose_wire_name_differs_is_priced_at_its_configured_name() {
    use crate::plane_driver::{FeeRefund, MoneySeam as _, PlaneMoney, UnitMoney};
    use busbar_contract::abi::plane::{UnitCount, UNITS_REPORTED};
    use busbar_contract::UnitKey;

    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).unwrap());
    // The card is keyed by the CONFIGURED name: 1000 micro-units a token, input and output.
    let card = BTreeMap::from([(
        "gpt-4o".to_string(),
        crate::config::RateEntryCfg {
            input_utok: 1000.0,
            output_utok: 1000.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: 1_000_000_000,
                per: Some(LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = Arc::new(CostModel::resolve_parts(Some(&card), 0, &groups));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("g".to_string()),
                labels: Default::default(),
                ..Default::default()
            },
            AT,
        )
        .unwrap();
    let money = PlaneMoney::new(Arc::clone(&gov), Arc::new(Posted));
    let unit = UnitKey::new(1);
    money.open(
        unit,
        UnitMoney {
            key: Arc::new(key),
            cost: Arc::clone(&cost),
            pool: String::new(),
            model: "gpt-4o".into(),
            classes: Arc::from(vec!["input".to_string(), "output".to_string()]),
            arrived: AT,
            mode: crate::config::groups::ExhaustionMode::FinishUnit,
            fee: FeeRefund::CallerStatus,
            charge: Default::default(),
        },
    );
    let ctx = crate::teller::UnitCtx {
        key: unit,
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: crate::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let counts = [
        UnitCount {
            class: 0,
            source: UNITS_REPORTED,
            amount: 600,
        },
        UnitCount {
            class: 1,
            source: UNITS_REPORTED,
            amount: 400,
        },
    ];
    let _ = money.checkpoint(&ctx, &counts);
    // The serving member is named as the walk names it: its configured name, never the name its
    // provider is sent (`glm-4.6`).
    money.served(&ctx, "gpt-4o", "zai");
    money.settle_end(unit, 200);

    let derived = gov
        .derived_bucket_usage(&cost, "group:g@day", "day", true, AT)
        .expect("usage read");
    assert_eq!(derived.tokens, 1000, "the tokens are ledgered");
    // 1000 tokens x 1000 micro-units = 1_000_000 micro-units = 100 cents.
    assert_eq!(
        derived.spend_cents, 100,
        "an aliased member's tokens price against the rate card; zero here is a budget-capped \
         group left uncapped on token cost"
    );
}

// ── the session hash ─────────────────────────────────────────────────────────────────────────────

/// Ports legacy `usage_tap_tests.rs::test_stable_hash_is_deterministic`: the hash session affinity
/// rides is FNV-1a, pinned to its golden so an algorithm or constant swap is caught directly, and it
/// tells different sessions apart.
#[test]
fn the_session_hash_is_fnv1a_pinned_to_its_golden() {
    assert_eq!(
        crate::store::fnv1a_u64("session-abc"),
        0xe909_c864_ab05_9bea
    );
    assert_ne!(
        crate::store::fnv1a_u64("session-abc"),
        crate::store::fnv1a_u64("session-xyz")
    );
}

// ── the configuration's literals ─────────────────────────────────────────────────────────────────

/// Ports legacy `on_exhausted_tests.rs::test_config_parsing_queue_unknown_inner_key_fails`: the
/// queue terminal's body refuses an unknown key, so a misspelt `max_millis` fails rather than being
/// ignored.
#[test]
fn a_misspelt_key_in_the_queue_terminals_body_is_refused() {
    let parsed: Result<crate::config::pools::OnExhaustedCfg, _> =
        serde_yaml::from_str("{ queue: { max_millis: 250 } }");
    assert!(
        parsed.is_err(),
        "an unknown queue inner key must fail parsing"
    );
    // The control: the spelling that exists parses.
    let parsed: Result<crate::config::pools::OnExhaustedCfg, _> =
        serde_yaml::from_str("{ queue: { max_ms: 250 } }");
    assert!(parsed.is_ok());
}

/// Ports legacy `stream_deadline_tests.rs::the_total_deadline_the_stream_rides_defaults_to_five_minutes`:
/// the default total deadline a streamed answer rides is five minutes, as a literal.
#[test]
fn the_default_upstream_request_timeout_is_five_minutes() {
    assert_eq!(
        crate::config::limits::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS,
        300
    );
}

/// Ports legacy `gate_policy_503_literals_tests.rs::the_refusal_literal_is_the_shared_constant`:
/// the refusal a failed load-bearing hook produces is one constant with the words that shipped, at
/// status 503.
#[test]
fn the_required_hook_refusal_says_the_words_that_shipped() {
    assert_eq!(
        crate::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
        "A required gate could not complete. Please retry shortly."
    );
    assert_eq!(crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS, 503);
}

// ── the error envelope of an ingress no plane resolves ───────────────────────────────────────────

/// Ports legacy `wire_tests.rs::unknown_ingress_error_envelope_is_core_s_own_and_names_no_dialect`:
/// an ingress name that resolves to no protocol is answered with the kernel's own envelope, its
/// kind stated verbatim, and no dialect's response fields.
#[test]
fn an_unresolved_ingress_is_answered_in_the_kernels_own_envelope() {
    let resp = crate::proxy::ingress_error(
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_kernel_egress::wire::KIND_OVERLOADED,
        "everything is on fire",
    );
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        resp.headers().get("x-amzn-requestid").is_none(),
        "an unresolved ingress must not carry a dialect's error fields"
    );
    let v: serde_json::Value = serde_json::from_str(&body_text(resp)).expect("a JSON envelope");
    assert_eq!(
        v["error"]["type"],
        busbar_kernel_egress::wire::KIND_OVERLOADED,
        "the kernel's envelope states the kind verbatim"
    );
    assert_eq!(v["error"]["message"], "everything is on fire");
}

// ── the data plane's gate when the chain does not name the keys verifier ─────────────────────────

/// A chain of the static `grp:<role>` module, the role `role` bound to every pool.
fn static_chain(app: TestApp, role: &str) -> TestApp {
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.chain = vec![crate::config::AuthChainEntry::bare("test-groups-module")];
    let mut table = BTreeMap::new();
    table.insert(
        role.to_string(),
        crate::config::RoleBindingCfg {
            allowed_pools: None,
            group: None,
            admin_scope: None,
        },
    );
    let mut bindings = crate::config::RoleBindings::new();
    bindings.insert("test-groups-module".to_string(), table);
    app.auth(Arc::new(crate::auth::AuthMiddleware::new_builtin(&cfg)))
        .role_bindings(bindings)
}

/// Serve `app`; the URL of pool `pa`'s messages path and the server's handle.
async fn serve(app: Arc<crate::state::App>) -> (String, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/pa/v1/messages"), handle)
}

fn messages_body() -> String {
    serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
        .to_string()
}

/// Ports legacy `auth_dispatch_tests.rs::test_governance_inert_without_admin_token_static_token_admitted`:
/// with no admin token and a chain that does not name the keys verifier, the governance book does
/// not demand a virtual key: a credential the static chain recognises is admitted by it, and a
/// credential it does not recognise is still refused.
#[tokio::test]
async fn a_static_chain_admits_its_own_credential_when_no_virtual_key_is_demanded() {
    crate::metrics::init();
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "the book holds no admin token"
    );
    let app = static_chain(
        TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::test_support::NEUTRAL_WIRE_FORMATS[0],
                    "http://127.0.0.1:1",
                )
                .api_key("busbar-upstream-key"),
            )
            .pool("pa", &[(0, 1)])
            .governance(gov),
        "static",
    )
    .build();
    let (url, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let ok = client
        .post(&url)
        .bearer_auth("grp:static")
        .body(messages_body())
        .send()
        .await
        .unwrap();
    assert_ne!(
        ok.status().as_u16(),
        401,
        "the static chain's own credential is admitted: no virtual key is demanded"
    );
    assert_ne!(ok.status().as_u16(), 403);

    let bad = client
        .post(&url)
        .bearer_auth("not-the-token")
        .body(messages_body())
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        401,
        "the static chain still refuses a credential it does not recognise"
    );
    handle.abort();
}

/// Ports legacy `auth_dispatch_tests.rs::test_inert_governance_persisted_key_is_not_enforced_static_chain_wins`:
/// a virtual key persisted in the book, restricted to another pool, confers nothing when the chain
/// does not name the keys verifier: its secret is refused by the static chain, and the static
/// credential is admitted without the key's pool restriction being consulted.
#[tokio::test]
async fn a_persisted_key_is_not_enforced_when_the_chain_does_not_name_the_keys_verifier() {
    crate::metrics::init();
    let persisted_secret = "sk-vk-persisted-from-prior-run";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kold".to_string(),
            generation_hash: crate::test_support::sigv4::sha256_hex(persisted_secret.as_bytes()),
            name: "kold".to_string(),
            allowed_scopes: Some(vec![ScopeRef::pool("restricted")]),
            enabled: true,
            created_at: 0,
            group: None,
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
            ..Default::default()
        })
        .unwrap();
    let gov = Arc::new(GovState::new(store, None).unwrap());
    assert!(gov.admin_token_hash().is_none());
    let app = static_chain(
        TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::test_support::NEUTRAL_WIRE_FORMATS[0],
                    "http://127.0.0.1:1",
                )
                .api_key("busbar-upstream-key"),
            )
            .pool("pa", &[(0, 1)])
            .governance(gov),
        "static-chain",
    )
    .build();
    let (url, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let with_key = client
        .post(&url)
        .bearer_auth(persisted_secret)
        .body(messages_body())
        .send()
        .await
        .unwrap();
    assert_eq!(
        with_key.status().as_u16(),
        401,
        "the persisted key confers nothing: the static chain, which does not list it, refuses it"
    );

    let with_static = client
        .post(&url)
        .bearer_auth("grp:static-chain")
        .body(messages_body())
        .send()
        .await
        .unwrap();
    assert_ne!(
        with_static.status().as_u16(),
        401,
        "the static chain decides admission; the persisted key's controls are not consulted"
    );
    assert_ne!(with_static.status().as_u16(), 403);
    handle.abort();
}
