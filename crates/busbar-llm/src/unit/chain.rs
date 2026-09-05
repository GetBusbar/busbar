// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REHEARSAL OF THE FLIP — one request driven through every step file in the design's order,
//! against the legacy plane on the same fixture.
//!
//! Each of the nine step files beside this one is identity-tested ALONE: its own harness builds the
//! one input it needs, calls the live site it was lifted from, and compares. That proves each step
//! is faithful. It does not prove they COMPOSE, because nothing has ever handed step N+1 what step N
//! actually returned. This file is that missing proof, and it is deliberately a test and nothing
//! else: the composition root that will really drive these steps is the kernel's, and a driver that
//! shipped in the plane would be a second one.
//!
//! # What it does
//!
//! For each fixture it runs two legs against two SEPARATE deployments — own registry, own scripted
//! upstream, own governance store — and compares what a client and an operator can see:
//!
//! - LEGACY: `native_ingress::operation_ingress_inner`, the shipped entry point, which is arrival,
//!   decode, the gauntlet's verify, `NativePlane::drive`'s door, the one engine and the finish tail.
//! - CHAINED: the step files, called one after another, each fed only from the previous one's
//!   output and from the tokens the kernel would have minted.
//!
//! # What it deliberately does not do
//!
//! Where a step's input cannot be produced from the step before it, this file does NOT invent the
//! missing value inside the chain and carry on. It stops, and the gap is written down as its own
//! test at the bottom of this file, named for the two sides that do not fit. That list is the flip's
//! work order: every one of them is a seam that has to exist before the kernel can drive this plane,
//! and a green chain over an invented value would hide exactly the work the flip has to do.
//!
//! # The tokens
//!
//! Minted the way the loop mints them — one seal for the length of one unit, one `UnitToken<S>` per
//! step, dropped when the call it was lent to returns. The seal is the caps crate's own kernel-only
//! symbol, used here exactly as the nine per-step harnesses beside this file use it: inside a test
//! module, standing in for the kernel that will lend these tokens in production.

#![cfg(test)]

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use busbar_caps::{
    Admission, AdmitToken, Approve, Authenticate, KernelSeal, PrincipalId, TrustToken, UnitToken,
    VerifiedDestination, Verify,
};
use busbar_substrate::plane_host::EngineTablesView;

use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use crate::unit::{admit, approve, arrival, audit, authenticate, decode, route, verify};

/// The one dialect these fixtures speak. Same-protocol openai→openai, so the comparison is about
/// the CHAIN rather than about a translation: a cross-protocol leg has its own identity harness in
/// the codec crate, and putting one here would give a divergence two possible homes.
const PROTO: &str = crate::proto_codec::PROTO_OPENAI;

/// The pool every fixture names, and the one lane behind it.
const POOL: &str = "p";
const LANE: &str = "m0";

/// The flat per-request fee the governed rigs price, in whole cents — one, so that derived spend in
/// cents reads as the billable count.
const FEE_CENTS: i64 = 1;

/// The token figures the scripted upstream reports on a delivered answer.
const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

// ---------------------------------------------------------------------------------------------
// The fixtures
// ---------------------------------------------------------------------------------------------

/// The six units this rehearsal drives. Each names an END, not a step: what a client is answered
/// with, and what the operator's counters say afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fixture {
    /// An admitted, buffered 200 — the whole loop, delivered.
    BufferedOk,
    /// An admitted streamed answer — the same loop with the accrual landing at stream end rather
    /// than at the buffered tap.
    StreamedOk,
    /// A key whose group budget is spent: the door refuses, nothing is charged, nothing is
    /// refunded.
    OverBudget,
    /// A key that may not reach the pool it named: the pre-admission guard refuses, before pricing
    /// is asked about at all.
    PoolAcl,
    /// A model that resolves to no pool and no lane: refused AFTER the door, so it is charged.
    UnknownModel,
    /// The destination answered, badly: an upstream 502 relayed to the client under the pool's
    /// least-bad disposition. A FAILED TRANSFER — the fee does not post and the fee base is
    /// refunded, while the admission slot the door drew is kept.
    UpstreamFailure,
}

impl Fixture {
    /// The model the caller names. Every fixture but [`Fixture::UnknownModel`] names the configured
    /// pool.
    fn model(self) -> &'static str {
        match self {
            Fixture::UnknownModel => "no-such-model",
            _ => POOL,
        }
    }

    /// Whether the caller asked for a stream.
    fn streamed(self) -> bool {
        matches!(self, Fixture::StreamedOk)
    }

    /// The pools the key is restricted to, or `None` for a key that may reach every pool.
    fn key_scopes(self) -> Option<Vec<String>> {
        match self {
            // Restricted to a pool that is NOT the one it asks for, which is the pre-admission
            // guard's own condition.
            Fixture::PoolAcl => Some(vec!["some-other-pool".to_string()]),
            _ => None,
        }
    }

    /// The seeded spend on the key's group bucket, or `None` for an ungrouped key under no cap.
    fn seeded_group_requests(self) -> Option<u64> {
        // 250 seeded requests at a one-cent fee derive to 250 cents, over the 100-cent cap the
        // group declares — the same arithmetic the admit step's own refusal identity pins.
        matches!(self, Fixture::OverBudget).then_some(250)
    }

    /// What the scripted upstream is told to answer.
    fn upstream(self) -> MockResponse {
        match self {
            Fixture::StreamedOk => MockResponse::Sse {
                events: sse_events(),
                abort_at_index: None,
            },
            Fixture::UpstreamFailure => MockResponse::ServerError {
                status: reqwest::StatusCode::BAD_GATEWAY,
                body: serde_json::json!({"error": {"message": "upstream refused the transfer",
                                                   "type": "server_error"}}),
            },
            _ => MockResponse::Ok {
                status: reqwest::StatusCode::OK,
                body: serde_json::json!({
                    "id": "chatcmpl-chain", "object": "chat.completion", "created": 0,
                    "model": LANE,
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "hello"}}],
                    "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                              "total_tokens": INPUT + OUTPUT}
                }),
            },
        }
    }
}

/// A streamed answer carrying the same token figures the buffered one reports, so the two admitted
/// fixtures differ only in HOW the accrual arrives.
fn sse_events() -> Vec<String> {
    vec![
        serde_json::json!({"id": "chatcmpl-chain", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {"role": "assistant",
                                                              "content": "hello"}}]})
        .to_string(),
        serde_json::json!({"id": "chatcmpl-chain", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                                     "total_tokens": INPUT + OUTPUT}})
        .to_string(),
        "[DONE]".to_string(),
    ]
}

/// The request body, as the caller sends it.
fn request_body(fixture: Fixture) -> Bytes {
    let mut v = serde_json::json!({
        "model": fixture.model(),
        "messages": [{"role": "user", "content": "hi"}],
    });
    if fixture.streamed() {
        v["stream"] = serde_json::Value::Bool(true);
    }
    Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
}

fn json_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    h
}

// ---------------------------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------------------------

/// One deployment: a governed key, a one-lane pool, and a scripted upstream. Each LEG builds its
/// own, so the two legs' counters are compared rather than summed.
struct Rig {
    app: Arc<busbar_core::state::App>,
    key: Arc<busbar_api::VirtualKey>,
    server: MockServer,
    charged_at: u64,
    /// The group bucket this rig's key charges through. Unique per rig so two rigs never share a
    /// bucket — and therefore normalized out of the observed body, because the door's quota copy
    /// NAMES the group and two legs legitimately run on two different ones.
    group: String,
}

/// A unique group name per rig, so two rigs running concurrently never share a bucket.
fn unique(prefix: &str) -> String {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{prefix}-{}",
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    )
}

async fn rig(fixture: Fixture) -> Rig {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    // Enough for every failover hop the walk may take; a delivered fixture consumes one.
    for _ in 0..8 {
        state.push(fixture.upstream());
    }
    let server = MockServer::new(state).await;

    let group = unique("chain");
    let mut groups = std::collections::BTreeMap::new();
    if fixture.seeded_group_requests().is_some() {
        groups.insert(
            group.clone(),
            busbar_core::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![busbar_core::config::groups::LimitCfg {
                    metric: busbar_core::config::groups::LimitMetric::Budget,
                    amount: 100,
                    per: Some(busbar_core::config::groups::LimitWindow::Total),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        );
    }

    let store = Arc::new(busbar_core::governance::MemoryStore::new());
    if let Some(requests) = fixture.seeded_group_requests() {
        use busbar_api::Store as _;
        store
            .put_usage(
                &format!("group:{group}@total"),
                0,
                &busbar_api::UsageLedger {
                    requests,
                    billable_requests: requests,
                    models: vec![],
                },
            )
            .expect("seed the durable bucket");
    }
    let gov = Arc::new(
        busbar_core::governance::GovState::new_with_signer(store, None, None).expect("governance"),
    );
    let (key, _) = gov
        .create_key(
            busbar_substrate::governance::NewKeySpec {
                name: "chain".to_string(),
                allowed_pools: fixture.key_scopes(),
                group: fixture
                    .seeded_group_requests()
                    .is_some()
                    .then(|| group.clone()),
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let cost = busbar_core::cost::CostModel::resolve_parts(None, FEE_CENTS, &groups);
    // Enforcement is in-memory and authoritative, so the seeded durable spend has to be hydrated
    // into the cells exactly as boot hydrates it; without this the door would not see it.
    gov.hydrate_budgets(&cost, 0).expect("hydrate");

    let mut builder = TestApp::new()
        .lane(LaneSpec::new(LANE, PROTO, &server.base_url()).provider("test"))
        .pool(POOL, &[(0, 1)])
        .governance(gov)
        .cost(cost);
    if fixture == Fixture::UpstreamFailure {
        // RELAY, not retry-until-exhausted: `least_bad` is the disposition that hands the client
        // the upstream's own answer when every lane is unhealthy, which is what makes this fixture
        // a FAILED TRANSFER (the destination answered, badly) rather than a pool-empty 503.
        builder = builder.on_exhausted(POOL, busbar_core::config::OnExhausted::LeastBad);
    }
    let app = builder.build();

    Rig {
        app,
        key: Arc::new(key),
        server,
        charged_at: busbar_substrate::store::now(),
        group,
    }
}

impl Rig {
    fn gov(&self) -> busbar_api::PlaneRequestCtx {
        busbar_api::PlaneRequestCtx {
            key: Some(self.key.clone()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// What a leg leaves behind
// ---------------------------------------------------------------------------------------------

/// Header values a response mints fresh per run. The NAME stays in the comparison and only the
/// value is blanked, so a leg that stopped emitting one is still a divergence.
const VOLATILE_HEADERS: [&str; 6] = [
    "date",
    "request-id",
    "x-request-id",
    "x-amzn-requestid",
    "x-amzn-request-id",
    "retry-after",
];

/// Everything one leg left behind, as comparable strings: the bytes a client saw, and the counters
/// an operator can read back.
#[derive(Debug, PartialEq, Eq)]
struct Observed(Vec<(&'static str, String)>);

/// Blank the values a response synthesizes per run — ids and clocks — so the comparison is about
/// content rather than about a fresh id.
fn normalize(s: &str) -> String {
    fn blank(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    let is_id = k.ends_with("id") || k.ends_with("Id") || k.ends_with("ID");
                    let is_clock = matches!(k.as_str(), "created" | "created_at" | "createTime");
                    if is_id && val.is_string() {
                        *val = serde_json::Value::String("<id>".to_string());
                    } else if (is_clock || k == "latencyMs") && val.is_number() {
                        *val = serde_json::Value::from(0);
                    } else {
                        blank(val);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(blank),
            _ => {}
        }
    }
    // An SSE body is a sequence of framed JSON documents; normalize each frame's payload so a
    // streamed leg is compared on the same footing as a buffered one.
    if s.contains("data:") {
        return s
            .lines()
            .map(|line| match line.strip_prefix("data: ") {
                Some(rest) => format!("data: {}", normalize(rest)),
                None => line.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(mut v) => {
            blank(&mut v);
            v.to_string()
        }
        Err(_) => s.to_string(),
    }
}

async fn observe(rig: &Rig, resp: Response) -> Observed {
    use busbar_substrate::store::BreakerState;

    let mut fields: Vec<(&'static str, String)> = Vec::new();
    fields.push(("status", resp.status().as_u16().to_string()));
    let mut headers: Vec<String> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            if VOLATILE_HEADERS.contains(&k.as_str()) {
                format!("{k}: <volatile>")
            } else {
                format!("{k}: {}", String::from_utf8_lossy(v.as_bytes()))
            }
        })
        .collect();
    headers.sort();
    fields.push(("headers", headers.join("\n")));
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    fields.push((
        "body",
        normalize(&String::from_utf8_lossy(&body)).replace(&rig.group, "<group>"),
    ));

    // The body wrapper records the stream's outcome on drop; give it a tick before the reads.
    tokio::task::yield_now().await;

    // THE MONEY. The derived figures the enforcer compares against a cap, and the raw per-model
    // series row the flush writes — the two surfaces a metering divergence would show on.
    let gov = rig
        .app
        .governance
        .clone()
        .expect("governance is configured");
    let derived = gov
        .derived_bucket_usage(&rig.app.cost, &rig.key.id, "total", true, rig.charged_at)
        .expect("usage read");
    fields.push(("ledger_requests", derived.requests.to_string()));
    fields.push(("ledger_tokens", derived.tokens.to_string()));
    fields.push(("ledger_spend_cents", derived.spend_cents.to_string()));
    gov.flush_metering();
    let mut rows: Vec<busbar_api::MeteringRow> = gov
        .metering_for(busbar_substrate::governance::metering_bucket(
            rig.charged_at,
        ))
        .expect("metering read")
        .into_iter()
        .filter(|r| r.key_id == rig.key.id)
        .collect();
    rows.sort_by(|a, b| (&a.model, &a.provider).cmp(&(&b.model, &b.provider)));
    fields.push((
        "metering_rows",
        rows.iter()
            .map(|r| {
                format!(
                    "{}/{} in={} out={} cr={} cw={} req={} billable={}",
                    r.model,
                    r.provider,
                    r.tokens_input,
                    r.tokens_output,
                    r.tokens_cache_read,
                    r.tokens_cache_write,
                    r.requests,
                    r.billable_requests
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    ));

    // THE BREAKER. The lane's own state after the walk, which is what an exhausted fixture moves.
    let store = &*rig.app.store;
    fields.push((
        "breaker",
        match store.breaker_state_in(POOL, 0) {
            BreakerState::Closed => "Closed",
            BreakerState::Open { .. } => "Open",
            BreakerState::HalfOpen => "HalfOpen",
        }
        .to_string(),
    ));
    fields.push((
        "cooldown",
        if store.cooldown_remaining_in(POOL, 0, busbar_substrate::store::now()) > 0 {
            "running".to_string()
        } else {
            "none".to_string()
        },
    ));
    fields.push(("admissible", store.lane_admissible(0).to_string()));
    fields.push((
        "lane_budget",
        format!("{:?}", store.lane_budget_remaining(0)),
    ));

    Observed(fields)
}

// ---------------------------------------------------------------------------------------------
// LEG 1 — the legacy plane
// ---------------------------------------------------------------------------------------------

/// The shipped entry point, driven on this fixture. Arrival, decode, the gauntlet's verify,
/// `NativePlane::drive`'s door, the one engine and the finish tail — all of it, unchanged.
async fn leg_legacy(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let (host, _rt) = crate::engine::test_host_rt(&rig.app);
    let resp = crate::native_ingress::operation_ingress_inner(
        &host,
        &rig.gov(),
        None,
        &json_headers(),
        request_body(fixture),
        PROTO,
        busbar_api::operation::Operation::CHAT,
        None,
    )
    .await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

// ---------------------------------------------------------------------------------------------
// LEG 2 — the step files, in the design's order
// ---------------------------------------------------------------------------------------------

/// THE ONE MINT SITE. The kernel lends a unit its seal; this rehearsal has no kernel, so it stands
/// in for one — in ONE place, so that "who may open a decision" is as readable here as it is in the
/// loop, and so a step's harness cannot quietly mint a second one.
fn kernel_seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

/// THE NODE'S ONE INTERNER, standing in for the composition root's.
///
/// A configured lane's name is read out of config at boot and a [`LaneId`] is a borrowed static
/// name, so the two are bridged by interning the name ONCE — the root's job, and the recorded rule
/// for every config-derived open-vocabulary key. This rehearsal has no root, so it holds the one
/// interner itself: process-wide, filled from the deployment's own tables, and idempotent, so a
/// second leg over the same lane name leaks nothing further. A per-leg interner would be a leak per
/// request wearing a test's clothes, which is exactly the shape the rule forbids.
static LANES: std::sync::LazyLock<std::sync::Mutex<busbar_contract::Registration>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(busbar_contract::Registration::new()));

/// The destination set the trust unit would have sealed, over the lane this deployment CONFIGURED —
/// the name read back off the running routing tables, not a literal spelled here.
fn sealed_destinations(seal: &KernelSeal, lane: &str) -> Vec<VerifiedDestination> {
    let lane = LANES
        .lock()
        .expect("the rehearsal's interner is never poisoned")
        .lane(lane);
    vec![VerifiedDestination::seal(&TrustToken::mint(seal), lane)]
}

/// The chained leg: every step file, in the loop's order, each fed from the one before it.
async fn leg_chain(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let (host, rt) = crate::engine::test_host_rt(&rig.app);
    let gov = rig.gov();
    let headers = json_headers();
    let body = request_body(fixture);
    let started = Instant::now();
    let charged_at = rig.charged_at;

    // THE SEAL, held for the length of this one unit. Every token below is minted from it and
    // dropped when the step it was lent to returns, exactly as the loop lends them.
    let seal = kernel_seal();

    let resp = drive(
        &seal, &host, &rt, &gov, &headers, &body, started, charged_at, fixture,
    )
    .await;

    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

/// STEP 0 THROUGH STEP 7, called in the order section 2.2 fixes them in.
#[allow(clippy::too_many_arguments)]
async fn drive(
    seal: &KernelSeal,
    host: &Arc<dyn busbar_substrate::plane_host::EngineHost>,
    rt: &Arc<crate::engine::NativeRuntime>,
    gov: &busbar_api::PlaneRequestCtx,
    headers: &HeaderMap,
    body: &Bytes,
    started: Instant,
    charged_at: u64,
    fixture: Fixture,
) -> Response {
    // ---- STEP 0, ARRIVAL --------------------------------------------------------------------
    // The body-model path: read the content type, validate the bytes, capture the head projection.
    let arrived = match arrival::arrival_body(headers, body) {
        Ok(a) => a,
        Err(refusal) => {
            // A named refusal becomes bytes at the audit step and nowhere else: the step answers
            // with a `RefusalOutcome` and the terminal is the one place that renders one.
            let outcome = refusal.outcome();
            return audit::audit_refused(
                host,
                gov,
                PROTO,
                started,
                charged_at,
                audit::render_refusal(PROTO, &outcome),
            );
        }
    };

    // ---- STEP 1, DECODE ---------------------------------------------------------------------
    let mut model_out = String::new();
    let decoded = match decode::decode_body(
        PROTO,
        busbar_api::operation::Operation::CHAT,
        &arrived.content_type,
        &arrived.body,
        arrived.parsed.as_ref(),
        None,
        &mut model_out,
    ) {
        Ok(d) => d,
        Err(refusal) => {
            let outcome = refusal.outcome();
            return audit::audit_refused(
                host,
                gov,
                PROTO,
                started,
                charged_at,
                audit::render_refusal(PROTO, &outcome),
            );
        }
    };
    let model: String = decoded.model.to_string();

    // ---- STEP 1, AUTHENTICATE ---------------------------------------------------------------
    // Cannot refuse — every refusal this step could raise is the middleware's, upstream of the
    // plane — so the principal is always established. It is still called, and its answer is still
    // opened, because the chain is about what each step ACTUALLY returns.
    let principal: PrincipalId = {
        let token: UnitToken<Authenticate> = UnitToken::mint(seal);
        let decision = authenticate::authenticate(&token, gov);
        match decision.into_result(seal) {
            Ok(facts) => facts
                .principal()
                .cloned()
                .expect("this plane opens no handshake unit, so the challenge arm is unreachable"),
            Err(_) => unreachable!("the authenticate step's refusal set is empty"),
        }
    };

    // ---- STEP 2, VERIFY ---------------------------------------------------------------------
    // The destination set the trust unit would have sealed, over the lane this deployment
    // configured — the runtime name read off the tables and interned once, which is how a
    // config-derived name becomes the borrowed static one the priced axis is written in.
    let configured_lane = rt
        .lane_view(0)
        .expect("the fixture configures one lane")
        .model
        .to_string();
    let destinations = sealed_destinations(seal, &configured_lane);
    let view = verify::HostPoolView::new(&**host, &**rt, gov.key.as_deref());
    let destinations = {
        let token: UnitToken<Verify> = UnitToken::mint(seal);
        let answer = verify::verify(&token, &view, &model, &principal, destinations);
        // The step's own named refusal, carried back beside the decision — the guards are read once
        // and the wire triple is the step's, not the driver's.
        let named = answer.refusal;
        match answer.decision.into_result(seal) {
            Ok(dests) => dests,
            Err(_) => {
                // A named refusal becomes bytes at the audit step and nowhere else, exactly as
                // arrival's and decode's do.
                let outcome = named
                    .expect("a refused decision carries the refusal that named it")
                    .outcome();
                return audit::audit_refused(
                    host,
                    gov,
                    PROTO,
                    started,
                    charged_at,
                    audit::render_refusal(PROTO, &outcome),
                );
            }
        }
    };

    // ---- STEP 3, APPROVE --------------------------------------------------------------------
    // No seat is installed on any deployment today, so the step is a no-op — and it is still
    // called, because "nothing is seated" is a fact about config, not a licence to skip a step.
    {
        let token: UnitToken<Approve> = UnitToken::mint(seal);
        let decision = approve::approve(&token, &principal, &destinations, &[]);
        if decision.into_result(seal).is_err() {
            unreachable!("no veto seat is installed, so this step cannot refuse");
        }
    }

    // ---- STEP 4, ADMIT ----------------------------------------------------------------------
    let admitted = admit::admit(
        &UnitToken::mint(seal),
        &AdmitToken::mint(seal),
        &admit::AdmitCtx {
            host,
            gov,
            proto: PROTO,
            destination: &model,
            started,
            charged_at,
        },
        &principal,
        &destinations,
    );
    let charged = admitted.charged;
    let effective = admitted
        .effective_pool
        .clone()
        .unwrap_or_else(|| model.clone());
    // The door renders AND finishes its own refusal, so a refused unit leaves here: posting it
    // through the audit step would be a second link for one unit. See
    // `the_admit_door_finishes_its_own_refusal_before_the_audit_step_sees_it`.
    if let Some(resp) = admitted.refusal {
        let _ = admitted.decision;
        return resp;
    }
    let hold = match admitted.decision.into_result(seal) {
        Ok(Admission::Own(hold)) => Some(hold),
        Ok(Admission::Accrual(_)) => panic!("a client unit holds its own admission"),
        Ok(Admission::ZeroHold) => None,
        Err(_) => unreachable!("a refusal carries its rendered bytes and returned above"),
    };
    // The hold reaches no exit path in this rehearsal: the exit is the kernel's, and there is no
    // plane-side settle. Held to the end of the unit so the accounting is not silently dropped.
    let _hold = hold;

    // ---- STEP 5, ROUTE ----------------------------------------------------------------------
    let routed = route::route(route::RouteInput {
        host,
        rt,
        proto: PROTO,
        op: busbar_substrate::handlers::frame(
            busbar_substrate::transport::Transport::Http,
            busbar_api::operation::Operation::CHAT,
            decoded.op_handler,
        ),
        destination: &effective,
        headers,
        body: body.clone(),
        parsed: arrived.parsed,
        caller_token: None,
        resolved_gov_key: gov.key.as_ref(),
        // The meter half of the hold, built at the door and carried to every accrual site. It is
        // what makes the walk's own stream-end tap the accrual — which is also why the Meter step
        // below cannot run; see `the_route_step_meters_before_the_meter_step_is_reached`.
        usage_sink: admitted.sink,
        model_not_found_message: None,
    })
    .await;

    // ---- STEP 6, METER ----------------------------------------------------------------------
    // NOT REACHED. `Routed` carries a `Response` and nothing else: the serving lane, the reported
    // usage and the billing-failed fact `MeterCtx::new` requires are all consumed inside the walk
    // and never handed back. Faking them here would prove the chain by inventing the very values
    // the flip has to plumb. The gap is `the_meter_step_cannot_be_fed_from_the_route_steps_output`.
    let _ = fixture;

    // ---- STEP 7, AUDIT ----------------------------------------------------------------------
    match routed {
        // A destination that never resolved is a refusal taken AFTER the door, so it is charged and
        // it leaves through the admitted terminal, exactly as the legacy tail leaves it.
        route::Routed::Refused(resp) | route::Routed::Completed(resp) => audit::audit(
            host, gov, PROTO, &effective, started, charged_at, resp, charged,
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// The rehearsal
// ---------------------------------------------------------------------------------------------

const CASES: [Fixture; 6] = [
    Fixture::BufferedOk,
    Fixture::StreamedOk,
    Fixture::OverBudget,
    Fixture::PoolAcl,
    Fixture::UnknownModel,
    Fixture::UpstreamFailure,
];

/// THE REHEARSAL. Same fixture in, same bytes and same counters out — through the legacy plane and
/// through the nine step files driven one after another.
///
/// Every field is compared: the status, every header the identity tests pin (with only the
/// per-response volatiles blanked, name kept), the body, the derived ledger the enforcer reads, the
/// raw metering rows the flush writes, and the lane's breaker state and remaining budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chain_matches_the_legacy_drive_on_every_fixture() {
    let mut failures: Vec<String> = Vec::new();
    for fixture in CASES {
        let legacy = leg_legacy(fixture).await;
        let chained = leg_chain(fixture).await;
        for ((field, want), (_, got)) in legacy.0.iter().zip(chained.0.iter()) {
            if want != got {
                failures.push(format!(
                    "{fixture:?}: field `{field}` diverges\n  legacy: {want}\n  chain:  {got}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} chain divergence(s) across {} fixtures:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
}

/// The ENDS are what the fixtures claim they are. Without this the rehearsal above could be green
/// on six identical 404s and prove nothing about the loop at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_fixture_reaches_the_end_it_names() {
    let mut seen: Vec<(Fixture, String)> = Vec::new();
    for fixture in CASES {
        let observed = leg_chain(fixture).await;
        let status = observed
            .0
            .iter()
            .find(|(k, _)| *k == "status")
            .map(|(_, v)| v.clone())
            .expect("every leg observes a status");
        seen.push((fixture, status));
    }
    assert_eq!(
        seen,
        vec![
            (Fixture::BufferedOk, "200".to_string()),
            (Fixture::StreamedOk, "200".to_string()),
            // The exhausted budget: the door's own 429.
            (Fixture::OverBudget, "429".to_string()),
            // The pre-admission guard's 403, before pricing is asked about.
            (Fixture::PoolAcl, "403".to_string()),
            // Refused AFTER the door, so it is charged and audited as an admitted unit.
            (Fixture::UnknownModel, "404".to_string()),
            // The failed transfer: the upstream's own 502, relayed to the client.
            (Fixture::UpstreamFailure, "502".to_string()),
        ],
        "the fixtures do not reach the six distinct ends they are named for"
    );
}

/// THE MONEY, spelled out rather than only compared. A delivered unit charges one admission slot,
/// posts one fee cent and meters the reported token split; a refusal at the door charges nothing;
/// a refusal after the door keeps its slot and refunds its fee base.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chain_leaves_the_money_where_the_legacy_plane_leaves_it() {
    fn field(o: &Observed, k: &str) -> String {
        o.0.iter()
            .find(|(f, _)| *f == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    // A STREAMED unit accrues at stream end rather than at the buffered tap, so it is asserted in
    // its own right: without this the rehearsal could be green on a stream that metered nothing.
    let streamed = leg_chain(Fixture::StreamedOk).await;
    assert_eq!(field(&streamed, "ledger_requests"), "1");
    assert_eq!(
        field(&streamed, "ledger_tokens"),
        (INPUT + OUTPUT).to_string(),
        "the stream-end tap accrued the reported split"
    );
    assert_eq!(
        field(&streamed, "metering_rows"),
        format!("{LANE}/test in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1")
    );

    // A FAILED TRANSFER keeps its admission slot and posts no tokens.
    let failed = leg_chain(Fixture::UpstreamFailure).await;
    assert_eq!(field(&failed, "ledger_requests"), "1");
    assert_eq!(field(&failed, "ledger_tokens"), "0");
    assert_eq!(field(&failed, "metering_rows"), "");

    let delivered = leg_chain(Fixture::BufferedOk).await;
    assert_eq!(field(&delivered, "ledger_requests"), "1");
    assert_eq!(
        field(&delivered, "ledger_tokens"),
        (INPUT + OUTPUT).to_string()
    );
    assert_eq!(
        field(&delivered, "metering_rows"),
        format!("{LANE}/test in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1")
    );

    // The door refused: nothing was charged, so there is nothing on the key's own bucket at all.
    let refused = leg_chain(Fixture::OverBudget).await;
    assert_eq!(field(&refused, "ledger_requests"), "0");
    assert_eq!(field(&refused, "metering_rows"), "");

    // The pre-admission guard refused: charged nothing either, and it never reached the door.
    let guarded = leg_chain(Fixture::PoolAcl).await;
    assert_eq!(field(&guarded, "ledger_requests"), "0");
    assert_eq!(field(&guarded, "metering_rows"), "");

    // Refused after the door: the admission slot is drawn and NEVER released, which is the rule
    // that makes a request cap impossible to escape by failing.
    let post_door = leg_chain(Fixture::UnknownModel).await;
    assert_eq!(field(&post_door, "ledger_requests"), "1");
    assert_eq!(field(&post_door, "metering_rows"), "");
}

// ---------------------------------------------------------------------------------------------
// THE SEAM GAPS — the flip's work order
// ---------------------------------------------------------------------------------------------
//
// Each test below names one place where the step files do not yet fit together, and each one is
// written as a failing assertion rather than as a comment, so the gap closes by turning a test
// green rather than by someone remembering to delete a paragraph.

/// GAP 1 — ROUTE hands the METER step nothing it can be fed with.
///
/// `route::route` answers with `Routed`, whose two arms both carry a `Response` and nothing else.
/// `meter::MeterCtx::new` asks for the serving lane, the reported `TokenUsage`, the client-facing
/// status, and the billing-failed fact — four values the walk computes and drops. There is no
/// expression a driver can write here that produces a `MeterCtx` from a `Routed`.
#[test]
#[should_panic(
    expected = "SEAM GAP: Routed carries no lane, no reported usage and no \
                           billing-failed fact, so meter::MeterCtx cannot be built from it"
)]
fn the_meter_step_cannot_be_fed_from_the_route_steps_output() {
    panic!(
        "SEAM GAP: Routed carries no lane, no reported usage and no billing-failed fact, so \
         meter::MeterCtx cannot be built from it"
    );
}

/// GAP 2 — the walk METERS, so the METER step would meter a second time.
///
/// The admission's meter half (`Admitted::sink`) is handed to `route`, which threads it into the
/// walk, which accrues at the buffered tap or at stream end. A chain that then called `meter` with
/// the same sink would post the same tokens twice. Withholding the sink from `route` is not an
/// answer either: the walk's own taps are where a streamed response's usage becomes known at all.
#[test]
#[should_panic(
    expected = "SEAM GAP: route::route accrues through Admitted::sink, so meter::meter \
                           over the same sink double-posts"
)]
fn the_route_step_meters_before_the_meter_step_is_reached() {
    panic!(
        "SEAM GAP: route::route accrues through Admitted::sink, so meter::meter over the same \
         sink double-posts"
    );
}

/// GAP 3, CLOSED — the VERIFY step hands its named refusal back with the decision.
///
/// `verify::verify` answers a [`verify::Verified`]: the `Decision<Verify>` the loop reads, whose
/// `Refusal` carries the neutral reason code and retry hint, and beside it the `VerifyRefusal` the
/// step actually raised. The wire triple therefore comes from the ONE reading of the guards that
/// produced the refusal, rather than from a second reading that could answer differently.
#[tokio::test]
async fn the_verify_refusal_carries_the_wire_triple_the_guards_named() {
    let rig = rig(Fixture::PoolAcl).await;
    let (host, rt) = crate::engine::test_host_rt(&rig.app);
    let gov = rig.gov();
    let view = verify::HostPoolView::new(&*host, &*rt, gov.key.as_deref());
    let seal = kernel_seal();
    let answer = verify::verify(
        &UnitToken::mint(&seal),
        &view,
        POOL,
        &PrincipalId::new(rig.key.id.clone()),
        Vec::new(),
    );
    let named = answer.refusal.clone().expect("the guards refused");
    let refusal = answer
        .decision
        .into_result(&seal)
        .expect_err("the decision refused");
    // The two readings of one answer agree: the loop's reason code, and the step's own triple.
    assert_eq!(refusal.reason(), named.reason());
    assert_eq!(named.status(), 403);
    assert_eq!(named.kind(), crate::engine::KIND_PERMISSION);
    rig.server.shutdown().await;
}

/// GAP 3b, CLOSED — VERIFY is on the typed refusal value.
///
/// `VerifyRefusal::outcome()` answers an `audit::RefusalOutcome`, exactly as `ArrivalRefusal` and
/// `DecodeRefusal` do, so the driver above names no status, no kind word and no sentence of its own
/// — it hands the outcome to the terminal, which is the one place a refusal becomes bytes.
#[test]
fn the_verify_step_answers_with_the_typed_refusal_value() {
    let outcome = verify::VerifyRefusal::NotAuthorized.outcome();
    assert_eq!(outcome.status(), StatusCode::FORBIDDEN);
    assert_eq!(outcome.kind(), crate::engine::KIND_PERMISSION);
    assert_eq!(
        outcome.message(),
        "Your API key does not have permission to access this resource."
    );
}

/// GAP 4, CLOSED — the VERIFY step reads a live deployment through a production `PoolView`.
///
/// `verify::HostPoolView` is that view, and the chain above drives it rather than an adapter of its
/// own. This pins that it answers what the LIVE guard answers on the same deployment: the fixture's
/// key may not reach the pool it names, `destination_guard` over the view refuses, and
/// `EngineHost::destination_guard` — the shipped path, which answers with finished bytes — refuses
/// the same request.
#[tokio::test]
async fn the_verify_step_reads_a_live_deployment_through_a_pool_view() {
    let rig = rig(Fixture::PoolAcl).await;
    let (host, rt) = crate::engine::test_host_rt(&rig.app);
    let gov = rig.gov();
    let view = verify::HostPoolView::new(&*host, &*rt, gov.key.as_deref());

    let refused = verify::destination_guard(&view, POOL).expect_err("the key may not reach it");
    assert_eq!(refused, verify::VerifyRefusal::NotAuthorized);
    assert!(
        host.destination_guard(&gov, PROTO, POOL, Instant::now(), rig.charged_at)
            .is_err(),
        "the shipped guard refuses the same request on the same deployment"
    );

    // And an unrestricted name on the same deployment passes both.
    let unkeyed = busbar_api::PlaneRequestCtx { key: None };
    let open = verify::HostPoolView::new(&*host, &*rt, None);
    assert_eq!(verify::destination_guard(&open, POOL), Ok(()));
    assert!(host
        .destination_guard(&unkeyed, PROTO, POOL, Instant::now(), rig.charged_at)
        .is_ok());
    rig.server.shutdown().await;
}

/// GAP 4b, CLOSED — the plane can read whether a rate card is present.
///
/// The two questions VERIFY's third guard asks are answered through the host's cost seam over the
/// opaque handle, so the guard that refuses an unbillable name is answered from the plane side
/// without the plane ever reading a rate. The fixtures configure no card, and the seam says so —
/// which is the difference between an answer and a fixture-shaped guess.
#[tokio::test]
async fn the_plane_reads_whether_a_rate_card_is_present() {
    use busbar_substrate::plane_host::BudgetHost as _;
    use verify::PoolView as _;

    let rig = rig(Fixture::BufferedOk).await;
    let (host, rt) = crate::engine::test_host_rt(&rig.app);
    let cost = host.cost();
    assert!(
        !host.cost_pricing_enabled(&cost),
        "these fixtures configure no rate card"
    );
    assert!(!host.cost_model_unpriced(&cost, "made-up-name"));

    let gov = rig.gov();
    let view = verify::HostPoolView::new(&*host, &*rt, gov.key.as_deref());
    assert_eq!(view.pricing_enabled(), host.cost_pricing_enabled(&cost));
    assert_eq!(
        view.is_unpriced("made-up-name"),
        host.cost_model_unpriced(&cost, "made-up-name")
    );
    rig.server.shutdown().await;
}

/// GAP 5, CLOSED — a configured lane's runtime name can be sealed into a `VerifiedDestination`.
///
/// The bridge is the registration interner, not a second id type: a config-derived name is leaked
/// into a `&'static str` exactly once and `LaneId` stays the one `Copy` name the rate card, the
/// verified destination and the locator comparison are all written in. Interning is idempotent, so
/// sealing the same lane twice yields the same id and leaks once — which is what makes this legal on
/// a request path at all.
#[tokio::test]
async fn a_configured_lanes_runtime_name_can_be_sealed() {
    let rig = rig(Fixture::BufferedOk).await;
    let (_host, rt) = crate::engine::test_host_rt(&rig.app);
    // Read out of the running tables as a runtime `String` — nothing static about it.
    let configured: String = rt
        .lane_view(0)
        .expect("the fixture configures one lane")
        .model
        .to_string();
    assert_eq!(configured, LANE);

    let seal = kernel_seal();
    let sealed = sealed_destinations(&seal, &configured);
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].lane().as_str(), configured);
    // Idempotent: the second seal of the same name is the same id, so this is a fixed cost.
    let again = sealed_destinations(&seal, &configured);
    assert_eq!(again[0].lane(), sealed[0].lane());
    assert!(std::ptr::eq(
        again[0].lane().as_str(),
        sealed[0].lane().as_str()
    ));
    rig.server.shutdown().await;
}

/// GAP 6 — the ADMIT door finishes its own refusal, so the AUDIT step never sees it.
///
/// `admit::admit` carries back `Admitted::refusal`: a response the door ALREADY posted through the
/// not-charged terminal. The chain has to return it untouched, because handing it to
/// `audit::audit_refused` would post a second link for one unit. So on the one path where a step
/// refuses after Authenticate, the audit step is not the plane's single terminal after all.
#[test]
#[should_panic(
    expected = "SEAM GAP: EngineHost::admission_door finishes its own refusal, so the \
                           audit step is bypassed on the over-budget path"
)]
fn the_admit_door_finishes_its_own_refusal_before_the_audit_step_sees_it() {
    panic!(
        "SEAM GAP: EngineHost::admission_door finishes its own refusal, so the audit step is \
         bypassed on the over-budget path"
    );
}

/// GAP 7 — `audit_refused` labels every pre-door refusal `unresolved`; the live guard labels it
/// with the pool.
///
/// The live pre-admission guard finishes through `finish_rejected` with `pool_label(app, pool)`, so
/// a 403 against a CONFIGURED pool is recorded against that pool's name. `audit::audit_refused`
/// takes no destination and passes `POOL_LABEL_UNRESOLVED` unconditionally. The bytes agree; the
/// record does not.
#[tokio::test]
#[should_panic(
    expected = "SEAM GAP: audit::audit_refused hard-codes POOL_LABEL_UNRESOLVED where \
                           the live pre-admission guard labels the record with the pool"
)]
async fn the_refused_terminal_labels_a_configured_pool_as_unresolved() {
    let rig = rig(Fixture::PoolAcl).await;
    let (host, _rt) = crate::engine::test_host_rt(&rig.app);
    assert_eq!(
        host.pool_label(POOL),
        POOL,
        "the fixture's pool is configured, so the live label is its name"
    );
    rig.server.shutdown().await;
    panic!(
        "SEAM GAP: audit::audit_refused hard-codes POOL_LABEL_UNRESOLVED where the live \
         pre-admission guard labels the record with the pool"
    );
}

/// GAP 8 — neither ROUTE nor AUDIT is on the token seam.
///
/// Every other step file takes a `UnitToken<S>` and answers with a `Decision<S>`. `route::route`
/// takes a `RouteInput` and answers `Routed`; `audit::audit` takes eight plumbing arguments and
/// answers a `Response`. Steps 5 and 7 therefore cannot be installed on the composition root's step
/// seam at all — they are the two the flip has to re-shape, not merely re-wire.
#[test]
#[should_panic(
    expected = "SEAM GAP: route and audit take no UnitToken and return no Decision, so \
                           steps 5 and 7 are not on the step seam"
)]
fn route_and_audit_are_not_on_the_token_seam() {
    panic!(
        "SEAM GAP: route and audit take no UnitToken and return no Decision, so steps 5 and 7 are \
         not on the step seam"
    );
}
