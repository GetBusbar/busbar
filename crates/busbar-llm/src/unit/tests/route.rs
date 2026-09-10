//! Tests for `route.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use busbar_caps::KernelSeal;
use busbar_contract::Registration;
use busbar_substrate::store::{now as store_now, BreakerState};
use serde_json::json;

/// A kernel seal for the length of one leg, and the step-5 token minted from it — exactly as
/// the loop lends it, and dropped when the call it was lent to returns.
fn tokens() -> (KernelSeal, UnitToken<Route>) {
    let seal = KernelSeal::acquire_for_kernel();
    let token = UnitToken::mint(&seal);
    (seal, token)
}

const INGRESS: [&str; 6] = [
    crate::proto_codec::PROTO_ANTHROPIC,
    crate::proto_codec::PROTO_OPENAI,
    crate::proto_codec::PROTO_RESPONSES,
    crate::proto_codec::PROTO_GEMINI,
    crate::proto_codec::PROTO_BEDROCK,
    crate::proto_codec::PROTO_COHERE,
];

/// The scripted upstreams: one that answers, one that never will.
#[derive(Clone, Copy, Debug)]
enum Fixture {
    /// A delivered 2xx in the caller's own dialect.
    Ok,
    /// A 5xx on every hop, so the walk exhausts and the lane's breaker moves.
    ServerError,
}

fn request_body(ingress: &str, model: &str) -> Vec<u8> {
    let v = match ingress {
        "anthropic" => json!({"model": model, "max_tokens": 16,
                              "messages": [{"role": "user", "content": "hi"}]}),
        "openai" | "cohere" => {
            json!({"model": model, "messages": [{"role": "user", "content": "hi"}]})
        }
        "responses" => json!({"model": model, "input": "hi"}),
        "gemini" => {
            json!({"model": model, "contents": [{"role": "user", "parts": [{"text": "hi"}]}]})
        }
        "bedrock" => {
            json!({"model": model, "messages": [{"role": "user", "content": [{"text": "hi"}]}]})
        }
        other => panic!("unknown ingress dialect {other}"),
    };
    serde_json::to_vec(&v).unwrap()
}

fn ok_body(egress: &str) -> serde_json::Value {
    if egress == crate::proto_codec::PROTO_ANTHROPIC {
        json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
               "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
               "usage": {"input_tokens": 3, "output_tokens": 2}})
    } else {
        json!({"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "m",
               "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop"}],
               "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}})
    }
}

fn mock_response(fixture: Fixture, egress: &str) -> MockResponse {
    match fixture {
        Fixture::Ok => MockResponse::Ok {
            status: reqwest::StatusCode::OK,
            body: ok_body(egress),
        },
        Fixture::ServerError => MockResponse::ServerError {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body: json!({"error": {"message": "overloaded", "type": "server_error"}}),
        },
    }
}

/// Blank the values a response synthesizes per run — ids, clocks, and busbar's own measured
/// latency — so the comparison is about shape and content rather than about a fresh id or a
/// wall-clock reading taken microseconds apart on two racing legs.
fn normalize(s: &str) -> String {
    fn blank(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    let is_id = k.ends_with("id") || k.ends_with("Id") || k.ends_with("ID");
                    let is_clock = matches!(k.as_str(), "created" | "created_at" | "createTime");
                    let is_latency = k == "latencyMs";
                    if is_id && val.is_string() {
                        *val = serde_json::Value::String("<id>".to_string());
                    } else if (is_clock || is_latency) && val.is_number() {
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
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(mut v) => {
            blank(&mut v);
            v.to_string()
        }
        Err(_) => s.to_string(),
    }
}

/// Headers whose value is minted per response or per run. `retry-after` is here for the same
/// reason the cooldown below is compared as "running or not": the advertised back-off is the
/// jittered cooldown, so two legs of the same fixture legitimately advertise numbers a second or
/// two apart. What is identity-bearing is that BOTH legs advertise one at all, which the header
/// set comparison still holds — a leg that stopped emitting it would drop the key, not change
/// the value.
const VOLATILE_HEADERS: [&str; 6] = [
    "date",
    "request-id",
    "x-request-id",
    "x-amzn-requestid",
    "x-amzn-request-id",
    "retry-after",
];

/// Everything one leg left behind, as comparable strings.
#[derive(Debug, PartialEq, Eq)]
struct Observed(Vec<(&'static str, String)>);

async fn observe(
    resp: Response,
    store: &dyn busbar_substrate::store::LaneRuntime,
    state: &MockServerState,
    ids_drawn: u64,
) -> Observed {
    let mut fields: Vec<(&'static str, String)> = Vec::new();
    fields.push(("status", resp.status().as_u16().to_string()));
    // A volatile header keeps its NAME in the comparison and loses only its value, so a leg that
    // stopped emitting one is still a divergence.
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
    fields.push(("body", normalize(&String::from_utf8_lossy(&body))));
    // The body wrapper records mid-stream outcomes on drop; give it a tick before the store read.
    tokio::task::yield_now().await;
    let state_name = match store.breaker_state_in("p", 0) {
        BreakerState::Closed => "Closed",
        BreakerState::Open { .. } => "Open",
        BreakerState::HalfOpen => "HalfOpen",
    };
    fields.push(("breaker", state_name.to_string()));
    fields.push((
        "cooldown",
        if store.cooldown_remaining_in("p", 0, store_now()) > 0 {
            "running".to_string()
        } else {
            "none".to_string()
        },
    ));
    fields.push(("admissible", store.lane_admissible(0).to_string()));
    fields.push(("budget", format!("{:?}", store.lane_budget_remaining(0))));
    fields.push((
        "upstream_body",
        format!(
            "{:?}",
            state
                .get_last_request_body()
                .map(|b| normalize(&String::from_utf8_lossy(&b)))
        ),
    ));
    fields.push(("correlation_ids_drawn", ids_drawn.to_string()));
    Observed(fields)
}

/// A one-lane deployment in the caller's own dialect, budget-limited so the spend is visible.
/// A macro, not a fn, so the built app's concrete type stays inferred and this file names no
/// core type.
macro_rules! one_lane {
    ($proto:expr, $url:expr) => {
        TestApp::new()
            .lane(LaneSpec::new("m", $proto, $url).provider("test").budget(5))
            .pool("p", &[(0, 1)])
            .build()
    };
}

/// Drive the live shell: resolve the pool exactly as the plane does, then call the engine's own
/// forward entry.
async fn leg_live(proto: &'static str, fixture: Fixture) -> Observed {
    let state = Arc::new(MockServerState::new());
    for _ in 0..8 {
        state.push(mock_response(fixture, proto));
    }
    let server = MockServer::new(state.clone()).await;
    let app = one_lane!(proto, &server.base_url());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let body = Bytes::from(request_body(proto, "p"));
    let (cands, pool_name) = candidates(&rt, "p").expect("the pool resolves");
    let before = host.next_request_id();
    let resp = crate::engine::forward_with_pool_parsed(
        &host,
        &rt,
        cands,
        body.clone(),
        LazyBody::parse(&body).ok(),
        APPLICATION_JSON,
        None,
        None,
        pool_name,
        None,
        proto,
        crate::test_support::CHAT,
        None,
        Vec::new(),
    )
    .await;
    let drawn = host.next_request_id() - before - 1;
    let observed = observe(resp, &*app.store, &state, drawn).await;
    server.shutdown().await;
    observed
}

/// Drive the Route step.
async fn leg_unit(proto: &'static str, fixture: Fixture) -> Observed {
    let state = Arc::new(MockServerState::new());
    for _ in 0..8 {
        state.push(mock_response(fixture, proto));
    }
    let server = MockServer::new(state.clone()).await;
    let app = one_lane!(proto, &server.base_url());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let body = Bytes::from(request_body(proto, "p"));
    let headers = HeaderMap::new();
    let before = host.next_request_id();
    let (seal, token) = tokens();
    let routed = route(
        &token,
        RouteInput {
            host: &host,
            rt: &rt,
            proto,
            op: crate::test_support::CHAT,
            destination: "p",
            headers: &headers,
            body: body.clone(),
            parsed: LazyBody::parse(&body).ok(),
            caller_token: None,
            resolved_gov_key: None,
            usage_sink: None,
            model_not_found_message: None,
        },
    )
    .await;
    let drawn = host.next_request_id() - before - 1;
    let resp = routed.response;
    routed
        .decision
        .into_result(&seal)
        .expect("a resolvable pool must not refuse at Route");
    let observed = observe(resp, &*app.store, &state, drawn).await;
    server.shutdown().await;
    observed
}

/// Same recorded upstream in, same bytes and same breaker mutations out — for every dialect, on
/// a delivered answer and on an exhausted walk, with exactly one correlation id drawn on each
/// leg.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_step_matches_the_live_forward() {
    crate::testkit::install_test_seams();
    let mut failures: Vec<String> = Vec::new();
    let mut cases = 0usize;
    for proto in INGRESS {
        for fixture in [Fixture::Ok, Fixture::ServerError] {
            cases += 1;
            let live = leg_live(proto, fixture).await;
            let unit = leg_unit(proto, fixture).await;
            for ((field, want), (_, got)) in live.0.iter().zip(unit.0.iter()) {
                if want != got {
                    failures.push(format!(
                        "{proto}/{fixture:?}: field `{field}` diverges\n  live: {want}\n  unit: {got}"
                    ));
                }
            }
            assert_eq!(
                live.0
                    .iter()
                    .find(|(k, _)| *k == "correlation_ids_drawn")
                    .map(|(_, v)| v.as_str()),
                Some("1"),
                "the live shell stamps exactly one correlation id per routed unit"
            );
        }
    }
    assert_eq!(cases, 12, "the table collapsed to {cases} cases");
    assert!(
        failures.is_empty(),
        "{} identity failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A three-lane pool behind ONE scripted upstream, so the model the upstream received names the
/// lane that was picked. Six requests per leg, and the two sequences must be the same sequence:
/// a walk that lands on the same bytes by a different pick order is not the same walk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_step_pick_order_matches_the_live_forward() {
    crate::testkit::install_test_seams();
    const ROUNDS: usize = 6;
    let proto = crate::proto_codec::PROTO_OPENAI;

    async fn picks(proto: &'static str, unit_step: bool, rounds: usize) -> Vec<String> {
        let state = Arc::new(MockServerState::new());
        for _ in 0..(rounds * 4) {
            state.push(MockResponse::Ok {
                status: reqwest::StatusCode::OK,
                body: ok_body(proto),
            });
        }
        let server = MockServer::new(state.clone()).await;
        let url = server.base_url();
        let app = TestApp::new()
            .lane(LaneSpec::new("m0", proto, &url).provider("test"))
            .lane(LaneSpec::new("m1", proto, &url).provider("test"))
            .lane(LaneSpec::new("m2", proto, &url).provider("test"))
            .pool("p", &[(0, 1), (1, 1), (2, 1)])
            .build();
        let (host, rt) = crate::engine::test_host_rt(&app);
        let headers = HeaderMap::new();
        let mut seen = Vec::new();
        for _ in 0..rounds {
            let body = Bytes::from(request_body(proto, "p"));
            let resp = if unit_step {
                let (seal, token) = tokens();
                let routed = route(
                    &token,
                    RouteInput {
                        host: &host,
                        rt: &rt,
                        proto,
                        op: crate::test_support::CHAT,
                        destination: "p",
                        headers: &headers,
                        body: body.clone(),
                        parsed: LazyBody::parse(&body).ok(),
                        caller_token: None,
                        resolved_gov_key: None,
                        usage_sink: None,
                        model_not_found_message: None,
                    },
                )
                .await;
                routed
                    .decision
                    .into_result(&seal)
                    .expect("a resolvable pool must not refuse at Route");
                routed.response
            } else {
                let (cands, pool_name) = candidates(&rt, "p").expect("the pool resolves");
                crate::engine::forward_with_pool_parsed(
                    &host,
                    &rt,
                    cands,
                    body.clone(),
                    LazyBody::parse(&body).ok(),
                    APPLICATION_JSON,
                    None,
                    None,
                    pool_name,
                    None,
                    proto,
                    crate::test_support::CHAT,
                    None,
                    Vec::new(),
                )
                .await
            };
            let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
            let upstream = state
                .get_last_request_body()
                .expect("the upstream received a request");
            let v: serde_json::Value =
                serde_json::from_slice(&upstream).expect("the egress body is JSON");
            seen.push(
                v.get("model")
                    .and_then(|m| m.as_str())
                    .unwrap_or("<none>")
                    .to_string(),
            );
        }
        server.shutdown().await;
        seen
    }

    let live = picks(proto, false, ROUNDS).await;
    let unit = picks(proto, true, ROUNDS).await;
    assert_eq!(live.len(), ROUNDS, "every round reached the upstream");
    assert!(
        live.iter().collect::<std::collections::HashSet<_>>().len() > 1,
        "the fixture must actually spread across lanes, else the order proves nothing: {live:?}"
    );
    assert_eq!(
        live, unit,
        "the Route step must walk the lanes in the live path's order"
    );
}

/// A destination that resolves to no lane is a REFUSAL taken after the door — handed back for
/// the Audit step to post, never finished here. The response is the dialect's own not-found.
#[tokio::test]
async fn route_step_refuses_an_unresolved_destination_without_a_terminal() {
    crate::testkit::install_test_seams();
    let app = TestApp::new().build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let proto = crate::proto_codec::PROTO_OPENAI;
    let body = Bytes::from(request_body(proto, "nope"));
    let headers = HeaderMap::new();
    let before = host.next_request_id();
    let (seal, token) = tokens();
    let routed = route(
        &token,
        RouteInput {
            host: &host,
            rt: &rt,
            proto,
            op: crate::test_support::CHAT,
            destination: "nope",
            headers: &headers,
            body: body.clone(),
            parsed: LazyBody::parse(&body).ok(),
            caller_token: None,
            resolved_gov_key: None,
            usage_sink: None,
            model_not_found_message: None,
        },
    )
    .await;
    assert_eq!(
        host.next_request_id() - before - 1,
        0,
        "a unit that never reaches the walk draws no correlation id"
    );
    let resp = routed.response;
    // The facts a miss hands the Meter step: nothing was dialled, so no tap of anyone's accrued
    // anything. Whether a leg was fee-bearing is no longer among them — the fee is the kernel's
    // one decision and it reads the admission's `upstream_candidate`, not the walk's dial.
    assert!(!routed.facts.accrued);
    assert_eq!(routed.facts.status, 404);
    let refusal = routed
        .decision
        .into_result(&seal)
        .expect_err("an unresolved destination must refuse");
    assert_eq!(refusal.reason(), busbar_caps::ReasonCode::NoDestination);
    assert_eq!(
        refusal.step(),
        Some(busbar_caps::StepName::Route),
        "the decision stamps the step, so the record cannot claim it stopped elsewhere"
    );
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        v.to_string().contains("nope"),
        "the refusal names the destination the caller asked for: {v}"
    );
}

/// THE THREE FIGURES ROUTE COULD NOT FILL, filled — on the one end where the tap has already
/// finished by the time the step returns.
///
/// A buffered cross-protocol answer is read WHOLE, translated, and only then handed back, so its
/// completion tap runs inside the walk and its report is on the response the walk returns. The
/// Route step folds it, and the facts the Meter step is bound to name the serving lane, carry the
/// split the dialect's reader found, and say the figures are a charge rather than evidence —
/// where before the fix all three were `None`/`false` by construction.
///
/// The literals are the fixture's own: lane 0, three uncached input tokens and two output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_reports_the_taps_figures_for_an_answer_that_finished() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(mock_response(Fixture::Ok, crate::proto_codec::PROTO_OPENAI));
    let server = MockServer::new(state).await;
    // CROSS-PROTOCOL and non-streaming: an anthropic caller over an openai lane takes the
    // buffered path, which is the path whose tap completes before the walk returns.
    let ingress = crate::proto_codec::PROTO_ANTHROPIC;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("m", crate::proto_codec::PROTO_OPENAI, &server.base_url())
                .provider("test"),
        )
        .pool("p", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let body = Bytes::from(request_body(ingress, "p"));
    let headers = HeaderMap::new();
    let (_seal, token) = tokens();
    let routed = route(
        &token,
        RouteInput {
            host: &host,
            rt: &rt,
            proto: ingress,
            op: crate::test_support::CHAT,
            destination: "p",
            headers: &headers,
            body: body.clone(),
            parsed: LazyBody::parse(&body).ok(),
            caller_token: None,
            resolved_gov_key: None,
            usage_sink: None,
            model_not_found_message: None,
        },
    )
    .await;
    assert_eq!(routed.facts.status, 200, "the answer was delivered");
    assert_eq!(
        routed.facts.lane,
        Some(0),
        "the serving lane the tap named, not the `None` the step used to report"
    );
    assert_eq!(
        routed.facts.usage.as_ref().map(|u| (u.input, u.output)),
        Some((3, 2)),
        "the split the dialect's reader found, carried to the step that reports it"
    );
    assert!(
        !routed.facts.billing_failed,
        "an answer that finished is a charge, not evidence"
    );
    assert!(
        !routed.facts.accrued,
        "the walk held no meter half on this fixture, so the Meter step is the posting — and it \
         now has a lane and a split to post"
    );
    let _ = axum::body::to_bytes(routed.response.into_body(), usize::MAX).await;
    server.shutdown().await;
}

/// An in-process tap capture, so the completion tap can be counted.
struct CaptureTap {
    fired: std::sync::atomic::AtomicUsize,
    last: std::sync::Mutex<Option<Vec<u8>>>,
}

#[async_trait::async_trait]
impl busbar_api::RoutingPolicy for CaptureTap {
    async fn decide(
        &self,
        _req: &busbar_api::RoutingRequest<'_>,
        _cands: &[busbar_api::Candidate<'_>],
        _ctx: &busbar_api::RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> busbar_api::PolicyResult {
        Ok(busbar_api::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "route-step-capture-tap"
    }
    async fn notify(&self, projection: &[u8], _budget: std::time::Duration) {
        *self.last.lock().unwrap() = Some(projection.to_vec());
        self.fired.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The completion tap fires ONCE per routed unit, with the same outcome and the same status the
/// live shell fires it with — and a unit REFUSED before the walk fires none at all, because a
/// pre-forward refusal never reaches the seam that fires it. Both facts are the same fact about
/// where the tap lives: at the end of the walk, not at the end of the unit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn completion_tap_fires_once_on_the_walk_and_never_on_a_pre_forward_refusal() {
    crate::testkit::install_test_seams();
    let proto = crate::proto_codec::PROTO_OPENAI;

    async fn run(
        proto: &'static str,
        destination: &str,
        unit_step: bool,
    ) -> (Arc<CaptureTap>, u16) {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: reqwest::StatusCode::OK,
            body: ok_body(proto),
        });
        let server = MockServer::new(state).await;
        let cap = Arc::new(CaptureTap {
            fired: std::sync::atomic::AtomicUsize::new(0),
            last: std::sync::Mutex::new(None),
        });
        let policy: Arc<dyn busbar_api::RoutingPolicy> = cap.clone();
        let mut app = TestApp::new()
            .lane(
                LaneSpec::new("m", proto, &server.base_url())
                    .provider("test")
                    .budget(5),
            )
            .pool("p", &[(0, 1)])
            .build();
        Arc::get_mut(&mut app)
            .expect("sole owner")
            .tap_hooks_response = vec![(
            std::time::Duration::from_millis(500),
            false,
            policy,
            Vec::new(),
        )];
        let (host, rt) = crate::engine::test_host_rt(&app);
        let body = Bytes::from(request_body(proto, destination));
        let headers = HeaderMap::new();
        let resp = if unit_step {
            let (_seal, token) = tokens();
            route(
                &token,
                RouteInput {
                    host: &host,
                    rt: &rt,
                    proto,
                    op: crate::test_support::CHAT,
                    destination,
                    headers: &headers,
                    body: body.clone(),
                    parsed: LazyBody::parse(&body).ok(),
                    caller_token: None,
                    resolved_gov_key: None,
                    usage_sink: None,
                    model_not_found_message: None,
                },
            )
            .await
            .response
        } else {
            match candidates(&rt, destination) {
                Some((cands, pool_name)) => {
                    crate::engine::forward_with_pool_parsed(
                        &host,
                        &rt,
                        cands,
                        body.clone(),
                        LazyBody::parse(&body).ok(),
                        APPLICATION_JSON,
                        None,
                        None,
                        pool_name,
                        None,
                        proto,
                        crate::test_support::CHAT,
                        None,
                        Vec::new(),
                    )
                    .await
                }
                // The live shell resolves candidates before it forwards, so an unresolved
                // destination never reaches the walk on that path either.
                None => busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::NOT_FOUND,
                    KIND_NOT_FOUND,
                    &busbar_substrate::ingress::not_found_message(destination, None),
                ),
            }
        };
        let status = resp.status().as_u16();
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
        // Taps are detached tasks; give them room to deliver before counting.
        for _ in 0..50 {
            if cap.fired.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        server.shutdown().await;
        (cap, status)
    }

    let (live, live_status) = run(proto, "p", false).await;
    let (unit, unit_status) = run(proto, "p", true).await;
    assert_eq!(live_status, unit_status, "the served status is the same");
    assert_eq!(
        live.fired.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the live shell fires the completion tap exactly once"
    );
    assert_eq!(
        unit.fired.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the Route step fires the completion tap exactly once"
    );
    let live_payload: serde_json::Value =
        serde_json::from_slice(&live.last.lock().unwrap().clone().expect("live tap fired"))
            .unwrap();
    let unit_payload: serde_json::Value =
        serde_json::from_slice(&unit.last.lock().unwrap().clone().expect("unit tap fired"))
            .unwrap();
    assert_eq!(live_payload["stage"], unit_payload["stage"]);

    // The pre-forward refusal: no walk, so no completion tap, on either path.
    let (live_miss, live_miss_status) = run(proto, "missing", false).await;
    let (unit_miss, unit_miss_status) = run(proto, "missing", true).await;
    assert_eq!(live_miss_status, 404);
    assert_eq!(unit_miss_status, 404);
    assert_eq!(
        live_miss.fired.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a pre-forward refusal fires no completion tap on the live path"
    );
    assert_eq!(
        unit_miss.fired.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a pre-forward refusal fires no completion tap through the Route step either"
    );
}

/// NAMING THE LEGS RE-DERIVES NOTHING, INTERNS NOTHING AND LOCKS NOTHING.
///
/// A leg names a lane and a dial target as borrowed static strings, and both are a pure
/// function of the lane row config froze at table-build time. Deriving them again while the
/// plan is being built means one process-wide vocabulary acquisition per candidate per side —
/// two per candidate — plus the node's own registration held across the whole candidate loop,
/// all to recompute a value that could not have changed since the generation was published.
///
/// Measured, not argued, and measured on names NO other test in this image uses. That is what
/// makes the count a proof rather than a coincidence: the process vocabulary is cold for these
/// names until something interns them, so a planner that interns MUST grow it — and grow it per
/// candidate per side — while a planner that reads a seated field cannot grow it at all. The
/// vocabulary mutex is taken by exactly one thing, `Registration::key`, and a `key` call on a
/// cold name is a call this counter sees; zero growth over four cold candidates is therefore
/// zero acquisitions.
///
/// The allocation count is the same claim from the other side. ONE is the floor and one is the
/// contract: `RoutePlan::legs` is a `BoundedVec` over a heap `Vec`, so filling it takes exactly
/// one buffer however many legs are pushed. Interning a cold name leaks a fresh `Box` and grows
/// a set, so anything above one here is naming work that has crept back onto the request path.
///
/// Four candidates, so a per-candidate cost cannot hide inside a slack bound. Do not raise
/// either number to make a change green.
#[test]
fn naming_the_legs_over_a_pool_interns_nothing_and_allocates_only_the_plan() {
    use crate::CountingJemalloc;

    crate::testkit::install_test_seams();
    let proto = crate::proto_codec::PROTO_OPENAI;

    // WARM every first-touch lazy static this path can reach — the interner stand-in, the
    // tables seam, the allocator's own bookkeeping — on a deployment whose names the rest of
    // this file already interns. A first touch is a per-process cost, not a per-request one,
    // and warming it HERE keeps the gate deployment below cold.
    let warm = TestApp::new()
        .lane(LaneSpec::new("m", proto, "http://127.0.0.1:9").provider("test"))
        .pool("p", &[(0, 1)])
        .build();
    let (_warm_host, warm_rt) = crate::engine::test_host_rt(&warm);
    let (warm_cands, _) = candidates(&warm_rt, "p").expect("the warm pool resolves");
    let _ = plan_over(&warm_rt, &warm_cands);

    // THE GATE DEPLOYMENT: four lanes behind one pool, under names nothing else spells.
    let url = "http://127.0.0.1:9/leg-naming-gate";
    let mut builder = TestApp::new();
    for i in 0..4 {
        builder = builder
            .lane(LaneSpec::new(&format!("leg-naming-gate-m{i}"), proto, url).provider("test"));
    }
    let app = builder
        .pool("leg-naming-gate-p", &[(0, 1), (1, 1), (2, 1), (3, 1)])
        .build();
    let (_host, rt) = crate::engine::test_host_rt(&app);
    let (cands, _) = candidates(&rt, "leg-naming-gate-p").expect("the gate pool resolves");
    assert_eq!(cands.len(), 4, "the gate pool must be four lanes wide");

    let vocabulary_before = Registration::interned();
    let _ = CountingJemalloc::reset();
    let plan = plan_over(&rt, &cands);
    let allocs = CountingJemalloc::count();
    let vocabulary_after = Registration::interned();

    assert_eq!(
        plan.legs.len(),
        4,
        "every candidate must still be named as a leg"
    );
    assert_eq!(
        vocabulary_after - vocabulary_before,
        0,
        "naming the legs of a planned walk interned {} fresh name(s) on the request path",
        vocabulary_after - vocabulary_before
    );
    assert_eq!(
        allocs, 1,
        "naming the legs of a planned walk allocates the plan's own leg buffer and nothing else"
    );
}
