// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE STEP — the governed hop that performs the actual work.
//!
//! Route is the fifth of the unit's seven steps, and the only one that touches an upstream. What it
//! owns, in call order, is exactly what the legacy shell owned between the admission door and the
//! terminal:
//!
//! 1. **Candidate resolution.** The admitted destination resolves to a configured pool, or to a
//!    single bare lane, or to nothing at all. Nothing-at-all is a REFUSAL, and — because the door
//!    has already run and the caller has already been charged — it is a refusal the Audit step must
//!    post with the pool label and the charge flag, not one that can be quietly turned away. This
//!    step therefore hands it back as [`Routed::Refused`] and calls no terminal door itself.
//! 2. **The affinity header and the forwardable client headers**, read off the arrival's headers.
//! 3. **The correlation id, stamped exactly once**, and only on a unit that reaches this step. It is
//!    the join key between the routing messages emitted before the response and the completion tap
//!    fired after it, so it is taken here — one monotonic read — and threaded through the whole
//!    walk. A unit refused before Route stamps none, which is why the counter never double-advances
//!    and request-id sequences are identical run to run.
//! 4. **The completion-shape capture**, taken BEFORE the parsed body moves into the walk, so the tap
//!    fired after the response head is known describes the request that was actually sent.
//! 5. **The walk itself.** One deadline check per hop, the pick, and the ONE attempt — `max_hops`
//!    plus the first try, so the loop runs `0..=max_hops`. The pick order, the exclusion of a lane
//!    that has been tried, the context-length narrowing and the hand-off to the exhaustion
//!    dispositions are the engine's, unchanged and uncopied: this step calls them.
//! 6. **The completion tap**, fired once, with the outcome the response actually carries.
//!
//! ## What this step deliberately does not do
//!
//! It does not open or close a hold, it does not meter, and it never returns a finished response.
//! The two terminal doors live in the Audit step and are reached from there and from nowhere else —
//! including on the candidate-miss path above, which is why that path returns a variant rather than
//! a `Response`. It also does not select: `pick_among` is the one selection site and the engine's
//! walk owns it, so a second ordering policy cannot grow beside the first by growing here.
//!
//! ## The bodies are today's functions
//!
//! Everything below either calls the engine or reproduces the wrapper the engine's walk was already
//! wrapped in. Nothing here is a second implementation of the walk, the pick, the attempt or the
//! taps, and the identity tests at the bottom of this file hold that to the byte: same recorded
//! upstream, same client bytes, same breaker mutations, same pick order and the same single
//! correlation stamp through this step as through the live path.

// BUILT DARK. This step has no production caller until the unit's own shell is assembled and the
// composition root installs its ingress tables; until then the only thing that drives it is the
// identity harness below, which is the point of building it dark in the first place. The allow is
// scoped to this file rather than the directory so it retires with the step it covers.
#![allow(dead_code)]

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::Value;

use busbar_substrate::observability::HOTPATH_LEVEL;
use busbar_substrate::plane_host::EngineHost;

use crate::engine::{
    capture_stage_shape, fire_stage_taps, forwardable_client_header_names, EngineTables, GateRejected,
    LazyBody, NativeRuntime, UsageSink, WeightedLane, APPLICATION_JSON, KIND_NOT_FOUND,
};
use crate::native_ingress::affinity_header_for;

/// Everything the Route step borrows or takes ownership of for one unit.
///
/// The shape mirrors what the kernel's `route` method is handed plus what a plane's own step needs
/// to reach its egress: the loop supplies the unit's identity and its meter, and the plane supplies
/// the arrival it decoded and the admission the door produced. `destination` is the model the charge
/// actually LANDED on — a budget downgrade re-pools the admission, and dispatching through the pool
/// the client asked for after charging a different one is the bug that ordering makes impossible.
pub(crate) struct RouteInput<'a> {
    pub(crate) host: &'a Arc<dyn EngineHost>,
    pub(crate) rt: &'a Arc<NativeRuntime>,
    pub(crate) proto: &'static str,
    pub(crate) op: busbar_substrate::handlers::Op,
    /// The admitted destination — post-downgrade, never the requested one.
    pub(crate) destination: &'a str,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) body: Bytes,
    /// The body the Arrival step validated, carried as the lazy head projection. `None` for an
    /// opaque (multipart/binary) body, which relays at the byte level.
    pub(crate) parsed: Option<LazyBody>,
    pub(crate) caller_token: Option<&'a str>,
    /// The key the Authenticate step resolved, so a group or SSO principal still projects its
    /// routing signals for a pool that reads them.
    pub(crate) resolved_gov_key: Option<&'a Arc<busbar_api::VirtualKey>>,
    /// The meter half of the hold, built at the door: it carries the admission grant, so the leases
    /// live exactly as long as the response body does.
    pub(crate) usage_sink: Option<UsageSink>,
    /// A dialect's pre-shaped candidate-miss body, or `None` for the neutral copy.
    pub(crate) model_not_found_message: Option<&'a str>,
}

/// What the Route step produced.
///
/// Both arms carry a response, and neither is finished: the Audit step posts one of them. The split
/// is which door it posts through — a unit that reached an upstream (or the pool's own exhaustion
/// answer) is a completed route; a destination that never resolved is a refusal taken AFTER the
/// door, so it is charged and audited as one.
pub(crate) enum Routed {
    /// The walk ran. The response is whatever it produced — a delivered body, a relayed upstream
    /// error, or the exhaustion disposition's own answer.
    Completed(Response),
    /// The destination did not resolve to any lane. Nothing was dispatched; the caller was still
    /// charged at the door.
    Refused(Response),
}

/// The candidate set for one destination: a configured pool's members, or the single lane a bare
/// model name resolves to, or nothing.
///
/// The pool cell name that rides alongside is the breaker's key and the exhaustion config's lookup:
/// a bare model lane routes on the default (empty) cell, exactly as it always has.
pub(crate) fn candidates<'a>(
    rt: &Arc<NativeRuntime>,
    destination: &'a str,
) -> Option<(Vec<WeightedLane>, &'a str)> {
    if let Some(members) = EngineTables::new(rt).pools().get(destination) {
        Some((members.clone(), destination))
    } else {
        EngineTables::new(rt).by_model().get(destination).map(|&i| {
            (
                vec![WeightedLane {
                    reasoning: None,
                    idx: i,
                    weight: 1,
                    attempt_timeout_ms: None,
                }],
                "",
            )
        })
    }
}

/// The Route step.
pub(crate) async fn route(input: RouteInput<'_>) -> Routed {
    let RouteInput {
        host,
        rt,
        proto,
        op,
        destination,
        headers,
        body,
        mut parsed,
        caller_token,
        resolved_gov_key,
        usage_sink,
        model_not_found_message,
    } = input;

    // Candidate resolution. A miss is a post-door refusal, shaped in the caller's own dialect and
    // handed back for the Audit step to post — this step opens no door and closes none.
    let Some((cands, pool_name)) = candidates(rt, destination) else {
        return Routed::Refused(busbar_substrate::proxy::ingress_error(
            proto,
            StatusCode::NOT_FOUND,
            KIND_NOT_FOUND,
            &busbar_substrate::ingress::not_found_message(destination, model_not_found_message),
        ));
    };

    // The egress content type is the arrival's own, borrowed — the byte-level codecs need the
    // multipart boundary and nothing here needs an owned copy.
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let req_content_type = if ct.is_empty() { APPLICATION_JSON } else { ct };
    // Sticky routing is an engine capability, so the affinity header is read for every operation,
    // not just for chat.
    let affinity_key: Option<String> = headers
        .get(affinity_header_for(rt, destination))
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    // Opt-in client beta/version headers, collected against this plane's forwardable set. Empty ⇒
    // byte-identical egress.
    let client_fwd =
        busbar_substrate::proxy::collect_client_headers(headers, &forwardable_client_header_names());

    let span = tracing::span!(
        HOTPATH_LEVEL,
        "forward",
        pool = %pool_name,
        ingress = %proto,
        op = op.name(),
        transport = op.transport().name(),
        request_id = tracing::field::Empty
    );
    let resp = {
        use tracing::Instrument;
        async move {
            // THE CORRELATION STAMP, taken exactly once and only here. Every routing message the
            // walk emits and the completion tap fired below carry this same value; that identity is
            // the whole join-key contract, and it is why the read is not repeated after the walk
            // has returned and the walk's own context has gone out of scope.
            let request_id = host.next_request_id();
            tracing::Span::current().record("request_id", request_id);
            // The completion shape is captured BEFORE the parsed body moves into the walk. Zero cost
            // when no response tap is configured — the empty-list branch builds nothing and never
            // materializes the body tree.
            let completion_shape = if host.tap_hooks_response().is_empty() {
                None
            } else {
                let stream = parsed
                    .as_ref()
                    .and_then(|b| b.probe().get("stream"))
                    .and_then(|s| s.as_bool())
                    .unwrap_or(false);
                let dom: Option<&Value> = match parsed.as_mut() {
                    Some(l) => l.ensure_dom().ok().map(|m| &*m),
                    None => None,
                };
                Some(capture_stage_shape(
                    dom,
                    &body,
                    req_content_type,
                    pool_name,
                    proto,
                    Some(op.operation),
                    stream,
                    request_id,
                ))
            };

            // THE WALK: the deadline check per hop, the one pick site, the one attempt, the
            // context-length narrowing and the exhaustion hand-off. Called, not copied.
            let resp = crate::engine::pipeline::forward_with_pool_parsed_inner(
                host,
                rt,
                cands,
                body,
                parsed,
                req_content_type,
                caller_token,
                resolved_gov_key,
                pool_name,
                affinity_key.as_deref(),
                proto,
                op,
                usage_sink,
                request_id,
                client_fwd,
            )
            .await;

            if let Some(shape) = completion_shape {
                // A gate-produced rejection is its own synthetic outcome; otherwise the served
                // status decides. For a streaming response this fires at head time — the status is
                // known, the body is still flowing.
                let outcome = if resp.extensions().get::<GateRejected>().is_some() {
                    "rejected_by_gate"
                } else if resp.status().is_success() {
                    "ok"
                } else {
                    "failed"
                };
                fire_stage_taps(
                    host.tap_hooks_response(),
                    &shape,
                    busbar_substrate::hooks::wire::HookStageProjection {
                        at: "response",
                        model: None,
                        attempt_number: None,
                        remaining_candidates: None,
                        previous_failure: None,
                        outcome: Some(outcome),
                        status: Some(resp.status().as_u16()),
                    },
                    resolved_gov_key.and_then(|k| k.group.as_deref()),
                    &**host,
                );
            }
            resp
        }
        .instrument(span)
        .await
    };
    Routed::Completed(resp)
}

/// THE ROUTE-STEP IDENTITY HARNESS: this step against the live path it was lifted from.
///
/// Each case builds two identical deployments — own lane store, own scripted upstream — drives one
/// leg through `engine::forward_with_pool_parsed` (the shell the legacy plane calls) and the other
/// through [`route`], and compares what a client and an operator can see: the status, the headers
/// minus the per-response volatiles, the body, the lane's breaker state and cooldown, its remaining
/// budget, and the request the upstream actually received. The pick order gets its own case,
/// because a walk that lands on the same bytes by a different route is not the same walk.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_substrate::store::{now as store_now, BreakerState};
    use serde_json::json;

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
                        let is_clock =
                            matches!(k.as_str(), "created" | "created_at" | "createTime");
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
        let routed = route(RouteInput {
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
        })
        .await;
        let drawn = host.next_request_id() - before - 1;
        let resp = match routed {
            Routed::Completed(resp) => resp,
            Routed::Refused(_) => panic!("a resolvable pool must not refuse at Route"),
        };
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
                    match route(RouteInput {
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
                    })
                    .await
                    {
                        Routed::Completed(resp) => resp,
                        Routed::Refused(_) => panic!("a resolvable pool must not refuse at Route"),
                    }
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
        let routed = route(RouteInput {
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
        })
        .await;
        assert_eq!(
            host.next_request_id() - before - 1,
            0,
            "a unit that never reaches the walk draws no correlation id"
        );
        let resp = match routed {
            Routed::Refused(resp) => resp,
            Routed::Completed(_) => panic!("an unresolved destination must refuse"),
        };
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
            self.fired
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
                match route(RouteInput {
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
                })
                .await
                {
                    Routed::Completed(resp) | Routed::Refused(resp) => resp,
                }
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
}
