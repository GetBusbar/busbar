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
//!    step therefore refuses in its own [`Routed::decision`] and calls no terminal door itself.
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
//! including on the candidate-miss path above, which is why that path answers with a refusing
//! decision rather than with a posted `Response`. It also does not select: `pick_among` is the one
//! selection site and the engine's walk owns it, so a second ordering policy cannot grow beside the
//! first by growing here.
//!
//! It does not meter, and that is now a claim with a mechanism behind it rather than a promise: the
//! walk it calls is handed the admission's meter half and ITS taps accrue, which is where a streamed
//! answer's usage becomes known at all. What this step does is report that — [`MeterFacts`] — so the
//! Meter step seals what the tap posted instead of posting a second copy of it.
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

use busbar_caps::{step::Route, Decision, LaneId, ReasonCode, Refusal, RoutePlan, UnitToken};
use busbar_contract::{DestinationFacts, Leg, Registration, UpstreamAddress};
use busbar_substrate::observability::HOTPATH_LEVEL;
use busbar_substrate::plane_host::EngineHost;

use crate::unit::meter::MeterFacts;

use crate::engine::{
    capture_stage_shape, fire_stage_taps, forwardable_client_header_names, EngineTables,
    GateRejected, LazyBody, NativeRuntime, TapCell, UsageSink, WeightedLane, APPLICATION_JSON,
    KIND_NOT_FOUND,
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
    /// THE NODE'S INTERNER, held by the composition root and lent for the length of the unit.
    ///
    /// A leg names a lane and a dial target, and both are `&'static str` on the contract's side
    /// while a configured lane's name and base URL are runtime `String`s read out of config. The
    /// bridge is interning them ONCE — the root's job, and the same one the trust unit crosses to
    /// seal a verified destination — so the plan this step returns names the deployment's own lanes
    /// rather than a literal spelled in a source file. Idempotent and bounded by the number of
    /// configured lanes, so a request path may cross it.
    pub(crate) lanes: &'a std::sync::Mutex<Registration>,
}

/// What the Route step produced.
///
/// [`Routed::decision`] is exactly what the kernel's `Units::route` returns: proceed with the plan
/// the walk ran, or refuse where the destination resolved to no lane at all. That refusal is taken
/// AFTER the door, so the unit was charged and it is audited through the CHARGED terminal like any
/// other post-door end — the decision says which end it was, and the response is the bytes either
/// way. Nothing here is finished: the Audit step posts it, as it posts every other unit.
///
/// [`Routed::facts`] is the half that did not exist. The Meter step asks for the serving lane, the
/// reported usage, the client-facing status and the billing-failed fact, and a response carries
/// none of them; now the step that watched the walk hands them over, along with the one fact that
/// decides where the unit's single accrual is made.
pub(crate) struct Routed {
    /// The sealed step-5 answer.
    pub(crate) decision: Decision<Route>,
    /// The bytes the walk produced — a delivered body, a relayed upstream error, the exhaustion
    /// disposition's own answer, or the candidate-miss refusal. Never posted here.
    pub(crate) response: Response,
    /// What the Meter step is bound to.
    pub(crate) facts: MeterFacts,
    /// The admission's meter half, handed BACK unspent when this step never reached the walk. A
    /// walk that ran took it, and its taps own the accrual; a candidate miss never dispatched, so
    /// the sink returns for the Meter step to decide about.
    pub(crate) meter_sink: Option<UsageSink>,
}

// The shape of this step is not pinned as a `fn` alias the way the synchronous steps' are, and the
// reason is the `async`: an async fn's future is an opaque type with no name, so a type alias for
// it would have to box the future and would then be pinning the shape of a boxed adapter rather
// than the shape of the step. The signature is held by the compiler at the one call site instead —
// the token in, the sealed answer out — which is the same guarantee by a different instrument.

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

/// The plan a resolved destination names: one leg per candidate lane, in the order the walk takes
/// them.
///
/// A candidate the tables no longer hold is skipped rather than guessed at, and the leg count is
/// bounded by the contract (`MAX_LEGS`) because a unit is one authorization — a pool wider than the
/// bound plans the legs it is allowed to plan and the walk still walks every candidate it was
/// handed, because the walk is driven by the candidate list and not by this value.
fn plan_over(
    rt: &Arc<NativeRuntime>,
    cands: &[WeightedLane],
    lanes: &std::sync::Mutex<Registration>,
) -> RoutePlan {
    let tables = EngineTables::new(rt);
    let all = tables.lanes();
    let mut plan = RoutePlan::default();
    let mut reg = lanes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for c in cands {
        let Some(lane) = all.get(c.idx) else {
            continue;
        };
        let facts = DestinationFacts::Upstream {
            // The family that dials an LLM lane. A lane's `protocol` is its DIALECT, which is a
            // different question from which transport carries it.
            transport: busbar_substrate::transport::Transport::Http.name(),
            address: UpstreamAddress::Socket {
                authority: reg.key(&lane.base_url),
                sni: None,
            },
            lane: LaneId::new(reg.key(&lane.model)),
        };
        if plan.legs.push(Leg { destination: facts }).is_err() {
            break;
        }
    }
    plan
}

/// WHAT THE WALK SAW, before a token seals it.
///
/// The same four things [`Routed`] carries, minus the one that cannot cross a thread: a
/// `Decision<Route>` can only be built with the step's own token, and the token is minted for the
/// length of the loop's call on the thread the loop runs on. The walk itself is asynchronous and the
/// loop is not, so the two are on opposite sides of a channel — and a channel carries values, not
/// borrows. So the walk answers with the REFUSAL or the PLAN and the sealing happens back where the
/// token is, in [`route`], which is the only caller that has one.
pub(crate) struct RouteParts {
    /// The refusal this walk raised, or `None` where it proceeded. Exactly one of this and `plan`
    /// is `Some`.
    pub(crate) refusal: Option<Refusal>,
    /// The plan the walk ran, where it ran one.
    pub(crate) plan: Option<RoutePlan>,
    /// The bytes the walk produced. Never posted here.
    pub(crate) response: Response,
    /// What the Meter step is bound to.
    pub(crate) facts: MeterFacts,
    /// The admission's meter half, handed back unspent where the walk never took it.
    pub(crate) meter_sink: Option<UsageSink>,
}

/// The Route step.
///
/// The body is [`route_parts`]; this is the sealing, and it is the whole of the difference between
/// them. Keeping the two apart is what lets a driver run the walk on the runtime and seal the answer
/// on the thread the loop's token was minted on, without either half learning about the other's.
pub(crate) async fn route(unit_token: &UnitToken<Route>, input: RouteInput<'_>) -> Routed {
    seal(unit_token, route_parts(input).await)
}

/// Seal what the walk saw with the step's own token.
pub(crate) fn seal(unit_token: &UnitToken<Route>, parts: RouteParts) -> Routed {
    let RouteParts {
        refusal,
        plan,
        response,
        facts,
        meter_sink,
    } = parts;
    let decision = match refusal {
        Some(refusal) => Decision::refuse(unit_token, refusal),
        // A walk that did not refuse ran a plan; the `unwrap_or_default` is the empty plan a
        // refusing walk would have carried, and it is unreachable from the two constructions below.
        None => Decision::proceed(unit_token, plan.unwrap_or_default()),
    };
    Routed {
        decision,
        response,
        facts,
        meter_sink,
    }
}

/// The Route step's body: candidates, the pick, the walk, the completion tap.
pub(crate) async fn route_parts(input: RouteInput<'_>) -> RouteParts {
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
        lanes,
    } = input;

    // Candidate resolution. A miss is a post-door refusal, shaped in the caller's own dialect and
    // handed back for the Audit step to post — this step opens no door and closes none. The meter
    // half comes back unspent with it: nothing was dispatched, so nothing took it.
    let Some((cands, pool_name)) = candidates(rt, destination) else {
        let response = busbar_substrate::proxy::ingress_error(
            proto,
            StatusCode::NOT_FOUND,
            KIND_NOT_FOUND,
            &busbar_substrate::ingress::not_found_message(destination, model_not_found_message),
        );
        return RouteParts {
            facts: MeterFacts {
                // No lane answered and none could: the name resolved to nothing.
                lane: None,
                usage: None,
                status: response.status().as_u16(),
                billing_failed: false,
                // Nothing was dialled, so this is not a fee-bearing upstream leg.
                upstream_leg: false,
                // The walk never ran, so no tap of its can have accrued anything.
                accrued: false,
            },
            meter_sink: usage_sink,
            refusal: Some(Refusal::new(ReasonCode::NoDestination)),
            plan: None,
            response,
        };
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
    let client_fwd = busbar_substrate::proxy::collect_client_headers(
        headers,
        &forwardable_client_header_names(),
    );

    // THE PLAN, named before the walk runs it: one leg per candidate the destination resolved to,
    // in the order the walk was handed them. The lane and the dial target are the deployment's own
    // runtime strings, interned once through the node's registration.
    let plan = plan_over(rt, &cands, lanes);

    // The walk is about to take the meter half, and its taps are where this unit's accrual is made
    // — see the Meter step's header for why a streamed answer's usage can become known nowhere
    // else. Recorded here, before the move, because after it there is nothing left to ask.
    let accrued = usage_sink.is_some();

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
    // THE TAP'S REPORT-BACK, taken off the response the walk handed back. The serving lane, the
    // usage the dialect's reader found and the terminal-error fact are resolved INSIDE the walk, at
    // the tap that accrues them — the walk answers with a response, not with a lane — so this is how
    // they reach the step that has to report them.
    //
    // For a BUFFERED answer the tap has already finished: the body was read whole before it was
    // translated, so the cell is filled here and the three figures below are the tap's own. For a
    // STREAMED answer the cell is still empty, because the response is served on its headers and its
    // figures do not exist yet — so the fields stay as they were, `accrued` says the tap owns the
    // posting, and the Meter step reads the cell later, when it has been filled.
    let mut facts = MeterFacts {
        // Empty until the tap says otherwise, which is the state a stream leaves them in.
        lane: None,
        usage: None,
        // The status the CLIENT saw, which is the fee basis and is known at the head either way.
        status: resp.status().as_u16(),
        billing_failed: false,
        // The walk resolved candidates and dialled, so this is a fee-bearing client request.
        upstream_leg: true,
        accrued,
    };
    if let Some(report) = resp
        .extensions()
        .get::<TapCell>()
        .and_then(|cell| cell.get())
    {
        facts.fold(report);
    }
    RouteParts {
        facts,
        // The walk took it.
        meter_sink: None,
        // The plan the walk ran, for the token to seal as the step's answer.
        refusal: None,
        plan: Some(plan),
        response: resp,
    }
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
    use busbar_caps::KernelSeal;
    use busbar_substrate::store::{now as store_now, BreakerState};
    use serde_json::json;

    /// THE INTERNER the composition root would lend, standing in for it here — process-wide and
    /// idempotent, so a second leg over the same deployment leaks nothing further. A per-call one
    /// would be a leak per request wearing a test's clothes.
    static LANES: std::sync::LazyLock<std::sync::Mutex<Registration>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(Registration::new()));

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
                lanes: &LANES,
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
                            lanes: &LANES,
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
                lanes: &LANES,
            },
        )
        .await;
        assert_eq!(
            host.next_request_id() - before - 1,
            0,
            "a unit that never reaches the walk draws no correlation id"
        );
        let resp = routed.response;
        // The facts a miss hands the Meter step: nothing was dialled, so there is no fee-bearing
        // leg and no tap of anyone's accrued anything.
        assert!(!routed.facts.upstream_leg);
        assert!(!routed.facts.accrued);
        assert_eq!(routed.facts.status, 404);
        let refusal = routed
            .decision
            .into_result(&seal)
            .expect_err("an unresolved destination must refuse");
        assert_eq!(refusal.reason(), busbar_caps::ReasonCode::NoDestination);
        assert_eq!(
            refusal.step(),
            busbar_caps::StepName::Route,
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
                lanes: &LANES,
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
                        lanes: &LANES,
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
}
