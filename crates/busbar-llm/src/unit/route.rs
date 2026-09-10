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
use busbar_contract::{DestinationFacts, Leg, UpstreamAddress};
use busbar_substrate::observability::HOTPATH_LEVEL;
use busbar_substrate::plane_host::EngineHost;

use crate::unit::meter::MeterFacts;

// R4-0a. THE ALREADY-NEUTRAL HALF, NAMED AT ITS TRUE HOME. `fire_stage_taps`, `APPLICATION_JSON`
// and `KIND_NOT_FOUND` are defined in the neutral substrate and were reaching this step only
// because `engine/mod.rs` re-exports them into the flattened engine namespace. Naming the substrate
// directly is a BY-IDENTITY repoint — the very same items, resolved one hop earlier — so the bytes
// this step emits cannot change, and one more engine name leaves the step files.
use busbar_substrate::proxy::proxy_vocab::fire_stage_taps;
use busbar_substrate::proxy::{APPLICATION_JSON, KIND_NOT_FOUND};

use crate::engine::{
    capture_stage_shape, forwardable_client_header_names, EngineTables, GateRejected, LazyBody,
    NativeRuntime, TapCell, UsageSink, WeightedLane,
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
    pub(crate) resolved_gov_key: Option<&'a Arc<busbar_contract::store::VirtualKey>>,
    /// The meter half of the hold, built at the door: it carries the admission grant, so the leases
    /// live exactly as long as the response body does.
    pub(crate) usage_sink: Option<UsageSink>,
    /// A dialect's pre-shaped candidate-miss body, or `None` for the neutral copy.
    pub(crate) model_not_found_message: Option<&'a str>,
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
///
/// The two names a leg is written in are READ, not derived: the lane row carries its dial target and
/// its lane name already seated as the node's interned statics, put there when the generation's
/// table was built. So this takes no lock at all — neither the node's registration, which used to be
/// held across the whole candidate loop, nor the process vocabulary behind it, which used to be
/// taken twice per candidate to recompute a value that had been constant since boot.
fn plan_over(rt: &Arc<NativeRuntime>, cands: &[WeightedLane]) -> RoutePlan {
    let tables = EngineTables::new(rt);
    let all = tables.lanes();
    let mut plan = RoutePlan::default();
    for c in cands {
        let Some(lane) = all.get(c.idx) else {
            continue;
        };
        let facts = DestinationFacts::Upstream {
            // The family that dials an LLM lane. A lane's `protocol` is its DIALECT, which is a
            // different question from which transport carries it.
            transport: busbar_substrate::transport::Transport::Http.name(),
            address: UpstreamAddress::Socket {
                authority: lane.authority,
                sni: None,
                extras: &[],
            },
            lane: LaneId::new(lane.lane_id),
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
    let plan = plan_over(rt, &cands);

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
    // figures do not exist yet — so the fields stay as they were and `accrued` says the tap owns the
    // posting.
    //
    // This fold is a snapshot of the cell at THIS instant, not a promise about a later one. The cell
    // rides on the response, so the walk folds it once more just before the Meter step binds — which
    // catches every end that finished in between. What NO fold can catch is a stream still flowing
    // at step 6: its terminal usage frame arrives after the client has its bytes, so its report is
    // empty by construction and the tap's own accrual is the unit's one accrual. See the Meter
    // step's header.
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
#[path = "tests/route.rs"]
mod tests;
