// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WALK — the per-request carry the composition root's loop drives this plane's steps over.
//!
//! Seven of the nine step files beside this one are typed entirely in vocabulary a composition root
//! may name: the neutral host seam, the public governance context, `busbar-caps` tokens and
//! decisions. The root calls those seven directly, which is the point of the step files.
//!
//! TWO ARE NOT, and this file is why they are not. `route::RouteInput` and `meter::MeterCtx` name
//! the engine's own per-request values — the lazily projected body, the runtime table handle, the
//! admission's meter half, the serving lane row — and every one of those is crate-private, because
//! the engine is this plane's own machinery and not part of the plane ABI. A root that could name
//! them would be a root that had learned how this plane forwards, which is the one thing the ABI
//! exists to prevent. So the carry lives HERE, beside the steps, and the root drives those two
//! through a value it holds and never looks inside.
//!
//! THE OTHER THING THIS FILE OWNS is the runtime seam, and it is now a seam with nothing in it. The
//! loop's Route step is a future the loop awaits on the caller's own runtime, so the walk IS that
//! future: it is polled by whichever task is serving this request, on the thread that task is
//! already running on. Nothing is spawned, nothing is joined, no thread is parked for the length of
//! an upstream call, and a client that goes away drops this future exactly as it drops the loop's.
//!
//! WHAT THIS FILE IS NOT. It decides nothing. Every judgement below belongs to the step file it is
//! delegated to; what is here is the carry between them and the thread the walk runs on.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::Response;

use busbar_caps::{Decision, Meter, Outcome, Route, UnitToken, UsageToken};
use busbar_contract::Registration;
use busbar_substrate::plane_host::{EngineHost, EngineTablesView};

use crate::unit::admit::Admitted;
use crate::unit::arrival::BodyArrival;
use crate::unit::meter::{MeterCtx, MeterFacts};
use crate::unit::route::RouteInput;

/// Everything one request arrives with, as the composition root hands it over.
///
/// Plain data, and every field is public vocabulary: this is the ONE value that crosses from the
/// root into the plane per unit, so the crossing is readable at both ends.
pub struct WalkArrival {
    /// The neutral engine host, minted core-side over the live snapshot.
    pub host: Arc<dyn EngineHost>,
    /// This request's governance context — the resolved key, or none.
    pub gov: busbar_api::PlaneRequestCtx,
    /// The ingress dialect.
    pub proto: &'static str,
    /// The operation the dialect resolved off its own endpoint.
    pub operation: busbar_api::operation::Operation,
    /// The caller's bearer token, for passthrough forwarding.
    pub caller_token: Option<String>,
    /// The request headers, as they arrived.
    pub headers: HeaderMap,
    /// The request body, as it arrived.
    pub body: Bytes,
    /// THE NODE'S INTERNER, held by the composition root and lent for the length of the unit. A
    /// configured lane's name is a runtime `String` and a `LaneId` is a borrowed static one; this is
    /// the bridge, and it is the root's because leaking is the root's decision to make.
    pub lanes: Arc<Mutex<Registration>>,
    /// WHAT THE URL SAID, on the two surfaces whose model rides the path rather than the body.
    ///
    /// `None` is a body-model unit, which is every other surface on this plane. Where it is `Some`,
    /// the dialect's own parse has already read the model, the stream intent, the framing that intent
    /// selects and the dialect's own model-miss copy — and all four are facts about the request that
    /// steps 0, 1 and 5 read. They ride HERE, in the unit's own carry, because a unit is a future
    /// that yields at its Route step and may be resumed on another thread: anything pinned to the
    /// thread the unit started on is a fact the rest of the unit cannot safely read, and a fact the
    /// NEXT unit on that thread might.
    pub path: Option<crate::arrival::PathModelFacts>,
}

/// What the walk has established so far.
///
/// Behind one lock because the loop hands each step `&self` and the steps run in a fixed order: two
/// of these are never in flight at once, and the lock is what makes that readable rather than
/// assumed.
#[derive(Default)]
struct Carry {
    /// What the Arrival step read: the pristine bytes and their head projection.
    arrived: Option<BodyArrival>,
    /// The admission's meter half, built at the door and carried to the walk.
    sink: Option<crate::engine::UsageSink>,
    /// Whether the admission charge landed.
    charged: bool,
    /// The pool the charge landed on — post-downgrade, never the requested one.
    effective: Option<String>,
    /// Whether the verified set offered an upstream to route to.
    upstream_candidate: bool,
    /// The bytes some step already rendered and no step has posted.
    pending: Option<Response>,
    /// What the Route step observed, for the Meter step to be bound to.
    facts: Option<MeterFacts>,
    /// The meter half the walk handed back unspent.
    meter_sink: Option<crate::engine::UsageSink>,
    /// Whether the Meter step made the accrual itself rather than sealing the walk's.
    posted_here: bool,
    /// What the Meter step said about the fee and the refund.
    fee_count: u32,
    refund: bool,
    /// The bytes the terminal posted, which are the bytes the client is given.
    terminal: Option<Response>,
}

/// One request, as this plane's steps carry it.
pub struct Walk {
    host: Arc<dyn EngineHost>,
    rt: Arc<crate::engine::NativeRuntime>,
    gov: busbar_api::PlaneRequestCtx,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    caller_token: Option<String>,
    headers: HeaderMap,
    body: Bytes,
    lanes: Arc<Mutex<Registration>>,
    path: Option<crate::arrival::PathModelFacts>,
    carry: Mutex<Carry>,
}

impl std::fmt::Debug for Walk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Walk")
            .field("proto", &self.proto)
            .field("operation", &self.operation.name())
            .finish_non_exhaustive()
    }
}

impl Walk {
    /// Open the carry for one request.
    ///
    /// The runtime table is resolved off the host slot ONCE, here, exactly as the legacy tail
    /// resolves it: one `Arc` bump and a downcast, borrowed for the whole unit. Resolving it per
    /// step would be the same read four times against a snapshot that may have been replaced
    /// between them, which is the shape a unit finishing against two generations has.
    #[must_use]
    pub fn open(arrival: WalkArrival) -> Self {
        let WalkArrival {
            host,
            gov,
            proto,
            operation,
            caller_token,
            headers,
            body,
            lanes,
            path,
        } = arrival;
        let rt = crate::engine::native_runtime_arc(host.as_ref());
        Walk {
            host,
            rt,
            gov,
            proto,
            operation,
            caller_token,
            headers,
            body,
            lanes,
            path,
            carry: Mutex::new(Carry::default()),
        }
    }

    /// WHAT THE URL SAID, for the steps that read it.
    ///
    /// `None` on every body-model surface, which is what makes this the one question a step asks to
    /// find out which of the two shapes it is running under. The facts are read rather than taken:
    /// step 0 wants the model and the framing, step 1 wants the model again, and step 5 wants the
    /// dialect's miss copy, so no one of them may consume them.
    #[must_use]
    pub fn with_path<R>(
        &self,
        read: impl FnOnce(&crate::arrival::PathModelFacts) -> R,
    ) -> Option<R> {
        self.path.as_ref().map(read)
    }

    // ---------------------------------------------------------------------------------------------
    // What the root reads to drive the seven steps it calls directly
    // ---------------------------------------------------------------------------------------------

    /// The neutral host seam, for the steps whose context names it.
    #[must_use]
    pub fn host(&self) -> &Arc<dyn EngineHost> {
        &self.host
    }

    /// This request's governance context.
    #[must_use]
    pub fn gov(&self) -> &busbar_api::PlaneRequestCtx {
        &self.gov
    }

    /// The ingress dialect.
    #[must_use]
    pub fn proto(&self) -> &'static str {
        self.proto
    }

    /// The operation the dialect resolved.
    #[must_use]
    pub fn operation(&self) -> busbar_api::operation::Operation {
        self.operation
    }

    /// The request headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The request body, as it arrived.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// THE DEPLOYMENT, as the Verify step's guards read one.
    ///
    /// The runtime tables behind the neutral projection the production `PoolView` is built over. It
    /// is the plane's own handle and the root never names its type — only the trait it satisfies,
    /// which is published on the plane ABI for exactly this.
    #[must_use]
    pub fn tables(&self) -> &dyn EngineTablesView {
        &*self.rt
    }

    /// The lane names this destination resolves to, in the order the walk would take them.
    ///
    /// Read through the Route step's own candidate resolution rather than through a second reading
    /// of the tables, so the set the trust unit seals is the set the walk will dial. A destination
    /// that resolves to nothing answers with nothing, which is the honest empty verified set: the
    /// door still draws and retains its slot and the unit ends at the Route step's own no-destination
    /// refusal.
    #[must_use]
    pub fn candidate_lane_names(&self, destination: &str) -> Vec<String> {
        let Some((cands, _pool)) = crate::unit::route::candidates(&self.rt, destination) else {
            return Vec::new();
        };
        let tables = crate::engine::EngineTables::new(&self.rt);
        let all = tables.lanes();
        cands
            .iter()
            .filter_map(|c| all.get(c.idx).map(|lane| lane.model.to_string()))
            .collect()
    }

    // ---------------------------------------------------------------------------------------------
    // The carry
    // ---------------------------------------------------------------------------------------------

    fn lock(&self) -> std::sync::MutexGuard<'_, Carry> {
        self.carry.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Keep what the Arrival step read.
    pub fn keep_arrival(&self, arrived: BodyArrival) {
        self.lock().arrived = Some(arrived);
    }

    /// Read what the Arrival step kept, without taking it.
    ///
    /// The one seam the model ladder crosses. The ladder's third rung is a point read of the head
    /// projection step 0 captured, and a projection is an engine value — so the projection stays
    /// here and the LADDER stays where it belongs, at the caller, which is handed the arrival and
    /// passes its fields straight into the step file without naming any of their types. `None` where
    /// the Arrival step never answered, which the loop's order makes unreachable.
    #[must_use]
    pub fn with_arrival<R>(&self, read: impl FnOnce(&BodyArrival) -> R) -> Option<R> {
        self.lock().arrived.as_ref().map(read)
    }

    /// Hold bytes a step rendered until the terminal posts them.
    ///
    /// Rendering and posting are two jobs: a step names its refusal, one place turns it into bytes,
    /// and one place posts it. This is where the bytes wait in between.
    pub fn hold_bytes(&self, resp: Response) {
        self.lock().pending = Some(resp);
    }

    /// The bytes waiting for the terminal, if a step left any.
    #[must_use]
    pub fn take_bytes(&self) -> Option<Response> {
        self.lock().pending.take()
    }

    /// Take the door's answer.
    ///
    /// The plane's own half of it — the meter half of the hold, whether the charge landed, and which
    /// pool it landed on — stays here; the kernel's half is handed straight back. The refusal, where
    /// the door raised one, waits with the other rendered bytes for the terminal.
    pub fn take_admission(&self, admitted: Admitted) -> Decision<busbar_caps::Admit> {
        let mut carry = self.lock();
        carry.charged = admitted.charged;
        carry.effective = admitted.effective_pool;
        carry.upstream_candidate = admitted.upstream_candidate;
        carry.sink = admitted.sink;
        if let Some(resp) = admitted.refusal {
            carry.pending = Some(resp);
        }
        admitted.decision
    }

    /// Whether the admission charge landed, which is what decides whether a non-2xx refunds.
    #[must_use]
    pub fn charged(&self) -> bool {
        self.lock().charged
    }

    /// The pool the charge landed on, or the requested one where nothing re-pooled it.
    #[must_use]
    pub fn effective_pool(&self, requested: &str) -> String {
        self.lock()
            .effective
            .clone()
            .unwrap_or_else(|| requested.to_string())
    }

    /// Whether the verified set offered an upstream, which is what makes this unit draw a slot.
    #[must_use]
    pub fn upstream_candidate(&self) -> bool {
        self.lock().upstream_candidate
    }

    /// What the Meter step said the fee was.
    #[must_use]
    pub fn fee_count(&self) -> u32 {
        self.lock().fee_count
    }

    /// Whether the Meter step made the accrual rather than sealing the walk's.
    #[must_use]
    pub fn posted_here(&self) -> bool {
        self.lock().posted_here
    }

    /// Whether the Audit step owes a refund of the fee base.
    #[must_use]
    pub fn refund(&self) -> bool {
        self.lock().refund
    }

    /// The status the CLIENT saw, once the walk has produced one.
    #[must_use]
    pub fn served_status(&self) -> Option<u16> {
        self.lock().facts.as_ref().map(|f| f.status)
    }

    /// Whether the caller asked for a stream, read off the head projection the Arrival step kept.
    ///
    /// A point read, never a parse: the projection is what step 0 captured and this asks it the one
    /// question the terminal needs — a streamed answer's end is not known when the head is written,
    /// so the finish it seals cannot be the finish a buffered answer seals.
    #[must_use]
    pub fn streamed(&self) -> bool {
        self.lock()
            .arrived
            .as_ref()
            .and_then(|a| a.parsed.as_ref())
            .and_then(|b| b.probe().get("stream"))
            .and_then(|s| s.as_bool())
            .unwrap_or(false)
    }

    /// Post the terminal's bytes.
    pub fn seal_terminal(&self, resp: Response) {
        self.lock().terminal = Some(resp);
    }

    /// The bytes the client is given, once the unit has ended.
    #[must_use]
    pub fn take_terminal(&self) -> Option<Response> {
        self.lock().terminal.take()
    }

    // ---------------------------------------------------------------------------------------------
    // The two steps the root drives through this file
    // ---------------------------------------------------------------------------------------------

    /// STEP 5, ROUTE — the walk, awaited by the loop and sealed with the loop's own token.
    ///
    /// The walk IS the loop's one await: it is polled by the task serving this request, so no thread
    /// is parked for the length of the upstream call and the node's in-flight ceiling is the
    /// in-flight table's rather than a thread pool's. Dropping this future is what a client going
    /// away does to the upstream leg, and it is what the loop does to it when the caller drops the
    /// unit. What the walk SEES travels back here; the sealing happens here, where the token is.
    pub async fn route(&self, token: &UnitToken<Route>, destination: &str) -> Decision<Route> {
        let (arrived, sink) = {
            let mut carry = self.lock();
            (carry.arrived.take(), carry.sink.take())
        };
        // A unit that never reached the Arrival step's answer has no bytes to forward. Unreachable
        // from the loop's order — Route runs after Arrival or not at all — and answered rather than
        // unwrapped, because an arm that cannot be taken is still an arm that must say something.
        let Some(arrived) = arrived else {
            return Decision::refuse(
                token,
                busbar_caps::Refusal::new(busbar_caps::ReasonCode::NoDestination),
            );
        };
        let op = busbar_substrate::handlers::frame(
            busbar_substrate::transport::Transport::Http,
            self.operation,
            // The handler the Decode step resolved is looked up again here rather than carried,
            // because the lookup is a table read against a `&'static` registry and a borrowed vtable
            // is not a thing the carry holds. Same protocol, same operation, same table: the same
            // handler, or none — and none is unreachable, because the Decode step already refused a
            // unit whose pair has no handler.
            match busbar_substrate::handlers::request_handler(self.proto)
                .and_then(|rh| rh.operation_handler(self.operation))
            {
                Some(h) => h,
                None => {
                    return Decision::refuse(
                        token,
                        busbar_caps::Refusal::new(busbar_caps::ReasonCode::NoDestination),
                    )
                }
            },
        );

        let BodyArrival { body, parsed, .. } = arrived;
        // THE AWAIT. Everything the walk needs is borrowed straight off the carry — there is no task
        // to move it into and no channel to carry it back — so a cancelled request drops this future
        // and, with it, the upstream leg it was in the middle of.
        let parts = crate::unit::route::route_parts(RouteInput {
            host: &self.host,
            rt: &self.rt,
            proto: self.proto,
            op,
            destination,
            headers: &self.headers,
            body,
            parsed,
            caller_token: self.caller_token.as_deref(),
            resolved_gov_key: self.gov.key.as_ref(),
            usage_sink: sink,
            // THE DIALECT'S OWN MISS COPY, where the URL's parse produced one. A body-model arrival
            // has none and gets the neutral sentence; a path-model arrival on a dialect that words
            // its own is answered in that dialect's words, which is what the shipped entry point
            // does and what the loop would otherwise have quietly stopped doing.
            model_not_found_message: self
                .path
                .as_ref()
                .and_then(|path| path.model_not_found_message.as_deref()),
            lanes: &self.lanes,
        })
        .await;
        let routed = crate::unit::route::seal(token, parts);
        {
            let mut carry = self.lock();
            carry.facts = Some(routed.facts);
            carry.meter_sink = routed.meter_sink;
            carry.pending = Some(routed.response);
        }
        routed.decision
    }

    /// STEP 6, METER — the one metering seam, bound to what the Route step observed.
    ///
    /// The hold is NOT handed to the step: the loop put it in the unit's cell at the door and the
    /// exit is the one place it comes out again. What the step does here is what it does on the
    /// rehearsal's admitted fixtures — seal the accrual the walk's tap already made, or make it
    /// where the walk held no meter half — and answer with the report the posting is made against.
    pub fn meter(&self, token: &UnitToken<Meter>, usage: &UsageToken) -> Decision<Meter> {
        let mut carry = self.lock();
        let charged = carry.charged;
        let Some(facts) = carry.facts.as_ref() else {
            // Route never ran, so there is nothing the walk reported to seal. Unreachable from the
            // loop's order and answered rather than unwrapped.
            return Decision::proceed(
                token,
                busbar_caps::Usage::report(usage, Vec::new())
                    .unwrap_or_else(|_| unreachable!("the empty report fits any record")),
            );
        };
        let tables = crate::engine::EngineTables::new(&self.rt);
        let lane = facts.lane.and_then(|i| tables.lanes().get(i));
        let ctx = MeterCtx::bind(&self.host, carry.meter_sink.as_ref(), lane, facts, charged);
        let metered = crate::unit::meter::meter(token, usage, &ctx, None, &Outcome::Completed);
        carry.posted_here = metered.row.is_some();
        carry.fee_count = metered.fee_count;
        carry.refund = metered.refund;
        metered.decision
    }
}
