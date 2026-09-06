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
use busbar_substrate::plane_host::{EngineHost, EngineTablesView};

use crate::unit::admit::Admitted;
use crate::unit::arrival::BodyArrival;
use crate::unit::audit::Served;
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
    /// The bytes some step already rendered and no step has posted, in the sealed shape.
    pending: Option<Served>,
    /// What the Route step observed, for the Meter step to be bound to.
    facts: Option<MeterFacts>,
    /// The meter half the walk handed back unspent.
    meter_sink: Option<crate::engine::UsageSink>,
    /// THE CARD THIS UNIT WAS ADMITTED UNDER, kept for a reading taken after the unit has ended.
    ///
    /// The sink itself cannot be kept. It carries the admission's in-flight grant, whose `Drop` on
    /// the LAST clone is what releases the `concurrent` gauges — so a clone held for the length of
    /// the response body would hold a deployment's concurrency leases open past the moment the
    /// previous release releases them, which is an observable change and not one this seam is
    /// allowed to make. The card is the one thing off the sink a late pricing needs, it is an opaque
    /// handle with no drop of its own, and it is the SAME card: pinned when the hold opened at the
    /// door, so a request that opened before a reload is still priced on the rates it agreed to.
    card: Option<busbar_substrate::plane_host::CostHandle>,
    /// Whether the Meter step made the accrual itself rather than sealing the walk's.
    posted_here: bool,
    /// What the Meter step said about the fee and the refund.
    fee_count: u32,
    refund: bool,
    /// The bytes the terminal posted, which are the bytes the client is given.
    terminal: Option<Served>,
}

/// THE COMPLETION TAP, as a root may hold it.
///
/// Opaque on purpose: what is inside is the engine's own cell and naming it would be a root that had
/// learned how this plane forwards. What a holder can do with it is the one thing a holder needs —
/// hand it back to [`Walk::priced_after_terminal`] once the body it belongs to has drained.
///
/// Cheap to hold and safe to hold for as long as the body lives: it is a refcount on a cell that is
/// written exactly once and never rewritten.
#[derive(Clone, Debug)]
pub struct Tap(crate::engine::TapCell);

/// WHAT THE RESPONSE WAS WORTH, read after its body drained.
///
/// The three facts a second book needs about a spend that arrived after the terminal, and no more:
/// the amount, and the two names the row it belongs to is keyed by. Whether that amount is a
/// posting, and what flags it carries, is the ledger's decision and not this plane's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LateFigure {
    /// The amount, in the nano-units a reservation is in.
    pub priced_nanos: u128,
    /// The SERVING lane's config name — the lane that actually answered, after any failover, which
    /// is the key a rate card is written against and the key the legacy row carries.
    pub lane: String,
    /// That lane's provider, as the legacy row carries it.
    pub provider: String,
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
        // The ONE place a rendered refusal is taken into the sealed shape. It is taken here rather
        // than at the caller so a step that rendered bytes has nowhere to put them but this cell.
        self.lock().pending = Some(Served::of(resp));
    }

    /// The bytes waiting for the terminal, if a step left any.
    ///
    /// PRIVATE, and that is the point of it. This used to be the walk's public escape hatch: a
    /// driver could take the pending bytes and hand them straight back to the transport, which is a
    /// unit ending without passing a terminal door. The two doors below are now the only readers,
    /// so the bytes a step rendered can only leave this carry through the terminal.
    fn take_bytes(&self) -> Option<Served> {
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
        // The card, off the sink and before the walk takes it — see `Carry::card` for why the sink
        // itself cannot be the thing that is kept.
        carry.card = admitted.sink.as_ref().map(|s| s.cost.clone());
        carry.sink = admitted.sink;
        if let Some(resp) = admitted.refusal {
            carry.pending = Some(Served::of(resp));
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

    /// A HANDLE ON THIS RESPONSE'S COMPLETION TAP, taken before the body that fills it is handed to
    /// the client.
    ///
    /// The tap is what knows what a streamed or deferred answer consumed, and it does not know it
    /// until the BODY has drained — which is after the unit's terminal, after the exit sealed the
    /// end, and after the response left this plane. The cell rides on the response as an extension
    /// so that the thing draining the body can still find it; taking a handle here is the same move
    /// the engine's own driver makes for the same reason, and it is a refcount bump on a cell that
    /// is written exactly once.
    ///
    /// `None` where the response carries no tap: nothing was ever going to fill one.
    #[must_use]
    pub fn tap_of(response: &Response) -> Option<Tap> {
        response
            .extensions()
            .get::<crate::engine::TapCell>()
            .cloned()
            .map(Tap)
    }

    /// WHAT THE TAP REPORTED, PRICED — the reading that does not exist until the body has drained.
    ///
    /// The Meter step ran while this cell was empty, so the amount it priced was zero: on this plane
    /// there is no earlier moment at which a streamed answer's money is a fact. This is that moment.
    /// The figure is the SAME expression the step would have run had it been able to — the tier split
    /// the tap read, priced against the card the sink pinned at the door, keyed by the lane that
    /// actually answered — because it is literally that function, called here instead of there.
    ///
    /// It ACCRUES NOTHING. The tap already put this response on the governance ledger when it filled
    /// the cell, which is what the previous release bills and what `/usage` reports; calling the
    /// accrual seam again here would bill the same tokens twice. What this produces is a reading, for
    /// a second book to post onto.
    ///
    /// The card is the one the admission pinned at the door and NOT the sink, which by this point no
    /// longer exists on this side: the walk takes the sink and its taps are where the accrual is
    /// made, so a reading that waited for the sink to come back would wait forever on every routed
    /// unit — which is exactly what the metering step's own zero was.
    ///
    /// `None` where there is nothing to post: the cell is still empty, the Route step never ran, no
    /// lane answered, or the unit was admitted under no card at all. A response the tap marked as
    /// billing failed prices at zero, which is what the plane bills for it — the figures seen before
    /// a terminal error are evidence and not a charge.
    #[must_use]
    pub fn priced_after_terminal(&self, tap: &Tap) -> Option<LateFigure> {
        let report = tap.0.get()?;
        let carry = self.lock();
        let mut facts = carry.facts.clone()?;
        facts.fold(report);
        let tables = crate::engine::EngineTables::new(&self.rt);
        let lane = facts.lane.and_then(|i| tables.lanes().get(i))?;
        let card = carry.card.as_ref()?;
        // A terminal error, an abort or a cut transfer bills ZERO and the tier is empty, so the
        // reading is zero rather than absent: this response reached a lane and consumed nothing the
        // node will charge for, which is a different statement from "no reading could be taken".
        let tier = if facts.billing_failed {
            busbar_substrate::billing::Usage::default()
        } else {
            facts
                .usage
                .as_ref()
                .map(crate::engine::usage::tier_usage)
                .unwrap_or_default()
        };
        Some(LateFigure {
            priced_nanos: crate::unit::meter::price_against(&self.host, card, lane, &tier),
            lane: lane.model.clone(),
            provider: lane.provider.clone(),
        })
    }

    /// Post the terminal's bytes. Private: the two doors below are the only posters.
    fn seal_terminal(&self, resp: Served) {
        self.lock().terminal = Some(resp);
    }

    /// THE ONE WAY A RESPONSE LEAVES THIS PLANE — the bytes the client is given, once the unit has
    /// ended, in the sealed shape the terminal put them in.
    ///
    /// `Served` rather than a bare `Response`, and the difference is not cosmetic: unwrapping one is
    /// spelled in `audit.rs` and nowhere else, so the driver can give the transport its answer and
    /// still cannot manufacture an answer anywhere earlier. `None` where the loop never reached a
    /// terminal at all, which its own order makes unreachable.
    #[must_use]
    pub fn take_terminal(&self) -> Option<Served> {
        self.lock().terminal.take()
    }

    // ---------------------------------------------------------------------------------------------
    // STEP 7, AUDIT — the two terminal doors, driven through the carry
    // ---------------------------------------------------------------------------------------------

    /// THE CHARGED TERMINAL. A unit that passed the door leaves here, whatever it ended on.
    ///
    /// The carry is handed to the door INTERNALLY. That is the whole shape of this pair: the driver
    /// names the destination and the clock, the walk supplies the bytes and the charge, the door
    /// posts, and what comes back is a decision. At no point is there an expression outside
    /// `audit.rs` that evaluates to a finished `Response` — so a unit cannot be ended by anything
    /// but a door, which is what "posted exactly once" needs in order to be a property of the call
    /// graph rather than of the driver's good intentions.
    ///
    /// The bytes are the ones a step rendered, or the empty-carry fallback the caller supplies. That
    /// fallback is unreachable from the loop's order — every path to a terminal has already rendered
    /// something — and it is an answer rather than an unwrap, because a path that cannot be taken
    /// still has to say something if it is.
    pub fn audit(
        &self,
        token: &UnitToken<busbar_caps::step::Audit>,
        ctx: &crate::unit::audit::AuditCtx<'_>,
        fallback: impl FnOnce() -> Served,
    ) -> Decision<busbar_caps::step::Audit> {
        let bytes = self.take_bytes().unwrap_or_else(fallback);
        let audited = crate::unit::audit::audit(token, ctx, bytes, self.charged());
        self.seal_terminal(audited.response);
        audited.decision
    }

    /// THE NOT-CHARGED TERMINAL. Nothing was charged, so nothing is refunded.
    ///
    /// Same shape, same carry, same sealing; the difference is the door, and the door's difference
    /// is the refund. See [`Walk::audit`] for why the bytes are fetched here rather than passed in.
    pub fn audit_refused(
        &self,
        token: &UnitToken<busbar_caps::step::Audit>,
        ctx: &crate::unit::audit::AuditCtx<'_>,
        fallback: impl FnOnce() -> Served,
    ) -> Decision<busbar_caps::step::Audit> {
        let bytes = self.take_bytes().unwrap_or_else(fallback);
        let audited = crate::unit::audit::audit_refused(token, ctx, bytes);
        self.seal_terminal(audited.response);
        audited.decision
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
        })
        .await;
        let routed = crate::unit::route::seal(token, parts);
        {
            let mut carry = self.lock();
            carry.facts = Some(routed.facts);
            carry.meter_sink = routed.meter_sink;
            carry.pending = Some(Served::of(routed.response));
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
        // THE TAP CELL, READ AGAIN — as late as this unit is allowed to read it.
        //
        // What Route folded was the cell as it stood the instant the walk returned, which for a
        // buffered answer is already the tap's own figures and for anything still in flight is
        // nothing. Between that instant and this one the response may have finished: a transfer
        // that was cut, a stream that died before its terminal frame. Sealing such a unit off the
        // Route-time snapshot reports an empty usage for a response whose figures are sitting in
        // the cell on the very value this carry is holding. The fold is idempotent in the only way
        // that matters — it takes the whole report or none of it — so folding a cell Route already
        // folded rewrites the same three figures with themselves.
        //
        // A stream still flowing at this step is the one case that stays empty, and it stays empty
        // by construction: its figures do not exist yet. Its accrual is the tap's, which is what
        // `accrued` says and what `posted` below confirms.
        let mut facts = facts.clone();
        if let Some(report) = carry
            .pending
            .as_ref()
            .and_then(|resp| {
                resp.as_response()
                    .extensions()
                    .get::<crate::engine::TapCell>()
            })
            .and_then(|cell| cell.get())
        {
            facts.fold(report);
        }
        let tables = crate::engine::EngineTables::new(&self.rt);
        let lane = facts.lane.and_then(|i| tables.lanes().get(i));
        let ctx = MeterCtx::bind(&self.host, carry.meter_sink.as_ref(), lane, &facts, charged);
        let metered = crate::unit::meter::meter(token, usage, &ctx, None, &Outcome::Completed);
        // What the ACCRUAL ARM reported about itself. `row` is filled whether this step posted or
        // only sealed, so reading it here called every sealed unit a posting — and this value is
        // what the rehearsal asserts one-posting-per-unit on.
        carry.posted_here = metered.posted;
        carry.fee_count = metered.fee_count;
        carry.refund = metered.refund;
        metered.decision
    }
}
