// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # The LLM plane's unit, and the arrivals that hand it to the node
//!
//! The plane's half of the loop: an implementor of the kernel's `Units` trait whose ten methods are
//! this plane's nine step files, and the arrival table that puts every body- and path-model request
//! on the loop. The loop itself — the in-flight table, the sweep, the exit and the money book a
//! unit settles onto — is the composition root's node, which this plane never names: it is handed
//! a [`Drive`](crate::unit::node::Drive) through the entry's `node` axis ([`install_node`](crate::unit::node::install_node)), and every arrival below hands
//! the node one unit ([`Handed`](crate::unit::node::Handed)) through it.
//!
//! ## What each arm is bound to
//!
//! | step | what answers it |
//! |------|-----------------|
//! | arrival | `unit::arrival::arrival_body` — the content-type read, the body validation, the head projection |
//! | decode | `unit::decode::handler_for` then `unit::decode::model_from` — the handler cell, then the model ladder |
//! | authenticate | `unit::authenticate::authenticate` — the read of the middleware's resolved outcome |
//! | verify | `unit::verify::verify` over `unit::verify::HostPoolView`, with the lent trust token sealing the lane names the node's resolver interned |
//! | approve | `unit::approve::approve` — the migrated hook seats' veto |
//! | admit | `unit::admit::admit` — `EngineHost::admission_check`, the door without its terminal |
//! | route | `unit::route::route_parts`, run on the runtime and sealed here |
//! | meter | `unit::meter::meter`, bound to what the route step observed |
//! | audit | `unit::audit::audit` / `unit::audit::audit_refused` — the two terminal doors, and nothing else |
//! | encode | the kernel's own step; this plane's bytes are the terminal's |
//!
//! ## The two steps reached through the plane's own binding
//!
//! Seven of the nine are called from this file directly, because their contexts are typed in
//! vocabulary the loop's seam names. `route` and `meter` are not: `RouteInput` and `MeterCtx`
//! name the lazily projected body, the runtime table handle, the admission's meter half and the
//! serving lane row, and every one of those is private to the plane's engine. A unit that restated
//! them would be a second copy of how this plane forwards. So the walk's carry lives beside
//! the steps and this file drives those two through it — which is the seam, stated, rather than a
//! reach across it.
//!
//! ## The order this file keeps that the loop does not state
//!
//! The live BODY-model entry point answers a `(protocol, operation)` pair it holds no handler for
//! BEFORE it reads the bytes, so a malformed body on an unsupported endpoint is answered with the
//! endpoint's own refusal rather than with a parse error. The loop's order is arrival then decode, so
//! the handler lookup is PERFORMED in the arrival arm and its refusal is RAISED in the decode arm,
//! where it belongs. The bytes a client sees are the released ones; the step a record names is the
//! step that refused.
//!
//! The live PATH-model entry point interleaves the two the other way round — it parses and splices
//! first and looks the handler up after — which is already the loop's own order, so that surface
//! needs no compensation at all and takes none. The two orders are the plane's, written down beside
//! the step files that hold them apart; this file only composes them the way each surface composes
//! them live.
//!
//! ## The two surfaces whose model is in the URL
//!
//! Gemini and Bedrock name their model in the path rather than in the body. Reading it out is the
//! DIALECT'S statement about its own URL space, so it happens where a dialect's statements happen —
//! at the ingress, in the plane's own parse — exactly as the operation resolution does for a
//! body-model arrival. What comes back is a VALUE, and this file drives it: the parse-and-splice the
//! URL's facts imply is the arrival arm's body (`unit::arrival::arrival_path_model`), and the handler
//! the pair resolves to is the decode arm's (`unit::decode::decode_path_model`, whose single-sentence
//! 404 is the path surface's own and not the body surface's two).
//!
//! ## What the switch costs
//!
//! Nothing a thread pool can run out of. The loop's Route step is a future it awaits on the caller's
//! own runtime, so a unit on this path occupies its in-flight slot and no thread at all while the
//! upstream thinks: the node's ceiling is the in-flight table's, an in-flight request costs no thread
//! stack, and a client that goes away drops the loop, which drops the walk, which drops the upstream
//! leg. The unit still ends exactly once — through the charged audit door and the one exit, named for
//! what happened — and the slot it held is free before the next arrival asks for one.
//!
//! ## What is deliberately not here
//!
//! No wire shaping, no money rule and no second reading of anything. Every judgement below belongs
//! to the step file it is delegated to; what this file owns is the binding and the arrivals. The
//! interner, the in-flight table the unit's cell lives in, the Route seam the leg is driven through
//! and the book the unit's end and its late figure settle onto are the node's, and a unit reaches
//! them only as the values the node lends it at the build ([`Lent`](crate::unit::node::Lent)).
//!
//! ## What crosses to the node, and back
//!
//! Plain values in the loop's own vocabulary, so neither side names the other: one arrival hands the
//! node whose unit it is, its operation class, its dialect and a [`Build`](crate::unit::node::Build); the node lends the build
//! its lane resolver, the loop's meter and the pinned arrival epoch, and gets back the unit's steps,
//! its awaited Route leg and its [`Finish`](crate::unit::node::Finish) — the terminal's bytes and the reading of what they
//! consumed, taken once their body has drained ([`Late`](crate::unit::node::Late)). The reading is a REPORT, never an amount:
//! what it is worth is the node's card's answer.
//!
//! ## What this file answers with
//!
//! A [`PlaneAnswer`] (#28), never a finished response: the construction gate refuses a function
//! under this directory that returns one anywhere but the audit step's own file. The plane's answer
//! is `Live` — its body is a live stream whose tap fills as it drains — and `PlaneAnswer::Live` is
//! the one carrier a response crosses the plane's boundary in. Every answer here that no unit on the
//! loop produced wears it too: a response the dialect's own arrival already rendered (and, where it
//! is accounted, already posted through the rejected door), which the outer handler serves as it
//! stands.
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use axum::http::StatusCode;

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, ArrivalRecord, Audit, Authenticate,
    Consumption, Decision, Decode, Dial, Encode, Grant, Hold, Meter, OpClassId, OriginKind,
    Outcome, Pass, PrincipalId, ReasonCode, Refusal, Route, VerifiedDestination, Verify,
};
use busbar_contract::slice::GroupLeaseSlip;
use busbar_contract::LaneId;
use busbar_kernel::{
    ingress::arrival::{Arrival as ArrivalRequest, ArrivalCtx, ArrivalPayload},
    plane_host::PlaneAnswer,
    teller::{AccrualMeter, Ended, Evidence, FeeEvidence, RouteAwait, RouteLeg, UnitCtx, Units},
};
use busbar_substrate_values::proxy::POOL_LABEL_UNRESOLVED;

use crate::arrival::PathArrivalFacts;
use crate::unit::walk::{Walk, WalkArrival};
use crate::unit::{admit, approve, arrival, audit, authenticate, decode, verify};

// ---------------------------------------------------------------------------------------------
// What crosses to the node
// ---------------------------------------------------------------------------------------------

/// THE NODE'S LANE RESOLVER, as it lends it to a unit: a configured lane name to the interned lane
/// the priced axis is written in, or `None` where the image's vocabulary cannot hold the name.
pub type Resolve = Arc<dyn Fn(&str) -> Option<LaneId> + Send + Sync>;

/// What the node lends the unit it builds: its lane resolver, the loop's own meter, and the unit's
/// pinned header-arrival epoch — the window every charge and every refund it makes lands in.
pub type Lent = (Resolve, Arc<AccrualMeter>, u64);

/// WHAT A UNIT CONSUMED, read after its body drained: every class the tap reported, the billable
/// count the Meter step decided, and the serving lane's config name. A report, never an amount.
pub type Reported = (busbar_substrate_values::billing::Usage, u32, String);

/// The reading of what a drained body consumed, taken once, when the body is done with.
pub type Late = Box<dyn FnOnce() -> Option<Reported> + Send>;

/// A unit's finish: the answer its terminal posted, and the late reading of what it consumed —
/// `None` where the answer carries no tap, because nothing was ever going to fill one. The answer is
/// a [`PlaneAnswer`] (#28), never a finished response: it becomes one on the node's audited exit.
pub type Finish = Box<dyn FnOnce() -> (Option<PlaneAnswer>, Option<Late>) + Send>;

/// A built unit: its steps, its awaited Route leg, and its finish. The first two are the same unit.
pub type Built = (
    Arc<dyn Units + Send + Sync>,
    Arc<dyn RouteAwait + Send + Sync>,
    Finish,
);

/// The build the node runs once it holds the values it lends.
pub type Build = Box<dyn FnOnce(Lent) -> Built + Send>;

/// ONE ARRIVAL, HANDED TO THE NODE: whose unit it is, its operation class, the dialect a node-side
/// refusal is written in, and its build.
pub type Handed = (PrincipalId, OpClassId, &'static str, Build);

/// THE NODE a composition root installs ([`install_node`]): it takes a handed unit, drives it through
/// the loop, and answers with what its terminal posted — as the plane's [`PlaneAnswer`] (#28).
pub type Drive = fn(Handed) -> Pin<Box<dyn Future<Output = PlaneAnswer> + Send>>;

/// The node this plane's units are driven through, once the composition root has installed one.
static NODE: OnceLock<Drive> = OnceLock::new();

/// INSTALL THE NODE this plane's arrivals hand their units to — the entry's `node` axis, driven by
/// the composition root before any listener binds. Set once: the first node installed is the
/// process's node, and a second install of the same composition is a no-op.
pub fn install_node(drive: Drive) {
    let _ = NODE.set(drive);
}

/// Hand one unit to the node. A process whose composition root installed no node has no loop to
/// run the unit on, and says so in the caller's own dialect rather than serving it some other way.
fn drive(handed: Handed) -> Pin<Box<dyn Future<Output = PlaneAnswer> + Send>> {
    match NODE.get() {
        Some(node) => node(handed),
        None => {
            let proto = handed.2;
            Box::pin(async move { PlaneAnswer::Live(audit::render_refusal(proto, &unavailable())) })
        }
    }
}

/// ONE UNIT, as an arrival hands it to the node: the carry opened over what arrived, the Approve
/// seats it is judged by, and the build that makes the unit once the node lends it what it needs.
///
/// The principal is read here, off the governance context the door resolved, because the node
/// opens the unit's hold for it before any step runs.
pub(crate) fn handed(
    arrival: WalkArrival,
    model_hint: Option<String>,
    seats: &'static [&'static (dyn approve::VetoSeat + Sync)],
) -> Handed {
    let proto = arrival.proto;
    let op_class = OpClassId::new(arrival.operation.name());
    let principal = authenticate::principal_id(&arrival.gov);
    let build: Build = Box::new(move |(resolve, meter, charged_at)| {
        let unit = Arc::new(LlmUnit {
            seats,
            walk: Arc::new(Walk::open(arrival)),
            op_class,
            model_hint,
            started: Instant::now(),
            charged_at,
            resolve,
            deferred: Mutex::new(None),
            model: Mutex::new(String::new()),
            meter,
        });
        let finish: Finish = {
            let unit = Arc::clone(&unit);
            Box::new(move || unit.finish())
        };
        (
            Arc::clone(&unit) as Arc<dyn Units + Send + Sync>,
            unit,
            finish,
        )
    });
    (principal, op_class, proto, build)
}

/// The transport stack every request on this plane arrives over.
///
/// One layer, named rather than empty: the LLM surfaces are HTTP and nothing else, and a chain of
/// none would be the under-reported shape composition exists to fix.
const TRANSPORT_CHAIN: [&str; 1] = ["http"];

/// THE NATIVE GATES SEATED AT APPROVE, and there are none.
///
/// The seat is the 1.6.0-native [`approve::VetoSeat`]: a gate that may stop a unit BEFORE the door
/// and may do nothing else. Nothing installs one today, and that emptiness is the whole reason this
/// plane's approve step is behaviour-identical to the shipped path — so it is written down as a
/// value the tests can read rather than as an argument literal nobody can name.
///
/// The MIGRATED hooks are deliberately absent. They fire after the door on the live path — the
/// request-log and completion taps run around admission and around the response — and a hook that
/// fires after Admit cannot veto at Approve, because by the time it runs the unit is admitted and
/// charged. Seating them here would move a veto from after a charge to before one, which changes
/// what is billed; that is a behaviour change wearing a refactor's clothes, and this file does not
/// make it.
///
/// `+ Sync` because a seat is shared by reference across the loop's one await, and a gate that were
/// not shareable would have to be cloned per unit.
pub(crate) static NATIVE_SEATS: &[&(dyn approve::VetoSeat + Sync)] = &[];

/// The refusal a unit a seated gate stopped answers with; the audit step renders it in the caller's
/// own dialect.
///
/// One permission sentence, vendor-plausible, naming nothing of the operator's — not the seat, not
/// the principal, not a word of governance vocabulary — because a gate's veto is not entitled to a
/// reason of its own and a client is owed the same answer whichever gate stopped it. WHICH seat
/// stopped the unit is the operator's diagnostic, and the step file already logs it.
fn vetoed() -> audit::RefusalOutcome {
    audit::RefusalOutcome::new(
        StatusCode::FORBIDDEN,
        busbar_substrate_values::proxy::KIND_PERMISSION,
        "Your API key does not have permission to access this resource.",
    )
}

/// The refusal a node that cannot take the unit at all answers with; the audit step renders it in
/// the caller's own dialect.
fn unavailable() -> audit::RefusalOutcome {
    audit::RefusalOutcome::new(
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_substrate_values::proxy::KIND_OVERLOADED,
        "The service is temporarily overloaded. Please retry shortly.",
    )
}

// ---------------------------------------------------------------------------------------------
// The unit
// ---------------------------------------------------------------------------------------------

/// One LLM request, as the loop reaches it.
///
/// Constructed per unit and thrown away with it. Every field is either something an earlier stage
/// already determined — the dialect, the operation, the arrival epoch — or a place one step leaves a
/// value the next reads. No step here re-derives what another already knew.
pub struct LlmUnit {
    /// The gates seated at Approve for this unit, in the order they are consulted. A seat is
    /// configuration, and configuration is not per-request state: the list lives as long as the
    /// process does.
    seats: &'static [&'static (dyn approve::VetoSeat + Sync)],
    /// The plane's per-request carry, and the two steps reached through it. Shared with the
    /// finish, which reads the terminal's bytes and the late reading off it once the loop is done.
    walk: Arc<Walk>,
    /// The operation class this unit is, as the sealed facts name it.
    op_class: OpClassId,
    /// A routing name the URL carried, for the convenience surfaces whose model is in the path.
    model_hint: Option<String>,
    /// When the request started, for the terminal's finish-stage latency observation.
    started: Instant,
    /// The pinned header-arrival epoch every charge and every refund lands in — the node's one
    /// arrival reading, lent at the build.
    charged_at: u64,
    /// THE NODE'S LANE RESOLVER, lent at the build: a configured lane name to the interned lane the
    /// priced axis is written in. The node's, because the interner is the image's and the table in
    /// front of it is kept for the life of the node.
    resolve: Resolve,
    /// The handler-lookup refusal the arrival arm performed and the decode arm raises. See this
    /// module's header for why the two are apart.
    deferred: Mutex<Option<decode::DecodeRefusal>>,
    /// The model the caller named, once the ladder has read it.
    model: Mutex<String>,
    /// THE LOOP'S OWN METER, lent at the build and read at the unit's evidence.
    ///
    /// The same value on both sides: the kernel is handed a borrow of this and the Meter step
    /// accrues onto it, because the step that knows what the unit is worth is not the step the loop
    /// hands the meter to. Two meters would be a unit that accrued on one and settled the other.
    meter: Arc<AccrualMeter>,
}

impl std::fmt::Debug for LlmUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmUnit")
            .field("op_class", &self.op_class.as_str())
            .finish_non_exhaustive()
    }
}

impl LlmUnit {
    /// The model the caller named.
    fn model(&self) -> String {
        self.model.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The destination a record names: the pool the charge landed on for a unit that reached
    /// routing, and the reserved unresolved label for one refused before a model was ever read.
    fn destination(&self) -> String {
        let model = self.model();
        if model.is_empty() {
            return POOL_LABEL_UNRESOLVED.to_string();
        }
        self.walk.effective_pool(&model)
    }

    /// The terminal's context, built once per end.
    fn audit_ctx<'a>(&'a self, destination: &'a str) -> audit::AuditCtx<'a> {
        audit::AuditCtx {
            host: self.walk.host(),
            gov: self.walk.gov(),
            proto: self.walk.proto(),
            op_class: self.op_class,
            destination,
            started: self.started,
            charged_at: self.charged_at,
        }
    }

    /// The node's own answer, for a terminal reached with an empty carry.
    ///
    /// Handed to the walk's doors as a fallback rather than fetched here: the bytes a step rendered
    /// live in the walk's carry and the walk hands them to the door itself, so there is no
    /// expression on this side that evaluates to a finished response before a door has posted one.
    /// Unreachable from the loop's order — every path to a terminal has already rendered
    /// something — and an answer rather than an unwrap, because a path that cannot be taken still
    /// has to say something if it is.
    fn nothing_rendered(&self) -> audit::Served {
        audit::Served::of(audit::render_refusal(self.walk.proto(), &unavailable()))
    }
}

// ---------------------------------------------------------------------------------------------
// The twelve methods
// ---------------------------------------------------------------------------------------------

impl Units for LlmUnit {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        let record = ArrivalRecord {
            source: String::new(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: TRANSPORT_CHAIN.to_vec(),
        };
        // THE PATH SURFACES' STEP 0: the parse-and-splice the URL's facts imply. It runs FIRST and it
        // runs alone — the live path-model entry point parses before it looks a handler up, so the
        // handler cell below is not read on this surface at all and the decode arm performs its own
        // lookup in its own spelling. The model, the stream intent and the framing come from the
        // dialect's parse; the bytes that leave here are the ones the walk forwards.
        if let Some(read) = self.walk.with_path(|facts| {
            arrival::arrival_path_model(
                self.walk.body(),
                &facts.model,
                facts.stream,
                facts.gemini_json_array,
                self.walk.proto(),
            )
        }) {
            return match read {
                Ok(arrived) => {
                    let ct = arrival::content_type(self.walk.headers()).to_string();
                    self.walk.keep_arrival(arrived.into_arrival(ct));
                    Decision::proceed(token, record)
                }
                Err(refusal) => {
                    self.walk
                        .hold_bytes(audit::render_refusal(self.walk.proto(), &refusal.outcome()));
                    Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed))
                }
            };
        }
        // THE HANDLER CELL, read before the bytes. A pair this plane holds no handler for is
        // answered with the endpoint's own refusal on the live path, and it is answered before the
        // body is looked at — so a malformed body on an unsupported endpoint gets the 404 it has
        // always got rather than a parse error the endpoint would never have reached. The refusal is
        // RAISED at the decode arm, where it belongs; what happens here is only the reading.
        if let Err(refusal) = decode::handler_for(self.walk.proto(), self.walk.operation()) {
            *self.deferred.lock().unwrap_or_else(|e| e.into_inner()) = Some(refusal);
            return Decision::proceed(token, record);
        }
        match arrival::arrival_body(self.walk.headers(), self.walk.body()) {
            Ok(arrived) => {
                self.walk.keep_arrival(arrived);
                Decision::proceed(token, record)
            }
            Err(refusal) => {
                // A named refusal becomes bytes at the audit step and nowhere else: the step names
                // the refusal, one function renders it, and the terminal posts it.
                self.walk
                    .hold_bytes(audit::render_refusal(self.walk.proto(), &refusal.outcome()));
                Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed))
            }
        }
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        let refuse = |refusal: decode::DecodeRefusal| {
            self.walk
                .hold_bytes(audit::render_refusal(self.walk.proto(), &refusal.outcome()));
            Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed))
        };
        if let Some(refusal) = self
            .deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            return refuse(refusal);
        }
        // THE PATH SURFACES' STEP 1: the model is already known, so only the handler is left — and it
        // is looked up in the path-model SPELLING, whose single sentence for both misses is the
        // released 404 body on this surface and is not the body surface's two.
        if let Some(read) = self.walk.with_path(|facts| {
            decode::decode_path_model(self.walk.proto(), self.walk.operation(), &facts.model)
                .map(|_| facts.model.clone())
        }) {
            return match read {
                Ok(model) => {
                    *self.model.lock().unwrap_or_else(|e| e.into_inner()) = model;
                    Decision::proceed(token, self.op_class)
                }
                Err(refusal) => refuse(refusal),
            };
        }
        // THE MODEL LADDER, walked once. The arrival's fields go straight into the step file: the
        // content type it read, the pristine bytes it retained, and the head projection it captured
        // — which this file passes along without naming, because a projection is the plane's.
        let hint = self.model_hint.clone();
        let read = self.walk.with_arrival(|arrived| {
            decode::model_from(
                &arrived.content_type,
                &arrived.body,
                arrived.parsed.as_ref(),
                hint.as_deref(),
            )
        });
        // `None` is a unit whose arrival never answered, which the loop's order makes unreachable:
        // decode runs after arrival or not at all. Answered rather than unwrapped.
        match read {
            Some(Ok(model)) => {
                *self.model.lock().unwrap_or_else(|e| e.into_inner()) = model;
                Decision::proceed(token, self.op_class)
            }
            Some(Err(refusal)) => refuse(refusal),
            None => Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
        }
    }

    fn authenticate(&self, token: &Pass<Authenticate>, _ctx: &UnitCtx) -> Decision<Authenticate> {
        // The read of the auth middleware's already-resolved outcome. It cannot refuse — every
        // refusal this step could raise is the middleware's, upstream of the plane — and it is still
        // called, because "the middleware answered" is a fact this step states rather than one the
        // loop assumes.
        authenticate::authenticate(token, self.walk.gov())
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        let model = self.model();
        // THE SEALED SET, over the lanes this deployment CONFIGURED for the destination — the
        // runtime names read off the running tables and interned once through the node's own
        // registration, which is how a config-derived name becomes the borrowed static one the
        // priced axis is written in. Sealing takes the trust token the loop lends this step, so no
        // other step can seal a destination.
        let destinations: Vec<VerifiedDestination> = self
            .walk
            .candidate_lane_names(&model)
            .iter()
            // A lane the frozen vocabulary does not hold is not a candidate this node can route
            // to, so it is left out rather than sealed under a name it cannot name.
            .filter_map(|name| {
                (self.resolve)(name).map(|lane| VerifiedDestination::seal(trust, lane))
            })
            .collect();
        // The empty set is the honest answer for a name that resolves to no lane: the unit proceeds,
        // the door draws and RETAINS its slot, and the unit ends at the route step's own
        // no-destination refusal — which is where the shipped behaviour ends it, and it is charged.
        let view = verify::HostPoolView::new(
            &**self.walk.host(),
            self.walk.tables(),
            self.walk.gov().key.as_deref(),
        );
        let answer = verify::verify(token, &view, &model, principal, destinations);
        if let Some(named) = answer.refusal {
            // The wire triple is the step's, from the ONE reading of the guards that produced the
            // refusal — never a second reading that could answer differently.
            self.walk
                .hold_bytes(audit::render_refusal(self.walk.proto(), &named.outcome()));
        }
        answer.decision
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        // THE SEATS, as the node was composed with them. The step's only refusal is a seated gate's
        // veto, and [`NATIVE_SEATS`] is empty on every deployment today — so on every deployment
        // today this step proceeds, which is the same unit-for-unit behaviour as the live path. It
        // is still called, because "nothing is seated" is a fact about configuration rather than a
        // licence to skip a step.
        //
        // A VETO CARRIES NO BYTES OF ITS OWN. The step answers in the neutral vocabulary — a gate is
        // not entitled to add to the closed reason set, and is handed neither the body nor the
        // dialect — so the ANSWER a vetoed unit leaves with is rendered here, and the terminal posts
        // it exactly as it posts every other step's. Without it the not-charged door would find
        // nothing rendered and a client refused on policy would read the node's overload sentence.
        //
        // It is rendered BEFORE the ask rather than after it because a `Decision` is the kernel's to
        // read and no step can open its own. The cost is one response for a unit that may proceed —
        // paid only where a gate is actually seated, which is nowhere today — and it is discarded
        // the moment any later step ends the unit: the door overwrites it with its own refusal and
        // the route step overwrites it with the upstream's answer, which is the same one-slot
        // discipline every other rendered refusal on this plane already relies on.
        if !self.seats.is_empty() {
            self.walk
                .hold_bytes(audit::render_refusal(self.walk.proto(), &vetoed()));
        }
        // The auto trait is dropped for the call because the step file's seat list does not ask for
        // it; an empty list collects into a `Vec` that allocates nothing, which is what the mount
        // hands down.
        let seats: Vec<&dyn approve::VetoSeat> = self
            .seats
            .iter()
            .map(|seat| *seat as &dyn approve::VetoSeat)
            .collect();
        approve::approve(token, principal, destinations, &seats)
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit_token: &Grant<Admittance>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        // This plane's door is the shipped release's, which keeps its group gauges on its own
        // registration and names none of them here. The unit is counted on the node-wide gauge
        // exactly as it always has been.
        _leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        let model = self.model();
        // THE DOOR, taken without its terminal: `admission_check` is the check-and-charge that
        // `admission_door` wraps its refusing arm in a posting. So a refusal here is BYTES rather
        // than an already-posted record, and the over-budget path leaves through the same terminal
        // every other path leaves through, with exactly one link on the unit's chain.
        let admitted = admit::admit(
            &admit::AdmitCtx {
                host: self.walk.host(),
                gov: self.walk.gov(),
                proto: self.walk.proto(),
                destination: &model,
                charged_at: self.charged_at,
            },
            destinations,
        );
        // The plane's half of the answer — the metering sink, whether the charge landed, and which
        // pool it landed on — stays with the walk; the door's verdict comes back here. THE HOLD IS
        // OPENED HERE, not in the plane (#43, #83 defs 5/6): at zero, for this principal — it never
        // refused a unit the door admitted, and the spend is the governance ledger's.
        match self.walk.take_admission(admitted) {
            Ok(()) => Decision::proceed(
                token,
                Admission::Own(Hold::open(admit_token, principal.clone(), 0)),
            ),
            Err(refusal) => Decision::refuse(token, refusal),
        }
    }

    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _meter: &AccrualMeter,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Route> {
        // THIS PLANE'S ROUTE AWAITS, so it is answered by the `RouteAwait` arm below and this one is
        // not a path any unit on this plane takes: the node drives the loop's asynchronous entry point
        // and there is no other caller. Answered rather than unwrapped — an arm that
        // cannot be taken is still an arm that must say something — and answered with the reason a
        // synchronous driver would truly have: there is no task here to run the leg on.
        Decision::refuse(token, Refusal::new(ReasonCode::TaskLost))
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Meter> {
        // THE ACCRUAL IS NOT MADE HERE, and the reason is a fact about this plane rather than a
        // choice. What the unit is worth is what the response's tap reports, and the tap fills its
        // cell when the BODY is consumed — which on this surface is after the loop's terminal has
        // handed the client its bytes. At this step the cell is on the response and empty, so a
        // figure read here would be zero on every delivered unit and a meter accruing it would be
        // accruing a zero it could not tell from a free request.
        //
        // THE STEP NAMES NO PRICE, and the pricing is not here either. The step assembles what the
        // unit consumed and hands it back on its report; the amount is worked out where the report
        // and the card already meet — the LATE reading, against the snapshot this unit was admitted
        // under and at the instant it arrived, which is the one expression a delivered answer's
        // figures are ever priced through on this plane.
        self.walk.meter(token, usage)
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Audit> {
        // THE CHARGED TERMINAL. A unit that passed the door leaves here, whatever it ended on: a
        // delivered answer, a relayed upstream failure, or a destination that resolved to nothing
        // after the caller was already charged. All three are the same door.
        let destination = self.destination();
        self.walk.audit(token, &self.audit_ctx(&destination), || {
            self.nothing_rendered()
        })
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        // THE NOT-CHARGED TERMINAL. Nothing was charged, so nothing is refunded — and the label is
        // the same bound the charged door applies over the same destination, so a refusal raised
        // against a CONFIGURED pool is recorded under that pool's name on both paths.
        let destination = self.destination();
        self.walk
            .audit_refused(token, &self.audit_ctx(&destination), || {
                self.nothing_rendered()
            })
    }

    fn encode(&self, token: &Pass<Encode>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Encode> {
        // The terminal already produced the bytes and the transport already owns the envelope: this
        // is an HTTP response, and there is no frame this plane writes around one. An empty envelope
        // is the honest answer rather than a trailer this surface does not send.
        Decision::proceed(
            token,
            busbar_contract::caps::Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        let status = self.walk.served_status();
        Evidence {
            // WHAT THIS UNIT SPENT IS NOT LOCATED HERE, and the settlement table therefore posts
            // zero. The figure exists — the walk's tap prices it and puts it on the governance
            // ledger — but it exists LATER: the tap fills its cell when the response body is
            // consumed, which is after this unit has ended. So there is no reading of it a unit's
            // own evidence could take, and a floor invented in its place would be a number the
            // books could not defend.
            //
            // This is what keeps the root's ledger empty for this plane. A settlement of zero is not
            // a row, so the totals view answers over nothing and the identity holds vacuously; the
            // exit arm below is bound and does reach the book, and what it carries is the kernel's
            // record that a unit ran and ended. Carrying the money as well needs the settlement to
            // happen where the figure is, which is past this unit's terminal.
            located: None,
            accrued_floor: self.meter.total(),
            locator_required: false,
            terminal_error: status.is_some_and(|s| !(200..300).contains(&s)),
            recovered: false,
            dispatched: status.is_some(),
            checkpointed: 0,
            variance: None,
            lane_mismatch: None,
            settle_record_lost: false,
            class: None,
            // A verified set with an upstream in it is what makes a client unit draw a request slot,
            // and the slot is drawn at the door and never released.
            upstream_candidate: self.walk.upstream_candidate(),
            fee: FeeEvidence {
                // READ OFF THE UNIT'S ORIGIN, never asserted. The flat fee is a CLIENT'S fee: it is
                // what a caller pays for a request the node carried on its behalf, and a unit the
                // node runs for any other reason is not a caller's request. Hard-coded true, every
                // origin this loop could ever carry would post one — a provider push, a tick, a
                // nested unit — and the sibling planes, which read the same field off the same
                // context, would price the same traffic differently. The origin the kernel sealed is
                // the one fact that answers this, so it is the one thing read.
                client_open_or_one_shot: ctx.origin == OriginKind::Client,
                selected_upstream: self.walk.upstream_candidate(),
                relayed_first_response_frame: status.is_some(),
                // This transport reports no status leg of its own: the response IS the status, and
                // the plane's finish is decided from the frame the client saw.
                status_at: None,
                status: None,
                finish: status.map(|s| {
                    if (200..300).contains(&s) {
                        busbar_contract::FinishClass::Complete
                    } else {
                        busbar_contract::FinishClass::Error
                    }
                }),
            },
        }
    }
}

/// STEP 5, ROUTE — the one step of this plane's ten that waits on anything.
///
/// The leg is the walk's own future, boxed because it is an `async` block and handed straight to the
/// loop, which awaits it on the runtime serving this request. Nothing spawns it and nothing joins
/// it: it is polled where the request already is, so no thread is parked for the length of the
/// upstream call and dropping the unit drops the leg.
impl RouteAwait for LlmUnit {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _meter: &'a AccrualMeter,
        _destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        // The destination the charge actually LANDED on — post-downgrade, never the requested one.
        // Dispatching through the pool the client asked for after charging a different one is the
        // bug this ordering makes impossible.
        let destination = self.walk.effective_pool(&self.model());
        // THE METER IS NOT ACCRUED ON THIS LEG, and it is the plane's timing that says so rather
        // than a policy: what this unit is worth is what the response's tap reports, and the tap
        // reports when the BODY is consumed, which is after the unit has ended. There is nothing for
        // a leg to accrue at this point that would not be a zero.
        //
        // The leg is the walk's own, and the node drives it through its one Route seam — the seam
        // awaits it and gives back its value, so the bytes, the status, the headers, the stream's
        // frames and the tap on its body are the plane's exactly as they are here.
        Box::pin(async move { self.walk.route(token, &destination).await })
    }

    /// THE CALLER WENT AWAY MID-DISPATCH. The end the loop reached for this unit is the node's to
    /// post, onto the book the node settles every end onto: the node's own leg is what the loop
    /// hands an abandoned end to, and this plane keeps no book. Nothing to do here, and nothing may
    /// be done here twice.
    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}
}

impl LlmUnit {
    /// THE UNIT'S FINISH, once the loop has ended it: the bytes the terminal posted, and — where the
    /// response carries a completion tap — the reading of what they consumed, to be taken once their
    /// body has drained.
    ///
    /// The reading keeps the walk alive with it, for exactly as long as it is held: it needs the lane
    /// table the walk resolved and the facts the Route and Meter steps left.
    fn finish(&self) -> (Option<PlaneAnswer>, Option<Late>) {
        let response = self.walk.take_terminal().map(audit::Served::into_response);
        let late = response.as_ref().and_then(Walk::tap_of).map(|tap| {
            let walk = Arc::clone(&self.walk);
            Box::new(move || {
                walk.reported_after_terminal(&tap)
                    .map(|report| (report.usage, report.fee_count, report.lane))
            }) as Late
        });
        // LIVE, per #28: this plane's answer is a live body whose tap fills as it drains, and it
        // crosses to the node as it stands — the node turns it into the served response on its
        // audited exit.
        (response.map(PlaneAnswer::Live), late)
    }
}

// ---------------------------------------------------------------------------------------------
// The arrivals
// ---------------------------------------------------------------------------------------------

/// One body-model arrival, driven through the loop.
///
/// The operation resolution is the DIALECT'S OWN — its `RequestHandler::resolve_operation` over its
/// own endpoint — read here exactly as the legacy arrival reads it, and a path the dialect names no
/// operation for is not a request at all: it gets the plain path-shaped 404 the catch-all uses and
/// is never accounted, which is what the released behaviour does.
async fn body_arrival(proto: &'static str, a: ArrivalRequest) -> PlaneAnswer {
    let ArrivalRequest {
        host,
        ctx,
        path,
        model_hint,
        uri,
        headers,
        body,
    } = a;
    let Some(operation) = busbar_substrate_values::handlers::request_handler(proto)
        .and_then(|rh| rh.resolve_operation(uri.path(), &body))
    else {
        return PlaneAnswer::Live(host.fallback_not_found(
            &ctx,
            &path,
            StatusCode::NOT_FOUND,
            host.err_type_not_found(),
            "the requested resource was not found",
        ));
    };
    // The neutral arrival payload core boxed at the catch-all: the minted engine host, the resolved
    // governance context and the caller's bearer token. A context carrying anything else is a wiring
    // bug rather than a runtime input, and it is answered rather than unwrapped.
    let Some(payload) = ctx.downcast_ref::<ArrivalPayload>() else {
        return PlaneAnswer::Live(audit::render_refusal(proto, &unavailable()));
    };
    let arrival = WalkArrival {
        host: Arc::clone(&payload.host),
        gov: busbar_contract::records::PlaneRequestCtx {
            key: payload.gov.key.clone(),
        },
        proto,
        operation,
        caller_token: payload.caller_token.clone(),
        headers,
        body,
        // A body-model arrival: the model rides the body, so there is no URL fact to carry and the
        // dialect's miss copy, where it has one, is not this surface's.
        path: None,
    };
    // THE LOOP AWAITS, so it is awaited: right here, on the task and the runtime this request
    // already arrived on. Nothing is spawned, so nothing outlives the client — a connection that
    // goes away drops this future, and with it the loop, the walk and the upstream leg.
    drive(handed(arrival, model_hint, NATIVE_SEATS)).await
}

/// Generate one `BodyIngress` fn-pointer target per dialect. The seam is a bare `fn` that cannot
/// capture the protocol name, so each dialect gets its own — the same shape the plane's own table
/// has, over the loop instead of over the shell.
macro_rules! body_arrivals {
    ($(($name:ident, $proto:expr)),+ $(,)?) => {
        $(
            pub(crate) fn $name(
                a: ArrivalRequest,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlaneAnswer> + Send>> {
                Box::pin(body_arrival($proto, a))
            }
        )+
    };
}

body_arrivals! {
    (anthropic_body_arrival, crate::proto_codec::PROTO_ANTHROPIC),
    (openai_body_arrival, crate::proto_codec::PROTO_OPENAI),
    (gemini_body_arrival, crate::proto_codec::PROTO_GEMINI),
    (bedrock_body_arrival, crate::proto_codec::PROTO_BEDROCK),
    (responses_body_arrival, crate::proto_codec::PROTO_RESPONSES),
    (cohere_body_arrival, crate::proto_codec::PROTO_COHERE),
}

/// One path-model arrival, driven through the loop.
///
/// The dialect's own URL parse answers first, because what a URL says is the dialect's statement and
/// no composition root's. Three answers come back and each takes a different path: the URL named a
/// model and a stream intent, so the unit is a path unit and the facts ride the hold below; or it
/// named only the model and left the operation to the body, which is the body-model shape with a
/// routing hint and takes the body arms unchanged; or it is not a request this dialect answers, and
/// the dialect's own already-accounted bytes are returned untouched.
async fn path_arrival(
    proto: &'static str,
    parsed: PathArrivalFacts,
    ctx: ArrivalCtx,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> PlaneAnswer {
    // The URL's facts, the operation they resolved to, and the routing hint a body-model shape
    // carries. Exactly one of the first and the last is ever set.
    let (facts, operation, model_hint) = match parsed {
        // A pre-rendered fallback 404 (a different terminal): return its bytes unchanged.
        PathArrivalFacts::Refused(resp) => return PlaneAnswer::Live(resp),
        // A NAMED pre-routing refusal is rendered and posted through the rejected door at the
        // dialect's own path arrival on the loop, which holds the arrival host and the pinned epoch —
        // BEFORE the loop this function drives — so it never reaches here.
        PathArrivalFacts::RefusedNeutral { .. } => {
            unreachable!("a named path-arrival refusal is posted at the arrival, before the loop")
        }
        PathArrivalFacts::BodyModel {
            operation,
            model_hint,
        } => (None, operation, Some(model_hint)),
        PathArrivalFacts::PathModel(facts) => {
            let operation = facts.operation;
            (Some(facts), operation, None)
        }
    };
    // The neutral arrival payload core boxed at the catch-all. A context carrying anything else is a
    // wiring bug rather than a runtime input, and it is answered rather than unwrapped.
    let Some(payload) = ctx.downcast_ref::<ArrivalPayload>() else {
        return PlaneAnswer::Live(audit::render_refusal(proto, &unavailable()));
    };
    let arrival = WalkArrival {
        host: Arc::clone(&payload.host),
        gov: busbar_contract::records::PlaneRequestCtx {
            key: payload.gov.key.clone(),
        },
        proto,
        operation,
        caller_token: payload.caller_token.clone(),
        headers,
        body,
        // THE URL'S FACTS, handed to the unit's own carry rather than pinned to a thread. They are
        // read by three steps — the parse-and-splice at step 0, the handler lookup at step 1 and the
        // dialect's miss copy at step 5 — and the third of those is on the far side of the loop's one
        // await, which is exactly where a thread-pinned fact stops being this unit's.
        path: facts,
    };
    // The same drive the body arrivals make: awaited here, on the task the request arrived on.
    drive(handed(arrival, model_hint, NATIVE_SEATS)).await
}

/// GEMINI'S PATH ARRIVAL, ON THE LOOP. The dialect's own tail decode and URL parse, then the loop.
pub(crate) fn gemini_path_arrival(
    a: ArrivalRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlaneAnswer> + Send>> {
    // Pinned before the parse, because a parse that rejects accounts its own rejection against them.
    let started = Instant::now();
    let charged_at = busbar_substrate_values::store::now();
    let rest = crate::arrival::gemini_rest(&a.host, &a.path);
    let parsed = crate::arrival::gemini_path_parse(&a.host, &a.ctx, &rest, &a.uri, &a.body);
    match parsed {
        // A NAMED pre-routing refusal: render it at the audit terminal and post it through the
        // rejected door on this dialect's own arrival host — byte- and accounting-identical to the
        // finish the parse used to spell inline, pinned against the epoch pinned above.
        PathArrivalFacts::RefusedNeutral {
            envelope_proto,
            outcome,
        } => {
            let resp = PlaneAnswer::Live(audit::finish_rejected_via_audit_arrival(
                &a.host,
                &a.ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                audit::render_refusal(envelope_proto, &outcome),
            ));
            Box::pin(async move { resp })
        }
        other => Box::pin(path_arrival(
            crate::proto_codec::PROTO_GEMINI,
            other,
            a.ctx,
            a.headers,
            a.body,
        )),
    }
}

/// BEDROCK'S PATH ARRIVAL, ON THE LOOP. Three shapes under one model path, and the native 404 for
/// anything else — all four the dialect's own answer, and only the driving is this file's.
pub(crate) fn bedrock_path_arrival(
    a: ArrivalRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlaneAnswer> + Send>> {
    let started = Instant::now();
    let charged_at = busbar_substrate_values::store::now();
    let parsed = crate::arrival::bedrock_path_parse(&a.host, &a.ctx, &a.path, &a.uri, &a.body);
    match parsed {
        // A NAMED pre-routing refusal: render it at the audit terminal and post it through the
        // rejected door on this dialect's own arrival host — byte- and accounting-identical to the
        // finish the parse used to spell inline, pinned against the epoch pinned above.
        PathArrivalFacts::RefusedNeutral {
            envelope_proto,
            outcome,
        } => {
            let resp = PlaneAnswer::Live(audit::finish_rejected_via_audit_arrival(
                &a.host,
                &a.ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                audit::render_refusal(envelope_proto, &outcome),
            ));
            Box::pin(async move { resp })
        }
        other => Box::pin(path_arrival(
            crate::proto_codec::PROTO_BEDROCK,
            other,
            a.ctx,
            a.headers,
            a.body,
        )),
    }
}
