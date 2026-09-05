// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # The LLM plane, switched over
//!
//! The fifth plane's bindings: an implementor of the kernel's `Units` trait whose ten methods are
//! the LLM plane's nine step files, and the arrival table that puts every body-model request on the
//! loop instead of on the legacy shell.
//!
//! ## What each arm is bound to
//!
//! | step | what answers it |
//! |------|-----------------|
//! | arrival | `unit::arrival::arrival_body` — the content-type read, the body validation, the head projection |
//! | decode | `unit::decode::handler_for` then `unit::decode::model_from` — the handler cell, then the model ladder |
//! | authenticate | `unit::authenticate::authenticate` — the read of the middleware's resolved outcome |
//! | verify | `unit::verify::verify` over `unit::verify::HostPoolView`, with the lent trust token sealing the node's interned lane names |
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
//! vocabulary a composition root may name. `route` and `meter` are not: `RouteInput` and `MeterCtx`
//! name the lazily projected body, the runtime table handle, the admission's meter half and the
//! serving lane row, and every one of those is private to the plane's engine. A root that could name
//! them would be a root that had learned how this plane forwards. So the walk's carry lives beside
//! the steps and this file drives those two through it — which is the seam, stated, rather than a
//! reach across it.
//!
//! ## The order this file keeps that the loop does not state
//!
//! The live entry point answers a `(protocol, operation)` pair it holds no handler for BEFORE it
//! reads the bytes, so a malformed body on an unsupported endpoint is answered with the endpoint's
//! own refusal rather than with a parse error. The loop's order is arrival then decode, so the
//! handler lookup is PERFORMED in the arrival arm and its refusal is RAISED in the decode arm, where
//! it belongs. The bytes a client sees are the released ones; the step a record names is the step
//! that refused.
//!
//! ## What is deliberately not here
//!
//! No wire shaping, no money rule and no second reading of anything. Every judgement below belongs
//! to the step file it is delegated to; what this file owns is the binding, the interner it lends,
//! and the in-flight table the unit's cell lives in.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use axum::http::StatusCode;
use axum::response::Response;

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, Authenticate, Decision, Decode,
    Encode, Meter, OpClassId, OriginKind, Outcome, PrincipalId, ReasonCode, Refusal, Route,
    TrustToken, UnitToken, UsageToken, VerifiedDestination, Verify,
};
use busbar_contract::{Registration, UnitKey};
use busbar_kernel::teller::{AccrualMeter, Evidence, FeeEvidence, UnitCtx, Units};
use busbar_llm::unit::walk::{Walk, WalkArrival};
use busbar_llm::unit::{admit, approve, arrival, audit, authenticate, decode, verify};
use busbar_substrate::ingress::arrival::{Arrival as ArrivalRequest, ArrivalPayload};
use busbar_substrate::proxy::POOL_LABEL_UNRESOLVED;

/// The transport stack every request on this plane arrives over.
///
/// One layer, named rather than empty: the LLM surfaces are HTTP and nothing else, and a chain of
/// none would be the under-reported shape composition exists to fix.
const TRANSPORT_CHAIN: [&str; 1] = ["http"];

// ---------------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------------

/// The long-lived half: the kernel, the in-flight table, the gauge, the counts and the interner.
///
/// One per process. The per-request half is [`LlmUnit`], which borrows this and is thrown away with
/// the unit.
pub struct LlmNode {
    kernel: busbar_kernel::teller::Kernel,
    inflight: busbar_kernel::inflight::InFlight,
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    canary: busbar_caps::Canary,
    door: crate::root::kernel::AdmissionDoor,
    /// THE NODE'S ONE INTERNER. A configured lane's name is read out of config as a runtime `String`
    /// and a `LaneId` is a borrowed static one, so the two are bridged by leaking each name exactly
    /// once. Leaking is the composition root's decision and this is where it is made: idempotent,
    /// bounded by the number of configured lanes, and therefore legal on a request path.
    lanes: Arc<Mutex<Registration>>,
    next_key: AtomicU64,
}

impl std::fmt::Debug for LlmNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmNode").finish_non_exhaustive()
    }
}

impl Default for LlmNode {
    fn default() -> Self {
        LlmNode::new()
    }
}

impl LlmNode {
    /// Compose the node every LLM request is answered by.
    #[must_use]
    pub fn new() -> Self {
        LlmNode {
            kernel: crate::root::kernel::new_kernel(),
            // The data listener already carries the operator-configured inbound-concurrency layer,
            // which is where this deployment's admission-to-the-node decision is made and has always
            // been made. A second cap here would be a second answer to one question, and the one
            // that refused first would decide — silently, and with a different status. So the table
            // is opened at a ceiling no deployment reaches and none is held back. It is still a real
            // table, because a hold still has to live somewhere, and it is still the thing the sweep
            // walks — what it is not is a second cap answering a question the listener already
            // answered.
            inflight: busbar_kernel::inflight::InFlight::new(usize::MAX, 0),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
            door: crate::root::kernel::AdmissionDoor,
            lanes: Arc::new(Mutex::new(crate::root::kernel::new_registration())),
            next_key: AtomicU64::new(1),
        }
    }

    /// The interner, as the walk borrows it for the length of one unit.
    #[must_use]
    pub fn lanes(&self) -> Arc<Mutex<Registration>> {
        Arc::clone(&self.lanes)
    }

    /// Walk one request through the loop and answer with what the terminal posted.
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a request that used to
    /// reach the plane's own shell directly. What comes back is what the AUDIT step posted: this
    /// function chooses the PATH, never the bytes.
    #[must_use]
    pub fn answer(&self, arrival: WalkArrival, model_hint: Option<String>) -> Response {
        let proto = arrival.proto;
        let op_class = OpClassId::new(arrival.operation.name());
        let key = UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed));
        let principal = authenticate::principal_id(&arrival.gov);
        let unit = LlmUnit {
            node: self,
            op_class,
            model_hint,
            started: Instant::now(),
            // The header-arrival epoch, pinned once and reused for every charge and every refund
            // this unit makes, exactly as the legacy entry point pins it: a request whose response
            // completes in a later window than its headers arrived must not split its charges
            // across two windows.
            charged_at: busbar_substrate::store::now(),
            deferred: Mutex::new(None),
            model: Mutex::new(String::new()),
            walk: Walk::open(arrival),
        };

        let hold = busbar_kernel::inflight::arrival_hold(&self.kernel, &self.door, principal);
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: hold,
        });

        match entered {
            // The table is uncapped on this listener, so this arm is the table declining for a
            // reason that is not capacity. It is still an answer rather than a panic.
            Err(_refused) => unavailable(proto),
            Ok(slot) => {
                let ctx = UnitCtx {
                    key,
                    origin: OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: false,
                    kernel_verb_only: false,
                };
                let mut leases = busbar_kernel::slice::LeaseSet::new();
                let meter = AccrualMeter::new();
                let _ended = busbar_kernel::teller::run_unit(
                    &self.kernel,
                    &unit,
                    &ctx,
                    busbar_kernel::teller::Run {
                        cell: slot.cell(),
                        parent: None,
                        leases: &mut leases,
                        gauge: &self.gauge,
                        canary: &self.canary,
                        meter: &meter,
                    },
                );
                self.inflight.remove(key);
                // The loop ran; the answer is whatever the terminal posted. There is no unit that
                // reaches an end without passing one of the two audit doors, so the fallback below
                // is unreachable — and it is an answer rather than an unwrap, because a path that
                // cannot be taken still has to say something if it is.
                unit.walk
                    .take_terminal()
                    .unwrap_or_else(|| unavailable(proto))
            }
        }
    }
}

/// What a node that cannot take the unit at all answers with, in the caller's own dialect.
fn unavailable(proto: &str) -> Response {
    busbar_substrate::proxy::ingress_error(
        proto,
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_substrate::proxy::KIND_OVERLOADED,
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
pub struct LlmUnit<'n> {
    /// The node's long-lived half.
    node: &'n LlmNode,
    /// The plane's per-request carry, and the two steps reached through it.
    walk: Walk,
    /// The operation class this unit is, as the sealed facts name it.
    op_class: OpClassId,
    /// A routing name the URL carried, for the convenience surfaces whose model is in the path.
    model_hint: Option<String>,
    /// When the request started, for the terminal's finish-stage latency observation.
    started: Instant,
    /// The pinned header-arrival epoch every charge and every refund lands in.
    charged_at: u64,
    /// The handler-lookup refusal the arrival arm performed and the decode arm raises. See this
    /// module's header for why the two are apart.
    deferred: Mutex<Option<decode::DecodeRefusal>>,
    /// The model the caller named, once the ladder has read it.
    model: Mutex<String>,
}

impl std::fmt::Debug for LlmUnit<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmUnit")
            .field("op_class", &self.op_class.as_str())
            .finish_non_exhaustive()
    }
}

impl LlmUnit<'_> {
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

    /// The bytes a step already rendered, or the node's own answer where somehow none were.
    fn released(&self) -> Response {
        self.walk
            .take_bytes()
            .unwrap_or_else(|| unavailable(self.walk.proto()))
    }
}

// ---------------------------------------------------------------------------------------------
// The twelve methods
// ---------------------------------------------------------------------------------------------

impl Units for LlmUnit<'_> {
    fn arrival(&self, token: &UnitToken<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        let record = ArrivalRecord {
            source: String::new(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: TRANSPORT_CHAIN.to_vec(),
        };
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

    fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
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

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        // The read of the auth middleware's already-resolved outcome. It cannot refuse — every
        // refusal this step could raise is the middleware's, upstream of the plane — and it is still
        // called, because "the middleware answered" is a fact this step states rather than one the
        // loop assumes.
        authenticate::authenticate(token, self.walk.gov())
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        trust: &TrustToken,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        let model = self.model();
        // THE SEALED SET, over the lanes this deployment CONFIGURED for the destination — the
        // runtime names read off the running tables and interned once through the node's own
        // registration, which is how a config-derived name becomes the borrowed static one the
        // priced axis is written in. Sealing takes the trust token the loop lends this step, so no
        // other step can seal a destination.
        let destinations: Vec<VerifiedDestination> = {
            let mut reg = self
                .node
                .lanes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.walk
                .candidate_lane_names(&model)
                .iter()
                .map(|name| VerifiedDestination::seal(trust, reg.lane(name)))
                .collect()
        };
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
        token: &UnitToken<Approve>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        // A veto answers in the neutral vocabulary and carries no bytes of its own, and a decision
        // can only be opened with the seal the KERNEL holds — so this file cannot ask whether the
        // step refused. It does not need to: the veto's bytes are rendered and held HERE, before the
        // answer, and every path that walks past this step replaces them. The door replaces them
        // with its own refusal, and the walk replaces them with the response it produced; there is
        // no path from here to a terminal that posts these bytes except the one where the seat
        // actually vetoed.
        self.walk.hold_bytes(audit::render_refusal(
            self.walk.proto(),
            &audit::RefusalOutcome::new(
                StatusCode::FORBIDDEN,
                busbar_substrate::proxy::KIND_PERMISSION,
                "Your API key does not have permission to access this resource.",
            ),
        ));
        // No veto seat is installed on any deployment today, so this step is a no-op — and it is
        // still called, because "nothing is seated" is a fact about configuration, not a licence to
        // skip a step.
        approve::approve(token, principal, destinations, &[])
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit_token: &AdmitToken<Admit>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Admit> {
        let model = self.model();
        // THE DOOR, taken without its terminal: `admission_check` is the check-and-charge that
        // `admission_door` wraps its refusing arm in a posting. So a refusal here is BYTES rather
        // than an already-posted record, and the over-budget path leaves through the same terminal
        // every other path leaves through, with exactly one link on the unit's chain.
        let admitted = admit::admit(
            token,
            admit_token,
            &admit::AdmitCtx {
                host: self.walk.host(),
                gov: self.walk.gov(),
                proto: self.walk.proto(),
                destination: &model,
                charged_at: self.charged_at,
            },
            principal,
            destinations,
        );
        // The plane's half of the answer — the meter half of the hold, whether the charge landed,
        // and which pool it landed on — stays with the walk; the kernel's half comes back here.
        self.walk.take_admission(admitted)
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        _ctx: &UnitCtx,
        _meter: &AccrualMeter,
    ) -> Decision<Route> {
        // The destination the charge actually LANDED on — post-downgrade, never the requested one.
        // Dispatching through the pool the client asked for after charging a different one is the
        // bug this ordering makes impossible.
        let destination = self.walk.effective_pool(&self.model());
        // The kernel's accrual meter is left at zero deliberately. What this unit spends is spent on
        // the governance ledger, by the walk's own tap, in the window the arrival epoch pinned — and
        // it is settled there. Accruing a second copy of it here would put one spend on two ledgers.
        self.walk.route(token, &destination)
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        self.walk.meter(token, usage)
    }

    fn audit(
        &self,
        token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Audit> {
        // THE CHARGED TERMINAL. A unit that passed the door leaves here, whatever it ended on: a
        // delivered answer, a relayed upstream failure, or a destination that resolved to nothing
        // after the caller was already charged. All three are the same door.
        let destination = self.destination();
        let audited = audit::audit(
            token,
            &self.audit_ctx(&destination),
            self.released(),
            self.walk.charged(),
        );
        self.walk.seal_terminal(audited.response);
        audited.decision
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        // THE NOT-CHARGED TERMINAL. Nothing was charged, so nothing is refunded — and the label is
        // the same bound the charged door applies over the same destination, so a refusal raised
        // against a CONFIGURED pool is recorded under that pool's name on both paths.
        let destination = self.destination();
        let audited = audit::audit_refused(token, &self.audit_ctx(&destination), self.released());
        self.walk.seal_terminal(audited.response);
        audited.decision
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
        // The terminal already produced the bytes and the transport already owns the envelope: this
        // is an HTTP response, and there is no frame this plane writes around one. An empty envelope
        // is the honest answer rather than a trailer this surface does not send.
        Decision::proceed(
            token,
            busbar_caps::Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        let status = self.walk.served_status();
        Evidence {
            // What this unit spent is on the governance ledger, posted once by the walk's tap or by
            // the meter step, and the kernel's own cell is not a second copy of it. So the figure
            // this table settles is zero and the marks below are what carry the evidence.
            located: None,
            accrued_floor: 0,
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
                client_open_or_one_shot: true,
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

// ---------------------------------------------------------------------------------------------
// The mount
// ---------------------------------------------------------------------------------------------

/// THE NODE, for the length of the process.
///
/// The arrival seam is a bare `fn` pointer and a bare `fn` cannot capture, so the node it drives is
/// reached here. One of these exists, it is built on first use, and every request on this plane
/// walks through it.
static NODE: LazyLock<LlmNode> = LazyLock::new(LlmNode::new);

/// One body-model arrival, driven through the loop.
///
/// The operation resolution is the DIALECT'S OWN — its `RequestHandler::resolve_operation` over its
/// own endpoint — read here exactly as the legacy arrival reads it, and a path the dialect names no
/// operation for is not a request at all: it gets the plain path-shaped 404 the catch-all uses and
/// is never accounted, which is what the released behaviour does.
async fn body_arrival(proto: &'static str, a: ArrivalRequest) -> Response {
    let ArrivalRequest {
        host,
        ctx,
        path,
        model_hint,
        uri,
        headers,
        body,
    } = a;
    let Some(operation) = busbar_substrate::handlers::request_handler(proto)
        .and_then(|rh| rh.resolve_operation(uri.path(), &body))
    else {
        return host.fallback_not_found(
            &ctx,
            &path,
            StatusCode::NOT_FOUND,
            host.err_type_not_found(),
            "the requested resource was not found",
        );
    };
    // The neutral arrival payload core boxed at the catch-all: the minted engine host, the resolved
    // governance context and the caller's bearer token. A context carrying anything else is a wiring
    // bug rather than a runtime input, and it is answered rather than unwrapped.
    let Some(payload) = ctx.downcast_ref::<ArrivalPayload>() else {
        return unavailable(proto);
    };
    let arrival = WalkArrival {
        host: Arc::clone(&payload.host),
        gov: busbar_api::PlaneRequestCtx {
            key: payload.gov.key.clone(),
        },
        proto,
        operation,
        caller_token: payload.caller_token.clone(),
        headers,
        body,
        lanes: NODE.lanes(),
        runtime: tokio::runtime::Handle::current(),
    };
    // THE LOOP IS SYNCHRONOUS and the walk it drives is not, so the loop runs on a blocking worker
    // and the one await inside it — the walk's own — is driven back on this runtime through the
    // channel the plane's carry owns. That is the honest ordering: the loop drives the steps, the
    // route step drives the walk, and the answer comes back through the steps that are still to run.
    tokio::task::spawn_blocking(move || NODE.answer(arrival, model_hint))
        .await
        .unwrap_or_else(|_| unavailable(proto))
}

/// Generate one `BodyIngress` fn-pointer target per dialect. The seam is a bare `fn` that cannot
/// capture the protocol name, so each dialect gets its own — the same shape the plane's own table
/// has, over the loop instead of over the shell.
macro_rules! body_arrivals {
    ($(($name:ident, $proto:expr)),+ $(,)?) => {
        $(
            fn $name(
                a: ArrivalRequest,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
                Box::pin(body_arrival($proto, a))
            }
        )+
    };
}

body_arrivals! {
    (anthropic_body_arrival, busbar_llm::proto_codec::PROTO_ANTHROPIC),
    (openai_body_arrival, busbar_llm::proto_codec::PROTO_OPENAI),
    (gemini_body_arrival, busbar_llm::proto_codec::PROTO_GEMINI),
    (bedrock_body_arrival, busbar_llm::proto_codec::PROTO_BEDROCK),
    (responses_body_arrival, busbar_llm::proto_codec::PROTO_RESPONSES),
    (cohere_body_arrival, busbar_llm::proto_codec::PROTO_COHERE),
}

/// THE BODY-MODEL ARRIVALS, ON THE LOOP — the switched-over twin of the plane's own `BODY_INGRESS`.
///
/// Same six dialects, same names, same table; what changes is the PATH a request takes to reach the
/// answer. The composition root installs this one instead of the plane's when `root-llm` is on, and
/// with it off this static does not exist and the surface is the one it was.
///
/// The URL-model pair keep their own `PATH_INGRESS` entry points, which parse their own URL space
/// before they reach any step this file drives. Their BODY entries are here, because the generic
/// body-model dispatch arm resolves them by name like every other dialect.
pub static BODY_INGRESS: &[(&str, busbar_substrate::ingress::arrival::BodyIngress)] = &[
    (
        busbar_llm::proto_codec::PROTO_ANTHROPIC,
        anthropic_body_arrival,
    ),
    (busbar_llm::proto_codec::PROTO_OPENAI, openai_body_arrival),
    (busbar_llm::proto_codec::PROTO_GEMINI, gemini_body_arrival),
    (busbar_llm::proto_codec::PROTO_BEDROCK, bedrock_body_arrival),
    (
        busbar_llm::proto_codec::PROTO_RESPONSES,
        responses_body_arrival,
    ),
    (busbar_llm::proto_codec::PROTO_COHERE, cohere_body_arrival),
];

// ---------------------------------------------------------------------------------------------
// THE SWITCH-OVER'S OWN PROOF
// ---------------------------------------------------------------------------------------------

/// THE SWITCH, DRIVEN BOTH WAYS on the same fixture and the same deployment shape.
///
/// The rehearsal beside the step files proves the nine steps COMPOSE. What it cannot prove is that
/// the composition root drives them the way the loop drives them, because it has no loop: it is a
/// driver written in a test file. This module drives the real one — `run_unit`, the kernel's ten
/// steps, its two audit doors and its one exit — through [`LlmNode::answer`], against the shipped
/// entry point on its own deployment, and compares what a client and an operator can see.
///
/// Each fixture builds TWO deployments — own registry, own scripted upstream, own governance store —
/// so the two legs' counters are compared rather than summed.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::http::HeaderMap;
    use busbar_core::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};

    /// The one dialect these fixtures speak. Same-protocol openai→openai, so a divergence is about
    /// the PATH rather than about a translation.
    const PROTO: &str = busbar_llm::proto_codec::PROTO_OPENAI;
    const POOL: &str = "p";
    const LANE: &str = "m0";
    /// One cent, so that derived spend in cents reads as the billable count.
    const FEE_CENTS: i64 = 1;
    /// The token figures the scripted upstream reports on a delivered answer.
    const INPUT: u64 = 11;
    const OUTPUT: u64 = 7;

    /// The six ends these fixtures name. Each is an END a client reaches, not a step.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Fixture {
        /// The whole loop, delivered, buffered.
        BufferedOk,
        /// The same loop with the accrual landing at stream end rather than at the buffered tap.
        StreamedOk,
        /// A body that is not JSON: the arrival step's own parse refusal, before a model exists.
        Malformed,
        /// A key whose group budget is spent: the door refuses and nothing is charged.
        OverBudget,
        /// A key that may not reach the pool it named: the pre-admission guard, before pricing.
        PoolAcl,
        /// A model that resolves to no pool and no lane: refused AFTER the door, so it is charged.
        UnknownModel,
    }

    impl Fixture {
        fn model(self) -> &'static str {
            match self {
                Fixture::UnknownModel => "no-such-model",
                _ => POOL,
            }
        }

        fn streamed(self) -> bool {
            matches!(self, Fixture::StreamedOk)
        }

        fn key_scopes(self) -> Option<Vec<String>> {
            match self {
                Fixture::PoolAcl => Some(vec!["some-other-pool".to_string()]),
                _ => None,
            }
        }

        fn seeded_group_requests(self) -> Option<u64> {
            matches!(self, Fixture::OverBudget).then_some(250)
        }

        fn upstream(self) -> MockResponse {
            match self {
                Fixture::StreamedOk => MockResponse::Sse {
                    events: sse_events(),
                    abort_at_index: None,
                },
                _ => MockResponse::Ok {
                    status: reqwest::StatusCode::OK,
                    body: serde_json::json!({
                        "id": "chatcmpl-root", "object": "chat.completion", "created": 0,
                        "model": LANE,
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": "hello"}}],
                        "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                                  "total_tokens": INPUT + OUTPUT}
                    }),
                },
            }
        }

        /// The bytes the caller sends.
        fn body(self) -> Bytes {
            if self == Fixture::Malformed {
                return Bytes::from_static(b"{not json");
            }
            let mut v = serde_json::json!({
                "model": self.model(),
                "messages": [{"role": "user", "content": "hi"}],
            });
            if self.streamed() {
                v["stream"] = serde_json::Value::Bool(true);
            }
            Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
        }
    }

    fn sse_events() -> Vec<String> {
        vec![
            serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                               "created": 0, "model": LANE,
                               "choices": [{"index": 0, "delta": {"role": "assistant",
                                                                  "content": "hello"}}]})
            .to_string(),
            serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                               "created": 0, "model": LANE,
                               "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                               "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                                         "total_tokens": INPUT + OUTPUT}})
            .to_string(),
            "[DONE]".to_string(),
        ]
    }

    fn json_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    /// A unique group name per rig, so two rigs never share a bucket.
    fn unique(prefix: &str) -> String {
        static N: AtomicU64 = AtomicU64::new(0);
        format!("{prefix}-{}", N.fetch_add(1, Ordering::SeqCst))
    }

    /// One deployment: a governed key, a one-lane pool, and a scripted upstream.
    struct Rig {
        app: Arc<busbar_core::state::App>,
        key: Arc<busbar_api::VirtualKey>,
        server: MockServer,
        charged_at: u64,
        group: String,
    }

    async fn rig(fixture: Fixture) -> Rig {
        busbar_llm::testkit::install_test_seams();
        busbar_core::metrics::init();

        let state = Arc::new(MockServerState::new());
        for _ in 0..8 {
            state.push(fixture.upstream());
        }
        let server = MockServer::new(state).await;

        let group = unique("root-llm");
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
            busbar_core::governance::GovState::new_with_signer(store, None, None)
                .expect("governance"),
        );
        let (key, _) = gov
            .create_key(
                busbar_substrate::governance::NewKeySpec {
                    name: "root-llm".to_string(),
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
        gov.hydrate_budgets(&cost, 0).expect("hydrate");

        let app = TestApp::new()
            .lane(LaneSpec::new(LANE, PROTO, &server.base_url()).provider("test"))
            .pool(POOL, &[(0, 1)])
            .governance(gov)
            .cost(cost)
            .build();

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

        fn host(&self) -> Arc<dyn busbar_substrate::plane_host::EngineHost> {
            busbar_core::plane_host::engine_host(&self.app)
        }
    }

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

    /// Everything one leg left behind, as comparable strings.
    #[derive(Debug, PartialEq, Eq)]
    struct Observed(Vec<(&'static str, String)>);

    /// Blank the values a response synthesizes per run — ids and clocks.
    fn normalize(s: &str) -> String {
        fn blank(v: &mut serde_json::Value) {
            match v {
                serde_json::Value::Object(map) => {
                    for (k, val) in map.iter_mut() {
                        let is_id = k.ends_with("id") || k.ends_with("Id") || k.ends_with("ID");
                        let is_clock =
                            matches!(k.as_str(), "created" | "created_at" | "createTime");
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
        // series row the flush writes.
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

        // THE BREAKER. The lane's own state after the walk.
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
        fields.push(("admissible", store.lane_admissible(0).to_string()));

        Observed(fields)
    }

    /// LEG 1 — the shipped entry point, on its own deployment.
    async fn leg_legacy(fixture: Fixture) -> Observed {
        let rig = rig(fixture).await;
        let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
            host: rig.host(),
            gov: rig.gov(),
            caller_token: None,
        });
        let resp = busbar_llm::native_ingress::operation_ingress(
            &ctx,
            json_headers(),
            fixture.body(),
            PROTO,
            busbar_api::operation::Operation::CHAT,
            None,
        )
        .await;
        let observed = observe(&rig, resp).await;
        rig.server.shutdown().await;
        observed
    }

    /// LEG 2 — the same request through the kernel's loop over the nine step files.
    async fn leg_loop(fixture: Fixture) -> Observed {
        let rig = rig(fixture).await;
        let resp = drive(&rig, fixture).await;
        let observed = observe(&rig, resp).await;
        rig.server.shutdown().await;
        observed
    }

    /// One request, through the real loop, on a blocking worker — exactly as the mount drives it.
    async fn drive(rig: &Rig, fixture: Fixture) -> Response {
        let node = LlmNode::new();
        let arrival = WalkArrival {
            host: rig.host(),
            gov: rig.gov(),
            proto: PROTO,
            operation: busbar_api::operation::Operation::CHAT,
            caller_token: None,
            headers: json_headers(),
            body: fixture.body(),
            lanes: node.lanes(),
            runtime: tokio::runtime::Handle::current(),
        };
        tokio::task::spawn_blocking(move || node.answer(arrival, None))
            .await
            .expect("the loop's blocking worker joins")
    }

    const CASES: [Fixture; 6] = [
        Fixture::BufferedOk,
        Fixture::StreamedOk,
        Fixture::Malformed,
        Fixture::OverBudget,
        Fixture::PoolAcl,
        Fixture::UnknownModel,
    ];

    /// THE SWITCH. Same fixture in, same bytes and same counters out — through the shipped entry
    /// point and through the kernel's loop over the step files.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_loop_matches_the_shipped_entry_point_on_every_fixture() {
        let mut failures: Vec<String> = Vec::new();
        for fixture in CASES {
            let legacy = leg_legacy(fixture).await;
            let looped = leg_loop(fixture).await;
            for ((field, want), (_, got)) in legacy.0.iter().zip(looped.0.iter()) {
                if want != got {
                    failures.push(format!(
                        "{fixture:?}: field `{field}` diverges\n  shipped: {want}\n  loop:    {got}"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} divergence(s) across {} fixtures:\n{}",
            failures.len(),
            CASES.len(),
            failures.join("\n")
        );
    }

    /// The ENDS are what the fixtures claim they are. Without this the comparison above could be
    /// green on six identical 404s and prove nothing about the loop at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_fixture_reaches_the_end_it_names() {
        let mut seen: Vec<(Fixture, String)> = Vec::new();
        for fixture in CASES {
            let observed = leg_loop(fixture).await;
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
                // The arrival step's own parse refusal, before a model exists.
                (Fixture::Malformed, "400".to_string()),
                // The door's own turn-away.
                (Fixture::OverBudget, "429".to_string()),
                // The pre-admission guard, before pricing is asked about.
                (Fixture::PoolAcl, "403".to_string()),
                // Refused AFTER the door, so it is charged and audited as an admitted unit.
                (Fixture::UnknownModel, "404".to_string()),
            ],
            "the fixtures do not reach the six distinct ends they are named for"
        );
    }

    /// THE MONEY, spelled out rather than only compared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_loop_leaves_the_money_where_the_shipped_plane_leaves_it() {
        fn field(o: &Observed, k: &str) -> String {
            o.0.iter()
                .find(|(f, _)| *f == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        }

        // A STREAMED unit accrues at stream end rather than at the buffered tap, so it is asserted
        // in its own right: without this the comparison could be green on a stream metering nothing.
        let streamed = leg_loop(Fixture::StreamedOk).await;
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

        let delivered = leg_loop(Fixture::BufferedOk).await;
        assert_eq!(field(&delivered, "ledger_requests"), "1");
        assert_eq!(
            field(&delivered, "metering_rows"),
            format!("{LANE}/test in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1")
        );

        // The door refused: nothing was charged, so there is nothing on the key's bucket at all.
        let refused = leg_loop(Fixture::OverBudget).await;
        assert_eq!(field(&refused, "ledger_requests"), "0");
        assert_eq!(field(&refused, "metering_rows"), "");

        // The pre-admission guard refused: charged nothing either, and never reached the door.
        let guarded = leg_loop(Fixture::PoolAcl).await;
        assert_eq!(field(&guarded, "ledger_requests"), "0");

        // Refused after the door: the admission slot is drawn and NEVER released, which is the rule
        // that makes a request cap impossible to escape by failing.
        let post_door = leg_loop(Fixture::UnknownModel).await;
        assert_eq!(field(&post_door, "ledger_requests"), "1");
        assert_eq!(field(&post_door, "metering_rows"), "");
    }

    /// EXACTLY ONE LINK PER UNIT on the principal's chain, whichever door the unit left through.
    ///
    /// The rule the switch could most easily break: the shipped door POSTS its own refusal, and the
    /// step files' door does not — it renders, and the terminal posts. A unit that left through both
    /// would carry two links and the chain would still verify, which is why the COUNT is asserted
    /// rather than the verification alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_unit_leaves_exactly_one_link_on_the_chain() {
        use busbar_core::proxy::reqlog::REQUESTS;

        for fixture in [
            Fixture::BufferedOk,
            Fixture::OverBudget,
            Fixture::PoolAcl,
            Fixture::UnknownModel,
        ] {
            // LEG 1 — the shipped entry point names a destination on its link; whatever it names is
            // what the loop's link has to name too, so the expectation is READ rather than spelled.
            let shipped_rig = rig(fixture).await;
            let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
                host: shipped_rig.host(),
                gov: shipped_rig.gov(),
                caller_token: None,
            });
            let resp = busbar_llm::native_ingress::operation_ingress(
                &ctx,
                json_headers(),
                fixture.body(),
                PROTO,
                busbar_api::operation::Operation::CHAT,
                None,
            )
            .await;
            let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
            let shipped = REQUESTS.records_for(&shipped_rig.key.id);
            assert_eq!(shipped.len(), 1, "{fixture:?}: the shipped path posts once");
            shipped_rig.server.shutdown().await;

            // LEG 2 — the loop, on its own deployment.
            let rig = rig(fixture).await;
            let resp = drive(&rig, fixture).await;
            let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
            let records = REQUESTS.records_for(&rig.key.id);
            assert_eq!(records.len(), 1, "{fixture:?}: one unit, one link");
            assert_eq!(
                (
                    records[0].pool.clone(),
                    records[0].outcome.clone(),
                    records[0].reason.clone(),
                    records[0].status
                ),
                (
                    shipped[0].pool.clone(),
                    shipped[0].outcome.clone(),
                    shipped[0].reason.clone(),
                    shipped[0].status
                ),
                "{fixture:?}: the loop's link is the shipped path's link"
            );
            assert!(REQUESTS.verify_principal_chain(&rig.key.id).is_ok());
            rig.server.shutdown().await;
        }
    }

    /// THE TABLE IS THE PLANE'S TABLE. Same dialects, same names, same order.
    ///
    /// The switch replaces one arrival table with another, and a dialect missing from the
    /// replacement does not fail loudly — it resolves no arrival and the surface 404s, which is a
    /// deletion wearing a routing bug's clothes. So the two tables are compared as data.
    #[test]
    fn the_switched_table_names_every_dialect_the_plane_names() {
        let shipped: Vec<&str> = busbar_llm::BODY_INGRESS.iter().map(|(n, _)| *n).collect();
        let switched: Vec<&str> = BODY_INGRESS.iter().map(|(n, _)| *n).collect();
        assert_eq!(switched, shipped);
    }

    /// THE INTERNER IS THE NODE'S, and it is idempotent.
    ///
    /// A lane name is leaked to become the borrowed static one the priced axis is written in, so
    /// interning the same name twice must yield the same pointer: a leak per request would be a
    /// leak per request whatever it was called.
    #[test]
    fn the_nodes_interner_leaks_a_lane_name_once() {
        let node = LlmNode::new();
        let lanes = node.lanes();
        let first = lanes
            .lock()
            .expect("the node's interner is never poisoned")
            .lane(LANE);
        let again = lanes
            .lock()
            .expect("the node's interner is never poisoned")
            .lane(LANE);
        assert_eq!(first, again);
        assert!(std::ptr::eq(first.as_str(), again.as_str()));
    }
}
