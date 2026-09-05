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
            // that refused first would decide — silently, and with a different status. The table is
            // still real, because a hold still has to live somewhere.
            inflight: busbar_kernel::inflight::InFlight::new(0, 0),
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
                unit.walk.take_terminal().unwrap_or_else(|| unavailable(proto))
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
        if let Some(refusal) = self.deferred.lock().unwrap_or_else(|e| e.into_inner()).take() {
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

    fn audit(&self, token: &UnitToken<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Audit> {
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
    (busbar_llm::proto_codec::PROTO_ANTHROPIC, anthropic_body_arrival),
    (busbar_llm::proto_codec::PROTO_OPENAI, openai_body_arrival),
    (busbar_llm::proto_codec::PROTO_GEMINI, gemini_body_arrival),
    (busbar_llm::proto_codec::PROTO_BEDROCK, bedrock_body_arrival),
    (busbar_llm::proto_codec::PROTO_RESPONSES, responses_body_arrival),
    (busbar_llm::proto_codec::PROTO_COHERE, cohere_body_arrival),
];
