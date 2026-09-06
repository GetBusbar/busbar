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
//! to the step file it is delegated to; what this file owns is the binding, the interner it lends,
//! and the in-flight table the unit's cell lives in.

use std::collections::HashMap;
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
use busbar_contract::{LaneId, Registration, UnitKey};
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{AccrualMeter, Evidence, FeeEvidence, UnitCtx, Units};
use busbar_llm::unit::walk::{Tap, Walk, WalkArrival};
use busbar_llm::unit::{admit, approve, arrival, audit, authenticate, decode, verify};
use busbar_substrate::ingress::arrival::{Arrival as ArrivalRequest, ArrivalPayload};
use busbar_substrate::proxy::POOL_LABEL_UNRESOLVED;

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
static NATIVE_SEATS: &[&(dyn approve::VetoSeat + Sync)] = &[];

// ---------------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------------

/// THE NAMES THIS NODE HAS ALREADY RESOLVED, in front of the image's one interner.
///
/// The interner is a single mutex for the whole process — every plane, every node, every thread —
/// and the answer it gives for a given name never changes, because a leaked name is never unleaked.
/// So a step that asks it per request, per candidate lane, is queueing the whole image behind one
/// lock to be told something that was settled the first time the name was seen. This table is that
/// first time, kept: the interner is consulted once per distinct configured lane name for the life
/// of the node, and every request after reads the map.
///
/// Bounded by the number of configured lanes, because that is what its keys are.
struct LaneNames {
    interner: Arc<Mutex<Registration>>,
    resolved: HashMap<String, LaneId>,
    consulted: u64,
}

impl LaneNames {
    /// The id for one lane name, reaching the interner only for a name this node has not resolved.
    ///
    /// `None` where the image's vocabulary does not hold the name and cannot take it — the freeze
    /// is done, or the ceiling is reached — which is a refusal to route on that name rather than an
    /// error to recover from, and is not cached: a name the vocabulary refuses today is a name it
    /// may hold tomorrow, and nothing was leaked to remember.
    fn resolve(&mut self, name: &str) -> Option<LaneId> {
        if let Some(lane) = self.resolved.get(name) {
            return Some(*lane);
        }
        self.consulted += 1;
        let lane = self
            .interner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lane(name)?;
        self.resolved.insert(name.to_owned(), lane);
        Some(lane)
    }

    /// How many times the image's interner has been reached through this table.
    ///
    /// One per distinct lane name for the life of the node, which is the property the table exists
    /// for — and a number a test can read, rather than a claim about a lock.
    fn consulted(&self) -> u64 {
        self.consulted
    }
}

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
    /// The names this node has already put through that interner, so the request path does not put
    /// them through it again.
    lane_names: Mutex<LaneNames>,
    next_key: AtomicU64,
    /// THE BOOK THIS NODE SETTLES ONTO, once the composition root has bound one. See [`bind_book`].
    ///
    /// A cell rather than a field, because the node is reached through a `static` — a bare `fn` is
    /// what the arrival seam takes and a bare `fn` cannot capture — so the node exists before the
    /// boot that owns the book has finished assembling it.
    ///
    /// [`bind_book`]: LlmNode::bind_book
    book: std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>,
    /// The journal's token, minted from this node's own kernel at construction and lent to the exit
    /// arm for the length of one settlement.
    ///
    /// Minted outside the loop because making a posting durable happens after the exit has sealed
    /// the end: there is no step of the unit whose token could stand in, which is the same reason
    /// the verbs unit's and the transport-key unit's are minted outside it.
    durability_token: busbar_caps::DurabilityToken,
    /// THE CARD THIS NODE PRICES AGAINST, once the composition root has bound one. See [`bind_card`].
    ///
    /// The cost unit's own card, and it belongs HERE rather than on the plane. The plane reports what
    /// a unit consumed; what those quantities are worth is a question about the deployment's rates,
    /// and the rates are the root's to hold — so a plane that priced its own traffic would be a second
    /// place a rate lives, and two places a rate lives is two answers to what one request cost.
    ///
    /// It is also what carries the FLAT PER-REQUEST FEE onto the books. The card holds the configured
    /// fee beside the per-token rates, and the cost unit's pricing puts it on the posting as a line of
    /// its own — so a node that prices through the card cannot post the tokens and forget the fee.
    ///
    /// A cell for the same reason the book is one: the node is reached through a `static`, so it
    /// exists before the boot that reads the configuration has finished.
    ///
    /// [`bind_card`]: LlmNode::bind_card
    card: std::sync::OnceLock<Arc<busbar_unit_cost::RateCard>>,
    /// The usage record's token, minted from this node's own kernel at construction and lent to the
    /// exit arm for the length of one pricing.
    ///
    /// Minted outside the loop for the same reason the journal's and the ledger's are: the report a
    /// late accrual prices arrives after the exit sealed the end, so there is no step of the unit
    /// whose token could stand in.
    usage_token: busbar_caps::UsageToken,
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
        let lanes = Arc::new(Mutex::new(crate::root::kernel::new_registration()));
        let kernel = crate::root::kernel::new_kernel();
        LlmNode {
            durability_token: kernel.durability_token(),
            usage_token: kernel.usage_token(),
            book: std::sync::OnceLock::new(),
            card: std::sync::OnceLock::new(),
            kernel,
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
            lanes: Arc::clone(&lanes),
            lane_names: Mutex::new(LaneNames {
                interner: lanes,
                resolved: HashMap::new(),
                consulted: 0,
            }),
            next_key: AtomicU64::new(1),
        }
    }

    /// The interner, as the walk borrows it for the length of one unit.
    #[must_use]
    pub fn lanes(&self) -> Arc<Mutex<Registration>> {
        Arc::clone(&self.lanes)
    }

    /// Bind this node's exit arm to the book the process settles onto.
    ///
    /// The one book, handed in rather than opened here, and that is the whole point of it: the
    /// administrative views read the handle the boot holds, so a node that opened its own would post
    /// onto a set of books nothing serves and serve a set of books nothing posts to. Both would look
    /// healthy — an empty ledger reconciles — which is exactly why the binding is a wiring decision
    /// the composition root makes rather than a default this node falls into.
    ///
    /// Unbound, the exit arm below does nothing and the unit ends as it always has. That is the
    /// honest answer for a build with no root ledger in it, not a settlement quietly dropped.
    pub fn bind_book(&self, book: Arc<Mutex<crate::root::durability::Durability>>) {
        let _ = self.book.set(book);
    }

    /// Bind this node's exit arm to the card the process prices against.
    ///
    /// Built by the composition root from the SAME configured figures the previous release's usage
    /// projection derives its spend from — the per-model rates and the flat per-request fee — so the
    /// two sides of the reconciliation are two readings of one configuration rather than two
    /// configurations that happen to agree.
    ///
    /// Unbound, a report is not priced and nothing is posted. That is the honest answer for a build
    /// with no card in it: a node that fell back to a card of its own would post figures no operator
    /// configured, and they would look exactly like figures somebody did.
    pub fn bind_card(&self, card: Arc<busbar_unit_cost::RateCard>) {
        let _ = self.card.set(card);
    }

    /// Put what the loop posted onto the book, if this node has one.
    ///
    /// Three ways this does nothing, and each is a statement rather than a swallow. No book bound:
    /// the build carries no root ledger and there is nowhere for the posting to go. Already settled:
    /// the node's sweep took the hold first, and settling here would be the second settlement of one
    /// unit. A posting the record could not hold: the loop already recorded the durability loss on
    /// the end it sealed, and there is no posting to move.
    ///
    /// A journal that refuses the record is not a settlement rolled back. The books have moved and
    /// the value was delivered; what is lost is the proof, which the exit arm's own error says.
    fn settle_end(
        &self,
        principal: &PrincipalId,
        charged_at: u64,
        ended: busbar_kernel::teller::Ended,
    ) {
        let Some(book) = self.book.get() else {
            return;
        };
        let busbar_kernel::teller::Ended::Settled { end, .. } = ended else {
            return;
        };
        let Ok(posted) = end.into_posted() else {
            return;
        };
        let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let _settled = settle(
            &mut durability,
            principal,
            charged_at,
            &self.durability_token,
            posted,
        );
    }

    /// Walk one request through the loop and answer with what the terminal posted.
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a request that used to
    /// reach the plane's own shell directly. What comes back is what the AUDIT step posted: this
    /// function chooses the PATH, never the bytes.
    ///
    /// Awaited on the runtime the request arrived on. Drop this future — which is what axum does
    /// when the client hangs up — and the loop's own future goes with it: the unit ends at its one
    /// terminal, the hold leaves the cell, and [`Occupied`] hands the table its slot back on the way
    /// out. Nothing is spawned here, so there is no detached task left holding either.
    #[must_use]
    pub async fn answer(&self, arrival: WalkArrival, model_hint: Option<String>) -> Response {
        self.answer_with(arrival, model_hint, NATIVE_SEATS).await
    }

    /// The same drive, with the Approve seats named rather than assumed.
    ///
    /// [`answer`](Self::answer) is this with [`NATIVE_SEATS`], which is empty on every deployment
    /// today. It is split out because "nothing is seated, so the step is a no-op" and "a seated gate
    /// stops the unit before the door" are two behaviours of one arm, and only one of them can be
    /// reached through a mount that hard-codes the list.
    #[must_use]
    pub async fn answer_with(
        &self,
        arrival: WalkArrival,
        model_hint: Option<String>,
        seats: &[&(dyn approve::VetoSeat + Sync)],
    ) -> Response {
        let proto = arrival.proto;
        let op_class = OpClassId::new(arrival.operation.name());
        let key = UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed));
        let principal = authenticate::principal_id(&arrival.gov);
        // ONE METER, on both sides of the loop: the unit accrues onto it at the Meter step and the
        // kernel reads it at the exit. See `LlmUnit::meter`.
        let meter = Arc::new(AccrualMeter::new());
        let unit = LlmUnit {
            node: self,
            seats,
            meter: Arc::clone(&meter),
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

        let hold =
            busbar_kernel::inflight::arrival_hold(&self.kernel, &self.door, principal.clone());
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: hold,
            now: busbar_substrate::store::now_ms(),
        });

        match entered {
            // The table is uncapped on this listener, so this arm is the table declining for a
            // reason that is not capacity. It is still an answer rather than a panic.
            Err(_refused) => unavailable(proto),
            Ok(slot) => {
                // THE SLOT, from here to whichever way this unit leaves. The table is what bounds
                // how many units this node has in flight, so the one thing that must not depend on
                // the unit finishing is giving the slot back — and a client that hangs up is exactly
                // the case where it does not finish.
                let _occupied = Occupied {
                    table: &self.inflight,
                    key,
                };
                let ctx = UnitCtx {
                    key,
                    origin: OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: false,
                    kernel_verb_only: false,
                };
                let ended = busbar_kernel::teller::run_unit_async(
                    &self.kernel,
                    &unit,
                    &ctx,
                    busbar_kernel::teller::Run {
                        cell: slot.cell(),
                        parent: None,
                        leases: slot.leases(),
                        gauge: &self.gauge,
                        canary: &self.canary,
                        meter: &meter,
                    },
                    &unit,
                )
                .await;
                // THE EXIT ARM. The loop took the hold out of the cell and handed back a POSTING,
                // which has moved no balance and left no record until something settles it — and
                // until this line nothing did, so a unit ran, ended, posted, and posted into a value
                // that was dropped on the floor.
                let charged_at = unit.charged_at;
                self.settle_end(&principal, charged_at, ended);
                // The loop ran; the answer is whatever the terminal posted. There is no unit that
                // reaches an end without passing one of the two audit doors, so the fallback below
                // is unreachable — and it is an answer rather than an unwrap, because a path that
                // cannot be taken still has to say something if it is.
                let walk = unit.walk;
                let response = walk
                    .take_terminal()
                    .map(audit::Served::into_response)
                    .unwrap_or_else(|| unavailable(proto));
                // THE LATE ARM. The settlement above carried what the terminal knew, and on this
                // plane that is the record a unit ran and ended and nothing else: the money is in a
                // cell the response's own body fills when it DRAINS, which has not happened yet. So
                // the body goes out wrapped, and the figure lands when it arrives.
                self.attach_late_accrual(response, walk, &principal, charged_at)
            }
        }
    }

    /// Wrap the answer's body so the figure that arrives after the terminal has somewhere to land.
    ///
    /// Nothing here changes a byte of what the client is given: the frames, their order, the trailers
    /// and the size hint are the inner body's, forwarded. What the wrapper adds is a place to stand
    /// at the one instant this plane's money becomes a fact.
    ///
    /// Two ways this hands the response straight back, and each is a case where there is nothing to
    /// wait for. No book bound: the build carries no root ledger and there is nowhere for a posting
    /// to go. No tap on the response: nothing was ever going to fill one, so a wrapper would only
    /// ever drop empty.
    fn attach_late_accrual(
        &self,
        response: Response,
        walk: Walk,
        principal: &PrincipalId,
        charged_at: u64,
    ) -> Response {
        let Some(book) = self.book.get() else {
            return response;
        };
        // No card bound is the third: a report nothing can price is a report nothing can post, and
        // wrapping the body to discover that when it drains would be a wrapper that only ever drops
        // empty.
        let Some(card) = self.card.get() else {
            return response;
        };
        let Some(tap) = Walk::tap_of(&response) else {
            return response;
        };
        let arm = LateAccrual {
            book: Arc::clone(book),
            card: Arc::clone(card),
            // MINTED FOR THIS ONE POSTING and dropped with it. A token is neither `Clone` nor `Copy`
            // and the node's own is lent by reference for the length of a call, which is exactly what
            // this is not: the posting outlives every call on this path. So the pair is minted where
            // the unit is and travels with the body it is a posting OF.
            durability_token: self.kernel.durability_token(),
            ledger_token: self.kernel.ledger_token(),
            usage_token: self.kernel.usage_token(),
            principal: principal.clone(),
            // The unit's PINNED arrival epoch, not a clock read at drain time. The late posting lands
            // on the same balance and in the same window the terminal settled in, which is the whole
            // of what makes it the same row: a body that drained past midnight would otherwise open a
            // second day's row for a request the node admitted, priced and billed in the first.
            charged_at,
            walk,
            tap,
        };
        let (parts, body) = response.into_parts();
        Response::from_parts(parts, axum::body::Body::new(LateBody::new(body, arm)))
    }
}

// ---------------------------------------------------------------------------------------------
// The late accrual
// ---------------------------------------------------------------------------------------------

/// The plane's neutral consumption report, in the record the cost unit prices.
///
/// A lift and nothing more: one line per reported class, at the quantity the tap read, counted rather
/// than estimated because the figures came off the destination's own response. The class names are
/// the neutral reserved-unit spellings — the same names the plane's own metering step reports its
/// lines under and the same names a card entry is written against — so no name is translated on the
/// way. A rename here would be this root deciding what a lane's rates apply to.
///
/// The four reserved tiers are walked in the canonical order rather than the report's map order,
/// which is what makes the line sequence a property of this function rather than of a `BTreeMap`'s
/// collation. An OPEN unit a report carries prices at nothing on this path and is left off: the card
/// this node binds names the reserved four, so a line for a class it cannot price would be a zero
/// line claiming to be a priced one.
///
/// The flat fee is NOT a line built here. It is the card's, added by the pricing as a line of its own
/// from the billable count the report carries, which is what keeps one configured fee to one place.
fn usage_record(
    token: &busbar_caps::UsageToken,
    usage: &busbar_substrate::billing::Usage,
) -> busbar_caps::Usage {
    let lines = [
        busbar_api::UNIT_INPUT,
        busbar_api::UNIT_OUTPUT,
        busbar_api::UNIT_CACHE_READ,
        busbar_api::UNIT_CACHE_WRITE,
    ]
    .into_iter()
    .filter_map(|class| {
        // A zero-quantity line is not a fact about anything, and the plane's own metering step drops
        // them for the same reason. Kept out here too so the two reports have the same shape.
        let quantity = usage.usage_units.get(class).copied().unwrap_or(0);
        (quantity > 0).then(|| busbar_caps::UsageLine {
            class: busbar_caps::MeterClassId::new(class),
            quantity,
            source: busbar_caps::QuantitySource::Count,
            estimated: false,
        })
    })
    .collect();
    // A report wider than the record holds is not a reason to post nothing: the record's own limit is
    // a bound on lines, and the four tiers this plane reports are far inside it. An empty record is
    // the honest fallback — it prices the fee and no tokens, which is what a response that reported
    // nothing costs.
    busbar_caps::Usage::report(token, lines)
        .unwrap_or_else(|_| busbar_caps::Usage::report(token, Vec::new()).expect("no lines fit"))
}

/// **THE LATE ACCRUAL'S ARM.** What this unit spent, posted once the body that reports it has
/// drained.
///
/// The exit settles what it knows AT THE TERMINAL. On this plane a delivered answer's usage is not
/// among it: the response's completion tap fills its cell when the body is consumed, and the body is
/// consumed after the terminal handed the client its bytes, after the audit door sealed the end, and
/// after the slot went back to the table. A figure that arrives then is a LATE ACCRUAL — posted onto
/// the same principal, the same window and the same lane and provider the legacy row carries, flagged
/// so that a reader can tell it apart from a spend the door reserved for.
///
/// It needs no hold and no slot, and that is not an accommodation — it is what the flags SAY. The
/// reservation went back at the terminal, so the whole amount books as overdraft with nothing behind
/// it, which is the honest description of a spend the node learned about after it had let go.
struct LateAccrual {
    book: Arc<Mutex<crate::root::durability::Durability>>,
    /// The card the report is priced against — the deployment's configured rates and its flat
    /// per-request fee, in the cost unit's own terms.
    card: Arc<busbar_unit_cost::RateCard>,
    durability_token: busbar_caps::DurabilityToken,
    ledger_token: busbar_caps::LedgerToken,
    usage_token: busbar_caps::UsageToken,
    principal: PrincipalId,
    charged_at: u64,
    /// The unit's carry, kept alive for exactly as long as the body is: the reading needs the lane
    /// table the walk resolved and the facts the Route and Meter steps left, and both live here.
    walk: Walk,
    /// The cell the body fills. Held rather than looked up again, because by the time it is read the
    /// response it rode on no longer exists.
    tap: Tap,
}

impl LateAccrual {
    /// Read the tap and post what it says. Runs at most once per unit — see [`LateBody`].
    fn post(self) {
        let LateAccrual {
            book,
            card,
            durability_token,
            ledger_token,
            usage_token,
            principal,
            charged_at,
            walk,
            tap,
        } = self;
        let Some(report) = walk.reported_after_terminal(&tap) else {
            return;
        };
        // THE PRICING, and it happens HERE rather than on the plane. The plane said what the unit
        // consumed — quantities, by class — and how many billable requests it is. What that is worth
        // is the card's answer, and this is the only side that holds a card.
        //
        // The FEE comes with it, and it comes for free. The cost unit's pricing puts the flat
        // per-request charge on the posting as a line of its own, at the card's configured fee times
        // the count the plane reported, and sums it in with the token lines before the single tier
        // divide. So one call produces token lines AND a fee line, and there is no arm anywhere that
        // could post the tokens and forget the fee.
        //
        // That is what makes the identity exact rather than approximate. The previous release's
        // projection reprices a row's token counts and adds the same configured fee at read time; a
        // node that posted only the tokens was out by the fee on every billable request, and the
        // identity had to name the difference as its own term instead of checking it.
        let posting = busbar_unit_cost::price(
            &card.pin(),
            &report.lane,
            &usage_record(&usage_token, &report.usage),
            u64::from(report.fee_count),
            busbar_unit_cost::STANDARD_TIER_BP,
        );
        // THE ROW THIS LANDS ON. `report` names the serving lane and its provider — the two names the
        // legacy row is keyed by — and the balance below is keyed by principal and window. Those are
        // the same row: the node's books retain no lane and no provider, so both the ledger's side and
        // the legacy side of the reconciliation are read at the width the node keeps, with the two
        // names empty on BOTH. Carrying them here is what makes that a fact about the width rather
        // than a figure that lost its row on the way — and it is where a wider key attaches the day
        // the books grow one.
        //
        // A ZERO IS NOT A ROW, and posting one would say the node had settled something. A unit that
        // reached a lane and priced at nothing — no tokens, no fee, or a lane the card does not name —
        // is already fully described by the settlement the exit made.
        //
        // A figure too large for the record settles at the ceiling rather than wrapping, exactly as
        // the terminal's own settlement narrows it: there is no amount above the ceiling to post, and
        // a wrap would post nearly nothing for the most expensive unit the node has ever run.
        let amount = u64::try_from(posting.priced_amount()).unwrap_or(u64::MAX);
        if amount == 0 {
            return;
        }
        let accrual =
            busbar_caps::HoldAccrual::after_terminal(principal.clone(), amount, &ledger_token);
        let posted = busbar_caps::Posted::settle_late(accrual, &ledger_token);
        let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let _settled = settle(
            &mut durability,
            &principal,
            charged_at,
            &durability_token,
            posted,
        );
    }
}

/// The answer's body, with the late arm riding on it.
///
/// A passthrough and nothing more: every frame the inner body yields is the frame this yields, in
/// order, and the end-of-stream and size-hint questions are answered by asking it. The client cannot
/// tell this is here, which is the requirement — the previous release's bytes are the bytes.
///
/// The arm fires ONCE, on whichever of the two ends this body reaches. A body that runs to
/// `Ready(None)` has been drained and the tap has filled; a body that is DROPPED first has been cut,
/// which is the client hanging up mid-answer, and the tap fills on that path too — the engine's own
/// stream wrapper reports a partial from its `Drop`. Which of the two happened is the tap's to say
/// and not this wrapper's.
struct LateBody {
    /// `None` after the inner body has been let go, which is how the drop path orders itself.
    inner: Option<axum::body::Body>,
    /// `None` after the arm has fired, which is what makes "once" a property of the value.
    arm: Option<LateAccrual>,
}

impl LateBody {
    fn new(inner: axum::body::Body, arm: LateAccrual) -> Self {
        LateBody {
            inner: Some(inner),
            arm: Some(arm),
        }
    }

    /// Fire the arm if it has not fired. Called from both ends.
    fn fire(&mut self) {
        if let Some(arm) = self.arm.take() {
            arm.post();
        }
    }
}

impl http_body::Body for LateBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let Some(inner) = this.inner.as_mut() else {
            return std::task::Poll::Ready(None);
        };
        let polled = std::pin::Pin::new(inner).poll_frame(cx);
        // THE DRAIN. `Ready(None)` is the inner body saying it has no more frames, and by then its
        // own end-of-stream arm has already filled the tap — the report is on the cell before the
        // frame that ends the stream is handed back. A stream that ends in an ERROR is not fired on
        // here: that body is dropped rather than drained, and the drop path below is what reads it.
        if matches!(polled, std::task::Poll::Ready(None)) {
            this.fire();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner
            .as_ref()
            .is_none_or(http_body::Body::is_end_stream)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.as_ref().map_or_else(
            || http_body::SizeHint::with_exact(0),
            http_body::Body::size_hint,
        )
    }
}

impl Drop for LateBody {
    /// THE CUT. A client that hangs up mid-answer drops this body where it stands, and what the node
    /// bills for that is what the tap reported — the same figure the previous release's ledger took
    /// from the same cell, on the same event, which is why this arm posts rather than declining.
    ///
    /// The inner body is let go FIRST and the order is the whole of it: the engine's stream wrapper
    /// files its partial report from its own `Drop`, so an arm that read the cell before that ran
    /// would read an empty one and post nothing for a request the previous release charges for.
    /// Fields drop after this body runs, so dropping it by hand here is what puts the two in the
    /// order the figure needs.
    fn drop(&mut self) {
        drop(self.inner.take());
        self.fire();
    }
}

/// THE IN-FLIGHT SLOT, for the length of one unit.
///
/// The table is what bounds how many units this node has in flight, so the slot has to come back on
/// every way out of the unit — the answer, a panic, and the one this seam exists for: the client
/// hanging up mid-request, which drops the whole of `answer` where it stands. A `remove` written at
/// the end of that function comes back on one of those three.
struct Occupied<'n> {
    table: &'n busbar_kernel::inflight::InFlight,
    key: UnitKey,
}

impl Drop for Occupied<'_> {
    fn drop(&mut self) {
        self.table.remove(self.key);
    }
}

/// What a unit a seated gate stopped answers with, in the caller's own dialect.
///
/// One permission sentence, vendor-plausible, naming nothing of the operator's — not the seat, not
/// the principal, not a word of governance vocabulary — because a gate's veto is not entitled to a
/// reason of its own and a client is owed the same answer whichever gate stopped it. WHICH seat
/// stopped the unit is the operator's diagnostic, and the step file already logs it.
fn vetoed(proto: &str) -> Response {
    busbar_substrate::proxy::ingress_error(
        proto,
        StatusCode::FORBIDDEN,
        busbar_substrate::proxy::KIND_PERMISSION,
        "Your API key does not have permission to access this resource.",
    )
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
    /// The gates seated at Approve for this unit, in the order they are consulted. Borrowed for the
    /// length of the unit: a seat is configuration, and configuration is not per-request state.
    seats: &'n [&'n (dyn approve::VetoSeat + Sync)],
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
    /// THE LOOP'S OWN METER, held here as well as lent to the loop.
    ///
    /// The same value on both sides: the kernel is handed a borrow of this and the Meter step
    /// accrues onto it, because the step that knows what the unit is worth is not the step the loop
    /// hands the meter to. Two meters would be a unit that accrued on one and settled the other.
    meter: Arc<AccrualMeter>,
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

    /// The node's own answer, for a terminal reached with an empty carry.
    ///
    /// Handed to the walk's doors as a fallback rather than fetched here: the bytes a step rendered
    /// live in the walk's carry and the walk hands them to the door itself, so there is no
    /// expression on this side that evaluates to a finished response before a door has posted one.
    /// Unreachable from the loop's order — every path to a terminal has already rendered
    /// something — and an answer rather than an unwrap, because a path that cannot be taken still
    /// has to say something if it is.
    fn nothing_rendered(&self) -> audit::Served {
        audit::Served::of(unavailable(self.walk.proto()))
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
            let mut names = self
                .node
                .lane_names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.walk
                .candidate_lane_names(&model)
                .iter()
                // A lane the frozen vocabulary does not hold is not a candidate this node can
                // route to, so it is left out rather than sealed under a name it cannot name.
                .filter_map(|name| {
                    names
                        .resolve(name)
                        .map(|lane| VerifiedDestination::seal(trust, lane))
                })
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
            self.walk.hold_bytes(vetoed(self.walk.proto()));
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
        token: &UnitToken<Admit>,
        admit_token: &AdmitToken<Admit>,
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
        // THIS PLANE'S ROUTE AWAITS, so it is answered by the `RouteAwait` arm below and this one is
        // not a path any unit on this plane takes: `LlmNode::answer` drives the loop's asynchronous
        // entry point and there is no other caller. Answered rather than unwrapped — an arm that
        // cannot be taken is still an arm that must say something — and answered with the reason a
        // synchronous driver would truly have: there is no task here to run the leg on.
        Decision::refuse(token, Refusal::new(ReasonCode::TaskLost))
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        // THE ACCRUAL IS NOT MADE HERE, and the reason is a fact about this plane rather than a
        // choice. What the unit is worth is what the response's tap reports, and the tap fills its
        // cell when the BODY is consumed — which on this surface is after the loop's terminal has
        // handed the client its bytes. At this step the cell is on the response and empty, so a
        // figure read here would be zero on every delivered unit and a meter accruing it would be
        // accruing a zero it could not tell from a free request.
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
        self.walk.audit(token, &self.audit_ctx(&destination), || {
            self.nothing_rendered()
        })
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
        self.walk
            .audit_refused(token, &self.audit_ctx(&destination), || {
                self.nothing_rendered()
            })
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

/// STEP 5, ROUTE — the one step of this plane's ten that waits on anything.
///
/// The leg is the walk's own future, boxed because it is an `async` block and handed straight to the
/// loop, which awaits it on the runtime serving this request. Nothing spawns it and nothing joins
/// it: it is polled where the request already is, so no thread is parked for the length of the
/// upstream call and dropping the unit drops the leg.
impl busbar_kernel::teller::RouteAwait for LlmUnit<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a UnitToken<Route>,
        _ctx: &'a UnitCtx,
        _meter: &'a AccrualMeter,
    ) -> busbar_kernel::teller::RouteLeg<'a> {
        // The destination the charge actually LANDED on — post-downgrade, never the requested one.
        // Dispatching through the pool the client asked for after charging a different one is the
        // bug this ordering makes impossible.
        let destination = self.walk.effective_pool(&self.model());
        // THE METER IS NOT ACCRUED ON THIS LEG, and it is the plane's timing that says so rather
        // than a policy: what this unit is worth is what the response's tap reports, and the tap
        // reports when the BODY is consumed, which is after the unit has ended. There is nothing for
        // a leg to accrue at this point that would not be a zero.
        //
        // The unit still holds the loop's own meter — the same one this argument names — so that
        // the figure has somewhere to land when the settlement moves to where the tap is.
        Box::pin(async move { self.walk.route(token, &destination).await })
    }
}

// ---------------------------------------------------------------------------------------------
// The exit arm
// ---------------------------------------------------------------------------------------------

/// The balance an LLM unit's kernel posting moves: the caller's own, in nano-units, unscoped.
///
/// The caller rather than the pool, because the kernel's posting is the unit's — what the POOL spent
/// is the governance ledger's figure and is already moved there by the walk's tap. Two figures, two
/// books, neither a second spelling of the other.
fn balance(principal: &PrincipalId) -> busbar_unit_ledger::totals::TotalsKey {
    busbar_unit_ledger::totals::TotalsKey::new(
        busbar_unit_ledger::totals::BucketId::new(principal.as_str()),
        busbar_unit_ledger::totals::CapDimension::NanoUnits,
        busbar_unit_ledger::totals::BucketScope::All,
    )
}

/// **THE EXIT ARM.** Move the books for what this unit posted, and put the posting on the journal.
///
/// The loop's exit path takes the hold out of its cell, applies what the unit spent and settles it —
/// that is where the hold stops existing. What comes back is the POSTING, and until it reaches here
/// it has moved no balance and left no record. So this is the far end of the reservation's life, and
/// on this plane it is the far end of a reservation the door opened at zero: the spend is the
/// governance ledger's and what settles here is the kernel's own record that a unit ran and ended.
///
/// The window comes off the unit's pinned arrival epoch, never a fresh clock read, so a request that
/// straddled a boundary posts in the window it was admitted in — the same epoch every charge and
/// every refund this unit made was landed in.
///
/// # Errors
///
/// The journal could not make the record durable. The books have already moved: value was delivered,
/// and a settlement is not rolled back because a write failed.
pub fn settle(
    durability: &mut crate::root::durability::Durability,
    principal: &PrincipalId,
    charged_at: u64,
    token: &busbar_caps::DurabilityToken,
    posted: busbar_caps::Posted,
) -> Result<crate::root::durability::Settled, busbar_caps::DurabilityLost> {
    let key = balance(principal);
    let at = crate::root::durability::Settling {
        key: &key,
        window: busbar_unit_admission::budget_window(
            busbar_unit_admission::window::WINDOW_DAY,
            charged_at,
        ),
        durability: token,
        // The loop has no exit step of its own; the figure this posting is OF is the metering step's,
        // and that is the step a durability loss here is attributed to.
        step: busbar_caps::StepName::Meter,
        stamp: crate::root::durability::PostingStamp {
            rate_card_version: 0,
            wall: charged_at,
            mono: charged_at,
        },
    };
    durability.settle_posted(&at, posted)
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

/// Bind the process's one node to the process's one book.
///
/// Called by the composition root at boot, with the same handle the administrative views were bound
/// to. Without it the exit arm settles nothing and the root's ledger stays empty — which reads as a
/// node that has posted nothing rather than as a node whose postings had nowhere to go.
pub fn bind_book(book: Arc<Mutex<crate::root::durability::Durability>>) {
    NODE.bind_book(book);
}

/// Bind the process's one node to the card it prices against, built from the configured rates.
///
/// `rates` is the deployment's `rate_card:` as the neutral per-lane raw view, and `fee_cents` is its
/// flat per-request fee — the SAME two configured figures the previous release's usage projection
/// derives a row's spend from. Read once at boot, in the composition root, because that is the one
/// place entitled to hold a configuration; the plane below never sees a rate.
///
/// A deployment with no `rate_card:` binds an ABSENT card rather than no card at all, and the
/// difference matters: absent prices every class at nothing and still charges the flat fee, which is
/// exactly what the previous release bills for that deployment. Skipping the binding instead would
/// post nothing for a node that charges a fee.
pub fn bind_card<'r>(
    rates: impl IntoIterator<Item = (&'r str, busbar_substrate::billing::RawTierRates)>,
    fee_cents: i64,
    present: bool,
) {
    NODE.bind_card(Arc::new(card_from_config(rates, fee_cents, present)));
}

/// The configured rates, in the cost unit's own card.
///
/// The version is a constant name rather than a hash of the configuration, and that is a stated
/// limit rather than an oversight: the postings this card prices are read back at the width the node
/// keeps, which carries no card version, so nothing downstream can tell two versions apart yet. The
/// day the books grow that column, this is the one line that fills it.
fn card_from_config<'r>(
    rates: impl IntoIterator<Item = (&'r str, busbar_substrate::billing::RawTierRates)>,
    fee_cents: i64,
    present: bool,
) -> busbar_unit_cost::RateCard {
    let version = busbar_unit_cost::RateCardVersion::new("root-llm");
    if !present {
        return busbar_unit_cost::RateCard::absent(version, fee_cents);
    }
    // One entry per (lane, class), in the neutral reserved-unit spellings the plane's own metering
    // step reports its lines under — so a line the plane reports and the card entry that prices it
    // are keyed by the same name, with no translation between them.
    let mut entries = Vec::new();
    for (lane, raw) in rates {
        for (class, micro) in [
            (busbar_api::UNIT_INPUT, raw.input),
            (busbar_api::UNIT_OUTPUT, raw.output),
            (busbar_api::UNIT_CACHE_READ, raw.cache_read),
            (busbar_api::UNIT_CACHE_WRITE, raw.cache_write),
        ] {
            entries.push((busbar_unit_cost::LaneClass::new(lane, class), micro));
        }
    }
    busbar_unit_cost::RateCard::from_micro_rates(version, entries, fee_cents)
}

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
        // A body-model arrival: the model rides the body, so there is no URL fact to carry and the
        // dialect's miss copy, where it has one, is not this surface's.
        path: None,
    };
    // THE LOOP AWAITS, so it is awaited: right here, on the task and the runtime this request
    // already arrived on. Nothing is spawned, so nothing outlives the client — a connection that
    // goes away drops this future, and with it the loop, the walk and the upstream leg.
    NODE.answer(arrival, model_hint).await
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
    parsed: busbar_llm::arrival::PathArrivalFacts,
    ctx: busbar_substrate::ingress::arrival::ArrivalCtx,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    use busbar_llm::arrival::PathArrivalFacts;
    // The URL's facts, the operation they resolved to, and the routing hint a body-model shape
    // carries. Exactly one of the first and the last is ever set.
    let (facts, operation, model_hint) = match parsed {
        PathArrivalFacts::Refused(resp) => return resp,
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
        // THE URL'S FACTS, handed to the unit's own carry rather than pinned to a thread. They are
        // read by three steps — the parse-and-splice at step 0, the handler lookup at step 1 and the
        // dialect's miss copy at step 5 — and the third of those is on the far side of the loop's one
        // await, which is exactly where a thread-pinned fact stops being this unit's.
        path: facts,
    };
    // The same drive the body arrivals make: awaited here, on the task the request arrived on.
    NODE.answer(arrival, model_hint).await
}

/// GEMINI'S PATH ARRIVAL, ON THE LOOP. The dialect's own tail decode and URL parse, then the loop.
fn gemini_path_arrival(
    a: ArrivalRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    // Pinned before the parse, because a parse that rejects accounts its own rejection against them.
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    let rest = busbar_llm::arrival::gemini_rest(&a.host, &a.path);
    let parsed = busbar_llm::arrival::gemini_path_parse(
        &a.host, &a.ctx, &rest, &a.uri, &a.body, started, charged_at,
    );
    Box::pin(path_arrival(
        busbar_llm::proto_codec::PROTO_GEMINI,
        parsed,
        a.ctx,
        a.headers,
        a.body,
    ))
}

/// BEDROCK'S PATH ARRIVAL, ON THE LOOP. Three shapes under one model path, and the native 404 for
/// anything else — all four the dialect's own answer, and only the driving is this file's.
fn bedrock_path_arrival(
    a: ArrivalRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    let parsed = busbar_llm::arrival::bedrock_path_parse(
        &a.host, &a.ctx, &a.path, &a.uri, &a.body, started, charged_at,
    );
    Box::pin(path_arrival(
        busbar_llm::proto_codec::PROTO_BEDROCK,
        parsed,
        a.ctx,
        a.headers,
        a.body,
    ))
}

/// THE PATH-MODEL ARRIVALS, ON THE LOOP — the switched-over twin of the plane's own `PATH_INGRESS`.
///
/// Same two dialects, same names, same table; what changes is the PATH a request takes to reach the
/// answer. The composition root installs this one instead of the plane's when `root-llm` is on, and
/// with it off this static does not exist and the surface is the one it was.
pub static PATH_INGRESS: &[(&str, busbar_substrate::ingress::arrival::PathIngress)] = &[
    (busbar_llm::proto_codec::PROTO_GEMINI, gemini_path_arrival),
    (busbar_llm::proto_codec::PROTO_BEDROCK, bedrock_path_arrival),
];

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
    use busbar_kernel::teller::Ended;

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
        /// The BEARER the deployment's own door will resolve back to [`Rig::key`]. Minted rather
        /// than synthesized, so a fixture that presents it is presenting the thing a client sends.
        token: String,
        /// A bearer for a SECOND key on the same deployment whose lifetime has already run out.
        /// It verifies against the same signer and names a live, enabled binding — the only thing
        /// wrong with it is the clock, which is what makes it an expiry fixture rather than a
        /// forgery fixture.
        expired_token: String,
        server: MockServer,
        /// The scripted upstream's own state, kept so a fixture can ask whether the upstream was
        /// dialled at all — "the unit stopped before the route step" is not a fact any counter on
        /// this side of the loop reports.
        upstream: Arc<MockServerState>,
        charged_at: u64,
        group: String,
    }

    /// The signing secret every rig's door verifies against. One process-wide constant, because a
    /// per-rig secret would make "this token is not ours" and "this token has expired" the same
    /// failure.
    const SIGNING_SECRET: [u8; 32] = [7u8; 32];
    /// When a rig's tokens are minted, and when the live one runs out. The live `exp` is far enough
    /// out that a wall clock reads it as valid; the expired one is already behind every clock.
    const MINTED_AT: u64 = 1_700_000_000;
    const LIVE_EXP: u64 = 4_000_000_000;
    const DEAD_EXP: u64 = 1_000_000_000;

    async fn rig(fixture: Fixture) -> Rig {
        busbar_llm::testkit::install_test_seams();
        busbar_core::metrics::init();

        let state = Arc::new(MockServerState::new());
        for _ in 0..8 {
            state.push(fixture.upstream());
        }
        let server = MockServer::new(Arc::clone(&state)).await;

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
        // A SIGNER, so the keys below are minted as the credentials a client actually presents and
        // the deployment's own door can be asked to resolve them. Without one a rig could only ever
        // hand the plane a hand-built context, which is the one thing an authenticate fixture must
        // not do.
        let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
            &SIGNING_SECRET,
            busbar_substrate::governance::signing::DEFAULT_KID,
        );
        let gov = Arc::new(
            busbar_core::governance::GovState::new_with_signer(store, None, Some(signer))
                .expect("governance"),
        );
        let spec = |name: &str| busbar_substrate::governance::NewKeySpec {
            name: name.to_string(),
            allowed_pools: fixture.key_scopes(),
            group: fixture
                .seeded_group_requests()
                .is_some()
                .then(|| group.clone()),
            labels: Default::default(),
            ..Default::default()
        };
        let (key, token) = gov
            .mint_signed(spec("root-llm"), LIVE_EXP, MINTED_AT)
            .expect("mint the deployment's key");
        let (_, expired_token) = gov
            .mint_signed(spec("root-llm-expired"), DEAD_EXP, MINTED_AT)
            .expect("mint the expired key");
        let cost = busbar_core::cost::CostModel::resolve_parts(None, FEE_CENTS, &groups);
        gov.hydrate_budgets(&cost, 0).expect("hydrate");

        let app = TestApp::new()
            // THE CONFIGURED AUTH CHAIN, so `identity_admit` runs the same resolution the HTTP
            // middleware runs rather than falling through an open front door.
            .keys_chain()
            .lane(LaneSpec::new(LANE, PROTO, &server.base_url()).provider("test"))
            .pool(POOL, &[(0, 1)])
            .governance(gov)
            .cost(cost)
            .build();

        Rig {
            app,
            key: Arc::new(key),
            token,
            expired_token,
            server,
            upstream: state,
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

    /// One field of what a leg left behind, by name. Absent reads as empty rather than panicking,
    /// so a comparison that named a field nobody observes fails on the VALUE rather than on the
    /// lookup — a missing field is a divergence, not a test bug.
    fn field(o: &Observed, k: &str) -> String {
        o.0.iter()
            .find(|(f, _)| *f == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// Compare the two legs field by field, collecting every divergence under `label` rather than
    /// stopping at the first — one run should name everything that moved, not the earliest thing.
    fn compare(label: &str, legacy: &Observed, looped: &Observed, failures: &mut Vec<String>) {
        for ((f, want), (_, got)) in legacy.0.iter().zip(looped.0.iter()) {
            if want != got {
                failures.push(format!(
                    "{label}: field `{f}` diverges\n  shipped: {want}\n  loop:    {got}"
                ));
            }
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

    /// One request, through the real loop, awaited on this task — exactly as the mount drives it.
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
            path: None,
        };
        node.answer(arrival, None).await
    }

    const CASES: [Fixture; 6] = [
        Fixture::BufferedOk,
        Fixture::StreamedOk,
        Fixture::Malformed,
        Fixture::OverBudget,
        Fixture::PoolAcl,
        Fixture::UnknownModel,
    ];

    /// The unit-arrival epoch this proof pins, so the window a posting lands in is a fixed one.
    const EPOCH: u64 = 1_700_000_000;

    /// **THE EXIT ARM, END TO END.** The reservation the door opened reaches the journal.
    ///
    /// The loop's exit path is where a hold stops existing, and what it hands back is a POSTING that
    /// has moved no balance and left no record until something settles it. Before this arm was bound
    /// nothing on this plane did, so a unit ran, ended, posted — and posted into a value that was
    /// dropped. This drives the REAL loop over the real steps, takes the end it sealed, and puts the
    /// posting on a journal it then reads back.
    ///
    /// The figures are this plane's own: the door opens the kernel's hold at zero, because the spend
    /// is the governance ledger's and the walk's tap already moved it. So what this proves is not a
    /// price — it is that the kernel's record of a unit having run reaches a durable record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_exit_arm_puts_the_loops_posting_on_the_journal() {
        let rig = rig(Fixture::BufferedOk).await;
        let node = LlmNode::new();
        let ended = drive_to_end(&rig, &node, Fixture::BufferedOk, rig.gov(), NATIVE_SEATS).await;
        rig.server.shutdown().await;

        let Ended::Settled { end, .. } = ended else {
            panic!("the exit path settles the unit");
        };
        let posted = end.into_posted().expect("the usage report fits the record");
        assert_eq!(
            posted.reserved(),
            0,
            "this plane's door opens the kernel's hold at zero; the spend is the governance ledger's"
        );

        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let mut durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");
        let who = PrincipalId::new("acct:llm");
        let settled = settle(
            &mut durability,
            &who,
            EPOCH,
            &busbar_caps::DurabilityToken::mint(&seal),
            posted,
        )
        .expect("the memory-buffered journal takes it");
        assert!(settled.overdraft.is_none(), "nothing to carry out");

        let window =
            busbar_unit_admission::budget_window(busbar_unit_admission::window::WINDOW_DAY, EPOCH);
        let figures = durability.ledger.book().get(&balance(&who), window);
        assert_eq!(figures.overdraft_carried_out, 0);
        let replayed = durability
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies");
        assert_eq!(replayed.len(), 1, "one posting, one record");
    }

    /// One request, driven through the real loop, answering with the END rather than the bytes.
    ///
    /// The same drive [`LlmNode::answer`] performs — the same table, the same slot, the same
    /// `run_unit_async` — kept apart only because the entry point answers a client and this answers
    /// the exit arm's proof.
    ///
    /// `gov` is the caller's own resolved context rather than the rig's, because what the
    /// authenticate step ANSWERS is only visible on this side of the loop: the hold the door opens
    /// is opened for the principal that step settled on, and the posting the exit hands back names
    /// it. A drive that always used the rig's key could not tell the step's answer from the walk's.
    async fn drive_to_end<'n>(
        rig: &Rig,
        node: &'n LlmNode,
        fixture: Fixture,
        gov: busbar_api::PlaneRequestCtx,
        seats: &'n [&'n (dyn approve::VetoSeat + Sync)],
    ) -> Ended {
        let arrival = WalkArrival {
            host: rig.host(),
            gov,
            proto: PROTO,
            operation: busbar_api::operation::Operation::CHAT,
            caller_token: None,
            headers: json_headers(),
            body: fixture.body(),
            path: None,
        };
        let key = UnitKey::new(node.next_key.fetch_add(1, Ordering::Relaxed));
        let principal = authenticate::principal_id(&arrival.gov);
        let meter = Arc::new(AccrualMeter::new());
        let unit = LlmUnit {
            node,
            seats,
            meter: Arc::clone(&meter),
            op_class: OpClassId::new(arrival.operation.name()),
            model_hint: None,
            started: Instant::now(),
            charged_at: EPOCH,
            deferred: Mutex::new(None),
            model: Mutex::new(String::new()),
            walk: Walk::open(arrival),
        };
        let hold = busbar_kernel::inflight::arrival_hold(&node.kernel, &node.door, principal);
        let slot = node
            .inflight
            .insert(busbar_kernel::inflight::Enter {
                key,
                origin: OriginKind::Client,
                session: None,
                admin_listener: false,
                provider_of_open_session: false,
                zero_hold_tick: false,
                arrival: hold,
                now: busbar_substrate::store::now_ms(),
            })
            .expect("the uncapped table takes the unit");
        let ctx = UnitCtx {
            key,
            origin: OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        let ended = busbar_kernel::teller::run_unit_async(
            &node.kernel,
            &unit,
            &ctx,
            busbar_kernel::teller::Run {
                cell: slot.cell(),
                parent: None,
                leases: slot.leases(),
                gauge: &node.gauge,
                canary: &node.canary,
                meter: &meter,
            },
            &unit,
        )
        .await;
        node.inflight.remove(key);
        ended
    }

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

    // ── THE TWO SURFACES WHOSE MODEL IS IN THE URL ─────────────────────────────────────────────

    /// The two dialects that keep their model in the path.
    const GEMINI: &str = busbar_llm::proto_codec::PROTO_GEMINI;
    const BEDROCK: &str = busbar_llm::proto_codec::PROTO_BEDROCK;

    /// The four ends a URL-model fixture reaches. Malformed and the pool ACL are the body surface's
    /// fixtures and are exercised there; what these four pin is the surface that was OFF the loop —
    /// a delivered answer, a streamed one, a name that resolves to nothing, and a spent budget.
    const PATH_CASES: [Fixture; 4] = [
        Fixture::BufferedOk,
        Fixture::StreamedOk,
        Fixture::UnknownModel,
        Fixture::OverBudget,
    ];

    /// THE NATIVE REQUEST BODY each dialect's client sends. The model is NOT in it — that is the whole
    /// point of the surface — so one body per dialect serves every fixture.
    fn path_body(proto: &str) -> Bytes {
        let v = if proto == GEMINI {
            serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]})
        } else {
            serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]})
        };
        Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
    }

    /// The URL's facts, as the carry names them.
    type PathFacts = busbar_llm::arrival::PathModelFacts;

    /// WHAT THE URL SAYS, for the URL each fixture is sent to.
    ///
    /// Spelled here rather than parsed, because the parse is the DIALECT'S and is pinned beside it —
    /// `busbar_llm`'s own tests drive the real `gemini_path_parse` / `bedrock_path_parse` over these
    /// exact URLs and assert these exact facts. What this file is responsible for is what the loop
    /// does with them.
    fn path_facts(proto: &'static str, fixture: Fixture) -> PathFacts {
        let model = fixture.model().to_string();
        let stream = fixture.streamed();
        PathFacts {
            operation: busbar_api::operation::Operation::CHAT,
            stream,
            // `/v1beta/models/{model}:streamGenerateContent` with no `?alt=sse` is the JSON-array
            // framing; bedrock has no such framing at all.
            gemini_json_array: proto == GEMINI && stream,
            // The gemini surface echoes its own versioned not-found copy; bedrock uses the neutral
            // sentence. The api version is the one the fixture's `/v1beta/...` URL carries.
            model_not_found_message: (proto == GEMINI).then(|| {
                format!(
                    "models/{model} is not found for API version v1beta, \
                     or is not supported for the task you are trying to perform."
                )
            }),
            model,
        }
    }

    /// LEG 1 — the shipped path-model entry point, on its own deployment.
    async fn leg_legacy_path(fixture: Fixture, proto: &'static str) -> Observed {
        let rig = rig(fixture).await;
        let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
            host: rig.host(),
            gov: rig.gov(),
            caller_token: None,
        });
        let facts = path_facts(proto, fixture);
        let resp = busbar_llm::native_ingress::ingress_path_model(
            &ctx,
            json_headers(),
            path_body(proto),
            facts.model,
            facts.operation,
            facts.stream,
            facts.gemini_json_array,
            proto,
            facts.model_not_found_message,
        )
        .await;
        let observed = observe(&rig, resp).await;
        rig.server.shutdown().await;
        observed
    }

    /// LEG 2 — the same request through the kernel's loop, with the URL's facts in the unit's carry.
    async fn leg_loop_path(fixture: Fixture, proto: &'static str) -> Observed {
        let rig = rig(fixture).await;
        let node = LlmNode::new();
        let facts = path_facts(proto, fixture);
        let arrival = WalkArrival {
            host: rig.host(),
            gov: rig.gov(),
            proto,
            operation: facts.operation,
            caller_token: None,
            headers: json_headers(),
            body: path_body(proto),
            path: Some(facts),
        };
        let resp = node.answer(arrival, None).await;
        let observed = observe(&rig, resp).await;
        rig.server.shutdown().await;
        observed
    }

    /// THE SWITCH, ON THE URL-MODEL SURFACES. Same request in, same bytes and same counters out —
    /// through the shipped path-model entry point and through the kernel's loop over the step files.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_loop_matches_the_shipped_path_model_entry_point() {
        let mut failures: Vec<String> = Vec::new();
        for proto in [GEMINI, BEDROCK] {
            for fixture in PATH_CASES {
                let legacy = leg_legacy_path(fixture, proto).await;
                let looped = leg_loop_path(fixture, proto).await;
                for ((field, want), (_, got)) in legacy.0.iter().zip(looped.0.iter()) {
                    if want != got {
                        failures.push(format!(
                            "{proto}/{fixture:?}: field `{field}` diverges\n  shipped: {want}\n  loop:    {got}"
                        ));
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} divergence(s) across the two url-model dialects:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The ENDS are what these fixtures claim they are. Without this the comparison above could be
    /// green on eight identical 404s and prove nothing about the surface at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_url_model_fixture_reaches_the_end_it_names() {
        let mut seen: Vec<(&str, Fixture, String)> = Vec::new();
        for proto in [GEMINI, BEDROCK] {
            for fixture in PATH_CASES {
                let observed = leg_loop_path(fixture, proto).await;
                let status = observed
                    .0
                    .iter()
                    .find(|(k, _)| *k == "status")
                    .map(|(_, v)| v.clone())
                    .expect("every leg observes a status");
                seen.push((proto, fixture, status));
            }
        }
        let want: Vec<(&str, Fixture, String)> = [GEMINI, BEDROCK]
            .into_iter()
            .flat_map(|proto| {
                [
                    (proto, Fixture::BufferedOk, "200".to_string()),
                    (proto, Fixture::StreamedOk, "200".to_string()),
                    // Refused AFTER the door, so it is charged and audited as an admitted unit.
                    (proto, Fixture::UnknownModel, "404".to_string()),
                    // The door's own turn-away, in each dialect's own status vocabulary: gemini
                    // answers a throttle as a throttle, bedrock's envelope carries it as a client
                    // error. Both are the shipped entry point's answer, read off it rather than
                    // assumed — the leg above proves the two legs agree.
                    (
                        proto,
                        Fixture::OverBudget,
                        if proto == BEDROCK { "400" } else { "429" }.to_string(),
                    ),
                ]
            })
            .collect();
        assert_eq!(
            seen, want,
            "the url-model fixtures do not reach the ends they are named for"
        );
    }

    /// A URL THAT NAMED NO MODEL ENDS WHERE THE SHIPPED ENTRY POINT ENDS IT.
    ///
    /// The empty URL model is REACHABLE: bedrock's own path parse ends `unwrap_or_default()`, so a
    /// converse path whose model segment the handler did not recognise arrives as a `PathModelFacts`
    /// carrying an empty string. The shipped path-model entry point has no empty-model rung at all —
    /// it injects whatever the URL gave into the body and lets resolution answer, which for an empty
    /// name is the ordinary model-miss 404, taken after the door and therefore charged.
    ///
    /// That is the answer the loop has to give too, and it is the whole reason this case is pinned:
    /// the body-model entry point DOES carry an empty-model rung (`Some(m) if !m.is_empty()` → a
    /// 400 "Missing required parameter"), and a step file that copies that rung onto the URL surface
    /// turns one dialect's unrecognised path segment from a charged 404 into an uncharged 400. Two
    /// different statuses, two different ledgers, on a request the shipped node answers one way.
    ///
    /// Compared field for field against the shipped entry point rather than asserted as a number, so
    /// the body, the headers and the money all have to agree and not merely the status.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_empty_url_model_ends_where_the_shipped_path_model_entry_point_ends_it() {
        /// The fixture's facts with the model taken out — the shape bedrock's parse produces for a
        /// path whose model segment resolved to nothing.
        fn nameless(proto: &'static str) -> PathFacts {
            let mut facts = path_facts(proto, Fixture::UnknownModel);
            facts.model = String::new();
            facts.model_not_found_message = (proto == GEMINI).then(|| {
                "models/ is not found for API version v1beta, or is not supported for the task \
                 you are trying to perform."
                    .to_string()
            });
            facts
        }

        let mut failures: Vec<String> = Vec::new();
        for proto in [GEMINI, BEDROCK] {
            let shipped = {
                let rig = rig(Fixture::UnknownModel).await;
                let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
                    host: rig.host(),
                    gov: rig.gov(),
                    caller_token: None,
                });
                let facts = nameless(proto);
                let resp = busbar_llm::native_ingress::ingress_path_model(
                    &ctx,
                    json_headers(),
                    path_body(proto),
                    facts.model,
                    facts.operation,
                    facts.stream,
                    facts.gemini_json_array,
                    proto,
                    facts.model_not_found_message,
                )
                .await;
                let observed = observe(&rig, resp).await;
                rig.server.shutdown().await;
                observed
            };
            let looped = {
                let rig = rig(Fixture::UnknownModel).await;
                let node = LlmNode::new();
                let arrival = WalkArrival {
                    host: rig.host(),
                    gov: rig.gov(),
                    proto,
                    operation: busbar_api::operation::Operation::CHAT,
                    caller_token: None,
                    headers: json_headers(),
                    body: path_body(proto),
                    path: Some(nameless(proto)),
                };
                let resp = node.answer(arrival, None).await;
                let observed = observe(&rig, resp).await;
                rig.server.shutdown().await;
                observed
            };
            for ((field, want), (_, got)) in shipped.0.iter().zip(looped.0.iter()) {
                if want != got {
                    failures.push(format!(
                        "{proto}: field `{field}` diverges on a URL that named no model\n  \
                         shipped: {want}\n  loop:    {got}"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} divergence(s) on the empty URL model:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// THE PATH TABLE IS THE PLANE'S PATH TABLE. Same dialects, same names, same order — the
    /// path-axis twin of the body-table comparison below, and for the same reason: a dialect missing
    /// from the replacement resolves no arrival and the surface 404s, which is a deletion wearing a
    /// routing bug's clothes.
    #[test]
    fn the_switched_path_table_names_every_dialect_the_plane_names() {
        let shipped: Vec<&str> = busbar_llm::PATH_INGRESS.iter().map(|(n, _)| *n).collect();
        let switched: Vec<&str> = PATH_INGRESS.iter().map(|(n, _)| *n).collect();
        assert_eq!(switched, shipped);
    }

    /// THE URL'S FACTS ARE ONE UNIT'S, and they are the unit's for the whole of it.
    ///
    /// They used to be pinned to the thread the loop ran on, which was sound only while the loop
    /// occupied one blocking worker end to end. It does not any more: a unit yields at its Route step
    /// and may be resumed on another thread, and the step that reads the dialect's miss copy is on
    /// the far side of that yield. So they ride the carry, and this says what the carry answers on
    /// each of the two shapes — the fact a body-model unit has none is half the seam.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_url_facts_ride_the_unit_and_not_the_thread() {
        let rig = rig(Fixture::BufferedOk).await;
        let facts = path_facts(GEMINI, Fixture::BufferedOk);
        let base = |path| WalkArrival {
            host: rig.host(),
            gov: rig.gov(),
            proto: GEMINI,
            operation: busbar_api::operation::Operation::CHAT,
            caller_token: None,
            headers: json_headers(),
            body: path_body(GEMINI),
            path,
        };
        let carried = Walk::open(base(Some(facts)));
        assert_eq!(
            carried.with_path(|f| f.model.clone()).as_deref(),
            Some(POOL),
            "a path-model unit reads what its own URL said"
        );
        assert!(
            carried
                .with_path(|f| f.model_not_found_message.clone())
                .flatten()
                .is_some(),
            "and the dialect's own miss copy is one of the facts it carries"
        );
        assert!(
            Walk::open(base(None)).with_path(|_| ()).is_none(),
            "a body-model unit carries no URL fact at all"
        );
        rig.server.shutdown().await;
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
        let first = first.expect("an unfrozen image interns a configured lane");
        let again = again.expect("a repeated lane is the same lane");
        assert!(std::ptr::eq(first.as_str(), again.as_str()));
    }

    /// AND THE INTERNER IS REACHED ONCE PER NAME, not once per request.
    ///
    /// The interner is one mutex for the whole image, and the Verify step resolves a name per
    /// candidate lane, per request — so a node that asks it every time makes every plane in the
    /// process queue behind one lock for an answer that was settled the first time. The count is
    /// per distinct name and does not grow with how often the name is asked for.
    #[test]
    fn a_lane_name_reaches_the_interner_once_however_often_it_is_resolved() {
        let node = LlmNode::new();
        let mut names = node
            .lane_names
            .lock()
            .expect("the node's lane table is never poisoned");

        let first = names
            .resolve(LANE)
            .expect("an unfrozen image interns a lane");
        for _ in 0..64 {
            let again = names
                .resolve(LANE)
                .expect("a repeated lane is the same lane");
            assert!(std::ptr::eq(first.as_str(), again.as_str()));
        }
        assert_eq!(names.consulted(), 1);

        let _ = names.resolve("a-second-configured-lane");
        assert_eq!(
            names.consulted(),
            2,
            "a name the node has not resolved still reaches the interner, exactly once"
        );
    }

    // ── STEP 1, DECODE — the six dialects, over the loop ────────────────────────────────────────

    /// The six dialects whose model rides the body. The same six the mount installs, read off the
    /// table rather than retyped, so a dialect added to one and not the other cannot pass here.
    fn body_dialects() -> Vec<&'static str> {
        BODY_INGRESS.iter().map(|(name, _)| *name).collect()
    }

    /// The four shapes step 1 is asked about.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Decoded {
        /// A well-formed native request naming a configured pool: both halves of the step answer.
        Named,
        /// A well-formed native request with no `model` member: the model ladder resolves nothing,
        /// which is the decode step's own refusal and belongs to no other step.
        NoModel,
        /// Bytes that are not a document at all. On this plane the parse is step 0's, so this is
        /// refused at ARRIVAL and never reaches the ladder — which is exactly the ordering the
        /// module header spells out, and it is asserted rather than assumed.
        Malformed,
        /// A verb the dialect declares no handler for: the handler half of the step, refused with
        /// the endpoint's own 404 sentence.
        UnsupportedVerb,
    }

    /// THE NATIVE REQUEST BODY, per dialect. Each is the shape that dialect's own client sends, and
    /// the `model` member is the rung of the ladder a body-model surface resolves on.
    fn dialect_body(proto: &str, shape: Decoded) -> Bytes {
        if shape == Decoded::Malformed {
            return Bytes::from_static(b"{not json");
        }
        let mut v = if proto == busbar_llm::proto_codec::PROTO_ANTHROPIC {
            serde_json::json!({"max_tokens": 16,
                               "messages": [{"role": "user", "content": "hi"}]})
        } else if proto == GEMINI {
            serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]})
        } else if proto == BEDROCK {
            serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]})
        } else if proto == busbar_llm::proto_codec::PROTO_RESPONSES {
            serde_json::json!({"input": "hi"})
        } else if proto == busbar_llm::proto_codec::PROTO_COHERE {
            serde_json::json!({"message": "hi"})
        } else {
            serde_json::json!({"messages": [{"role": "user", "content": "hi"}]})
        };
        // The ladder's rung 3 — and its absence, which is the whole of the `NoModel` shape.
        if shape != Decoded::NoModel {
            v["model"] = serde_json::Value::String(POOL.to_string());
        }
        Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
    }

    /// A VERB THIS DIALECT DECLARES NO HANDLER FOR, found by ASKING the registry rather than by
    /// guessing: the first of the family's seven the dialect does not answer. `None` for a dialect
    /// that answers all seven, which is a dialect this shape has nothing to say about.
    fn unsupported_verb(proto: &str) -> Option<busbar_api::operation::Operation> {
        [
            busbar_api::operation::Operation::EMBEDDINGS,
            busbar_api::operation::Operation::MODERATION,
            busbar_api::operation::Operation::IMAGE,
            busbar_api::operation::Operation::TRANSCRIPTION,
            busbar_api::operation::Operation::SPEECH,
            busbar_api::operation::Operation::RERANK,
        ]
        .into_iter()
        .find(|op| decode::handler_for(proto, *op).is_err())
    }

    /// LEG 1 — the shipped body-model entry point, for any dialect and any verb.
    async fn leg_legacy_decode(
        proto: &'static str,
        operation: busbar_api::operation::Operation,
        body: Bytes,
    ) -> Observed {
        let rig = rig(Fixture::BufferedOk).await;
        let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
            host: rig.host(),
            gov: rig.gov(),
            caller_token: None,
        });
        let resp = busbar_llm::native_ingress::operation_ingress(
            &ctx,
            json_headers(),
            body,
            proto,
            operation,
            None,
        )
        .await;
        let observed = observe(&rig, resp).await;
        rig.server.shutdown().await;
        observed
    }

    /// LEG 2 — the same dialect and the same verb through the kernel's loop.
    async fn leg_loop_decode(
        proto: &'static str,
        operation: busbar_api::operation::Operation,
        body: Bytes,
    ) -> Observed {
        let rig = rig(Fixture::BufferedOk).await;
        let node = LlmNode::new();
        let arrival = WalkArrival {
            host: rig.host(),
            gov: rig.gov(),
            proto,
            operation,
            caller_token: None,
            headers: json_headers(),
            body,
            path: None,
        };
        let resp = node.answer(arrival, None).await;
        let observed = observe(&rig, resp).await;
        rig.server.shutdown().await;
        observed
    }

    /// **STEP 1 OVER THE LOOP, ON EVERY DIALECT THE PLANE MOUNTS.**
    ///
    /// The decode step answers two questions — which handler owns this `(protocol, operation)` pair,
    /// and which model the caller named — and every later step is about those two answers. So the
    /// step is driven through `run_unit` for each of the six body-model dialects in four shapes, and
    /// each is compared against the shipped entry point on its own deployment: the answer, the
    /// headers, the money and the breaker.
    ///
    /// The ends are asserted BESIDE the comparison, not instead of it, because six identical 404s
    /// would compare equal and prove nothing about resolution at all:
    ///
    /// * `Named` reaches the door, which is the observable fact that a model WAS resolved;
    /// * `NoModel` is the ladder's own refusal, in the dialect's envelope, charged to nobody;
    /// * `Malformed` is refused at step 0 — the plane parses before it reads the ladder;
    /// * `UnsupportedVerb` is the handler half, refused with the endpoint's own sentence.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_loop_decodes_every_dialect_the_way_the_shipped_plane_decodes_it() {
        let mut failures: Vec<String> = Vec::new();
        let mut verbs_exercised = 0usize;
        for proto in body_dialects() {
            for shape in [Decoded::Named, Decoded::NoModel, Decoded::Malformed] {
                let label = format!("{proto}/{shape:?}");
                let body = dialect_body(proto, shape);
                let op = busbar_api::operation::Operation::CHAT;
                let legacy = leg_legacy_decode(proto, op, body.clone()).await;
                let looped = leg_loop_decode(proto, op, body).await;
                compare(&label, &legacy, &looped, &mut failures);

                let status = field(&looped, "status");
                let answered = field(&looped, "body");
                let admitted = field(&looped, "ledger_requests");
                match shape {
                    // The model resolved, so the unit reached the door and drew its slot. A dialect
                    // whose ladder answered nothing would be refused BEFORE the door and read "0".
                    Decoded::Named => {
                        if admitted != "1" {
                            failures.push(format!(
                                "{label}: the resolved model never reached the door \
                                 (ledger_requests={admitted})"
                            ));
                        }
                    }
                    Decoded::NoModel => {
                        if status != "400"
                            || !answered.contains(decode::DecodeRefusal::MissingModel.message())
                        {
                            failures.push(format!(
                                "{label}: the ladder's own refusal is not what the client read \
                                 (status={status}) {answered}"
                            ));
                        }
                        if admitted != "0" {
                            failures.push(format!("{label}: a refused unit was charged"));
                        }
                    }
                    // Step 0's parse refusal: the bytes are not a document, so there is nothing for
                    // the ladder to read and the unit never reaches step 1 at all.
                    Decoded::Malformed => {
                        if status != "400" || admitted != "0" {
                            failures.push(format!(
                                "{label}: the parse refusal is not the shipped one \
                                 (status={status} ledger_requests={admitted})"
                            ));
                        }
                    }
                    Decoded::UnsupportedVerb => unreachable!("driven below, with its own verb"),
                }
            }
            // THE HANDLER HALF. A verb the dialect declares nothing for, asked of the registry
            // rather than guessed — and skipped for a dialect that answers the whole family, which
            // is an honest absence rather than a fabricated 404.
            if let Some(op) = unsupported_verb(proto) {
                verbs_exercised += 1;
                let label = format!("{proto}/UnsupportedVerb");
                let body = dialect_body(proto, Decoded::Named);
                let legacy = leg_legacy_decode(proto, op, body.clone()).await;
                let looped = leg_loop_decode(proto, op, body).await;
                compare(&label, &legacy, &looped, &mut failures);
                let status = field(&looped, "status");
                let answered = field(&looped, "body");
                if status != "404"
                    || !answered.contains(decode::DecodeRefusal::UnsupportedOperation.message())
                {
                    failures.push(format!(
                        "{label}: the endpoint's own 404 is not what the client read \
                         (status={status}) {answered}"
                    ));
                }
            }
        }
        assert!(
            verbs_exercised > 0,
            "no dialect declined a single verb of the family, so the handler half of step 1 was \
             never driven at all"
        );
        assert!(
            failures.is_empty(),
            "{} divergence(s) across {} dialect(s):\n{}",
            failures.len(),
            body_dialects().len(),
            failures.join("\n")
        );
    }

    // ── STEP 2, AUTHENTICATE — the three credentials, over the loop ─────────────────────────────

    /// The three credentials a client can present to a governed deployment.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Credential {
        /// The deployment's own live bearer.
        Good,
        /// A bearer this deployment did not mint. It is not the right shape and it is not signed by
        /// the rig's signer, which is the ordinary "wrong key" a door sees.
        Bad,
        /// A bearer this deployment DID mint, for a live and enabled binding, whose `exp` has
        /// passed. The only thing wrong with it is the clock.
        Expired,
    }

    impl Credential {
        fn present(self, rig: &Rig) -> String {
            match self {
                Credential::Good => rig.token.clone(),
                Credential::Bad => "vk_not_this_deployments_key".to_string(),
                Credential::Expired => rig.expired_token.clone(),
            }
        }
    }

    /// THE DOOR, asked exactly as a transport asks it: the deployment's configured auth chain plus
    /// the one verdict resolution the HTTP middleware runs, over this rig's live governance state.
    /// No audience is expected, because the data-plane boundary expects none.
    async fn admit(rig: &Rig, cred: Credential) -> Result<busbar_api::PlaneRequestCtx, String> {
        rig.host()
            .identity_admit(Some(cred.present(rig)), String::new(), String::new())
            .await
            .map(|(_, gov)| gov)
            .map_err(|refusal| format!("{refusal:?}"))
    }

    /// WHO THE LOOP DECIDED THIS UNIT IS, taken from the far end of the loop rather than from the
    /// fixture: the door opens the kernel's hold for the principal the AUTHENTICATE step settled
    /// on, and the posting the exit path hands back carries it. Nothing else on this plane reads
    /// that answer — the walk keeps its own context for the money and the record — so this is the
    /// one observation that is about step 2 and about nothing else.
    async fn principal_the_loop_settled_on(rig: &Rig, gov: busbar_api::PlaneRequestCtx) -> String {
        let node = LlmNode::new();
        let ended = drive_to_end(rig, &node, Fixture::BufferedOk, gov, NATIVE_SEATS).await;
        let Ended::Settled { end, .. } = ended else {
            panic!("the exit path settles a delivered unit");
        };
        end.into_posted()
            .expect("the usage report fits the record")
            .principal()
            .as_str()
            .to_string()
    }

    /// LEG 1 — the shipped entry point, driven with a context the DOOR produced.
    async fn leg_legacy_as(rig: &Rig, gov: busbar_api::PlaneRequestCtx) -> Observed {
        let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
            host: rig.host(),
            gov,
            caller_token: None,
        });
        let resp = busbar_llm::native_ingress::operation_ingress(
            &ctx,
            json_headers(),
            Fixture::BufferedOk.body(),
            PROTO,
            busbar_api::operation::Operation::CHAT,
            None,
        )
        .await;
        observe(rig, resp).await
    }

    /// LEG 2 — the loop, driven with the same context the door produced.
    async fn leg_loop_as(rig: &Rig, gov: busbar_api::PlaneRequestCtx) -> Observed {
        let node = LlmNode::new();
        let arrival = WalkArrival {
            host: rig.host(),
            gov,
            proto: PROTO,
            operation: busbar_api::operation::Operation::CHAT,
            caller_token: None,
            headers: json_headers(),
            body: Fixture::BufferedOk.body(),
            path: None,
        };
        let resp = node.answer(arrival, None).await;
        observe(rig, resp).await
    }

    /// **STEP 2 OVER THE LOOP: THE UNIT IS ATTRIBUTED TO WHAT THE DOOR RESOLVED, AND TO NOTHING
    /// ELSE.**
    ///
    /// The plane's authenticate step is a READ of an outcome the auth middleware already produced —
    /// every 401 this plane could raise is raised upstream of it. A cell that hand-built a context
    /// and handed it to the loop would prove nothing about that, because it would be asserting the
    /// fixture. So every credential here goes through the deployment's OWN door
    /// (`EngineHost::identity_admit`: the configured chain plus the one verdict resolution the HTTP
    /// middleware runs) and the loop is driven with whatever the door left behind.
    ///
    /// Three credentials, and the door's answer decides which half of the cell runs:
    ///
    /// * the deployment's live bearer is ADMITTED, so both legs run with the resolved context and
    ///   are compared — and the unit's one link lands on that key's chain, which is the attribution
    ///   claim spelled as something a reader can see;
    /// * a bearer this deployment never minted, and a bearer whose lifetime has run out, are both
    ///   REFUSED at the door, so neither leg is ever entered. The loop cannot be softer than the
    ///   shipped path here, because on both paths the plane is downstream of the same refusal; what
    ///   it could do wrong is invent an identity for the request that follows, so the shape the
    ///   middleware leaves when it binds no key is driven through both legs and must attribute the
    ///   anonymous actor — never the refused key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_loop_attributes_the_identity_the_door_resolved_and_invents_none() {
        use busbar_core::proxy::reqlog::REQUESTS;

        let mut failures: Vec<String> = Vec::new();
        for cred in [Credential::Good, Credential::Bad, Credential::Expired] {
            // LEG 1, on its own deployment: its own door, its own key, its own counters.
            let legacy_rig = rig(Fixture::BufferedOk).await;
            let legacy_admit = admit(&legacy_rig, cred).await;
            // LEG 2, on another.
            let loop_rig = rig(Fixture::BufferedOk).await;
            let loop_admit = admit(&loop_rig, cred).await;

            // THE DOOR AGREES WITH ITSELF across the two deployments. A cell whose two rigs made
            // different admission decisions would compare two different requests.
            if legacy_admit.is_ok() != loop_admit.is_ok() {
                failures.push(format!(
                    "{cred:?}: the two deployments' doors disagree ({legacy_admit:?} vs \
                     {loop_admit:?})"
                ));
            }

            match (legacy_admit, loop_admit) {
                (Ok(legacy_gov), Ok(loop_gov)) => {
                    if cred != Credential::Good {
                        failures.push(format!(
                            "{cred:?}: the door admitted a credential it must refuse"
                        ));
                    }
                    // THE RESOLVED KEY IS THE DEPLOYMENT'S KEY — the door read the bearer back to
                    // the binding it was minted for, which is what makes the attribution below a
                    // statement about a credential rather than about a struct literal.
                    if loop_gov.key().map(|k| k.id.clone()).as_deref()
                        != Some(loop_rig.key.id.as_str())
                    {
                        failures.push(format!(
                            "{cred:?}: the door resolved a key that is not this deployment's"
                        ));
                    }
                    // THE STEP'S OWN ANSWER, read at the far end of the loop: the hold the door
                    // opened names the principal step 2 settled on, and it is the resolved key. On
                    // its OWN deployment, because a second drive would double the counters the
                    // comparison below reads.
                    let settle_rig = rig(Fixture::BufferedOk).await;
                    match admit(&settle_rig, cred).await {
                        Ok(settle_gov) => {
                            let settled =
                                principal_the_loop_settled_on(&settle_rig, settle_gov).await;
                            if settled != settle_rig.key.id {
                                failures.push(format!(
                                    "{cred:?}: the loop settled on principal {settled:?}, not the \
                                     key the door resolved"
                                ));
                            }
                        }
                        Err(why) => failures.push(format!(
                            "{cred:?}: a third deployment's door refused the same bearer ({why})"
                        )),
                    }
                    settle_rig.server.shutdown().await;

                    let legacy = leg_legacy_as(&legacy_rig, legacy_gov).await;
                    let looped = leg_loop_as(&loop_rig, loop_gov).await;
                    compare(&format!("{cred:?}"), &legacy, &looped, &mut failures);
                    if field(&looped, "ledger_requests") != "1" {
                        failures.push(format!(
                            "{cred:?}: the admitted unit was not charged to the key"
                        ));
                    }
                    // THE ATTRIBUTION, as an operator reads it: one link, on the resolved key's own
                    // chain. A step that answered with any other principal would leave it elsewhere.
                    let links = REQUESTS.records_for(&loop_rig.key.id);
                    if links.len() != 1 {
                        failures.push(format!(
                            "{cred:?}: the loop left {} link(s) on the resolved key's chain",
                            links.len()
                        ));
                    }
                }
                (Err(_), Err(_)) => {
                    if cred == Credential::Good {
                        failures.push(format!(
                            "{cred:?}: the door refused the deployment's own bearer"
                        ));
                    }
                    // The door refused, so no unit exists on either leg. What the loop must not do
                    // is invent one: driven with the context the middleware leaves when it binds no
                    // key, both legs attribute the anonymous actor and leave the refused key's
                    // chain empty.
                    let open = busbar_api::PlaneRequestCtx { key: None };
                    let anonymous = busbar_api::AuthPrincipal(None).actor_id().to_string();
                    if authenticate::principal_id(&open).as_str() != anonymous {
                        failures.push(format!(
                            "{cred:?}: an unbound request is not attributed to the anonymous actor"
                        ));
                    }
                    // And the loop SETTLES on that actor: the hold the door opened for this unit
                    // names the anonymous caller, not the key whose bearer was just turned away.
                    let settle_rig = rig(Fixture::BufferedOk).await;
                    let settled = principal_the_loop_settled_on(&settle_rig, open.clone()).await;
                    if settled != anonymous || settled == settle_rig.key.id {
                        failures.push(format!(
                            "{cred:?}: the loop settled on principal {settled:?} for a request the \
                             door bound no key to"
                        ));
                    }
                    settle_rig.server.shutdown().await;

                    let legacy = leg_legacy_as(&legacy_rig, open.clone()).await;
                    let looped = leg_loop_as(&loop_rig, open).await;
                    compare(
                        &format!("{cred:?}/unbound"),
                        &legacy,
                        &looped,
                        &mut failures,
                    );
                    if !REQUESTS.records_for(&loop_rig.key.id).is_empty() {
                        failures.push(format!(
                            "{cred:?}: a refused credential's key carries a link it never earned"
                        ));
                    }
                }
                (legacy_admit, loop_admit) => failures.push(format!(
                    "{cred:?}: the doors disagreed ({legacy_admit:?} / {loop_admit:?})"
                )),
            }
            legacy_rig.server.shutdown().await;
            loop_rig.server.shutdown().await;
        }
        assert!(
            failures.is_empty(),
            "{} divergence(s) across the three credentials:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    // ── STEP 4, APPROVE — the native seat, over the loop ────────────────────────────────────────

    /// A seated gate that stops every unit, and records that it was asked. The recording is what
    /// makes "the loop consulted the seat" a fact rather than an inference from the refusal.
    struct StopsEverything(std::sync::atomic::AtomicBool);
    impl approve::VetoSeat for StopsEverything {
        fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
            self.0.store(true, Ordering::SeqCst);
            true
        }
    }

    /// A seated gate that stops nothing, and records that it was asked. Without this the pass-through
    /// half of the cell would be satisfied by a seat list the loop never reached at all.
    struct StopsNothing(std::sync::atomic::AtomicBool);
    impl approve::VetoSeat for StopsNothing {
        fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
            self.0.store(true, Ordering::SeqCst);
            false
        }
    }

    /// One request through the real loop with a named seat list, exactly as the mount drives it with
    /// its own.
    async fn leg_loop_seated(rig: &Rig, seats: &[&(dyn approve::VetoSeat + Sync)]) -> Observed {
        let node = LlmNode::new();
        let arrival = WalkArrival {
            host: rig.host(),
            gov: rig.gov(),
            proto: PROTO,
            operation: busbar_api::operation::Operation::CHAT,
            caller_token: None,
            headers: json_headers(),
            body: Fixture::BufferedOk.body(),
            path: None,
        };
        let resp = node.answer_with(arrival, None, seats).await;
        observe(rig, resp).await
    }

    /// **STEP 4 OVER THE LOOP: THE NATIVE SEAT, BOTH WAYS.**
    ///
    /// Approve is two halves and this plane's scope half has nothing to ask — its resource IS its
    /// destination, and the destination set was sealed one step earlier. What is left is the hook
    /// half, and the seat is the 1.6.0-native one: a gate that may stop a unit BEFORE the door and
    /// may do nothing else.
    ///
    /// The MIGRATED hooks are not seated here and this cell says so first: [`NATIVE_SEATS`] is the
    /// list the mount installs, it is empty, and that emptiness is why a unit over the loop is
    /// unit-for-unit what the shipped path answers. Seating the migrated hooks would move a veto
    /// from after a charge to before one, which changes what is billed.
    ///
    /// Then the three shapes, each on its own deployment:
    ///
    /// * NOTHING SEATED — the shipped entry point's answer, field for field;
    /// * A SEAT THAT DOES NOT VETO — the same answer again, and the seat records that it WAS asked,
    ///   so the pass-through above is a decision rather than an unwired field;
    /// * A SEAT THAT VETOES — the unit stops at Approve: before the door, so nothing is charged and
    ///   no metering row exists; before the route step, so the upstream is never dialled; and it
    ///   still leaves through a terminal, with exactly one link on the principal's chain and the
    ///   plane's own permission answer in the caller's dialect rather than the node's overload one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_seated_gate_stops_the_unit_before_the_door_and_an_empty_seat_list_changes_nothing() {
        use busbar_core::proxy::reqlog::REQUESTS;
        use std::sync::atomic::AtomicBool;

        assert!(
            NATIVE_SEATS.is_empty(),
            "the mount seats a native gate: the migrated hooks fire AFTER the door on the live \
             path, and a veto moved in front of a charge changes what is billed"
        );

        // THE SHIPPED ANSWER, on its own deployment — the expectation every seated run below is
        // read against, rather than a status spelled here.
        let shipped_rig = rig(Fixture::BufferedOk).await;
        let shipped = leg_legacy_as(&shipped_rig, shipped_rig.gov()).await;
        shipped_rig.server.shutdown().await;

        let mut failures: Vec<String> = Vec::new();

        // NOTHING SEATED: the mount's own list, which is the whole of today's behaviour.
        let bare_rig = rig(Fixture::BufferedOk).await;
        let bare = leg_loop_seated(&bare_rig, NATIVE_SEATS).await;
        compare("no seat", &shipped, &bare, &mut failures);
        bare_rig.server.shutdown().await;

        // A SEAT THAT DOES NOT VETO: consulted, and the unit goes on to the same end.
        let passing = StopsNothing(AtomicBool::new(false));
        let passing_rig = rig(Fixture::BufferedOk).await;
        let passed = leg_loop_seated(&passing_rig, &[&passing]).await;
        compare(
            "a seat that does not veto",
            &shipped,
            &passed,
            &mut failures,
        );
        if !passing.0.load(Ordering::SeqCst) {
            failures.push(
                "the loop never consulted the seated gate, so the pass-through above is an \
                 unwired field rather than a decision"
                    .to_string(),
            );
        }
        passing_rig.server.shutdown().await;

        // A SEAT THAT VETOES: the unit stops at Approve.
        let stopping = StopsEverything(AtomicBool::new(false));
        let veto_rig = rig(Fixture::BufferedOk).await;
        let stopped = leg_loop_seated(&veto_rig, &[&stopping]).await;
        assert!(
            stopping.0.load(Ordering::SeqCst),
            "the vetoing gate was never asked"
        );
        if field(&stopped, "status") != "403" {
            failures.push(format!(
                "a vetoed unit answers {} rather than the plane's permission refusal: {}",
                field(&stopped, "status"),
                field(&stopped, "body")
            ));
        }
        // BEFORE THE DOOR. Nothing charged, nothing metered — which is the whole reason the seat is
        // at this step and not the next one.
        if field(&stopped, "ledger_requests") != "0" || !field(&stopped, "metering_rows").is_empty()
        {
            failures.push(format!(
                "a veto was charged: requests={} rows={}",
                field(&stopped, "ledger_requests"),
                field(&stopped, "metering_rows")
            ));
        }
        // BEFORE THE ROUTE STEP. The scripted upstream saw nothing at all.
        if veto_rig.upstream.get_last_request_path().is_some() {
            failures.push("a vetoed unit reached the upstream".to_string());
        }
        // AND IT STILL ENDS AT A TERMINAL: one link, never none and never two.
        let links = REQUESTS.records_for(&veto_rig.key.id);
        if links.len() != 1 {
            failures.push(format!(
                "a vetoed unit left {} link(s) on the chain",
                links.len()
            ));
        }
        assert!(
            REQUESTS.verify_principal_chain(&veto_rig.key.id).is_ok(),
            "the chain a vetoed unit left does not verify"
        );
        veto_rig.server.shutdown().await;

        assert!(
            failures.is_empty(),
            "{} finding(s) at the approve seat:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
