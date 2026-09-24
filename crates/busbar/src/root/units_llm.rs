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

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, ArrivalRecord, Audit, Authenticate,
    Consumption, Decision, Decode, Dial, Encode, Grant, Hold, Meter, OpClassId, OriginKind,
    Outcome, Pass, PrincipalId, ReasonCode, Refusal, Route, VerifiedDestination, Verify,
};
use busbar_contract::{LaneId, Registration, UnitKey};
use busbar_kernel::ingress::arrival::{Arrival as ArrivalRequest, ArrivalPayload};
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{AccrualMeter, Evidence, FeeEvidence, UnitCtx, Units};
use busbar_llm::arrival::PathArrivalFacts;
use busbar_llm::unit::walk::{LateReport, Tap, Walk, WalkArrival};
use busbar_llm::unit::{admit, approve, arrival, audit, authenticate, decode, verify};
use busbar_substrate_values::proxy::POOL_LABEL_UNRESOLVED;

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

/// WHEN ONE UNIT ARRIVED — one reading of the wall clock, spelled in both the units this loop asks
/// for.
///
/// The loop needs the arrival instant twice and in two shapes: SECONDS, which is the window every
/// charge and every refund this unit makes lands in, and MILLISECONDS, which is the stamp the
/// in-flight table enters it under. Read the clock twice and those are two arrivals, not one in two
/// shapes — a request that arrives at the very end of a window can have its seconds fall in that
/// window and its milliseconds in the next, and the books then bill it in a window the table says it
/// did not arrive in. Nothing downstream can tell which of the two readings was the truth, because
/// both of them were.
///
/// So the clock is read ONCE, here, and every figure is spelled out of that one reading. Being a
/// value rather than a call is also what lets a test name the instant a unit arrived at, which is
/// the only way to drive the case that matters — the last millisecond of a window.
/// It carries the node's MONOTONIC reading beside the wall one, because the audit record and the
/// posting stamp each want both and they want different things from them. A wall clock is
/// steppable — an operator sets it, NTP corrects it, a leap second repeats it — so it DATES a record
/// and cannot order one. The monotonic reading only ever goes up, so it ORDERS the record and
/// cannot date it. Stamped from the wall clock twice, the second field is a copy rather than a
/// reading, and two units of one second become unorderable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrived {
    /// Milliseconds since the epoch: the reading, at the finest resolution either caller needs.
    ms: u64,
    /// The node's monotonic reading at the same arrival.
    mono: u64,
}

impl Arrived {
    /// A named arrival, for a caller that already holds both readings — the node below, and a test
    /// that needs to place a unit at an instant of its choosing.
    #[must_use]
    pub fn at(ms: u64, mono: u64) -> Self {
        Self { ms, mono }
    }

    /// The window every charge and every refund this unit makes lands in.
    ///
    /// The same truncation of the same clock `store::now` performs, so the epoch is the one the
    /// legacy entry point pinned — spelled out of the reading above rather than taken again.
    #[must_use]
    pub fn secs(self) -> u64 {
        self.ms / 1_000
    }

    /// The stamp the in-flight table takes.
    #[must_use]
    pub fn ms(self) -> u64 {
        self.ms
    }

    /// The reading that ORDERS this unit against the others the node ran.
    #[must_use]
    pub fn mono(self) -> u64 {
        self.mono
    }
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
    canary: busbar_contract::caps::Canary,
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
    /// How many slots the drop guard has MARKED since the sweep last walked the table.
    ///
    /// A counter rather than a walk on every arrival: a unit whose task went away leaves its slot
    /// marked for the sweep (see [`Occupied`]), and the sweep only walks the table when there is
    /// something marked in it, so the ordinary arrival pays one atomic read and nothing more.
    marked: AtomicU64,
    /// The ARRIVAL of every unit whose slot the drop guard marked, by key, until the sweep takes it.
    ///
    /// What the sweep posts has to land where the unit's own exit would have posted it: the window
    /// it arrived in, and the arrival reading that — with the balance and the journal's
    /// incarnation — names the unit on the chain and closes the hold its entry opened there.
    lost: Mutex<HashMap<UnitKey, Arrived>>,
    /// THE NODE'S MONOTONIC CLOCK, for the second stamp on every audit record and every posting
    /// this node writes: a counter that only ever goes up, whatever the wall clock does.
    ///
    /// It lives on the node rather than in a unit because ordering is a statement about a SET of
    /// units, and a per-unit source could only ever order a unit against itself.
    mono: AtomicU64,
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
    durability_token: busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
    // THE RATE-CARD HISTORY THIS NODE PRICES AGAINST is NOT a field here. It belongs to the root
    // (`crate::root::kernel::ROOT_CARD`) rather than to this node, and it is appended to rather than
    // bound once, because a rate is a statement about a deployment and a deployment's rates change
    // while it is running. A cell on the node would have frozen the boot reading: the engine's own
    // spend projection would reprice on a config apply and this ledger would not, and the identity
    // that says the two are one money would hold only until the first apply.
    //
    // The plane still never sees a rate. What a unit consumed is the plane's report; what those
    // quantities are worth is read in the root, off the same configured figures the projection
    // derives from — including the FLAT PER-REQUEST FEE, which the card holds beside the per-token
    // rates so a node that prices through the card cannot post the tokens and forget the fee.
    //
    // Each unit PINS THE SNAPSHOT it was admitted under (see `answer_with`) and resolves its whole
    // life against that one, AT ITS OWN ARRIVAL INSTANT — so an apply landing mid-body cannot
    // reprice a request halfway through, and an entry appended a day later cannot reprice it at all.
    /// The usage record's token, minted from this node's own kernel at construction and lent to the
    /// exit arm for the length of one pricing.
    ///
    /// Minted outside the loop for the same reason the journal's and the ledger's are: the report a
    /// late accrual prices arrives after the exit sealed the end, so there is no step of the unit
    /// whose token could stand in.
    usage_token: busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,
    /// THE ONE SEAM THIS PLANE'S ROUTE STEP REACHES THE ENGINE THROUGH.
    ///
    /// On the node rather than on the unit because what it instruments is a statement about a SET of
    /// units: "how many of the units this node took actually drove the engine" is the question, and a
    /// per-unit counter could only ever answer it about one.
    ///
    /// It is the loop's seam and not this plane's — see [`PlaneDispatch`] — and the plane's own leg
    /// is what gets handed across it. Route drives; nothing here reports.
    ///
    /// [`PlaneDispatch`]: crate::root::transports::PlaneDispatch
    dispatch: Arc<dyn crate::root::transports::PlaneDispatch>,
}

impl std::fmt::Debug for LlmNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmNode").finish_non_exhaustive()
    }
}

impl Default for LlmNode {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmNode {
    /// Compose the node every LLM request is answered by.
    #[must_use]
    pub fn new() -> Self {
        let lanes = Arc::new(Mutex::new(crate::root::kernel::new_registration()));
        let kernel = crate::root::kernel::new_kernel();
        Self {
            durability_token: kernel.durability_token(),
            usage_token: kernel.usage_token(),
            book: std::sync::OnceLock::new(),
            kernel,
            // The data listener already carries the operator-configured inbound-concurrency layer,
            // which is where this deployment's admission-to-the-node decision is made and has always
            // been made. A second cap here would be a second answer to one question, and the one
            // that refused first would decide — silently, and with a different status. So the table
            // is opened at a ceiling no deployment reaches and none is held back. It is still a real
            // table, because a hold still has to live somewhere, and it is still the thing the sweep
            // walks — what it is not is a second cap answering a question the listener already
            // answered.
            inflight: busbar_kernel::inflight::InFlight::new(usize::MAX),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_contract::caps::Canary::new(),
            door: crate::root::kernel::AdmissionDoor,
            lanes: Arc::clone(&lanes),
            lane_names: Mutex::new(LaneNames {
                interner: lanes,
                resolved: HashMap::new(),
                consulted: 0,
            }),
            next_key: AtomicU64::new(1),
            marked: AtomicU64::new(0),
            lost: Mutex::new(HashMap::new()),
            mono: AtomicU64::new(0),
            // THE PRODUCTION HALF, which awaits the leg it is handed and returns that leg's own
            // value. Composed here because composing is what this file does: the plane names the
            // work, the root names what the work is driven through, and neither names the other's.
            dispatch: Arc::new(crate::root::transports::DrivenOnce::new()),
        }
    }

    /// How many of this node's units have driven the engine through the Route seam.
    ///
    /// The instrument the switch-over is measured with, and it measures what a status cannot: a
    /// refusal the loop rendered and an upstream's own refusal are the same bytes on the wire, and
    /// only the count says whether anything ran. Reading it needs the seam this node was composed
    /// with to be one that counts, which the production composition above is.
    #[must_use]
    pub fn driven(&self) -> Option<u64> {
        self.dispatch.driven()
    }

    /// WHEN A UNIT ARRIVED, taken once: this node's two clocks, read together.
    ///
    /// The one place on the request path either clock is read. Everything a unit is judged by — the
    /// window it is charged in, the stamp the in-flight table enters it under, and the pair the
    /// audit record and the posting are dated and ordered by — is spelled out of this one value.
    fn arrived(&self) -> Arrived {
        Arrived::at(
            busbar_substrate_values::store::now_ms(),
            self.mono.fetch_add(1, Ordering::AcqRel),
        )
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
        arrived: Arrived,
        card: Option<&crate::root::kernel::PinnedHistory>,
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
        // Settle THROUGH the money-book seam rather than a `&mut` on the book itself: the lock is
        // taken and released inside the seam, so this arm settling does not hold the one book across
        // its whole exit the way a `&mut Durability` did. The pass-through settles the identical
        // posting onto the identical shared book — the bytes on the chain are unchanged.
        let book = crate::root::durability::SharedBook::over(Arc::clone(book));
        let _settled = settle(
            &book,
            principal,
            arrived,
            card,
            &self.durability_token,
            posted,
        );
    }

    /// Open this unit's hold on the book and on the journal, if this node has a book (item 127).
    ///
    /// On the same balance, in the same window and under the same arrival reading the exit arm
    /// will settle it with ([`settle`]), so the posting that ends the unit closes this record on the
    /// chain. A journal that will not take it is not a refusal: the log retains the record and
    /// offers it again, and the previous release served through a store hiccup.
    fn open_on_book(&self, principal: &PrincipalId, arrived: Arrived, reserved: u64) {
        let Some(book) = self.book.get() else {
            return;
        };
        let key = balance(principal);
        let at = crate::root::durability::Settling {
            key: &key,
            window: busbar_kernel_budget::budget_window(
                busbar_kernel_budget::window::WINDOW_DAY,
                arrived.secs(),
            ),
            durability: &self.durability_token,
            step: busbar_contract::caps::StepName::Admit,
            stamp: crate::root::durability::PostingStamp {
                rate_card_version: 0,
                wall: arrived.secs(),
                mono: arrived.mono(),
            },
        };
        let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let _opened = durability.open_hold(&at, principal, reserved);
    }

    /// THE SWEEP: the second holder of a key to every unit's hold cell, run over the slots the drop
    /// guard MARKED (item 129).
    ///
    /// A unit whose task goes away without reaching its own end leaves its slot in the table,
    /// marked, with whatever the cell still holds. This is what finds it: `tick::sweep` reads the
    /// mark as `TaskLost`, `tick::sweep_settle` takes the hold by compare-and-set — the same cell
    /// the exit path takes from, so whichever arrives second finds it empty and does nothing — and
    /// what it settles is posted onto this node's book exactly as the exit arm posts, in the window
    /// the unit ENTERED in. Then the slot leaves the table.
    ///
    /// A client that hangs up mid-dispatch is not usually this path: the loop's own guard reaches
    /// that unit's terminal and hands the end to [`LlmUnit`]'s `abandoned`, so by the time the sweep
    /// arrives the cell is already empty and the sweep only gives the slot back. What this path is
    /// FOR is the unit whose end nobody reached — and it posts that unit's hold rather than leaving
    /// it in a cell nothing will ever take it out of.
    ///
    /// Run by the next arrival (see [`LlmNode::answer_arriving_at`]), and only when something is
    /// marked, so a lost task costs one arrival's delay and an ordinary arrival costs one atomic
    /// read. The idle bound does not apply on this plane — a slow LLM stream was never cut, and the
    /// sweep does not start cutting it — so only a MARKED slot is ever settled here.
    ///
    /// Returns how many slots it gave back.
    pub fn sweep(&self, now: Arrived) -> usize {
        if self.marked.swap(0, Ordering::AcqRel) == 0 {
            return 0;
        }
        let mut swept = 0;
        for slot in self.inflight.snapshot() {
            if !slot.is_marked() {
                continue;
            }
            let verdict = busbar_kernel::tick::sweep(
                &slot,
                busbar_contract::caps::StepName::Route,
                now.ms(),
                busbar_kernel::Millis::MAX,
                false,
            );
            // The unit's own evidence went with its task, so the table's row for a lost unit reads
            // nothing located and posts the floor it can defend — marked estimated, never guessed
            // upward.
            let end = busbar_kernel::tick::sweep_settle(
                &self.kernel,
                &slot,
                verdict,
                &Evidence::default(),
                &self.canary,
                &self.gauge,
            );
            if let Some(end) = end {
                if let Ok(posted) = end.posted() {
                    let principal = posted.principal().clone();
                    // The unit's own ARRIVAL, as its guard recorded it: a unit found gone after
                    // midnight was admitted, and is charged, in the day before — and the same
                    // reading closes the hold its entry opened on the journal. Every slot in this
                    // node's table is marked by that guard, so the fallback — the sweeping arrival's
                    // own reading — is an answer for a slot nothing on this node could have marked.
                    let entered = self
                        .lost
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&slot.key())
                        .unwrap_or(now);
                    let card = crate::root::kernel::ROOT_CARD.pin();
                    self.settle_end(
                        &principal,
                        entered,
                        card.as_ref(),
                        busbar_kernel::teller::Ended::Settled {
                            end,
                            // The request slot and the flat fee are the exit's to count, and a
                            // unit the sweep ends never reached the exit that counts them.
                            requests: 0,
                            fee: 0,
                        },
                    );
                }
            }
            self.lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&slot.key());
            self.inflight.remove(slot.key());
            swept += 1;
        }
        swept
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
        self.answer_arriving_at(arrival, model_hint, seats, self.arrived())
            .await
    }

    /// The same drive, with the arrival reading HANDED IN rather than taken.
    ///
    /// [`answer_with`](Self::answer_with) is this with the node's own clock read once, at the top,
    /// which is the only place on this path a clock is read. It is split out for the same reason
    /// the seats are: "what this loop does with the instant it arrived at" is a property of the
    /// loop, and a drive that reads the clock itself cannot be asked about an instant a test picks —
    /// least of all the one instant that matters, a unit arriving at the last millisecond of a
    /// window.
    #[must_use]
    pub async fn answer_arriving_at(
        &self,
        arrival: WalkArrival,
        model_hint: Option<String>,
        seats: &[&(dyn approve::VetoSeat + Sync)],
        arrived: Arrived,
    ) -> Response {
        // The sweep, before this unit takes a slot of its own: any slot a lost task left MARKED is
        // settled and given back now. One atomic read when nothing is marked.
        self.sweep(arrived);
        let proto = arrival.proto;
        let op_class = OpClassId::new(arrival.operation.name());
        let key = UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed));
        let principal = authenticate::principal_id(&arrival.gov);
        // ONE METER, on both sides of the loop: the unit accrues onto it at the Meter step and the
        // kernel reads it at the exit. See `LlmUnit::meter`.
        let meter = Arc::new(AccrualMeter::new());
        // THE HISTORY SNAPSHOT THIS UNIT IS ADMITTED UNDER, pinned here for the same reason
        // `charged_at` below is: a live apply may APPEND to the root's history at any instant, and a
        // request that opened before one is priced against the history it agreed to. Pinning at
        // admission rather than reading at drain time is what makes that true even for the accrual
        // that lands after the body has finished — the figure arrives late, but the snapshot it is
        // resolved against was fixed at the door.
        //
        // A SNAPSHOT, NOT A CARD, and the difference is the whole of this wave. A card is one price;
        // a snapshot is every price this node has ever charged, up to the door. The unit prices at
        // the entry in force AT ITS ARRIVAL, which under a single-entry history is the same card the
        // previous release would have used and under a longer one is the card the request was
        // actually earned under.
        let history = crate::root::kernel::ROOT_CARD.pin();
        let unit = LlmUnit {
            node: self,
            history: history.clone(),
            arrived,
            seats,
            meter: Arc::clone(&meter),
            op_class,
            model_hint,
            started: Instant::now(),
            // The header-arrival epoch, pinned once and reused for every charge and every refund
            // this unit makes, exactly as the legacy entry point pins it: a request whose response
            // completes in a later window than its headers arrived must not split its charges
            // across two windows. Spelled out of the ONE arrival reading below rather than read
            // here, so the epoch this unit is billed in and the stamp the table enters it under
            // cannot be two different instants.
            charged_at: arrived.secs(),
            principal: principal.clone(),
            deferred: Mutex::new(None),
            model: Mutex::new(String::new()),
            walk: Walk::open(arrival),
        };

        let hold =
            busbar_kernel::inflight::arrival_hold(&self.kernel, &self.door, principal.clone());
        // What this unit reserves, read off the hold it enters the table with. The door on this
        // plane has its hold opened at ZERO (this file's `Units::admit` row), so the arrival hold's
        // figure is the unit's reservation for its whole life; a door that reserved would be the
        // place to journal the difference.
        let reserved = hold.reserved();
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            // THE SAME READING the charge above is pinned from, in the units this table keeps. A
            // second read here is a second arrival: the table would stamp the unit in one window
            // and the books would bill it in another, and nothing downstream could say which of the
            // two the request actually arrived in.
            now: arrived.ms(),
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
                // THE HOLD, ON THE JOURNAL, before the unit runs (item 127): what this unit holds
                // is written down now, so a node killed mid-unit leaves a record the next boot
                // recovers and posts rather than a hold that only ever existed in memory.
                self.open_on_book(&principal, arrived, reserved);
                let mut occupied = Occupied {
                    node: self,
                    slot: Arc::clone(&slot),
                    arrived,
                    reached_end: false,
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
                // The SAME pin the late arm prices against, so the posting and the figure that
                // follows it name one snapshot. Re-pinning here would read a history a live apply
                // may have appended to since the door, which is the hazard the pin exists for.
                self.settle_end(&principal, arrived, history.as_ref(), ended);
                // The unit reached its own end and its posting is on the book: the slot goes
                // straight back. Anything that leaves this function before here leaves it MARKED.
                occupied.reached_end = true;
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
                self.attach_late_accrual(response, walk, &principal, arrived, history)
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
        arrived: Arrived,
        history: Option<crate::root::kernel::PinnedHistory>,
    ) -> Response {
        let Some(book) = self.book.get() else {
            return response;
        };
        // No history pinned at admission is the third: a report nothing can price is a report
        // nothing can post, and wrapping the body to discover that when it drains would be a wrapper
        // that only ever drops empty.
        let Some(history) = history else {
            return response;
        };
        let Some(tap) = Walk::tap_of(&response) else {
            return response;
        };
        let arm = LateAccrual {
            book: Arc::clone(book),
            history,
            // MINTED FOR THIS ONE POSTING and dropped with it. A token is neither `Clone` nor `Copy`
            // and the node's own is lent by reference for the length of a call, which is exactly what
            // this is not: the posting outlives every call on this path. So the pair is minted where
            // the unit is and travels with the body it is a posting OF.
            durability_token: self.kernel.durability_token(),
            ledger_token: self.kernel.ledger_token(),
            usage_token: self.kernel.usage_token(),
            principal: principal.clone(),
            // The unit's PINNED ARRIVAL, not a clock read at drain time. The late posting lands on
            // the same balance and in the same window the terminal settled in, which is the whole of
            // what makes it the same row: a body that drained past midnight would otherwise open a
            // second day's row for a request the node admitted, priced and billed in the first. The
            // monotonic half travels with it for the same reason: the late posting and the terminal's
            // are two postings OF one unit, and they order beside it rather than beside each other.
            arrived,
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
/// collation. An OPEN class is not a line of this record — a contract line names its class with a
/// static id, and an open class is a runtime name — so [`priced_posting`] puts every open class the
/// report carries onto the POSTING directly, verbatim (#71). It used to be LEFT OFF entirely —
/// priced at nothing — which was a silent zero once a card could price an open class (item 123,
/// `units:`): a rerank's search units reached the governance ledger and its read, and this book
/// took the fee alone. Now the card prices the class, or a present card silent about it REFUSES (#42).
///
/// The flat fee is NOT a line built here. It is the card's, added by the pricing as a line of its own
/// from the billable count the report carries, which is what keeps one configured fee to one place.
/// The four reserved classes, in the canonical order.
const RESERVED_CLASSES: [&str; 4] = [
    busbar_api::UNIT_INPUT,
    busbar_api::UNIT_OUTPUT,
    busbar_api::UNIT_CACHE_READ,
    busbar_api::UNIT_CACHE_WRITE,
];

fn usage_record(
    token: &busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,
    usage: &busbar_substrate_values::billing::Usage,
) -> busbar_contract::caps::Usage {
    let lines = RESERVED_CLASSES
        .into_iter()
        .filter_map(|class| {
            // A zero-quantity line is not a fact about anything, and the plane's own metering step drops
            // them for the same reason. Kept out here too so the two reports have the same shape.
            let quantity = usage.usage_units.get(class).copied().unwrap_or(0);
            (quantity > 0).then(|| busbar_contract::caps::UsageLine {
                class: busbar_contract::caps::MeterClassId::new(class),
                quantity,
                source: busbar_contract::caps::QuantitySource::Count,
                estimated: false,
            })
        })
        .collect();
    // A report wider than the record holds is not a reason to post nothing: the record's own limit is
    // a bound on lines, and the four tiers this plane reports are far inside it. An empty record is
    // the honest fallback — it prices the fee and no tokens, which is what a response that reported
    // nothing costs.
    busbar_contract::caps::Usage::report(token, lines).unwrap_or_else(|_| {
        busbar_contract::caps::Usage::report(token, Vec::new()).expect("no lines fit")
    })
}

/// **WHAT ONE REPORT IS WORTH**, against one card — the node's single pricing expression.
///
/// Both readings of a unit's consumption come through here: the live metering step's, handed over as
/// the step runs, and the late reading's, taken off the tap once the body has drained. One
/// expression rather than two, because a second spelling of this arithmetic is how one unit ends up
/// settling two different amounts on two books.
///
/// The plane supplied the report — classes, quantities, the billable count and the two names the row
/// is keyed by — and nothing in it is money. The card supplies the rest.
///
/// **The fee arrives by construction.** The cost unit's pricing puts the flat per-request charge on
/// the posting as a line of its own, at the card's configured fee times the count the plane reported,
/// and sums it in with the token lines before the single tier divide. So one call produces the token
/// lines AND the fee line, and there is no arm anywhere that could post the tokens and forget the
/// fee. That is what makes the identity exact rather than approximate: the previous release's
/// projection reprices a row's token counts and adds the same configured fee at read time, so a node
/// that posted only the tokens was out by the fee on every billable request.
///
/// **SETTLEMENT PRICES FAIL-CLOSED** (#42, 789d55a78): the lookup is
/// [`busbar_kernel_ledger::cost::price_fail_closed`], never the read posture that flags an unpriced
/// line and prices it at nothing. A present card silent about the lane or about a class the unit
/// hit is a REFUSAL here. The posting — the counts and the instant — is returned either way: the
/// counts are what the unit did (#43, #71), and a refusal to price them is not a reason to lose
/// them or to call them zero.
fn priced_posting(
    history: &crate::root::kernel::PinnedHistory,
    arrived: Arrived,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,
    report: &LateReport,
) -> (
    busbar_kernel_ledger::cost::Posting,
    Result<busbar_kernel_ledger::cost::Priced, busbar_kernel_ledger::cost::Unpriceable>,
) {
    // A POSTING IS QUANTITIES AND AN INSTANT, and both are stated here: the plane's report supplies
    // the classes and their counts, and the unit's PINNED arrival supplies the instant in both its
    // readings. The instant is not a clock read — this runs after the body drained, which may be a
    // different day from the one the request was admitted in, and a fresh reading would price the
    // request against a card it never agreed to.
    let mut posting = busbar_kernel_ledger::cost::Posting::from_usage(
        &report.lane,
        &usage_record(token, &report.usage),
        u64::from(report.fee_count),
        busbar_kernel_ledger::cost::STANDARD_TIER_BP,
        arrived.ms(),
        arrived.mono(),
    );
    // EVERY OPEN CLASS the report carries, verbatim and in its name's order, after the reserved four
    // (#71; item 123/134 — a rerank's search units). A present card prices it or refuses it (#42);
    // an absent card prices it at nothing, the one silent zero.
    posting.quantities.extend(
        report
            .usage
            .usage_units
            .iter()
            .filter(|(class, count)| **count > 0 && !RESERVED_CLASSES.contains(&class.as_str()))
            .map(|(class, count)| {
                busbar_kernel_ledger::cost::Quantity::new(class.as_str(), *count)
            }),
    );
    // THE LOOKUP, at the snapshot pinned at the door and the instant the unit arrived at. The
    // history resolves which entry was in force then; a later apply is not in this view at all, so
    // there is no arm here that could read one.
    let priced = busbar_kernel_ledger::cost::price_fail_closed(&history.view(), &posting);
    // THE CACHE IS WRITTEN AND IS NEVER READ BACK. It rides the posting so a reader has a figure to
    // compare a re-derivation against and so a totals read need not re-price a day of postings on
    // every request — but the figure this function RETURNS is the lookup's, taken off `priced`
    // directly. There is no arm below that consults `posting.cached`, which is the invariant stated
    // as code rather than as a comment: corrupt the cache and this expression answers exactly what
    // the quantities and the history say.
    posting.cached = priced.as_ref().ok().map(|p| p.as_cache(history.seq()));
    (posting, priced)
}

/// The figure the books take, spelled out of [`priced_posting`]'s lookup — or the refusal.
///
/// Every way this cannot state a figure is an `Err`, never a number: a hole in the history, a lane
/// or a hit class a present card is silent about (#42), and a figure the record cannot hold, which
/// REFUSES rather than pinning at the ceiling (item 28) — a pinned figure is a bill nobody posted.
fn priced_amount(
    history: &crate::root::kernel::PinnedHistory,
    arrived: Arrived,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,
    report: &LateReport,
) -> Result<u64, busbar_kernel_ledger::cost::Unpriceable> {
    let (_posting, priced) = priced_posting(history, arrived, token, report);
    u64::try_from(priced?.priced_nanos)
        .map_err(|_| busbar_kernel_ledger::cost::Unpriceable::Overflow)
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
///
/// **THIS BOOK IS NOT THE INVOICE.** One delivered unit leaves two records: the tap's accrual of
/// raw counts onto the GOVERNANCE LEDGER (the metering series `GET /api/v1/admin/usage` prices at
/// read time, and what 1.5.5 billed) and this priced posting onto the Durability book. The money
/// model (BUSBAR-1.6.0.md Part 0; #43/#71: the ledger stores counts; #77(3): a price is never
/// stored) makes the governance ledger the invoice and this posting a derived reading of it. The
/// two must agree cell by cell —
/// `the_second_book_agrees_with_the_invoice_cell_by_cell_and_a_divergence_is_red` holds this book's
/// figure against the served read's own derivation, and a divergence is RED.
struct LateAccrual {
    book: Arc<Mutex<crate::root::durability::Durability>>,
    /// THE HISTORY SNAPSHOT the report is resolved against — the deployment's dated card history as
    /// it stood when this unit was admitted, pinned there.
    ///
    /// A snapshot rather than a card, so that the entry the late figure prices at is the entry in
    /// force at the unit's ARRIVAL and not the entry in force when its body finally drained. Those
    /// are the same entry on every ordinary request and they are different ones on exactly the
    /// request an operator edited a price underneath — which is the request the distinction exists
    /// for.
    history: crate::root::kernel::PinnedHistory,
    durability_token: busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
    ledger_token: busbar_contract::caps::Grant<busbar_contract::caps::WriteMoney>,
    usage_token: busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,
    principal: PrincipalId,
    arrived: Arrived,
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
            history,
            durability_token,
            ledger_token,
            usage_token,
            principal,
            arrived,
            walk,
            tap,
        } = self;
        let Some(report) = walk.reported_after_terminal(&tap) else {
            return;
        };
        post_late(
            &crate::root::durability::SharedBook::over(book),
            &LateTokens {
                durability: &durability_token,
                ledger: &ledger_token,
                usage: &usage_token,
            },
            &history,
            &principal,
            arrived,
            &report,
        );
    }
}

/// The three tokens the late arm posts under, lent together.
struct LateTokens<'a> {
    durability: &'a busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
    ledger: &'a busbar_contract::caps::Grant<busbar_contract::caps::WriteMoney>,
    usage: &'a busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,
}

/// The unit's raw counts as its posting record carries them (#71): the serving lane, the billable
/// count, and every class the report carries — the reserved four and the open ones — verbatim. A
/// zero-quantity class is not a fact about anything and is left off, as [`usage_record`] leaves it.
fn counts_of(report: &LateReport) -> crate::root::durability::UnitCounts {
    crate::root::durability::UnitCounts {
        lane: report.lane.clone(),
        fee_count: u64::from(report.fee_count),
        classes: report
            .usage
            .usage_units
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(class, count)| (class.clone(), *count))
            .collect(),
    }
}

/// **THE LATE ARM'S POSTING**: what one drained report leaves on the second book. ALWAYS one row
/// (#43: the write is unconditional; #71: the fact is the counts, and pricing is the read).
///
/// - PRICED above zero: the settlement moves the book, and its record carries the counts beside
///   the figure.
/// - PRICED AT ZERO, or REFUSED: a counts row that moves no balance. A refusal (#42) leaves the
///   money unpriced — no zero, no partial — and every read of the balance it sits on refuses.
fn post_late(
    book: &dyn crate::root::durability::MoneyBook,
    tokens: &LateTokens<'_>,
    history: &crate::root::kernel::PinnedHistory,
    principal: &PrincipalId,
    arrived: Arrived,
    report: &LateReport,
) {
    let counts = counts_of(report);
    // THE PRICING, and it happens HERE rather than on the plane. The plane said what the unit
    // consumed — quantities, by class — and how many billable requests it is. What that is worth is
    // the card's answer, and this is the only side that holds a card. It is the same expression the
    // live metering step is answered through, because one report priced two ways is two answers to
    // what one request cost.
    //
    // THE ROW THIS LANDS ON. `report` names the serving lane and its provider — the two names the
    // legacy row is keyed by — and the balance below is keyed by principal and window. Those are the
    // same row: the node's books retain no lane and no provider, so both the ledger's side and the
    // legacy side of the reconciliation are read at the width the node keeps, with the two names
    // empty on BOTH. The lane rides the counts row, which is where a read prices from.
    //
    // A ZERO IS NOT A SETTLEMENT, and posting one would say the node had settled something. But the
    // counts are still the unit's fact (#43), so a unit that priced at nothing leaves its counts row
    // and moves no balance.
    //
    // A REFUSAL IS NOT A ZERO AND NOT A PARTIAL (#42, item 28). A present card silent about the
    // lane or a hit class, a hole in the history, or a figure the record cannot hold states no
    // amount, so this book is handed none — never the priced part with the unpriced part at nothing.
    // The COUNTS are not lost: they are posted as a counts row with the money unpriced, and every
    // read of the balance it sits on refuses (`Durability::settled_read`). It used to post nothing
    // at all and only warn — the fact survived on the governance ledger alone.
    let key = balance(principal);
    // The same pinned snapshot the amount below is PRICED against, so the figure and the entry
    // number the posting claims priced it cannot come from two different reads.
    let at = settling_at(&key, arrived, Some(history), tokens.durability);
    let amount = match priced_amount(history, arrived, tokens.usage, report) {
        Ok(amount) => amount,
        Err(refusal) => {
            tracing::warn!(
                principal = principal.as_str(),
                lane = %report.lane,
                counts = ?report.usage.usage_units,
                fee_count = report.fee_count,
                ?refusal,
                "late accrual refused at settlement: the card cannot price these counts; \
                 the counts row is posted with no figure"
            );
            let _row = book.post_counts(&at, principal, &counts, Some(format!("{refusal:?}")));
            return;
        }
    };
    if amount == 0 {
        let _row = book.post_counts(&at, principal, &counts, None);
        return;
    }
    let accrual = busbar_contract::caps::HoldAccrual::after_terminal(
        principal.clone(),
        amount,
        tokens.ledger,
    );
    let posted = busbar_contract::caps::Posted::settle_late(accrual, tokens.ledger);
    // Through the money-book seam, as the terminal exit arm does — the same shared book, the same
    // posting, the lock taken and released behind the seam — with the counts on the record.
    let _settled = book.settle_counted(&at, posted, &counts);
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

/// THE IN-FLIGHT SLOT, for the length of one unit — and the drop guard that MARKS it (item 129).
///
/// A unit that reached its own end gives its slot straight back. Every other way out — a panic, or
/// the client hanging up mid-request, which drops the whole of `answer` where it stands — leaves the
/// slot in the table MARKED, and the node's sweep ([`LlmNode::sweep`]) is what gives it back.
///
/// It used to REMOVE the slot on every way out, and that is the half of the protocol that could not
/// work: the sweep is the second holder of a key to the unit's hold cell, and a slot removed on the
/// way out is a cell the sweep can never see — so a hold the exit never reached was left in a cell
/// nothing would ever take it out of, and a disconnect mid-dispatch skipped its charge. A guard only
/// ever MARKS: it runs during an unwind, where taking a hold and settling it is exactly what must not
/// happen, so ending the unit is the sweep's job and marking is the whole of this one's.
struct Occupied<'n> {
    node: &'n LlmNode,
    slot: Arc<busbar_kernel::inflight::UnitSlot>,
    /// The unit's arrival, handed to the sweep with the mark.
    arrived: Arrived,
    /// Set once the unit's end has been reached and settled on the ordinary path.
    reached_end: bool,
}

impl Drop for Occupied<'_> {
    fn drop(&mut self) {
        if self.reached_end {
            self.node.inflight.remove(self.slot.key());
        } else {
            self.node
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.slot.key(), self.arrived);
            self.slot.mark();
            self.node.marked.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// What a unit a seated gate stopped answers with, in the caller's own dialect.
///
/// One permission sentence, vendor-plausible, naming nothing of the operator's — not the seat, not
/// the principal, not a word of governance vocabulary — because a gate's veto is not entitled to a
/// reason of its own and a client is owed the same answer whichever gate stopped it. WHICH seat
/// stopped the unit is the operator's diagnostic, and the step file already logs it.
fn vetoed(proto: &str) -> Response {
    busbar_kernel::proxy::ingress_error(
        proto,
        StatusCode::FORBIDDEN,
        busbar_substrate_values::proxy::KIND_PERMISSION,
        "Your API key does not have permission to access this resource.",
    )
}

/// What a node that cannot take the unit at all answers with, in the caller's own dialect.
fn unavailable(proto: &str) -> Response {
    busbar_kernel::proxy::ingress_error(
        proto,
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
    /// THE HISTORY SNAPSHOT THIS UNIT WAS ADMITTED UNDER, pinned at the door with `charged_at`: the
    /// metering step resolves what the unit consumed through it, and the late accrual resolves
    /// through the same one, so a live apply mid-flight cannot price one unit two ways.
    history: Option<crate::root::kernel::PinnedHistory>,
    /// THE UNIT'S ARRIVAL, both readings, kept because the pricing needs the INSTANT and not only
    /// the window.
    ///
    /// `charged_at` above is this reading truncated to the second the balance is keyed by; a
    /// millisecond is what the history resolves at, and truncating to a window first and multiplying
    /// back would place a unit that arrived in the last millisecond of a second at the start of it —
    /// on the wrong side of an entry appended in between.
    arrived: Arrived,
    /// Whose unit this is — the principal the balance it settles onto is keyed by.
    ///
    /// Kept on the unit because the unit is what a caller going away leaves behind: the loop hands
    /// the end of an ABANDONED unit to this unit's `abandoned`, and posting it needs the same
    /// balance the returned end would have been posted to.
    principal: PrincipalId,
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
        _destinations: &[busbar_contract::caps::VerifiedDestination],
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
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[busbar_contract::caps::VerifiedDestination],
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
impl busbar_kernel::teller::RouteAwait for LlmUnit<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _meter: &'a AccrualMeter,
        _destinations: &'a [busbar_contract::caps::VerifiedDestination],
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
        //
        // THROUGH THE ONE SEAM. The leg below is the walk's own and is what this line always was;
        // what changed is that it is HANDED to the loop's dispatch instead of being returned
        // straight to the loop. The seam awaits it and gives back its value, so the bytes, the
        // status, the headers, the stream's frames and the tap on its body are the plane's exactly
        // as they were — byte identity is a property of that construction, not of a measurement.
        //
        // What the seam adds is the one fact no status can carry: that the engine ran for this unit.
        // A unit refused at Authenticate, Verify, Approve or Admit never reaches Route, so it never
        // reaches this line, and the count says so rather than a rendered refusal having to be told
        // apart from an upstream's own.
        self.node.dispatch.execute(
            self.op_class,
            Box::pin(async move { self.walk.route(token, &destination).await }),
        )
    }

    /// THE CALLER WENT AWAY MID-DISPATCH, and the end the loop reached for it is POSTED here (item
    /// 99) — onto the same book, the same balance and the same window [`LlmNode::answer_arriving_at`]
    /// posts a returned end to, through the same exit arm.
    ///
    /// The loop's guard has already sealed this end at the charged audit door, emptied the cell and
    /// given the leases back; what it hands over is the posting, which has moved no balance and left
    /// no record until something settles it. Nothing else will: the future that would have read it
    /// is the one being dropped. Before this arm the end was bound to `let _ended` and dropped, so
    /// an abandoned unit left no ledger row and no journal entry and its reservation stayed drawn.
    fn abandoned(&self, _ctx: &UnitCtx, ended: busbar_kernel::teller::Ended) {
        self.node
            .settle_end(&self.principal, self.arrived, self.history.as_ref(), ended);
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
fn balance(principal: &PrincipalId) -> busbar_kernel_ledger::totals::TotalsKey {
    busbar_kernel_ledger::totals::TotalsKey::new(
        busbar_kernel_ledger::totals::BucketId::new(principal.as_str()),
        busbar_kernel_ledger::totals::CapDimension::NanoUnits,
        busbar_kernel_ledger::totals::BucketScope::All,
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
    book: &dyn crate::root::durability::MoneyBook,
    principal: &PrincipalId,
    arrived: Arrived,
    card: Option<&crate::root::kernel::PinnedHistory>,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
    posted: busbar_contract::caps::Posted,
) -> Result<crate::root::durability::Settled, busbar_contract::caps::DurabilityLost> {
    let key = balance(principal);
    book.settle_posted(&settling_at(&key, arrived, card, token), posted)
}

/// Where an LLM unit's posting lands: its balance, the window of its pinned arrival, stamped with the
/// card in force at that arrival.
fn settling_at<'a>(
    key: &'a busbar_kernel_ledger::totals::TotalsKey,
    arrived: Arrived,
    card: Option<&crate::root::kernel::PinnedHistory>,
    token: &'a busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
) -> crate::root::durability::Settling<'a> {
    crate::root::durability::Settling {
        key,
        window: busbar_kernel_budget::budget_window(
            busbar_kernel_budget::window::WINDOW_DAY,
            arrived.secs(),
        ),
        durability: token,
        // The loop has no exit step of its own; the figure this posting is OF is the metering step's,
        // and that is the step a durability loss here is attributed to.
        step: busbar_contract::caps::StepName::Meter,
        // The posting's two clocks, and they are two READINGS of the one arrival: the wall epoch
        // DATES the posting, the monotonic reading ORDERS it. Stamped from the wall clock twice, the
        // second field is a copy — and two postings of one second become unorderable, which is
        // exactly what the field exists to prevent.
        stamp: crate::root::durability::PostingStamp {
            // The card in force when this unit ARRIVED, resolved through the dated history (#79)
            // rather than asserted. A literal zero here was `HistorySeq::OPENING` — a real entry
            // number, not a null — so every posting this plane made claimed the opening card had
            // priced it, which is false on every deployment that has ever changed a price. A
            // confident wrong answer, which is worse than none.
            rate_card_version: card_in_force(card, arrived.ms()),
            wall: arrived.secs(),
            mono: arrived.mono(),
        },
    }
}

/// THE PROVENANCE STAMP: which rate-card entry was in force when this unit arrived.
///
/// #79 makes the resolution key the posting's own ARRIVAL INSTANT against the dated history — never
/// the head of the history, and never a version stamped at settle time. The difference is the whole
/// ruling: a head read reports the newest card ever published, so a unit that arrived two prices ago
/// would be stamped with a card it was never charged under, and a back-dated correction would be
/// unreachable backwards.
///
/// THE MILLISECOND BINDING IS LOAD-BEARING, and this is why the argument is `arrived.ms()` rather
/// than the `wall` field beside it. `effective_from` is written on the MILLISECOND scale
/// (`root/kernel.rs:435`); resolving at a seconds-valued instant matches only the from-zero opening
/// entry and reports it forever — the same lie this function exists to remove, with a lookup in
/// front of it. [`Arrived`] carries both readings for exactly this reason.
///
/// Falling back to `OPENING` is a statement, not a convenience: no history pinned (a build with no
/// root ledger) or a HOLE at this instant means no entry claims to have priced the unit, and the
/// opening entry is the only one that covers every instant by construction.
///
/// The same six lines as `units_a2a::A2aUnits::rate_card_version` and
/// `units_mcp::Provenance::rate_card_version`, and the same `card_at` the admin read resolves
/// through (`busbar-core-admin/src/v1/service.rs:2375`). FOUR COPIES OF ONE RULING IS FOUR CHANCES
/// TO GET IT WRONG — this is the fourth, written to match rather than to differ, and #43's end
/// state is the one kernel-side implementation that retires all four.
fn card_in_force(card: Option<&crate::root::kernel::PinnedHistory>, arrived_ms: u64) -> u64 {
    card.and_then(|pinned| pinned.view().card_at(arrived_ms).map(|(seq, _)| seq.get()))
        .unwrap_or_else(|| busbar_kernel_ledger::cost::HistorySeq::OPENING.get())
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
    let Some(operation) = busbar_substrate_values::handlers::request_handler(proto)
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
    ctx: busbar_kernel::ingress::arrival::ArrivalCtx,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // The URL's facts, the operation they resolved to, and the routing hint a body-model shape
    // carries. Exactly one of the first and the last is ever set.
    let (facts, operation, model_hint) = match parsed {
        // A pre-rendered fallback 404 (a different terminal): return its bytes unchanged.
        PathArrivalFacts::Refused(resp) => return resp,
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
    let charged_at = busbar_substrate_values::store::now();
    let rest = busbar_llm::arrival::gemini_rest(&a.host, &a.path);
    let parsed = busbar_llm::arrival::gemini_path_parse(&a.host, &a.ctx, &rest, &a.uri, &a.body);
    match parsed {
        // A NAMED pre-routing refusal: render it at the audit terminal and post it through the
        // rejected door on this dialect's own arrival host — byte- and accounting-identical to the
        // finish the parse used to spell inline, pinned against the epoch pinned above.
        PathArrivalFacts::RefusedNeutral {
            envelope_proto,
            outcome,
        } => {
            let resp = audit::finish_rejected_via_audit_arrival(
                &a.host,
                &a.ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                audit::render_refusal(envelope_proto, &outcome),
            );
            Box::pin(async move { resp })
        }
        other => Box::pin(path_arrival(
            busbar_llm::proto_codec::PROTO_GEMINI,
            other,
            a.ctx,
            a.headers,
            a.body,
        )),
    }
}

/// BEDROCK'S PATH ARRIVAL, ON THE LOOP. Three shapes under one model path, and the native 404 for
/// anything else — all four the dialect's own answer, and only the driving is this file's.
fn bedrock_path_arrival(
    a: ArrivalRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    let started = Instant::now();
    let charged_at = busbar_substrate_values::store::now();
    let parsed = busbar_llm::arrival::bedrock_path_parse(&a.host, &a.ctx, &a.path, &a.uri, &a.body);
    match parsed {
        // A NAMED pre-routing refusal: render it at the audit terminal and post it through the
        // rejected door on this dialect's own arrival host — byte- and accounting-identical to the
        // finish the parse used to spell inline, pinned against the epoch pinned above.
        PathArrivalFacts::RefusedNeutral {
            envelope_proto,
            outcome,
        } => {
            let resp = audit::finish_rejected_via_audit_arrival(
                &a.host,
                &a.ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                audit::render_refusal(envelope_proto, &outcome),
            );
            Box::pin(async move { resp })
        }
        other => Box::pin(path_arrival(
            busbar_llm::proto_codec::PROTO_BEDROCK,
            other,
            a.ctx,
            a.headers,
            a.body,
        )),
    }
}

/// THE PATH-MODEL ARRIVALS, ON THE LOOP — the switched-over twin of the plane's own `PATH_INGRESS`.
///
/// Same two dialects, same names, same table; what changes is the PATH a request takes to reach the
/// answer. The composition root installs this one instead of the plane's when `root-llm` is on, and
/// with it off this static does not exist and the surface is the one it was.
pub static PATH_INGRESS: &[(&str, busbar_kernel::ingress::arrival::PathIngress)] = &[
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
pub static BODY_INGRESS: &[(&str, busbar_kernel::ingress::arrival::BodyIngress)] = &[
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
// THE LLM-NATIVE RESOLVED-OP RIDER, TEST-ONLY
// ---------------------------------------------------------------------------------------------

/// THE TEST-ONLY KERNEL-LOOP DRIVE OF THE RESOLVED-OP ENTRY, beside the shipped money authority.
///
/// `busbar_llm::native_ingress::run` is the shipped money authority for a resolved-op arrival — a
/// known `model`, the dialect's already-resolved `operation`, the caller's headers and body: it
/// builds a `NativePlane`/`GauntletRequest` and settles per-token billing through
/// `busbar_kernel::plane_host::run_gauntlet`, late-accruing against the admission-pinned
/// `ROOT_CARD` snapshot. `run_gauntlet` dispatches to the kernel-loop runner
/// `gauntlet_install::install()` registers for the LLM capability key at boot (item 125), and that
/// runner is money-neutral (a `ZeroHold`, no evidence), so the plane's own metering inside `drive`
/// stays what settles. Every resolved-op arrival funnels through `run()`: `operation_ingress` (once
/// the body's model is read), `ingress_path_model` (once the URL's is), and the MCP-sampling
/// re-entry `synthesize_completion`. On a default build (`root-llm` on) the body- and path-model
/// arrivals do not reach `run()` at all: they are driven through [`LlmNode`] and this module's late
/// accrual. Measured (item 125, 2026-09-24): `root-llm` OFF returns
/// `billing|rate-card|history-mid-window` to its 1.5.5 figures; the `install()` flips do not move it.
///
/// This is that SAME resolved-op arrival driven through [`LlmNode`] instead —
/// `answer_arriving_at` → `busbar_kernel::teller::run_unit_async`, settling onto the same Durability
/// money-book the composition root bound via [`bind_book`]. The resolved `model` is carried as the
/// loop's `model_hint`, exactly as `run()` carries its resolved `model`; `path: None`, because a
/// native arrival's model rides its body.
///
/// THIS FUNCTION is test-only. Nothing mounts it: the shipped `run()` keeps its own call, and
/// DECISION #29 gates moving the resolved-op money authority onto [`LlmNode`] on the fleet-box oracle
/// — proven byte-identical on that box (`bin/oracle` record+replay), never here. This entry exists so
/// the entry-level shadow proof can drive it beside `run()` on the same fixtures and prove exactly
/// that (see `the_loop_matches_native_ingress_run_at_the_resolved_op_entry`). When #29 authorizes the
/// move, this graduates — behind the `root-llm` composition-root switch — into the funnel `run()`'s
/// three callers reach.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn native_run_via_loop(
    host: &Arc<dyn busbar_kernel::plane_host::EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    model: &str,
    headers: &axum::http::HeaderMap,
    body: axum::body::Bytes,
    caller_token: Option<&str>,
    arrived: Arrived,
) -> Response {
    // The ONE value that crosses from the root into the plane per unit, built from the same
    // resolved-op args `run()` receives.
    let arrival = WalkArrival {
        host: Arc::clone(host),
        gov: busbar_api::PlaneRequestCtx {
            key: gov.key.clone(),
        },
        proto,
        operation,
        caller_token: caller_token.map(str::to_string),
        headers: headers.clone(),
        body,
        path: None,
    };
    // The process's ONE node, the arrival instant HANDED IN so the shadow can pin the same window
    // the legacy leg is charged in — and `NATIVE_SEATS`, empty on every deployment, so the Approve
    // step is the no-op the shipped path has no equivalent step for.
    NODE.answer_arriving_at(arrival, Some(model.to_string()), NATIVE_SEATS, arrived)
        .await
}

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
#[path = "tests/units_llm.rs"]
mod tests;
