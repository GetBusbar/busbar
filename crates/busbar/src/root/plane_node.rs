// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # The node, and the money book behind it
//!
//! The composition root's half of a unit that a plane's arrival HANDS it: the kernel, the in-flight
//! table the unit's cell lives in, the interner the unit's lanes are sealed through, the one Route
//! seam its leg is driven through, and the book its end and its late figure settle onto. The unit
//! itself — the ten methods over the plane's step files — is the plane's, and so are the arrivals
//! that hand it over: they reach this node through the linked table's `node` axis
//! ([`crate::root::linked::node`]), and this file names no plane.
//!
//! ## What crosses, and why it is values
//!
//! An arrival hands the node whose unit it is, its operation class, the dialect a refusal this node
//! renders is written in, and a BUILD ([`Handed`]). The node lends the build what only it holds — its
//! lane resolver, the loop's meter, and the unit's pinned arrival epoch — and gets back the unit's
//! steps, its awaited Route leg, and its FINISH: the bytes the terminal posted and the reading of
//! what they consumed, taken once their body has drained. That reading is a report, never an amount:
//! what it is worth is this node's card's answer, priced here (`one-pricing-site.allowed.root-wiring`)
//! against the snapshot pinned at the unit's door.
//!
//! ## The two ends the node keeps its hands on
//!
//! The loop hands whoever drives it two things beside the steps: the Route LEG, which it awaits, and
//! an ABANDONED end, when the caller goes away mid-dispatch. The node drives the plane's unit through
//! [`Driven`], which answers every step with the plane's own answer and holds those two: the leg goes
//! out through the node's one Route seam after the dispatch is on the book, and an abandoned end is
//! posted onto the same book, balance and window a returned end is.
//!
//! ## What the switch costs
//!
//! Nothing a thread pool can run out of. The loop's Route step is a future it awaits on the caller's
//! own runtime, so a unit occupies its in-flight slot and no thread at all while the upstream thinks:
//! the node's ceiling is the in-flight table's, an in-flight request costs no thread stack, and a
//! client that goes away drops the loop, which drops the unit, which drops the upstream leg. The unit
//! still ends exactly once — through the charged audit door and the one exit, named for what
//! happened — and the slot it held is free before the next arrival asks for one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use axum::http::StatusCode;
use axum::response::Response;

use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Audit, Authenticate, Consumption, Decode, Dial, Encode,
    Grant, Meter, OpClassId, OriginKind, Outcome, Pass, PrincipalId, Refusal, Route, SeatVerdict,
    VerifiedDestination, Verify,
};
use busbar_contract::{LaneId, Registration, UnitKey};
use busbar_kernel::plane_host::PlaneAnswer;
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{
    AccrualMeter, Ended, Evidence, RouteAwait, RouteLeg, Screen, UnitCtx, Units,
};
use busbar_kernel_audit::{
    AuditInputs, Controls, FinishClass as RecordFinish, OpClassId as RecordOpClass, OutcomeFacts,
    Subject, Usage as RecordUsage, UsageLine as RecordLine, What,
};
use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

use crate::root::linked::node::{Handed, Late, Reported, Resolve};

// ---------------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------------

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
/// One per process. The per-request half is the plane's unit, which a plane's arrival hands this
/// node ([`Handed`]) and which is thrown away with the unit.
pub struct Node {
    kernel: Arc<busbar_kernel::teller::Kernel>,
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
    /// them through it again. Shared with the resolver every unit is lent ([`Node::resolver`]).
    lane_names: Arc<Mutex<LaneNames>>,
    next_key: Arc<busbar_kernel::door::UnitKeyMint>,
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
    /// [`bind_book`]: Node::bind_book
    book: std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>,
    /// THE BOOK'S LANE TO THE CONFIGURED STORE, when the store is where the book's journal is kept
    /// (no data directory). Read at every arrival, without the book's lock: while it is full a new
    /// money-bearing unit is refused 503 with the reason (ARCHITECT 2026-10-07 H3 ruling).
    lane: std::sync::OnceLock<crate::root::durability::JournalLane>,
    /// The journal's token, minted from this node's own kernel at construction and lent to the exit
    /// arm for the length of one settlement.
    ///
    /// Minted outside the loop because making a posting durable happens after the exit has sealed
    /// the end: there is no step of the unit whose token could stand in, which is the same reason
    /// the verbs unit's is minted outside it.
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
    /// It is the loop's seam and not a plane's — see [`PlaneDispatch`] — and the plane's own leg
    /// is what gets handed across it. Route drives; nothing here reports.
    ///
    /// [`PlaneDispatch`]: crate::root::transports::PlaneDispatch
    dispatch: Arc<dyn crate::root::transports::PlaneDispatch>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node").finish_non_exhaustive()
    }
}

impl Default for Node {
    fn default() -> Self {
        Self::new()
    }
}

impl Node {
    /// Compose the node every handed unit is answered by.
    #[must_use]
    pub fn new() -> Self {
        let lanes = Arc::new(Mutex::new(crate::root::kernel::new_registration()));
        let kernel = crate::root::kernel::new_kernel();
        Self {
            durability_token: kernel.durability_token(),
            usage_token: kernel.usage_token(),
            book: std::sync::OnceLock::new(),
            lane: std::sync::OnceLock::new(),
            kernel: Arc::new(kernel),
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
            lane_names: Arc::new(Mutex::new(LaneNames {
                interner: lanes,
                resolved: HashMap::new(),
                consulted: 0,
            })),
            next_key: Arc::default(),
            marked: AtomicU64::new(0),
            lost: Mutex::new(HashMap::new()),
            mono: AtomicU64::new(0),
            // THE PRODUCTION HALF, which awaits the leg it is handed and returns that leg's own
            // value. Composed here because composing is what this file does: the plane names the
            // work, the root names what the work is driven through, and neither names the other's.
            dispatch: Arc::new(crate::root::transports::DrivenOnce::new()),
        }
    }

    /// The node's kernel and its one unit-key mint, shared with a unit the node does not drive but
    /// whose key must be unique beside its own (a door plane's health probe, K7).
    #[must_use]
    pub fn kernel_and_keys(
        &self,
    ) -> (
        Arc<busbar_kernel::teller::Kernel>,
        Arc<busbar_kernel::door::UnitKeyMint>,
    ) {
        (Arc::clone(&self.kernel), Arc::clone(&self.next_key))
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
    pub fn arrived(&self) -> Arrived {
        Arrived::at(
            busbar_kernel::store::now_ms(),
            self.mono.fetch_add(1, Ordering::AcqRel),
        )
    }

    /// The interner itself — the image's one vocabulary, as this node holds it.
    #[must_use]
    pub fn lanes(&self) -> Arc<Mutex<Registration>> {
        Arc::clone(&self.lanes)
    }

    /// THE RESOLVER THIS NODE LENDS A UNIT: a configured lane name to the interned lane, through the
    /// node's own table in front of the interner — so the image's one lock is reached once per
    /// distinct name for the life of the node, however many units ask.
    pub fn resolver(&self) -> Resolve {
        let names = Arc::clone(&self.lane_names);
        Arc::new(move |name: &str| {
            names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .resolve(name)
        })
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
    ///
    /// When the book's journal is kept by the configured store, the store's lane is bound with it:
    /// the node FAILS CLOSED while that lane is full ([`Node::journal_refusal`]).
    pub fn bind_book(&self, book: Arc<Mutex<crate::root::durability::Durability>>) {
        let lane = {
            let durability = book.lock().unwrap_or_else(|p| p.into_inner());
            durability
                .durable_in_store()
                .then(|| durability.lane().cloned())
                .flatten()
        };
        if let Some(lane) = lane {
            let _ = self.lane.set(lane);
        }
        let _ = self.book.set(book);
    }

    /// WHY THIS NODE REFUSES A NEW MONEY-BEARING UNIT NOW, or `None` — one atomic read while the
    /// store keeps up. The book's journal is kept by the configured store and the lane to it is
    /// full: admitting the unit would put records on the chain nothing has room to hold, and a record
    /// is never dropped, so the unit is refused instead (ARCHITECT 2026-10-07 H3 ruling).
    #[must_use]
    pub fn journal_refusal(&self) -> Option<String> {
        self.lane
            .get()
            .and_then(crate::root::durability::JournalLane::refuses_money)
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
        seal: Option<UnitSeal>,
    ) {
        let Some(book) = self.book.get() else {
            return;
        };
        let busbar_kernel::teller::Ended::Settled { end, .. } = ended else {
            return;
        };
        let outcome = end.outcome();
        let Ok(posted) = end.into_posted() else {
            return;
        };
        // THE UNIT'S RECORD, sealed with its one line. Its amount is the unit's counts plus the card
        // version, never a price (`BUSBAR-1.6.0.md` THE DESIGN §1, #43, #77(3)). The exit's posting
        // carries only the figure the settlement writer moved, money in nano-units, and no class or
        // count, so it gives the record no line. A unit whose counts are known has a late arm, and
        // that arm seals them ([`report_lines`]).
        let lines = Vec::new();
        // Settle THROUGH the money-book seam rather than a `&mut` on the book itself: the lock is
        // taken and released inside the seam, so this arm settling does not hold the one book across
        // its whole exit the way a `&mut Durability` did. The pass-through settles the identical
        // posting onto the identical shared book — the bytes on the chain are unchanged.
        let shared = crate::root::durability::SharedBook::over(Arc::clone(book));
        let _settled = settle(
            &shared,
            principal,
            arrived,
            card,
            &self.durability_token,
            posted,
        );
        if let Some(seal) = seal {
            seal.seal(
                book,
                &self.durability_token,
                principal,
                arrived,
                card_in_force(card, arrived.ms()),
                outcome,
                lines,
                0,
            );
        }
    }

    /// Open this unit's hold on the book and on the journal, if this node has a book (item 127).
    ///
    /// On the same balance, in the same window and under the same arrival reading the exit arm
    /// will settle it with ([`settle`]), so the posting that ends the unit closes this record on the
    /// chain. A journal that will not take it is not a refusal: the log retains the record and
    /// offers it again, and the previous release served through a store hiccup.
    ///
    /// The record carries the COUNTS the reservation was sized for, never a figure (#71): the door
    /// on this plane reserves nothing (its arrival hold opens at zero and no step sizes it), so the
    /// counts are none and the book derives a reservation of nothing from them.
    fn open_on_book(&self, principal: &PrincipalId, arrived: Arrived) {
        let Some(book) = self.book.get() else {
            return;
        };
        let key = balance(principal);
        let at = crate::root::durability::Settling {
            key: &key,
            window: busbar_kernel::governance::budget_window(
                busbar_kernel::governance::WINDOW_DAY,
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
        let _opened = durability.open_hold(
            &at,
            principal,
            &crate::root::durability::UnitCounts::default(),
            arrived.ms(),
        );
    }

    /// Record on the book that this unit DISPATCHED, before its leg leaves the node.
    ///
    /// On the balance, window and arrival reading its hold was opened under ([`Self::open_on_book`]),
    /// so the record names that hold: a node killed after this is durable recovers the hold as a
    /// unit that sent something — posted at its last accrual checkpoint and marked recovered —
    /// rather than voiding it as a unit that never left. A journal that will not take it is not a
    /// refusal of the dispatch: the log retains the record and offers it again.
    fn dispatch_on_book(&self, principal: &PrincipalId, arrived: Arrived) {
        let Some(book) = self.book.get() else {
            return;
        };
        let key = balance(principal);
        let at = crate::root::durability::Settling {
            key: &key,
            window: busbar_kernel::governance::budget_window(
                busbar_kernel::governance::WINDOW_DAY,
                arrived.secs(),
            ),
            durability: &self.durability_token,
            step: busbar_contract::caps::StepName::Route,
            stamp: crate::root::durability::PostingStamp {
                rate_card_version: 0,
                wall: arrived.secs(),
                mono: arrived.mono(),
            },
        };
        let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let _dispatched = durability.journal_dispatch(&at);
    }

    /// Record on the book this unit's ACCRUAL SO FAR: a durability `unit.accrued` checkpoint
    /// (THE DESIGN §7), counts and the instant they price at, never a figure (#71).
    ///
    /// On the balance, window and arrival reading its hold was opened under
    /// ([`Self::open_on_book`]), as [`Self::dispatch_on_book`] marks it, so a node killed before the
    /// unit's one line is written recovers the hold at these counts, marked recovered. Called from
    /// the root's checkpoint flush tick alone, never on a piece's path. A journal that will not take
    /// it retains and re-offers it; a checkpoint for a hold already closed marks nothing.
    fn checkpoint_on_book(
        &self,
        principal: &PrincipalId,
        arrived: Arrived,
        counts: &crate::root::durability::UnitCounts,
    ) {
        let Some(book) = self.book.get() else {
            return;
        };
        let key = balance(principal);
        let at = crate::root::durability::Settling {
            key: &key,
            window: busbar_kernel::governance::budget_window(
                busbar_kernel::governance::WINDOW_DAY,
                arrived.secs(),
            ),
            durability: &self.durability_token,
            step: busbar_contract::caps::StepName::Meter,
            stamp: crate::root::durability::PostingStamp {
                rate_card_version: 0,
                wall: arrived.secs(),
                mono: arrived.mono(),
            },
        };
        let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let _accrued = durability.checkpoint_accrual(&at, counts, arrived.ms());
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
    /// that unit's terminal and hands the end to [`Driven`]'s `abandoned`, so by the time the sweep
    /// arrives the cell is already empty and the sweep only gives the slot back. What this path is
    /// FOR is the unit whose end nobody reached — and it posts that unit's hold rather than leaving
    /// it in a cell nothing will ever take it out of.
    ///
    /// Run by the next arrival (see [`Node::answer_arriving_at`]), and only when something is
    /// marked, so a lost task costs one arrival's delay and an ordinary arrival costs one atomic
    /// read. The idle bound does not apply on this node — a slow streamed answer was never cut, and
    /// the sweep does not start cutting it — so only a MARKED slot is ever settled here.
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
                        // A unit the sweep ends never handed back its audit pass: it has no record.
                        None,
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

    /// THE PARENT a nested unit is driven under ([`Node::drive_borrowed`]): the unit `key`, while it
    /// is live in this node's table.
    #[must_use]
    pub fn parent(&self, key: UnitKey) -> Option<Parent> {
        self.inflight.get(key).map(|slot| Parent { key, slot })
    }

    /// A key for one unit this node is about to drive ([`Node::drive_borrowed`]), from the node's
    /// one mint: the steps that serve it are told it before it runs.
    #[must_use]
    pub fn mint(&self) -> UnitKey {
        self.next_key.mint()
    }

    /// THE BORROWED DRIVE (SERVE-WIRE step 33; the node's half of a unit served through a plane's
    /// door, ARCHITECT Q-SW3 2026-10-02): one unit whose steps, route and caller live on the serving
    /// future's stack (a plane driver's unit), walked through the loop under this node's in-flight
    /// table, sweep and gauge, its hold on the journal before it runs, as [`Node::answer`] walks a
    /// handed one. `key` is from [`Node::mint`], `arrived` from [`Node::arrived`] (the reading the
    /// unit's steps charged in); `principal` is whose arrival hold the table enters; `history` the
    /// card history pinned at its door, which its one line is priced against.
    ///
    /// Its facts are opened on `post` for the whole drive, so an end the loop's guard reaches for a
    /// caller that went away is posted there (`NodeEndPost`), and the egress walk's dispatch record
    /// is written under them. A unit that returns writes its ONE LINE here: the report `late` reads
    /// once the unit has ended (what it consumed, priced at the card pinned at its door, the node's
    /// one pricing site), else the exit's posting as it stood, its audit record sealed with it.
    /// Answers whether the table took the unit. Dropping the future marks its slot for the sweep.
    ///
    /// A NESTED unit (`unit.nest`, THE DESIGN §11.12 unit row) names its `parent`: it enters the
    /// table as `OriginKind::Nested`, its loop runs with the parent's hold cell as its `Run.parent`
    /// (so its door accrues against the parent's admission, and its posting goes into the parent's
    /// hold, or late on its own when the parent exited first), and its record names the parent.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_borrowed<U: Units + RouteAwait>(
        &self,
        key: UnitKey,
        arrived: Arrived,
        principal: &PrincipalId,
        post: &NodeEndPost,
        units: &U,
        late: Late,
        history: Option<crate::root::kernel::PinnedHistory>,
        parent: Option<&Parent>,
    ) -> Option<Outcome> {
        self.sweep(arrived);
        if self.journal_refusal().is_some() {
            return None;
        }
        post.open(key, principal.clone(), arrived, history.clone());
        let meter = Arc::new(AccrualMeter::new());
        let origin = parent.map_or(OriginKind::Client, |p| OriginKind::Nested { parent: p.key });
        let hold =
            busbar_kernel::inflight::arrival_hold(&self.kernel, &self.door, principal.clone());
        let Ok(slot) = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: arrived.ms(),
        }) else {
            post.close(key);
            return None;
        };
        self.open_on_book(principal, arrived);
        let mut occupied = Occupied {
            node: self,
            slot: Arc::clone(&slot),
            arrived,
            reached_end: false,
        };
        let ctx = UnitCtx {
            key,
            origin,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        let borrowed = Borrowed { units, post };
        let ended = busbar_kernel::teller::run_unit_async(
            &self.kernel,
            &borrowed,
            &ctx,
            busbar_kernel::teller::Run {
                cell: slot.cell(),
                parent: parent.map(|p| p.slot.cell()),
                leases: slot.leases(),
                gauge: &self.gauge,
                canary: &self.canary,
                meter: &meter,
            },
            &borrowed,
        )
        .await;
        // How the unit ended, for the caller's close (a framed stream's final status); `None` when
        // the node's sweep settled it first.
        let outcome = match &ended {
            Ended::Settled { end, .. } => Some(end.outcome()),
            Ended::AlreadySettled => None,
        };
        // The unit returned: its facts close here, and its record is sealed with its one line.
        let seal = post.take(key).map(|(facts, pass)| UnitSeal {
            facts,
            pass,
            key,
            origin: self.kernel.origin(origin),
            parent: parent.map(|p| p.key),
        });
        match self.late_arm(Some(late), principal, arrived, history.as_ref()) {
            Some(mut arm) => {
                arm.seal = seal;
                arm.carrying(ended).post();
            }
            None => self.settle_end(principal, arrived, history.as_ref(), ended, seal),
        }
        occupied.reached_end = true;
        outcome
    }

    /// THE BORROWED SESSION OPEN (K6; ARCHITECT Q-L5B-SESSION-SERVE 2026-10-03): one duplex session
    /// unit whose steps, far end and caller live on the serving task (a plane driver's unit), run
    /// through the loop's session opener ([`busbar_kernel::teller::open_unit`]: arrival to the door
    /// and its audit, a session admitting at a zero hold, so nothing is held on the book and there is
    /// no exit to settle) under this node's in-flight table, sweep and gauge. Its facts are opened on
    /// `post` for the whole session. What the door said comes back with the unit's context and the
    /// slot the session holds while it runs: [`SessionSlot::finish`] gives it back once the session
    /// ended (its money is the session's one line, `PlaneMoney::session_ended`); dropping the slot
    /// marks it for the sweep. `None` when the table would not take the unit.
    pub fn open_borrowed<U: Units>(
        &self,
        key: UnitKey,
        arrived: Arrived,
        principal: &PrincipalId,
        post: &'_ NodeEndPost,
        units: &U,
        history: Option<crate::root::kernel::PinnedHistory>,
    ) -> Option<(busbar_kernel::teller::SessionOpen, UnitCtx, SessionSlot<'_>)> {
        self.sweep(arrived);
        if self.journal_refusal().is_some() {
            return None;
        }
        post.open(key, principal.clone(), arrived, history);
        let meter = Arc::new(AccrualMeter::new());
        let hold =
            busbar_kernel::inflight::arrival_hold(&self.kernel, &self.door, principal.clone());
        let Ok(slot) = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: arrived.ms(),
        }) else {
            post.close(key);
            return None;
        };
        let occupied = Occupied {
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
        let borrowed = Borrowed { units, post };
        let opened = busbar_kernel::teller::open_unit(
            &self.kernel,
            &borrowed,
            &ctx,
            busbar_kernel::teller::Run {
                cell: slot.cell(),
                parent: None,
                leases: slot.leases(),
                gauge: &self.gauge,
                canary: &self.canary,
                meter: &meter,
            },
        );
        Some((opened, ctx, SessionSlot { occupied, key }))
    }

    /// Walk one handed unit through the loop and answer with what the terminal posted.
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a unit a plane's
    /// arrival handed this node. What comes back is what the AUDIT step posted: this function
    /// chooses the PATH, never the bytes.
    ///
    /// Awaited on the runtime the request arrived on. Drop this future — which is what axum does
    /// when the client hangs up — and the loop's own future goes with it: the unit ends at its one
    /// terminal, the hold leaves the cell, and [`Occupied`] hands the table its slot back on the way
    /// out. Nothing is spawned here, so there is no detached task left holding either.
    #[must_use]
    pub async fn answer(&self, handed: Handed) -> Response {
        self.answer_arriving_at(handed, self.arrived()).await
    }

    /// The same drive, with the arrival reading HANDED IN rather than taken.
    ///
    /// [`answer`](Self::answer) is this with the node's own clock read once, at the top, which is
    /// the only place on this path a clock is read. It is split out because "what this loop does
    /// with the instant it arrived at" is a property of the loop, and a drive that reads the clock
    /// itself cannot be asked about an instant a test picks — least of all the one instant that
    /// matters, a unit arriving at the last millisecond of a window.
    #[must_use]
    pub async fn answer_arriving_at(&self, handed: Handed, arrived: Arrived) -> Response {
        self.answer_pinned(handed, arrived, || crate::root::kernel::ROOT_CARD.pin())
            .await
    }

    /// The drive itself, with the history snapshot the unit is admitted under taken by `pin` — at the
    /// door, after the sweep, exactly where [`answer_arriving_at`](Self::answer_arriving_at) reads the
    /// process's history.
    async fn answer_pinned(
        &self,
        handed: Handed,
        arrived: Arrived,
        pin: impl FnOnce() -> Option<crate::root::kernel::PinnedHistory>,
    ) -> Response {
        // The sweep, before this unit takes a slot of its own: any slot a lost task left MARKED is
        // settled and given back now. One atomic read when nothing is marked.
        self.sweep(arrived);
        // Whose unit, what class, and the dialect a refusal this node renders is written in — the
        // plane's statements about what arrived, read off it before any step runs.
        let (principal, op_class, proto, build) = handed;
        // FAIL CLOSED while the book's journal cannot reach its store: nothing is built, held or
        // journalled for a unit that is refused here, and the reason is the answer.
        if let Some(why) = self.journal_refusal() {
            return journal_unavailable(proto, &why);
        }
        let key = self.next_key.mint();
        // ONE METER, on both sides of the loop: the unit accrues onto it at the Meter step and the
        // kernel reads it at the exit. It is lent to the unit at the build.
        let meter = Arc::new(AccrualMeter::new());
        // THE HISTORY SNAPSHOT THIS UNIT IS ADMITTED UNDER, pinned here for the same reason the
        // charge epoch below is: a live apply may APPEND to the root's history at any instant, and a
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
        let history = pin();
        // THE UNIT, built with what this node lends it: its resolver, the loop's meter, and the
        // header-arrival epoch every charge and every refund it makes lands in — pinned once, spelled
        // out of the ONE arrival reading, so a request whose response completes in a later window
        // than its headers arrived cannot split its charges across two windows, and the epoch it is
        // billed in and the stamp the table enters it under cannot be two different instants.
        let (units, route, finish) = build((self.resolver(), arrived.secs()));

        let hold =
            busbar_kernel::inflight::arrival_hold(&self.kernel, &self.door, principal.clone());
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
                self.open_on_book(&principal, arrived);
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
                let driven = Driven {
                    node: self,
                    units: &*units,
                    route: &*route,
                    op_class,
                    principal: &principal,
                    arrived,
                    history: history.as_ref(),
                    sealing: Mutex::new(None),
                };
                let ended = busbar_kernel::teller::run_unit_async(
                    &self.kernel,
                    &driven,
                    &ctx,
                    busbar_kernel::teller::Run {
                        cell: slot.cell(),
                        parent: None,
                        leases: slot.leases(),
                        gauge: &self.gauge,
                        canary: &self.canary,
                        meter: &meter,
                    },
                    &driven,
                )
                .await;
                // THE EXIT ARM. The loop took the hold out of the cell and handed back a POSTING,
                // which has moved no balance and left no record until something settles it — and
                // until this line nothing did, so a unit ran, ended, posted, and posted into a value
                // that was dropped on the floor.
                // The SAME pin the late arm prices against, so the posting and the figure that
                // follows it name one snapshot. Re-pinning here would read a history a live apply
                // may have appended to since the door, which is the hazard the pin exists for.
                // The loop ran; the answer is whatever the terminal posted. There is no unit that
                // reaches an end without passing one of the two audit doors, so the fallback below
                // is unreachable — and it is an answer rather than an unwrap, because a path that
                // cannot be taken still has to say something if it is.
                // THE AUDITED EXIT (#28): the plane's answer becomes the served response here, and
                // nowhere on the plane's side of the seam.
                let (answer, late) = finish();
                let response =
                    answer.map_or_else(|| unavailable(proto), PlaneAnswer::into_response);
                let seal = driven.take_seal(key);
                let response = self.tail(
                    ended,
                    response,
                    late,
                    &principal,
                    arrived,
                    history.as_ref(),
                    seal,
                );
                // The unit reached its own end and its posting is on the book or in the late arm's
                // hands: the slot goes straight back. Anything that leaves this function before here
                // leaves it MARKED.
                occupied.reached_end = true;
                response
            }
        }
    }

    /// THE UNIT'S TAIL: its ONE LINE (KERNEL<>PLUGINS step 14) and the answer it serves.
    ///
    /// A unit whose figure arrives with its drained body has its line written by the late arm, which
    /// carries the exit's posting there unwritten: the exit writes none for it, and the reservation
    /// and the reported figure close on one record when the figure arrives. Every other unit's line
    /// is the exit's posting, written here and now.
    #[allow(clippy::too_many_arguments)]
    fn tail(
        &self,
        ended: Ended,
        response: Response,
        late: Option<Late>,
        principal: &PrincipalId,
        arrived: Arrived,
        history: Option<&crate::root::kernel::PinnedHistory>,
        seal: Option<UnitSeal>,
    ) -> Response {
        match self.late_arm(late, principal, arrived, history) {
            Some(mut arm) => {
                arm.seal = seal;
                // THE LATE ARM. On a plane whose money is in a cell the response's own body fills
                // when it DRAINS, the terminal knew nothing of it. So the body goes out wrapped,
                // and the unit's one line lands when the figure arrives.
                let arm = arm.carrying(ended);
                let (parts, body) = response.into_parts();
                Response::from_parts(parts, axum::body::Body::new(LateBody::new(body, arm)))
            }
            None => {
                self.settle_end(principal, arrived, history, ended, seal);
                response
            }
        }
    }

    /// The late arm for this unit's answer, if its line is to be written when the figure arrives.
    ///
    /// Nothing the arm does changes a byte of what the client is given: the wrapper forwards the
    /// frames, their order, the trailers and the size hint. What it adds is a place to stand at the
    /// one instant the unit's money becomes a fact.
    ///
    /// Three ways there is no arm, and each is a case where there is nothing to wait for: no book
    /// bound (nowhere for a posting to go), no history pinned at admission (a report nothing can
    /// price), and no late reading on the response (nothing was ever going to fill one). The exit
    /// then writes the unit's one line itself.
    fn late_arm(
        &self,
        late: Option<Late>,
        principal: &PrincipalId,
        arrived: Arrived,
        history: Option<&crate::root::kernel::PinnedHistory>,
    ) -> Option<LateAccrual> {
        let book = self.book.get()?;
        let history = history?.clone();
        let late = late?;
        Some(LateAccrual {
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
            late,
            exit: None,
            outcome: None,
            seal: None,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The late accrual
// ---------------------------------------------------------------------------------------------

/// WHAT A UNIT CONSUMED, read after its body drained — the plane's report, in the node's hands.
///
/// A REPORT, not an amount, and the distinction is the whole shape of the seam. The plane says what a
/// unit did — the quantities it consumed, by class, and how many billable requests it is — and names
/// the serving lane the row is keyed by. What any of that is WORTH is the card's answer, and the card
/// is this node's; the fee lands as a line of that pricing rather than as a number the plane invented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Every class the tap reported, by neutral unit class — the reserved token split and every open
    /// class beside it (a rerank's search units): the same counts the governance ledger accrued when
    /// the cell filled. Empty for a response that billed nothing.
    pub usage: busbar_contract::billing::Usage,
    /// How many billable requests this unit is: one for a delivered client request that reached an
    /// upstream, zero otherwise — the Meter step's own count, carried rather than re-decided.
    pub fee_count: u32,
    /// The SERVING lane's config name — the lane that actually answered, after any failover, which
    /// is the key a rate card is written against and the key the legacy row carries.
    pub lane: String,
}

impl Report {
    /// The plane's reading, as the node's own report type.
    fn of((usage, fee_count, lane): Reported) -> Self {
        Report {
            usage,
            fee_count,
            lane,
        }
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
    busbar_contract::records::UNIT_INPUT,
    busbar_contract::records::UNIT_OUTPUT,
    busbar_contract::records::UNIT_CACHE_READ,
    busbar_contract::records::UNIT_CACHE_WRITE,
];

fn usage_record(
    token: &busbar_contract::caps::Grant<busbar_contract::caps::Consumption>,
    usage: &busbar_contract::billing::Usage,
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
/// The plane supplied the report — classes, quantities, the billable count and the lane the row is
/// keyed by — and nothing in it is money. The card supplies the rest.
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
    report: &Report,
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
    report: &Report,
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
    /// THE LATE READING the plane handed over with the unit's finish, taken once the body has
    /// drained. It keeps what the reading needs alive — the plane's carry and the cell the body
    /// fills — for exactly as long as the body is, and names neither.
    late: Late,
    /// THE EXIT'S POSTING, carried here unwritten (KERNEL<>PLUGINS step 14): the exit writes no line
    /// for a unit with a late arm, so its reservation closes on the one line this arm writes. `None`
    /// when the exit had no posting to hand over (the sweep got there first, or its record was lost
    /// and the loss is already on the end it sealed).
    exit: Option<busbar_contract::caps::Posted>,
    /// How the unit ended, as the exit sealed it — the record's outcome.
    outcome: Option<Outcome>,
    /// The unit's audit pass and facts, sealed into its one record with the line this arm writes.
    seal: Option<UnitSeal>,
}

impl LateAccrual {
    /// Carry the exit's posting to the one line this arm writes.
    fn carrying(mut self, ended: Ended) -> Self {
        self.exit = match ended {
            Ended::Settled { end, .. } => {
                self.outcome = Some(end.outcome());
                end.into_posted().ok()
            }
            _ => None,
        };
        self
    }

    /// Read the tap and write the unit's one line. Runs at most once per unit — see [`LateBody`].
    fn post(self) {
        let LateAccrual {
            book: held,
            history,
            durability_token,
            ledger_token,
            usage_token,
            principal,
            arrived,
            late,
            exit,
            outcome,
            seal,
        } = self;
        let book = crate::root::durability::SharedBook::over(Arc::clone(&held));
        let card = card_in_force(Some(&history), arrived.ms());
        let Some(report) = late().map(Report::of) else {
            // Nothing arrived after all: the one line is the exit's posting as it stood, written
            // where the exit would have written it.
            if let Some(exit) = exit {
                // No counts arrived, and the posting is a figure, not counts: no line.
                let lines = Vec::new();
                let _settled = settle(
                    &book,
                    &principal,
                    arrived,
                    Some(&history),
                    &durability_token,
                    exit,
                );
                if let (Some(seal), Some(outcome)) = (seal, outcome) {
                    seal.seal(
                        &held,
                        &durability_token,
                        &principal,
                        arrived,
                        card,
                        outcome,
                        lines,
                        0,
                    );
                }
            }
            return;
        };
        post_late(
            &book,
            &LateTokens {
                durability: &durability_token,
                ledger: &ledger_token,
                usage: &usage_token,
            },
            &history,
            &principal,
            arrived,
            &report,
            exit,
        );
        if let (Some(seal), Some(outcome)) = (seal, outcome) {
            seal.seal(
                &held,
                &durability_token,
                &principal,
                arrived,
                card,
                outcome,
                report_lines(&report),
                report.fee_count,
            );
        }
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
fn counts_of(report: &Report) -> crate::root::durability::UnitCounts {
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

/// **THE LATE ARM'S POSTING**: what one drained report leaves on the second book. ALWAYS ONE LINE
/// PER UNIT (KERNEL<>PLUGINS step 14; #43: the write is unconditional; #71: the fact is the counts,
/// and pricing is the read). `exit` is the exit's posting, carried here unwritten: the line closes
/// the unit's reservation too.
///
/// - PRICED above zero: the settlement moves the book, and its record carries the counts beside
///   the figure.
/// - PRICED AT ZERO, or REFUSED: the line moves no balance beyond closing the reservation. A
///   refusal (#42) leaves the money unpriced — no zero, no partial — and every read of the balance
///   it sits on refuses.
fn post_late(
    book: &dyn crate::root::durability::MoneyBook,
    tokens: &LateTokens<'_>,
    history: &crate::root::kernel::PinnedHistory,
    principal: &PrincipalId,
    arrived: Arrived,
    report: &Report,
    exit: Option<busbar_contract::caps::Posted>,
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
    let refuse = |refusal: String, exit: Option<busbar_contract::caps::Posted>| match exit {
        Some(exit) => {
            let _line =
                book.settle_counted_refusing(&at, exit, &counts, arrived.ms(), Some(refusal));
        }
        None => {
            let _row = book.post_counts(&at, principal, &counts, arrived.ms(), Some(refusal));
        }
    };
    // A CLASS NOBODY DECLARED (`BUSBAR-1.6.0.md` §7: a plane declares every class it reports). The
    // registered vocabulary holds the reserved four, every installed plane's declared billable
    // classes and every configured `units:` class; a reported class outside it is a plane fault.
    // FAIL-CLOSED: the line keeps every count and its money is refused — never priced at zero,
    // never dropped.
    if let Some(class) = counts
        .classes
        .keys()
        .find(|class| busbar_contract::Registration::resolve(class).is_none())
    {
        busbar_kernel::diagnostics::diag_error!(
            busbar_kernel::diagnostics::METER_CLASS_UNDECLARED,
            principal = principal.as_str(),
            lane = %report.lane,
            class = %class,
            "a unit reported a usage class its plane never declared; its line is refused"
        );
        refuse(
            format!("{}({class:?})", crate::root::durability::UNDECLARED_CLASS),
            exit,
        );
        return;
    }
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
            refuse(format!("{refusal:?}"), exit);
            return;
        }
    };
    if amount == 0 {
        match exit {
            Some(exit) => {
                let _line = book.settle_counted(&at, exit, &counts, arrived.ms());
            }
            None => {
                let _row = book.post_counts(&at, principal, &counts, arrived.ms(), None);
            }
        }
        return;
    }
    let accrual = busbar_contract::caps::HoldAccrual::after_terminal(
        principal.clone(),
        amount,
        tokens.ledger,
    );
    let posted = match exit {
        Some(exit) => exit.with_late(accrual, tokens.ledger),
        None => busbar_contract::caps::Posted::settle_late(accrual, tokens.ledger),
    };
    // Through the money-book seam, as the terminal exit arm does — the same shared book, the same
    // posting, the lock taken and released behind the seam — with the counts on the record.
    let _settled = book.settle_counted(&at, posted, &counts, arrived.ms());
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
/// slot in the table MARKED, and the node's sweep ([`Node::sweep`]) is what gives it back.
///
/// It used to REMOVE the slot on every way out, and that is the half of the protocol that could not
/// work: the sweep is the second holder of a key to the unit's hold cell, and a slot removed on the
/// way out is a cell the sweep can never see — so a hold the exit never reached was left in a cell
/// nothing would ever take it out of, and a disconnect mid-dispatch skipped its charge. A guard only
/// ever MARKS: it runs during an unwind, where taking a hold and settling it is exactly what must not
/// happen, so ending the unit is the sweep's job and marking is the whole of this one's.
struct Occupied<'n> {
    node: &'n Node,
    slot: Arc<busbar_kernel::inflight::UnitSlot>,
    /// The unit's arrival, handed to the sweep with the mark.
    arrived: Arrived,
    /// Set once the unit's end has been reached and settled on the ordinary path.
    reached_end: bool,
}

/// THE IN-FLIGHT SLOT A BORROWED SESSION HOLDS while it runs ([`Node::open_borrowed`]).
#[must_use = "a session slot dropped unfinished is marked for the sweep"]
pub struct SessionSlot<'n> {
    occupied: Occupied<'n>,
    key: UnitKey,
}

impl std::fmt::Debug for SessionSlot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSlot")
            .field("key", &self.key)
            .finish()
    }
}

impl SessionSlot<'_> {
    /// The session ended on its own path: its facts close on `post` and its slot is given back.
    pub fn finish(mut self, post: &NodeEndPost) {
        post.close(self.key);
        self.occupied.reached_end = true;
    }
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

/// What a node whose journal cannot reach its store answers a new unit with, in the caller's own
/// dialect: 503 and the reason. A state the previous release never reached (it kept no journal).
fn journal_unavailable(proto: &str, why: &str) -> Response {
    busbar_kernel::proxy::ingress_error(
        proto,
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        why,
    )
}

/// What a node that cannot take the unit at all answers with, in the caller's own dialect.
fn unavailable(proto: &str) -> Response {
    busbar_kernel::proxy::ingress_error(
        proto,
        StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        "The service is temporarily overloaded. Please retry shortly.",
    )
}

// ---------------------------------------------------------------------------------------------
// The unit, as this node drives it
// ---------------------------------------------------------------------------------------------

/// ONE UNIT, AS THIS NODE DRIVES IT: the plane's unit, answering every step with the plane's own
/// answer, and the node's hands on the two ends the loop gives to whoever drives it.
///
/// The ROUTE LEG goes out through the node's one seam ([`PlaneDispatch`]) after the dispatch is on
/// the book, so a recovery can tell a unit that sent something from one that never did. An
/// ABANDONED end — the caller went away mid-dispatch, and the loop's guard sealed the end at the
/// charged audit door — is posted here (item 99), onto the same book, balance and window
/// [`Node::answer_arriving_at`] posts a returned end to, through the same exit arm.
///
/// [`PlaneDispatch`]: crate::root::transports::PlaneDispatch
struct Driven<'n> {
    node: &'n Node,
    units: &'n (dyn Units + Send + Sync),
    route: &'n (dyn RouteAwait + Send + Sync),
    op_class: OpClassId,
    /// Whose unit this is — the principal the balance it settles onto is keyed by.
    principal: &'n PrincipalId,
    /// The unit's arrival, both readings.
    arrived: Arrived,
    /// The history snapshot the unit was admitted under.
    history: Option<&'n crate::root::kernel::PinnedHistory>,
    /// The audit pass and facts the loop handed back at the unit's audit door (`Units::audited`),
    /// held until the unit's one line is written, where its record is sealed with them.
    sealing: Mutex<Option<(busbar_contract::caps::AuditFacts, Pass<Audit>)>>,
}

impl Driven<'_> {
    /// The unit's record-to-be, if its audit door handed its pass back.
    fn take_seal(&self, key: UnitKey) -> Option<UnitSeal> {
        let (facts, pass) = self
            .sealing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()?;
        Some(UnitSeal {
            facts,
            pass,
            key,
            origin: self.node.kernel.origin(OriginKind::Client),
            parent: None,
        })
    }
}

impl Units for Driven<'_> {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        self.units.arrival(token, ctx)
    }

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> SeatVerdict<Decode> {
        self.units.decode(token, ctx)
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate> {
        self.units.authenticate(token, ctx)
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        self.units.verify(token, trust, ctx, principal)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        self.units.approve(token, ctx, principal, destinations)
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        self.units
            .admit(token, admit, ctx, principal, destinations, leases)
    }

    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        self.units.route(token, ctx, destinations)
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        self.units
            .meter(token, usage, ctx, provisional, destinations)
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit> {
        self.units.audit(token, ctx, outcome)
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        self.units.audit_refused(token, ctx, refusal)
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        self.units.encode(token, ctx, outcome)
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        self.units.evidence(ctx)
    }

    fn audited(&self, _ctx: &UnitCtx, facts: busbar_contract::caps::AuditFacts, pass: Pass<Audit>) {
        *self
            .sealing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((facts, pass));
    }
}

impl RouteAwait for Driven<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        // THE DISPATCH, ON THE JOURNAL, before the leg leaves: what a recovery reads to tell a unit
        // that sent something from one that never did.
        self.node.dispatch_on_book(self.principal, self.arrived);
        // THROUGH THE ONE SEAM. The leg is the plane's own; the seam awaits it and gives back its
        // value, so the bytes, the status, the headers, the stream's frames and the tap on its body
        // are the plane's exactly — byte identity is a property of that construction, not of a
        // measurement. What the seam adds is the one fact no status can carry: that the engine ran
        // for this unit. A unit refused at Authenticate, Verify, Approve or Admit never reaches
        // Route, so it never reaches this line.
        self.node.dispatch.execute(
            self.op_class,
            self.route.route_leg(token, ctx, destinations),
        )
    }

    /// The plane's own screen before the door (SEAM-4j: a gate-first plane's hooks), forwarded:
    /// a wrapper that answered the default would let the gate run after admission.
    fn screen<'a>(&'a self, ctx: &'a UnitCtx) -> Screen<'a> {
        self.route.screen(ctx)
    }

    /// THE CALLER WENT AWAY MID-DISPATCH, and the end the loop reached for it is POSTED here (item
    /// 99). The loop's guard has already sealed this end at the charged audit door, emptied the cell
    /// and given the leases back; what it hands over is the posting, which has moved no balance and
    /// left no record until something settles it. Nothing else will: the future that would have read
    /// it is the one being dropped.
    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        let seal = self.take_seal(ctx.key);
        self.node
            .settle_end(self.principal, self.arrived, self.history, ended, seal);
    }
}

// ---------------------------------------------------------------------------------------------
// The borrowed unit
// ---------------------------------------------------------------------------------------------

/// A BORROWED UNIT, as the loop drives it ([`Node::drive_borrowed`]): every seat the unit's own,
/// and its audit door's facts and pass held on the posting site with the unit's other facts, so its
/// one record is sealed where its one line is written, whichever way it ends.
struct Borrowed<'b, U> {
    units: &'b U,
    post: &'b NodeEndPost,
}

impl<U: Units> Units for Borrowed<'_, U> {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        self.units.arrival(token, ctx)
    }

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> SeatVerdict<Decode> {
        self.units.decode(token, ctx)
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate> {
        self.units.authenticate(token, ctx)
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        self.units.verify(token, trust, ctx, principal)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        self.units.approve(token, ctx, principal, destinations)
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        self.units
            .admit(token, admit, ctx, principal, destinations, leases)
    }

    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        self.units.route(token, ctx, destinations)
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        self.units
            .meter(token, usage, ctx, provisional, destinations)
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit> {
        self.units.audit(token, ctx, outcome)
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        self.units.audit_refused(token, ctx, refusal)
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        self.units.encode(token, ctx, outcome)
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        self.units.evidence(ctx)
    }

    fn audited(&self, ctx: &UnitCtx, facts: busbar_contract::caps::AuditFacts, pass: Pass<Audit>) {
        self.post.audited(ctx.key, facts, pass);
    }

    fn at_parent_exit(
        &self,
        ctx: &UnitCtx,
        accrual: &busbar_contract::caps::HoldAccrual,
    ) -> Result<u64, Refusal> {
        self.units.at_parent_exit(ctx, accrual)
    }
}

impl<U: RouteAwait> RouteAwait for Borrowed<'_, U> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        self.units.route_leg(token, ctx, destinations)
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        self.units.abandoned(ctx, ended);
    }

    /// The borrowed units' own screen before the door, forwarded (SEAM-4j).
    fn screen<'a>(&'a self, ctx: &'a UnitCtx) -> Screen<'a> {
        self.units.screen(ctx)
    }
}

// ---------------------------------------------------------------------------------------------
// The driven plane's abandoned end
// ---------------------------------------------------------------------------------------------

/// Each open unit's facts, by key: its principal, its pinned arrival, its admitted card history,
/// and the audit facts and pass its audit door handed back, once it has.
type OpenUnits = HashMap<
    UnitKey,
    (
        PrincipalId,
        Arrived,
        Option<crate::root::kernel::PinnedHistory>,
        Option<(busbar_contract::caps::AuditFacts, Pass<Audit>)>,
    ),
>;

/// THE ROOT'S POSTING SITE for an abandoned end of a unit the kernel's plane driver runs
/// (`busbar_kernel::plane_driver::EndPost`): the caller went away, the loop's guard sealed the end,
/// and it is posted here onto the same book, balance and window a returned end settles on
/// ([`Node::settle_end`], the node's one posting site; no second seal). The root opens each unit's
/// facts at admission (its principal, its pinned arrival, the card history it was admitted under)
/// and closes them when the unit returns; an end posts at most once.
pub struct NodeEndPost {
    node: Arc<Node>,
    open: Mutex<OpenUnits>,
}

impl std::fmt::Debug for NodeEndPost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeEndPost").finish_non_exhaustive()
    }
}

impl NodeEndPost {
    /// The posting site over `node`.
    #[must_use]
    pub fn new(node: Arc<Node>) -> Self {
        NodeEndPost {
            node,
            open: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OpenUnits> {
        self.open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The node this site posts onto.
    #[must_use]
    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    /// Unit `key`'s facts, at its admission.
    pub fn open(
        &self,
        key: UnitKey,
        principal: PrincipalId,
        arrived: Arrived,
        history: Option<crate::root::kernel::PinnedHistory>,
    ) {
        self.lock().insert(key, (principal, arrived, history, None));
    }

    /// Unit `key`'s audit door handed back its facts and pass (`Units::audited`): they are held with
    /// the unit's facts so an abandoned end seals its one audit record where its line is written, as
    /// a returned end does. A unit that is not open keeps nothing.
    pub fn audited(
        &self,
        key: UnitKey,
        facts: busbar_contract::caps::AuditFacts,
        pass: Pass<Audit>,
    ) {
        if let Some(open) = self.lock().get_mut(&key) {
            open.3 = Some((facts, pass));
        }
    }

    /// Unit `key` returned: its facts close, and the audit facts and pass its audit door handed
    /// back come out for the record its one line seals ([`Node::drive_borrowed`]).
    pub fn take(&self, key: UnitKey) -> Option<(busbar_contract::caps::AuditFacts, Pass<Audit>)> {
        self.lock().remove(&key).and_then(|open| open.3)
    }

    /// Unit `key` returned: its end is the node's exit arm's to post, never this site's.
    pub fn close(&self, key: UnitKey) {
        self.lock().remove(&key);
    }

    /// How many units' facts are open (a witness: every unit closes).
    #[must_use]
    pub fn open_units(&self) -> usize {
        self.lock().len()
    }
}

/// THE EGRESS WALK'S WRITE-AHEAD RECORD, ON THE NODE'S BOOK (ARCHITECT P3 (c), 2026-10-02): a
/// dispatch of a driven unit is written onto the book under the facts the unit was opened with at
/// admission (its balance, window and arrival), before the dial, as a handed unit's is
/// ([`Node::answer`]). A unit with no open facts was never admitted onto the book, so its record is
/// refused and the walk sends nothing.
impl busbar_kernel_egress::ports::Journal for NodeEndPost {
    fn dispatched(
        &self,
        record: &busbar_kernel_egress::ports::Dispatched,
    ) -> Result<(), busbar_kernel_egress::ports::DurabilityUnavailable> {
        let facts = self
            .lock()
            .get(&record.unit)
            .map(|(principal, arrived, _, _)| (principal.clone(), *arrived));
        let (principal, arrived) =
            facts.ok_or(busbar_kernel_egress::ports::DurabilityUnavailable)?;
        // As the node's own dispatch record: a journal that will not take it retains and re-offers
        // it, and that is never a refusal of the dispatch.
        self.node.dispatch_on_book(&principal, arrived);
        Ok(())
    }

    /// An attempt that produced no answer: the book carries no separate mark for it. The unit's
    /// end settles what it consumed (the loop's one exit, or the abandoned end posted here), and a
    /// recovery reads the dispatch mark as "something left", which an abandoned attempt did.
    fn abandoned(&self, _record: &busbar_kernel_egress::ports::Dispatched) {}
}

/// THE RUNNING UNIT'S CHECKPOINT, ON THE NODE'S BOOK (THE DESIGN §7): the root's flush tick hands
/// each driven unit's accrual so far here ([`busbar_kernel::plane_driver::PlaneMoney::flush_checkpoints`]),
/// and it is journaled as a `unit.accrued` record under the facts the unit was opened with at
/// admission. A session's turns are the same call with its cumulative counts. A unit with no open
/// facts was never admitted onto the book: nothing is written.
impl busbar_kernel::plane_driver::Checkpointer for NodeEndPost {
    fn checkpoint(&self, key: UnitKey, accrued: &busbar_kernel::plane_driver::Accrued) {
        let facts = self
            .lock()
            .get(&key)
            .map(|(principal, arrived, _, _)| (principal.clone(), *arrived));
        let Some((principal, arrived)) = facts else {
            return;
        };
        let counts = crate::root::durability::UnitCounts {
            lane: accrued.lane.clone(),
            fee_count: accrued.fee_count,
            classes: accrued.classes.clone(),
        };
        self.node.checkpoint_on_book(&principal, arrived, &counts);
    }
}

impl busbar_kernel::plane_driver::EndPost for NodeEndPost {
    /// Post the abandoned end, once. Inside the loop's `Drop` guard: the book's settle is the
    /// node's in-memory posting behind one short lock, and nothing here awaits or crosses a plugin.
    fn post(&self, ctx: &UnitCtx, ended: Ended) {
        let facts = self.lock().remove(&ctx.key);
        if let Some((principal, arrived, history, sealing)) = facts {
            // The unit's one audit record is sealed with its one line, as a returned end's is.
            let seal = sealing.map(|(facts, pass)| UnitSeal {
                facts,
                pass,
                key: ctx.key,
                origin: self.node.kernel.origin(ctx.origin),
                parent: match ctx.origin {
                    OriginKind::Nested { parent } => Some(parent),
                    _ => None,
                },
            });
            self.node
                .settle_end(&principal, arrived, history.as_ref(), ended, seal);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The unit's fixed audit record
// ---------------------------------------------------------------------------------------------

/// A NESTED UNIT'S PARENT, live in the node's table ([`Node::parent`]): its key and its slot, whose
/// hold cell the child accrues against.
pub struct Parent {
    key: UnitKey,
    slot: Arc<busbar_kernel::inflight::UnitSlot>,
}

impl Parent {
    /// The parent's key.
    #[must_use]
    pub fn key(&self) -> UnitKey {
        self.key
    }

    /// The parent's hold cell.
    #[must_use]
    pub fn cell(&self) -> &busbar_contract::caps::HoldCell {
        self.slot.cell()
    }
}

impl std::fmt::Debug for Parent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parent").field("key", &self.key).finish()
    }
}

/// A UNIT'S RECORD-TO-BE: the facts its audit door sealed and the pass that door was lent, handed
/// back by the loop (`Units::audited`), carried to the unit's one line and sealed there — once, since
/// sealing consumes the pass. A unit whose audit door never answered has none, so it has no record.
struct UnitSeal {
    facts: busbar_contract::caps::AuditFacts,
    pass: Pass<Audit>,
    key: UnitKey,
    origin: busbar_contract::caps::Origin,
    /// The unit that caused this one (a nested unit's parent).
    parent: Option<UnitKey>,
}

impl UnitSeal {
    /// Seal the record beside the line just written: its outcome is how the unit ended, its amount
    /// is the line's counts (none for a refused unit), and the book stamps this boot's incarnation.
    #[allow(clippy::too_many_arguments)]
    fn seal(
        self,
        book: &Arc<Mutex<crate::root::durability::Durability>>,
        token: &Grant<busbar_contract::caps::DurableWrite>,
        principal: &PrincipalId,
        arrived: Arrived,
        rate_card_version: u64,
        outcome: Outcome,
        lines: Vec<RecordLine>,
        fee_count: u32,
    ) {
        let refused = matches!(outcome, Outcome::Refused(..));
        let inputs = AuditInputs {
            subject: Subject::PrincipalId(principal.as_str().to_string()),
            what: What {
                unit_key: self.key,
                incarnation: 0,
                op_class: RecordOpClass::new(self.facts.op_class.as_str()),
                destination: None,
                parent: self.parent,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: arrived.secs(),
            mono: arrived.mono(),
            origin: self.origin,
            outcome: OutcomeFacts {
                unit_end: outcome,
                step: outcome.step(),
                finish: audit_finish(self.facts.finish),
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: RecordUsage {
                lines: if refused { Vec::new() } else { lines },
                tier_bp: 10_000,
                fee_count: if refused { 0 } else { fee_count },
                rate_card_version,
                bucket_chain_ref: String::new(),
            },
            controls: Controls::default(),
            correlation_label: None,
        };
        let sealed = book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seal_unit(inputs, self.pass, token);
        if let Err(lost) = sealed {
            tracing::error!(
                step = lost.step().as_str(),
                unit = self.key.get(),
                "the journal lost a unit's audit record: it is sealed on the chain and cached, and \
                 a restart will not read it back"
            );
        }
    }
}

/// How the plane classed the finish, in the record's own words.
fn audit_finish(finish: busbar_contract::FinishClass) -> RecordFinish {
    match finish {
        busbar_contract::FinishClass::Complete => RecordFinish::Complete,
        busbar_contract::FinishClass::TurnComplete => RecordFinish::TurnComplete,
        busbar_contract::FinishClass::Partial => RecordFinish::Partial,
        busbar_contract::FinishClass::Error => RecordFinish::Error,
    }
}

/// The record's amount for a line the LATE ARM wrote: every class the unit reported, by the
/// registered name. A class nobody declared has no registered name — its line was refused — and is
/// not a line the record can name.
fn report_lines(report: &Report) -> Vec<RecordLine> {
    report
        .usage
        .usage_units
        .iter()
        .filter(|(_, count)| **count > 0)
        .filter_map(|(class, count)| {
            Some(RecordLine {
                class: Registration::meter_class(class)?,
                quantity: *count,
                source: busbar_contract::caps::QuantitySource::Count,
                estimated: false,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The exit arm
// ---------------------------------------------------------------------------------------------

/// The balance a unit's kernel posting moves: the caller's own, in nano-units, unscoped.
///
/// The caller rather than the pool, because the kernel's posting is the unit's — what the POOL spent
/// is the governance ledger's figure and is already moved there by the walk's tap. Two figures, two
/// books, neither a second spelling of the other.
fn balance(principal: &PrincipalId) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(principal.as_str()),
        CapDimension::NanoUnits,
        BucketScope::All,
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

/// Where a unit's posting lands: its balance, the window of its pinned arrival, stamped with the
/// card in force at that arrival.
fn settling_at<'a>(
    key: &'a TotalsKey,
    arrived: Arrived,
    card: Option<&crate::root::kernel::PinnedHistory>,
    token: &'a busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
) -> crate::root::durability::Settling<'a> {
    crate::root::durability::Settling {
        key,
        window: busbar_kernel::governance::budget_window(
            busbar_kernel::governance::WINDOW_DAY,
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
/// The same `card_at` the admin read resolves through (`busbar-core-admin/src/v1/service.rs`). TWO
/// COPIES OF ONE RULING ARE TWO CHANCES TO GET IT WRONG — this one is written to match rather than to
/// differ, and #43's end state is the one kernel-side implementation that retires both.
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
/// reached here. One of these exists, it is built on first use, and every handed unit walks through
/// it.
static NODE: LazyLock<Arc<Node>> = LazyLock::new(|| Arc::new(Node::new()));

/// The process's one node: the in-flight table and the book every unit it drives settles onto,
/// shared with the plane drivers' end posting ([`NodeEndPost`]).
#[must_use]
pub fn node() -> Arc<Node> {
    Arc::clone(&NODE)
}

/// THE PROCESS'S NODE, as the node axis hands it to a plane ([`ROOT_UNIT`]'s `drive`): one handed
/// unit, driven on the runtime the request arrived on. What goes back is the served response the
/// audited exit made, as a [`PlaneAnswer::Live`] (#28): its body may still be draining into the
/// late arm, so the outer handler serves it as it stands.
fn drive(
    handed: Handed,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlaneAnswer> + Send>> {
    Box::pin(async move { PlaneAnswer::Live(NODE.answer(handed).await) })
}

/// Bind the process's one node to the process's one book.
///
/// Called by the composition root at boot, with the same handle the administrative views were bound
/// to. Without it the exit arm settles nothing and the root's ledger stays empty — which reads as a
/// node that has posted nothing rather than as a node whose postings had nowhere to go.
///
/// The process's dated rate-card history is bound to the SAME book here (#79): every applied card
/// goes on its journal, so a restart rebuilds the history this node priced under. The admin
/// assembly binds it too, and the second binding is a no-op; binding it only there left a build
/// with this node and no admin surface pricing against a history no restart could rebuild.
pub fn bind_book(book: Arc<Mutex<crate::root::durability::Durability>>) {
    bind_node_book(&NODE, &crate::root::kernel::ROOT_CARD, book);
}

/// THE NODE'S ROOT UNIT, addressed through the composition root's generated table — the loop every
/// handed unit runs through, and the money book behind it:
///
/// * the node itself ([`drive`]) is handed to every entry on the linked table's `node` axis, whose
///   arrivals hand it their units;
/// * the card repricer is installed once the limits resolve and BEFORE the first app build, so the
///   boot's own rate resolution is the history's opening entry (see
///   [`crate::root::kernel::install_card_repricer`]);
/// * the node's book is opened for it, and its exit arm is bound to that book ([`bind_book`]) before
///   any listener binds — without it the arm settles nothing;
/// * a door plane's driven unit posts its abandoned end onto the node ([`NodeEndPost`]).
pub const ROOT_UNIT: crate::root::linked::RootUnit = crate::root::linked::RootUnit {
    seal: None,
    drive: Some(drive),
    on_config: Some(|_| crate::root::kernel::install_card_repricer()),
    opens_book: true,
    on_book: Some(|ctx| bind_book(Arc::clone(&ctx.book.durability))),
    end_post: Some(|| Arc::new(NodeEndPost::new(node()))),
};

/// [`bind_book`] for a named node and card holder: the holder's journal first, then the node's
/// exit arm, both on the one book.
fn bind_node_book(
    node: &Node,
    cards: &crate::root::kernel::RootHistory,
    book: Arc<Mutex<crate::root::durability::Durability>>,
) {
    cards.bind_journal(&book);
    node.bind_book(book);
}

// ---------------------------------------------------------------------------------------------
// THE SWITCH-OVER'S OWN PROOF
// ---------------------------------------------------------------------------------------------

/// THE SWITCH, DRIVEN BOTH WAYS on the same fixture and the same deployment shape.
///
/// The rehearsal beside the step files proves the nine steps COMPOSE. What it cannot prove is that
/// the composition root drives them the way the loop drives them, because it has no loop: it is a
/// driver written in a test file. This module drives the real one — `run_unit`, the kernel's ten
/// steps, its two audit doors and its one exit — through [`Node::answer`], against the shell's
/// entry point on its own deployment, and compares what a client and an operator can see.
///
/// Each fixture builds TWO deployments — own registry, own scripted upstream, own governance store —
/// so the two legs' counters are compared rather than summed.
#[cfg(all(test, linked_axis_node))]
#[path = "tests/plane_node.rs"]
mod tests;
