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
    Admit, Admittance, Approve, Arrival, Audit, Authenticate, Consumption, Decision, Decode, Dial,
    Encode, Grant, Meter, OpClassId, OriginKind, Outcome, Pass, PrincipalId, Refusal, Route,
    VerifiedDestination, Verify,
};
use busbar_contract::{LaneId, Registration, UnitKey};
use busbar_kernel::plane_host::PlaneAnswer;
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{AccrualMeter, Ended, Evidence, RouteAwait, RouteLeg, UnitCtx, Units};

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
    /// them through it again. Shared with the resolver every unit is lent ([`Node::resolver`]).
    lane_names: Arc<Mutex<LaneNames>>,
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
    /// [`bind_book`]: Node::bind_book
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
            lane_names: Arc::new(Mutex::new(LaneNames {
                interner: lanes,
                resolved: HashMap::new(),
                consulted: 0,
            })),
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

    /// The interner itself — the image's one vocabulary, as this node holds it.
    #[must_use]
    pub fn lanes(&self) -> Arc<Mutex<Registration>> {
        Arc::clone(&self.lanes)
    }

    /// THE RESOLVER THIS NODE LENDS A UNIT: a configured lane name to the interned lane, through the
    /// node's own table in front of the interner — so the image's one lock is reached once per
    /// distinct name for the life of the node, however many units ask.
    fn resolver(&self) -> Resolve {
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
            window: busbar_kernel_budget::budget_window(
                busbar_kernel_budget::window::WINDOW_DAY,
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
        let key = UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed));
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
        let (units, route, finish) = build((self.resolver(), Arc::clone(&meter), arrived.secs()));

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
                self.settle_end(&principal, arrived, history.as_ref(), ended);
                // The unit reached its own end and its posting is on the book: the slot goes
                // straight back. Anything that leaves this function before here leaves it MARKED.
                occupied.reached_end = true;
                // The loop ran; the answer is whatever the terminal posted. There is no unit that
                // reaches an end without passing one of the two audit doors, so the fallback below
                // is unreachable — and it is an answer rather than an unwrap, because a path that
                // cannot be taken still has to say something if it is.
                // THE AUDITED EXIT (#28): the plane's answer becomes the served response here, and
                // nowhere on the plane's side of the seam.
                let (answer, late) = finish();
                let response =
                    answer.map_or_else(|| unavailable(proto), PlaneAnswer::into_response);
                // THE LATE ARM. The settlement above carried what the terminal knew, and on a plane
                // whose money is in a cell the response's own body fills when it DRAINS, that is the
                // record a unit ran and ended and nothing else. So the body goes out wrapped, and
                // the figure lands when it arrives.
                self.attach_late_accrual(response, late, &principal, arrived, history)
            }
        }
    }

    /// Wrap the answer's body so the figure that arrives after the terminal has somewhere to land.
    ///
    /// Nothing here changes a byte of what the client is given: the frames, their order, the trailers
    /// and the size hint are the inner body's, forwarded. What the wrapper adds is a place to stand
    /// at the one instant the unit's money becomes a fact.
    ///
    /// Two ways this hands the response straight back, and each is a case where there is nothing to
    /// wait for. No book bound: the build carries no root ledger and there is nowhere for a posting
    /// to go. No late reading on the response: nothing was ever going to fill one, so a wrapper would
    /// only ever drop empty.
    fn attach_late_accrual(
        &self,
        response: Response,
        late: Option<Late>,
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
        let Some(late) = late else {
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
            late,
        };
        let (parts, body) = response.into_parts();
        Response::from_parts(parts, axum::body::Body::new(LateBody::new(body, arm)))
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
    pub usage: busbar_substrate_values::billing::Usage,
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
            late,
        } = self;
        let Some(report) = late().map(Report::of) else {
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
    report: &Report,
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
            let _row = book.post_counts(
                &at,
                principal,
                &counts,
                arrived.ms(),
                Some(format!("{refusal:?}")),
            );
            return;
        }
    };
    if amount == 0 {
        let _row = book.post_counts(&at, principal, &counts, arrived.ms(), None);
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
}

impl Units for Driven<'_> {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> Decision<Arrival> {
        self.units.arrival(token, ctx)
    }

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> Decision<Decode> {
        self.units.decode(token, ctx)
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> Decision<Authenticate> {
        self.units.authenticate(token, ctx)
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        self.units.verify(token, trust, ctx, principal)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
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
    ) -> Decision<Admit> {
        self.units
            .admit(token, admit, ctx, principal, destinations, leases)
    }

    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        meter: &AccrualMeter,
        destinations: &[VerifiedDestination],
    ) -> Decision<Route> {
        self.units.route(token, ctx, meter, destinations)
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> Decision<Meter> {
        self.units
            .meter(token, usage, ctx, provisional, destinations)
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit> {
        self.units.audit(token, ctx, outcome)
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        self.units.audit_refused(token, ctx, refusal)
    }

    fn encode(&self, token: &Pass<Encode>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Encode> {
        self.units.encode(token, ctx, outcome)
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        self.units.evidence(ctx)
    }
}

impl RouteAwait for Driven<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        meter: &'a AccrualMeter,
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
            self.route.route_leg(token, ctx, meter, destinations),
        )
    }

    /// THE CALLER WENT AWAY MID-DISPATCH, and the end the loop reached for it is POSTED here (item
    /// 99). The loop's guard has already sealed this end at the charged audit door, emptied the cell
    /// and given the leases back; what it hands over is the posting, which has moved no balance and
    /// left no record until something settles it. Nothing else will: the future that would have read
    /// it is the one being dropped.
    fn abandoned(&self, _ctx: &UnitCtx, ended: Ended) {
        self.node
            .settle_end(self.principal, self.arrived, self.history, ended);
    }
}

// ---------------------------------------------------------------------------------------------
// The exit arm
// ---------------------------------------------------------------------------------------------

/// The balance a unit's kernel posting moves: the caller's own, in nano-units, unscoped.
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

/// Where a unit's posting lands: its balance, the window of its pinned arrival, stamped with the
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
static NODE: LazyLock<Node> = LazyLock::new(Node::new);

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
///   any listener binds — without it the arm settles nothing.
pub const ROOT_UNIT: crate::root::linked::RootUnit = crate::root::linked::RootUnit {
    seal: None,
    drive: Some(drive),
    on_config: Some(|_| crate::root::kernel::install_card_repricer()),
    opens_book: true,
    on_book: Some(|ctx| bind_book(Arc::clone(&ctx.book.durability))),
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
#[cfg(test)]
#[path = "tests/plane_node.rs"]
mod tests;
