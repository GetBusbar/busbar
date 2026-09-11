// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INTEGRATION-TEST HARNESS SEAM — one place a cross-leg test drives a unit through the REAL
//! kernel loop and reads back what the run posted.
//!
//! ## Why this module exists at all
//!
//! A cross-leg gate has to compare the five legs' behaviour against ONE expected column. It cannot
//! do that from `tests/`, because of how Rust compiles the two kinds of test:
//!
//! * a leg's own `#[cfg(test)] mod tests` is compiled into the LIBRARY's unit-test binary, where
//!   `cfg(test)` is true;
//! * an integration test under `tests/` is its own crate, and links the library as an ordinary
//!   DEPENDENCY, where `cfg(test)` is FALSE.
//!
//! So every fixture in every leg's test module is absent from the artifact an integration test
//! links. This is not a visibility problem and no visibility change fixes it: `pub(crate)` is not
//! visible from `tests/` either, and `pub` cannot export an item that was never compiled. The only
//! way a cross-leg test reaches in-crate construction is an in-crate module compiled INTO the
//! dependency build, which is what this module is — hence the `test-harness` feature beside `test`
//! in its `cfg`.
//!
//! ## What is here, and what is blocked
//!
//! The leg-AGNOSTIC half is real and complete: [`RecordingLedger`] and [`run`] drive any `Units`
//! implementor through `busbar_kernel::teller::run_unit` and hand back the `Ended` the loop sealed
//! together with the rows the run posted. Nothing about it is per-leg, which is the point — a table
//! that asked each leg a differently-shaped question would not be comparing them.
//!
//! The per-leg CONSTRUCTORS are not here, and deliberately not faked. Building a leg's node means
//! assembling the ten-odd collaborators its own fixture already assembles (`VoiceNodeParts` alone
//! names plane, groups, pricer, auth, auth bindings, scope, meter policy, durability, io, origin),
//! and the two ways to get them are:
//!
//! 1. re-implement each leg's fixture here — which forks the fixture, so the harness would be
//!    proving the legs agree with a COPY of their setup rather than with their real one; or
//! 2. have each leg expose its existing fixture under the same `cfg` this module uses.
//!
//! (2) is the correct seam and it is one line per leg — re-gate the leg's `mod tests` (or the
//! fixture subset of it) from `#[cfg(test)]` to `#[cfg(any(test, feature = "test-harness"))]` and
//! make the node builder `pub`. Those files belong to other owners, so the change is offered as a
//! proposed diff rather than made here. Until it lands, [`run`] is usable by any caller that can
//! already build a unit, and the cross-leg table cannot be closed.

use busbar_caps::{Canary, Hold, HoldCell, OriginKind, PrincipalId, UnitKey};
use busbar_kernel::{
    record::UnitMemory,
    slice::{ConcurrencyGauge, LeaseCell},
    teller::{run_unit, AccrualMeter, Ended, Kernel, Run, UnitCtx, Units},
};
use std::sync::Mutex;

/// One posting the run made, as the harness observed it.
///
/// A row rather than a total: a gate that compared only totals cannot tell "one fee posted" from
/// "two postings that happen to sum to one", and the difference between those is exactly the kind
/// of divergence a cross-leg table exists to find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingRow {
    /// Which principal the posting was made against.
    pub principal: String,
    /// The amount posted, in the kernel's accrual class.
    pub amount: u64,
    /// How many request slots the unit drew.
    pub requests: u32,
    /// Whether the flat per-request fee posted.
    pub fee: u32,
}

/// The rows one run posted, in the order the loop posted them.
pub type RecordingRows = Vec<RecordingRow>;

/// A ledger that keeps what it was told instead of storing it.
///
/// The legs settle through their own durability, which is where a real posting goes; this stands
/// beside that as the harness's own record of what the LOOP decided, so a gate can assert on the
/// decision without reaching into any leg's storage. It is a `Mutex<Vec<_>>` and nothing more —
/// deliberately, because logic here would be logic the legs are then not being tested for.
#[derive(Debug, Default)]
pub struct RecordingLedger {
    rows: Mutex<RecordingRows>,
}

impl RecordingLedger {
    /// A ledger with nothing in it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one posting.
    pub fn post(&self, row: RecordingRow) {
        self.rows.lock().expect("recording ledger").push(row);
    }

    /// Every row posted so far, in order.
    #[must_use]
    pub fn rows(&self) -> RecordingRows {
        self.rows.lock().expect("recording ledger").clone()
    }
}

/// The stack a harnessed unit arrives on. Named, because the transport view answers with it and a
/// leg that read a different chain from its siblings would not be the same driver.
const HARNESS_TRANSPORT_KEY: &str = "harness";

/// The chain under it.
const HARNESS_TRANSPORT_CHAIN: [&str; 1] = ["harness"];

/// THE VIEWS A CELL'S UNIT IS RUN OVER, from the root's own constructor.
///
/// Public because [`open_record!`](crate::open_record) needs it, and named here rather than
/// assembled at each cell for the reason the macro exists: a cell that built its own bundle would
/// be driving a step over a context the node never hands it.
/// The identity value a cell's unit carries, from one place.
///
/// A client unit on the data listener, on the first generation, reaching no kernel verb — which is
/// what every cell that drives a step by hand was writing out field by field. Written once here so
/// a cell that needed a different unit has to say which field differs and why.
#[must_use]
pub fn cell_ctx(key: u64) -> UnitCtx {
    UnitCtx {
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

/// A unit's memory, as the cells take one.
#[must_use]
pub fn unit_memory<'u>() -> UnitMemory<'u> {
    UnitMemory::new()
}

/// Open the record over one lease of it.
#[must_use]
pub fn open<'u>(
    views: &crate::root::unit_views::UnitViews<'u>,
    ctx: &UnitCtx,
    arena: &'u dyn busbar_contract::bounded::Arena,
) -> crate::root::unit_views::UnitRecord<'u> {
    crate::root::unit_views::UnitRecord::open(ctx, views, arena)
}

#[must_use]
pub fn view_set() -> crate::root::unit_views::UnitViewSet {
    crate::root::unit_views::UnitViewSet::new(
        crate::root::unit_views::Block::default(),
        HARNESS_TRANSPORT_KEY,
        &HARNESS_TRANSPORT_CHAIN,
    )
}

/// Drive one unit through the REAL kernel loop and record what it settled.
///
/// The loop is `busbar_kernel::teller::run_unit` itself, not a re-implementation of it: the whole
/// value of a cross-leg table is that every leg was asked by the same driver, and a driver that
/// approximated the loop would be comparing the legs against the approximation.
///
/// `principal` is who the hold opens against; the returned `Ended` is what the loop sealed, and the
/// ledger carries the run's postings.
pub fn run<U: Units>(
    kernel: &Kernel,
    unit: &U,
    ctx: &UnitCtx,
    principal: &str,
    ledger: &RecordingLedger,
) -> Ended {
    let cell = HoldCell::new(Hold::open(
        &kernel.admit_token(),
        PrincipalId::new(principal),
        0,
    ));
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    // THE VIEWS, from the root's own constructor and not a second set beside it. A harness that
    // assembled its own would be driving the loop over a context the node never builds, which is
    // the one thing a cross-leg table must not do.
    let view_set = crate::root::unit_views::UnitViewSet::new(
        crate::root::unit_views::Block::default(),
        HARNESS_TRANSPORT_KEY,
        &HARNESS_TRANSPORT_CHAIN,
    );
    let views = view_set.views(view_set.clock(), None, None);

    let ended = run_unit(
        kernel,
        unit,
        ctx,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            views: &views,
        },
    );

    if let Ended::Settled { requests, fee, .. } = &ended {
        ledger.post(RecordingRow {
            principal: principal.to_string(),
            amount: meter.total(),
            requests: *requests,
            fee: *fee,
        });
    }
    ended
}

/// OPEN A UNIT'S RECORD IN THE CALLER'S OWN FRAME, the way the loop opens one.
///
/// THE one constructor a cell reaches for. Every step the loop calls is handed a
/// [`UnitRecord`](crate::root::unit_views::UnitRecord), built once at the loop's entry over the
/// unit's own memory and the root's own views — so a cell driving a step directly has to build the
/// same thing the same way, or it is measuring a step against a context the node never hands it.
///
/// A macro rather than a function because of what the record IS: the memory is owned by a frame
/// and the record borrows one lease of it, so the two cannot be returned together. The macro puts
/// both in the caller's frame, which is exactly where the loop puts them.
#[macro_export]
macro_rules! open_record {
    ($record:ident, $ctx:expr) => {
        $crate::open_record!($record, $ctx, $crate::root::harness::view_set());
    };
    ($record:ident, $ctx:expr, $view_set:expr) => {
        let view_set = $view_set;
        let views = view_set.views(view_set.clock(), None, None);
        let mut memory = $crate::root::harness::unit_memory();
        let arena = memory.lease();
        let $record = $crate::root::harness::open(&views, $ctx, &arena);
    };
}
