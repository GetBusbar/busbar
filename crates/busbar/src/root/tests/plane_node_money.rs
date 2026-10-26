// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S OWN CELLS, PROVEN WITH NO PLANE LINKED (Law 10, `BUSBAR-1.6.0.md` l.2110), built in
//! EVERY test build: the arrival reading, the lane-name interner, the card provenance stamp, the
//! sweep and its drop guard, the card binding, and the one audit record every unit seals. The
//! node carries no money: a unit's counts are the governance ledger's (MONEY-DESIGN §3).
//!
//! Two shapes. A cell that already named no plane is ported VERBATIM from `tests/plane_node.rs`. A
//! cell that reached the node through the plane's handed unit is ported onto the DOOR PATH: a unit
//! of the test's own, driven through [`Node::drive_borrowed`] exactly as `root::serve` drives a door
//! unit, onto a bound journal.

use super::*;

use std::sync::atomic::AtomicBool;

use busbar_contract::caps::{
    Admission, ArrivalRecord, Authenticated, Frame, ReasonCode, RoutePlan, ScopeFacts,
};

/// A configured lane name the interner cells resolve.
const LANE: &str = "m0";

/// **One arrival is one reading, and both figures come out of it.**
///
/// The pure half of the straddle. A unit arriving at the last millisecond of a window has its
/// seconds in that window and its milliseconds one tick short of the next: read the clock twice
/// there and the second read is already over the line, so the table stamps the unit in one
/// window and the books bill it in another. Read once and the two figures are two spellings of
/// one instant, which is the property asserted here.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::one_arrival_reading_spells_both_the_figures_the_loop_asks_for`, verbatim: it names no plane.
#[test]
fn one_arrival_reading_spells_both_the_figures_the_loop_asks_for() {
    const LAST_MILLISECOND: u64 = 1_700_000_000_999;
    let arrived = Arrived::at(LAST_MILLISECOND, 0);
    assert_eq!(arrived.ms(), LAST_MILLISECOND, "the reading, unmodified");
    assert_eq!(
        arrived.secs(),
        1_700_000_000,
        "and the window it lands in, which is the second that has not ended yet"
    );
    assert_eq!(
        arrived.ms() / 1_000,
        arrived.secs(),
        "the two figures are one instant: neither can be on the far side of a boundary the \
         other is on the near side of"
    );
}

/// The unit-arrival epoch this proof pins, so the window a posting lands in is a fixed one.
const EPOCH: u64 = 1_700_000_000;

/// THE INTERNER IS THE NODE'S, and it is idempotent.
///
/// A lane name is leaked to become the borrowed static one the priced axis is written in, so
/// interning the same name twice must yield the same pointer: a leak per request would be a
/// leak per request whatever it was called.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_nodes_interner_leaks_a_lane_name_once`, verbatim: it names no plane.
#[test]
fn the_nodes_interner_leaks_a_lane_name_once() {
    let node = Node::new();
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
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_lane_name_reaches_the_interner_once_however_often_it_is_resolved`, verbatim: it names no plane.
#[test]
fn a_lane_name_reaches_the_interner_once_however_often_it_is_resolved() {
    let node = Node::new();
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

/// THE PROVENANCE STAMP NAMES THE CARD IN FORCE WHEN THE UNIT ARRIVED (#79), not the newest card
/// ever published and not a literal.
///
/// This stamp used to be a hardcoded `0`, and `0` is not a neutral placeholder: it is
/// `HistorySeq::OPENING`, a REAL entry number. So every posting this plane made claimed the opening
/// card had priced it — and the node (`plane_node`) is the root unit module that is live on the
/// serving path, so this was a confident wrong answer on shipped traffic, which is worse than none.
///
/// THE CANARY IS THE POINT. Three dated entries over one history and three arrivals, one in each
/// window. Two of the three expected values are NON-ZERO, so the pre-fix code — which answered `0`
/// for every unit — fails this test on those two. A test whose expectations were all `0` would have
/// passed against the bug it was written for.
///
/// It also pins the MILLISECOND binding: `effective_from` is written on the millisecond scale
/// (`root/kernel.rs:435`), so a resolution handed the seconds reading matches only the from-zero
/// opening entry and reports it forever. The `_at_seconds` assertion below is that hazard made
/// visible — it is the bug wearing a different hat, and it would pass a "reads a history" review.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived`, verbatim: it names no plane.
#[test]
fn the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived() {
    // Dated on the MILLISECOND scale the history is written on. The first is effective from instant
    // zero however it is dated — one entry has to cover every instant, or an early arrival falls in
    // a hole and is reported as OPENING for a different reason.
    const SECOND_CARD_MS: u64 = 1_700_000_500_000;
    const THIRD_CARD_MS: u64 = 1_700_000_900_000;

    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(11),
        SECOND_CARD_MS,
    );
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(29),
        THIRD_CARD_MS,
    );
    let pinned = holder.pin().expect("three applies put entries in place");
    assert_eq!(
        pinned.seq().get(),
        2,
        "the snapshot's head is the third entry — the figure a stamp must NOT be for a unit that \
         arrived before it, and the one a `read the head` implementation would answer every time"
    );

    let stamped_ms = |ms: u64| card_in_force(Some(&pinned), ms);

    assert_eq!(
        stamped_ms(1_700_000_100_000),
        0,
        "a unit that arrived before the second card was published is priced by the opening entry"
    );
    assert_eq!(
        stamped_ms(1_700_000_600_000),
        1,
        "a unit that arrived in the second card's window names the SECOND entry — not the third, \
         which had not been published when it arrived (#79: publishing never reprices backwards)"
    );
    assert_eq!(
        stamped_ms(1_700_001_000_000),
        2,
        "a unit that arrived after the third card names the third entry"
    );

    // NO HISTORY PINNED — a build with no root ledger. The opening entry is the only one that
    // covers every instant by construction, so it is the honest fallback rather than a silent hole.
    assert_eq!(
        card_in_force(None, 1_700_000_600_000),
        0,
        "no pinned history falls back to the opening entry"
    );

    // THE SECONDS/MILLISECONDS HAZARD, made visible. Handed the SECONDS reading of the same instant
    // that resolves to entry 1 above, every arrival collapses onto the opening entry — the original
    // bug with a lookup in front of it. `Arrived::ms()` is what the settle path passes, and this is
    // why.
    assert_eq!(
        stamped_ms(1_700_000_600),
        0,
        "a seconds-valued instant matches only the from-zero opening entry — which is why the \
         settle path resolves at `Arrived::ms()` and never at `Arrived::secs()`"
    );
}

// ---------------------------------------------------------------------------------------------
// THE SWEEP: a unit whose task went away seals its one audit record
// ---------------------------------------------------------------------------------------------

/// A fresh node over a memory-buffered book, and that book.
fn swept_node() -> (
    Node,
    Arc<std::sync::Mutex<crate::root::durability::Durability>>,
) {
    let node = Node::new();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ));
    node.bind_book(Arc::clone(&book));
    (node, book)
}

/// Enter unit `key` into `node`'s table with its arrival hold, then drop its guard unfinished: a
/// unit whose task went away under operation class `op_class`.
fn lose_a_unit(node: &Node, key: UnitKey, op_class: &'static str) {
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(
                &node.kernel,
                &node.door,
                PrincipalId::new("acct:swept"),
                node.kernel.next_call(),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node,
        slot,
        arrived: Arrived::at(EPOCH * 1_000, key.get()),
        op_class: busbar_contract::caps::OpClassId::new(op_class),
        reached_end: false,
    });
}

/// Q128 p29#5: A SWEPT UNIT SEALS EXACTLY ONE AUDIT RECORD, AND ITS AMOUNT IS ITS LEDGER LINE.
///
/// THE DESIGN §1 (`BUSBAR-1.6.0.md` l.190-197): "The audit step writes one fixed record, for every
/// plane ... never optional"; §7 U14 (l.1061-1065): one audit record per unit, sealed at its one
/// line. A unit whose task disappeared is ended by the node's sweep, never by its own exit, so the
/// record is the sweep's to seal: outcome `Failed(at, TaskLost)`, finish `Error`, the operation class
/// the unit's guard recorded, the hold its admission opened, and the posted line by its registered
/// class. The swept unit's evidence went with its task, so its line is the estimated zero under the
/// kernel's own class: a money figure no registration declares and a record may not hold (§1
/// l.193-195, #43, #77(3)), so the record names no line and its amount, zero, is the zero the line
/// moved. And the record reads back, as every record on the journal must at the next boot.
///
/// RED before the fix: the sweep posted the unit's line with `None::<Sealing>` ("A unit the sweep
/// ends never handed back its audit pass: it has no record"), so the book had a posting and the
/// chain no record.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_swept_unit_seals_exactly_one_audit_record_whose_amount_is_its_ledger_line`, verbatim: it names no plane.
#[test]
fn a_swept_unit_seals_exactly_one_audit_record_whose_amount_is_its_ledger_line() {
    let (node, book) = swept_node();
    let key = UnitKey::new(51);
    lose_a_unit(&node, key, "widget_call");
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let records: Vec<_> = durability
        .audit_records
        .iter()
        .filter(|r| r.what.unit_key == key)
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one record for the one swept unit: {:?}",
        durability.audit_records
    );
    let record = records[0];
    assert_eq!(
        record.outcome.unit_end,
        Outcome::Failed(
            busbar_contract::caps::StepName::Route,
            busbar_contract::caps::ReasonCode::TaskLost
        )
    );
    assert_eq!(record.outcome.finish, RecordFinish::Error);
    assert_eq!(record.what.op_class.as_str(), "widget_call");
    // No hold or settlement is journalled, so the record names neither.
    assert_eq!(record.controls.hold_ref, None);
    assert_eq!(record.controls.settle_ref, None);
    // The amount: the line the sweep posted was the estimated zero under the kernel's own class,
    // which the record does not name.
    assert!(
        record.usage.lines.is_empty(),
        "a record names no money-class line: {:?}",
        record.usage.lines
    );
    assert!(durability.retained_audit_findings().is_empty());
    // It reads back off the journal, as the next boot reads it.
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    let read_back: Vec<_> = replayed
        .iter()
        .filter_map(|r| crate::root::durability::decode_audit(r).expect("every record decodes"))
        .filter(|r| r.what.unit_key == key)
        .collect();
    assert_eq!(
        read_back.len(),
        1,
        "the swept unit's record is on the journal"
    );
}

/// Q128 p29#5: NO UNIT SETTLES WITH ZERO AUDIT RECORDS. Every unit the sweep settles has its one
/// record on the chain, one each. (No posting rides beside it: the one ledger is the store's usage
/// counts, MONEY-DESIGN §4.)
///
/// RED before the fix: the swept units posted their lines and sealed nothing.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::no_swept_unit_settles_with_zero_audit_records`, verbatim: it names no plane.
#[test]
fn no_swept_unit_settles_with_zero_audit_records() {
    let (node, book) = swept_node();
    let keys = [UnitKey::new(61), UnitKey::new(62), UnitKey::new(63)];
    for key in keys {
        lose_a_unit(&node, key, "widget_call");
    }
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), keys.len());

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(
        replayed
            .iter()
            .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
            .count(),
        keys.len(),
        "each swept unit has its one record on the journal, and no posting"
    );
    for key in keys {
        assert_eq!(
            durability
                .audit_records
                .iter()
                .filter(|r| r.what.unit_key == key)
                .count(),
            1,
            "unit {key:?} settled and must have exactly one record: {:?}",
            durability.audit_records
        );
    }
    assert_eq!(durability.audit_records.len(), keys.len());
}

/// The open class a rerank's search units are ledgered under (the rerank dialect codec's
/// `SEARCH_UNITS_CLASS`, which `record_resp_usage` ledgers verbatim — item 134). Spelled here because
/// this crate does not depend on the codec.
const SEARCH_UNITS: &str = "search_units";

/// The serving lane of the served-rerank fixture: a Cohere lane, the one dialect whose rerank reader
/// reads `meta.billed_units.search_units`.
const RERANK_LANE: &str = "rerank-v3.5";

/// The search units the scripted Cohere upstream bills.
const RERANK_UNITS: u64 = 50;

/// THE RECORD'S AMOUNT IS COUNTS AND A CARD VERSION, NEVER A PRICE (`BUSBAR-1.6.0.md` THE DESIGN
/// §1, "The amount is the unit's counts plus the rate-card version, never a price"; §7).
///
/// A unit whose exit settles a non-zero figure (the settlement writer's money, in nano-units) seals
/// its record beside that line. The record names what the unit reported, by class; the exit's
/// posting carries no class and no count, only the figure it moved, so the record it seals has no
/// line of it at all.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_exit_arm_seals_no_money_figure_into_the_record`, verbatim: it names no plane.
#[test]
fn the_exit_arm_seals_no_money_figure_into_the_record() {
    use busbar_contract::caps::{Admittance, Hold, Posted, Usage, WriteMoney};
    use busbar_kernel::test_support::tokens::{end, grant, origin, pass};

    let node = Node::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));

    // The count the settlement writer carried: 150.
    const MONEY: u64 = 150;
    let who = PrincipalId::new("acct:h2");
    let hold = Hold::open(&grant::<Admittance>(), who.clone());
    let usage = Usage::report(&grant::<busbar_contract::caps::Consumption>(), Vec::new())
        .expect("an empty report fits the record");
    let posted = Posted::settle(hold, MONEY, &usage, &grant::<WriteMoney>());
    assert_eq!(posted.quantity(), MONEY, "the posting carries the count");
    let ended = Ended::Settled {
        end: end(Outcome::Completed, Ok(posted)),
        requests: 0,
        fee: 0,
    };
    let seal = UnitSeal {
        facts: busbar_contract::caps::AuditFacts {
            op_class: busbar_contract::caps::OpClassId::new("call"),
            finish: busbar_contract::FinishClass::Complete,
        },
        pass: pass(),
        key: UnitKey::new(77),
        origin: origin(OriginKind::Client),
        parent: None,
    };
    node.seal_end(
        &who,
        Arrived::at(EPOCH * 1_000, 0),
        None,
        ended,
        Some(seal),
        Vec::new(),
    );

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let record = durability
        .audit_records
        .last()
        .expect("the exit arm sealed the unit's record");
    assert!(
        record.usage.lines.iter().all(|line| line.class
            != busbar_kernel::teller::KERNEL_ACCRUAL_CLASS
            && line.quantity != MONEY),
        "the record carries counts, never the settled money figure: {:?}",
        record.usage.lines
    );
}

// ---------------------------------------------------------------------------------------------
// THE DOOR PATH: a unit driven through `Node::drive_borrowed`, as `root::serve` drives a door unit
// ---------------------------------------------------------------------------------------------

/// Whose unit every door cell below drives.
const PRINCIPAL: &str = "acct:door";

/// The one destination Verify seals for a door unit.
const DESTINATION: &str = "door-dest";

/// A DOOR UNIT OF THE TEST'S OWN: every seat proceeds (its door at a zero hold, as a door plane's
/// is), its Route leg answers at once, and its record is sealed under [`DoorUnit::op_class`]. It
/// can be told to refuse at Decode or to screen itself out before the door, and it notes whether
/// its first seat and its admission seat were ever reached.
struct DoorUnit {
    /// Refuse at Decode with this reason: a request the unit cannot read.
    decode_refusal: Option<ReasonCode>,
    /// Screen the unit out before the door with this reason (SEAM-4j).
    screen: Option<ReasonCode>,
    /// The Arrival seat ran.
    reached_arrival: AtomicBool,
    /// The Admit seat (the door) ran.
    reached_admit: AtomicBool,
}

impl DoorUnit {
    fn served() -> Self {
        DoorUnit {
            decode_refusal: None,
            screen: None,
            reached_arrival: AtomicBool::new(false),
            reached_admit: AtomicBool::new(false),
        }
    }

    fn refused_at_decode() -> Self {
        DoorUnit {
            decode_refusal: Some(ReasonCode::DecodeFailed),
            ..DoorUnit::served()
        }
    }

    fn screened_by(reason: ReasonCode) -> Self {
        DoorUnit {
            screen: Some(reason),
            ..DoorUnit::served()
        }
    }

    fn op_class() -> OpClassId {
        OpClassId::new("call")
    }
}

impl Units for DoorUnit {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        self.reached_arrival.store(true, Ordering::SeqCst);
        SeatVerdict::proceed(
            token,
            ArrivalRecord {
                source: String::new(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: Vec::new(),
            },
        )
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> SeatVerdict<Decode> {
        match self.decode_refusal {
            Some(reason) => SeatVerdict::refuse(token, Refusal::new(reason)),
            None => SeatVerdict::proceed(token, Self::op_class()),
        }
    }

    fn authenticate(
        &self,
        token: &Pass<Authenticate>,
        _ctx: &UnitCtx,
    ) -> SeatVerdict<Authenticate> {
        SeatVerdict::proceed(token, Authenticated::Principal(PrincipalId::new(PRINCIPAL)))
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        SeatVerdict::proceed(
            token,
            vec![VerifiedDestination::seal(trust, LaneId::new(DESTINATION))],
        )
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        SeatVerdict::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        _admit: &Grant<Admittance>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        self.reached_admit.store(true, Ordering::SeqCst);
        // The arrival hold is the hold the exit settles: a door plane's door opens at zero.
        SeatVerdict::proceed(token, Admission::ZeroHold)
    }

    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        // Reached through the awaited leg below, never here.
        SeatVerdict::refuse(token, Refusal::new(ReasonCode::TaskLost))
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::Usage::report(usage, Vec::new())
                .expect("an empty usage report never overflows"),
        )
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::AuditFacts {
                op_class: Self::op_class(),
                finish: busbar_contract::FinishClass::Complete,
            },
        )
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::AuditFacts {
                op_class: Self::op_class(),
                finish: busbar_contract::FinishClass::Error,
            },
        )
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        SeatVerdict::proceed(
            token,
            Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

impl RouteAwait for DoorUnit {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        Box::pin(async move { SeatVerdict::proceed(token, RoutePlan::default()) })
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}

    fn screen<'a>(&'a self, _ctx: &'a UnitCtx) -> Screen<'a> {
        let screen = self.screen;
        Box::pin(async move {
            match screen {
                Some(reason) => Err(Refusal::new(reason)),
                None => Ok(()),
            }
        })
    }
}

/// A node bound to `book`, and the door's posting site over it (`root::serve` holds one per
/// process: `NodeEndPost::new(node())`).
fn door_node(book: &crate::root::durability::NodeBook) -> (Arc<Node>, NodeEndPost) {
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    (node, post)
}

/// ONE DOOR UNIT, through the node's borrowed drive, as `root::serve` drives it: a key from the
/// node's mint, the arrival it charged in, its late reading, the card history pinned at its door.
async fn drive_door(
    node: &Node,
    post: &NodeEndPost,
    unit: &DoorUnit,
    arrived: Arrived,
    late: Late,
    history: Option<crate::root::kernel::PinnedHistory>,
) -> (UnitKey, Option<Outcome>) {
    let key = node.mint();
    let outcome = node
        .drive_borrowed(
            key,
            arrived,
            &PrincipalId::new(PRINCIPAL),
            post,
            unit,
            late,
            history,
            None,
            DoorUnit::op_class(),
        )
        .await;
    (key, outcome)
}

/// A late reading that never arrives (a door unit whose money never opened).
fn no_late() -> Late {
    Box::new(|| None)
}

/// The door's late reading of `report`, as `root::serve`'s `report_of` hands it to the node.
fn late_of(report: Report) -> Late {
    Box::new(move || Some((report.usage, report.fee_count, report.lane)))
}

/// One door unit's END, as the loop seals it: the unit run through the kernel loop over the
/// borrowed drive's own wrapper ([`Borrowed`]) in `node`'s table, the end handed back unposted.
/// What `plane_node.rs`'s `drive_to_end` did over the handed unit's wrapper, on the door's.
async fn drive_to_end(node: &Node, post: &NodeEndPost) -> Ended {
    let unit = DoorUnit::served();
    let key = node.mint();
    let call = node.kernel.next_call();
    let meter = Arc::new(AccrualMeter::new());
    let hold = busbar_kernel::inflight::arrival_hold(
        &node.kernel,
        &node.door,
        PrincipalId::new(PRINCIPAL),
        call,
    );
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    let ctx = UnitCtx {
        call,
        key,
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let borrowed = Borrowed { units: &unit, post };
    let ended = busbar_kernel::teller::run_unit_async(
        &node.kernel,
        &borrowed,
        &ctx,
        busbar_kernel::teller::Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &node.gauge,
            canary: &node.canary,
            meter: &meter,
        },
        &borrowed,
    )
    .await;
    node.inflight.remove(key);
    ended
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_driven_planes_abandoned_end_seals_one_audit_record`.
// Each end is the loop's own, sealed over the borrowed drive's wrapper rather than the handed
// unit's; the posting site and every assertion are the original's.
/// A DRIVEN PLANE'S ABANDONED END SEALS EXACTLY ONE AUDIT RECORD with its one line, from the facts
/// and pass its audit door handed back; an abandoned unit whose audit door never answered seals none.
/// RED: without the held pass the posting site seals no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_driven_planes_abandoned_end_seals_one_audit_record() {
    use busbar_kernel::plane_driver::EndPost;
    let node = Arc::new(Node::new());
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));
    let records = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .audit_records
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let ctx = |key: u64| UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let who = PrincipalId::new("acct:node");
    let facts = busbar_contract::caps::AuditFacts {
        op_class: busbar_contract::caps::OpClassId::new("call"),
        finish: busbar_contract::FinishClass::Complete,
    };
    // The audit door answered: one record, with the line.
    let ended = drive_to_end(&node, &site).await;
    site.open(
        UnitKey::new(51),
        who.clone(),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );
    site.audited(
        UnitKey::new(51),
        facts,
        busbar_kernel::test_support::tokens::pass(),
    );
    let before = records();
    site.post(&ctx(51), ended);
    assert_eq!(
        records(),
        before + 1,
        "exactly one audit record for the abandoned unit"
    );
    // The audit door never answered: the line is posted, and no record is minted for it.
    let ended = drive_to_end(&node, &site).await;
    site.open(UnitKey::new(52), who, Arrived::at(EPOCH * 1_000, 1), None);
    let before = records();
    site.post(&ctx(52), ended);
    assert_eq!(records(), before, "no pass, no record");
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::every_unit_the_node_answers_served_or_refused_seals_one_record_on_one_tamper_evident_chain`,
// onto the door path: the served unit and the refused one (a request its Decode cannot read, the
// original's unreadable body) are driven through the borrowed drive; the chain assertions are the
// original's.
/// AUDIT-CHAIN, THE NODE'S DOOR UNITS: every unit the node drives, served (a dispatched completion)
/// or refused (a request it cannot read), seals ONE record on the node's audit chain, the second
/// linked to the first; the chain walks clean, and a record altered after its seal (the served unit
/// re-told as refused) breaks the walk. RED: a loop whose audit door's pass is never handed back to
/// the node seals nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_unit_the_node_answers_served_or_refused_seals_one_record_on_one_tamper_evident_chain(
) {
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);

    let (_, served) = drive_door(
        &node,
        &post,
        &DoorUnit::served(),
        node.arrived(),
        no_late(),
        None,
    )
    .await;
    assert!(
        served.is_some_and(Outcome::is_completed),
        "the completion is served: {served:?}"
    );
    let (_, refused) = drive_door(
        &node,
        &post,
        &DoorUnit::refused_at_decode(),
        node.arrived(),
        no_late(),
        None,
    )
    .await;
    assert!(
        matches!(refused, Some(Outcome::Refused(..))),
        "the unreadable request is refused: {refused:?}"
    );
    assert_eq!(post.open_units(), 0, "both units' facts closed");

    let durability = book.durability.lock().expect("unpoisoned");
    let records = durability.audit_records.clone();
    assert_eq!(records.len(), 2, "one record per unit: {records:?}");
    let (served, refused) = (&records[0], &records[1]);
    assert_eq!(
        served.outcome.unit_end,
        busbar_contract::caps::Outcome::Completed,
        "the dispatch is chained as served"
    );
    assert!(
        matches!(
            refused.outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(..)
        ),
        "the refusal is chained as one: {:?}",
        refused.outcome
    );
    assert_eq!(refused.seq, served.seq + 1, "contiguous");
    assert_eq!(
        refused.prev_hash, served.hash,
        "linked to the record before"
    );
    assert!(busbar_kernel_audit::AuditChain::verify_window(&records).is_ok());
    assert!(
        durability.retained_audit_findings().is_empty(),
        "the node's own verify finds nothing"
    );

    let mut forged = records.clone();
    forged[0].outcome.unit_end = refused.outcome.unit_end;
    assert!(
        busbar_kernel_audit::AuditChain::verify_window(&forged).is_err(),
        "a record altered after its seal breaks the chain"
    );
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_screened_veto_through_the_node_admits_nothing`,
// onto the door path: the unit screens itself out through the borrowed drive's wrapper. The
// original read "nothing admitted" off the plane's governance ledger; here it is read off the door
// seat itself, which the loop never reaches.
/// RED (SEAM-4j through the node): a unit whose route SCREENS it before the door (a gate-first
/// plane's veto) is screened through the node's own wrapper: the unit is refused at Approve's seat
/// with the screen's reason and the door never admits it. RED before: the node's wrapper answered
/// the default screen, the unit was admitted and served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_screened_veto_through_the_node_admits_nothing() {
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);
    let unit = DoorUnit::screened_by(busbar_contract::caps::ReasonCode::HookVeto);
    let (_, outcome) = drive_door(&node, &post, &unit, node.arrived(), no_late(), None).await;
    assert_eq!(
        outcome,
        Some(Outcome::Refused(
            busbar_contract::caps::StepName::Approve,
            busbar_contract::caps::ReasonCode::HookVeto
        )),
        "refused at the screen, before the door"
    );
    assert!(
        !unit.reached_admit.load(Ordering::SeqCst),
        "a veto admits nothing: the door was never asked"
    );
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_full_journal_lane_refuses_a_new_unit_503_with_the_reason`,
// onto the door path. The book, the full lane and every assertion on the node are the original's;
// the 503 the handed path renders is that path's own answer, and the door's answer is the door's.
/// **A NODE WHOSE JOURNAL CANNOT REACH ITS STORE FAILS CLOSED** (ARCHITECT 2026-10-07 H3 ruling):
/// the book's journal is kept by the configured store, the store refuses and the lane to it is
/// full, so a new money-bearing unit is refused with the reason, before any step of it runs or
/// anything is held or journalled for it, and nothing the journal holds is dropped. A state 1.5.5
/// never reached (it kept no journal).
///
/// RED before the fix: the node admitted the unit and drove it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_journal_lane_refuses_a_new_unit_with_the_reason() {
    let slots = crate::root::store_double::RecordSlots::new();
    slots.refuse(true);
    let lane = crate::root::durability::JournalLane::with_capacity(slots.calls(), "test-store", 1)
        .expect("the lane starts");
    let book = Arc::new(std::sync::Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            0,
            lane,
            None,
        )
        .expect("the store reads back"),
    ));
    let token = busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>();
    for _ in 0..3 {
        let _lost = book.lock().unwrap().journal.append(
            &token,
            busbar_contract::caps::StepName::Meter,
            &[busbar_kernel_wal::Entry::new(
                busbar_kernel_wal::RecordClass::Load,
                Vec::new(),
            )],
        );
    }
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    let post = NodeEndPost::new(Arc::clone(&node));
    let unit = DoorUnit::served();
    let (_, outcome) = drive_door(&node, &post, &unit, node.arrived(), no_late(), None).await;
    assert!(
        outcome.is_none(),
        "the node refuses the unit: the table never takes it"
    );
    assert!(
        !unit.reached_arrival.load(Ordering::SeqCst),
        "a refused unit is never driven"
    );
    assert_eq!(post.open_units(), 0, "nothing is held open for it");
    let why = node
        .journal_refusal()
        .expect("the node states why it refuses");
    assert!(
        why.contains("journal is full") && why.contains("`test-store`"),
        "the reason names the full journal and the store: {why}"
    );
    assert_eq!(
        book.lock().unwrap().journal.dropped_total(),
        0,
        "no record is dropped"
    );
}

/// **NO PROCESS-WIDE LOCK STANDS IN FRONT OF A UNIT'S MONEY** (MONEY-DESIGN §4, PR-C; owner ruling:
/// no process-wide lock around fsync). Eight units end CONCURRENTLY while another thread holds the
/// node's book — the one `Mutex<Durability>` every audit seal and every journal read takes — and
/// every one of them lands its counts on the one ledger before that lock is let go. The money is
/// the governance counts, behind per-key shard locks; nothing about it waits on the book.
///
/// RED on the base: an exit arm's money was also a posting on the node's second book
/// (`SharedBook::settle_*`, its `sync_data` under this same mutex), so a unit's settlement could not
/// complete while the book was held, and N settlements took turns behind it.
#[test]
fn concurrent_unit_ends_land_their_money_while_the_book_is_held() {
    use busbar_contract::abi::plane::{UnitCount, UNITS_REPORTED};
    use busbar_kernel::plane_driver::{FeeRefund, MoneySeam, PlaneMoney, UnitMoney};
    const UNITS: u64 = 8;
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(
            Arc::new(busbar_kernel::governance::MemoryStore::new()),
            None,
        )
        .expect("governance builds"),
    );
    let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(post)));
    let rates = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            ..Default::default()
        },
    )]);
    let cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
        Some(&rates),
        0,
        &std::collections::BTreeMap::new(),
    ));
    let key = Arc::new(busbar_kernel::governance::VirtualKey {
        id: "vk_unlocked".to_string(),
        generation_hash: "h:vk_unlocked".to_string(),
        name: "unlocked".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    });

    // The book, held for the whole of the units' run.
    let held = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let threads: Vec<_> = (1..=UNITS)
        .map(|n| {
            let (money, cost, key, done) = (
                Arc::clone(&money),
                Arc::clone(&cost),
                Arc::clone(&key),
                done_tx.clone(),
            );
            std::thread::spawn(move || {
                let unit = UnitKey::new(n);
                money.open(
                    unit,
                    UnitMoney {
                        key,
                        cost,
                        pool: String::new(),
                        lane: "m".into(),
                        classes: Arc::from(vec!["input".to_string()]),
                        arrived: EPOCH,
                        mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                        fee: FeeRefund::CallerStatus,
                        charge: Default::default(),
                    },
                );
                let ctx = UnitCtx {
                    call: busbar_contract::caps::CallId::UNBOUND,
                    key: unit,
                    origin: OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: false,
                    kernel_verb_only: false,
                };
                let _ = money.checkpoint(
                    &ctx,
                    &[UnitCount {
                        class: 0,
                        source: UNITS_REPORTED,
                        amount: 100,
                    }],
                );
                money.settle_end(unit, 200);
                done.send(n).expect("the test listens");
            })
        })
        .collect();
    drop(done_tx);
    let mut ended = 0;
    while ended < UNITS {
        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
            "a unit's end waited on the node's book: a process-wide lock stands in front of money",
        );
        ended += 1;
    }
    let landed = gov
        .derived_bucket_usage(
            &cost,
            &key.id,
            busbar_kernel::governance::WINDOW_TOTAL,
            true,
            EPOCH,
        )
        .expect("usage reads")
        .tokens;
    assert_eq!(
        landed,
        UNITS * 100,
        "every unit's counts landed while the book was held"
    );
    drop(held);
    for t in threads {
        t.join().expect("no unit panicked");
    }
    drop(node);
}
