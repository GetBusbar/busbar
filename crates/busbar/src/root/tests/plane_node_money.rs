// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Authenticate, Consumption, Decode, Dial, Encode, Meter,
    Refusal, SeatVerdict, Verify,
};
use busbar_kernel::slice::GroupLeaseSlip;

use std::sync::atomic::AtomicBool;

use busbar_contract::caps::{
    Admission, ArrivalRecord, Authenticated, Frame, ReasonCode, RoutePlan, ScopeFacts,
};

const LANE: &str = "m0";

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

const EPOCH: u64 = 1_700_000_000;

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

#[test]
fn the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived() {
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
        pinned.view().entries().last().unwrap().seq().get(),
        2,
        "the snapshot's head is the third entry — the figure a stamp must NOT be for a unit that \
         arrived before it, and the one a `read the head` implementation would answer every time"
    );

    let keys: Vec<_> = pinned
        .view()
        .entries()
        .iter()
        .map(|entry| entry.key().0)
        .collect();
    let stamped_ms = |ms: u64| card_in_force(Some(&pinned), ms);

    assert_eq!(
        stamped_ms(1_700_000_100_000),
        Some(keys[0]),
        "a unit that arrived before the second card was published is priced by the opening entry"
    );
    assert_eq!(
        stamped_ms(1_700_000_600_000),
        Some(keys[1]),
        "a unit that arrived in the second card's window names the SECOND entry — not the third, \
         which had not been published when it arrived (#79: publishing never reprices backwards)"
    );
    assert_eq!(
        stamped_ms(1_700_001_000_000),
        Some(keys[2]),
        "a unit that arrived after the third card names the third entry"
    );

    assert_eq!(
        card_in_force(None, 1_700_000_600_000),
        None,
        "no pinned history has no card entry identity"
    );

    assert_eq!(
        stamped_ms(1_700_000_600),
        Some(keys[0]),
        "a seconds-valued instant matches only the from-zero opening entry — which is why the \
         settle path resolves at `Arrived::ms()` and never at `Arrived::secs()`"
    );
}

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
        post: None,
        slot,
        arrived: Arrived::at(EPOCH * 1_000, key.get()),
        op_class: busbar_contract::caps::OpClassId::new(op_class),
        reached_end: false,
    });
}

#[test]
fn a_competing_sweep_leaves_a_claimed_units_hold_and_slot_with_its_owner() {
    let (node, book) = swept_node();
    let key = UnitKey::new(93);
    lose_a_unit(&node, key, "widget_call");

    let owned = node
        .lost
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&key)
        .unwrap();
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 0);
    assert!(
        node.parent(key).is_some(),
        "the losing sweep cannot retire the owner's slot"
    );
    assert!(book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .audit_records
        .is_empty());
    node.lost
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(key, owned);
    node.marked.fetch_add(1, Ordering::AcqRel);
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 100)), 1);
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 101)), 0);
    assert_eq!(
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .audit_records
            .iter()
            .filter(|r| r.what.unit_key == key)
            .count(),
        1
    );
}

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

    assert_eq!(record.controls.hold_ref, None);
    assert_eq!(record.controls.settle_ref, None);

    assert!(
        record.usage.lines.is_empty(),
        "a record names no money-class line: {:?}",
        record.usage.lines
    );
    assert!(durability.retained_audit_findings().is_empty());

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

const SEARCH_UNITS: &str = "search_units";

const RERANK_LANE: &str = "rerank-v3.5";

const RERANK_UNITS: u64 = 50;

#[test]
fn binding_the_node_to_the_book_journals_every_card_applied_after_it() {
    use crate::root::kernel::{CardApplied, RootHistory};
    fn apply(holder: &RootHistory, input: f64, at: u64) {
        let lanes = [(
            "gpt".to_string(),
            busbar_contract::billing::RawTierRates {
                input: busbar_kernel_ledger::cost::representable_nano_rate(input),
                output: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
            },
        )];
        let _ = holder.apply_rates(
            &busbar_kernel::rate_apply::RawRates {
                lanes: &lanes,
                units: &[],
                flat_minor: 0,
                present: true,
                plane_fees: &busbar_kernel::config::PlaneFeesMap::new(),
            },
            at,
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "busbar-node-book-cards-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");

    let holder: &'static RootHistory = Box::leak(Box::default());
    holder.arm_journal();
    apply(holder, 3.0, 1_000);
    let slots = crate::root::store_double::RecordSlots::new();
    let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store").unwrap();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig {
                data_dir: Some(dir.clone()),
            },
            7,
            lane,
            Some(holder),
        )
        .expect("the journal opens"),
    ));

    super::bind_node_book(&Node::new(), holder, Arc::clone(&book));
    apply(holder, 5.0, 20_000);

    let cards = book
        .lock()
        .expect("the book")
        .chain()
        .expect("reads")
        .expect("verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter_map(|r| CardApplied::from_body(&r.body))
        .map(|applied| applied.effective_from)
        .collect::<Vec<_>>();
    assert_eq!(
        cards,
        vec![0, 20_000],
        "the boot card and the card applied after the binding are both on the chain"
    );
    let lane = book.lock().unwrap().lane().unwrap().clone();
    assert!(lane.drain(std::time::Duration::from_secs(5)));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    drop(book);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_exit_arm_seals_no_money_figure_into_the_record() {
    use busbar_contract::caps::{Admittance, Hold, Posted, Usage, WriteMoney};
    use busbar_kernel_testkit::test_support::tokens::{end, grant, origin, pass};

    let node = Node::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));

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

const PRINCIPAL: &str = "acct:door";

const DESTINATION: &str = "door-dest";

struct DoorUnit {
    decode_refusal: Option<ReasonCode>,

    screen: Option<ReasonCode>,

    pause_screen: bool,

    reached_arrival: AtomicBool,

    reached_admit: AtomicBool,
}

impl DoorUnit {
    fn served() -> Self {
        DoorUnit {
            decode_refusal: None,
            screen: None,
            pause_screen: false,
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

impl busbar_kernel::teller::DoorSeats for DoorUnit {
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

        SeatVerdict::proceed(token, Admission::ZeroHold)
    }
}

impl busbar_kernel::teller::UnitEnds for DoorUnit {
    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
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
            if self.pause_screen {
                std::future::pending::<()>().await;
            }
            match screen {
                Some(reason) => Err(Refusal::new(reason)),
                None => Ok(()),
            }
        })
    }
}

#[test]
fn cancelling_before_the_door_retires_the_borrowed_facts_and_sweeps_once() {
    use std::future::Future as _;
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);
    let unit = DoorUnit {
        pause_screen: true,
        ..DoorUnit::served()
    };
    let key = node.mint();
    let principal = PrincipalId::new(PRINCIPAL);
    let mut run = Box::pin(node.drive_borrowed(
        key,
        node.arrived(),
        &principal,
        &post,
        &unit,
        no_late(),
        None,
        None,
        DoorUnit::op_class(),
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(run.as_mut().poll(&mut cx).is_pending());
    assert!(unit.reached_arrival.load(Ordering::Relaxed));
    assert!(!unit.reached_admit.load(Ordering::Relaxed));
    assert_eq!(post.open_units(), 1);
    drop(run);
    assert_eq!(
        post.open_units(),
        0,
        "the cancelled future owns no orphan facts"
    );
    assert_eq!(node.sweep(node.arrived()), 1);
    assert_eq!(node.sweep(node.arrived()), 0);
    assert!(node.parent(key).is_none());
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        durability
            .audit_records
            .iter()
            .filter(|r| r.what.unit_key == key)
            .count(),
        1
    );
}

fn door_node(book: &crate::root::durability::NodeBook) -> (Arc<Node>, NodeEndPost) {
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    (node, post)
}

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

fn no_late() -> Late {
    Box::new(|| None)
}

fn late_of(report: Report) -> Late {
    Box::new(move || Some((report.usage, report.fee_count, report.lane)))
}

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
            taps: Some(post),
        },
        &unit,
    )
    .await;
    node.inflight.remove(key);
    ended
}

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
        busbar_kernel_testkit::test_support::tokens::pass(),
    );
    let before = records();
    site.post(&ctx(51), ended);
    assert_eq!(
        records(),
        before + 1,
        "exactly one audit record for the abandoned unit"
    );

    let ended = drive_to_end(&node, &site).await;
    site.open(UnitKey::new(52), who, Arrived::at(EPOCH * 1_000, 1), None);
    let before = records();
    site.post(&ctx(52), ended);
    assert_eq!(records(), before, "no pass, no record");
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_journal_lane_refuses_a_new_unit_with_the_reason() {
    for data_dir in [
        None,
        Some(std::path::PathBuf::from("/dev/null/legacy-journal")),
    ] {
        let slots = crate::root::store_double::RecordSlots::new();
        slots.refuse(true);
        let lane =
            crate::root::durability::JournalLane::with_capacity(slots.calls(), "test-store", 1)
                .expect("the lane starts");
        let book = Arc::new(std::sync::Mutex::new(
            crate::root::durability::build_on_store(
                &crate::root::durability::DurabilityConfig { data_dir },
                0,
                lane,
                None,
            )
            .expect("the store reads back"),
        ));
        let token = busbar_kernel_testkit::test_support::tokens::grant::<
            busbar_contract::caps::DurableWrite,
        >();
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
}

#[test]
fn concurrent_unit_ends_land_their_money_while_the_book_is_held() {
    use busbar_contract::abi::plane::{UnitCount, UNITS_REPORTED};
    use busbar_kernel::plane_driver::{FeeRefund, MoneySeam, PlaneMoney, UnitMoney};
    const UNITS: u64 = 8;
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(crate::root::real_store::records(), None)
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
