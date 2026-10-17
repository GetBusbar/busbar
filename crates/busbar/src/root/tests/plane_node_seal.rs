// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A unit's one audit record names where the unit went and the controls it ran under (audit
//! root-R1#1; THE DESIGN §1: "what (unit key, op class, verified destination) ... controls
//! (hold/settle seqs, slice, hooks applied)"). Driven through the node both ways a unit reaches it:
//! handed by a plane's arrival ([`Node::answer`]) and borrowed by a plane driver
//! ([`Node::drive_borrowed`]).

use super::*;

use busbar_contract::caps::{
    Admission, ArrivalRecord, Authenticated, Frame, ReasonCode, RoutePlan, ScopeFacts, Usage,
};

/// The one destination Verify seals for the unit: the lane its record must name.
const DESTINATION: &str = "seal-dest-d";

/// A unit that passes every step and routes to [`DESTINATION`], the one destination it seals.
struct ToDestination;

impl ToDestination {
    fn op_class() -> OpClassId {
        OpClassId::new("call")
    }
}

impl Units for ToDestination {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> SeatVerdict<Arrival> {
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
        SeatVerdict::proceed(token, Self::op_class())
    }

    fn authenticate(
        &self,
        token: &Pass<Authenticate>,
        _ctx: &UnitCtx,
    ) -> SeatVerdict<Authenticate> {
        SeatVerdict::proceed(
            token,
            Authenticated::Principal(PrincipalId::new("acct:seal")),
        )
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
        // The arrival hold is the hold the exit settles: the unit runs under it.
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
            Usage::report(usage, Vec::new()).expect("an empty usage report never overflows"),
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

impl RouteAwait for ToDestination {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        Box::pin(async move { SeatVerdict::proceed(token, RoutePlan::default()) })
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}
}

/// The unit, as a plane's arrival hands it to the node.
fn handed() -> Handed {
    let build: crate::root::linked::node::Build = Box::new(
        |_lent: crate::root::linked::node::Lent| -> crate::root::linked::node::Built {
            let units: Arc<dyn Units + Send + Sync> = Arc::new(ToDestination);
            let route: Arc<dyn RouteAwait + Send + Sync> = Arc::new(ToDestination);
            let finish: crate::root::linked::node::Finish =
                Box::new(|| -> (Option<PlaneAnswer>, Option<Late>) { (None, None) });
            (units, route, finish)
        },
    );
    (
        PrincipalId::new("acct:seal"),
        ToDestination::op_class(),
        "seal-test",
        build,
    )
}

/// The one record the node sealed names [`DESTINATION`] and the hold and settlement the unit's own
/// records sit at on the chain.
fn assert_sealed_with_destination_and_controls(book: &crate::root::durability::NodeBook) {
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let records = durability.audit_records.clone();
    assert_eq!(records.len(), 1, "one record for the one unit: {records:?}");
    let record = &records[0];
    assert_eq!(
        record.what.destination.as_deref(),
        Some(DESTINATION),
        "the record names the verified destination the unit routed to"
    );
    let seq = |r: Option<&String>| r.and_then(|r| r.parse::<u64>().ok());
    let hold = seq(record.controls.hold_ref.as_ref()).expect("the record names the unit's hold");
    let settle =
        seq(record.controls.settle_ref.as_ref()).expect("the record names the unit's settlement");
    let Ok(Ok(chain)) = durability.journal.replay() else {
        panic!("the node's journal reads back");
    };
    let at = |seq: u64| chain.iter().find(|r| r.node_seq == seq);
    assert!(
        at(hold)
            .and_then(crate::root::durability::HoldOpened::from_record)
            .is_some(),
        "hold_ref {hold} is the seq of the unit's hold record"
    );
    assert!(
        at(settle)
            .and_then(crate::root::durability::Posting::from_record)
            .is_some_and(|p| p.kind == crate::root::durability::PostingKind::Settlement),
        "settle_ref {settle} is the seq of the settlement that closed the hold"
    );
    assert!(hold < settle, "the hold opens before it settles");
}

/// A HANDED unit that routes to destination D and runs under a hold seals a record whose
/// destination is D and whose controls name its hold and its settlement by seq. RED before
/// root-R1#1: the record carried `destination: None` and `Controls::default()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handed_unit_seals_its_verified_destination_and_its_hold_and_settle_seqs() {
    let node = Node::new();
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let _answer = node.answer(handed()).await;
    assert_sealed_with_destination_and_controls(&book);
}

/// The same, for a unit a plane driver lends the node ([`Node::drive_borrowed`]): its facts ride the
/// posting site's open entry to the seal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_borrowed_unit_seals_its_verified_destination_and_its_hold_and_settle_seqs() {
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    let outcome = node
        .drive_borrowed(
            node.mint(),
            node.arrived(),
            &PrincipalId::new("acct:seal"),
            &post,
            &ToDestination,
            Box::new(|| -> Option<Reported> { None }),
            None,
            None,
        )
        .await;
    assert!(outcome.is_some(), "the table took the unit and it ended");
    assert_eq!(post.open_units(), 0, "its facts closed at its end");
    assert_sealed_with_destination_and_controls(&book);
}
