// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT VERIFY ESTABLISHED, AT THE STEP THAT SPENDS IT.
//!
//! Verify is the one step lent a `TrustToken`, so it is the one step that can seal a destination.
//! Everything after it spends what it sealed: Approve and Admit decide against that set, Route
//! dials one member of it, and Meter reports what that member cost. Until this cell there was no
//! way for the last two to see it at all — `route` and `meter` were handed six scalars and a
//! meter, and the sealed set was dropped on the floor when Admit returned.
//!
//! That is not a missing convenience. `walk()` indexes the verified set by destination id, so a
//! Route that re-derives the set is a Route working in a different index space from the one Verify
//! sealed — a hop charged against a lane it was not sealed for. The same applies to the transport
//! key handle: it is pinned to the generation the unit started on so the unit finishes against the
//! material it started with, and a step that re-read the key registry would be a step that dials
//! under whatever a reload had just installed.
//!
//! So the property is stated at both ends: what Route and Meter read is BYTE-FOR-BYTE the set
//! Verify sealed, in Verify's own order, and the handle they read is the one pinned at Verify and
//! never material. Drop either from the record and this cell reds — there is nowhere else a step
//! could get them from.

use std::sync::Mutex;

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, Audit, Authenticate, Authenticated, Canary,
    Decision, Decode, Encode, Hold, HoldCell, LaneId, Meter, Outcome, PrincipalId, Refusal, Route,
    RoutePlan, ScopeFacts, StepName, TransportKeyHandle, TrustToken, UnitKey, UnitToken, UsageToken,
    Verify, VerifiedDestination,
};
use busbar_contract::bounded::Labels;
use busbar_contract::unit::{Clock, ConfigView, TransportView};
use busbar_kernel::record::{UnitMemory, UnitRecord, UnitViews};
use busbar_kernel::registry::Generation;
use busbar_kernel::slice::{ConcurrencyGauge, GroupLeaseSlip, LeaseCell};
use busbar_kernel::teller::{AccrualMeter, Evidence, Kernel, Run, UnitCtx, Units};

/// The two lanes this unit's Verify seals, in this order. Order is part of the property: the set is
/// an index space, so a step that saw the same two lanes the other way round is a step that would
/// dial the wrong one.
const LANES: [&str; 2] = ["lane-primary", "lane-failover"];

/// The fingerprint the generation's handle carries. A fingerprint and a slot are the whole of a
/// handle; there is no third field and there are no bytes.
const FINGERPRINT: &str = "sha256:fixture";

/// The slot the generation's handle names.
const SLOT: u64 = 7;

/// What each step could see of the verified set, recorded as the step saw it.
#[derive(Default)]
struct Seen {
    verify_sealed: Mutex<Vec<LaneId>>,
    approve: Mutex<Option<Vec<LaneId>>>,
    admit: Mutex<Option<Vec<LaneId>>>,
    route: Mutex<Option<Vec<LaneId>>>,
    meter: Mutex<Option<Vec<LaneId>>>,
    route_handle: Mutex<Option<(u64, &'static str)>>,
    meter_handle: Mutex<Option<(u64, &'static str)>>,
}

impl Seen {
    fn lanes(record: &UnitRecord<'_>) -> Vec<LaneId> {
        record.verified().iter().map(|d| *d.lane()).collect()
    }

    fn handle(record: &UnitRecord<'_>) -> Option<(u64, &'static str)> {
        record
            .key_handle()
            .map(|h| (h.slot(), h.fingerprint()))
    }
}

/// A plane that seals two lanes at Verify and reads the record at every step after it.
struct Sealing {
    seen: Seen,
}

impl Units for Sealing {
    fn arrival(&self, token: &UnitToken<Arrival>, _record: &UnitRecord<'_>) -> Decision<Arrival> {
        Decision::proceed(
            token,
            busbar_caps::ArrivalRecord {
                source: "127.0.0.1:9".into(),
                port: 9,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: vec!["cell"],
            },
        )
    }

    fn decode(&self, token: &UnitToken<Decode>, _record: &UnitRecord<'_>) -> Decision<Decode> {
        Decision::proceed(token, busbar_caps::OpClassId::new("cell"))
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _record: &UnitRecord<'_>,
    ) -> Decision<Authenticate> {
        Decision::proceed(
            token,
            Authenticated::Principal(PrincipalId::new("acct:cell")),
        )
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        trust: &TrustToken,
        _record: &UnitRecord<'_>,
        _principal: &PrincipalId,
    ) -> Decision<Verify> {
        let sealed: Vec<VerifiedDestination> = LANES
            .iter()
            .map(|lane| VerifiedDestination::seal(trust, LaneId::new(lane)))
            .collect();
        *self.seen.verify_sealed.lock().unwrap() = sealed.iter().map(|d| *d.lane()).collect();
        Decision::proceed(token, sealed)
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        record: &UnitRecord<'_>,
        _principal: &PrincipalId,
    ) -> Decision<Approve> {
        *self.seen.approve.lock().unwrap() = Some(Seen::lanes(record));
        Decision::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        record: &UnitRecord<'_>,
        principal: &PrincipalId,
        _leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        *self.seen.admit.lock().unwrap() = Some(Seen::lanes(record));
        Decision::proceed(
            token,
            Admission::Own(Hold::open(admit, principal.clone(), 0)),
        )
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        record: &UnitRecord<'_>,
        _meter: &AccrualMeter,
    ) -> Decision<Route> {
        *self.seen.route.lock().unwrap() = Some(Seen::lanes(record));
        *self.seen.route_handle.lock().unwrap() = Seen::handle(record);
        Decision::proceed(token, RoutePlan::default())
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        record: &UnitRecord<'_>,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        *self.seen.meter.lock().unwrap() = Some(Seen::lanes(record));
        *self.seen.meter_handle.lock().unwrap() = Seen::handle(record);
        Decision::proceed(
            token,
            busbar_caps::Usage::report(usage, Vec::new()).expect("an empty report is within bound"),
        )
    }

    fn audit(
        &self,
        token: &UnitToken<Audit>,
        _record: &UnitRecord<'_>,
        _outcome: &Outcome,
    ) -> Decision<Audit> {
        Decision::proceed(
            token,
            busbar_caps::AuditFacts {
                op_class: busbar_caps::OpClassId::new("cell"),
                finish: busbar_contract::FinishClass::Complete,
            },
        )
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        _record: &UnitRecord<'_>,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        Decision::proceed(
            token,
            busbar_caps::AuditFacts {
                op_class: busbar_caps::OpClassId::new("cell"),
                finish: busbar_contract::FinishClass::Error,
            },
        )
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _record: &UnitRecord<'_>,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
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

    fn evidence(&self, _record: &UnitRecord<'_>) -> Evidence {
        Evidence::default()
    }
}

/// A configuration block that answers nothing, which is what a unit with no plugin block has.
struct NoConfig;

impl ConfigView for NoConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

/// One transport stack, named the way the node composes one.
struct Stack;

impl TransportView for Stack {
    fn key(&self) -> &'static str {
        "cell"
    }
    fn chain(&self) -> &[&'static str] {
        &["cell"]
    }
    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

/// Run one unit through the whole loop and hand back what every step could see.
fn run_one() -> Seen {
    let kernel = Kernel::new();
    let units = Sealing { seen: Seen::default() };
    let handle = TransportKeyHandle::issue(&kernel.transport_key_token(), SLOT, FINGERPRINT);
    let config = NoConfig;
    let transport = Stack;
    let labels = Labels::new();
    let views = UnitViews {
        clock: Clock {
            unix_secs: 1_700_000_000,
            monotonic_nanos: 0,
        },
        config: &config,
        session: None,
        transport: &transport,
        labels: &labels,
        key_handle: Some(&handle),
    };
    let ctx = UnitCtx {
        key: UnitKey::new(1),
        origin: busbar_caps::OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let cell = HoldCell::new(Hold::open(
        &kernel.admit_token(),
        PrincipalId::new("acct:cell"),
        0,
    ));
    let leases = LeaseCell::new();
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::default();
    let meter = AccrualMeter::new();
    let _ended = busbar_kernel::teller::run_unit(
        &kernel,
        &units,
        &ctx,
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
    units.seen
}

/// Verify seals two lanes; Approve, Admit, Route and Meter all read THAT set, in that order.
#[test]
fn every_step_after_verify_reads_the_set_verify_sealed() {
    let seen = run_one();
    let sealed = seen.verify_sealed.lock().unwrap().clone();
    assert_eq!(
        sealed,
        LANES.iter().map(|l| LaneId::new(l)).collect::<Vec<_>>(),
        "the fixture's Verify seals the two lanes the cell names, in order"
    );
    for (step, got) in [
        (StepName::Approve, seen.approve.lock().unwrap().clone()),
        (StepName::Admit, seen.admit.lock().unwrap().clone()),
        (StepName::Route, seen.route.lock().unwrap().clone()),
        (StepName::Meter, seen.meter.lock().unwrap().clone()),
    ] {
        assert_eq!(
            got.as_deref(),
            Some(sealed.as_slice()),
            "{step:?} reads the set Verify sealed, not a set of its own"
        );
    }
}

/// Route and Meter read the handle pinned at Verify — a slot and a fingerprint, never material.
#[test]
fn route_and_meter_read_the_handle_pinned_at_verify() {
    let seen = run_one();
    let expected = Some((SLOT, FINGERPRINT));
    assert_eq!(
        *seen.route_handle.lock().unwrap(),
        expected,
        "Route dials under the handle the unit's own generation offered and Verify pinned"
    );
    assert_eq!(
        *seen.meter_handle.lock().unwrap(),
        expected,
        "Meter reports against the same handle Route dialled under"
    );
}
