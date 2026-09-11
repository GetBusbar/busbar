// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTED BODY, HELD AS A HANDLE AND RELEASED BY THE EXIT.
//!
//! Two clauses, and the money moves the moment either weakens.
//!
//! **A handle, not bytes.** Taking the bytes at the route seam means draining the body at the
//! route seam, and on a billing plane the instant a body finishes draining is the instant the
//! money is read — so a seam that buffered would be deciding when a stream ended. The body under
//! the hold is a lease number and what the stream counted; the bytes stay where the transport put
//! them. This cell relays NINE kilobytes through a unit whose one resource handle is four, and
//! measures the arena: a body that reached the meter by being copied would have taken the arena
//! with it, and the sibling cell below is what says that measurement can tell the difference.
//!
//! **The hold is not released when the walk returns.** Route's return is not an exit. The hold
//! stays on the unit across it, the Meter step reads what the stream carried, and the exit path —
//! the one holder of an exit token — is what gives it back. Move the release one step earlier,
//! into the loop's own `under_hold` ahead of the meter call, and both cells below red: the meter
//! reads `None`, because a released body is not a completed body the meter may report.
//!
//! The figure itself is the relay's own count against the classes the plane declared. Nothing here
//! re-derives it: there is no second reading of the body for the two to disagree about, which is
//! the whole reason the completion travels on the hold rather than being recomputed at the meter.

mod common;

use std::sync::Mutex;

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate,
    Authenticated, BodyLease, Canary, CompletedUnits, Completion, Decision, Decode, Encode, Frame,
    Hold, HoldCell, Meter, MeterClassId, OpClassId, Outcome, PrincipalId, Refusal, Route,
    RoutePlan, ScopeFacts, TrustToken, UnitToken, Usage, UsageToken, Verify,
};
use busbar_contract::bounded::Labels;
use busbar_contract::unit::Clock;
use busbar_contract::ARENA_BYTES;
use busbar_kernel::record::{UnitRecord, UnitViews};
use busbar_kernel::slice::{ConcurrencyGauge, GroupLeaseSlip, LeaseCell};
use busbar_kernel::teller::{AccrualMeter, Evidence, Kernel, Run, Units};

/// The answer this unit routes: nine kilobytes, which is more than twice the arena.
const BODY_BYTES: usize = 9 * 1024;

/// How much of it arrives at a time. The relay counts per frame and copies none of them.
const FRAME_BYTES: usize = 512;

/// The lease the body stream is held under.
const LEASE: u64 = 41;

/// The dimension this fixture's plane declares, priced by the tariff's `units` noun.
const CLASS: MeterClassId = MeterClassId::new("cell_tokens");

/// How many units of that class the body carried, as the relay counted them.
const UNITS: u64 = 37;

/// What the Meter step read off the hold: the frames, the bytes, the declared dimension, and what
/// the unit's own 4 KiB had left when it read them.
type MeterRead = (u64, u64, Option<u64>, usize);

/// What the steps after Route could see of the body under the hold.
#[derive(Default)]
struct Seen {
    /// The completion the Meter step read off the hold, and what the arena had left when it did.
    meter: Mutex<Option<MeterRead>>,
    /// Whether the body was still the unit's at the Meter step.
    meter_released: Mutex<Option<bool>>,
    /// Whether it still was at the audit door, which is after the meter and before the exit.
    audit_released: Mutex<Option<bool>>,
    /// What the settlement table saw — and this one runs INSIDE the exit, after the release.
    evidence_completion: Mutex<Option<Option<u64>>>,
    /// Whether the exit had released it by then.
    evidence_released: Mutex<Option<bool>>,
}

/// A plane whose Route relays a body far larger than the arena and holds it as a handle.
///
/// `copy_bytes` is the mutation, written as a sibling rather than left to a reviewer's hand: with
/// it set the route step copies that many bytes of the answer into the unit's own 4 KiB, which is
/// exactly what "the seam buffered" looks like from the arena's side.
struct Streaming {
    seen: Seen,
    copy_bytes: usize,
}

impl Streaming {
    fn new(copy_bytes: usize) -> Self {
        Streaming {
            seen: Seen::default(),
            copy_bytes,
        }
    }

    /// The answer, as it sits in the connection's own slab — which is where a body lives and is
    /// the reason the arena never has to be big enough to hold one.
    fn slab() -> Vec<u8> {
        (0..BODY_BYTES).map(|i| (i % 251) as u8).collect()
    }
}

impl Units for Streaming {
    fn arrival(&self, token: &UnitToken<Arrival>, _record: &UnitRecord<'_>) -> Decision<Arrival> {
        Decision::proceed(
            token,
            ArrivalRecord {
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
        Decision::proceed(token, OpClassId::new("cell"))
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
        _trust: &TrustToken,
        _record: &UnitRecord<'_>,
        _principal: &PrincipalId,
    ) -> Decision<Verify> {
        Decision::proceed(token, Vec::new())
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        _record: &UnitRecord<'_>,
        _principal: &PrincipalId,
    ) -> Decision<Approve> {
        Decision::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        _record: &UnitRecord<'_>,
        principal: &PrincipalId,
        _leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        Decision::proceed(
            token,
            Admission::Own(Hold::open(admit, principal.clone(), 0)),
        )
    }

    /// Dial, relay, and hand the body to the unit as a handle.
    ///
    /// The relay walks the slab a frame at a time and counts; what goes onto the hold is the count
    /// and the lease, never a byte. The `copy_bytes` arm is the buffering seam, for the sibling.
    fn route(
        &self,
        token: &UnitToken<Route>,
        record: &UnitRecord<'_>,
        _meter: &AccrualMeter,
    ) -> Decision<Route> {
        let slab = Streaming::slab();
        if self.copy_bytes > 0 {
            let _ = record
                .ctx()
                .arena()
                .alloc_bytes(&slab[..self.copy_bytes.min(slab.len())]);
        }

        assert!(
            record.hold_body(token, BodyLease::new(LEASE)),
            "the routed body goes under the unit's hold once, as a lease and never as bytes"
        );

        let mut frames = 0u64;
        let mut bytes = 0u64;
        for frame in slab.chunks(FRAME_BYTES) {
            frames += 1;
            bytes += frame.len() as u64;
        }
        let completion = Completion::of(
            frames,
            bytes,
            vec![CompletedUnits {
                class: CLASS,
                units: UNITS,
            }],
        )
        .expect("one dimension is within the report's bound");
        assert!(
            record.body_finished(token, completion),
            "the relay records what the stream carried, once"
        );
        Decision::proceed(token, RoutePlan::default())
    }

    /// The meter reads COMPLETION off the handle. It derives nothing.
    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        record: &UnitRecord<'_>,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        *self.seen.meter_released.lock().unwrap() = Some(record.body_is_released());
        *self.seen.meter.lock().unwrap() = record.completion().map(|c| {
            (
                c.frames(),
                c.bytes(),
                c.units(CLASS),
                record.ctx().arena().remaining(),
            )
        });
        Decision::proceed(
            token,
            Usage::report(usage, Vec::new()).expect("an empty report is within bound"),
        )
    }

    fn audit(
        &self,
        token: &UnitToken<Audit>,
        record: &UnitRecord<'_>,
        _outcome: &Outcome,
    ) -> Decision<Audit> {
        *self.seen.audit_released.lock().unwrap() = Some(record.body_is_released());
        Decision::proceed(
            token,
            AuditFacts {
                op_class: OpClassId::new("cell"),
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
            AuditFacts {
                op_class: OpClassId::new("cell"),
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
            Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    /// The settlement table's read — and it runs INSIDE the exit, after the release.
    fn evidence(&self, record: &UnitRecord<'_>) -> Evidence {
        *self.seen.evidence_completion.lock().unwrap() =
            Some(record.completion().map(Completion::bytes));
        *self.seen.evidence_released.lock().unwrap() = Some(record.body_is_released());
        Evidence::default()
    }
}

/// Run one unit whose Route relays the body, and hand back what every later step could see.
fn run_one(copy_bytes: usize) -> Seen {
    let kernel = Kernel::new();
    let units = Streaming::new(copy_bytes);
    let config = common::NoConfig;
    let transport = common::Stack;
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
        key_handle: None,
    };
    let ctx = common::ctx(1);
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

/// Nine kilobytes reach the Meter step through a four-kilobyte unit, and the arena is untouched.
#[test]
fn a_body_larger_than_the_arena_reaches_the_meter_without_a_copy() {
    let seen = run_one(0);
    let (frames, bytes, units, remaining) = seen
        .meter
        .lock()
        .unwrap()
        .expect("the Meter step reads the completion off the body under the hold");
    assert_eq!(
        bytes, BODY_BYTES as u64,
        "the whole answer went by, and it is larger than the arena"
    );
    assert!(
        bytes > ARENA_BYTES as u64,
        "the cell is only worth anything if the body does not fit: {bytes} against {ARENA_BYTES}"
    );
    assert_eq!(
        frames,
        BODY_BYTES.div_ceil(FRAME_BYTES) as u64,
        "the relay counted every frame it relayed"
    );
    assert_eq!(
        units,
        Some(UNITS),
        "the meter reads the plane's declared dimension off the handle rather than deriving one"
    );
    assert_eq!(
        remaining, ARENA_BYTES,
        "not one byte of the answer landed in the unit's own 4 KiB"
    );
}

/// The mutation, as a sibling: a seam that buffers is a seam the arena can see.
///
/// One kilobyte of the same answer, copied into the unit's own memory on the way past. If the
/// measurement above could not tell a buffered body from a streamed one, this cell would pass with
/// the same reading the cell above asserts — and it does not.
#[test]
fn a_body_copied_into_the_arena_is_a_body_the_arena_can_see() {
    let copied = 1024;
    let seen = run_one(copied);
    let (_, _, _, remaining) = seen
        .meter
        .lock()
        .unwrap()
        .expect("the Meter step still reads the completion");
    assert_eq!(
        remaining,
        ARENA_BYTES - copied,
        "a body the seam buffered shows up as the unit's own memory being spent on it"
    );
    assert!(
        remaining < ARENA_BYTES,
        "which is exactly what the cell above asserts did NOT happen"
    );
}

/// And the whole answer cannot be buffered at all: the arena is 4 KiB and the body is nine.
#[test]
fn the_whole_answer_does_not_fit_in_the_one_resource_handle_a_plugin_is_given() {
    let arena_bytes = ARENA_BYTES;
    let slab = Streaming::slab();
    assert!(
        slab.len() > arena_bytes,
        "a seam that took the bytes would have to refuse this answer for arena budget"
    );
}

/// Route's return is not an exit. The exit is.
#[test]
fn the_hold_is_released_by_the_exit_and_not_when_route_returns() {
    let seen = run_one(0);
    assert_eq!(
        *seen.meter_released.lock().unwrap(),
        Some(false),
        "the body is still the unit's at the Meter step, which is after Route returned"
    );
    assert_eq!(
        *seen.audit_released.lock().unwrap(),
        Some(false),
        "and still at the audit door, which is after the meter and before the exit"
    );
    assert_eq!(
        *seen.evidence_released.lock().unwrap(),
        Some(true),
        "the exit path is what gives it back"
    );
    assert_eq!(
        *seen.evidence_completion.lock().unwrap(),
        Some(None),
        "and a released body reports nothing: the meter already read what it carried"
    );
}
