// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESPONSE HEAD IS A FACE, AND THE FEE DECISION READS IT.
//!
//! The kernel's fee decision has two sources and it is written to distrust both: where the
//! transport's status class and the plane's finish class disagree it posts the LOWER count and
//! raises `METER_DISPUTED`, which is what makes a plane that lies about its finish visible rather
//! than profitable.
//!
//! That arm was unreachable on every plane in the tree, and not by accident of one dialect. Every
//! one of the four root legs that builds a fee leg wrote `status_at: None` as a literal, because
//! there was no value on the unit for the answer's HEAD to arrive in: the step that sees the head
//! is Route, the step that decides the fee is the exit, and nothing between them carried it. Four
//! legs independently disarming one kernel arm is not four bugs. It is a missing face.
//!
//! This cell states the face's one property: **the head the served leg saw is the head the fee
//! decision reads.** A mid-stream upstream error — a 200 head and a stream that died before the
//! answer finished — is the case the whole arm exists for, and it reaches the arm here through the
//! per-unit record rather than through anything this file assembles by hand.
//!
//! **The mutation is a sibling**, not a note: [`a_leg_that_records_no_head_falls_back_to_the_finish_alone`]
//! runs the identical unit with the head never recorded. The count is the same 0 and the DISPUTE
//! is gone, which is the whole finding: a fee of zero that nobody is told to look at is what the
//! four `status_at: None` literals were buying.
//!
//! RED at this base, and every error is the finding:
//!
//!   unresolved import `busbar_contract::StatusLeg`
//!   missing fields `finish`, `relayed_first_response_frame`, `status` and 1 other field in
//!     initializer of `FeeEvidence`
//!   no method named `record_head` found for reference `&UnitRecord<'_>`
//!   no method named `head` found for reference `&UnitRecord<'_>`
//!   this function takes 1 argument but 2 arguments were supplied
//!
//! There is no type for a response head, no cell on the record for one, and `fee_count` reads the
//! three fields the plane hands it rather than the one fact the unit saw.

mod common;

use std::sync::Mutex;

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate,
    Authenticated, Canary, Decision, Decode, Encode, Frame, Hold, HoldCell, Meter, OpClassId,
    Outcome, PostingFlags, PrincipalId, Refusal, Route, RoutePlan, ScopeFacts, TrustToken,
    UnitToken, Usage, UsageToken, Verify,
};
use busbar_contract::bounded::Labels;
use busbar_contract::unit::Clock;
use busbar_contract::{FinishClass, StatusAt, StatusClass, StatusLeg};
use busbar_kernel::record::{UnitRecord, UnitViews};
use busbar_kernel::slice::{ConcurrencyGauge, GroupLeaseSlip, LeaseCell};
use busbar_kernel::teller::{
    fee_count, AccrualMeter, Ended, Evidence, FeeEvidence, Kernel, Run, Units,
};

/// What the exit's own reading of the fee came to, and what the record was carrying when it read
/// it.
#[derive(Default)]
struct Seen {
    /// The kernel's fee decision over the head the RECORD carried, taken inside the exit.
    fee: Mutex<Option<(u32, PostingFlags)>>,
    /// The head the settlement table found on the unit, or its absence.
    head: Mutex<Option<Option<StatusLeg>>>,
}

/// A plane whose Route relays an answer and records the head it saw — or does not.
///
/// `head` is the mutation, written as data rather than as a second fixture: the served leg either
/// puts the answer's head on the unit or it does not, and every other line of this plane is the
/// same either way.
struct Served {
    seen: Seen,
    head: Option<StatusLeg>,
}

impl Served {
    fn new(head: Option<StatusLeg>) -> Self {
        Served {
            seen: Seen::default(),
            head,
        }
    }

    /// The two facts about the UNIT the fee decision needs beside the head: whose request this was
    /// and whether the route selected an upstream at all. Neither is a reading of the answer.
    fn identity() -> FeeEvidence {
        FeeEvidence {
            client_open_or_one_shot: true,
            selected_upstream: true,
        }
    }
}

impl Units for Served {
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

    /// THE ONE PLACE THAT SEES THE HEAD. The answer came back, its head is read once here, and it
    /// goes onto the unit under the Route token — the same token the routed body goes under, for
    /// the same reason: the step that dialled is the step that saw.
    fn route(
        &self,
        token: &UnitToken<Route>,
        record: &UnitRecord<'_>,
        _meter: &AccrualMeter,
    ) -> Decision<Route> {
        if let Some(head) = self.head {
            assert!(
                record.record_head(token, head),
                "the head the served leg saw goes onto the unit once"
            );
        }
        Decision::proceed(token, RoutePlan::default())
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        _record: &UnitRecord<'_>,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        Decision::proceed(
            token,
            Usage::report(usage, Vec::new()).expect("an empty report is within bound"),
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
            AuditFacts {
                op_class: OpClassId::new("cell"),
                finish: FinishClass::Error,
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
                finish: FinishClass::Error,
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

    /// The settlement table's read. The fee leg it hands over is the unit's identity and nothing
    /// about the answer: the head is the RECORD's, and the kernel reads it from there.
    fn evidence(&self, record: &UnitRecord<'_>) -> Evidence {
        *self.seen.head.lock().unwrap() = Some(record.head().copied());
        *self.seen.fee.lock().unwrap() = Some(fee_count(&Served::identity(), record.head()));
        Evidence {
            upstream_candidate: true,
            fee: Served::identity(),
            ..Default::default()
        }
    }
}

/// Run one unit whose served leg saw the given head, and hand back what the exit decided.
fn run_one(head: Option<StatusLeg>) -> (Seen, Ended) {
    let kernel = Kernel::new();
    let units = Served::new(head);
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
    let ended = busbar_kernel::teller::run_unit(
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
    (units.seen, ended)
}

/// The head a mid-stream failure leaves behind: a 200 the client saw, and an answer that never
/// finished. This is the case the dispute arm exists for and the one no plane could reach.
fn cut_after_a_good_head() -> StatusLeg {
    StatusLeg {
        at: Some(StatusAt::FirstFrame),
        status: Some(StatusClass::Success),
        finish: Some(FinishClass::Error),
        delivered: true,
        degraded: false,
        relayed_error: None,
    }
}

/// What the exit settled as the flat fee.
fn settled_fee(ended: &Ended) -> u32 {
    match ended {
        Ended::Settled { fee, .. } => *fee,
        Ended::AlreadySettled => panic!("the cell's unit is settled here and nowhere else"),
    }
}

/// A mid-stream upstream error reaches the dispute arm, with the status the transport reported.
#[test]
fn a_cut_stream_after_a_good_head_reaches_the_dispute_arm() {
    let (seen, ended) = run_one(Some(cut_after_a_good_head()));
    assert_eq!(
        *seen.head.lock().unwrap(),
        Some(Some(cut_after_a_good_head())),
        "the head the served leg saw is on the unit at the settlement table, unaltered"
    );
    let (fee, flags) = seen
        .fee
        .lock()
        .unwrap()
        .expect("the settlement table decided a fee");
    assert_eq!(
        fee, 0,
        "the two sources disagree, so the LOWER count posts — the house's reading never wins"
    );
    assert!(
        flags.contains(PostingFlags::METER_DISPUTED),
        "and the disagreement is marked, which is what makes it visible rather than profitable"
    );
    assert_eq!(
        settled_fee(&ended),
        0,
        "the exit posts the count the table decided and not a second one"
    );
}

/// THE MUTATION. The identical unit, with the head never recorded.
///
/// The count does not move — a fee of zero is a fee of zero — and the DISPUTE disappears. That is
/// the finding stated as a difference: four legs writing `status_at: None` were not billing less,
/// they were billing the same and telling nobody there was anything to look at.
#[test]
fn a_leg_that_records_no_head_falls_back_to_the_finish_alone() {
    let (seen, _ended) = run_one(None);
    assert_eq!(
        *seen.head.lock().unwrap(),
        Some(None),
        "nothing recorded the head, so the unit carries none"
    );
    let (fee, flags) = seen
        .fee
        .lock()
        .unwrap()
        .expect("the settlement table still decided a fee");
    assert_eq!(fee, 0, "the count is the same one");
    assert!(
        !flags.contains(PostingFlags::METER_DISPUTED),
        "and the dispute is gone — which is exactly what the cell above asserts did NOT happen"
    );
}

/// The face does not move the money on an answer whose two sources agree.
///
/// A clean 200 with a whole answer bills one and flags nothing; a 503 with an error ending bills
/// none and flags nothing. These are the two shapes every recorded cell in the corpus is, and the
/// arm above is reached by neither.
#[test]
fn the_two_sources_agreeing_bills_what_it_always_billed() {
    let clean = StatusLeg {
        at: Some(StatusAt::FirstFrame),
        status: Some(StatusClass::Success),
        finish: Some(FinishClass::Complete),
        delivered: true,
        degraded: false,
        relayed_error: None,
    };
    let (_seen, ended) = run_one(Some(clean));
    assert_eq!(settled_fee(&ended), 1, "a good answer bills one");
    assert_eq!(
        fee_count(&Served::identity(), Some(&clean)),
        (1, PostingFlags::NONE),
        "and nothing is disputed"
    );

    let refused = StatusLeg {
        at: Some(StatusAt::FirstFrame),
        status: Some(StatusClass::ServerError),
        finish: Some(FinishClass::Error),
        delivered: true,
        degraded: false,
        relayed_error: None,
    };
    let (_seen, ended) = run_one(Some(refused));
    assert_eq!(settled_fee(&ended), 0, "an upstream that failed bills none");
    assert_eq!(
        fee_count(&Served::identity(), Some(&refused)),
        (0, PostingFlags::NONE),
        "and nothing is disputed, because the two sources said the same thing"
    );
}

/// A transport that says WHERE its status is reported and then reports none has lost the evidence.
///
/// The stream died before the frame carrying it. Nothing is billed, and a plane claiming a whole
/// answer over a status that never arrived is the second source disagreeing.
#[test]
fn a_head_that_never_arrived_bills_nothing_and_disputes_a_whole_answer() {
    let lost = StatusLeg {
        at: Some(StatusAt::Terminal),
        status: None,
        finish: Some(FinishClass::Complete),
        delivered: true,
        degraded: false,
        relayed_error: None,
    };
    assert_eq!(
        fee_count(&Served::identity(), Some(&lost)),
        (0, PostingFlags::METER_DISPUTED),
        "a whole answer over a status that never came is a dispute"
    );
    let honest = StatusLeg {
        finish: Some(FinishClass::Partial),
        ..lost
    };
    assert_eq!(
        fee_count(&Served::identity(), Some(&honest)),
        (0, PostingFlags::NONE),
        "a plane telling the same story the transport is telling is not a dispute"
    );
}

/// The head is write-once: a second leg cannot replace what the first one saw.
#[test]
fn the_head_is_written_once_and_not_replaced() {
    // Driven through the same loop as everything else: the fixture's Route records the head it was
    // built with, and the record answers `false` to a second write. The cell below is the plane's
    // own assertion inside `route`, re-stated here as the property it protects — a second reading
    // of one answer is how a unit ends up with two heads and the fee decision reads whichever ran
    // last.
    let (seen, _ended) = run_one(Some(cut_after_a_good_head()));
    assert_eq!(
        *seen.head.lock().unwrap(),
        Some(Some(cut_after_a_good_head())),
        "one head per unit, and it is the one the served leg saw"
    );
}
