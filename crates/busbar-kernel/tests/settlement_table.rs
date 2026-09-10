// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement table, row by row, and the two quantity rules beside it.
//!
//! Every row says the same thing in a different situation: post the lower evidence, mark it, and
//! put it where someone will look at it. These are the rows.

use busbar_caps::OriginKind;
use busbar_caps::{
    CompletedUnits, Completion, MeterClassId, Outcome, PostingFlags, ReasonCode, StepName,
};
use busbar_contract::{DestinationFacts, LaneId, UpstreamAddress, UpstreamIdx};
use busbar_kernel::teller::{
    fee_count, requests_drawn, requests_settled, settle_lines, DisputePolicy, Evidence,
    FeeEvidence, FinishClass, StatusAt, StatusClass, StatusLeg,
};

/// The one class the rows below report against.
///
/// The rows are about WHICH FIGURE a situation settles at, and a plane's class list is not what
/// they vary — so they vary one quantity against one declared class, exactly as they always did.
/// What a four-dimension answer settles as is `tests/fee_identity.rs`, which is the cell that
/// changed the shape.
const REPORTED: MeterClassId = MeterClassId::new("reported");

/// What a destination reported, as the one dimension these rows are written over.
fn reported(units: u64) -> Option<Completion> {
    Some(
        Completion::of(
            1,
            0,
            vec![CompletedUnits {
                class: REPORTED,
                units,
            }],
        )
        .expect("one dimension is inside the usage record's bound"),
    )
}

/// What the table settles at, as ONE figure: the sum of the lines it answered with.
///
/// The rows read the same as they did when the table answered with a number, which is the point —
/// a table that posts what a destination reported now posts all of it, and over one dimension "all
/// of it" is the number that was there before.
fn settled(end: &Outcome, evidence: &Evidence) -> (u64, PostingFlags) {
    let (lines, flags) = settle_lines(end, evidence);
    (
        lines
            .iter()
            .fold(0_u64, |acc, line| acc.saturating_add(line.quantity)),
        flags,
    )
}

fn live_end() -> Outcome {
    Outcome::Failed(StepName::Route, ReasonCode::ClientGone)
}

#[test]
fn row_completed_with_a_reported_figure_posts_it() {
    let evidence = Evidence {
        completed: reported(4_200),
        accrued_floor: 90,
        ..Evidence::default()
    };
    assert_eq!(
        settled(&Outcome::Completed, &evidence),
        (4_200, PostingFlags::NONE)
    );
}

#[test]
fn row_completed_with_a_required_locator_missing_posts_zero_and_disputes_it() {
    let evidence = Evidence {
        completed: None,
        accrued_floor: 5_000,
        locator_required: true,
        ..Evidence::default()
    };
    let (amount, flags) = settled(&Outcome::Completed, &evidence);
    // Zero, not the floor: an upstream that reported no usage is billed nothing, exactly as before.
    assert_eq!(amount, 0);
    assert!(flags.contains(PostingFlags::ESTIMATED));
    assert!(flags.contains(PostingFlags::METER_DISPUTED));
}

#[test]
fn row_completed_with_no_card_requiring_a_locator_posts_zero_unflagged() {
    let evidence = Evidence::default();
    assert_eq!(
        settled(&Outcome::Completed, &evidence),
        (0, PostingFlags::NONE)
    );
}

#[test]
fn row_live_non_completed_with_a_reported_figure_posts_it() {
    let evidence = Evidence {
        completed: reported(700),
        ..Evidence::default()
    };
    assert_eq!(settled(&live_end(), &evidence), (700, PostingFlags::NONE));
}

#[test]
fn row_live_non_completed_ending_in_a_protocol_error_bills_nothing() {
    let evidence = Evidence {
        completed: reported(700),
        terminal_error: true,
        ..Evidence::default()
    };
    assert_eq!(settled(&live_end(), &evidence), (0, PostingFlags::NONE));
}

#[test]
fn row_live_non_completed_with_nothing_reported_posts_the_kernel_floor() {
    let evidence = Evidence {
        completed: None,
        accrued_floor: 1_234,
        ..Evidence::default()
    };
    assert_eq!(
        settled(&live_end(), &evidence),
        (1_234, PostingFlags::ESTIMATED)
    );
}

#[test]
fn row_recovered_with_a_dispatch_posts_the_last_checkpoint() {
    let evidence = Evidence {
        recovered: true,
        dispatched: true,
        checkpointed: 640,
        completed: reported(999_999),
        ..Evidence::default()
    };
    assert_eq!(
        settled(&live_end(), &evidence),
        (640, PostingFlags::RECOVERED)
    );
}

#[test]
fn row_recovered_with_no_dispatch_posts_zero_and_voids() {
    let evidence = Evidence {
        recovered: true,
        dispatched: false,
        checkpointed: 640,
        ..Evidence::default()
    };
    assert_eq!(settled(&live_end(), &evidence), (0, PostingFlags::VOIDED));
}

#[test]
fn row_two_reported_sources_disagreeing_posts_the_lower() {
    let evidence = Evidence {
        completed: reported(9_000),
        variance: Some((9_000, 4_000)),
        ..Evidence::default()
    };
    assert_eq!(
        settled(&Outcome::Completed, &evidence),
        (4_000, PostingFlags::METER_DISPUTED)
    );
}

#[test]
fn row_a_three_way_lane_mismatch_posts_the_cheaper_entry() {
    let evidence = Evidence {
        completed: reported(9_000),
        lane_mismatch: Some((3_000, 8_000)),
        variance: Some((9_000, 4_000)),
        ..Evidence::default()
    };
    // The lane mismatch is decided before the variance rule: the unit may not even be on the lane
    // the other two figures were priced against.
    assert_eq!(
        settled(&Outcome::Completed, &evidence),
        (3_000, PostingFlags::METER_DISPUTED)
    );
}

#[test]
fn row_a_lost_settle_record_keeps_the_amount_and_marks_it_unposted() {
    let evidence = Evidence {
        completed: reported(500),
        settle_record_lost: true,
        ..Evidence::default()
    };
    let (amount, flags) = settled(&Outcome::Completed, &evidence);
    assert_eq!(amount, 500);
    assert!(flags.contains(PostingFlags::UNPOSTED));
}

#[test]
fn no_row_ever_resolves_upward() {
    // Whatever the evidence, the amount posted is never more than the highest figure any source
    // reported. This is the property the whole table exists for.
    let cases = [
        Evidence {
            completed: reported(100),
            accrued_floor: 900,
            ..Evidence::default()
        },
        Evidence {
            completed: None,
            accrued_floor: 900,
            locator_required: true,
            ..Evidence::default()
        },
        Evidence {
            variance: Some((100, 900)),
            completed: reported(900),
            ..Evidence::default()
        },
        Evidence {
            recovered: true,
            dispatched: true,
            checkpointed: 100,
            accrued_floor: 900,
            ..Evidence::default()
        },
    ];
    for evidence in cases {
        for end in [Outcome::Completed, live_end()] {
            let (amount, _) = settled(&end, &evidence);
            let highest = evidence
                .completed
                .as_ref()
                .map_or(0, |c| {
                    c.dimensions()
                        .iter()
                        .fold(0_u64, |acc, d| acc.saturating_add(d.units))
                })
                .max(evidence.accrued_floor)
                .max(evidence.checkpointed);
            assert!(amount <= highest, "{evidence:?} at {end:?} posted {amount}");
        }
    }
}

// ── the fee ──────────────────────────────────────────────────────────────────────────────────────

/// WHAT THE UNIT IS: a client's request that selected an upstream. Nothing about the answer.
fn billable() -> FeeEvidence {
    FeeEvidence {
        client_open_or_one_shot: true,
        selected_upstream: true,
    }
}

/// WHAT THE ANSWER WAS, as the one step that saw it recorded it on the unit.
fn delivered() -> StatusLeg {
    StatusLeg {
        at: None,
        status: Some(StatusClass::Success),
        finish: Some(FinishClass::Complete),
        delivered: true,
        degraded: false,
        relayed_error: None,
    }
}

/// The fee for one unit and the head it saw, through the kernel's one decision.
fn fee(evidence: &FeeEvidence, head: Option<&StatusLeg>) -> (u32, PostingFlags) {
    fee_count(evidence, head)
}

#[test]
fn the_fee_posts_once_on_a_relayed_success() {
    assert_eq!(
        fee(&billable(), Some(&delivered())),
        (1, PostingFlags::NONE)
    );
}

#[test]
fn a_provider_push_posts_no_fee() {
    let evidence = FeeEvidence {
        client_open_or_one_shot: false,
        ..billable()
    };
    assert_eq!(fee(&evidence, Some(&delivered())), (0, PostingFlags::NONE));
}

#[test]
fn a_unit_that_never_relayed_a_response_frame_posts_no_fee() {
    let head = StatusLeg {
        delivered: false,
        ..delivered()
    };
    assert_eq!(fee(&billable(), Some(&head)), (0, PostingFlags::NONE));
    // And a unit that recorded no head at all relayed nothing either, which is the same answer.
    assert_eq!(fee(&billable(), None), (0, PostingFlags::NONE));
}

#[test]
fn a_non_success_status_posts_no_fee() {
    let head = StatusLeg {
        status: Some(StatusClass::ServerError),
        finish: Some(FinishClass::Error),
        ..delivered()
    };
    assert_eq!(fee(&billable(), Some(&head)), (0, PostingFlags::NONE));
}

#[test]
fn with_no_transport_status_the_planes_finish_decides_alone() {
    let head = StatusLeg {
        status: None,
        finish: Some(FinishClass::Partial),
        ..delivered()
    };
    // A partial answer is still an answer: only an error finish posts nothing.
    assert_eq!(fee(&billable(), Some(&head)), (1, PostingFlags::NONE));

    let errored = StatusLeg {
        status: None,
        finish: Some(FinishClass::Error),
        ..delivered()
    };
    assert_eq!(fee(&billable(), Some(&errored)), (0, PostingFlags::NONE));
}

#[test]
fn a_stream_that_dies_before_its_status_trailer_posts_nothing() {
    // The transport reports its status on the terminal frame, and the stream ended before it.
    let no_trailer = StatusLeg {
        at: Some(StatusAt::Terminal),
        status: None,
        finish: Some(FinishClass::Partial),
        ..delivered()
    };
    assert_eq!(fee(&billable(), Some(&no_trailer)), (0, PostingFlags::NONE));

    // The plane says the answer was whole against a status that never arrived. That is the second
    // source disagreeing with the first, so it is the lower figure and a dispute.
    let claiming_complete = StatusLeg {
        at: Some(StatusAt::Terminal),
        status: None,
        finish: Some(FinishClass::Complete),
        ..delivered()
    };
    assert_eq!(
        fee(&billable(), Some(&claiming_complete)),
        (0, PostingFlags::METER_DISPUTED)
    );

    // The trailer that did arrive still bills, on both kinds of transport.
    for at in [StatusAt::FirstFrame, StatusAt::Terminal] {
        let arrived = StatusLeg {
            at: Some(at),
            status: Some(StatusClass::Success),
            ..delivered()
        };
        assert_eq!(fee(&billable(), Some(&arrived)), (1, PostingFlags::NONE));
    }
}

/// EVERY combination of the three legs the fee is decided from, written out as data rather than as
/// a second copy of the rule: where the transport says its status is reported, what it reported
/// there, and what the plane said about the same exchange. This is the ONE table the fee has —
/// there is no second spelling of it in a unit crate to drift from, and the arms a two-valued
/// spelling cannot express (a `Partial` finish, a trailer that never arrived) each have a row.
#[test]
fn the_fee_table_is_exhaustive_over_status_placement_status_class_and_finish() {
    #[allow(clippy::type_complexity)]
    let rows: &[(
        Option<StatusAt>,
        Option<StatusClass>,
        Option<FinishClass>,
        u32,
        bool,
    )] = &[
        (None, None, None, 1, false),
        (None, None, Some(FinishClass::Complete), 1, false),
        (None, None, Some(FinishClass::TurnComplete), 1, false),
        (None, None, Some(FinishClass::Partial), 1, false),
        (None, None, Some(FinishClass::Error), 0, false),
        (None, Some(StatusClass::Success), None, 1, false),
        (
            None,
            Some(StatusClass::Success),
            Some(FinishClass::Complete),
            1,
            false,
        ),
        (
            None,
            Some(StatusClass::Success),
            Some(FinishClass::TurnComplete),
            1,
            false,
        ),
        (
            None,
            Some(StatusClass::Success),
            Some(FinishClass::Partial),
            1,
            false,
        ),
        (
            None,
            Some(StatusClass::Success),
            Some(FinishClass::Error),
            1,
            true,
        ),
        (None, Some(StatusClass::ClientError), None, 0, false),
        (
            None,
            Some(StatusClass::ClientError),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::ClientError),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::ClientError),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::ClientError),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (None, Some(StatusClass::ServerError), None, 0, false),
        (
            None,
            Some(StatusClass::ServerError),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::ServerError),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::ServerError),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::ServerError),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (None, Some(StatusClass::Other), None, 0, false),
        (
            None,
            Some(StatusClass::Other),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::Other),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::Other),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            None,
            Some(StatusClass::Other),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (Some(StatusAt::FirstFrame), None, None, 0, false),
        (
            Some(StatusAt::FirstFrame),
            None,
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            None,
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            None,
            Some(FinishClass::Partial),
            0,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            None,
            Some(FinishClass::Error),
            0,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Success),
            None,
            1,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Success),
            Some(FinishClass::Complete),
            1,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Success),
            Some(FinishClass::TurnComplete),
            1,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Success),
            Some(FinishClass::Partial),
            1,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Success),
            Some(FinishClass::Error),
            1,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ClientError),
            None,
            0,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ClientError),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ClientError),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ClientError),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ClientError),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ServerError),
            None,
            0,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ServerError),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ServerError),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ServerError),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::ServerError),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Other),
            None,
            0,
            false,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Other),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Other),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Other),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            Some(StatusAt::FirstFrame),
            Some(StatusClass::Other),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (Some(StatusAt::Terminal), None, None, 0, false),
        (
            Some(StatusAt::Terminal),
            None,
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            None,
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            None,
            Some(FinishClass::Partial),
            0,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            None,
            Some(FinishClass::Error),
            0,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Success),
            None,
            1,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Success),
            Some(FinishClass::Complete),
            1,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Success),
            Some(FinishClass::TurnComplete),
            1,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Success),
            Some(FinishClass::Partial),
            1,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Success),
            Some(FinishClass::Error),
            1,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ClientError),
            None,
            0,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ClientError),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ClientError),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ClientError),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ClientError),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ServerError),
            None,
            0,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ServerError),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ServerError),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ServerError),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::ServerError),
            Some(FinishClass::Error),
            0,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Other),
            None,
            0,
            false,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Other),
            Some(FinishClass::Complete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Other),
            Some(FinishClass::TurnComplete),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Other),
            Some(FinishClass::Partial),
            0,
            true,
        ),
        (
            Some(StatusAt::Terminal),
            Some(StatusClass::Other),
            Some(FinishClass::Error),
            0,
            false,
        ),
    ];
    assert_eq!(
        rows.len(),
        3 * 5 * 5,
        "one row per combination, none skipped"
    );
    for &(status_at, status, finish, expected_fee, disputed) in rows {
        let head = StatusLeg {
            at: status_at,
            status,
            finish,
            ..delivered()
        };
        let expected = if disputed {
            PostingFlags::METER_DISPUTED
        } else {
            PostingFlags::NONE
        };
        assert_eq!(
            fee_count(&billable(), Some(&head)),
            (expected_fee, expected),
            "at {status_at:?} / {status:?} / {finish:?}"
        );
        // The three preconditions dominate the whole table: fail any one and the row posts nothing,
        // undisputed, whatever the evidence says. Two of them are facts about the UNIT and the
        // third is the head's own — a unit with no head recorded relayed nothing.
        let ineligible: [(FeeEvidence, Option<&StatusLeg>); 4] = [
            (
                FeeEvidence {
                    client_open_or_one_shot: false,
                    ..billable()
                },
                Some(&head),
            ),
            (
                FeeEvidence {
                    selected_upstream: false,
                    ..billable()
                },
                Some(&head),
            ),
            (billable(), None),
            (
                billable(),
                Some(&StatusLeg {
                    delivered: false,
                    ..head
                }),
            ),
        ];
        for (evidence, head) in ineligible {
            assert_eq!(
                fee_count(&evidence, head),
                (0, PostingFlags::NONE),
                "ineligible at {status_at:?} / {status:?} / {finish:?}"
            );
        }
    }
}

/// Which side of the fee line a route landed on is the DESTINATION KIND's answer, read from the
/// contract's own predicate rather than restated anywhere else: an upstream leg and a session
/// upstream carry the fee, a kernel verb, an accrual tick and an upgrade do not.
#[test]
fn the_upstream_leg_of_the_fee_is_the_destination_kinds_answer() {
    let posts = |dest: DestinationFacts| {
        fee_count(
            &FeeEvidence {
                selected_upstream: dest.is_upstream_kind(),
                ..billable()
            },
            Some(&delivered()),
        )
    };
    assert_eq!(
        posts(DestinationFacts::Upstream {
            transport: "http",
            address: UpstreamAddress::socket("api.example:443"),
            lane: LaneId::new("gold"),
        }),
        (1, PostingFlags::NONE)
    );
    assert_eq!(
        posts(DestinationFacts::SessionUpstream {
            upstream: UpstreamIdx(0),
            stream: None,
            lane: LaneId::new("gold"),
        }),
        (1, PostingFlags::NONE)
    );
    for other in [
        DestinationFacts::KernelVerb { verb: "health" },
        DestinationFacts::SessionAccrual {
            lane: LaneId::new("gold"),
        },
        DestinationFacts::Upgrade { to: "ws" },
    ] {
        assert_eq!(
            posts(other),
            (0, PostingFlags::NONE),
            "{other:?} carries no fee"
        );
    }
}

// ── the request slot ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_client_unit_with_an_upstream_draws_one_slot_and_never_gets_it_back() {
    let drawn = requests_drawn(OriginKind::Client, true);
    assert_eq!(drawn, 1);
    // Whatever the end, a unit that reached the door keeps the slot: failures cannot escape a cap.
    assert_eq!(requests_settled(true, drawn), 1);
    // A unit refused before the door drew nothing.
    assert_eq!(requests_settled(false, drawn), 0);
}

#[test]
fn a_provider_push_and_a_unit_with_no_upstream_draw_no_slot() {
    assert_eq!(requests_drawn(OriginKind::Provider, true), 0);
    assert_eq!(requests_drawn(OriginKind::Client, false), 0);
    assert_eq!(requests_drawn(OriginKind::Tick, true), 0);
}

// ------------------------------------------------------------------------------------------------
// THE ONE POLICY FOR A CONTRADICTED FEE
// ------------------------------------------------------------------------------------------------

/// **WHEN THE TWO SOURCES CONTRADICT EACH OTHER, THE FRAME THE CLIENT SAW DECIDES — AND THE POSTING
/// SAYS SO.**
///
/// A unit has two readings of how it ended: the status the transport reported on the frame it says
/// it reports one on, and the finish the plane afterwards gives. Most of the time they agree. When
/// they do not, one of two things has happened — an answer that started well and then died, or a
/// plane that is not telling the truth about its own finish — and the fee cannot wait to find out
/// which.
///
/// The rule is the one the previous release already billed by, stated here as a rule rather than
/// left implicit in six providers' worth of stream handling: **the fee is decided at the first
/// frame the client actually saw, and no later abort reverses it.** A response that was good at the
/// moment it started was a response. What the contradiction changes is not the count — it is that
/// the posting is MARKED, so a plane whose finishes routinely disagree with its own wire shows up
/// on the disputes report instead of quietly billing like everyone else.
///
/// The other direction is the same rule and a different answer: a status that says the request
/// failed, against a plane claiming a whole answer, posts NOTHING. The client saw a failure; a
/// plane cannot bill over the top of it by asserting otherwise.
///
/// One function, one policy, every plane. Changing what a contradicted fee costs is one edit at one
/// site — a pricing decision somebody makes on purpose — and not a structural gap that has to be
/// found first.
#[test]
fn a_contradicted_fee_is_decided_at_the_frame_the_client_saw() {
    for at in [StatusAt::FirstFrame, StatusAt::Terminal] {
        // The client saw an answered request; the plane says it ended badly. Billed, and disputed.
        let died_after_a_good_frame = StatusLeg {
            at: Some(at),
            status: Some(StatusClass::Success),
            finish: Some(FinishClass::Error),
            ..delivered()
        };
        assert_eq!(
            fee_count(&billable(), Some(&died_after_a_good_frame)),
            (1, PostingFlags::METER_DISPUTED),
            "a stream that dies halfway through a good response was still a good response at the \
             moment it started, on every transport that reports a status at all"
        );

        // The client saw a failure; the plane claims a whole answer. Not billed, and disputed.
        for claimed in [
            FinishClass::Complete,
            FinishClass::TurnComplete,
            FinishClass::Partial,
        ] {
            for failed in [StatusClass::ClientError, StatusClass::ServerError] {
                let claiming_over_a_failure = StatusLeg {
                    at: Some(at),
                    status: Some(failed),
                    finish: Some(claimed),
                    ..delivered()
                };
                assert_eq!(
                    fee_count(&billable(), Some(&claiming_over_a_failure)),
                    (0, PostingFlags::METER_DISPUTED),
                    "a plane cannot bill over the top of a failure the client was handed"
                );
            }
        }
    }
}

/// **A PLANE THAT DECLARES NO STATUS LEG IS UNCHANGED BY ANY OF THIS.**
///
/// The contradiction arm needs two readings, and a dialect whose answer document IS the whole of
/// the evidence has one. Its finish decides alone, exactly as it did — which is what makes the
/// declaration a real answer rather than a way of opting out of the arm.
#[test]
fn a_plane_that_declares_no_status_leg_is_decided_by_its_finish_alone() {
    for finish in [
        FinishClass::Complete,
        FinishClass::TurnComplete,
        FinishClass::Partial,
        FinishClass::Error,
    ] {
        let no_leg = StatusLeg {
            at: None,
            status: None,
            finish: Some(finish),
            ..delivered()
        };
        let expected = u32::from(finish != FinishClass::Error);
        assert_eq!(
            fee_count(&billable(), Some(&no_leg)),
            (expected, PostingFlags::NONE),
            "no second reading exists, so there is nothing to contradict and nothing to dispute"
        );
    }
}

/// **THE DISPUTE POLICY IS A VALUE, AND ITS DEFAULT IS WHAT THE NODE HAS ALWAYS BILLED.**
///
/// Three variants, each the answer some deployment would want, all of them marking the posting so
/// that the disagreement is on the disputes report whichever one is in force. The DEFAULT is the
/// one this release ships and the one the recorded corpus was billed under: the frame the client
/// saw decides.
///
/// Pinned as a value rather than checked through `fee_count` alone, because what a contradicted
/// fee costs is a pricing decision and a pricing decision that can only be observed by running the
/// thing that uses it is a pricing decision nobody can quote.
#[test]
fn the_dispute_policy_is_a_value_whose_default_is_the_frame_the_client_saw() {
    assert_eq!(
        DisputePolicy::default(),
        DisputePolicy::TheFrameTheClientSaw,
        "the shipped default is the rule the recorded corpus was billed under; changing it is a \
         pricing decision somebody makes on purpose, and this line is where they see it"
    );

    // The two readings, both ways round, under all three variants.
    for (status_says_answered, finish_says_answered) in [(true, false), (false, true)] {
        assert_eq!(
            DisputePolicy::TheFrameTheClientSaw.decide(status_says_answered, finish_says_answered),
            (
                u32::from(status_says_answered),
                PostingFlags::METER_DISPUTED
            ),
        );
        assert_eq!(
            DisputePolicy::ThePlanesFinish.decide(status_says_answered, finish_says_answered),
            (
                u32::from(finish_says_answered),
                PostingFlags::METER_DISPUTED
            ),
        );
        assert_eq!(
            DisputePolicy::NeitherReading.decide(status_says_answered, finish_says_answered),
            (0, PostingFlags::METER_DISPUTED),
        );
    }
}

/// **THE FEE APPLIES THE DEFAULT POLICY AND NOTHING ELSE.**
///
/// The one site the policy is read at is inside `fee_count`, so this drives the fee and checks the
/// answer against the policy VALUE rather than against a number written twice. If the site ever
/// stops applying the policy — or starts applying a different one for one kind of plane — the two
/// sides of this assertion part.
#[test]
fn the_fee_applies_the_dispute_policy_and_the_policy_alone() {
    for at in [StatusAt::FirstFrame, StatusAt::Terminal] {
        for (status, status_says_answered) in [
            (StatusClass::Success, true),
            (StatusClass::ServerError, false),
        ] {
            for (finish, finish_says_answered) in
                [(FinishClass::Complete, true), (FinishClass::Error, false)]
            {
                if status_says_answered == finish_says_answered {
                    continue;
                }
                let contradicted = StatusLeg {
                    at: Some(at),
                    status: Some(status),
                    finish: Some(finish),
                    ..delivered()
                };
                assert_eq!(
                    fee_count(&billable(), Some(&contradicted)),
                    DisputePolicy::default().decide(status_says_answered, finish_says_answered),
                );
            }
        }
    }
}
