// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement table, row by row, and the two quantity rules beside it.
//!
//! Every row says the same thing in a different situation: post the lower evidence, mark it, and
//! put it where someone will look at it. These are the rows.

use busbar_caps::OriginKind;
use busbar_caps::{Outcome, PostingFlags, ReasonCode, StepName};
use busbar_contract::{DestinationFacts, LaneId, UpstreamAddress, UpstreamIdx};
use busbar_kernel::teller::{
    fee_count, requests_drawn, requests_settled, settle_amount, Evidence, FeeEvidence, FinishClass,
    StatusAt, StatusClass,
};

fn live_end() -> Outcome {
    Outcome::Failed(StepName::Route, ReasonCode::ClientGone)
}

#[test]
fn row_completed_with_a_located_figure_posts_it() {
    let evidence = Evidence {
        located: Some(4_200),
        accrued_floor: 90,
        ..Evidence::default()
    };
    assert_eq!(
        settle_amount(&Outcome::Completed, &evidence),
        (4_200, PostingFlags::NONE)
    );
}

#[test]
fn row_completed_with_a_required_locator_missing_posts_zero_and_disputes_it() {
    let evidence = Evidence {
        located: None,
        accrued_floor: 5_000,
        locator_required: true,
        ..Evidence::default()
    };
    let (amount, flags) = settle_amount(&Outcome::Completed, &evidence);
    // Zero, not the floor: an upstream that reported no usage is billed nothing, exactly as before.
    assert_eq!(amount, 0);
    assert!(flags.contains(PostingFlags::ESTIMATED));
    assert!(flags.contains(PostingFlags::METER_DISPUTED));
}

#[test]
fn row_completed_with_no_card_requiring_a_locator_posts_zero_unflagged() {
    let evidence = Evidence::default();
    assert_eq!(
        settle_amount(&Outcome::Completed, &evidence),
        (0, PostingFlags::NONE)
    );
}

#[test]
fn row_live_non_completed_with_a_located_figure_posts_it() {
    let evidence = Evidence {
        located: Some(700),
        ..Evidence::default()
    };
    assert_eq!(
        settle_amount(&live_end(), &evidence),
        (700, PostingFlags::NONE)
    );
}

#[test]
fn row_live_non_completed_ending_in_a_protocol_error_bills_nothing() {
    let evidence = Evidence {
        located: Some(700),
        terminal_error: true,
        ..Evidence::default()
    };
    assert_eq!(
        settle_amount(&live_end(), &evidence),
        (0, PostingFlags::NONE)
    );
}

#[test]
fn row_live_non_completed_with_nothing_located_posts_the_kernel_floor() {
    let evidence = Evidence {
        located: None,
        accrued_floor: 1_234,
        ..Evidence::default()
    };
    assert_eq!(
        settle_amount(&live_end(), &evidence),
        (1_234, PostingFlags::ESTIMATED)
    );
}

#[test]
fn row_recovered_with_a_dispatch_posts_the_last_checkpoint() {
    let evidence = Evidence {
        recovered: true,
        dispatched: true,
        checkpointed: 640,
        located: Some(999_999),
        ..Evidence::default()
    };
    assert_eq!(
        settle_amount(&live_end(), &evidence),
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
    assert_eq!(
        settle_amount(&live_end(), &evidence),
        (0, PostingFlags::VOIDED)
    );
}

#[test]
fn row_two_reported_sources_disagreeing_posts_the_lower() {
    let evidence = Evidence {
        located: Some(9_000),
        variance: Some((9_000, 4_000)),
        ..Evidence::default()
    };
    assert_eq!(
        settle_amount(&Outcome::Completed, &evidence),
        (4_000, PostingFlags::METER_DISPUTED)
    );
}

#[test]
fn row_a_three_way_lane_mismatch_posts_the_cheaper_entry() {
    let evidence = Evidence {
        located: Some(9_000),
        lane_mismatch: Some((3_000, 8_000)),
        variance: Some((9_000, 4_000)),
        ..Evidence::default()
    };
    // The lane mismatch is decided before the variance rule: the unit may not even be on the lane
    // the other two figures were priced against.
    assert_eq!(
        settle_amount(&Outcome::Completed, &evidence),
        (3_000, PostingFlags::METER_DISPUTED)
    );
}

#[test]
fn row_a_lost_settle_record_keeps_the_amount_and_marks_it_unposted() {
    let evidence = Evidence {
        located: Some(500),
        settle_record_lost: true,
        ..Evidence::default()
    };
    let (amount, flags) = settle_amount(&Outcome::Completed, &evidence);
    assert_eq!(amount, 500);
    assert!(flags.contains(PostingFlags::UNPOSTED));
}

#[test]
fn no_row_ever_resolves_upward() {
    // Whatever the evidence, the amount posted is never more than the highest figure any source
    // reported. This is the property the whole table exists for.
    let cases = [
        Evidence {
            located: Some(100),
            accrued_floor: 900,
            ..Evidence::default()
        },
        Evidence {
            located: None,
            accrued_floor: 900,
            locator_required: true,
            ..Evidence::default()
        },
        Evidence {
            variance: Some((100, 900)),
            located: Some(900),
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
            let (amount, _) = settle_amount(&end, &evidence);
            let highest = evidence
                .located
                .unwrap_or(0)
                .max(evidence.accrued_floor)
                .max(evidence.checkpointed);
            assert!(amount <= highest, "{evidence:?} at {end:?} posted {amount}");
        }
    }
}

// ── the fee ──────────────────────────────────────────────────────────────────────────────────────

fn billable() -> FeeEvidence {
    FeeEvidence {
        client_open_or_one_shot: true,
        selected_upstream: true,
        relayed_first_response_frame: true,
        status_at: None,
        status: Some(StatusClass::Success),
        finish: Some(FinishClass::Complete),
    }
}

#[test]
fn the_fee_posts_once_on_a_relayed_success() {
    assert_eq!(fee_count(&billable()), (1, PostingFlags::NONE));
}

#[test]
fn a_provider_push_posts_no_fee() {
    let evidence = FeeEvidence {
        client_open_or_one_shot: false,
        ..billable()
    };
    assert_eq!(fee_count(&evidence), (0, PostingFlags::NONE));
}

#[test]
fn a_unit_that_never_relayed_a_response_frame_posts_no_fee() {
    let evidence = FeeEvidence {
        relayed_first_response_frame: false,
        ..billable()
    };
    assert_eq!(fee_count(&evidence), (0, PostingFlags::NONE));
}

#[test]
fn a_non_success_status_posts_no_fee() {
    let evidence = FeeEvidence {
        status: Some(StatusClass::ServerError),
        finish: Some(FinishClass::Error),
        ..billable()
    };
    assert_eq!(fee_count(&evidence), (0, PostingFlags::NONE));
}

#[test]
fn a_plane_whose_finish_contradicts_the_status_posts_the_lower_and_disputes_it() {
    let lying = FeeEvidence {
        status: Some(StatusClass::Success),
        finish: Some(FinishClass::Error),
        ..billable()
    };
    assert_eq!(fee_count(&lying), (0, PostingFlags::METER_DISPUTED));

    let other_way = FeeEvidence {
        status: Some(StatusClass::ServerError),
        finish: Some(FinishClass::Complete),
        ..billable()
    };
    assert_eq!(fee_count(&other_way), (0, PostingFlags::METER_DISPUTED));
}

#[test]
fn with_no_transport_status_the_planes_finish_decides_alone() {
    let evidence = FeeEvidence {
        status: None,
        finish: Some(FinishClass::Partial),
        ..billable()
    };
    // A partial answer is still an answer: only an error finish posts nothing.
    assert_eq!(fee_count(&evidence), (1, PostingFlags::NONE));

    let errored = FeeEvidence {
        status: None,
        finish: Some(FinishClass::Error),
        ..billable()
    };
    assert_eq!(fee_count(&errored), (0, PostingFlags::NONE));
}

#[test]
fn a_stream_that_dies_before_its_status_trailer_posts_nothing() {
    // The transport reports its status on the terminal frame, and the stream ended before it.
    let no_trailer = FeeEvidence {
        status_at: Some(StatusAt::Terminal),
        status: None,
        finish: Some(FinishClass::Partial),
        ..billable()
    };
    assert_eq!(fee_count(&no_trailer), (0, PostingFlags::NONE));

    // The plane says the answer was whole against a status that never arrived. That is the second
    // source disagreeing with the first, so it is the lower figure and a dispute.
    let claiming_complete = FeeEvidence {
        status_at: Some(StatusAt::Terminal),
        status: None,
        finish: Some(FinishClass::Complete),
        ..billable()
    };
    assert_eq!(
        fee_count(&claiming_complete),
        (0, PostingFlags::METER_DISPUTED)
    );

    // The trailer that did arrive still bills, on both kinds of transport.
    for at in [StatusAt::FirstFrame, StatusAt::Terminal] {
        let arrived = FeeEvidence {
            status_at: Some(at),
            status: Some(StatusClass::Success),
            ..billable()
        };
        assert_eq!(fee_count(&arrived), (1, PostingFlags::NONE));
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
            0,
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
            0,
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
            0,
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
    for &(status_at, status, finish, fee, disputed) in rows {
        let evidence = FeeEvidence {
            status_at,
            status,
            finish,
            ..billable()
        };
        let expected = if disputed {
            PostingFlags::METER_DISPUTED
        } else {
            PostingFlags::NONE
        };
        assert_eq!(
            fee_count(&evidence),
            (fee, expected),
            "at {status_at:?} / {status:?} / {finish:?}"
        );
        // The three preconditions dominate the whole table: fail any one and the row posts nothing,
        // undisputed, whatever the evidence says.
        for ineligible in [
            FeeEvidence {
                client_open_or_one_shot: false,
                ..evidence
            },
            FeeEvidence {
                selected_upstream: false,
                ..evidence
            },
            FeeEvidence {
                relayed_first_response_frame: false,
                ..evidence
            },
        ] {
            assert_eq!(
                fee_count(&ineligible),
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
        fee_count(&FeeEvidence {
            selected_upstream: dest.is_upstream_kind(),
            ..billable()
        })
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
