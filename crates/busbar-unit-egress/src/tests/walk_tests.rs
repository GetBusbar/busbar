// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The walk: how many attempts, which cell they record against, when a failure fails over, and
//! when it does not.
//!
//! Carried over from the previous release's pool-cell and reroute tests. The claims are the same:
//! a member that cannot be reached at all is failed over from; a member that answered is not; the
//! outcome lands on the ROUTING pool's cell and not the default one; the hop cap is a hop cap and
//! not an attempt cap; and the request budget is spent once, after the success, and given back
//! when the answer does not arrive whole.

use busbar_contract_transport::wire::StatusClass;
use busbar_contract_transport::wire::TransportError;
use busbar_contract_transport::wire::WireStatus;

use super::harness::{frame, frame_with_upstream, ok_frames, Health, Script};
use super::{member, Node};
use crate::ports::{disposition, Outcome};
use crate::wire::RouteOutcome;
use busbar_contract::DestinationId;

fn two_lane_pool() -> Node {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node
}

#[test]
fn a_member_that_cannot_be_dialled_is_failed_over_from() {
    let node = two_lane_pool();
    node.transport
        .script("a", Script::DialError(TransportError::Refused));
    node.transport.script("b", Script::Frames(ok_frames()));
    // Ask for `a` first, so the failure is the one under test rather than a rotation accident.
    let mut node = node;
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);

    let outcome = node.route("primary");
    match outcome {
        RouteOutcome::Delivered(delivered) => {
            assert_eq!(delivered.destination, DestinationId::new(1));
            assert_eq!(delivered.pool, "primary");
        }
        other => panic!("expected the sibling to serve, got {other:?}"),
    }
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }],
        "the failure is recorded against the ROUTING pool's cell"
    );
    assert!(
        node.breaker.outcomes("", DestinationId::new(0)).is_empty(),
        "and never against the default cell"
    );
}

#[test]
fn a_success_closes_the_routing_pools_cell_and_not_the_default_one() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success]
    );
    assert!(node.breaker.outcomes("", DestinationId::new(0)).is_empty());
}

#[test]
fn the_walk_takes_the_hop_cap_plus_one_attempts() {
    let mut node = Node::with_lanes(&["a", "b", "c", "d", "e"]);
    node.pool(
        "primary",
        (0..5)
            .map(|d| member(DestinationId::new(d), &format!("m{d}")))
            .collect(),
    );
    node.tune("primary", |p| p.failover.max_hops = 3);
    for lane in ["a", "b", "c", "d", "e"] {
        node.transport
            .script(lane, Script::DialError(TransportError::Refused));
    }

    let outcome = node.route("primary");
    assert!(outcome.shed().is_some(), "every attempt failed");
    let attempts = node.telemetry.attempts.lock().unwrap().len();
    assert_eq!(
        attempts, 4,
        "a cap of three hops attempts four members: the first attempt is not a hop"
    );
}

#[test]
fn there_is_no_failover_after_the_first_byte() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    // The first frame is relayed and then the upstream dies before its terminal frame. The client
    // already has part of the answer, so the walk must not try the sibling.
    node.transport.script(
        "a",
        Script::Truncated(frame(Some(StatusClass::Success), "head")),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    match outcome {
        RouteOutcome::Delivered(delivered) => {
            assert_eq!(
                delivered.destination,
                DestinationId::new(0),
                "the answer stays with the member that started it"
            );
            assert_eq!(delivered.frames, 1);
        }
        other => panic!("expected the truncated answer to be returned, got {other:?}"),
    }
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().len(),
        1,
        "only one member was ever attempted"
    );
}

#[test]
fn a_truncated_answer_gives_the_request_budget_unit_back() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Truncated(frame(Some(StatusClass::Success), "head")),
    );

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        0,
        "the unit spent on the success is given back when the body does not arrive whole"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success, Outcome::Transient { retry_after: None }],
        "and the failed transfer is recorded as a compensating transient"
    );
}

#[test]
fn a_whole_answer_keeps_the_request_budget_unit() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        1,
        "the charge stands"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success]
    );
}

#[test]
fn the_callers_own_fault_is_relayed_and_the_member_is_not_penalised() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Frames(vec![frame(Some(StatusClass::ClientError), "bad")]),
    );

    let outcome = node.route("primary");
    match outcome {
        RouteOutcome::Delivered(delivered) => {
            assert_eq!(delivered.destination, DestinationId::new(0));
            assert_eq!(delivered.status, Some(StatusClass::ClientError));
        }
        other => panic!("expected the client fault to be relayed, got {other:?}"),
    }
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::RecordNothing],
        "the caller's bad input is not the member's fault"
    );
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().len(),
        1,
        "and it does not fail over"
    );
}

#[test]
fn a_member_that_answers_with_a_server_error_is_failed_over_from() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Frames(vec![frame(Some(StatusClass::ServerError), "boom")]),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1))
    );
    assert_eq!(
        node.telemetry.failovers.lock().unwrap().as_slice(),
        &[("primary".to_string(), disposition::TRANSIENT)]
    );
}

/// A withdrawn credential answers 403, and 403 is a 4xx — so the coarse class alone says
/// `ClientError`, which is the caller's own fault and penalises nothing. The exact number is the
/// only thing that tells the two apart, and it has to reach the classifier for the destination to
/// go down. The verdict here is stated against the NUMBER: a walk that hands the classifier no
/// number falls through to the coarse-class default and relays instead of failing over.
#[test]
fn a_403_reaches_the_classifier_as_a_403_and_the_destination_goes_hard_down() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.breaker.set_verdict(
        WireStatus::Http(403),
        crate::ports::Classified {
            disposition: crate::ports::Disposition::HardDown,
            outcome: Outcome::HardDown,
            label: disposition::HARD_DOWN,
        },
    );
    node.transport.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(StatusClass::ClientError),
            Some(WireStatus::Http(403)),
            None,
            "forbidden",
        )]),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert_eq!(
        node.breaker
            .classified
            .lock()
            .unwrap()
            .first()
            .map(|s| s.code),
        Some(Some(WireStatus::Http(403))),
        "the upstream's own number crossed the seam, not just the 4xx class"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::HardDown],
        "and the destination is recorded hard-down, which is what fans out to its siblings"
    );
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1)),
        "a hard-down member is failed over from, never relayed: {outcome:?}"
    );
}

/// The wait an upstream asks for is a fact about THAT answer, and the only layer that ever sees it
/// is the transport that read the response head. It has to arrive at the classifier or the
/// cooldown is computed from the ladder alone and the upstream's floor is silently dropped.
#[test]
fn a_429_carries_the_upstreams_own_retry_after_through_to_the_breaker() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(StatusClass::ClientError),
            Some(WireStatus::Http(429)),
            Some(7),
            "slow down",
        )]),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(seen.map(|s| s.code), Some(Some(WireStatus::Http(429))));
    assert_eq!(
        seen.map(|s| s.retry_after),
        Some(Some(7)),
        "the seven seconds the upstream asked for reached the classifier"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient {
            retry_after: Some(7)
        }],
        "and it is what the breaker is told to floor the cooldown at"
    );
}

/// The other half of the same claim: an upstream that asked for nothing must not have a wait
/// invented for it. `None` here is what leaves the cooldown to the ladder.
#[test]
fn a_server_error_with_no_retry_after_leaves_the_cooldown_to_the_ladder() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(StatusClass::ServerError),
            Some(WireStatus::Http(503)),
            None,
            "boom",
        )]),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(seen.map(|s| s.code), Some(Some(WireStatus::Http(503))));
    assert_eq!(seen.map(|s| s.retry_after), Some(None));
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }],
    );
}

/// A gRPC upstream that refuses with a trailers-only `UNAVAILABLE`. The frame the grpc transport
/// hands up carries `Grpc(14)` — gRPC's number, named as gRPC's — and the walk must do with it
/// exactly what it does with an HTTP 503: record a transient failure against the destination and
/// fail over to the sibling.
///
/// The number alone did neither. `14` matched no HTTP band, classified as the caller's fault, and
/// the walk relayed a dead upstream's refusal without recording anything or trying the next member.
#[test]
fn a_grpc_unavailable_records_a_failure_and_fails_over() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script(
        "a",
        Script::Frames(vec![frame_with_upstream(
            Some(StatusClass::ServerError),
            Some(WireStatus::Grpc(14)),
            None,
            "",
        )]),
    );
    node.transport.script("b", Script::Frames(ok_frames()));

    assert!(
        node.route("primary").is_delivered(),
        "the walk failed over to the sibling rather than relaying the refusal"
    );
    let seen = node.breaker.classified.lock().unwrap().first().copied();
    assert_eq!(
        seen.map(|s| s.code),
        Some(Some(WireStatus::Grpc(14))),
        "the number crossed the seam WITH the numbering that spelled it"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Transient { retry_after: None }],
        "and the destination that said UNAVAILABLE was recorded against"
    );
}

#[test]
fn a_request_too_large_excludes_every_member_with_the_same_or_a_smaller_window() {
    let mut node = Node::with_lanes(&["a", "b", "c"]);
    let mut members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
        member(DestinationId::new(2), "c"),
    ];
    members[0].context_max = Some(8_000);
    members[1].context_max = Some(8_000);
    members[2].context_max = Some(200_000);
    node.pool("primary", members);
    node.preference = Some(vec![
        DestinationId::new(0),
        DestinationId::new(1),
        DestinationId::new(2),
    ]);
    // The classifier says this answer means the request was too big for the member's window.
    node.breaker.set_verdict(
        WireStatus::Http(0),
        crate::ports::Classified {
            disposition: crate::ports::Disposition::ContextLength,
            outcome: Outcome::RecordNothing,
            label: disposition::CONTEXT_LENGTH,
        },
    );
    let too_big = frame(Some(StatusClass::ClientError), "too big");
    node.transport
        .script("a", Script::Frames(vec![too_big.clone()]));
    node.transport.script("b", Script::Frames(vec![too_big]));
    node.transport.script("c", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(2)),
        "the sibling that shares the window that just refused it is excluded too: {outcome:?}"
    );
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().len(),
        2,
        "the equal-window sibling is never attempted"
    );
}

#[test]
fn a_dispatch_that_cannot_be_recorded_sends_nothing() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    *node.journal.fail.lock().unwrap() = true;

    let outcome = node.route("primary");
    let shed = outcome.shed().expect("a refusal");
    assert_eq!(shed.status, crate::wire::STATUS_INTERNAL_ERROR);
    assert!(
        node.transport.dialled.lock().unwrap().is_empty(),
        "the record is durable BEFORE the dial, so a failed record means no dial at all"
    );
    assert!(
        node.breaker
            .outcomes("primary", DestinationId::new(0))
            .is_empty(),
        "and nothing is recorded against the member"
    );
}

#[test]
fn every_attempt_is_recorded_before_its_dial() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport
        .script("a", Script::DialError(TransportError::Refused));
    node.transport.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let dispatched = node.journal.dispatched.lock().unwrap();
    assert_eq!(dispatched.len(), 2, "one record per attempt");
    assert_eq!(dispatched[0].destination, DestinationId::new(0));
    assert_eq!(dispatched[0].attempt, 1);
    assert_eq!(dispatched[1].destination, DestinationId::new(1));
    assert_eq!(dispatched[1].attempt, 2);
    assert_eq!(
        node.journal.abandoned.lock().unwrap().len(),
        1,
        "the attempt that produced nothing is explicitly abandoned"
    );
}

#[test]
fn an_attempt_whose_caller_goes_away_mid_send_abandons_its_record() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0)]);
    // The member accepts the dial and then says nothing, so the attempt is parked on the send when
    // the caller drops it.
    node.transport.script("a", Script::Hang);

    let mut ctx = node.request_ctx();
    node.route_poll_once_then_drop("primary", &mut ctx);

    assert_eq!(
        node.journal.dispatched.lock().unwrap().len(),
        1,
        "the record was made durable before the dial"
    );
    assert_eq!(
        node.journal.abandoned.lock().unwrap().len(),
        1,
        "a record left behind by a cancelled attempt is settled by recovery as a crash unless the \
         attempt says it was abandoned"
    );
}

#[test]
fn an_answer_that_could_not_be_assembled_records_nothing_against_the_member() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    *node.plane.refuse_encode.lock().unwrap() = true;

    let shed = node.route("primary");
    assert_eq!(
        shed.shed().expect("a refusal").detail,
        crate::wire::DETAIL_INTERNAL_ERROR
    );
    assert!(node
        .breaker
        .outcomes("primary", DestinationId::new(0))
        .is_empty());
    assert!(node.transport.dialled.lock().unwrap().is_empty());
}

#[test]
fn the_decoration_reaches_the_bytes_the_lane_check_ran_on() {
    let mut node = two_lane_pool();
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());
    let written = node.transport.written.lock().unwrap();
    let sent = String::from_utf8_lossy(&written[0]).to_string();
    assert!(
        sent.contains("authorization: decorated"),
        "the decoration is on the wire: {sent}"
    );
    assert!(
        sent.ends_with("request"),
        "and so is the plane's body: {sent}"
    );
}

#[test]
fn a_member_that_is_dead_is_never_attempted() {
    let mut node = two_lane_pool();
    node.breaker.set(
        DestinationId::new(0),
        Health {
            dead: true,
            ..Health::default()
        },
    );
    node.preference = Some(vec![DestinationId::new(0), DestinationId::new(1)]);
    node.transport.script("b", Script::Frames(ok_frames()));

    assert!(
        matches!(node.route("primary"), RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1))
    );
    assert_eq!(
        node.telemetry.attempts.lock().unwrap().as_slice(),
        &[("primary".to_string(), DestinationId::new(1))]
    );
}

// ── the lane cross-check ─────────────────────────────────────────────────────────────────────────

mod lane_cross_check {
    use crate::attempt::lane_matches_seal;
    use busbar_contract::LaneId;

    fn field(name: &str, value: &str) -> (String, Vec<u8>) {
        (name.to_string(), value.as_bytes().to_vec())
    }

    fn sealed() -> Option<LaneId> {
        Some(LaneId::new("lane-a"))
    }

    /// The matching case, and the plain divergence — the check's reason for existing.
    #[test]
    fn the_envelope_lane_must_be_the_one_the_trust_unit_sealed() {
        assert!(lane_matches_seal(Some("host"), &[field("host", "lane-a")], sealed()).is_ok());
        assert!(lane_matches_seal(Some("host"), &[field("host", "lane-b")], sealed()).is_err());
        // No lane field declared, or the envelope carries none: nothing to cross-check.
        assert!(lane_matches_seal(None, &[field("host", "lane-b")], sealed()).is_ok());
        assert!(lane_matches_seal(Some("host"), &[field("other", "x")], sealed()).is_ok());
    }

    /// ENVELOPE FIELD NAMES ARE CASE-INSENSITIVE ON THE WIRE, so the check must be too.
    ///
    /// A case-sensitive `find` let a decoration that wrote `Host` where the lane field is spelled
    /// `host` carry any lane it liked: the check found nothing, returned `Ok`, and the request went
    /// out on a lane nobody had compared against the seal. The egress-auth unit's own cross-check
    /// has always matched with `eq_ignore_ascii_case`; this one now agrees.
    #[test]
    fn the_field_is_found_whatever_case_the_decoration_spelled_it_in() {
        assert!(
            lane_matches_seal(Some("host"), &[field("Host", "lane-b")], sealed()).is_err(),
            "a diverged lane under a different capitalisation is still a diverged lane"
        );
        assert!(lane_matches_seal(Some("host"), &[field("HOST", "lane-a")], sealed()).is_ok());
        assert!(lane_matches_seal(Some("Host"), &[field("host", "lane-b")], sealed()).is_err());
    }

    /// TWO ENTRIES CARRYING THE LANE FIELD IS A REFUSAL, not a first-match.
    ///
    /// Taking the first meant a decoration could append a second spelling of the field and leave
    /// the check answering about the entry it was happy with while the transport encoded both. A
    /// request whose lane is written down twice has no answer to "which lane is this priced on".
    #[test]
    fn a_duplicated_lane_field_is_refused_rather_than_read_first_match() {
        let duplicated = [field("host", "lane-a"), field("host", "lane-b")];
        assert!(
            lane_matches_seal(Some("host"), &duplicated, sealed()).is_err(),
            "the first entry agreeing with the seal does not make the second one disappear"
        );
        // Including across spellings, and including when both agree — the ambiguity is the defect.
        let mixed_case = [field("host", "lane-a"), field("Host", "lane-a")];
        assert!(lane_matches_seal(Some("host"), &mixed_case, sealed()).is_err());
        // And a destination with no sealed lane still refuses a duplicate: the field is unreadable
        // whatever it would have been compared against.
        assert!(lane_matches_seal(Some("host"), &duplicated, None).is_err());
    }
}
