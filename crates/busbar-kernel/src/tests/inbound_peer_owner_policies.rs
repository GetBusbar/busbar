// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::auth::AuthPoints;

#[test]
fn mixed_peer_answers_never_replace_their_per_request_verdicts() {
    let providers = vec!["mixed".to_string()];
    let request_auths = HashSet::from(["mixed".to_string()]);
    for provisional in [Judged::Identity, Judged::Pass] {
        assert!(
            inherited_peer_answers(&providers, &request_auths, &[Some(provisional)], &[], &[])
                .next()
                .is_none()
        );
    }
    for terminal in [Judged::Denied, Judged::Overloaded] {
        let copied: Vec<_> =
            inherited_peer_answers(&providers, &request_auths, &[Some(terminal)], &[], &[])
                .collect();
        assert_eq!(copied.len(), 1);
        assert_eq!((copied[0].index, copied[0].answer), (0, Some(terminal)));
    }
}

#[test]
fn peer_only_identity_survives_an_earlier_head_pass_and_a_mixed_provisional_identity() {
    let providers = vec!["mixed".to_string(), "fallback".to_string()];
    let request_auths = HashSet::from(["mixed".to_string()]);
    for first in [None, Some(Judged::Identity), Some(Judged::Pass)] {
        let peer_identity = VerifiedIdentity {
            subject: "fallback-peer".to_string(),
            ..Default::default()
        };
        let copied: Vec<_> = inherited_peer_answers(
            &providers,
            &request_auths,
            &[first, Some(Judged::Identity)],
            &[None, Some(peer_identity)],
            &[],
        )
        .collect();
        let mut request_answers = [None, None];
        let mut inherited_identity = None;
        for inherited in copied {
            request_answers[inherited.index] = inherited.answer;
            if inherited.index == 1 {
                inherited_identity = inherited.identity;
            }
        }
        assert_eq!(request_answers, [None, Some(Judged::Identity)]);
        assert_eq!(inherited_identity.unwrap().subject, "fallback-peer");
        assert_eq!(
            fixed_answer_at(&request_answers, &providers, &request_auths, false),
            None
        );
        request_answers[0] = Some(Judged::Pass);
        assert_eq!(
            fixed_answer_at(&request_answers, &providers, &request_auths, false),
            Some(Fixed::Admitted(1))
        );
    }
}

#[test]
fn inherited_peer_positions_keep_the_exact_replay_authority_and_provider_order() {
    let actual = crate::real_store::store();
    let gov = Arc::new(crate::governance::GovState::new(actual.clone(), None).unwrap());
    assert!(gov.attach_store_calls(actual));
    let identity = VerifiedIdentity {
        subject: "peer-principal".to_string(),
        replay: Some(Box::new(busbar_contract::auth_calls::Replay {
            key: format!("peer-policy-{}", crate::door::op_id().counter()),
            ttl_secs: 60,
        })),
        ..Default::default()
    };
    let replay = Arc::new(ReplayAdmission {
        pending: crate::auth::PendingClaim::for_identity(
            "peer-policy",
            &identity,
            Some(gov),
            crate::store::now(),
        )
        .unwrap(),
        won: tokio::sync::OnceCell::new(),
    });
    let providers = vec![
        "request".to_string(),
        "peer".to_string(),
        "unanswered".to_string(),
    ];
    let copied: Vec<_> = inherited_peer_answers(
        &providers,
        &HashSet::from(["request".to_string()]),
        &[Some(Judged::Identity), Some(Judged::Identity), None],
        &[Some(identity.clone()), Some(identity), None],
        &[Some(replay.clone()), Some(replay.clone())],
    )
    .collect();
    assert_eq!(copied.iter().map(|p| p.index).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(
        copied[0].identity.as_ref().unwrap().subject,
        "peer-principal"
    );
    assert!(Arc::ptr_eq(copied[0].replay.as_ref().unwrap(), &replay));
    assert_eq!(copied[1].answer, None);
    assert!(copied[1].identity.is_none());
    assert!(copied[1].replay.is_none());
}

#[test]
fn ended_peer_collections_release_each_connection_and_preserve_a_live_identity() {
    let peer = |subject: &str| VerifiedIdentity {
        subject: subject.to_string(),
        ..Default::default()
    };
    let mut peers = HashMap::new();
    for framing in 100..140 {
        peers.insert((7, 3, framing), peer("retired"));
        let retired = take_framing_peers(&mut peers, framing);
        assert_eq!(retired.len(), 1);
    }
    assert!(peers.is_empty());
    peers.insert((7, 3, 7), peer("live"));
    for framing in 200..260 {
        peers.insert((7, 3, framing), peer("retired"));
        assert_eq!(take_framing_peers(&mut peers, framing).len(), 1);
    }
    assert_eq!(peers.len(), 1);
    assert_eq!(peers.get(&(7, 3, 7)).unwrap().subject, "live");
    assert_eq!(take_framing_peers(&mut peers, 7)[0].subject, "live");
    assert!(peers.is_empty());
}

#[test]
fn a_full_peer_collection_refuses_new_connections_without_evicting_a_held_identity() {
    let mut peers = HashMap::new();
    for framing in 0..PEER_CONNECTIONS_MAX as u64 {
        peer_capacity(peers.contains_key(&(7, 3, framing)), peers.len()).unwrap();
        peers.insert(
            (7, 3, framing),
            VerifiedIdentity {
                subject: framing.to_string(),
                ..Default::default()
            },
        );
    }
    assert_eq!(peer_capacity(false, peers.len()), Err(PEER_TABLE_FULL));
    assert_eq!(peers.len(), PEER_CONNECTIONS_MAX);
    assert_eq!(peers.get(&(7, 3, 0)).unwrap().subject, "0");
    assert_eq!(
        peer_capacity(true, peers.len()),
        Ok(()),
        "an existing connection remains usable at capacity"
    );
}

#[test]
fn peer_calls_present_neither_unit_nor_request_nor_body() {
    assert!(peer_payload_empty(UnitRef::NONE, &Head::default(), None));
    assert!(!peer_payload_empty(
        UnitRef { id: 9, mac: 9 },
        &Head::default(),
        None
    ));
    assert!(!peer_payload_empty(
        UnitRef::NONE,
        &Head {
            method: "POST".to_string(),
            target: "/v1/messages".to_string(),
            ..Default::default()
        },
        None
    ));
    assert!(!peer_payload_empty(
        UnitRef::NONE,
        &Head::default(),
        Some(&[])
    ));
    assert!(!peer_payload_empty(
        UnitRef::NONE,
        &Head::default(),
        Some(b"body")
    ));
}

#[test]
fn peer_answers_return_flow_alone_and_never_name_a_request_unit_or_strips() {
    let strips = [Strip::field("authorization".to_string())];
    for fixed in [
        None,
        Some(Fixed::Admitted(0)),
        Some(Fixed::Denied),
        Some(Fixed::Overloaded),
    ] {
        let answer = inbound_answer(fixed, UnitRef::NONE, true, &strips);
        assert_eq!(
            answer.flow,
            if matches!(fixed, Some(Fixed::Denied | Fixed::Overloaded)) {
                FLOW_STOP
            } else {
                FLOW_CONTINUE
            }
        );
        assert_eq!(answer.unit, UnitRef::NONE);
        assert!(answer.strips.is_empty());
    }
    let unit = UnitRef { id: 17, mac: 19 };
    let request = inbound_answer(Some(Fixed::Admitted(1)), unit, false, &strips);
    assert_eq!(request.unit, unit);
    assert_eq!(request.strips, strips);
    assert_eq!(request.flow, FLOW_CONTINUE);
}

#[test]
fn mixed_peer_metadata_requires_each_declared_request_point_and_peer_only_never_repeats() {
    use busbar_contract::abi::auth::{POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
    for request_point in [POINT_HEAD, POINT_HEAD_BODY] {
        let points = AuthPoints(POINT_PEER | request_point);
        assert!(points.has(AuthPoint::Peer));
        assert!(points.has(AuthPoint::from_bit(request_point).unwrap()));
        assert!(!points.has(
            AuthPoint::from_bit(if request_point == POINT_HEAD {
                POINT_HEAD_BODY
            } else {
                POINT_HEAD
            })
            .unwrap()
        ));
    }
    assert!(AuthPoints::PEER.has(AuthPoint::Peer));
    assert!(!AuthPoints::PEER.has(AuthPoint::Head));
    assert!(!AuthPoints::PEER.has(AuthPoint::HeadBody));
}
