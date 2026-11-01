// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

struct PeerAndRequest {
    point: u32,
    pass_request: bool,
    calls: Mutex<Vec<(AuthPoint, u64)>>,
}

impl AuthCalls for PeerAndRequest {
    fn name(&self) -> &str {
        "peer-and-request"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn inbound_points(&self) -> AuthPoints {
        AuthPoints(POINT_PEER | self.point)
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        self.calls
            .lock()
            .unwrap()
            .push((request.point, request.unit));
        let answer = if request.point == AuthPoint::Peer {
            identity("peer", "connection")
        } else if self.pass_request {
            Verified::Pass
        } else if request.path == MESSAGES {
            identity("request", "per-request")
        } else {
            Verified::Reject
        };
        Box::new(Answered(Some(VerifyAnswer::from(answer))))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

fn peer_identity_does_not_skip_a_request_point(point: u32) {
    let placeholder = Script::new(AuthPoints(POINT_PEER | point), Verified::Pass, Vec::new());
    let k = kit(&[("a", placeholder)]);
    let calls = Arc::new(PeerAndRequest {
        point,
        pass_request: false,
        calls: Mutex::new(Vec::new()),
    });
    let prior = k.inbound.table(OWNER, GEN).unwrap();
    let auth: Arc<dyn AuthCalls> = calls.clone();
    k.inbound
        .install(
            OWNER,
            GEN,
            Listener {
                guests: prior.listener.guests.clone(),
                auths: HashMap::from([("a".into(), auth)]),
                body_limit: prior.listener.body_limit,
                app: Arc::clone(&prior.listener.app),
                door_refusals: prior.listener.door_refusals.clone(),
                ids: prior.listener.ids.clone(),
                signed_ingress: Arc::clone(&prior.listener.signed_ingress),
                scope: prior.listener.scope.clone(),
            },
        )
        .unwrap();
    drop(prior);
    let peer = k
        .call(MESSAGES, UnitRef::NONE, POINT_PEER, Head::default())
        .unwrap();
    let first = k
        .call(MESSAGES, UnitRef::NONE, point, post(MESSAGES, &[], None))
        .unwrap();
    let first_identity = k.inbound.admitted(first.unit.id);
    let second = k
        .call(OTHER, UnitRef::NONE, point, post(OTHER, &[], None))
        .unwrap();
    let second_identity = k.inbound.admitted(second.unit.id);
    let seen = calls.calls.lock().unwrap().clone();
    k.inbound.exit(first.unit.id);
    k.inbound.exit(second.unit.id);
    k.inbound.framing_ended(1);

    assert_eq!((peer.flow, peer.unit), (FLOW_CONTINUE, UnitRef::NONE));
    assert_eq!(first.flow, FLOW_CONTINUE);
    assert_eq!(first_identity.unwrap().identity.subject, "request");
    assert_eq!(
        second.flow, FLOW_STOP,
        "a connection verdict cannot admit a rejected request"
    );
    assert!(second_identity.is_none());
    assert_eq!(
        seen,
        vec![
            (AuthPoint::Peer, 0),
            (AuthPoint::from_bit(point).unwrap(), first.unit.id),
            (AuthPoint::from_bit(point).unwrap(), second.unit.id)
        ]
    );
}

#[test]
fn a_peer_and_head_auth_checks_each_requests_head() {
    peer_identity_does_not_skip_a_request_point(POINT_HEAD);
}

#[test]
fn a_peer_and_body_auth_checks_each_requests_body() {
    peer_identity_does_not_skip_a_request_point(POINT_HEAD_BODY);
}

#[test]
fn a_peer_only_identity_survives_an_earlier_head_positions_pass() {
    let head = Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new());
    let peer = Script::new(AuthPoints::PEER, identity("peer", "held"), Vec::new());
    let k = kit(&[("head", Arc::clone(&head)), ("peer", Arc::clone(&peer))]);
    let initial = k
        .call(MESSAGES, UnitRef::NONE, POINT_PEER, Head::default())
        .unwrap();
    let request = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    let admitted = k.inbound.admitted(request.unit.id);
    k.inbound.exit(request.unit.id);
    k.inbound.framing_ended(1);
    assert_eq!(initial.flow, FLOW_CONTINUE);
    assert_eq!(request.flow, FLOW_CONTINUE);
    assert_eq!(
        admitted
            .expect("the inherited position keeps its identity")
            .identity
            .subject,
        "peer"
    );
    assert_eq!(head.calls(), 1);
    assert_eq!(
        peer.calls(),
        1,
        "a Peer-only provider is not called again at Head"
    );
}

#[test]
fn a_mixed_peers_provisional_identity_does_not_skip_a_later_peer_provider() {
    let placeholder = Script::new(
        AuthPoints(POINT_PEER | POINT_HEAD),
        Verified::Pass,
        Vec::new(),
    );
    let fallback = Script::new(
        AuthPoints::PEER,
        identity("fallback", "peer-credential"),
        Vec::new(),
    );
    let k = kit(&[("a", placeholder), ("b", Arc::clone(&fallback))]);
    let calls = Arc::new(PeerAndRequest {
        point: POINT_HEAD,
        pass_request: true,
        calls: Mutex::new(Vec::new()),
    });
    let prior = k.inbound.table(OWNER, GEN).unwrap();
    let mut auths = prior.listener.auths.clone();
    auths.insert("a".into(), calls.clone());
    k.inbound
        .install(
            OWNER,
            GEN,
            Listener {
                guests: prior.listener.guests.clone(),
                auths,
                body_limit: prior.listener.body_limit,
                app: Arc::clone(&prior.listener.app),
                door_refusals: prior.listener.door_refusals.clone(),
                ids: prior.listener.ids.clone(),
                signed_ingress: Arc::clone(&prior.listener.signed_ingress),
                scope: prior.listener.scope.clone(),
            },
        )
        .unwrap();
    drop(prior);
    let peer = k
        .call(MESSAGES, UnitRef::NONE, POINT_PEER, Head::default())
        .unwrap();
    let request = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    let admitted = k.inbound.admitted(request.unit.id);
    let handed = k.hand_in(MESSAGES, MESSAGES, request.unit, post(MESSAGES, &[], None));
    k.inbound.exit(request.unit.id);
    k.inbound.framing_ended(1);
    assert_eq!(peer.flow, FLOW_CONTINUE);
    assert_eq!(request.flow, FLOW_CONTINUE);
    assert_eq!(handed.0, FLOW_CONTINUE);
    assert_eq!(
        admitted
            .expect("the later Peer provider remains available")
            .identity
            .subject,
        "fallback"
    );
    assert_eq!(fallback.calls(), 1);
    assert_eq!(
        *calls.calls.lock().unwrap(),
        vec![(AuthPoint::Peer, 0), (AuthPoint::Head, request.unit.id)]
    );
}
