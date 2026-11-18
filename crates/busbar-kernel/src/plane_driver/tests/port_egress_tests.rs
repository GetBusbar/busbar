// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The egress half of a port-driven session over a fake far end: how the walk's picks become candidates, how an
//! exchange becomes the far end's request, how its reply is read back piece by piece, how the plane's verdicts
//! reach the breaker, and which dials are judged before they are made.

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::Mutex;

use busbar_contract::abi::auth::{NO_MEMBER_AUTH_FIELD, SCOPE_REQUEST_FIELD};
use busbar_contract::abi::transport::{FAULT_HARD, FAULT_NONE, FAULT_RATE_LIMIT, FAULT_TRANSIENT};
use busbar_contract::caps::{Pass, Route};
use busbar_plugin_abi::host_side::caller::Accept;
use busbar_plugin_abi::plane::{
    ATT_HARD, ATT_RETRY, CARRIER_GRPC, CARRIER_HTTP, FC_RATE_LIMIT, FC_SERVER, OUTBOUND_NONE,
};
use tokio::runtime::Runtime;

use super::{is_request_of, request_of, route_of, EgressWalk, MemberTarget, WalkMembers, WalkSend};
use crate::plane_driver::far_end::{dial_admitted, UnitRoute};
use crate::plane_driver::port_session::UpExchange;
use crate::plane_driver::port_upstream::{
    Candidate, Chunk, Failure, Members, SendFailed, UpSend, Wants,
};
use crate::plane_driver::route::{FarEnd, FarPiece, OutboundRequest, Pick};

fn token() -> Pass<Route> {
    let kernel = crate::teller::Kernel::new();
    Pass::mint(kernel.seal())
}

fn member(name: &str) -> Pick {
    Pick::Member {
        name: name.into(),
        pool: "pool".into(),
        passthrough: false,
        provider: "p".into(),
    }
}

fn spent() -> Pick {
    Pick::Exhausted {
        status: 503,
        retry_after: None,
        detail: "",
    }
}

/// A far end whose picks, replies and acceptance of a send are scripted; it records what it was asked.
#[derive(Default)]
struct Fake {
    picks: Mutex<VecDeque<Pick>>,
    pieces: Mutex<VecDeque<Option<FarPiece>>>,
    refuse_send: bool,
    sent: Mutex<Vec<OutboundRequest>>,
    judged: Mutex<Vec<u8>>,
    /// The waits the plane's verdicts carried, in order.
    waits: Mutex<Vec<Option<u64>>>,
}

impl FarEnd for Fake {
    async fn member(&self, _: &Pass<Route>, _: u32) -> Pick {
        self.picks.lock().unwrap().pop_front().unwrap_or_else(spent)
    }

    async fn send(&self, _: &Pass<Route>, request: OutboundRequest) -> bool {
        self.sent.lock().unwrap().push(request);
        !self.refuse_send
    }

    async fn next(&self, _: &Pass<Route>) -> Option<FarPiece> {
        self.pieces.lock().unwrap().pop_front().flatten()
    }

    fn judged_stating(&self, _: &Pass<Route>, fault: u8, _: Option<&str>) {
        self.judged.lock().unwrap().push(fault);
    }

    fn judged_waiting(&self, token: &Pass<Route>, fault: u8, retry_after_s: Option<u64>) {
        self.waits.lock().unwrap().push(retry_after_s);
        self.judged_stating(token, fault, None);
    }

    async fn write(&self, _: &Pass<Route>, _: OutboundRequest) -> bool {
        true
    }
}

fn head_piece(status: u32) -> FarPiece {
    FarPiece {
        status: Some((status, 0)),
        head: vec![(b"content-type".to_vec(), b"text/event-stream".to_vec())],
        ..FarPiece::default()
    }
}

fn body_piece(bytes: &[u8], last: bool) -> FarPiece {
    FarPiece {
        bytes: bytes.to_vec(),
        last,
        ..FarPiece::default()
    }
}

fn exchange() -> UpExchange {
    UpExchange {
        id: 0,
        method: Some("POST".into()),
        path: Some("/v1/chat".into()),
        headers: vec![(b"x-a".to_vec(), b"b".to_vec())],
        body: b"{}".to_vec(),
        ..UpExchange::default()
    }
}

fn candidate() -> Candidate {
    Candidate {
        pool: "pool".into(),
        qualified_member: "fixture-member".into(),
        identity: crate::plane_driver::port_upstream::TargetIdentity::Registration,
        resource: None,
        upstream: "a".into(),
        provider: "{}".into(),
        base_path: "".into(),
        flags: 0,
        params: Vec::new(),
    }
}

fn target_for(_pool: &str, name: &str) -> Option<MemberTarget> {
    (name != "skip").then(|| MemberTarget {
        identity: crate::plane_driver::port_upstream::TargetIdentity::Registration,
        resource: None,
        registered_upstream: None,
        definition: None,
        provider: "{\"k\":1}".into(),
        base_path: "/v1".into(),
        flags: 2,
        params: vec![("region".into(), "eu".into())],
    })
}

#[test]
fn target_definition_retains_the_actual_registration_allocation() {
    use std::sync::Arc;

    let definition = crate::upstreams::UpstreamDef::from_config(
        "actual",
        &busbar_contract::json::json!({"url": "https://example.com"}),
        &crate::config::min3::UpstreamCfg::default(),
        &|_| unreachable!("this registration has no custom trust anchor"),
    )
    .unwrap();
    let actual = Arc::new(definition.clone());
    let lookalike = Arc::new(definition);
    let target = super::TargetDefinition::new(Arc::clone(&actual));
    assert!(Arc::ptr_eq(target.as_arc(), &actual));
    assert_eq!(target, target.clone());
    assert_ne!(target, super::TargetDefinition::new(lookalike));
}

#[test]
fn target_lookup_preserves_the_selected_member_qualification() {
    let fake = Fake::default();
    fake.picks
        .lock()
        .unwrap()
        .push_back(member("seat\u{1f}model"));
    let rt = Runtime::new().unwrap();
    let tok = token();
    let cell = Mutex::new(Some(fake));
    let make =
        |_: &Wants, _: Option<&super::RequestPoolReceipt>| cell.lock().unwrap().take().unwrap();
    let targets = |pool: &str, name: &str| {
        (pool == "pool" && name == "seat\u{1f}model").then(MemberTarget::bare)
    };
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &targets);
    let got = walk.members().next(&Wants::default());
    assert!(
        got.is_some(),
        "the exact configured member must reach its target record"
    );
    assert_eq!(&*got.unwrap().upstream, "model");
}

#[test]
fn the_same_member_in_two_pools_uses_each_pools_resolved_target() {
    let fake = Fake::default();
    for pool in ["fast", "careful"] {
        fake.picks.lock().unwrap().push_back(Pick::Member {
            name: "seat\u{1f}model".into(),
            pool: pool.into(),
            passthrough: false,
            provider: "configured".into(),
        });
    }
    let rt = Runtime::new().unwrap();
    let tok = token();
    let cell = Mutex::new(Some(fake));
    let make =
        |_: &Wants, _: Option<&super::RequestPoolReceipt>| cell.lock().unwrap().take().unwrap();
    let targets = |pool: &str, member: &str| {
        if member != "seat\u{1f}model" {
            return None;
        }
        let mut target = MemberTarget::bare();
        target.identity = crate::plane_driver::port_upstream::TargetIdentity::Model {
            dialect: format!("{pool}-dialect").into(),
            model: format!("{pool}-wire").into(),
        };
        target.resource = Some(format!("{pool}-resource").into());
        Some(target)
    };
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &targets);
    for pool in ["fast", "careful"] {
        let picked = walk.members().next(&Wants::default()).unwrap();
        assert_eq!(&*picked.pool, pool);
        assert_eq!(&*picked.qualified_member, "seat\u{1f}model");
        assert_eq!(
            picked.resource.as_deref(),
            Some(format!("{pool}-resource").as_str())
        );
        picked.with_target(1, "caller-dialect", "alias", |target| {
            assert_eq!(target.dialect, format!("{pool}-dialect"));
            assert_eq!(target.model, format!("{pool}-wire"));
        });
    }
}

#[test]
fn a_pick_becomes_a_candidate_named_as_the_operator_and_stated_as_its_target() {
    let fake = Fake::default();
    fake.picks.lock().unwrap().push_back(member("a"));
    let rt = Runtime::new().unwrap();
    let tok = token();
    let made = Cell::new(0);
    let cell = Mutex::new(Some(fake));
    let make = |_: &Wants, _: Option<&super::RequestPoolReceipt>| {
        made.set(made.get() + 1);
        cell.lock().unwrap().take().unwrap()
    };
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &target_for);
    let mut members = walk.members();
    let got = members.next(&Wants::default()).unwrap();
    assert_eq!(&*got.upstream, "a");
    assert_eq!(&*got.provider, "{\"k\":1}");
    assert_eq!(&*got.base_path, "/v1");
    assert_eq!(got.flags, 2);
    assert_eq!(got.params, vec![("region".into(), "eu".into())]);
    // The walk is out of members: the pool's terminal ends it.
    assert!(members.next(&Wants::default()).is_none());
    assert_eq!(
        made.get(),
        1,
        "the far end is built once, from the first wants"
    );
}

#[test]
fn the_far_end_is_built_from_the_wants_the_plane_forwarded_with() {
    let rt = Runtime::new().unwrap();
    let tok = token();
    let seen = Mutex::new(None);
    let make = |w: &Wants, _: Option<&super::RequestPoolReceipt>| {
        *seen.lock().unwrap() = Some(w.clone());
        Fake::default()
    };
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &target_for);
    let wants = Wants {
        stream: true,
        upstream: Some("pinned".into()),
        affinity: Some("k".into()),
        ..Wants::default()
    };
    let _ = walk.members().next(&wants);
    assert_eq!(seen.lock().unwrap().as_ref(), Some(&wants));
}

#[test]
fn a_member_the_plane_has_no_upstream_for_is_passed_over() {
    let fake = Fake::default();
    fake.picks.lock().unwrap().push_back(member("skip"));
    fake.picks.lock().unwrap().push_back(member("b"));
    let rt = Runtime::new().unwrap();
    let tok = token();
    let cell = Mutex::new(Some(fake));
    let make =
        |_: &Wants, _: Option<&super::RequestPoolReceipt>| cell.lock().unwrap().take().unwrap();
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &target_for);
    let got = walk.members().next(&Wants::default()).unwrap();
    assert_eq!(&*got.upstream, "b");
}

/// Builds a walk over `fake`, takes its first pick (so the far end exists), and hands both ends to `body`.
fn with_walk<R>(
    fake: Fake,
    body: impl FnOnce(WalkMembers<'_, '_, Fake>, WalkSend<'_, '_, Fake>) -> R,
) -> R {
    let rt = Runtime::new().unwrap();
    let tok = token();
    let cell = Mutex::new(Some(fake));
    let make =
        |_: &Wants, _: Option<&super::RequestPoolReceipt>| cell.lock().unwrap().take().unwrap();
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &target_for);
    let mut members = walk.members();
    let _ = members.next(&Wants::default());
    body(members, walk.sender())
}

fn picking(fake: Fake) -> Fake {
    fake.picks.lock().unwrap().push_back(member("a"));
    fake
}

fn judged_of(fake: Fake, run: impl FnOnce(&mut dyn Members)) -> Vec<u8> {
    let rt = Runtime::new().unwrap();
    let tok = token();
    let cell = Mutex::new(Some(picking(fake)));
    let make =
        |_: &Wants, _: Option<&super::RequestPoolReceipt>| cell.lock().unwrap().take().unwrap();
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &target_for);
    let mut members = walk.members();
    let _ = members.next(&Wants::default());
    run(&mut members);
    walk.far()
        .map(|far| far.judged.lock().unwrap().clone())
        .unwrap()
}

#[test]
fn the_plane_s_verdicts_are_the_breaker_s_inputs() {
    let hard = Failure {
        verdict: ATT_HARD,
        class: FC_SERVER,
        retry_after_s: 0,
    };
    let limited = Failure {
        verdict: ATT_RETRY,
        class: FC_RATE_LIMIT,
        retry_after_s: 9,
    };
    let transient = Failure {
        verdict: ATT_RETRY,
        class: FC_SERVER,
        retry_after_s: 0,
    };
    let told = judged_of(Fake::default(), |m| {
        m.failed(&candidate(), &hard);
        m.failed(&candidate(), &limited);
        m.failed(&candidate(), &transient);
        m.served(&candidate());
    });
    assert_eq!(
        told,
        vec![FAULT_HARD, FAULT_RATE_LIMIT, FAULT_TRANSIENT, FAULT_NONE]
    );
}

#[test]
fn an_exchange_is_sent_as_the_far_end_s_request_and_its_reply_is_read_piece_by_piece() {
    let fake = picking(Fake::default());
    {
        let mut pieces = fake.pieces.lock().unwrap();
        pieces.push_back(Some(head_piece(200)));
        pieces.push_back(Some(body_piece(b"a", false)));
        pieces.push_back(Some(body_piece(b"b", true)));
    }
    with_walk(fake, |_, mut send| {
        let mut open = send.open(&candidate(), exchange()).unwrap();
        assert_eq!(open.status, 200);
        assert_eq!(
            open.headers,
            vec![(b"content-type".to_vec(), b"text/event-stream".to_vec())]
        );
        assert_eq!(open.rest.next().unwrap(), Some(Chunk::Body(b"a".to_vec())));
        assert_eq!(open.rest.next().unwrap(), Some(Chunk::Body(b"b".to_vec())));
        assert_eq!(open.rest.next().unwrap(), None);
    });
}

#[test]
fn the_request_carries_the_exchange_the_member_and_the_pool() {
    let request = request_of("lane:a", "pool", 3, exchange()).unwrap();
    assert_eq!(request.member, "lane:a");
    assert_eq!(request.pool, "pool");
    assert_eq!(request.attempt_no, 3);
    assert_eq!(request.verb, b"POST".to_vec());
    assert_eq!(request.target, b"/v1/chat".to_vec());
    assert_eq!(request.fields, vec![(b"x-a".to_vec(), b"b".to_vec())]);
    assert_eq!(request.body, b"{}".to_vec());
    assert_eq!(request.need, 0, "the member's own need");
}

#[test]
fn outbound_none_waives_the_member_credential_and_a_scope_rides_as_its_field() {
    let none = UpExchange {
        outbound: OUTBOUND_NONE,
        scope: Some("tenant-1".into()),
        ..exchange()
    };
    let request = request_of("a", "p", 1, none.clone()).unwrap();
    assert!(request
        .fields
        .iter()
        .any(|(n, _)| n == NO_MEMBER_AUTH_FIELD.as_bytes()));
    assert!(request
        .fields
        .iter()
        .any(|(n, v)| n == SCOPE_REQUEST_FIELD.as_bytes() && v == b"tenant-1"));
}

#[test]
fn is_request_of_agrees_with_building_the_request_and_comparing_it() {
    for outbound in [OUTBOUND_NONE, 0] {
        let rich = UpExchange {
            outbound,
            scope: Some("tenant-1".into()),
            ..exchange()
        };
        let built = request_of("lane:a", "pool", 3, rich.clone()).unwrap();
        // The old form: build a whole request from the parts and compare it.
        let agrees = |request: &OutboundRequest| {
            is_request_of(request, "lane:a", "pool", &rich)
                == (request_of("lane:a", "pool", request.attempt_no, rich.clone()).as_ref()
                    == Some(request))
        };
        assert!(is_request_of(&built, "lane:a", "pool", &rich));
        assert!(agrees(&built));
        // One difference in each of the other eight fields.
        let mut differs: Vec<OutboundRequest> = Vec::new();
        for edit in [
            (|r: &mut OutboundRequest| r.member.push('x')) as fn(&mut OutboundRequest),
            |r| r.pool.push('x'),
            |r| r.verb.push(b'x'),
            |r| r.target.push(b'x'),
            |r| r.fields.push((b"x".to_vec(), b"y".to_vec())),
            |r| {
                r.fields.pop();
            },
            |r| r.fields[0].1.push(b'x'),
            |r| r.body.push(b'x'),
            |r| r.need = 1,
            |r| r.text = true,
        ] {
            let mut other = built.clone();
            edit(&mut other);
            differs.push(other);
        }
        // The attempt number is taken from the request itself, so it always matches.
        let mut later = built.clone();
        later.attempt_no += 1;
        assert!(is_request_of(&later, "lane:a", "pool", &rich));
        assert!(agrees(&later));
        for other in &differs {
            assert!(!is_request_of(other, "lane:a", "pool", &rich), "{other:?}");
            assert!(agrees(other));
        }
        // Carrier and missing parts: nothing is built, nothing matches.
        let grpc = UpExchange {
            carrier: CARRIER_GRPC,
            ..rich.clone()
        };
        assert!(!is_request_of(&built, "lane:a", "pool", &grpc));
        let no_path = UpExchange {
            path: None,
            ..rich.clone()
        };
        assert!(!is_request_of(&built, "lane:a", "pool", &no_path));
    }
}

#[test]
fn an_exchange_this_carrier_does_not_send_is_not_a_request() {
    let grpc = UpExchange {
        carrier: CARRIER_GRPC,
        ..exchange()
    };
    assert!(request_of("a", "p", 1, grpc.clone()).is_none());
    let no_path = UpExchange {
        path: None,
        ..exchange()
    };
    assert!(request_of("a", "p", 1, no_path.clone()).is_none());
    let http = UpExchange {
        carrier: CARRIER_HTTP,
        ..exchange()
    };
    assert!(request_of("a", "p", 1, http).is_some());
}

#[test]
fn a_send_the_far_end_refuses_is_a_failed_send() {
    let fake = Fake {
        refuse_send: true,
        ..picking(Fake::default())
    };
    with_walk(fake, |_, mut send| {
        assert!(matches!(
            send.open(&candidate(), exchange()),
            Err(SendFailed)
        ));
    });
}

#[test]
fn a_reply_the_walk_s_own_table_failed_over_is_a_failed_send_before_the_plane_sees_it() {
    let fake = picking(Fake::default());
    fake.pieces.lock().unwrap().push_back(Some(FarPiece {
        fail_over: true,
        last: true,
        ..FarPiece::default()
    }));
    with_walk(fake, |_, mut send| {
        assert!(matches!(
            send.open(&candidate(), exchange()),
            Err(SendFailed)
        ));
    });
}

#[test]
fn a_reply_cut_after_its_head_is_an_error_on_the_next_read() {
    let fake = picking(Fake::default());
    {
        let mut pieces = fake.pieces.lock().unwrap();
        pieces.push_back(Some(head_piece(200)));
        pieces.push_back(Some(FarPiece {
            last: true,
            cut: true,
            ..FarPiece::default()
        }));
    }
    with_walk(fake, |_, mut send| {
        let mut open = send.open(&candidate(), exchange()).unwrap();
        assert!(open.rest.next().is_err());
    });
}

#[test]
fn trailing_fields_are_their_own_chunk() {
    let fake = picking(Fake::default());
    {
        let mut pieces = fake.pieces.lock().unwrap();
        pieces.push_back(Some(head_piece(200)));
        pieces.push_back(Some(FarPiece {
            bytes: b"grpc-status: 0\r\n".to_vec(),
            fields: true,
            last: true,
            ..FarPiece::default()
        }));
    }
    with_walk(fake, |_, mut send| {
        let mut open = send.open(&candidate(), exchange()).unwrap();
        assert_eq!(
            open.rest.next().unwrap(),
            Some(Chunk::Trailers(b"grpc-status: 0\r\n".to_vec()))
        );
        assert_eq!(open.rest.next().unwrap(), None);
    });
}

#[test]
fn a_whole_send_joins_the_body_and_drops_the_trailers() {
    let fake = picking(Fake::default());
    {
        let mut pieces = fake.pieces.lock().unwrap();
        pieces.push_back(Some(head_piece(201)));
        pieces.push_back(Some(body_piece(b"x", false)));
        pieces.push_back(Some(body_piece(b"y", true)));
    }
    with_walk(fake, |_, mut send| {
        let reply = send.send(&candidate(), exchange()).unwrap();
        assert_eq!(reply.status, 201);
        assert_eq!(reply.body, b"xy".to_vec());
    });
}

// ---- every dial is judged ------------------------------------------------------------------------------

/// #297 model A: a unit with no owning registration holds the empty acceptance, so it dials verified
/// TLS only; there is no unjudged legacy route and no loopback exemption.
#[test]
fn a_unit_with_no_owning_registration_dials_verified_tls_only() {
    let unowned = UnitRoute::default().accept;
    assert_eq!(unowned, Accept::default());
    assert!(!dial_admitted(unowned, "http://10.0.0.5:8000/v1"));
    assert!(!dial_admitted(unowned, "http://127.0.0.1:8000/v1"));
    assert!(!dial_admitted(unowned, "http://localhost:8000/v1"));
    assert!(!dial_admitted(unowned, "http://[::1]:8000/v1"));
    assert!(dial_admitted(unowned, "https://api.example.com/v1"));
}

#[test]
fn verified_tls_is_the_default_and_plaintext_is_refused_without_its_acceptance() {
    let verified = Accept::default();
    assert!(dial_admitted(verified, "https://api.example.com/v1"));
    assert!(dial_admitted(verified, "HTTPS://api.example.com/v1"));
    assert!(dial_admitted(verified, "wss://api.example.com/ws"));
    assert!(!dial_admitted(verified, "http://localhost:8000/v1"));
    assert!(!dial_admitted(verified, "http://127.0.0.1:8000/v1"));
    assert!(!dial_admitted(verified, "ws://api.example.com/ws"));
    assert!(!dial_admitted(verified, "unix:/run/x.sock"));
}

#[test]
fn plaintext_is_admitted_only_by_the_plaintext_acceptance() {
    let plain = Accept(Accept::PLAINTEXT);
    assert!(dial_admitted(plain, "http://localhost:8000/v1"));
    assert!(dial_admitted(plain, "https://api.example.com/v1"));
    let unverified = Accept(Accept::UNVERIFIED_TLS);
    assert!(
        !dial_admitted(unverified, "http://localhost:8000/v1"),
        "accepting unverified TLS does not accept plaintext"
    );
    assert!(dial_admitted(unverified, "https://api.example.com/v1"));
}

#[test]
fn the_route_a_session_walks_under_states_the_wants_and_the_acceptance() {
    let wants = Wants {
        stream: true,
        upstream: Some("pinned".into()),
        affinity: Some("k".into()),
        ..Wants::default()
    };
    let key = busbar_contract::UnitKey::new(7);
    let route = route_of("pool", key, Accept(Accept::PLAINTEXT), &wants);
    assert_eq!(route.pool, "pool");
    assert_eq!(route.unit, key);
    assert!(route.wants_stream);
    assert_eq!(route.allowed_member.as_deref(), Some("pinned"));
    assert!(route.affinity.is_some());
    assert_eq!(route.accept, Accept(Accept::PLAINTEXT));
    let plain = route_of("pool", key, Accept::default(), &Wants::default());
    assert_eq!(plain.affinity, None);
    assert_eq!(plain.allowed_member, None);
    assert_eq!(
        plain.accept,
        Accept::default(),
        "judged even with no acceptance"
    );
}

#[test]
fn the_plane_s_wait_rides_with_its_verdict_into_the_breaker() {
    let fake = Fake::default();
    let rt = Runtime::new().unwrap();
    let tok = token();
    let cell = Mutex::new(Some(picking(fake)));
    let make =
        |_: &Wants, _: Option<&super::RequestPoolReceipt>| cell.lock().unwrap().take().unwrap();
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &target_for);
    let mut members = walk.members();
    let _ = members.next(&Wants::default());
    members.failed(
        &candidate(),
        &Failure {
            verdict: ATT_RETRY,
            class: FC_RATE_LIMIT,
            retry_after_s: 9,
        },
    );
    members.failed(
        &candidate(),
        &Failure {
            verdict: ATT_RETRY,
            class: FC_SERVER,
            retry_after_s: 0,
        },
    );
    let waits = walk.far().map(|far| far.waits.lock().unwrap().clone());
    assert_eq!(
        waits,
        Some(vec![Some(9), None]),
        "no wait stated is no wait"
    );
}

#[test]
fn an_exhausted_walk_keeps_the_wait_it_stated_for_the_client() {
    let fake = Fake::default();
    fake.picks.lock().unwrap().push_back(Pick::Exhausted {
        status: 503,
        retry_after: Some(30),
        detail: "",
    });
    let rt = Runtime::new().unwrap();
    let tok = token();
    let cell = Mutex::new(Some(fake));
    let make =
        |_: &Wants, _: Option<&super::RequestPoolReceipt>| cell.lock().unwrap().take().unwrap();
    let handle = rt.handle().clone();
    let walk = EgressWalk::new(&make, &tok, &handle, &target_for);
    let mut members = walk.members();
    assert_eq!(
        members.retry_after(),
        None,
        "nothing stated before the walk ends"
    );
    assert!(members.next(&Wants::default()).is_none());
    assert_eq!(members.retry_after(), Some(30));
}

/// B-REQUEST-OF: what turning one exchange (12 header fields, 4 KiB body) into the far end's request
/// costs, copied (the exchange cloned first, as the selected path does) against moved, in time and in bytes allocated on this thread. Prints the
/// numbers (run with `--no-capture`); asserts the moved request equals the held one.
#[test]
fn b_request_of_held_against_moved() {
    const CYCLES: usize = 2_000;
    let rich = || UpExchange {
        method: Some("POST".into()),
        path: Some("/v1/chat/completions".into()),
        headers: (0..12)
            .map(|n| (format!("x-field-{n}").into_bytes(), vec![b'v'; 24]))
            .collect(),
        body: vec![b'b'; 4096],
        ..UpExchange::default()
    };
    let spare: Vec<UpExchange> = (0..CYCLES).map(|_| rich()).collect();
    crate::ThreadAllocated::reset();
    let start = std::time::Instant::now();
    let mut kept = Vec::with_capacity(CYCLES);
    for exchange in &spare {
        kept.push(request_of("lane:a", "pool", 1, exchange.clone()));
    }
    let held_ns = start.elapsed().as_nanos() as usize / CYCLES;
    let held_bytes = crate::ThreadAllocated::bytes() as usize / CYCLES;
    drop(kept);
    let moved_input: Vec<UpExchange> = (0..CYCLES).map(|_| rich()).collect();
    crate::ThreadAllocated::reset();
    let start = std::time::Instant::now();
    let mut out = Vec::with_capacity(CYCLES);
    for exchange in moved_input {
        out.push(request_of("lane:a", "pool", 1, exchange));
    }
    let moved_ns = start.elapsed().as_nanos() as usize / CYCLES;
    let moved_bytes = crate::ThreadAllocated::bytes() as usize / CYCLES;
    println!(
        "B-REQUEST-OF held: {held_ns} ns, {held_bytes} bytes; moved: {moved_ns} ns, {moved_bytes} bytes"
    );
    assert_eq!(out[0], request_of("lane:a", "pool", 1, spare[0].clone()));
}
