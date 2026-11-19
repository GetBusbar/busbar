// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! K9 (PLANE-DRIVER.md "BOOT (K9)"): the pool a plane seat walks is composed from the instance's configured upstreams
//! ([`SeatPool::of`]), and a FORWARD on a seat composed that way reaches the configured upstream through the real
//! walk ([`PortEgress`] over [`Egress`]), the harness's fake connection table standing in for the connector.

use std::collections::BTreeMap;

use busbar_contract::json::{json, JsonContainerTrait, Value};
use busbar_plugin_abi::host_side::caller::Accept;

use super::*;
use crate::plane_driver::port_egress::{
    upstream_targets, EgressWalk, PortEgress, ProbeTarget, SeatPool, SessionFacts,
};
use crate::plane_driver::port_session::UpExchange;
use crate::plane_driver::port_upstream::{Members, UpChunks, UpSend, Wants};
use crate::plane_driver::request_admission::RequestPoolReceipt;
use crate::upstreams::{ConfiguredUpstreams, Upstreams};

const PIN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const OTHER_PIN_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

fn upstreams(section: Value) -> Arc<ConfiguredUpstreams> {
    let section = section.as_object().expect("an upstreams map").clone();
    Arc::new(
        ConfiguredUpstreams::from_config(
            &section,
            &BTreeMap::new(),
            &crate::plugin_config::upstream_anchor,
        )
        .expect("the upstreams type"),
    )
}

fn three() -> Arc<ConfiguredUpstreams> {
    upstreams(json!({
        "beta": {"url": "https://beta.test"},
        "alpha": {"url": "https://alpha.test/base"},
        "files": {"command": {"argv": ["/opt/mcp/files"]}},
    }))
}

#[test]
fn a_seat_walks_one_member_per_network_upstream_in_name_order_under_its_lane() {
    let pool = SeatPool::of("mcp", &three()).expect("the seat composes");
    assert_eq!(pool.pool, "mcp");
    let names: Vec<&str> = pool.members.iter().map(|m| &*m.upstream).collect();
    assert_eq!(
        names,
        ["alpha", "beta"],
        "a command upstream is never walked"
    );
    let walked = pool.pools.get("mcp").expect("the instance's pool");
    let lanes: Vec<&str> = walked.members.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(lanes, ["mcp\u{1f}alpha", "mcp\u{1f}beta"]);
    for (index, member) in pool.members.iter().enumerate() {
        assert_eq!(member.destination, DestinationId::new(index as u64));
        assert_eq!(member.need, NeedId(index as u32));
        let route = pool.routes.get(&member.destination).expect("a route");
        assert_eq!(route.need, member.need);
        assert_eq!(route.provider, &*member.upstream);
        assert_eq!(route.base_url, &*member.url);
        assert!(route.auth.is_none());
        assert!(!route.anchors.secures());
    }
    assert_eq!(
        pool.probe_members(),
        [
            ProbeTarget {
                destination: DestinationId::new(0),
                pool: "mcp".into(),
                qualified_member: "mcp\u{1f}alpha".into()
            },
            ProbeTarget {
                destination: DestinationId::new(1),
                pool: "mcp".into(),
                qualified_member: "mcp\u{1f}beta".into()
            },
        ]
    );
}

#[test]
fn an_upstream_pin_is_held_and_a_check_this_path_cannot_hold_refuses_the_seat() {
    let pinned = SeatPool::of(
        "a2a",
        &upstreams(json!({"agent": {"url": "https://agent.test", "tls": {"pin_spki": [PIN_HEX]}}})),
    )
    .expect("one pin composes");
    let route = pinned.routes.values().next().expect("the member's route");
    assert!(route
        .anchors
        .key_pin
        .as_deref()
        .is_some_and(|pin| pin.starts_with("sha256/")));

    let refused = SeatPool::of(
        "a2a",
        &upstreams(json!({"agent": {
            "url": "https://agent.test",
            "tls": {"pin_spki": [PIN_HEX, OTHER_PIN_HEX]},
        }})),
    )
    .err()
    .expect("two pins refuse the seat");
    assert!(
        refused.contains("upstreams.agent.tls.pin_spki"),
        "{refused}"
    );
}

#[test]
fn a_seat_reads_only_its_own_upstreams_as_targets() {
    let table: Arc<dyn Upstreams> = three();
    let targets = upstream_targets("mcp", table);
    assert!(targets("mcp", "mcp\u{1f}alpha").is_some());
    assert!(targets("mcp", "mcp\u{1f}files").is_some());
    assert!(targets("mcp", "mcp\u{1f}ghost").is_none());
    assert!(targets("other", "mcp\u{1f}alpha").is_none());
    assert!(targets("mcp", "other\u{1f}alpha").is_none());
    assert!(targets("mcp", "alpha").is_none());
    assert_eq!(
        targets("mcp", "mcp\u{1f}alpha")
            .unwrap()
            .registered_upstream
            .as_deref(),
        Some("alpha")
    );
}

#[test]
fn a_forward_on_a_seat_composed_from_its_upstreams_reaches_the_upstream() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    let pool = SeatPool::of("mcp", &three()).expect("the seat composes");
    let conns = Arc::new(TestConns::new());
    let breaker = Arc::new(TestBreaker::new());
    let egress = Egress {
        caller: InstanceId(1 << 40),
        conns: conns.clone(),
        breaker: crate::plane_driver::fixed_breaker(breaker.clone()),
        capacity: Arc::new(TestCapacity::new()),
        clock: TestClock::at(rt.handle().clone(), 1_000).host,
        journal: Arc::new(TestJournal::new()),
        telemetry: Arc::new(TestTelemetry::new()),
        pools: pool.pools.clone(),
        routes: pool.routes.clone(),
        stream_ceiling_secs: STREAM_CEILING_SECS,
        stated_ceiling_secs: 0,
        error_body_max: DEFAULT_ERROR_BODY_MAX,
    };
    let walk = PortEgress::new(
        Arc::new(egress),
        Arc::new(crate::teller::Kernel::new()),
        pool.pool.clone(),
        Accept::default(),
        upstream_targets("mcp", three()),
    );
    let exchange = UpExchange {
        method: Some("POST".into()),
        path: Some("/v1/call".into()),
        body: b"{}".to_vec(),
        ..UpExchange::default()
    };
    // The walk `PortEgress::walk` runs, built from the same far end and targets, driven on this runtime.
    let facts = SessionFacts {
        pending: None,
        unit: busbar_contract::UnitKey::new(9),
    };
    let token = walk.token();
    let make =
        |wants: &Wants, receipt: Option<&RequestPoolReceipt>| walk.far_end(&facts, wants, receipt);
    let walked = EgressWalk::new(&make, &token, walk.targets());
    let (picked, status) = rt.block_on(async {
        let (mut members, mut send) = (walked.members(), walked.sender());
        let wants = Wants {
            upstream: Some("alpha".into()),
            ..Wants::default()
        };
        let member = members
            .next(&wants)
            .await
            .expect("the pinned upstream is picked");
        let status = {
            let mut open = send
                .open(&member, exchange.clone())
                .await
                .expect("the upstream answers");
            while let Ok(Some(_)) = open.rest.next().await {}
            open.status
        };
        members.served(&member);
        (Some(member.upstream.to_string()), Some(status))
    });
    assert_eq!(picked.as_deref(), Some("alpha"));
    assert_eq!(status, Some(200));
    assert_eq!(
        conns.dialled(),
        ["alpha"],
        "the dial reached the configured URL"
    );
}

/// The base URL a member's WebSocket request dials: the need `websocket_ride` names, as `ride` reads it.
fn websocket_base(route: &MemberRoute) -> Option<(NeedId, String)> {
    let named = route.websocket_ride()?;
    let ride = route.ride(named)?;
    Some((ride.need, ride.base_url.to_owned()))
}

#[test]
fn a_need_over_an_upgrade_framer_spells_the_base_url_in_its_scheme() {
    let pool = SeatPool::of(
        "voice",
        &upstreams(json!({
            "secure": {"url": "https://secure.test/v1"},
            "plain": {"url": "http://127.0.0.1:9/v1"},
            "socket": {"url": "wss://socket.test/live"},
        })),
    )
    .expect("the seat composes");
    let route = |name: &str| {
        let member = pool
            .members
            .iter()
            .find(|m| &*m.upstream == name)
            .expect("the member");
        pool.routes.get(&member.destination).expect("its route")
    };
    let secure = route("secure");
    let (need, base) = websocket_base(secure).expect("an https member has a WebSocket ride");
    assert_ne!(
        need, secure.need,
        "the WebSocket spelling rides its own need"
    );
    assert_eq!(base, "wss://secure.test/v1", "https is spelled wss");
    assert_eq!(
        secure.ride(0).map(|r| (r.need, r.base_url)),
        Some((secure.need, "https://secure.test/v1")),
        "an HTTP request still dials the base URL as the operator wrote it"
    );
    let plain = route("plain");
    assert_eq!(
        websocket_base(plain).map(|(_, base)| base).as_deref(),
        Some("ws://127.0.0.1:9/v1"),
        "http is spelled ws"
    );
    let socket = route("socket");
    assert_eq!(
        socket.websocket_ride(),
        Some(0),
        "a base URL already in a WebSocket scheme is the member's own ride"
    );
    assert!(
        socket.rides.is_empty() && socket.spelled.is_empty(),
        "and it rides no second need"
    );
}

#[test]
fn a_registration_member_rides_every_member_target_need() {
    let pool = SeatPool::of("mcp", &three()).expect("the seat composes");
    let mut needs = std::collections::BTreeSet::new();
    for member in &pool.members {
        let route = pool.routes.get(&member.destination).expect("a route");
        assert!(
            needs.insert(route.need),
            "{}: its own need is its own",
            member.upstream
        );
        assert_eq!(
            route.rides.len(),
            1,
            "{}: an http(s) registration rides one more need, its WebSocket spelling",
            member.upstream
        );
        let (ride, keep) = &route.rides[0];
        assert!(
            needs.insert(*ride),
            "{}: no two needs of a seat are the same, own or ridden",
            member.upstream
        );
        assert_eq!(
            keep, &route.keep,
            "the ride keeps the member's response-head rule"
        );
        let named = ride.0 + 1;
        assert_eq!(route.ride(named).map(|r| r.need), Some(*ride));
        assert_eq!(websocket_base(route).map(|(need, _)| need), Some(*ride));
        let base = route.ride(named).expect("the ride").base_url;
        assert_eq!(
            base.split_once("://").map(|(_, rest)| rest),
            member.url.split_once("://").map(|(_, rest)| rest),
            "{}: the ride dials the member's own authority and path",
            member.upstream
        );
    }
    let unbound = needs.iter().map(|n| n.0).max().expect("needs") + 2;
    for route in pool.routes.values() {
        assert!(
            route.ride(unbound).is_none(),
            "a need no member binds is no ride"
        );
    }
}

#[test]
fn connection_route_binds_nested_declared_exchange_without_shared_auth_or_peer_identity() {
    let pool = SeatPool::of(
        "mcp",
        &upstreams(json!({"one": {
            "url": "https://resource.example/rpc",
            "allow_private": true,
            "tls": {"pin_spki": [PIN_HEX]},
        }})),
    )
    .expect("the seat composes");
    let route = pool.routes.values().next().expect("the member's route");
    assert!(
        route.auth.is_none(),
        "a registration route carries no shared configured auth"
    );
    assert_eq!(
        route.rides.len(),
        1,
        "the registration rides its WebSocket spelling"
    );
    for (need, _) in &route.rides {
        let base = route.ride(need.0 + 1).expect("the ride").base_url;
        assert_eq!(
            base, "wss://resource.example/rpc",
            "a ride is the member's own origin, never another (an exchange endpoint is its auth's, not a ride)"
        );
        let anchors = route.anchors_for(*need);
        assert!(
            anchors.client_identity.is_none(),
            "no client identity rides"
        );
        assert_eq!(
            anchors.key_pin, route.anchors.key_pin,
            "the member's own pin, at its own origin"
        );
        assert!(
            anchors.private_reach,
            "the member's own reach, at its own origin"
        );
    }
    assert!(
        route
            .spelled
            .iter()
            .all(|(_, url)| url.starts_with("wss://resource.example/")),
        "nothing is spelled at another origin: {:?}",
        route.spelled
    );
}
