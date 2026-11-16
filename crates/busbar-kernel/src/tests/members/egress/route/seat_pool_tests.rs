// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! K9 (PLANE-DRIVER.md "BOOT (K9)"): the pool a plane seat walks is composed from the instance's configured upstreams
//! ([`SeatPool::of`]), and a FORWARD on a seat composed that way reaches the configured upstream through the real
//! walk ([`PortEgress`] over [`Egress`]), the harness's fake connection table standing in for the connector.

use std::collections::BTreeMap;

use busbar_plugin_abi::host_side::caller::Accept;
use serde_json::json;

use super::*;
use crate::plane_driver::port_egress::{
    upstream_targets, PortEgress, PortUpstream, SeatPool, SessionFacts,
};
use crate::plane_driver::port_session::UpExchange;
use crate::plane_driver::port_upstream::{Members, UpSend, Wants};
use crate::upstreams::{ConfiguredUpstreams, Upstreams};

const PIN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const OTHER_PIN_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

fn upstreams(section: serde_json::Value) -> Arc<ConfiguredUpstreams> {
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
            (DestinationId::new(0), "alpha".to_owned()),
            (DestinationId::new(1), "beta".to_owned())
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
    let targets = upstream_targets(table);
    assert!(targets("alpha").is_some());
    assert!(targets("files").is_some());
    assert!(targets("ghost").is_none());
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
        clock: Arc::new(TestClock::at(rt.handle().clone(), 1_000)),
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
        rt.handle().clone(),
        pool.pool.clone(),
        Accept::default(),
        upstream_targets(three()),
    );
    let exchange = UpExchange {
        method: Some("POST".into()),
        path: Some("/v1/call".into()),
        body: b"{}".to_vec(),
        ..UpExchange::default()
    };
    let mut picked = None;
    let mut status = None;
    walk.walk(
        SessionFacts {
            unit: busbar_contract::UnitKey::new(9),
        },
        &mut |members: &mut dyn Members, send: &mut dyn UpSend| {
            let wants = Wants {
                upstream: Some("alpha".into()),
                ..Wants::default()
            };
            let member = members.next(&wants).expect("the pinned upstream is picked");
            picked = Some(member.upstream.to_string());
            let reply = send.send(&member, &exchange).expect("the upstream answers");
            status = Some(reply.status);
            members.served(&member);
        },
    );
    assert_eq!(picked.as_deref(), Some("alpha"));
    assert_eq!(status, Some(200));
    assert_eq!(
        conns.dialled(),
        ["alpha"],
        "the dial reached the configured URL"
    );
}
