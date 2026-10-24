// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which needs a member dials: resolved at config load by its auth key, every outbound need it
//! names, one binding per (transport, auth).

use super::*;
use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
use busbar_contract::abi::mechanism::rendering::ReadBlob;

fn need(direction: u32, auth: &str) -> ReadNeed {
    need_over(direction, "t", auth)
}

fn need_over(direction: u32, transport: &str, auth: &str) -> ReadNeed {
    ReadNeed {
        direction,
        egress_class: 0,
        transport: transport.to_string(),
        auth: auth.to_string(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

fn member<'a>(member: &'a str, auth: &'a str) -> MemberAuth<'a> {
    MemberAuth { member, auth }
}

#[test]
fn each_member_dials_the_one_outbound_need_its_auth_key_names() {
    let needs = [
        need(DIRECTION_INBOUND, "key-a"),
        need(DIRECTION_OUTBOUND, "key-a"),
        need(DIRECTION_OUTBOUND, "key-b"),
    ];
    let got = resolve_member_needs(
        &needs,
        &[
            member("m1", "key-a"),
            member("m2", "key-b"),
            member("m3", "key-a"),
        ],
    )
    .expect("every member resolves");
    assert_eq!(
        got.get("m1"),
        Some(&vec![NeedId(1)]),
        "the inbound need is not dialled"
    );
    assert_eq!(got.get("m2"), Some(&vec![NeedId(2)]));
    assert_eq!(got.get("m3"), Some(&vec![NeedId(1)]));
}

#[test]
fn a_member_with_no_auth_binding_dials_the_need_that_declares_none() {
    let needs = [
        need(DIRECTION_OUTBOUND, ""),
        need(DIRECTION_OUTBOUND, "key-a"),
    ];
    let got = resolve_member_needs(&needs, &[member("m", "")]).expect("resolves");
    assert_eq!(got.get("m"), Some(&vec![NeedId(0)]));
}

/// RED: a member whose auth key matches no declared outbound need refuses the load, naming the
/// member and the keys.
#[test]
fn red_a_member_whose_auth_matches_no_need_refuses_the_load() {
    let needs = [
        need(DIRECTION_OUTBOUND, "key-a"),
        need(DIRECTION_INBOUND, "key-c"),
    ];
    let refused = resolve_member_needs(&needs, &[member("m1", "key-a"), member("m2", "key-c")])
        .expect_err("key-c is only an inbound need");
    assert_eq!(
        refused,
        NeedRefusal::NoMatch {
            member: "m2".to_string(),
            auth: "key-c".to_string(),
            declared: vec!["key-a".to_string()],
        }
    );
    let text = refused.to_string();
    for word in ["'m2'", "'key-c'", "'key-a'"] {
        assert!(text.contains(word), "{text}");
    }
}

/// MULTI-NEED (ARCHITECT Q-L5B-NEEDS 2026-10-03): a member binds EVERY outbound need its auth key
/// names, one per transport, in declared order; two over one transport is one binding twice.
#[test]
fn a_member_binds_every_need_its_auth_names_one_per_transport() {
    let needs = [
        need_over(DIRECTION_INBOUND, "ws", "key-a"),
        need_over(DIRECTION_OUTBOUND, "ws", "key-a"),
        need_over(DIRECTION_OUTBOUND, "http", "key-a"),
        need_over(DIRECTION_OUTBOUND, "http", "key-b"),
    ];
    let got = resolve_member_needs(&needs, &[member("m", "key-a"), member("n", "key-b")])
        .expect("both resolve");
    assert_eq!(got.get("m"), Some(&vec![NeedId(1), NeedId(2)]));
    assert_eq!(got.get("n"), Some(&vec![NeedId(3)]));
}

#[test]
fn a_member_whose_auth_two_needs_declare_refuses_the_load() {
    let needs = [
        need(DIRECTION_OUTBOUND, "key-a"),
        need(DIRECTION_OUTBOUND, "key-a"),
    ];
    let refused =
        resolve_member_needs(&needs, &[member("m", "key-a")]).expect_err("two needs match");
    assert_eq!(
        refused,
        NeedRefusal::Ambiguous {
            member: "m".to_string(),
            auth: "key-a".to_string(),
            needs: vec![NeedId(0), NeedId(1)],
        }
    );
    assert!(refused.to_string().contains("'m'"));
}
