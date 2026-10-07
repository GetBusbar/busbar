// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The previous release's engine tests whose behaviour this unit owns now: the per-attempt cap's
//! floor, and the neutral client-header mechanism (what of a client's head goes upstream on a
//! same-dialect route, and how it folds into the head busbar builds).
//!
//! Each test names the legacy test it carries over and keeps its inputs and expected values.

use busbar_contract::http::{HeaderMap, HeaderName, HeaderValue};

use crate::attempt::attempt_cap_ms;
use crate::upstream::{apply_client_headers, collect_client_headers, strip_re_derived};

/// Ports legacy `attempt_timeout_precedence_tests.rs::test_attempt_cap_budget_floor`: the
/// per-attempt cap is the configured value while the request has the time, the request's
/// remaining budget when it has less, and never zero, even with the budget spent.
#[test]
fn the_attempt_cap_is_floored_by_the_remaining_budget_and_never_zero() {
    // Plenty of budget (30 s): the cap is the configured value.
    assert_eq!(attempt_cap_ms(200, 30_000), 200);
    // A cap larger than the remaining budget (2 s) is clamped to it.
    assert_eq!(attempt_cap_ms(10_000, 2_000), 2_000);
    // A spent budget: 1 ms, never a zero-length (instant-fail) timer.
    assert_eq!(attempt_cap_ms(10_000, 0), 1);
}

/// Ports legacy `client_header_forwarding_tests.rs::neutral_collect_keeps_all_but_mechanics_and_governed`:
/// every client header is kept, in order and with its multiplicity, except the per-connection
/// mechanics (a field the `connection` field nominates, `transfer-encoding`, `host`,
/// `content-length`), busbar's own namespace and the names the plane governs.
#[test]
fn collecting_a_clients_head_keeps_all_but_the_mechanics_and_the_governed() {
    let mut hm = HeaderMap::new();
    for (n, v) in [
        ("x-made-up-alpha", "a1"),
        ("x-made-up-alpha", "a2"),
        ("x-made-up-governed", "g"),
        ("x-busbar-made-up", "busbar's own"),
        ("connection", "x-made-up-nominated"),
        ("x-made-up-nominated", "n"),
        ("transfer-encoding", "chunked"),
        ("host", "h"),
        ("content-length", "1"),
    ] {
        hm.append(HeaderName::from_static(n), HeaderValue::from_static(v));
    }
    let got = collect_client_headers(&hm, |n| n == "x-made-up-governed");
    let names: Vec<(&str, &str)> = got
        .iter()
        .map(|(n, v)| (n.as_str(), v.to_str().unwrap()))
        .collect();
    assert_eq!(
        names,
        vec![("x-made-up-alpha", "a1"), ("x-made-up-alpha", "a2")]
    );
}

/// Ports legacy `client_header_forwarding_tests.rs::neutral_apply_replaces_then_appends`: folding
/// collected headers into the head busbar built replaces busbar's default with the caller's first
/// value and appends the rest.
#[test]
fn folding_a_clients_headers_replaces_the_default_then_appends() {
    let name = HeaderName::from_static("x-made-up-multi");
    let collected = vec![
        (name.clone(), HeaderValue::from_static("first")),
        (name.clone(), HeaderValue::from_static("second")),
    ];
    let mut egress = HeaderMap::new();
    egress.insert(name.clone(), HeaderValue::from_static("busbar-default"));
    apply_client_headers(&mut egress, &collected);
    let values: Vec<_> = egress
        .get_all(&name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(values, vec!["first", "second"]);
}

/// Ports legacy `client_header_forwarding_tests.rs::hop_by_hop_host_and_length_are_re_derived`, on
/// the head a plane hands the far end: the hop-by-hop fields, a field the `connection` field
/// nominates, `host` and `content-length` are dropped (the upstream connection derives its own);
/// every other field passes.
#[test]
fn the_head_a_plane_hands_the_far_end_drops_the_mechanics_and_keeps_the_rest() {
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = [
        ("connection", "keep-alive, x-nominated"),
        ("x-nominated", "1"),
        ("keep-alive", "timeout=5"),
        ("te", "trailers"),
        ("upgrade", "websocket"),
        ("proxy-authorization", "Basic Zm9v"),
        ("host", "client.example"),
        ("content-length", "9999"),
        ("x-client-trace", "abc"),
    ]
    .into_iter()
    .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
    .collect();
    strip_re_derived(&mut fields);
    let kept: Vec<(String, String)> = fields
        .iter()
        .map(|(n, v)| {
            (
                String::from_utf8_lossy(n).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            )
        })
        .collect();
    assert_eq!(
        kept,
        vec![("x-client-trace".to_string(), "abc".to_string())],
        "every per-connection field is dropped and the caller's own field passes"
    );
}
