// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-DEFAULTS (ABI-MIN3-INTERFACE §14): `offer(ROLE_CLIENT)` defaults and the head order; the
//! transport-ws ROLE_CLIENT arm (rounds 22, 23).
//!
//! W1-K8B's arm is the head a binding's `outbound` sees (`busbar_kernel::auth::upstream_binding`): the plane's
//! lines, then each transport default the head lacks, never one of the four framer-owned handshake names, and
//! the authority with no default port. The transport, sigv4 and ws image arms are the transport switch-over's.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_kernel::auth::upstream_binding::{authority, framer_owned, upstream_head};
use busbar_plugin_abi::types::{Bytes, Pair, Str};

fn pair<'a>(name: &'a str, value: &'a str) -> Pair<'a> {
    Pair {
        name: Str::new(name),
        value: Bytes::new(value.as_bytes()),
    }
}

fn lines<'a>(head: &[Pair<'a>]) -> Vec<(&'a str, &'a [u8])> {
    head.iter().map(|p| (p.name.get(), p.value.get())).collect()
}

#[test]
fn client_defaults_and_head_order() {
    let grpc = [
        pair("content-type", "application/grpc"),
        pair("te", "trailers"),
    ];
    let plane = [pair("x-request-id", "r1")];
    assert_eq!(
        lines(&upstream_head(&plane, &grpc)),
        vec![
            ("x-request-id", &b"r1"[..]),
            ("content-type", &b"application/grpc"[..]),
            ("te", &b"trailers"[..]),
        ],
        "a head without content-type gets the transport's, once, before outbound"
    );
    let own = [pair("Content-Type", "application/grpc+proto")];
    assert_eq!(
        lines(&upstream_head(&own, &grpc)),
        vec![
            ("Content-Type", &b"application/grpc+proto"[..]),
            ("te", &b"trailers"[..])
        ],
        "a plane head that states its own content-type keeps it"
    );
}

#[test]
fn the_four_handshake_names_never_reach_outbound() {
    let plane = [
        pair("connection", "keep-alive"),
        pair("Upgrade", "websocket"),
        pair("sec-websocket-protocol", "realtime"),
        pair("Sec-WebSocket-Key", "c3RhbGU="),
    ];
    let defaults = [pair("sec-websocket-version", "13"), pair("accept", "*/*")];
    assert_eq!(
        lines(&upstream_head(&plane, &defaults)),
        vec![
            ("sec-websocket-protocol", &b"realtime"[..]),
            ("accept", &b"*/*"[..])
        ]
    );
    for name in [
        "upgrade",
        "CONNECTION",
        "sec-websocket-key",
        "Sec-WebSocket-Version",
    ] {
        assert!(framer_owned(name));
    }
    assert!(!framer_owned("sec-websocket-protocol"));
}

#[test]
fn the_authority_elides_the_default_port() {
    let at = |u: &str| authority(&url::Url::parse(u).expect("url"));
    assert_eq!(
        at("https://api.example:443/v1").as_deref(),
        Some("api.example")
    );
    assert_eq!(at("http://api.example:80/").as_deref(), Some("api.example"));
    assert_eq!(
        at("https://api.example:8443/").as_deref(),
        Some("api.example:8443")
    );
    assert_eq!(at("http://[::1]:8080/").as_deref(), Some("[::1]:8080"));
}

#[test]
#[ignore = "owner: W2-SW-TRANSPORT (the transport-grpc, transport-http, transport-ws and auth-sigv4 image arms)"]
fn transport_image_arms() {
    todo!("owner: W2-SW-TRANSPORT (C-TRANSPORT-DEFAULTS image arms)")
}
