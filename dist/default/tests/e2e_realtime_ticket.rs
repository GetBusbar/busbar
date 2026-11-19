// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The realtime ticket: a key's holder mints one (`POST /v1/realtime/client_secrets`) and hands it
//! to a browser, which places one call with it (`POST /v1/realtime/calls`). The ticket admits that
//! call once. Presented again it is refused, as a ticket nobody minted is: the one unverified
//! answer, with nothing about which of the two it was.

#![cfg(unix)]
#![cfg(linked_every_plane_door)]

mod common;
mod e2e_support;

use e2e_support::{
    bearer, post_json, realtime, send, streams_section, Deployment, Node, Reply, Scripted,
};
use serde_json::{json, Value};

/// A browser's offer: one audio line and one data channel, as an OpenAI Realtime client sends.
const OFFER: &str = "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
a=group:BUNDLE 0 1\r\na=msid-semantic: WMS\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\n\
a=ice-ufrag:e2eU\r\na=ice-pwd:e2ePasswordOfTwentyTwoCh\r\n\
a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF\r\n\
a=setup:actpass\r\na=mid:0\r\na=sendrecv\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:e2eU\r\na=ice-pwd:e2ePasswordOfTwentyTwoCh\r\n\
a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF\r\n\
a=setup:actpass\r\na=mid:1\r\na=sctp-port:5000\r\n";

/// A node whose realtime provider answers every request the same way: what the plane makes of the
/// provider's answer to a placed call is the plane's own suite's subject, not admission's.
fn boot(tag: &str, provider: &Scripted) -> Node {
    realtime(Deployment::new(tag), &provider.url(""))
        .section(&streams_section(""))
        .boot()
}

/// Mint a ticket as a new key's holder.
fn mint_ticket(node: &Node) -> String {
    let key = node.mint(&json!({ "name": "e2e-ticket" }));
    let minted = post_json(
        node.data,
        "/v1/realtime/client_secrets",
        &key.token,
        br#"{"session":{"type":"realtime","model":"test-model"}}"#,
    );
    assert_eq!(minted.status, 200, "the mint: {}", minted.text());
    fn find(value: &Value) -> Option<String> {
        match value {
            Value::String(text) if text.starts_with("ek_") => Some(text.clone()),
            Value::Array(items) => items.iter().find_map(find),
            Value::Object(members) => members.values().find_map(find),
            _ => None,
        }
    }
    find(&minted.json()).unwrap_or_else(|| panic!("a mint states its ticket: {}", minted.text()))
}

/// Place a call presenting `ticket` as the browser does.
fn call(node: &Node, ticket: &str) -> Reply {
    let authorization = bearer(ticket);
    send(
        node.data,
        "POST",
        "/v1/realtime/calls",
        &[
            ("Authorization", authorization.as_str()),
            ("Content-Type", "application/sdp"),
        ],
        OFFER.as_bytes(),
    )
}

#[test]
fn a_minted_ticket_admits_one_call() {
    let provider = Scripted::start(201, &json!({}));
    let node = boot("ticket-once", &provider);
    let ticket = mint_ticket(&node);

    let placed = call(&node, &ticket);

    assert!(
        placed.admitted(),
        "a call presenting a ticket just minted: answered {} {}",
        placed.status,
        placed.text()
    );
    assert_eq!(
        placed.header("www-authenticate"),
        None,
        "an admitted caller is not challenged"
    );
}

#[test]
fn a_ticket_presented_a_second_time_is_refused() {
    let provider = Scripted::start(201, &json!({}));
    let node = boot("ticket-twice", &provider);
    let ticket = mint_ticket(&node);
    let first = call(&node, &ticket);
    assert!(
        first.admitted(),
        "the ticket's one call: answered {} {}",
        first.status,
        first.text()
    );

    let second = call(&node, &ticket);

    assert!(
        second.is_the_unverified_answer(),
        "the same ticket again: answered {} {}",
        second.status,
        second.text()
    );
    // A spent ticket and one nobody minted are told the same thing.
    let forged = call(&node, "ek_not_a_ticket_anyone_minted");
    assert_eq!(
        (second.status, &second.body, second.header_names()),
        (forged.status, &forged.body, forged.header_names()),
        "a spent ticket is told something a forged one is not"
    );
    assert_eq!(
        second.header("www-authenticate"),
        forged.header("www-authenticate")
    );
}
