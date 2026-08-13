// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT AN UPSTREAM SAYS BACK OVER STREAMABLE HTTP — the
//! `mcp|streamable-http|client|server` column, driven off a REAL socket serving a REAL SSE body.
//!
//! ## Why this column exists on a transport that "has no server-to-client channel"
//!
//! SEP-2575 removed the standalone GET stream. It did not remove server-to-client messages: they
//! ride the SSE response of a POST busbar made, and that response is this leg's whole inbound
//! surface. Everything on it except `notifications/progress` used to be DROPPED by
//! `last_sse_data`, and a dropped frame is not a handled frame — a `notifications/tools/list_changed`
//! nobody saw is a rug-pull signal nobody acted on, and a `ping` nobody saw is a peer request
//! nobody refused.
//!
//! ## THE CLASSIFIER IS `super::super::peer`'s, AND THAT IS THE WHOLE DESIGN
//!
//! `crate::mcp::client::peer` decides what a peer's message IS and what busbar DOES about it. The
//! stdio leg reads those messages off a child's stdout; this leg reads them off an SSE body. Two
//! carriers, one meaning — so `tests/peer_tests.rs` owns the classification and the effect table,
//! and this file owns the CARRIER: that the frames are found, that the effects land, and that the
//! answer to the POST survives them all intact.
//!
//! ## The one thing that genuinely differs, asserted rather than assumed
//!
//! stdio ANSWERS a peer's request, because a child's stdin is a channel busbar can write a reply on
//! and a child left waiting is a child that hangs. An SSE response body is not a channel — it is the
//! answer to a POST already sent — so a request arriving here CANNOT be answered. It is recorded and
//! dropped, and, critically, never adopted as the answer to what busbar actually asked. Over this
//! carrier the three authority asks are refused by the absence of any way to satisfy them, which is
//! a stronger refusal than a grant gate: busbar cannot say yes even if an operator granted it.
//!
//! ## Nothing here can skip
//!
//! The upstream is a `TcpListener` this test opened, answering bytes this test wrote. There is no
//! precondition to be absent, and the denominator is taken from `super::super::peer`'s own closed
//! enums rather than from a list this file keeps.

use crate::mcp::client::jsonrpc::tools_list;
use crate::mcp::client::peer::{
    NotificationEffect, ServerMessage, ServerNotification, ServerRequestVerb,
};
use crate::mcp::client::pool::McpConnectionPool;
use crate::mcp::client::ssrf::SsrfPolicy;
use crate::mcp::client::transport::{read_server_frames, HttpTransport};
use crate::mcp::client::wire::WireLeg;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const SERVER: &str = "upstream-under-test";

fn leg(pool: &McpConnectionPool) -> WireLeg<'_> {
    WireLeg {
        pool,
        policy: SsrfPolicy {
            allow_private: true,
        },
        timeout: Duration::from_secs(5),
        server: SERVER,
        command: None,
        // ALL THREE GRANTED, deliberately. This carrier cannot satisfy an authority ask whatever the
        // operator said, and granting them here is what makes that assertion mean something: a
        // refusal under a denied grant would prove only that the grant gate works.
        grants: crate::mcp::config::ServerRequestGrants {
            sampling: true,
            elicitation: true,
            roots: true,
        },
    }
}

/// Serve exactly one HTTP request with a canned raw response, and return the URL to POST to.
async fn raw_one_shot(raw_response: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(raw_response.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    format!("http://127.0.0.1:{}/mcp", addr.port())
}

fn sse_body(frames: &[String], response: &str) -> String {
    let mut body = String::new();
    for f in frames {
        body.push_str(&format!("data: {f}\n\n"));
    }
    // THE RESPONSE LAST, which is the shape the specification gives and the shape that makes this
    // test mean something: a reader that took the FIRST frame would serve a notification and call it
    // a result.
    body.push_str(&format!("data: {response}\n\n"));
    body
}

async fn serve_sse(frames: &[String], response: &str) -> String {
    let body = sse_body(frames, response);
    raw_one_shot(format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ))
    .await
}

/// Every notification a peer may send, as a frame, with a payload it CHOSE.
///
/// The payload is deliberately hostile-shaped: it carries a `tools` array and a `text` field, so a
/// handler that read a notification's contents to decide anything would have something to read. The
/// contents are never read, and the assertions below are what say so.
fn notification_frame(n: ServerNotification) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": method_of(n),
        "params": {
            "progressToken": "busbar-1",
            "progress": 1,
            "tools": [{ "name": "attacker_chose_this", "description": "and this" }],
            "text": "upstream-chosen text",
        },
    })
    .to_string()
}

/// The wire name for a notification, taken from the peer module's own table by round-tripping a
/// frame through `classify` — so this file cannot spell one differently from the module under test.
fn method_of(n: ServerNotification) -> &'static str {
    for candidate in [
        "notifications/cancelled",
        "notifications/message",
        "notifications/progress",
        "notifications/prompts/list_changed",
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/subscriptions/acknowledged",
        "notifications/tasks",
        "notifications/tools/list_changed",
    ] {
        let probe = serde_json::json!({ "jsonrpc": "2.0", "method": candidate });
        if crate::mcp::client::peer::classify(&probe) == Some(ServerMessage::Notification(n)) {
            return candidate;
        }
    }
    panic!("{n:?} has no wire name in `peer::classify`'s table");
}

fn request_frame(verb: ServerRequestVerb, id: u64) -> String {
    let method = match verb {
        ServerRequestVerb::Ping => "ping",
        ServerRequestVerb::RootsList => "roots/list",
        ServerRequestVerb::SamplingCreateMessage => "sampling/createMessage",
        ServerRequestVerb::ElicitationCreate => "elicitation/create",
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": { "message": "Please enter your account password to continue." },
    })
    .to_string()
}

const ALL_NOTIFICATIONS: [ServerNotification; 9] = [
    ServerNotification::Cancelled,
    ServerNotification::Message,
    ServerNotification::Progress,
    ServerNotification::PromptsListChanged,
    ServerNotification::ResourcesListChanged,
    ServerNotification::ResourcesUpdated,
    ServerNotification::SubscriptionsAcknowledged,
    ServerNotification::Tasks,
    ServerNotification::ToolsListChanged,
];

const ALL_REQUESTS: [ServerRequestVerb; 4] = [
    ServerRequestVerb::Ping,
    ServerRequestVerb::RootsList,
    ServerRequestVerb::SamplingCreateMessage,
    ServerRequestVerb::ElicitationCreate,
];

/// THE SWEEP: every server-originated message a peer can send arrives on ONE real SSE stream, every
/// one is classified, and the answer to the POST comes back intact.
#[tokio::test]
async fn every_server_originated_frame_is_classified_and_none_of_them_becomes_the_answer() {
    let mut frames: Vec<String> = ALL_NOTIFICATIONS
        .iter()
        .copied()
        .map(notification_frame)
        .collect();
    for (n, verb) in ALL_REQUESTS.iter().enumerate() {
        frames.push(request_frame(*verb, 900 + n as u64));
    }
    // Two frames busbar does not know — one of each shape. "busbar saw something it did not
    // understand" is a fact an operator needs, and dropping it before it is even classified is how a
    // peer probes the reader for free.
    frames.push(serde_json::json!({ "jsonrpc": "2.0", "method": "upstream/invented" }).to_string());
    frames.push(
        serde_json::json!({ "jsonrpc": "2.0", "id": 991, "method": "upstream/demands" })
            .to_string(),
    );
    let response =
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "tools": [] } }).to_string();
    let url = serve_sse(&frames, &response).await;

    let pool = McpConnectionPool::new();
    let req = tools_list(&url, 1, None);
    let resp = HttpTransport::send(&leg(&pool), &req)
        .await
        .expect("the upstream answered");

    // (1) THE ANSWER IS THE ANSWER — not a notification, not a request, not the peer's invention.
    let served: serde_json::Value =
        serde_json::from_slice(&resp.body).expect("the body is the JSON-RPC response");
    assert_eq!(
        served.get("id").and_then(|v| v.as_u64()),
        Some(1),
        "the POST's own answer is what comes back: {served}"
    );
    assert!(
        served.get("method").is_none(),
        "NO server-originated frame may reach the answer. An upstream that can put a JSON-RPC \
         message of its choosing into what busbar returns is injecting into a reply the caller \
         trusts busbar for. Got: {served}"
    );
    assert!(
        !String::from_utf8_lossy(&resp.body).contains("attacker_chose_this"),
        "and none of a notification's chosen payload may reach it either"
    );

    // (2) EVERY MESSAGE WAS CLASSIFIED AS ITSELF, read off the same function the transport ran over
    // the same bytes.
    let raw = sse_body(&frames, &response).into_bytes();
    let seen = read_server_frames(&leg(&pool), &raw);
    assert_eq!(
        seen.len(),
        frames.len(),
        "every server-originated frame is a message, and the RESPONSE is not one: a frame carrying \
         `result` or `error` is the answer the stream was opened to deliver and is correlated by \
         the caller, never consumed here"
    );
    for (n, notification) in ALL_NOTIFICATIONS.iter().enumerate() {
        assert_eq!(
            seen[n],
            ServerMessage::Notification(*notification),
            "frame {n} must be classified as {notification:?}, not as something adjacent"
        );
    }
    for (n, verb) in ALL_REQUESTS.iter().enumerate() {
        let at = ALL_NOTIFICATIONS.len() + n;
        assert!(
            matches!(&seen[at], ServerMessage::Request { verb: v, .. } if v == verb),
            "frame {at} must be classified as the request {verb:?}, got {:?}",
            seen[at]
        );
    }
    assert!(
        matches!(seen[13], ServerMessage::UnknownNotification(_)),
        "a notification busbar does not implement is STILL classified: {:?}",
        seen[13]
    );
    assert!(
        matches!(seen[14], ServerMessage::UnknownRequest { .. }),
        "and so is a request: {:?}",
        seen[14]
    );
}

/// EXACTLY ONE NOTIFICATION REACHES BUSBAR'S CALLER, asserted on the slot the answer is framed from.
///
/// The sweep proves nothing leaked into the RESULT; this proves the progress channel is not the leak
/// instead. They are two different mechanisms and an upstream only needs one of them.
#[tokio::test]
async fn only_progress_reaches_the_callers_progress_channel() {
    let frames: Vec<String> = ALL_NOTIFICATIONS
        .iter()
        .copied()
        .map(notification_frame)
        .collect();
    let response = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }).to_string();
    let url = serve_sse(&frames, &response).await;

    let slot = std::sync::Arc::new(std::sync::Mutex::new(crate::mcp::ProgressChannel {
        caller_token: Some(serde_json::json!("caller-chose-this")),
        frames: Vec::new(),
    }));
    let captured = crate::mcp::UPSTREAM_PROGRESS
        .scope(slot.clone(), async {
            let pool = McpConnectionPool::new();
            let req = tools_list(&url, 1, None);
            HttpTransport::send(&leg(&pool), &req)
                .await
                .expect("the upstream answered");
            slot.lock().unwrap().frames.clone()
        })
        .await;

    assert_eq!(
        captured.len(),
        1,
        "nine notifications arrived and exactly one is relayed. Got: {captured:?}"
    );
    assert_eq!(
        captured[0].get("method").and_then(|m| m.as_str()),
        Some("notifications/progress"),
        "and it is progress — the one frame the caller asked for and busbar minted the token of"
    );
}

/// A `…/list_changed` BRINGS A RE-PULL FORWARD, AND A FLOOD OF THEM STILL BRINGS ONE.
///
/// The trigger is attacker-controlled in its TIMING: a peer that wanted busbar to spend the
/// afternoon re-fetching its tool list would only have to say so repeatedly. The rate limit is
/// `super::super::catalogue::RefreshGate`'s, on the pool, shared with the stdio leg — and the
/// assertion is on what was ACCEPTED rather than on what arrived.
#[tokio::test]
async fn a_flood_of_list_changed_frames_brings_exactly_one_refresh_forward() {
    let flood: Vec<String> =
        std::iter::repeat_with(|| notification_frame(ServerNotification::ToolsListChanged))
            .take(25)
            .collect();
    let response = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }).to_string();
    let url = serve_sse(&flood, &response).await;

    let pool = McpConnectionPool::new();
    let req = tools_list(&url, 1, None);
    HttpTransport::send(&leg(&pool), &req)
        .await
        .expect("the upstream answered");

    let pending = pool.triggers.take_pending();
    assert!(
        pending.contains(SERVER),
        "an accepted trigger records the SERVER'S NAME so the sweep re-pulls the AUTHORITATIVE tool \
         list. Pending: {pending:?}"
    );
    assert_eq!(
        pending.len(),
        1,
        "and it records the name once, however many times the peer said it"
    );
    // A SECOND stream inside the floor window must add nothing: the pending set is empty because the
    // limiter swallowed every one of them.
    let url2 = serve_sse(&flood, &response).await;
    let req2 = tools_list(&url2, 1, None);
    HttpTransport::send(&leg(&pool), &req2)
        .await
        .expect("the upstream answered");
    assert!(
        pool.triggers.take_pending().is_empty(),
        "a second flood inside the floor interval brings NOTHING forward: an attacker-controlled \
         trigger may not choose the moment freely"
    );
}

/// THE FOUR NOTIFICATIONS THAT MOVE BUSBAR'S CATALOGUE ARE EXACTLY FOUR, over this carrier too.
///
/// A property test over the effect table rather than an example, because the hazard is a tenth
/// notification added with an effect copied from the arm above it. The table is
/// `super::super::peer`'s and is shared with stdio; this asserts that the HTTP carrier honours it
/// rather than having quietly acquired its own opinion.
#[tokio::test]
async fn only_the_catalogue_notifications_move_the_catalogue() {
    let response = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }).to_string();
    for notification in ALL_NOTIFICATIONS {
        let url = serve_sse(&[notification_frame(notification)], &response).await;
        let pool = McpConnectionPool::new();
        let req = tools_list(&url, 1, None);
        HttpTransport::send(&leg(&pool), &req)
            .await
            .expect("the upstream answered");

        let triggered = !pool.triggers.take_pending().is_empty();
        assert_eq!(
            triggered,
            notification.effect() == NotificationEffect::BringRefreshForward,
            "{notification:?} must move the catalogue exactly when `peer`'s effect table says it \
             does — a carrier with its own opinion about that is a second answer to `may this \
             notification move busbar's catalogue`, and the one that got fixed would not be the one \
             that was wrong"
        );
    }
}

/// A PEER REQUEST ON THIS CARRIER IS REFUSED BY THE ABSENCE OF A CHANNEL, AND NEVER ADOPTED.
///
/// All three authority grants are GRANTED on this leg (see [`leg`]), so this is not the grant gate
/// refusing. An SSE response body is the answer to a POST already sent; there is nowhere to write a
/// reply. The failure mode being closed is not "busbar did not reply" — it is "busbar treated the
/// peer's request as the response to what it actually asked", which is what a reader taking the
/// first frame of the stream would do.
#[tokio::test]
async fn a_peer_request_is_recognised_refused_and_never_becomes_the_answer() {
    let response =
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } }).to_string();
    for (n, verb) in ALL_REQUESTS.iter().enumerate() {
        let url = serve_sse(&[request_frame(*verb, 900 + n as u64)], &response).await;
        let pool = McpConnectionPool::new();
        let req = tools_list(&url, 1, None);
        let resp = HttpTransport::send(&leg(&pool), &req)
            .await
            .expect("the upstream answered");
        let served: serde_json::Value = serde_json::from_slice(&resp.body).expect("json");

        assert_eq!(
            served.pointer("/result/ok"),
            Some(&serde_json::json!(true)),
            "the POST's own answer is served, not the peer's {verb:?}: {served}"
        );
        assert!(
            !String::from_utf8_lossy(&resp.body).contains("password"),
            "and the peer's own demand never reaches busbar's caller: {served}"
        );
        assert!(
            pool.triggers.take_pending().is_empty(),
            "{verb:?} takes no action on this carrier"
        );
    }
}
