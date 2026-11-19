// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A signed webhook (`POST /v1/llm/webhooks/openai`, Standard Webhooks: HMAC-SHA256 over
//! `id.timestamp.body` in `webhook-id`, `webhook-timestamp`, `webhook-signature`). The sender
//! holds no key: its signature admits it. A delivery whose body is not the one that was signed is
//! refused, and is told exactly what a sender with no signature is told.

#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_section_tools,
    linked_section_agents,
    linked_section_decisions,
    linked_section_streams
))]

mod common;
mod e2e_support;

use base64::Engine as _;
use e2e_support::{chat_answer, llm, send, Node, Reply, Scripted, WEBHOOK_SIGNATURE_IMAGE};

/// The secret the sender and the deployment share: 32 bytes, written as the sender's console
/// shows it (`whsec_` and its base64).
const SECRET: [u8; 32] = *b"e2e-standard-webhooks-secret-32b";
const SECRET_ENV: &str = "E2E_WEBHOOK_SECRET";

const WEBHOOK: &str = "/v1/llm/webhooks/openai";
const EVENT: &[u8] =
    br#"{"id":"evt_e2e_1","object":"event","type":"response.completed","created_at":1,"data":{"id":"resp_e2e_1"}}"#;

fn boot(tag: &str, upstream: &Scripted) -> Node {
    let b64 = base64::engine::general_purpose::STANDARD;
    llm(tag, upstream, None)
        .plugin("auth", WEBHOOK_SIGNATURE_IMAGE)
        .identity(
            "openai-webhooks",
            &format!(
                "{{ module: webhook-signature, settings: {{ variant: standard-webhooks, \
                 signing_secret: {{ env: {SECRET_ENV} }} }} }}"
            ),
        )
        .env(SECRET_ENV, &format!("whsec_{}", b64.encode(SECRET)))
        .boot()
}

/// The three headers of a delivery of `signed` made now, under the shared secret.
fn signature_headers(id: &str, signed: &[u8]) -> [(&'static str, String); 3] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        .to_string();
    let key = busbar_contract::crypto::HmacSha256Key::new(&SECRET).expect("an HMAC key");
    let dot = ".".as_bytes();
    let mac = key.sign_parts(&[id.as_bytes(), dot, now.as_bytes(), dot, signed]);
    let b64 = base64::engine::general_purpose::STANDARD;
    [
        ("webhook-id", id.to_owned()),
        ("webhook-timestamp", now),
        ("webhook-signature", format!("v1,{}", b64.encode(mac))),
    ]
}

/// Deliver `body` under `headers`.
fn deliver(node: &Node, headers: &[(&'static str, String)], body: &[u8]) -> Reply {
    let mut sent = vec![("Content-Type", "application/json")];
    sent.extend(headers.iter().map(|(name, value)| (*name, value.as_str())));
    send(node.data, "POST", WEBHOOK, &sent, body)
}

#[test]
fn a_delivery_signed_by_the_shared_secret_is_admitted() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = boot("webhook-valid", &upstream);

    let reply = deliver(&node, &signature_headers("msg_e2e_valid", EVENT), EVENT);

    assert!(
        reply.status != 401 && reply.status != 403,
        "a correctly signed delivery: answered {} {}",
        reply.status,
        reply.text()
    );
    assert_eq!(
        reply.header("www-authenticate"),
        None,
        "an admitted sender is not challenged"
    );
}

#[test]
fn a_delivery_whose_body_is_not_the_one_signed_is_refused() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = boot("webhook-modified", &upstream);
    // One byte of the signed body differs: the event names another response.
    let modified: Vec<u8> = String::from_utf8_lossy(EVENT)
        .replace("resp_e2e_1", "resp_e2e_2")
        .into_bytes();
    assert_eq!(modified.len(), EVENT.len());

    let reply = deliver(
        &node,
        &signature_headers("msg_e2e_modified", EVENT),
        &modified,
    );

    assert!(
        reply.is_the_unverified_answer(),
        "a delivery whose body was changed after signing: answered {} {}",
        reply.status,
        reply.text()
    );
    // It is told what a sender with no signature at all is told, and nothing about why.
    let unsigned = deliver(&node, &[], &modified);
    assert_eq!(
        (
            reply.status,
            &reply.body,
            reply.header("www-authenticate"),
            reply.header_names()
        ),
        (
            unsigned.status,
            &unsigned.body,
            unsigned.header("www-authenticate"),
            unsigned.header_names()
        ),
        "a bad signature is told something no signature is not"
    );
    // The same node admits the same sender when the body is the one it signed.
    let honest = deliver(&node, &signature_headers("msg_e2e_honest", EVENT), EVENT);
    assert!(
        honest.status != 401 && honest.status != 403,
        "the route is served to a correct signature on this node: answered {} {}",
        honest.status,
        honest.text()
    );
}
