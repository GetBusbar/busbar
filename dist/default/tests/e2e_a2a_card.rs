// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A2A discovery through the real binary (A2A v1.0 section 8.2): with an agent registered and
//! `public_url` set, busbar's own agent card is served, unauthenticated, at
//! `/.well-known/agent-card.json`, and every address it publishes is built from the configured
//! `public_url`. The public card enumerates no fronted agent and never names the agent's own
//! address. A path the plane does not claim is still 404.

#![cfg(unix)]
#![cfg(linked_section_agents)]

mod common;
mod e2e_support;

use e2e_support::{closed_port, send, Deployment, Node};
use serde_json::Value;

/// The registered agent's name.
const AGENT: &str = "conformance-agent";

/// The A2A section as the conformance run writes it (the plane's settings `format` 2): one agent,
/// at an address nothing listens on (the public card dials nothing).
fn boot(tag: &str, agent_port: u16) -> Node {
    Deployment::new(tag)
        .section(&format!(
            "a2a:\n  format: 2\n  agents:\n    {AGENT}:\n      \
             url: \"http://127.0.0.1:{agent_port}/a2a\"\n      pin: unpinned\n"
        ))
        .boot()
}

/// The interface the card offers on `binding`.
fn interface<'a>(card: &'a Value, binding: &str) -> Option<&'a Value> {
    card["supportedInterfaces"]
        .as_array()?
        .iter()
        .find(|i| i["protocolBinding"] == binding)
}

#[test]
fn a2a_card_is_served_at_the_well_known_path_with_the_configured_public_url() {
    let agent_port = closed_port();
    let node = boot("a2a-card", agent_port);
    let public_url = format!("http://127.0.0.1:{}", node.data);

    let reply = send(node.data, "GET", "/.well-known/agent-card.json", &[], &[]);

    assert_eq!(
        reply.status,
        200,
        "the agent card at the well-known path: {}",
        reply.text()
    );
    assert!(
        reply
            .header("content-type")
            .is_some_and(|t| t.starts_with("application/json")),
        "the card is JSON: {:?}",
        reply.header("content-type")
    );
    let card = reply.json();
    for field in [
        "name",
        "description",
        "version",
        "capabilities",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
        "supportedInterfaces",
    ] {
        assert!(
            !card[field].is_null(),
            "the card carries `{field}` (A2A v1.0 AgentCard): {card}"
        );
    }
    let mount = format!("{public_url}/a2a");
    for binding in ["JSONRPC", "HTTP+JSON"] {
        let offered = interface(&card, binding)
            .unwrap_or_else(|| panic!("the card offers {binding}: {card}"));
        assert_eq!(
            offered["url"], mount,
            "{binding} is published at public_url's /a2a: {card}"
        );
    }
    let text = reply.text();
    assert!(
        !text.contains(&agent_port.to_string()),
        "the agent's own address is never published: {text}"
    );
    assert!(
        !text.contains(AGENT),
        "the public card enumerates no fronted agent: {text}"
    );
}

#[test]
fn a2a_card_unclaimed_well_known_path_is_still_404() {
    let node = boot("a2a-card-404", closed_port());

    let reply = send(
        node.data,
        "GET",
        "/.well-known/agent-card.json.bak",
        &[],
        &[],
    );

    assert_eq!(reply.status, 404, "an unclaimed path: {}", reply.text());
}
