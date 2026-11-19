// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a caller with no credential, or one nobody issued, can learn from the data listener: one
//! answer. The same status, the same bytes and the same header names whether the path exists, the
//! method fits, the body parses, the model is configured or the body is over the cap.

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

use e2e_support::{bearer, chat_answer, llm, send, streams_section, Reply, Scripted, BODY_CAP};

/// Asked of the node: a method, a path, a content type and a body.
type Asked = (&'static str, &'static str, &'static str, Vec<u8>);

fn asked() -> Vec<Asked> {
    const JSON: &str = "application/json";
    let text = |body: &str| body.as_bytes().to_vec();
    vec![
        (
            "POST",
            "/v1/chat/completions",
            JSON,
            text(r#"{"model":"e2e","messages":[{"role":"user","content":"hi"}]}"#),
        ),
        (
            "POST",
            "/v1/chat/completions",
            JSON,
            text(r#"{"model":"no-such-model","messages":[{"role":"user","content":"hi"}]}"#),
        ),
        ("POST", "/v1/chat/completions", JSON, text("{not json")),
        (
            "POST",
            "/v1/chat/completions",
            JSON,
            vec![b' '; BODY_CAP + 1],
        ),
        ("DELETE", "/v1/chat/completions", JSON, Vec::new()),
        ("GET", "/v1/models", JSON, Vec::new()),
        ("GET", "/stats", JSON, Vec::new()),
        ("GET", "/no/such/path", JSON, Vec::new()),
        ("POST", "/no/such/path", JSON, text("{}")),
        (
            "POST",
            "/v1/realtime/client_secrets",
            JSON,
            text(r#"{"session":{"type":"realtime","model":"test-model"}}"#),
        ),
        ("GET", "/v1/realtime", JSON, Vec::new()),
        (
            "POST",
            "/v1/llm/webhooks/openai",
            JSON,
            text(r#"{"type":"response.completed"}"#),
        ),
    ]
}

fn ask(port: u16, asked: &Asked, credential: Option<&str>) -> Reply {
    let (method, path, content_type, body) = asked;
    let authorization = credential.map(bearer);
    let mut headers = vec![("Content-Type", *content_type)];
    if let Some(authorization) = &authorization {
        headers.push(("Authorization", authorization.as_str()));
    }
    send(port, method, path, &headers, body)
}

#[test]
fn an_unverified_caller_gets_the_one_401_and_learns_nothing_else() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = llm("unverified", &upstream, None)
        .section(&streams_section(""))
        .boot();

    let mut answers: Vec<(String, Reply)> = Vec::new();
    for asked in asked() {
        for (caller, credential) in [
            ("no credential", None),
            (
                "a credential nobody issued",
                Some("bbk_not_a_key_anyone_issued"),
            ),
            (
                "a ticket nobody minted",
                Some("ek_not_a_ticket_anyone_minted"),
            ),
        ] {
            let reply = ask(node.data, &asked, credential);
            answers.push((format!("{} {} [{caller}]", asked.0, asked.1), reply));
        }
    }

    let (first_asked, first) = &answers[0];
    for (asked, reply) in &answers {
        assert!(
            reply.is_the_unverified_answer(),
            "{asked}: answered {} {:?} {}",
            reply.status,
            reply.header("content-type"),
            reply.text()
        );
        assert_eq!(
            reply.header("www-authenticate"),
            Some("Bearer"),
            "{asked}: the challenge names no realm, resource or reason"
        );
        assert_eq!(
            reply.header_names(),
            first.header_names(),
            "{asked} is told something {first_asked} is not: a header"
        );
        assert_eq!(
            reply.header("content-length"),
            first.header("content-length"),
            "{asked}"
        );
    }
    assert_eq!(
        upstream.posts(""),
        0,
        "nothing an unverified caller sent reached a provider"
    );
}
