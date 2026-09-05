// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim ladder, as a table: one row per rung, plus the rows that prove the ORDER rather than
//! the individual tests. A rung that moved would fail a precedence row even if every single-rung row
//! still passed, which is the point of stating them separately.

use super::Headers;
use crate::detect::{protocol, protocol_id, LADDER};

/// One row: what arrived, and which dialect the ladder must claim.
struct Row {
    rung: u16,
    headers: Vec<(&'static str, &'static str)>,
    path: &'static str,
    expect: &'static str,
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            rung: 1,
            headers: vec![("authorization", "AWS4-HMAC-SHA256 Credential=AKIA/…")],
            path: "/anything",
            expect: protocol::BEDROCK,
        },
        Row {
            rung: 2,
            headers: vec![("anthropic-version", "2023-06-01")],
            path: "/anything",
            expect: protocol::ANTHROPIC,
        },
        Row {
            rung: 2,
            headers: vec![("anthropic-beta", "tools-2024-04-04")],
            path: "/anything",
            expect: protocol::ANTHROPIC,
        },
        Row {
            rung: 3,
            headers: vec![("x-goog-api-key", "k")],
            path: "/anything",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 4,
            headers: vec![("x-api-key", "k")],
            path: "/anything",
            expect: protocol::ANTHROPIC,
        },
        Row {
            rung: 5,
            headers: vec![],
            path: "/v1beta/models/gemini-pro:generateContent",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 5,
            headers: vec![],
            path: "/x:streamGenerateContent",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 5,
            headers: vec![],
            path: "/x:embedContent",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 5,
            headers: vec![],
            path: "/x:batchEmbedContents",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 5,
            headers: vec![],
            path: "/x:predict",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 6,
            headers: vec![],
            path: "/v1/models/anything",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 6,
            headers: vec![],
            path: "/v1beta/models/anything",
            expect: protocol::GEMINI,
        },
        Row {
            rung: 7,
            headers: vec![],
            path: "/pool/v1/chat/completions",
            expect: protocol::OPENAI,
        },
        Row {
            rung: 8,
            headers: vec![],
            path: "/p/v2/chat",
            expect: protocol::COHERE,
        },
        Row {
            rung: 8,
            headers: vec![],
            path: "/p/v1/chat",
            expect: protocol::COHERE,
        },
        Row {
            rung: 9,
            headers: vec![],
            path: "/p/v2/embed",
            expect: protocol::COHERE,
        },
        Row {
            rung: 9,
            headers: vec![],
            path: "/p/v2/rerank",
            expect: protocol::COHERE,
        },
        Row {
            rung: 10,
            headers: vec![],
            path: "/p/v1/responses",
            expect: protocol::OPENAI_RESPONSES,
        },
        Row {
            rung: 11,
            headers: vec![],
            path: "/p/v1/messages",
            expect: protocol::ANTHROPIC,
        },
        Row {
            rung: 12,
            headers: vec![],
            path: "/model/x/converse",
            expect: protocol::BEDROCK,
        },
        Row {
            rung: 13,
            headers: vec![],
            path: "/model/x/invoke",
            expect: protocol::BEDROCK,
        },
        Row {
            rung: 14,
            headers: vec![],
            path: "/p/v1/embeddings",
            expect: protocol::OPENAI,
        },
        Row {
            rung: 14,
            headers: vec![],
            path: "/p/v1/moderations",
            expect: protocol::OPENAI,
        },
        Row {
            rung: 14,
            headers: vec![],
            path: "/p/v1/images/generations",
            expect: protocol::OPENAI,
        },
        Row {
            rung: 14,
            headers: vec![],
            path: "/p/v1/audio/speech",
            expect: protocol::OPENAI,
        },
    ]
}

#[test]
fn every_rung_claims_its_own_dialect() {
    for row in rows() {
        let h = Headers(row.headers.clone());
        assert_eq!(
            protocol_id(row.path, &h),
            Some(row.expect),
            "rung {} — path {:?}, headers {:?}",
            row.rung,
            row.path,
            row.headers
        );
    }
}

#[test]
fn the_ladder_has_fourteen_rungs_numbered_one_to_fourteen() {
    assert_eq!(LADDER.len(), 14);
    let mut seen: Vec<u16> = LADDER.iter().map(|r| r.strength).collect();
    seen.sort_unstable();
    assert_eq!(seen, (1..=14).collect::<Vec<u16>>());
}

#[test]
fn a_header_rung_outranks_every_path_rung() {
    // A signed authorization header on a chat-completions path is the FIRST rung, not the seventh.
    let h = Headers(vec![("authorization", "AWS4-HMAC-SHA256 Credential=…")]);
    assert_eq!(
        protocol_id("/pool/v1/chat/completions", &h),
        Some(protocol::BEDROCK)
    );
}

#[test]
fn the_google_key_header_outranks_the_anthropic_one() {
    let h = Headers(vec![("x-api-key", "a"), ("x-goog-api-key", "g")]);
    assert_eq!(protocol_id("/anything", &h), Some(protocol::GEMINI));
}

#[test]
fn the_anthropic_version_header_outranks_both_key_headers() {
    let h = Headers(vec![
        ("x-goog-api-key", "g"),
        ("anthropic-version", "2023-06-01"),
    ]);
    assert_eq!(protocol_id("/anything", &h), Some(protocol::ANTHROPIC));
}

#[test]
fn a_gemini_action_suffix_outranks_a_chat_completions_suffix() {
    let h = Headers(vec![]);
    assert_eq!(
        protocol_id("/v1/chat/completions:predict", &h),
        Some(protocol::GEMINI)
    );
}

#[test]
fn an_unmatched_request_claims_nothing() {
    let h = Headers(vec![("content-type", "application/json")]);
    assert_eq!(protocol_id("/healthz", &h), None);
    assert_eq!(protocol_id("/api/v1/keys", &h), None);
}
