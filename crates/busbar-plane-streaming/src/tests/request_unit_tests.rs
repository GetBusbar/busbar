// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/request_unit.rs`: the mint door, answered by a
//! ticket busbar mints (row 132).

use super::*;

fn piece(from: From, bytes: &[u8], last: bool) -> Piece<'_> {
    Piece {
        from,
        bytes,
        status: None,
        last,
        head: &[],
    }
}

fn locked() -> SessionConfig {
    SessionConfig {
        instructions: Some("locked".into()),
        ..SessionConfig::default()
    }
}

#[test]
fn the_mint_door_asks_for_a_ticket_locking_its_session_once() {
    let mut unit = RequestUnit::open(Door::Mint, locked()).expect("a request door");
    assert_eq!(unit.door(), Door::Mint);
    // Nothing before the caller's last piece; an ATTEMPT never comes to a unit that dials nothing.
    assert_eq!(
        unit.on_piece(piece(From::Caller, b"{", false)),
        Answer::Nothing
    );
    assert_eq!(
        unit.on_piece(piece(From::Kernel(1), b"", false)),
        Answer::Nothing
    );
    let Answer::Mint { ttl_secs, record } = unit.on_piece(piece(From::Caller, b"}", true)) else {
        panic!("the caller's last piece asks for the ticket");
    };
    assert_eq!(
        ttl_secs, 600,
        "the default lifetime, held inside its bounds"
    );
    assert_eq!(crate::ticket::locked_by(&record).expect("reads"), locked());
    // Asked once.
    assert_eq!(
        unit.on_piece(piece(From::Caller, b"", true)),
        Answer::Nothing
    );
    assert!(!unit.answered());
}

/// The mint door's answer: the OpenAI-compatible `{value, expires_at_unix}` shape.
#[test]
fn a_minted_ticket_is_answered_in_the_shape_sdks_read() {
    let mut unit = RequestUnit::open(Door::Mint, locked()).expect("a request door");
    let _ = unit.on_piece(piece(From::Caller, b"", true));
    let Answer::ToCaller(reply) = unit.minted(Ok(("ek_abc".into(), 1_700_000_600))) else {
        panic!("answered");
    };
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.fields,
        vec![("content-type", "application/json".to_string())]
    );
    let v: serde_json::Value = serde_json::from_slice(&reply.body).expect("json");
    assert_eq!(
        v,
        serde_json::json!({"value": "ek_abc", "expires_at_unix": 1_700_000_600})
    );
    assert!(unit.answered());
    assert_eq!(
        unit.on_piece(piece(From::Caller, b"", true)),
        Answer::Nothing
    );
}

/// RED: a mint the host refused is the served plane's 502, naming why and nothing secret.
#[test]
fn a_refused_mint_keeps_the_served_text() {
    let mut unit = RequestUnit::open(Door::Mint, locked()).expect("a request door");
    let _ = unit.on_piece(piece(From::Caller, b"", true));
    let Answer::ToCaller(reply) = unit.minted(Err("no principal".into())) else {
        panic!("answered");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(
        String::from_utf8(reply.body).expect("utf-8"),
        "streaming ephemeral-secret mint failed: ephemeral token mint failed: no principal"
    );
}

#[test]
fn a_session_door_opens_no_request_unit_and_a_far_end_never_answers_the_mint() {
    for door in [Door::Sdp, Door::Sideband, Door::Gemini, Door::Twilio] {
        assert!(RequestUnit::open(door, locked()).is_none(), "{door:?}");
    }
    let mut unit = RequestUnit::open(Door::Mint, locked()).expect("a request door");
    assert_eq!(
        unit.on_piece(piece(From::FarEnd, b"x", true)),
        Answer::Refused
    );
}
