// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `abi/sdk/cred/json.rs`: a JSON reply's credential captured, a JSON answer's credential
//! sealed, and a sealed answer streamed into a host buffer.

use serde::Deserialize;

use super::{json_reply, JsonFailure, SealedJson};
use crate::abi::plane::OnPieceIn;
use crate::abi::sdk::cred::Cred;
use crate::abi::sdk::test_support::zeroed;
use crate::abi::sdk::Lent;

const CANARY: &str = "ek_CANARY-json-7d21b0";

#[derive(Deserialize)]
struct Minted {
    value: Cred,
    expires_at: Option<u64>,
}

fn cred(text: &str) -> Cred {
    Cred::captured(zeroize::Zeroizing::new(text.as_bytes().to_vec()))
}

fn bytes(w: &mut super::SealedWrite) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = crate::abi::sdk::test_support::chip::drive_sealed::<()>(w, |b: &[u8]| {
        out.extend_from_slice(b);
        std::task::Poll::Ready(Ok(b.len()))
    });
    out
}

#[test]
fn a_reply_captures_its_credential_and_reads_its_public_members() {
    let body = format!(r#"{{"value":"{CANARY}","expires_at":1700000600,"session":{{"x":[1]}}}}"#);
    let m: Minted = json_reply(body.as_bytes()).expect("reads");
    assert_eq!(m.value.wire(), CANARY.as_bytes());
    assert_eq!(m.expires_at, Some(1_700_000_600));
}

#[test]
fn an_escaped_credential_is_captured_unescaped() {
    let m: Minted = json_reply(br#"{"value":"ek_A\n\"\\/","expires_at":null}"#).expect("reads");
    assert_eq!(m.value.wire(), b"ek_A\n\"\\/");
    assert_eq!(m.expires_at, None);
}

/// RED: the decoder's own text quotes the value it met (`invalid type: string "<value>"`); the
/// reply error names the class and the position only, the position serde_json states.
#[test]
fn a_reply_error_names_its_class_and_position_never_a_value() {
    let cases: [(String, JsonFailure); 4] = [
        (
            format!(r#"{{"value":"{CANARY}","expires_at":"{CANARY}"}}"#),
            JsonFailure::Data,
        ),
        (
            format!(r#"{{"value":7,"other":"{CANARY}"}}"#),
            JsonFailure::Data,
        ),
        (format!("not json {CANARY}"), JsonFailure::Syntax),
        (format!(r#"{{"value":"{CANARY}""#), JsonFailure::Eof),
    ];
    for (body, failure) in cases {
        let Err(e) = json_reply::<Minted>(body.as_bytes()) else {
            panic!("refused: {body}");
        };
        let raw = serde_json::from_slice::<Minted>(body.as_bytes())
            .err()
            .expect("serde_json refuses it too");
        assert_eq!(e.failure(), failure, "{body}");
        assert_eq!((e.line(), e.column()), (raw.line(), raw.column()), "{body}");
        let text = e.to_string();
        assert!(!text.contains("CANARY"), "{text}");
        assert!(!format!("{e:?}").contains("CANARY"));
    }
    let e = json_reply::<Minted>(br#"{"value":5}"#)
        .err()
        .expect("refused");
    assert_eq!(
        e.to_string(),
        "a field is missing or has the wrong type (line 1, column 10; the decoder's text is \
         withheld)"
    );
    let e = json_reply::<Minted>(b"not json").err().expect("refused");
    assert_eq!(
        e.to_string(),
        "it is not well-formed JSON (line 1, column 2; the decoder's text is withheld)"
    );
}

/// RED: the sealed object encodes as `serde_json::to_vec` writes the same object, byte for byte,
/// every escape included.
#[test]
fn a_sealed_object_encodes_as_serde_json_writes_it() {
    let tricky = [
        CANARY,
        "",
        "q\"b\\s/",
        "\u{0}\u{1}\u{8}\t\n\u{b}\u{c}\r\u{1f}\u{7f}",
        "héllo ✓ 😀 \u{2028}",
    ];
    for secret in tricky {
        let mut w = SealedJson::new()
            .public("expires_at_unix", 5u64)
            .public(
                "n\"ame",
                serde_json::json!({"b": [1, null, true], "a": "x\ny"}),
            )
            .sealed("value", &cred(secret))
            .public("z", -1.5)
            .encoded()
            .expect("text");
        let mut want = serde_json::Map::new();
        want.insert("expires_at_unix".into(), 5u64.into());
        want.insert(
            "n\"ame".into(),
            serde_json::json!({"b": [1, null, true], "a": "x\ny"}),
        );
        want.insert("value".into(), secret.into());
        want.insert("z".into(), (-1.5).into());
        let want = serde_json::to_vec(&serde_json::Value::Object(want)).expect("json");
        assert_eq!(w.len(), want.len());
        assert_eq!(bytes(&mut w), want, "{secret:?}");
    }
    let mut empty = SealedJson::new().encoded().expect("text");
    assert_eq!(bytes(&mut empty), b"{}");
}

/// The members go out in the order named: a plugin matching `json!` (members sorted, no
/// `preserve_order`) names them sorted.
#[test]
fn the_members_go_out_in_the_order_named() {
    let mut w = SealedJson::new()
        .sealed("b", &cred("2"))
        .public("a", 1)
        .encoded()
        .expect("text");
    assert_eq!(bytes(&mut w), br#"{"b":"2","a":1}"#);
}

/// The sealed buffer is sized once: no reallocation leaves a copy of the credential behind.
#[test]
fn the_encoded_buffer_is_allocated_once_at_its_length() {
    let w = SealedJson::new()
        .public("expires_at_unix", 5u64)
        .sealed("value", &cred("ek_\"long\" secret \u{1} with escapes"))
        .encoded()
        .expect("text");
    assert_eq!(w.buf.capacity(), w.buf.len());
}

#[test]
fn a_credential_that_is_not_text_is_refused_by_name() {
    let raw = Cred::captured(zeroize::Zeroizing::new(vec![0xff, 0xfe]));
    let e = SealedJson::new()
        .sealed("value", &raw)
        .encoded()
        .err()
        .expect("not text");
    assert_eq!(e.member(), "value");
}

#[test]
fn a_sealed_object_debugs_its_names_only() {
    let o = SealedJson::new()
        .sealed("value", &cred(CANARY))
        .public("expires_at_unix", 5);
    let d = format!("{o:?}");
    assert!(!d.contains("CANARY"), "{d}");
    assert_eq!(d, r#"["value", "expires_at_unix"]"#);
    assert_eq!(o.names().collect::<Vec<_>>(), ["value", "expires_at_unix"]);
}

/// RED: a sealed answer streams into a host buffer (a plane's `reply_buf`) a buffer's room at a
/// time, every byte once, in order.
#[test]
fn a_sealed_answer_streams_into_a_host_buffer() {
    let mut w = SealedJson::new()
        .public("expires_at_unix", 5u64)
        .sealed("value", &cred(CANARY))
        .encoded()
        .expect("text");
    let want = format!(r#"{{"expires_at_unix":5,"value":"{CANARY}"}}"#);
    let mut got = Vec::new();
    let mut rounds = 0;
    while !w.finished() {
        let mut room = [0u8; 16];
        let mut input: OnPieceIn = zeroed();
        input.reply_buf = room.as_mut_ptr();
        input.reply_cap = room.len() as _;
        // SAFETY: `reply_buf` is `room`, `reply_cap` writable bytes, live for the borrow.
        let lent = unsafe { Lent::new(&input) };
        let mut buf = lent.reply_buf();
        let before = w.remaining();
        let n = w.stream_into(&mut buf).expect("not secure-required");
        assert_eq!(n, before.min(room.len()));
        assert_eq!(w.remaining(), before - n);
        got.extend_from_slice(&room[..n]);
        rounds += 1;
        assert!(rounds < 100);
    }
    assert_eq!(got, want.as_bytes());
    assert_eq!(rounds, want.len().div_ceil(16));
    let mut room = [0u8; 4];
    let mut input: OnPieceIn = zeroed();
    input.reply_buf = room.as_mut_ptr();
    input.reply_cap = room.len() as _;
    // SAFETY: as above.
    let lent = unsafe { Lent::new(&input) };
    assert_eq!(
        w.stream_into(&mut lent.reply_buf()),
        Ok(0),
        "nothing is left"
    );
}

/// RED: a host buffer reports no connection security, so an answer carrying a credential that must
/// go out secured is refused there, nothing written (as `poll_io` refuses it).
#[test]
fn a_secure_required_credential_is_refused_into_a_host_buffer() {
    let mut w = SealedJson::new()
        .sealed("value", &cred(CANARY).require_secure())
        .encoded()
        .expect("text");
    assert!(w.secure_required());
    let mut room = [0u8; 64];
    let mut input: OnPieceIn = zeroed();
    input.reply_buf = room.as_mut_ptr();
    input.reply_cap = room.len() as _;
    // SAFETY: `reply_buf` is `room`, `reply_cap` writable bytes, live for the borrow.
    let lent = unsafe { Lent::new(&input) };
    assert_eq!(
        w.stream_into(&mut lent.reply_buf()),
        Err(crate::abi::sdk::cred::NOT_SECURE)
    );
    assert_eq!(w.remaining(), w.len());
    assert_eq!(room, [0u8; 64]);
}

/// RED: a captured token's public format marker (a provider's `ek_`) is checked without a getter:
/// the answer is whether it matches, nothing else.
#[test]
fn a_credential_answers_whether_it_starts_with_a_marker() {
    let m: Minted = json_reply(format!(r#"{{"value":"{CANARY}"}}"#).as_bytes()).expect("reads");
    assert!(m.value.starts_with(b"ek_"));
    assert!(m.value.starts_with(b""));
    assert!(!m.value.starts_with(b"sk-"));
    assert!(!cred("ek").starts_with(b"ek_"));
}
