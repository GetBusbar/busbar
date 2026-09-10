//! Tests for `jsonrpc.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{error, id_shape, id_value, read, success, IdShape, ERRORS};
use busbar_contract::wire::Decode;

/// The serializer writes members in sorted order, and every byte-identity claim rests on it.
///
/// If a dependency ever turns on insertion-order preservation for the document library, every
/// envelope this node writes changes shape at once. This is the assertion that says so out loud
/// rather than letting a conformance rig discover it.
#[test]
fn the_serializer_writes_members_in_sorted_order() {
    let v = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
    assert_eq!(
        serde_json::to_string(&v).unwrap(),
        r#"{"id":1,"jsonrpc":"2.0","result":{}}"#
    );
}

/// A well-formed request reads as a request.
#[test]
fn a_request_reads_as_a_request() {
    let body = br#"{"jsonrpc":"2.0","id":7,"method":"tasks/get","params":{"id":"t1"}}"#;
    let e = read(body).expect("a well-formed request reads");
    assert_eq!(e.method_str(body), Some("tasks/get"));
    assert_eq!(e.id_bytes(body), Some(&b"7"[..]));
    assert!(e.params.is_some());
}

/// A quoted identifier keeps its quotes, because the answer must echo those bytes.
#[test]
fn a_named_identifier_keeps_its_quotes() {
    let body = br#"{"jsonrpc":"2.0","id":"a2a-http-json","method":"SendMessage"}"#;
    let e = read(body).expect("a named identifier reads");
    assert_eq!(e.id_bytes(body), Some(&br#""a2a-http-json""#[..]));
    assert_eq!(e.id.map(|(_, s)| s), Some(IdShape::Str));
}

/// A request with no identifier is a notification.
#[test]
fn an_absent_identifier_is_a_notification() {
    let body = br#"{"jsonrpc":"2.0","method":"tasks/list"}"#;
    let e = read(body).expect("a notification reads");
    assert!(e.id.is_none());
}

/// An empty identifier is refused rather than read as absent.
///
/// The existing ingress refuses it for the same reason and answers the caller; reading it as a
/// notification would drop an answer the caller is waiting for.
#[test]
fn an_empty_identifier_is_refused() {
    let body = br#"{"jsonrpc":"2.0","id":null,"method":"tasks/list"}"#;
    assert_eq!(read(body), Err(Decode::Malformed));
}

/// An identifier of any other shape is refused.
#[test]
fn an_identifier_of_another_shape_is_refused() {
    for body in [
        &br#"{"jsonrpc":"2.0","id":true,"method":"x"}"#[..],
        &br#"{"jsonrpc":"2.0","id":[1],"method":"x"}"#[..],
        &br#"{"jsonrpc":"2.0","id":{"a":1},"method":"x"}"#[..],
    ] {
        assert_eq!(read(body), Err(Decode::Malformed), "{body:?} was admitted");
    }
}

/// The wrong version, or none, is not this protocol.
#[test]
fn the_wrong_version_is_not_this_protocol() {
    assert_eq!(
        read(br#"{"jsonrpc":"1.0","id":1,"method":"x"}"#),
        Err(Decode::Malformed)
    );
    assert_eq!(
        read(br#"{"id":1,"method":"x"}"#),
        Err(Decode::MissingDeclaredFact)
    );
}

/// A missing or non-string method is not a request.
#[test]
fn a_method_must_be_a_string() {
    assert_eq!(
        read(br#"{"jsonrpc":"2.0","id":1}"#),
        Err(Decode::MissingDeclaredFact)
    );
    assert_eq!(
        read(br#"{"jsonrpc":"2.0","id":1,"method":7}"#),
        Err(Decode::Malformed)
    );
}

/// The identifier-shape test admits exactly the two shapes and nothing else.
#[test]
fn the_identifier_shapes_are_two() {
    assert_eq!(id_shape(br#""a""#), Some(IdShape::Str));
    assert_eq!(id_shape(b"1"), Some(IdShape::Number));
    assert_eq!(id_shape(b"-1.5e3"), Some(IdShape::Number));
    assert_eq!(id_shape(b"null"), None);
    assert_eq!(id_shape(b"true"), None);
    assert_eq!(id_shape(b""), None);
}

/// Every identifier the reader ADMITS is one an answer can echo.
///
/// The two ends read the same bytes: the reader decides whether a request is admissible, and the
/// answer writes the identifier back by parsing those same bytes into a value. A request the
/// reader admits and the writer cannot echo is a caller who is told nothing at all — not an
/// answer, not a refusal — because both replies encode through the same step. The rows below are
/// the ones the old reader admitted: each merely STARTS like a number.
#[test]
fn every_admitted_identifier_can_be_echoed() {
    for raw in [
        &b"1"[..],
        &b"0"[..],
        &b"-1"[..],
        &b"1.5"[..],
        &b"1e3"[..],
        &b"1E+3"[..],
        &b"1.2.3"[..],
        &b"007"[..],
        &b"1e"[..],
        &b"1e+"[..],
        &b"--1"[..],
        &b"-"[..],
        &b"1-2"[..],
        &br#""a""#[..],
    ] {
        if id_shape(raw).is_some() {
            assert!(
                id_value(raw).is_ok(),
                "{raw:?} is admitted as an identifier and cannot be written back"
            );
        }
    }
}

/// The identifiers that merely START like a number are refused as identifiers.
#[test]
fn a_run_of_bytes_that_only_starts_like_a_number_is_not_one() {
    for raw in [
        &b"1.2.3"[..],
        &b"007"[..],
        &b"1e"[..],
        &b"1e+"[..],
        &b"--1"[..],
        &b"-"[..],
        &b"1-2"[..],
        &b"1."[..],
    ] {
        assert_eq!(id_shape(raw), None, "{raw:?} was read as a number");
    }
    // And the shapes that ARE numbers stay admitted.
    for raw in [
        &b"0"[..],
        &b"-0"[..],
        &b"42"[..],
        &b"1.5"[..],
        &b"-1e-3"[..],
    ] {
        assert_eq!(
            id_shape(raw),
            Some(IdShape::Number),
            "{raw:?} is a number and was refused"
        );
    }
}

/// A successful answer is the envelope the codec writes, byte for byte.
#[test]
fn a_successful_answer_is_the_codecs_envelope() {
    let id = id_value(b"7").expect("a number is a value");
    let bytes = success(&id, br#"{"kind":"task","id":"t1"}"#).expect("the result writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"id":7,"jsonrpc":"2.0","result":{"id":"t1","kind":"task"}}"#
    );
}

/// An answer echoes a named identifier as the caller wrote it.
#[test]
fn an_answer_echoes_a_named_identifier() {
    let id = id_value(br#""a2a-http-json""#).expect("a string is a value");
    let bytes = success(&id, b"{}").expect("the result writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"id":"a2a-http-json","jsonrpc":"2.0","result":{}}"#
    );
}

/// This protocol's own errors carry the typed detail entry.
#[test]
fn a_protocol_error_carries_its_detail_entry() {
    let id = id_value(b"1").expect("a number is a value");
    let bytes = error(&id, -32001, "no such task").expect("the error writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"error":{"code":-32001,"data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","domain":"a2a-protocol.org","reason":"TASK_NOT_FOUND"}],"message":"no such task"},"id":1,"jsonrpc":"2.0"}"#
    );
}

/// A standard error carries no detail entry, because this protocol names no word for it.
#[test]
fn a_standard_error_carries_no_detail_entry() {
    let id = id_value(b"1").expect("a number is a value");
    let bytes = error(&id, -32601, "no such method").expect("the error writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"error":{"code":-32601,"message":"no such method"},"id":1,"jsonrpc":"2.0"}"#
    );
}

/// Every code and word here is the codec's own, and so is the detail entry they are carried in.
///
/// A copy that is checked is not a second opinion; a copy that is not checked is. There is no
/// copy left to check: [`ERRORS`] IS the codec's table, and what remains for this to say is
/// that the whole band this plane may write is A2A-specific — a standard JSON-RPC code with a
/// reason word attached would be a word the specification does not define, put on the wire.
#[test]
fn the_error_table_is_the_codecs_own() {
    assert_eq!(ERRORS.as_ptr(), busbar_a2a_codec::ERRORS.as_ptr());
    assert!(!ERRORS.is_empty());
    for (code, reason) in ERRORS {
        assert!(
            (-32099..=-32001).contains(code),
            "{code} is outside the A2A-specific band and carries the reason {reason}"
        );
    }
    assert_eq!(
        super::ERROR_INFO_TYPE,
        busbar_a2a_codec::ERROR_INFO_TYPE,
        "the detail entry is tagged with the codec's own type URL"
    );
}

/// The reader is deterministic over the same bytes.
#[test]
fn the_reader_is_deterministic() {
    let body = br#"{"jsonrpc":"2.0","id":"x","method":"message/send","params":{}}"#;
    assert_eq!(read(body), read(body));
}

/// Both halves of the hook subject are pointers the decode step already resolves.
///
/// The subject on this protocol is the METHOD — which skill of the agent is being asked for — and
/// the argument payload is the params object under it. `hook_subject` answers with locators into the
/// span table rather than by re-scanning, so a pointer it names that the request-pointer table does
/// not carry would leave a gate on this plane screening nothing, silently.
#[test]
fn the_hook_subject_names_only_pointers_this_plane_declares() {
    for ptr in [super::PTR_METHOD, super::PTR_PARAMS] {
        assert!(
            super::REQUEST_PTRS.contains(&ptr),
            "the hook subject names `{ptr}`, so the request-pointer table must resolve it"
        );
    }
}
