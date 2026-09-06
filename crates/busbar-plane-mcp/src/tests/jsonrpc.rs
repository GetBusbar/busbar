//! Tests for `jsonrpc.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{
    error, id_shape, id_value, read, success, IdShape, CODES, RESULT_TYPE_COMPLETE, RETIRED_CODES,
};
use busbar_contract::wire::Decode;

/// The serializer writes members in sorted order, and every byte-identity claim rests on it.
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
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}"#;
    let e = read(body).expect("a well-formed request reads");
    assert_eq!(e.method_str(body), Some("tools/call"));
    assert_eq!(e.id_bytes(body), Some(&b"1"[..]));
    assert!(e.is_request());
}

/// A request with no identifier is a notification and obliges no answer.
#[test]
fn an_absent_identifier_is_a_notification() {
    let body = br#"{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}"#;
    let e = read(body).expect("a notification reads");
    assert!(!e.is_request());
}

/// An empty identifier is refused rather than read as absent.
#[test]
fn an_empty_identifier_is_refused() {
    let body = br#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#;
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

/// The identifier-shape test admits exactly the two shapes and nothing else.
#[test]
fn the_identifier_shapes_are_two() {
    assert_eq!(id_shape(br#""a""#), Some(IdShape::Str));
    assert_eq!(id_shape(b"1"), Some(IdShape::Number));
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

/// A successful answer carries the discriminator and the caller's identifier.
#[test]
fn a_successful_answer_carries_the_discriminator() {
    let id = id_value(b"1").expect("a number is a value");
    let bytes =
        success(Some(&id), br#"{"tools":[]}"#, RESULT_TYPE_COMPLETE).expect("the result writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"id":1,"jsonrpc":"2.0","result":{"resultType":"complete","tools":[]}}"#
    );
}

/// A result that cannot CARRY the discriminator is refused, never written without one.
///
/// The discriminator is what this node says about its own answer, and the caller-facing decode
/// step reads it back: a result with none reads as finished. A result that is not an object has
/// nowhere to put the member, and the write used to notice that and go on regardless — so a
/// composed answer that meant "this asks the caller for something" left here saying nothing,
/// and a peer, and this plane's own reader, took it as complete. There is no spelling of the
/// member for these shapes, so the honest answer is that the result cannot be written.
#[test]
fn a_result_that_cannot_carry_the_discriminator_is_refused() {
    let id = id_value(b"1").expect("a number is a value");
    for result in [
        &b"[]"[..],
        &b"[{\"a\":1}]"[..],
        &b"\"done\""[..],
        &b"7"[..],
        &b"true"[..],
        &b"null"[..],
    ] {
        assert_eq!(
            success(Some(&id), result, RESULT_TYPE_COMPLETE),
            Err(busbar_contract::wire::Encode::Unrepresentable),
            "{} was written with no discriminator",
            core::str::from_utf8(result).unwrap()
        );
    }
}

/// A discriminator a server put on its own result is REPLACED, never passed through.
///
/// This is the laundering the three-constructor shape exists to prevent, asserted rather than
/// described: a server's demand for the caller's authority does not leave here wearing this
/// node's name.
#[test]
fn a_servers_own_discriminator_is_replaced() {
    let id = id_value(b"1").expect("a number is a value");
    let bytes = success(
        Some(&id),
        br#"{"resultType":"input_required","content":[]}"#,
        RESULT_TYPE_COMPLETE,
    )
    .expect("the result writes");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("it is a document");
    assert_eq!(value["result"]["resultType"], "complete");
}

/// On a successful answer with no identifier, the member is omitted.
#[test]
fn a_successful_answer_omits_an_absent_identifier() {
    let bytes = success(None, b"{}", RESULT_TYPE_COMPLETE).expect("the result writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"jsonrpc":"2.0","result":{"resultType":"complete"}}"#
    );
}

/// On an error the member is always written, and it is empty when there is none.
///
/// A peer's own test for "is this a response" is whether the member is present at all, so an
/// omitted one would be classified as neither a response nor a notification.
#[test]
fn an_error_always_writes_the_identifier() {
    let bytes = error(None, super::CODE_INVALID_REQUEST, "bad", None).expect("it writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"error":{"code":-32600,"message":"bad"},"id":null,"jsonrpc":"2.0"}"#
    );
}

/// An error with detail carries it under the member the shared builder uses.
#[test]
fn an_error_carries_its_detail() {
    let id = id_value(b"4").expect("a number is a value");
    let bytes = error(
        Some(&id),
        super::CODE_MISSING_CLIENT_CAPABILITY,
        "no capability",
        Some(serde_json::json!({ "requiredCapabilities": ["sampling"] })),
    )
    .expect("it writes");
    assert_eq!(
        core::str::from_utf8(&bytes).unwrap(),
        r#"{"error":{"code":-32021,"data":{"requiredCapabilities":["sampling"]},"message":"no capability"},"id":4,"jsonrpc":"2.0"}"#
    );
}

/// Every code this plane may write is one the codec names.
///
/// A VALUE comparison against the codec's own table. It read the server half's SOURCE for this
/// once — `include_str!` over `../../busbar-mcp/src/…` — which coupled this crate to a sibling
/// the manifest does not name, so the plane could not be built, or deleted, on its own. The
/// codes are the codec's now, so the question that is left is about the SET rather than about
/// any one value.
#[test]
fn every_code_is_the_codecs_own() {
    for code in CODES {
        assert!(
            busbar_mcp_codec::codec::CODES.contains(code),
            "the codec no longer names the code {code}"
        );
    }
}

/// This plane writes none of the codes the current revision retired.
#[test]
fn no_retired_code_is_writable() {
    for retired in RETIRED_CODES {
        assert!(
            !CODES.contains(retired),
            "the plane can write the retired code {retired}"
        );
    }
}

/// The reader is deterministic over the same bytes.
#[test]
fn the_reader_is_deterministic() {
    let body = br#"{"jsonrpc":"2.0","id":"x","method":"tools/list","params":{}}"#;
    assert_eq!(read(body), read(body));
}
