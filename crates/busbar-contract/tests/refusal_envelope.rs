//! The frozen two-key refusal envelope, proven where it is now rendered.
//!
//! The shape a client pinned — `{"error":{"code":...,"message":...}}`, those two keys, that order,
//! no trailing byte — used to be rendered in three places: a plane's own `format!`, the retiring
//! engine's `json!`, and the composition root's. It is one function on the face now, so a caller
//! that spells `envelope_of` is rendering the SAME bytes whichever crate it lives in. These cells
//! are what a delegating caller is proved against: a crate whose own `envelope_of` forwards to this
//! one cannot drift from it, and these say what "this one" is.

use busbar_contract::envelope_of;

/// The envelope is one document with one key, whose value is exactly code and message.
#[test]
fn the_envelope_is_two_keys_in_a_frozen_order() {
    let rendered = envelope_of("forbidden", "this endpoint requires more");
    assert_eq!(
        rendered, r#"{"error":{"code":"forbidden","message":"this endpoint requires more"}}"#,
        "the frozen envelope's bytes"
    );
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert_eq!(parsed.as_object().expect("an object").len(), 1);
    let error = parsed
        .get("error")
        .and_then(serde_json::Value::as_object)
        .expect("the envelope's one key");
    assert_eq!(error.len(), 2, "code and message and nothing else");
    assert_eq!(error["code"], "forbidden");
    assert_eq!(error["message"], "this endpoint requires more");
}

/// The envelope stays ONE JSON document when the message is one a caller supplied.
///
/// The callers this shape had while it lived in a plane brought closed, quote-free prose, so it was
/// never asked this — but the moment an administrative taxonomy renders through it the message
/// carries caller-supplied text: a resource name in a not-found, a validation complaint, the human
/// half of a conflict. A `"` in any of those closes the string early and hands the reader a
/// DIFFERENT document from the one this rendered, with a `code` the client's parser never sees.
///
/// The characters below are the closed set JSON requires an escape for: the two structural ones,
/// the five with short forms, and a representative control character. Asserting through a parser
/// rather than against expected bytes is deliberate — the claim is "still one document that says
/// what it was given", not "escaped the way this test's author would have escaped it".
#[test]
fn the_envelope_survives_a_message_a_caller_wrote() {
    const AWKWARD: &[&str] = &[
        r#"key "prod" not found"#,
        r"path C:\config not found",
        "line one\nline two",
        "carriage\rreturn",
        "tab\there",
        "backspace\u{08}here",
        "formfeed\u{0c}here",
        "control\u{01}here",
    ];
    for message in AWKWARD {
        let rendered = envelope_of("invalid_request", message);
        let parsed: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|e| panic!("the envelope around {message:?} is not one document: {e}"));
        let error = parsed
            .get("error")
            .and_then(serde_json::Value::as_object)
            .expect("the envelope's one key");
        assert_eq!(
            error.len(),
            2,
            "the envelope is code and message and nothing else"
        );
        assert_eq!(error["code"], "invalid_request");
        assert_eq!(
            error["message"].as_str(),
            Some(*message),
            "the message a reader parses back is not the message this was given"
        );
    }
}

/// The ten frozen code strings render through this envelope unchanged, byte for byte.
///
/// This is the cell a CONSUMER of the face is held to. The taxonomy that picks one of these ten for
/// a given refusal is not here and is not this crate's — it belongs to whichever surface is
/// refusing, and each of those surfaces reaches this function rather than the others — but whatever
/// picks a code renders it through here, and these are the bytes that come out. The messages below
/// are this cell's own, deliberately: what is frozen is the SHAPE and the code strings, and a
/// consumer's phrasing is proved beside the consumer. Written as literals rather than built from a
/// table, so a change to either side of the rendering has to edit the frozen string to pass.
#[test]
fn the_ten_frozen_codes_render_byte_identically() {
    const FROZEN: &[(&str, &str, &str)] = &[
        (
            "not_found",
            "no such thing",
            r#"{"error":{"code":"not_found","message":"no such thing"}}"#,
        ),
        (
            "unauthorized",
            "not authenticated",
            r#"{"error":{"code":"unauthorized","message":"not authenticated"}}"#,
        ),
        (
            "method_not_allowed",
            "not allowed for this resource",
            r#"{"error":{"code":"method_not_allowed","message":"not allowed for this resource"}}"#,
        ),
        (
            "forbidden",
            "this endpoint requires more",
            r#"{"error":{"code":"forbidden","message":"this endpoint requires more"}}"#,
        ),
        (
            "invalid_request",
            "unknown field `mode`",
            r#"{"error":{"code":"invalid_request","message":"unknown field `mode`"}}"#,
        ),
        (
            "version_conflict",
            "stale precondition",
            r#"{"error":{"code":"version_conflict","message":"stale precondition"}}"#,
        ),
        (
            "conflict",
            "state says otherwise",
            r#"{"error":{"code":"conflict","message":"state says otherwise"}}"#,
        ),
        (
            "rate_limited",
            "allowance exhausted; retry next minute",
            r#"{"error":{"code":"rate_limited","message":"allowance exhausted; retry next minute"}}"#,
        ),
        (
            "internal",
            "internal error",
            r#"{"error":{"code":"internal","message":"internal error"}}"#,
        ),
        (
            "unavailable",
            "the node is draining",
            r#"{"error":{"code":"unavailable","message":"the node is draining"}}"#,
        ),
    ];
    for (code, message, bytes) in FROZEN {
        assert_eq!(
            &envelope_of(code, message),
            bytes,
            "the frozen envelope for `{code}` moved"
        );
    }
}
