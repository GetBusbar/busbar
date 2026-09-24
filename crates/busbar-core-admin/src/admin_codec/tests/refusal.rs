//! Tests for `refusal.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The frozen wire shape, from the one place it is written.
///
/// Two keys and no third, in that order, around whatever code and message the caller brought. This
/// used to be asserted through the deleted `RefusalReason` renderer, which meant the SHAPE was only
/// ever checked on a path nothing took; it is asserted here through `envelope_of`, which is the
/// function the administrative listener's every error answer is built with
/// (`units_admin::error_answer_with_message`).
#[test]
fn envelope_shape_matches_the_1_5_5_error_contract() {
    let rendered = envelope_of("forbidden", "insufficient scope");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert_eq!(parsed.as_object().expect("an object").len(), 1);
    let error = parsed
        .get("error")
        .expect("error key")
        .as_object()
        .expect("an object");
    assert_eq!(error.len(), 2);
    assert_eq!(error["code"], "forbidden");
    assert_eq!(error["message"], "insufficient scope");
}

/// Byte-for-byte, not merely shaped right once parsed.
///
/// A client pinned to this surface reads bytes, and a renderer that gained a space after a colon,
/// reordered the two keys or appended a newline would still parse to the same document while
/// changing every admin error body on the wire. The oracle compares bytes; so does this.
#[test]
fn the_envelope_is_the_frozen_bytes_and_not_merely_the_frozen_document() {
    assert_eq!(
        envelope_of("not_found", "not_found"),
        r#"{"error":{"code":"not_found","message":"not_found"}}"#
    );
}

/// Every one of the eleven frozen codes renders, and renders only itself.
///
/// The eleven are `busbar-core`'s own `AdminError` set, which is what an operator's tooling matches
/// on. The assertion is that the envelope is transparent to the code it was handed — it neither
/// normalises one code onto another nor carries a default of its own.
#[test]
fn all_eleven_frozen_codes_render_verbatim() {
    const FROZEN_CODES: &[&str] = &[
        "not_found",
        "unauthorized",
        "method_not_allowed",
        "forbidden",
        "invalid_request",
        "version_conflict",
        "conflict",
        "rate_limited",
        "internal",
        "unavailable",
        "unpriced_class",
    ];
    assert_eq!(FROZEN_CODES.len(), 11, "the frozen set is eleven and only eleven");
    for code in FROZEN_CODES {
        let parsed: serde_json::Value =
            serde_json::from_str(&envelope_of(code, code)).expect("valid json");
        assert_eq!(parsed["error"]["code"], *code);
        assert_eq!(parsed["error"]["message"], *code);
    }
}
