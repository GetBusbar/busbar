// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/proxy/engine/mod.rs`.

use super::inject_openai_stream_include_usage;
use bytes::Bytes;

/// The byte-level injector splices `stream_options.include_usage:true` into a body with NO
/// existing `stream_options` - the result must still be valid JSON with the flag set and every
/// original key preserved.
#[test]
fn injector_splices_include_usage() {
    crate::testkit::install_test_seams();
    let body = br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    let v: serde_json::Value =
        busbar_plane_llm::codec::json::parse(&out).expect("spliced body must be valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&serde_json::json!(true)),
        "include_usage must be spliced: {v}"
    );
    assert_eq!(v.pointer("/model"), Some(&serde_json::json!("gpt-4o")));
    assert_eq!(v.pointer("/stream"), Some(&serde_json::json!(true)));
    assert_eq!(
        v.pointer("/messages/0/content"),
        Some(&serde_json::json!("hi")),
        "original keys must survive the splice: {v}"
    );
}

/// BILLING-SAFETY: a body that ALREADY has `stream_options` (a caller's, or one a `prompt: rw` hook
/// injected) must never gain a DUPLICATE top-level key - last-wins would discard busbar's
/// include_usage and bill zero for the stream. The injector edits the existing member in place, so
/// the body ends up with a SINGLE `stream_options` whose `include_usage` is honored true.
#[test]
fn injector_idempotent_when_stream_options_already_present() {
    crate::testkit::install_test_seams();
    // As if a rewrite hook injected `stream_options` after the has-stream_options decision was
    // captured false: the pristine injector is (wrongly, per the stale flag) selected.
    let body = br#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false},"messages":[]}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    let v: serde_json::Value =
        busbar_plane_llm::codec::json::parse(&out).expect("body must remain valid JSON");
    // No duplicate top-level key: a single stream_options object survives.
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&serde_json::json!(true)),
        "include_usage must be forced true and honored (no duplicate key): {v}"
    );
    // Guard against the duplicate-key regression directly: the raw bytes must contain the
    // `"stream_options"` key exactly ONCE (a duplicate would appear twice).
    let occurrences = out
        .windows(br#""stream_options""#.len())
        .filter(|w| *w == br#""stream_options""#)
        .count();
    assert_eq!(
        occurrences,
        1,
        "exactly one top-level stream_options key must exist, found {occurrences}: \
             {}",
        String::from_utf8_lossy(&out)
    );
}

/// Leading whitespace before the opening `{` is tolerated (the only bytes JSON permits
/// ahead of the top-level value) - the splice still lands right after the brace.
#[test]
fn injector_tolerates_leading_whitespace() {
    crate::testkit::install_test_seams();
    let body = b"  \n\t{\"model\":\"m\",\"stream\":true}";
    let out = inject_openai_stream_include_usage(Bytes::copy_from_slice(body));
    let v: serde_json::Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(v.pointer("/model"), Some(&serde_json::json!("m")));
}

/// A degenerate `{}` (no first key) gains the member; a non-object body passes through.
#[test]
fn injector_falls_back_on_empty_or_non_object() {
    crate::testkit::install_test_seams();
    // `{}` - no first key: the member is inserted alone.
    let out = inject_openai_stream_include_usage(Bytes::from_static(b"{}"));
    let v: serde_json::Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&serde_json::json!(true)),
        "empty object must still gain include_usage via fallback: {v}"
    );
    // Non-object top level: returned unchanged (nothing to reshape).
    let arr = br#"[1,2,3]"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(arr));
    assert_eq!(
        &out[..],
        &arr[..],
        "non-object body must pass through verbatim"
    );
}

/// A body of PURE whitespace (no `{` anywhere) must pass through cleanly, not index past the end of
/// the buffer while scanning for the opening brace.
#[test]
fn injector_does_not_overrun_an_all_whitespace_body() {
    crate::testkit::install_test_seams();
    let out = inject_openai_stream_include_usage(Bytes::from_static(b"   \n\t "));
    // Not valid JSON either way - the point is only that this does not panic, and passes the
    // untouched bytes through (nothing looked like an object to reshape).
    assert_eq!(&out[..], &b"   \n\t "[..]);
}

/// The splice preserves BYTE-FOR-BYTE formatting a DOM re-serialize would normalize away
/// (irregular internal whitespace here) - the semantic (parsed) assertions elsewhere can't tell
/// the difference, only the raw bytes can.
#[test]
fn injector_actually_splices_rather_than_falling_back_to_dom_reconstruction() {
    crate::testkit::install_test_seams();
    let body: &[u8] = br#"{"model":  "m",    "stream":true}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    let out_str = String::from_utf8(out.to_vec()).unwrap();
    assert!(
        out_str.contains(r#""model":  "m",    "stream":true"#),
        "the splice must preserve the original tail byte-for-byte (irregular whitespace \
             intact), proving the byte-level path ran, not a DOM re-serialize: {out_str}"
    );
    assert!(
        out_str.starts_with(r#"{"stream_options":{"include_usage":true},"#),
        "the insert must land immediately after the opening brace: {out_str}"
    );
}

/// An OpenAI Chat streaming body with NO `stream_options` gains
/// `stream_options.include_usage: true` so the upstream reports usage busbar can bill.
#[test]
fn adds_include_usage_when_absent() {
    crate::testkit::install_test_seams();
    let body = br#"{"model":"gpt-4o","stream":true,"messages":[]}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    let v: serde_json::Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&serde_json::json!(true)),
        "include_usage must be injected: {v}"
    );
}

/// A body that already carries `stream_options` (with other keys, or include_usage:false) has the
/// flag set to true WITHOUT dropping sibling options.
#[test]
fn upgrades_existing_stream_options_preserving_siblings() {
    crate::testkit::install_test_seams();
    let body = br#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false,"foo":1},"messages":[]}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    let v: serde_json::Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&serde_json::json!(true)),
        "include_usage must be forced true: {v}"
    );
    assert_eq!(
        v.pointer("/stream_options/foo"),
        Some(&serde_json::json!(1)),
        "sibling stream_options keys must be preserved: {v}"
    );
}

/// A body whose `stream_options` is NOT an object is left untouched (busbar must not reshape a
/// caller's malformed value; the upstream will reject it).
#[test]
fn leaves_non_object_stream_options_untouched() {
    crate::testkit::install_test_seams();
    let body = br#"{"stream":true,"stream_options":"bogus"}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    assert_eq!(
        &out[..],
        &body[..],
        "malformed stream_options must pass through verbatim"
    );
}

/// A body that already opted in stays semantically opted in.
#[test]
fn keeps_existing_true() {
    crate::testkit::install_test_seams();
    let body = br#"{"stream":true,"stream_options":{"include_usage":true}}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    let v: serde_json::Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&serde_json::json!(true))
    );
}

/// A caller's own `stream_options` is edited IN PLACE (LLM DIALECT FIDELITY): the flag is set where
/// it stands, its siblings and every other byte (key order, spacing) stay the caller's. A DOM
/// re-serialize would sort the keys and drop the spacing.
#[test]
fn an_existing_stream_options_is_edited_in_place() {
    crate::testkit::install_test_seams();
    let body = br#"{"model":"gpt-4o", "stream":true,"stream_options":{"foo":1, "include_usage":false},"messages":[]}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    assert_eq!(
        &out[..],
        &br#"{"model":"gpt-4o", "stream":true,"stream_options":{"foo":1, "include_usage":true},"messages":[]}"#[..]
    );
    let body = br#"{"stream":true,"stream_options":{ "foo":1 },"z":1}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    assert_eq!(
        &out[..],
        &br#"{"stream":true,"stream_options":{"include_usage":true, "foo":1 },"z":1}"#[..]
    );
    let body = br#"{"stream":true,"stream_options":null,"z":1}"#;
    let out = inject_openai_stream_include_usage(Bytes::from_static(body));
    assert_eq!(
        &out[..],
        &br#"{"stream":true,"stream_options":{"include_usage":true},"z":1}"#[..]
    );
}
