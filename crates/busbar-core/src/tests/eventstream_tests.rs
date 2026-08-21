// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/eventstream.rs`.

use super::*;

#[test]
fn test_decode_single_frame() {
    let mut buf = encode_frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
    let frames = drain_frames(&mut buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, "contentBlockDelta");
    assert_eq!(frames[0].1, br#"{"delta":{"text":"hi"}}"#);
    assert!(buf.is_empty(), "fully-consumed buffer");
}

#[test]
fn test_decode_multiple_and_partial() {
    let mut buf = encode_frame("messageStart", br#"{"role":"assistant"}"#);
    buf.extend(encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#));
    // Append a truncated third frame (only part of its prelude+body).
    let partial = encode_frame("metadata", br#"{"usage":{}}"#);
    buf.extend_from_slice(&partial[..partial.len() - 5]);

    let frames = drain_frames(&mut buf);
    assert_eq!(frames.len(), 2, "two complete frames decoded");
    assert_eq!(frames[0].0, "messageStart");
    assert_eq!(frames[1].0, "messageStop");
    assert!(!buf.is_empty(), "partial third frame remains buffered");

    // Feed the rest → the third frame completes.
    buf.extend_from_slice(&partial[partial.len() - 5..]);
    let more = drain_frames(&mut buf);
    assert_eq!(more.len(), 1);
    assert_eq!(more[0].0, "metadata");
    assert!(buf.is_empty());
}

#[test]
fn test_oversized_total_len_is_abandoned_not_buffered() {
    // A prelude declaring an enormous-but-internally-consistent total_len must be rejected
    // immediately (buffer cleared, stream abandoned) rather than waiting to accumulate that many
    // bytes — otherwise it is a memory-exhaustion DoS vector.
    let mut buf = Vec::new();
    let huge: u32 = u32::MAX; // ~4 GiB, far above MAX_FRAME_BYTES but >= 16 and self-consistent
    buf.extend_from_slice(&huge.to_be_bytes()); // total_len
    buf.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0 (<= total_len - 16)
    buf.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
    buf.extend_from_slice(b"trailing junk"); // a few extra bytes

    let frames = drain_frames(&mut buf);
    assert!(frames.is_empty(), "no frame should be emitted");
    assert!(
        buf.is_empty(),
        "oversized frame must clear the buffer, not buffer toward total_len"
    );
}

#[test]
fn test_frame_at_cap_still_decodes() {
    // A normal, small frame (well under MAX_FRAME_BYTES) is unaffected by the cap.
    let mut buf = encode_frame("contentBlockDelta", br#"{"delta":{"text":"ok"}}"#);
    let frames = drain_frames(&mut buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, "contentBlockDelta");
    assert!(buf.is_empty());
}

/// `drain_frames(encode_frame(x)) == [x]` for a spread of event types + payload sizes, including
/// empty and large payloads. This is the encoder's primary acceptance gate: it proves the
/// framing + CRC are correct against the existing production decoder (decode(encode(x)) == x).
#[test]
fn test_encode_decode_round_trip() {
    let cases: &[(&str, Vec<u8>)] = &[
        ("messageStart", br#"{"role":"assistant"}"#.to_vec()),
        ("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#.to_vec()),
        ("messageStop", br#"{"stopReason":"end_turn"}"#.to_vec()),
        (
            "metadata",
            br#"{"usage":{"inputTokens":3,"outputTokens":5}}"#.to_vec(),
        ),
        ("contentBlockStop", Vec::new()), // empty payload
        ("contentBlockDelta", vec![b'x'; 64 * 1024]), // large payload
    ];
    for (event_type, payload) in cases {
        let mut buf = encode_frame(event_type, payload);
        let frames = drain_frames(&mut buf);
        assert_eq!(frames.len(), 1, "exactly one frame for {event_type}");
        assert_eq!(&frames[0].0, event_type, "event type round-trips");
        assert_eq!(
            &frames[0].1, payload,
            "payload round-trips for {event_type}"
        );
        assert!(buf.is_empty(), "buffer fully consumed for {event_type}");
    }
}

/// The encoder writes REAL CRC32s (not the `[0,0,0,0]` placeholders the old test helper used).
/// Independently recompute both CRCs over the exact byte ranges the spec defines and assert they
/// match the bytes the encoder emitted — and that neither is zero.
#[test]
fn test_encode_crcs_are_real() {
    let frame = encode_frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
    let total_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(
        total_len,
        frame.len(),
        "total_len matches the bytes written"
    );

    // prelude_crc lives at bytes [8..12] and covers bytes [0..8].
    let prelude_crc = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
    let expected_prelude = crc32fast::hash(&frame[..8]);
    assert_eq!(
        prelude_crc, expected_prelude,
        "prelude CRC is the real CRC32"
    );
    assert_ne!(prelude_crc, 0, "prelude CRC is not the zero placeholder");

    // message_crc is the trailing 4 bytes and covers everything before it (bytes 0..len-4).
    // golden wire-contract literal (kept bare on purpose): pins the exact 4-byte CRC trailer offset.
    let len = frame.len();
    let message_crc = u32::from_be_bytes([
        frame[len - 4],
        frame[len - 3],
        frame[len - 2],
        frame[len - 1],
    ]);
    let expected_message = crc32fast::hash(&frame[..len - 4]);
    assert_eq!(
        message_crc, expected_message,
        "message CRC is the real CRC32"
    );
    assert_ne!(message_crc, 0, "message CRC is not the zero placeholder");
}

/// Build a header block with one type-7 string header `[name][value]`.
fn string_header(name: &str, value: &str) -> Vec<u8> {
    let mut h = Vec::new();
    h.push(name.len() as u8);
    h.extend_from_slice(name.as_bytes());
    h.push(HDR_TYPE_STRING); // string
    h.extend_from_slice(&(value.len() as u16).to_be_bytes());
    h.extend_from_slice(value.as_bytes());
    h
}

/// `event_type_for_frame` returns `""` (rather than panic or misread) when it meets a header
/// whose value-type byte is genuinely unknown / has no defined width before any recognized
/// header.
#[test]
fn test_event_type_unknown_value_type_yields_empty() {
    // One header named "x" with value_type = 200 (not a real AWS type) → malformed → no headers.
    let mut h = Vec::new();
    h.push(1u8); // name_len
    h.extend_from_slice(b"x"); // name
    h.push(200u8); // value_type: unknown
    assert_eq!(event_type_for_frame(&h), "");
}

/// A fixed-width header (e.g. a `timestamp`, type 8) appearing BEFORE `:event-type` must be
/// skipped by advancing the correct number of bytes, not abort the scan — so the event type is
/// still recovered.
#[test]
fn test_event_type_skips_fixed_width_header() {
    let mut h = Vec::new();
    // Header 1: ":ts" timestamp (type 8, 8-byte value) — must be skipped.
    h.push(3u8);
    h.extend_from_slice(b":ts");
    h.push(8u8); // timestamp
    h.extend_from_slice(&0u64.to_be_bytes()); // 8 bytes
                                              // Header 2: ":event-type" string = "messageStart".
    h.extend_from_slice(&string_header(HDR_EVENT_TYPE, "messageStart"));
    assert_eq!(event_type_for_frame(&h), "messageStart");
}

/// A zero-length `:event-type` string value yields `""` — a present-but-empty event type is
/// indistinguishable from absent at the `drain_frames` boundary, which is fine (the reader
/// treats both as a no-op frame).
#[test]
fn test_event_type_empty_value() {
    let h = string_header(HDR_EVENT_TYPE, "");
    assert_eq!(event_type_for_frame(&h), "");
}

/// An AWS modeled-exception frame carries
/// `:message-type: exception` + `:exception-type: <Name>` and NO `:event-type`. `drain_frames`
/// must surface the exception name (normalized to the Smithy union-member token the reader
/// matches) rather than the old empty string that fell into the no-op arm and silently dropped
/// the mid-stream error.
#[test]
fn test_event_type_exception_frame_returns_normalized_exception_name() {
    // Header order deliberately puts :exception-type before :message-type to prove the parser
    // does not depend on ordering.
    let mut h = string_header(HDR_EXCEPTION_TYPE, "InternalServerException");
    h.extend_from_slice(&string_header(
        HDR_CONTENT_TYPE,
        crate::proxy::APPLICATION_JSON,
    ));
    h.extend_from_slice(&string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION));
    assert_eq!(event_type_for_frame(&h), "internalServerException");

    // A ThrottlingException maps the same way.
    let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h2.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "ThrottlingException"));
    assert_eq!(event_type_for_frame(&h2), "throttlingException");
}

/// AWS may qualify the `:exception-type`
/// header with a Smithy namespace / shape-ARN prefix (e.g. `com.amazon.coral.service#ThrottlingException`).
/// The prefix must be stripped before lowercasing — mirroring `extract_error`'s
/// `rsplit(['#', '/'])` in proto/bedrock.rs — so the bare normalized name still matches the
/// `read_response_events` exception arms. Before the fix this returned the whole namespaced
/// string lowercased only at its first char (`com.amazon...`), which matched nothing and dropped
/// the mid-stream error.
#[test]
fn test_event_type_exception_strips_namespace_prefix() {
    // `#`-delimited Smithy shape id.
    let mut h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h.extend_from_slice(&string_header(
        HDR_EXCEPTION_TYPE,
        "com.amazon.coral.service#ThrottlingException",
    ));
    assert_eq!(
        event_type_for_frame(&h),
        "throttlingException",
        "namespace prefix stripped before lowercasing the bare exception name"
    );

    // `/`-delimited ARN-style suffix.
    let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h2.extend_from_slice(&string_header(
        HDR_EXCEPTION_TYPE,
        "aws.bedrock/InternalServerException",
    ));
    assert_eq!(event_type_for_frame(&h2), "internalServerException");

    // A bare (unqualified) name is unaffected — no `#`/`/` to split on.
    let mut h3 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h3.extend_from_slice(&string_header(
        HDR_EXCEPTION_TYPE,
        "ModelStreamErrorException",
    ));
    assert_eq!(event_type_for_frame(&h3), "modelStreamErrorException");
}

/// An `:exception-type` value
/// that ENDS with a Smithy/ARN delimiter (`ThrottlingException#`, `aws.bedrock/`) made
/// `rsplit(['#', '/']).next()` return the empty LEADING token, dropping the classification to
/// `""` — re-sinking the mid-stream error into the no-op arm the namespace fix was meant to
/// prevent. Taking the last NON-EMPTY token (`.find(|s| !s.is_empty())`) strips the trailing
/// delimiter and recovers the bare name. The normal namespaced case is unaffected.
#[test]
fn test_event_type_exception_trailing_delimiter_recovers_name() {
    // Trailing `#` — the empty leading token must be skipped, not returned.
    let mut h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "ThrottlingException#"));
    assert_eq!(
        event_type_for_frame(&h),
        "throttlingException",
        "a trailing `#` must not drop the exception classification to empty"
    );

    // Trailing `/` — same recovery.
    let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h2.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "ThrottlingException/"));
    assert_eq!(
        event_type_for_frame(&h2),
        "throttlingException",
        "a trailing `/` must not drop the exception classification to empty"
    );

    // The normal namespaced value still resolves to the same bare token (no regression).
    let mut h3 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h3.extend_from_slice(&string_header(
        HDR_EXCEPTION_TYPE,
        "com.amazon.coral.service#ThrottlingException",
    ));
    assert_eq!(event_type_for_frame(&h3), "throttlingException");

    // All-delimiter pathological value: every token is empty → `unwrap_or(&exc)` falls back to
    // the raw value (lowercased first char), never panics and never yields `""`.
    let mut h4 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h4.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "#"));
    assert_eq!(
        event_type_for_frame(&h4),
        "#",
        "an all-delimiter value falls back to the raw value, not empty/panic"
    );
}

/// An exception-typed frame
/// (`:message-type: exception`) that carries NO `:exception-type` header must fall through to the
/// empty string — never panic and never misreport. This guards the `None` arm of the
/// `:exception-type` lookup, which a future refactor adding an assertion/panic there would break.
#[test]
fn test_event_type_exception_without_exception_type_yields_empty() {
    // Only `:message-type: exception` is present; no `:exception-type`, no `:event-type`.
    let h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    assert_eq!(
        event_type_for_frame(&h),
        "",
        "exception frame missing :exception-type falls through to empty, no panic"
    );

    // Same, but with an unrelated (non-exception) header riding along — still empty.
    let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
    h2.extend_from_slice(&string_header(
        HDR_CONTENT_TYPE,
        crate::proxy::APPLICATION_JSON,
    ));
    assert_eq!(
        event_type_for_frame(&h2),
        "",
        "exception frame with only :message-type + :content-type is still empty"
    );
}

/// A frame with `:message-type: event` (the normal case) must still report its `:event-type`,
/// never an exception name, even if a stray `:exception-type` somehow rode along.
#[test]
fn test_event_type_event_message_type_prefers_event_type() {
    let mut h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EVENT);
    h.extend_from_slice(&string_header(HDR_EVENT_TYPE, "contentBlockDelta"));
    assert_eq!(event_type_for_frame(&h), "contentBlockDelta");
}

/// End-to-end through `drain_frames`: a real binary exception frame (built by the production
/// `encode_exception_frame`) decodes to the normalized exception event-type, so the egress
/// decode path (`StreamTranslate::feed`) folds a matchable `type` into the JSON and the reader
/// surfaces an error instead of dropping a typeless frame.
#[test]
fn test_drain_frames_surfaces_exception_event_type() {
    let mut buf =
        encode_exception_frame("ServiceUnavailableException", "upstream temporarily down");
    let frames = drain_frames(&mut buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].0, "serviceUnavailableException",
        "exception frame decodes to the normalized union-member token"
    );
    let payload: serde_json::Value = serde_json::from_slice(&frames[0].1).unwrap();
    assert_eq!(payload["message"], "upstream temporarily down");
    assert!(buf.is_empty());
}

/// A modeled-exception frame is a valid event-stream message: real CRC32s, and a header block
/// carrying `:message-type: exception` + `:exception-type` + the JSON `{"message":...}` payload.
/// This is what a Bedrock-ingress stream emits on a mid-stream upstream failure.
#[test]
fn test_encode_exception_frame_is_valid() {
    let frame = encode_exception_frame("InternalServerException", "upstream stream error");
    // total_len must equal the bytes written.
    let total_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(total_len, frame.len(), "total_len matches frame bytes");
    // prelude CRC over [0..8] is real.
    let prelude_crc = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
    assert_eq!(prelude_crc, crc32fast::hash(&frame[..8]));
    // message CRC over [0..len-4] is real.
    let len = frame.len();
    let msg_crc = u32::from_be_bytes([
        frame[len - CRC_BYTES],
        frame[len - CRC_BYTES + 1],
        frame[len - CRC_BYTES + 2],
        frame[len - CRC_BYTES + 3],
    ]);
    assert_eq!(msg_crc, crc32fast::hash(&frame[..len - CRC_BYTES]));
    // Header block carries the exception markers.
    let headers_len = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    let headers = String::from_utf8_lossy(&frame[PRELUDE_LEN..PRELUDE_LEN + headers_len]);
    assert!(headers.contains(":message-type")); // golden wire-contract literal (kept bare on purpose)
    assert!(headers.contains("exception")); // golden wire-contract literal (kept bare on purpose)
    assert!(headers.contains(":exception-type")); // golden wire-contract literal (kept bare on purpose)
    assert!(headers.contains("InternalServerException")); // golden wire-contract literal (kept bare on purpose)
                                                          // Payload is the JSON body the SDK surfaces.
    let payload = &frame[PRELUDE_LEN + headers_len..len - CRC_BYTES];
    let v: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(v["message"], "upstream stream error");
    // It must NOT be SSE text.
    assert!(!frame.starts_with(b"event:"));
}

/// An oversized payload (above `MAX_FRAME_BYTES`) must be DROPPED (empty frame), never emitted as
/// a CRC-valid frame carrying byte-truncated, unparseable JSON. Exercises the cap branch that the
/// round-trip test (64 KiB) never reaches.
#[test]
fn test_encode_frame_oversized_payload_drops_frame() {
    // A payload comfortably above MAX_FRAME_BYTES.
    let payload = vec![b'x'; MAX_FRAME_BYTES + 1024];
    let frame = encode_frame("contentBlockDelta", &payload);
    assert!(
        frame.is_empty(),
        "oversized payload must drop the frame, not truncate JSON into a CRC-valid corrupt frame"
    );
}

/// `drain_frames` must abandon (clear) the buffer on a frame whose `total_len` is in range but
/// whose `headers_len` exceeds the space remaining after the 16-byte overhead — the second half
/// of the prelude-validation guard, previously untested. Without the guard, `&frame[12..12 +
/// headers_len]` would slice out of bounds and panic downstream.
#[test]
fn test_headers_len_overflow_abandoned() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&20u32.to_be_bytes()); // total_len = 20 (>= 16, <= cap)
    buf.extend_from_slice(&5u32.to_be_bytes()); // headers_len = 5 (> 20 - 16 = 4)
    buf.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
    buf.extend_from_slice(b"junk extra bytes");

    let frames = drain_frames(&mut buf);
    assert!(
        frames.is_empty(),
        "no frame emitted for headers_len overflow"
    );
    assert!(
        buf.is_empty(),
        "headers_len overflow must abandon (clear) the buffer, not slice OOB"
    );
}

/// An oversized header NAME or VALUE must DROP the whole frame (empty `Vec`) rather than silently
/// byte-truncate the string — a truncation could split a multi-byte UTF-8 sequence and emit a
/// CRC-valid frame carrying an invalid-UTF-8 type-7 header a strict AWS SDK rejects.
#[test]
fn test_oversized_header_value_drops_frame() {
    // A header value just over the u16 cap (65535 bytes).
    let huge_value = "x".repeat(u16::MAX as usize + 1);
    let frame = encode_exception_frame(&huge_value, "msg");
    assert!(
        frame.is_empty(),
        "an oversized exception-type header must drop the frame, not truncate the string"
    );
    // A short, valid exception type still encodes normally.
    let ok = encode_exception_frame("InternalServerException", "msg");
    assert!(!ok.is_empty());
}

/// `encode_frame` must DROP the whole frame (empty `Vec`) when the caller-supplied `:event-type`
/// value exceeds the type-7 string cap (u16, 65535 bytes), rather than emit a CRC-valid frame
/// carrying a byte-truncated (possibly invalid-UTF-8) header. This exercises the `encode_frame`
/// early-return on a failed `push_string_header` for `:event-type` — the only caller-supplied
/// header in that path — which the payload-cap and exception-frame tests do not reach.
#[test]
fn test_encode_frame_oversized_event_type_drops_frame() {
    // An event-type value one byte over the u16 type-7 string cap.
    let huge_event_type = "e".repeat(u16::MAX as usize + 1);
    let frame = encode_frame(&huge_event_type, br#"{"x":1}"#);
    assert!(
        frame.is_empty(),
        "an oversized :event-type header must drop the frame, not truncate the string"
    );
    // A short, valid event type still encodes normally.
    let ok = encode_frame("contentBlockDelta", br#"{"x":1}"#);
    assert!(!ok.is_empty());
}

/// The encoder carries the three Bedrock framing headers (`:event-type`, `:content-type`,
/// `:message-type`); `parse_event_type` must skip past the others and still find the event name.
#[test]
fn test_encode_carries_three_headers() {
    let frame = encode_frame("messageStart", br#"{"role":"assistant"}"#);
    let headers_len = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    let headers = &frame[PRELUDE_LEN..PRELUDE_LEN + headers_len];
    // :content-type and :message-type values must be present in the header block.
    let hs = String::from_utf8_lossy(headers);
    assert!(hs.contains(":event-type")); // golden wire-contract literal (kept bare on purpose)
    assert!(hs.contains(":content-type")); // golden wire-contract literal (kept bare on purpose)
    assert!(hs.contains("application/json")); // golden wire-contract literal (kept bare on purpose)
    assert!(hs.contains(":message-type")); // golden wire-contract literal (kept bare on purpose)
    assert!(hs.contains("event")); // golden wire-contract literal (kept bare on purpose)
}

/// The SMALLEST valid frame —
/// `total_len == 16` (12-byte prelude + 0-byte headers + 0-byte payload + 4-byte message CRC) —
/// must decode cleanly. This is the lower boundary of the `(16..=MAX_FRAME_BYTES)` guard at line
/// 61: a frame this small carries an empty header block and an empty payload (e.g. a
/// `contentBlockStop` with no body). It is hand-crafted here (the production `encode_frame`
/// always writes three headers, so it can never emit a 16-byte frame) so that tightening the
/// guard from `16..=` to `17..=` — which would wrongly abandon a valid minimum frame — is caught.
#[test]
fn test_drain_frames_minimum_valid_frame() {
    // 16-byte frame: prelude(12) + headers(0) + payload(0) + message_crc(4).
    let mut frame = Vec::with_capacity(16); // golden wire-contract literal (kept bare on purpose)
    frame.extend_from_slice(&16u32.to_be_bytes()); // golden wire-contract literal (kept bare on purpose): total_len = 16 (the minimum valid value)
    frame.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0
    let prelude_crc = crc32fast::hash(&frame[..8]);
    frame.extend_from_slice(&prelude_crc.to_be_bytes()); // prelude CRC over [0..8]
                                                         // No headers, no payload. message_crc over everything written so far ([0..12]).
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());
    assert_eq!(
        frame.len(),
        16, // golden wire-contract literal (kept bare on purpose)
        "hand-crafted frame is exactly the minimum size"
    );

    let mut buf = frame;
    let frames = drain_frames(&mut buf);
    assert_eq!(
        frames.len(),
        1,
        "the minimum 16-byte frame decodes to one frame"
    );
    assert_eq!(frames[0].0, "", "no :event-type header → empty event type");
    assert!(frames[0].1.is_empty(), "empty payload round-trips");
    assert!(buf.is_empty(), "minimum frame is fully consumed");
}

/// The single-buffer
/// encoder must be BYTE-FOR-BYTE identical to the prior two-Vec (`headers` + `frame`) encoding.
/// We independently rebuild the exact wire bytes from the documented layout — placeholder-free,
/// in one pass — and assert equality, so a future refactor of the buffer plumbing that perturbs
/// even one byte (a wrong CRC range, a misplaced length, a dropped/extra header byte) is caught.
#[test]
fn test_encode_frame_byte_for_byte_matches_reference() {
    // A representative Bedrock ConverseStream delta frame.
    let event_type = "contentBlockDelta";
    let payload = br#"{"delta":{"text":"hi"}}"#;
    let got = encode_frame(event_type, payload);

    // Reference encoding, built straight from the documented wire layout (NOT via encode_frame):
    //   header block = the three Bedrock string headers in order.
    // golden wire-contract literal (kept bare on purpose): header name/value strings pin the
    // exact bytes the encoder must emit; changing them here changes the wire format.
    let mut headers = Vec::new();
    headers.extend_from_slice(&string_header(":event-type", event_type));
    headers.extend_from_slice(&string_header(":content-type", "application/json"));
    headers.extend_from_slice(&string_header(":message-type", "event"));

    let headers_len = headers.len();
    let total_len = 12 + headers_len + payload.len() + 4; // golden wire-contract literal (kept bare on purpose)

    let mut want = Vec::new();
    want.extend_from_slice(&(total_len as u32).to_be_bytes()); // total_len
    want.extend_from_slice(&(headers_len as u32).to_be_bytes()); // headers_len
    let prelude_crc = crc32fast::hash(&want[..8]); // prelude CRC over the two length fields
    want.extend_from_slice(&prelude_crc.to_be_bytes());
    want.extend_from_slice(&headers);
    want.extend_from_slice(payload);
    let message_crc = crc32fast::hash(&want); // message CRC over everything written so far
    want.extend_from_slice(&message_crc.to_be_bytes());

    assert_eq!(
        got, want,
        "single-buffer encode_frame must be byte-for-byte identical to the reference encoding"
    );
}

use crate::test_support::warn_capture::WarnCapture;

/// When an oversized `:event-type` makes
/// `push_string_header` reject the header, `encode_frame` drops the frame. The drop stays OBSERVABLE
/// in the diagnostics catalog — it now carries `BUSBAR-9004` at `debug!` (a per-request data-path
/// event that is unreachable for any real Bedrock event name, so it must not spam operator WARN
/// logs). This test pins two things: the frame is dropped (empty `Vec`), and the drop is SILENT at
/// WARN — it must not surface as an unlatched per-frame warning.
#[test]
fn test_encode_frame_oversized_event_type_warns() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let huge_event_type = "e".repeat(u16::MAX as usize + 1);
    let frame = tracing::subscriber::with_default(subscriber, || {
        // Emit twice: tracing caches per-callsite interest globally, and a concurrent test
        // installing/dropping another dispatcher can race the cache rebuild so the FIRST
        // emission through this scoped subscriber is occasionally invisible (seen as a CI-only
        // flake). The second emission always follows the rebuilt interest, making the capture
        // deterministic; the returned frame is from the first call (identical inputs).
        let f = encode_frame(&huge_event_type, br#"{"x":1}"#);
        let _ = encode_frame(&huge_event_type, br#"{"x":1}"#);
        f
    });

    assert!(
        frame.is_empty(),
        "oversized :event-type still drops the frame"
    );
    let msgs = cap.messages();
    assert!(
        msgs.is_empty(),
        "dropping an oversized :event-type frame is a per-frame data-path event (BUSBAR-9004) and \
         must stay at debug, never an unlatched WARN, got: {msgs:?}"
    );
}

/// The same guarantee for
/// `encode_exception_frame` — an oversized `:exception-type` drops the frame. The drop is observable
/// as `BUSBAR-9005` at `debug!` (a swallowed mid-stream error-signal frame, near-unreachable per
/// request), so this pins the drop AND that it stays SILENT at WARN rather than spamming per frame.
#[test]
fn test_encode_exception_frame_oversized_type_warns() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let huge = "x".repeat(u16::MAX as usize + 1);
    let frame =
        tracing::subscriber::with_default(subscriber, || encode_exception_frame(&huge, "msg"));

    assert!(
        frame.is_empty(),
        "oversized :exception-type still drops the frame"
    );
    let msgs = cap.messages();
    assert!(
        msgs.is_empty(),
        "dropping an oversized :exception-type frame is a per-frame data-path event (BUSBAR-9005) \
         and must stay at debug, never an unlatched WARN, got: {msgs:?}"
    );
}

/// A malformed prelude must abandon
/// the stream via a DISTINCT propagated status (`DrainStatus::MalformedPrelude`), not be inferred
/// from the buffer being emptied. The key discriminator this test pins: a NORMAL full drain that
/// also leaves the buffer empty returns `DrainStatus::Ok`, so the abort signal is unambiguous —
/// length alone could not tell the two apart, which was the fragile behavior being fixed.
#[test]
fn test_drain_frames_checked_signals_malformed_prelude_distinctly() {
    // (a) Malformed prelude: oversized total_len. Buffer cleared AND status is MalformedPrelude.
    let mut bad = Vec::new();
    bad.extend_from_slice(&u32::MAX.to_be_bytes()); // total_len ~4 GiB, above MAX_FRAME_BYTES
    bad.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0
    bad.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
    bad.extend_from_slice(b"trailing junk");
    let (frames, status, valid_consumed) = drain_frames_checked(&mut bad, None);
    assert!(
        frames.is_empty(),
        "no frame emitted for a malformed prelude"
    );
    assert!(bad.is_empty(), "malformed prelude clears the buffer");
    assert_eq!(
        valid_consumed, 0,
        "a malformed prelude at the front consumes ZERO valid frame bytes — the same-proto \
             verbatim emit must forward none of the cleared remainder"
    );
    assert_eq!(
        status,
        DrainStatus::MalformedPrelude,
        "malformed prelude must propagate the DISTINCT abort signal, not be length-inferred"
    );

    // (b) headers_len overflow is the OTHER malformed-prelude shape — same distinct signal.
    let mut bad2 = Vec::new();
    bad2.extend_from_slice(&20u32.to_be_bytes()); // total_len = 20 (>= 16, <= cap)
    bad2.extend_from_slice(&5u32.to_be_bytes()); // headers_len = 5 (> 20 - 16 = 4)
    bad2.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
    bad2.extend_from_slice(b"junk extra bytes");
    let (frames2, status2, _) = drain_frames_checked(&mut bad2, None);
    assert!(frames2.is_empty());
    assert!(bad2.is_empty());
    assert_eq!(status2, DrainStatus::MalformedPrelude);

    // (c) The AMBIGUITY case the old length-inference got wrong: a CLEAN full drain that consumes
    // every buffered byte also leaves an EMPTY buffer — but it is NOT an abort. Status is Ok.
    let mut good = encode_frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
    let good_len = good.len();
    let (frames3, status3, valid_consumed3) = drain_frames_checked(&mut good, None);
    assert_eq!(frames3.len(), 1);
    assert_eq!(
        valid_consumed3, good_len,
        "a clean full drain reports the whole consumed frame length"
    );
    assert!(
        good.is_empty(),
        "a clean full drain also empties the buffer"
    );
    assert_eq!(
        status3,
        DrainStatus::Ok,
        "an empty buffer after a clean full drain must NOT be read as an abort"
    );

    // (d) A trailing PARTIAL frame is healthy too (buffer non-empty): status Ok, await more bytes.
    let full = encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#);
    let mut partial = full[..full.len() - 4].to_vec();
    let (frames4, status4, _) = drain_frames_checked(&mut partial, None);
    assert!(frames4.is_empty(), "no complete frame yet");
    assert!(!partial.is_empty(), "partial frame stays buffered");
    assert_eq!(
        status4,
        DrainStatus::Ok,
        "a buffered partial is not an abort"
    );

    // (e) The thin `drain_frames` wrapper still returns just the frames (existing callers).
    let mut buf = encode_frame("messageStart", br#"{"role":"assistant"}"#);
    let only_frames = drain_frames(&mut buf);
    assert_eq!(only_frames.len(), 1);
    assert_eq!(only_frames[0].0, "messageStart");
}

/// The smallest frame with a NON-empty
/// payload that carries no headers — `total_len == 18` (12 prelude + 0 headers + 2 payload + 4
/// CRC). Sits one above the empty-payload minimum and guards the `12 + headers_len .. total_len
/// - 4` payload slice arithmetic at its lower edge.
#[test]
fn test_drain_frames_two_byte_payload_no_headers() {
    let payload = b"hi";
    // total_len = prelude(12) + headers(0) + payload + message_crc(4) = 18.
    let total_len = PRELUDE_LEN as u32 + payload.len() as u32 + CRC_BYTES as u32;
    let mut frame = Vec::with_capacity(total_len as usize);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0
    let prelude_crc = crc32fast::hash(&frame[..8]);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(payload);
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());
    assert_eq!(frame.len(), 18); // golden wire-contract literal (kept bare on purpose)

    let mut buf = frame;
    let frames = drain_frames(&mut buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, "", "no :event-type header → empty event type");
    assert_eq!(frames[0].1, payload, "two-byte payload round-trips");
    assert!(buf.is_empty());
}

/// Regression proof (byte-identical behavior before and after the O(frames²)→O(bytes) rewrite
/// of `drain_frames_checked`'s per-frame buffer advance): many frames, a trailing partial, a
/// `consumed_sink` populated in order, exact `valid_consumed`.
#[test]
fn drain_frames_checked_is_byte_identical_after_the_index_rewrite() {
    let mut buf = Vec::new();
    let mut expected: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..50 {
        let payload = format!("{{\"i\":{i}}}");
        let frame = encode_frame("contentBlockDelta", payload.as_bytes());
        buf.extend_from_slice(&frame);
        expected.push(("contentBlockDelta".to_string(), payload.into_bytes()));
    }
    // Trailing partial frame.
    let partial_full = encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#);
    let partial = &partial_full[..partial_full.len() - 3];
    buf.extend_from_slice(partial);

    let mut sink = Vec::new();
    let (frames, status, valid_consumed) = drain_frames_checked(&mut buf, Some(&mut sink));
    assert_eq!(status, DrainStatus::Ok);
    assert_eq!(frames, expected);
    assert_eq!(
        valid_consumed,
        sink.len(),
        "valid_consumed must equal the verbatim bytes captured in the sink"
    );
    assert_eq!(
        buf, partial,
        "the trailing partial frame remains buffered, byte-identical"
    );
    // The sink holds exactly the 50 valid frames' verbatim bytes, in order.
    let mut expected_sink = Vec::new();
    for i in 0..50 {
        let payload = format!("{{\"i\":{i}}}");
        expected_sink.extend_from_slice(&encode_frame("contentBlockDelta", payload.as_bytes()));
    }
    assert_eq!(sink, expected_sink);
}

/// Extends `test_drain_frames_checked_signals_malformed_prelude_distinctly` with valid frames
/// BEFORE the malformed one — the case the index-tracking rewrite is most likely to break,
/// since it is the first test to exercise `pos` advancing across multiple frames before hitting
/// the `buf.clear()` / status-abort arm.
#[test]
fn a_malformed_prelude_after_valid_frames_still_clears_and_reports_the_prefix() {
    let mut buf = Vec::new();
    let mut prefix_len = 0usize;
    for i in 0..5 {
        let payload = format!("{{\"i\":{i}}}");
        let frame = encode_frame("contentBlockDelta", payload.as_bytes());
        prefix_len += frame.len();
        buf.extend_from_slice(&frame);
    }
    // Malformed prelude appended after 5 valid frames.
    buf.extend_from_slice(&u32::MAX.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(b"trailing junk");

    let (frames, status, valid_consumed) = drain_frames_checked(&mut buf, None);
    assert_eq!(
        frames.len(),
        5,
        "the 5 valid frames before the malformed one are returned"
    );
    assert_eq!(
        valid_consumed, prefix_len,
        "valid_consumed counts only the valid prefix, not the cleared malformed remainder"
    );
    assert_eq!(status, DrainStatus::MalformedPrelude);
    assert!(buf.is_empty(), "the WHOLE buffer clears, prefix included");
}

/// Complexity regression: `drain_frames_checked` used `Vec::drain(..total_len)` PER FRAME, which
/// memmoves the entire remaining tail on every call — O(frames × bytes) for a buffer of many
/// small frames. The index-tracking rewrite does ONE buffer edit for the whole pass, O(bytes).
/// A ratio test (not an absolute wall-clock threshold) so it stays machine-independent: quadratic
/// predicts ~16× for a 4× frame-count increase; linear predicts ~4×.
///
/// WEAKEST TEST IN THIS FILE: if `t(1000)` is too fast to be
/// above timer-granularity noise, the ratio is meaningless. The assertion checks that floor first
/// and panics with a clear message rather than silently passing on noise.
///
/// MIN-OF-`TRIALS`, not a single sample: contention from other tests running concurrently in the
/// same `cargo test --workspace` invocation can only ever ADD delay to one `Instant::now()` /
/// `elapsed()` pair — a scheduler preemption, a cache eviction from a neighboring thread, GC-style
/// jemalloc housekeeping — never subtract below the true uncontended cost of the drain. So the
/// MINIMUM across several independent trials converges toward that true cost regardless of how
/// loaded the machine is, while a single sample has no such guarantee and can land on an
/// arbitrarily contended instant for either data point, skewing the ratio in either
/// direction. This is a structural hardening of the MEASUREMENT, not a widened tolerance: the
/// asserted ratio, its rationale, and the floor check are all unchanged.
#[test]
fn drain_frames_checked_scales_linearly_in_frame_count() {
    /// Independent trials per data point; the reported duration is the minimum observed. Three
    /// (not more) because at 1M/4M frames each measurement is hundreds of milliseconds of
    /// DRAM-bound work — scheduler blips that dominate a microsecond sample are relative
    /// rounding error here, and min-of-N only needs ONE uncontended trial to converge.
    const TRIALS: u32 = 3;

    fn bench(n: usize) -> std::time::Duration {
        let mut best: Option<std::time::Duration> = None;
        for _ in 0..TRIALS {
            let mut buf = Vec::new();
            for i in 0..n {
                let payload = format!("{{\"i\":{i}}}");
                buf.extend_from_slice(&encode_frame("contentBlockDelta", payload.as_bytes()));
            }
            let start = std::time::Instant::now();
            let (_, status, _) = drain_frames_checked(&mut buf, None);
            assert_eq!(status, DrainStatus::Ok);
            let elapsed = start.elapsed();
            best = Some(match best {
                Some(b) if b <= elapsed => b,
                _ => elapsed,
            });
        }
        best.expect("TRIALS is a nonzero constant, so the loop runs at least once")
    }
    // 1M and 4M frames (~30 MB and ~120 MB of buffer): BOTH data points are far past every
    // cache level, so the whole measurement lives in one memory regime (DRAM). The earlier
    // 8k/32k sizing straddled the L2→L3 boundary, which made genuinely linear code measure
    // 6.4–8.9x on real CI runners and forced arbitrary threshold tuning; at these sizes the
    // linear prediction really is ~4x and quadratic really is ~16x, with nothing in between
    // to hand-wave about.
    let t1m = bench(1_000_000);
    assert!(
        t1m >= std::time::Duration::from_millis(1),
        "min-of-{TRIALS} t(1M) = {t1m:?} is too fast to be above timer-granularity noise; \
             the ratio below would be meaningless, so this assertion is WITHDRAWN rather than \
             tuned"
    );
    let t4m = bench(4_000_000);
    // < 8x: the log-scale midpoint of linear's ~4x and quadratic's ~16x — equal headroom to
    // both hypotheses, not a constant tuned to any particular runner's measurement.
    assert!(
        t4m < t1m * 8,
        "drain_frames_checked scaled worse than linear: min-of-{TRIALS} t(1M)={t1m:?} \
             min-of-{TRIALS} t(4M)={t4m:?} (ratio {:.1}x, quadratic predicts ~16x, linear \
             predicts ~4x)",
        t4m.as_secs_f64() / t1m.as_secs_f64()
    );
}
