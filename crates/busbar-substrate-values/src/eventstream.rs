// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS event-stream (`application/vnd.amazon.eventstream`) frame codec.
//!
//! [`drain_frames_checked`] is the production DECODER — just enough to pull `(event_type, payload)`
//! pairs out of Bedrock ConverseStream responses so they can feed the Bedrock reader's existing
//! `read_response_events`. Incremental: leaves a trailing partial frame in the buffer. CRCs are not
//! validated on decode (we are a client decoder consuming well-formed AWS frames). (`drain_frames`
//! is a test-only thin wrapper that discards the consumed-byte count.)
//!
//! The returned `event_type` is normally the frame's `:event-type` header. AWS, however, signals a
//! mid-stream MODELED EXCEPTION with a frame that carries `:message-type: exception` plus an
//! `:exception-type: <ExceptionName>` header and NO `:event-type` (e.g. a `ThrottlingException` or
//! `InternalServerException` mid ConverseStream). For those frames [`drain_frames_checked`] returns the
//! exception name normalized to the Smithy union-member form (leading letter lowercased, e.g.
//! `internalServerException`) so it matches the `read_response_events` exception arms and is surfaced
//! as an error event rather than being silently dropped as a typeless no-op frame.
//!
//! [`encode_frame`] is the production ENCODER (the exact inverse of [`drain_frames_checked`]) used for
//! Bedrock *ingress* streaming: a native AWS SDK Bedrock client consumes the binary framing, so the
//! frames must be byte-exact with VALID CRC32 (AWS clients reject malformed/zero CRCs).
//!
//! Frame layout:
//! ```text
//!   [total_len: u32 BE][headers_len: u32 BE][prelude_crc: u32 BE]
//!   [headers: headers_len bytes]
//!   [payload: total_len - headers_len - 16 bytes]
//!   [message_crc: u32 BE]
//! ```
//! Header: `[name_len: u8][name][value_type: u8][value]`. Bedrock uses string headers (type 7):
//! `[value_len: u16 BE][value]`.

/// Upper bound on a single event-stream frame. Bedrock ConverseStream frames are small JSON deltas
/// (well under this), so a declared `total_len` above this cap can only be a malformed or hostile
/// prelude. Bounding it stops a single frame's declared length from driving unbounded buffering.
///
/// NOTE on the effective per-frame ceiling: the egress reassembly path in
/// `StreamTranslate::feed` aborts a stream once its reassembly buffer exceeds
/// `StreamTranslate::MAX_BUF`. The two caps are deliberately kept equal so that any frame the decoder
/// here is willing to assemble can also be buffered to completion upstream — otherwise a frame
/// between the two caps would be aborted before `drain_frames_checked` ever saw it. Keep `MAX_FRAME_BYTES`
/// and `StreamTranslate::MAX_BUF` in sync.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

use crate::diag_debug;
use crate::diagnostics::{
    EVENTSTREAM_EVENTTYPE_HEADER_OVERSIZE, EVENTSTREAM_EXCEPTIONTYPE_HEADER_OVERSIZE,
    EVENTSTREAM_FRAME_OVERSIZE,
};

/// Outcome of a [`drain_frames_checked`] pass: WHY the decoder stopped pulling frames from the
/// buffer. This is the DISTINCT abandonment signal the egress reassembler (`StreamTranslate::feed`)
/// must key off — previously it inferred a malformed-prelude abort by observing that `drain_frames`
/// had emptied the buffer, which is fragile: a normal pass that happens to consume every buffered
/// byte ALSO leaves an empty buffer, so length alone cannot tell a clean full-drain apart from an
/// unrecoverable abort. Making the abort an explicit variant removes that ambiguity entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainStatus {
    /// The decoder consumed every COMPLETE frame and stopped cleanly: either the buffer is now empty
    /// or it holds only a trailing PARTIAL frame awaiting more bytes. The buffer is intact and the
    /// stream is healthy — feed more bytes and call again.
    Ok,
    /// A malformed prelude (out-of-range `total_len`, or `headers_len` larger than the frame can
    /// hold) was encountered. The stream is UNRECOVERABLE: the buffer has been cleared and the caller
    /// must abandon the stream rather than continue feeding it. This is the propagated abort signal
    /// (no longer length-inferred).
    MalformedPrelude,
}

/// Drain every COMPLETE frame from `buf`, returning the `(event_type, payload_bytes)` pairs AND a
/// [`DrainStatus`] saying why the pass stopped. [`DrainStatus::MalformedPrelude`] is the EXPLICIT,
/// propagated abort signal: on a malformed prelude the buffer is cleared (the stream is
/// unrecoverable) and the status reflects it, so the caller no longer has to infer abandonment from
/// the (ambiguous) post-pass buffer length. A clean pass — buffer emptied or a trailing partial
/// frame left buffered — returns [`DrainStatus::Ok`]. The third tuple element is the count of bytes
/// consumed as COMPLETE VALID frames from the front of `buf` (excluding any malformed-prelude
/// remainder that was cleared), available to callers needing a byte-accurate count of bytes consumed
/// as complete valid frames (excluding any malformed-prelude remainder); the same-protocol verbatim
/// re-emit path uses the `consumed_sink` parameter instead and discards this count.
/// `consumed_sink`, when `Some`, receives the VERBATIM bytes of each complete valid frame as it is
/// drained (in frame order). The same-protocol bedrock→bedrock re-emit path uses this to forward the
/// original frame bytes unchanged WITHOUT cloning the whole reassembly buffer on every chunk: that
/// per-chunk `buf.clone()` was O(buf) each call, so a large frame arriving as many small chunks cost
/// O(chunks × buf) cumulative allocation (a memory-pressure DoS). The sink collects only the bytes
/// actually consumed — nothing on a chunk that completes no frame — and never the cleared
/// malformed-prelude remainder (the malformed branch breaks before the push). Pass `None` on the
/// cross-protocol path, which re-encodes and needs no verbatim copy.
pub fn drain_frames_checked(
    buf: &mut Vec<u8>,
    mut consumed_sink: Option<&mut Vec<u8>>,
) -> (Vec<(String, Vec<u8>)>, DrainStatus, usize) {
    let mut out = Vec::new();
    let mut status = DrainStatus::Ok;
    // Index into `buf` marking how much of the FRONT has been consumed as complete, valid frames.
    // ONE buffer edit for the whole pass, not one per frame: `Vec::drain` from the front memmoves
    // the entire remaining tail, so draining per frame cost O(frames × bytes) on a chunk carrying
    // many small deltas. Nothing else observes `buf` mid-loop (this function holds the only `&mut`),
    // so tracking a position and applying ONE `drain`/`clear` at the end is behavior-identical.
    let mut pos = 0usize;
    loop {
        let rem = &buf[pos..];
        if rem.len() < PRELUDE_LEN {
            break; // need the full prelude
        }
        let total_len = u32::from_be_bytes([rem[0], rem[1], rem[2], rem[3]]) as usize;
        let headers_len = u32::from_be_bytes([rem[4], rem[5], rem[6], rem[7]]) as usize;
        // `total_len` is attacker/upstream-controlled (up to ~4 GiB). Reject any frame larger than
        // MAX_FRAME_BYTES BEFORE waiting for `rem.len() >= total_len`, otherwise a crafted prelude
        // declaring an enormous internally-consistent length would force the caller to buffer
        // unbounded bytes toward a frame that never arrives (memory-exhaustion DoS). An oversized
        // length is treated like any other malformed prelude: abandon the (unrecoverable) stream.
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&total_len)
            || headers_len > total_len - MIN_FRAME_BYTES
        {
            status = DrainStatus::MalformedPrelude; // distinct propagated signal, not length-inferred
            break;
        }
        if rem.len() < total_len {
            break; // partial frame — wait for more bytes
        }
        // Read the frame in place via slices into `rem` (one payload copy) and advance `pos` —
        // rather than `drain(..total_len).collect()` into a throwaway per-frame Vec (which was a
        // SECOND heap allocation per frame on the hot streaming-decode path).
        let headers = &rem[PRELUDE_LEN..PRELUDE_LEN + headers_len];
        let event_type = event_type_for_frame(headers);
        let payload = rem[PRELUDE_LEN + headers_len..total_len - CRC_BYTES].to_vec();
        out.push((event_type, payload));
        // Capture the frame's verbatim bytes for the same-proto re-emit.
        if let Some(sink) = consumed_sink.as_deref_mut() {
            sink.extend_from_slice(&rem[..total_len]);
        }
        pos += total_len;
    }
    // Malformed: the stream is unrecoverable, so the valid prefix AND the remainder both go —
    // `valid_consumed` still reports only the prefix, exactly as before.
    match status {
        DrainStatus::Ok => {
            buf.drain(..pos);
        }
        DrainStatus::MalformedPrelude => buf.clear(),
    }
    (out, status, pos)
}

/// Drain every COMPLETE frame from `buf`, returning `(event_type, payload_bytes)` per frame and
/// leaving any trailing partial frame buffered. A malformed prelude clears the buffer (the stream
/// is unrecoverable) rather than looping.
///
/// Thin wrapper over [`drain_frames_checked`] that DISCARDS the [`DrainStatus`], used by the route /
/// proto tests that only need the decoded frames. Production code (the egress reassembler) calls
/// [`drain_frames_checked`] directly for the explicit malformed-prelude signal; after the byte-scanner's
/// `feed_eventstream` was removed, this convenience wrapper has only test callers, so it is
/// gated to test builds to avoid an unused-function warning in the 1.0 binary — on the
/// `test-support` gate, not bare `cfg(test)`, because the callers are the Bedrock dialect's tests
/// and that dialect is now a module of the `busbar-llm` plugin, whose test build reaches core
/// through `test-support`.
#[cfg(any(test, feature = "test-support"))]
pub fn drain_frames(buf: &mut Vec<u8>) -> Vec<(String, Vec<u8>)> {
    drain_frames_checked(buf, None).0
}

/// The framing headers `drain_frames_checked` cares about: the normal `:event-type`, plus the
/// `:message-type` discriminator and `:exception-type` name that an AWS mid-stream modeled-exception
/// frame carries INSTEAD of an `:event-type`. All three are optional string headers.
#[derive(Default)]
struct FrameHeaders {
    event_type: Option<String>,
    message_type: Option<String>,
    exception_type: Option<String>,
}

/// Resolve the event-type token `drain_frames_checked` returns for one frame.
///
/// For a normal `event`-typed frame this is the `:event-type` header verbatim. For an AWS modeled
/// EXCEPTION frame (`:message-type: exception`, which carries `:exception-type: <ExceptionName>` and
/// NO `:event-type`), it is the exception name normalized to the Smithy union-member form (leading
/// letter lowercased) — `InternalServerException` → `internalServerException` — so it matches the
/// `read_response_events` exception arms instead of being dropped as a typeless no-op frame. Falls
/// back to the empty string when neither header is present (a genuinely typeless / malformed frame),
/// preserving the previous `unwrap_or_default()` behavior for that case.
fn event_type_for_frame(headers: &[u8]) -> String {
    let parsed = parse_frame_headers(headers);
    // An exception frame is identified by `:message-type: exception`. Prefer its `:exception-type`
    // (AWS does not set `:event-type` on these), normalized to the union-member token the reader
    // matches. This is what was previously lost: such a frame yielded `""` and was silently dropped.
    if parsed.message_type.as_deref() == Some(MSG_TYPE_EXCEPTION) {
        if let Some(exc) = parsed.exception_type {
            // AWS may qualify the `:exception-type` with a Smithy namespace / shape ARN prefix
            // (e.g. `com.amazon.coral.service#ThrottlingException`). Keep only the trailing bare
            // exception name before lowercasing — mirroring `extract_error`'s
            // `rsplit(['#', '/'])` in proto/bedrock.rs — so the normalized token matches the
            // `read_response_events` exception arms rather than being a no-op long namespaced string.
            //
            // Use the last NON-EMPTY token, not `.next()`: a value that ENDS with a delimiter
            // (e.g. `ThrottlingException#` or `aws.bedrock/`) makes `rsplit` yield an empty leading
            // token, which `.next()` would return verbatim — dropping the classification to `""`
            // and re-sinking the mid-stream error into the no-op arm. `.find(|s| !s.is_empty())`
            // skips that trailing-delimiter empty and recovers the bare name. The `unwrap_or(&exc)`
            // guards the all-delimiter case (e.g. `"#"`/`"/"`), where every token is empty: fall
            // back to the raw value rather than panicking or yielding `""`.
            let bare = exc
                .rsplit(['#', '/'])
                .find(|s| !s.is_empty())
                .unwrap_or(&exc);
            return lowercase_first(bare);
        }
    }
    parsed.event_type.unwrap_or_default()
}

/// Lowercase only the FIRST character of an exception name (`InternalServerException` →
/// `internalServerException`), mapping the AWS PascalCase `:exception-type` header to the Smithy
/// union-member token the `read_response_events` exception arms key off. ASCII-only by construction
/// (Converse exception names are ASCII identifiers); leaves the remainder untouched.
fn lowercase_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Scan the header block for the `:event-type`, `:message-type` and `:exception-type` string headers.
/// Handles the u16-length-prefixed string/bytes value types (string = 7, bytes = 6) by reading their
/// value, and the AWS-spec fixed-width types (bool/byte/short/int/long/timestamp/uuid) by SKIPPING
/// the correct number of bytes so a non-string header appearing before the ones we want no longer
/// aborts the scan. Stops early (returning whatever was found) only when the header block is
/// truncated or carries a value-type byte with no defined width (a genuinely malformed frame), so a
/// future AWS framing header (e.g. a timestamp correlation header) does not silently drop the
/// recognized headers that preceded it.
fn parse_frame_headers(mut h: &[u8]) -> FrameHeaders {
    let mut found = FrameHeaders::default();
    while !h.is_empty() {
        let Some(&name_len_byte) = h.first() else {
            break;
        };
        let name_len = name_len_byte as usize;
        if h.len() < 1 + name_len + 1 {
            break;
        }
        let name = &h[1..1 + name_len];
        let value_type = h[1 + name_len];
        let mut p = 1 + name_len + 1;
        // AWS event-stream value types. Fixed-width types carry no length prefix and are skipped by
        // advancing `p`; the variable-width string/bytes types (6/7) carry a u16 length prefix.
        let fixed_width: Option<usize> = match value_type {
            0 | 1 => Some(0), // bool true / bool false — value is encoded in the type byte itself
            2 => Some(1),     // byte
            3 => Some(2),     // short
            4 => Some(4),     // int
            5 => Some(8),     // long
            8 => Some(8),     // timestamp
            9 => Some(16),    // uuid
            _ => None,
        };
        let value: Option<&[u8]> = match value_type {
            6 | HDR_TYPE_STRING => {
                if h.len() < p + 2 {
                    break;
                }
                let vlen = u16::from_be_bytes([h[p], h[p + 1]]) as usize;
                p += 2;
                if h.len() < p + vlen {
                    break;
                }
                let v = &h[p..p + vlen];
                p += vlen;
                Some(v)
            }
            _ => match fixed_width {
                Some(w) => {
                    if h.len() < p + w {
                        break;
                    }
                    p += w;
                    None
                }
                // Unknown value-type byte with no defined width: the frame is malformed, bail.
                None => break,
            },
        };
        // These framing headers are always type-7 strings in AWS framing; capture each value when it
        // is one. A fixed-width-typed value carries no string to record.
        if let Some(v) = value.and_then(|v| std::str::from_utf8(v).ok()) {
            match name {
                n if n == HDR_EVENT_TYPE.as_bytes() => found.event_type = Some(v.to_string()),
                n if n == HDR_MESSAGE_TYPE.as_bytes() => found.message_type = Some(v.to_string()),
                n if n == HDR_EXCEPTION_TYPE.as_bytes() => {
                    found.exception_type = Some(v.to_string())
                }
                _ => {}
            }
        }
        h = &h[p..];
    }
    found
}

/// Append one `[name_len:u8][name][value_type:u8 = 7 string][value_len:u16 BE][value]` string
/// header to `headers`. The AWS event-stream spec caps a header name at 255 bytes (u8 length) and a
/// type-7 string value at 65535 bytes (u16 length). All current callers pass fixed short ASCII
/// labels and short event-type/exception names, so the limits never fire in practice.
///
/// Returns `false` (and pushes NOTHING) when `name` or `value` exceeds its length limit, rather than
/// silently byte-truncating: a truncation could split a multi-byte UTF-8 sequence, emitting a
/// CRC-valid frame carrying an invalid-UTF-8 type-7 string header that a strict AWS SDK rejects —
/// the exact "CRC-valid but corrupt" outcome `encode_with_headers` deliberately avoids for payloads.
/// The encoder treats a `false` return as a reason to DROP the whole frame (consistent with the
/// oversized-payload policy) — a graceful, no-panic outcome safe on the streaming request path in
/// every build profile (we do NOT `debug_assert`, which would panic a debug build on the hot path).
#[must_use]
fn push_string_header(headers: &mut Vec<u8>, name: &str, value: &str) -> bool {
    if name.len() > u8::MAX as usize || value.len() > u16::MAX as usize {
        return false; // oversized — drop rather than emit a truncated/corrupt header
    }
    headers.push(name.len() as u8);
    headers.extend_from_slice(name.as_bytes());
    headers.push(HDR_TYPE_STRING); // value_type 7 = UTF-8 string
    headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
    headers.extend_from_slice(value.as_bytes());
    true
}

/// Encode one AWS `application/vnd.amazon.eventstream` message — the exact inverse of one
/// [`drain_frames_checked`] iteration, with REAL CRC32 (AWS SDK clients validate both CRCs).
///
/// Wire layout:
/// ```text
///   [total_len:u32 BE][headers_len:u32 BE][prelude_crc:u32 BE = CRC32(first 8 bytes)]
///   [headers][payload]
///   [message_crc:u32 BE = CRC32(byte 0 .. end of payload)]
/// ```
/// A Bedrock ConverseStream frame carries three string headers — `:event-type` (the event name),
/// `:content-type` (`application/json`) and `:message-type` (`event`). Runs in the streaming hot
/// path: all arithmetic is `u64`-widened and the result is bounded by `MAX_FRAME_BYTES`, so no cast
/// can wrap (frame lengths are bounded and this never panics on the request path).
pub fn encode_frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
    // Build the header block DIRECTLY into the frame buffer (after a 12-byte prelude placeholder)
    // rather than into a throwaway `headers` Vec that `encode_with_headers` would then copy — that
    // copy was a second heap allocation per frame on the Bedrock streaming hot path. `frame_open`
    // returns the single buffer with the prelude reserved; we append headers, then `frame_close`
    // backfills the prelude + CRCs. Byte output is identical to the prior two-buffer path.
    let mut frame = frame_open();
    // Drop the frame if any header is oversized rather than emit a corrupt/truncated header (see
    // push_string_header). `:event-type` is the only caller-supplied value; the others are literals.
    if !push_string_header(&mut frame, HDR_EVENT_TYPE, event_type)
        || !push_string_header(&mut frame, HDR_CONTENT_TYPE, crate::proxy::APPLICATION_JSON)
        || !push_string_header(&mut frame, HDR_MESSAGE_TYPE, MSG_TYPE_EVENT)
    {
        // An oversized header dropped the frame. This is unreachable for any real Bedrock event name
        // but must be OBSERVABLE rather than a silent empty-Vec: log it so a dropped streaming frame
        // is diagnosable. `:event-type` is the only caller-supplied (and thus possibly oversized)
        // value, so name it; the other two are fixed literals well under the cap.
        diag_debug!(
            EVENTSTREAM_EVENTTYPE_HEADER_OVERSIZE,
            event_type_len = event_type.len(),
            "event-stream :event-type header exceeds the type-7 string cap; dropping frame"
        );
        return Vec::new();
    }
    frame_close(frame, payload)
}

/// Encode a modeled-exception event-stream message for a native AWS SDK Bedrock client. AWS signals
/// a mid-stream error with `:message-type: exception` and an `:exception-type` header naming the
/// Converse exception (e.g. `InternalServerException`, `ModelStreamErrorException`); the payload is
/// the JSON `{"message": ...}` body the SDK surfaces. This is what a Bedrock-ingress stream must emit
/// on a mid-stream upstream failure instead of an SSE `event: error` text frame — writing SSE text
/// into a binary eventstream body produces an undecodable prelude/CRC for the SDK's decoder.
pub fn encode_exception_frame(exception_type: &str, message: &str) -> Vec<u8> {
    // Fallback only if serializing `{"message": <string>}` somehow fails (effectively unreachable
    // for a plain string). Use AWS's own generic phrasing rather than any busbar-internal routing
    // vocabulary like "upstream" — a native Bedrock exception frame would never carry that word, so
    // leaking it here would be a protocol-indistinguishability tell (mirrors the scrub already done
    // for the Gemini truncation path in proto::gemini::GeminiJsonArrayFramer::finish_with_error).
    let payload = serde_json::to_vec(&serde_json::json!({ "message": message }))
        .unwrap_or_else(|_| b"{\"message\":\"An internal server error occurred.\"}".to_vec());
    // Build headers straight into the single frame buffer (see `encode_frame`) — one allocation.
    let mut frame = frame_open();
    if !push_string_header(&mut frame, HDR_EXCEPTION_TYPE, exception_type)
        || !push_string_header(&mut frame, HDR_CONTENT_TYPE, crate::proxy::APPLICATION_JSON)
        || !push_string_header(&mut frame, HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION)
    {
        // `:exception-type` is the caller-supplied value; an oversized one drops the frame. Log so a
        // dropped exception frame (a swallowed mid-stream error signal) is observable, not silent.
        diag_debug!(
            EVENTSTREAM_EXCEPTIONTYPE_HEADER_OVERSIZE,
            exception_type_len = exception_type.len(),
            "event-stream :exception-type header exceeds the type-7 string cap; dropping frame"
        );
        return Vec::new();
    }
    frame_close(frame, &payload)
}

/// Length of the fixed event-stream prelude: `total_len:u32 + headers_len:u32 + prelude_crc:u32`.
const PRELUDE_LEN: usize = 12;

/// Length of the trailing CRC32 message checksum appended to every frame.
const CRC_BYTES: usize = 4;

/// Minimum valid frame size: prelude + message CRC, with zero-length headers and payload.
const MIN_FRAME_BYTES: usize = PRELUDE_LEN + CRC_BYTES;

/// AWS event-stream header name for the event type (normal frames).
const HDR_EVENT_TYPE: &str = ":event-type";

/// AWS event-stream header name for the content MIME type.
const HDR_CONTENT_TYPE: &str = ":content-type";

/// AWS event-stream header name for the message type discriminator (`event` or `exception`).
const HDR_MESSAGE_TYPE: &str = ":message-type";

/// AWS event-stream header name for the modeled-exception type (exception frames only).
const HDR_EXCEPTION_TYPE: &str = ":exception-type";

/// `:message-type` value for a normal Bedrock event frame.
const MSG_TYPE_EVENT: &str = "event";

/// `:message-type` value for an AWS mid-stream modeled-exception frame.
const MSG_TYPE_EXCEPTION: &str = "exception";

/// AWS event-stream value-type byte for a UTF-8 string header (type 7 per the spec).
const HDR_TYPE_STRING: u8 = 7;

/// Open a single frame buffer with the 12-byte prelude (`total_len`, `headers_len`, `prelude_crc`)
/// reserved as a zeroed placeholder. Callers append their header block directly after it, then hand
/// the buffer to [`frame_close`], which backfills the prelude. This keeps the WHOLE frame — prelude,
/// headers, payload and both CRCs — in ONE allocation (the prior `encode_with_headers` built headers
/// in a separate Vec and copied them in, a second per-frame allocation on the streaming hot path).
fn frame_open() -> Vec<u8> {
    vec![0u8; PRELUDE_LEN]
}

/// Close a frame opened by [`frame_open`] whose header block has been appended: backfill the prelude
/// (`total_len`, `headers_len`, real `prelude_crc`), append `payload`, then the real `message_crc`.
/// Shared by [`encode_frame`] and [`encode_exception_frame`]. The produced bytes are identical to the
/// prior two-buffer `encode_with_headers` path.
///
/// A frame this encoder builds is always well under `MAX_FRAME_BYTES` (small JSON bodies). If the
/// header+payload would exceed the cap, the frame is DROPPED (empty `Vec` returned) rather than
/// byte-truncating the payload: a truncated JSON payload is syntactically invalid and a CRC-valid
/// frame carrying unparseable JSON is worse for a native SDK than no frame at all. The caller appends
/// the result to its output buffer, so an empty return simply emits nothing for this event.
fn frame_close(mut frame: Vec<u8>, payload: &[u8]) -> Vec<u8> {
    // At entry `frame` is [12-byte prelude placeholder][headers]; everything past the prelude is the
    // header block.
    let headers_len = (frame.len() - PRELUDE_LEN) as u64;
    // total_len = prelude(12) + headers + payload + message_crc(4). Widen to u64 so the sum cannot
    // overflow `usize` arithmetic, then bound it against MAX_FRAME_BYTES.
    let total_len = PRELUDE_LEN as u64 + headers_len + payload.len() as u64 + CRC_BYTES as u64;
    if total_len > MAX_FRAME_BYTES as u64 {
        // Oversized: drop the frame rather than emit corrupt (truncated) JSON. Unreachable for any
        // real Bedrock ConverseStream delta; this only guards a pathological multi-MiB single event.
        // Dropping a frame is graceful (the caller appends the empty result and emits nothing for
        // this event); a CRC-valid frame carrying truncated, unparseable JSON would be worse.
        diag_debug!(
            EVENTSTREAM_FRAME_OVERSIZE,
            total_len,
            cap = MAX_FRAME_BYTES,
            "event-stream frame exceeds MAX_FRAME_BYTES; dropping"
        );
        return Vec::new();
    }

    // Reserve the payload + CRC trailer up front so appending them does not reallocate.
    frame.reserve(payload.len() + CRC_BYTES);

    // Backfill the prelude in place: total_len + headers_len (both u32 BE). Bounded above, so the
    // casts are exact.
    frame[0..4].copy_from_slice(&(total_len as u32).to_be_bytes());
    frame[4..8].copy_from_slice(&(headers_len as u32).to_be_bytes());

    // prelude_crc = CRC32 of the first 8 bytes (the two length fields).
    let prelude_crc = crc32fast::hash(&frame[..8]);
    frame[8..12].copy_from_slice(&prelude_crc.to_be_bytes());

    frame.extend_from_slice(payload);

    // message_crc = CRC32 of everything from byte 0 through the end of the payload (i.e. the whole
    // frame written so far, which is prelude + prelude_crc + headers + payload).
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());

    frame
}

#[cfg(test)]
#[path = "tests/eventstream_tests.rs"]
mod tests;
