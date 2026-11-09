// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared stateless framing helpers and established error/media vocabulary.
//! LLM dialect declarations and codecs live in their owning plane.

use zeroize::{Zeroize, Zeroizing};

/// Error `type` for a missing or invalid API key.
pub const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";
/// Error `type` for a malformed / bad-argument request.
pub const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
/// Error `type` for a permission / access-control denial.
pub const ERR_TYPE_PERMISSION: &str = "permission_error";
/// Error `type` for a resource that does not exist.
pub const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
/// Error `type` for a rate-limit / throttle response.
pub const ERR_TYPE_RATE_LIMIT: &str = "rate_limit_error";
/// Error `type` for a transient upstream failure.
pub const ERR_TYPE_SERVER_ERROR: &str = "server_error";
/// Error `type` for a billing-quota exhaustion (HTTP 429).
pub const ERR_TYPE_INSUFFICIENT_QUOTA: &str = "insufficient_quota";
/// Internal kind for an overloaded upstream; a dialect whose wire has no overloaded type maps it to
pub const ERR_TYPE_OVERLOADED: &str = "overloaded_error";
/// Error `type` for a generic upstream/API failure; also the agnostic forward-layer kind
pub const ERR_TYPE_API_ERROR: &str = "api_error";
/// Error `type` for an oversized request (HTTP 413); shared by the forward KIND bank and the
pub const ERR_TYPE_REQUEST_TOO_LARGE: &str = "request_too_large";

/// Agnostic forward kind for a generic upstream/API failure.
pub const KIND_API_ERROR: &str = ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from [`ERR_TYPE_OVERLOADED`] ("overloaded_error", one
pub const KIND_OVERLOADED: &str = "overloaded";
/// Bare `timeout` — distinct from one dialect's `timeout_error` wire spelling.
pub const KIND_TIMEOUT: &str = "timeout";
/// Transient upstream-failure forward kind (aliases the `server_error` type).
pub const KIND_SERVER_ERROR: &str = ERR_TYPE_SERVER_ERROR;
/// Caller-authentication failure forward kind (aliases the `authentication_error` type).
pub const KIND_AUTHENTICATION: &str = ERR_TYPE_AUTHENTICATION;
/// Caller-permission failure forward kind (aliases the `permission_error` type).
pub const KIND_PERMISSION: &str = ERR_TYPE_PERMISSION;
/// Rate-limit forward kind (aliases the `rate_limit_error` type).
pub const KIND_RATE_LIMIT: &str = ERR_TYPE_RATE_LIMIT;
/// Malformed/invalid-request forward kind (aliases the `invalid_request_error` type).
pub const KIND_INVALID_REQUEST: &str = ERR_TYPE_INVALID_REQUEST;
/// Unknown-model / not-found forward kind (aliases the `not_found_error` type).
pub const KIND_NOT_FOUND: &str = ERR_TYPE_NOT_FOUND;
/// Quota-exhausted forward kind (aliases the `insufficient_quota` type).
pub const KIND_INSUFFICIENT_QUOTA: &str = ERR_TYPE_INSUFFICIENT_QUOTA;
/// Oversized-request forward kind (aliases the `request_too_large` type).
pub const KIND_REQUEST_TOO_LARGE: &str = ERR_TYPE_REQUEST_TOO_LARGE;

/// The failure-DISPOSITION metric-label value for a context-length result — the label a dialect's
pub const DISPOSITION_CONTEXT_LENGTH: &str = crate::upstream::Disposition::ContextLength.label();

/// Provider error-code token emitted when a request exceeds the model's context-window limit.
pub const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
pub const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for event-stream responses — the `Content-Type` value that
pub const TEXT_EVENT_STREAM: &str = "text/event-stream";

/// Unknown/foreign egress protocol default `User-Agent`: a generic-but-present UA still beats
pub const EGRESS_UA_DEFAULT: &str = "okhttp/4.12.0";

/// Busbar-internal `provider_signal` label for an IR-parse failure (the LANE label the breaker/metrics
pub const SIGNAL_IR_PARSE: &str = "ir_parse";

/// An IR-level error, currently an alias for [`CanonicalSignal`](crate::upstream::CanonicalSignal)
pub type IrError = crate::upstream::CanonicalSignal;

/// Client-visible detail string for a mid-stream abort (the upstream connection dropped or a
pub const STREAM_ABORT_DETAIL: &str = "The response stream was interrupted.";

/// The length of the line terminator starting at `i`, or `None` when `i` does not begin one.
fn terminator_len(buf: &[u8], i: usize) -> Option<usize> {
    match buf.get(i)? {
        b'\n' => Some(1),
        b'\r' => match buf.get(i + 1) {
            Some(b'\n') => Some(2),
            Some(_) => Some(1),
            None => None,
        },
        _ => None,
    }
}

/// Find the first event-stream frame terminator (a blank line) in `buf`, returning `(offset,
pub fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    loop {
        let at = i + memchr::memchr2(b'\r', b'\n', &buf[i..])?;
        let first = terminator_len(buf, at)?;
        if let Some(second) = terminator_len(buf, at + first) {
            return Some((at, first + second));
        }

        i = at + first;
    }
}

/// Split event-stream frame text into lines on the event-stream grammar's own line-terminator rule
pub fn sse_lines(text: &str) -> Vec<&str> {
    sse_line_spans(text.as_bytes())
        .into_iter()
        .map(|(start, end)| &text[start..end])
        .collect()
}

/// The `(start, end)` byte span of each line in `bytes` under the event-stream line-terminator
pub fn sse_line_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match terminator_len(bytes, i).or((bytes[i] == b'\r').then_some(1)) {
            Some(len) => {
                spans.push((start, i));
                i += len;
                start = i;
            }
            None => i += 1,
        }
    }
    if start < bytes.len() {
        spans.push((start, bytes.len()));
    }
    spans
}

/// THE EVENT-STREAM FRAME REASSEMBLER: bytes in, whole frames out, borrowed from the one buffer.
///
/// An event stream does not arrive one frame per chunk: one read can carry three frames, half a
/// frame, or the tail of one and the head of the next. So bytes accumulate here and a frame is
/// yielded only once the blank line that ends it ([`find_frame_terminator`]) has arrived; the frame
/// includes its terminator.
///
/// Linear in the bytes fed, however they are chunked: a scan resumes where the last one stopped
/// (three bytes behind it, as the longest terminator, `\r\n\r\n`, is four), never below the end of
/// the last frame yielded; and the framed prefix is dropped once per [`push`](Self::push), not once
/// per frame. A frame is copied nowhere: [`next_frame`](Self::next_frame) lends it, and
/// [`next_span`](Self::next_span) names it in [`buffer`](Self::buffer), which holds until the next
/// push.
#[derive(Debug, Clone, Default)]
pub struct SseFrames {
    buf: Vec<u8>,
    /// The end of the last frame yielded.
    consumed: usize,
    /// How far into `buf` a scan has looked.
    scanned: usize,
}

/// The longest terminator is four bytes, so a scan resuming three bytes behind the previous end
const TERMINATOR_REWIND: usize = 3;

impl SseFrames {
    /// An empty reassembler.
    #[must_use]
    pub const fn new() -> Self {
        SseFrames {
            buf: Vec::new(),
            consumed: 0,
            scanned: 0,
        }
    }

    /// Add a chunk, first dropping every frame already yielded.
    pub fn push(&mut self, chunk: &[u8]) {
        if self.consumed > 0 {
            let remaining = self.buf.len() - self.consumed;
            self.buf.copy_within(self.consumed.., 0);

            self.buf[remaining..].zeroize();
            self.buf.truncate(remaining);
            self.scanned -= self.consumed;
            self.consumed = 0;
        }
        let required = self
            .buf
            .len()
            .checked_add(chunk.len())
            .expect("SSE buffer length overflow");
        if required > self.buf.capacity() {
            let mut grown = Zeroizing::new(Vec::new());

            grown.reserve(required.max(self.buf.capacity().saturating_mul(2)));
            grown.extend_from_slice(&self.buf);
            self.buf.zeroize();
            self.buf = std::mem::take(&mut *grown);
        }
        self.buf.extend_from_slice(chunk);
    }

    /// The span in [`buffer`](Self::buffer) of the next complete frame (its terminator included),
    pub fn next_span(&mut self) -> Option<std::ops::Range<usize>> {
        let from = self
            .scanned
            .saturating_sub(TERMINATOR_REWIND)
            .max(self.consumed)
            .min(self.buf.len());
        match find_frame_terminator(&self.buf[from..]) {
            Some((at, len)) => {
                let start = self.consumed;
                let end = from + at + len;
                self.consumed = end;
                self.scanned = end;
                Some(start..end)
            }
            None => {
                self.scanned = self.buf.len();
                None
            }
        }
    }

    /// The next complete frame (its terminator included), lent, or `None` until more bytes arrive.
    pub fn next_frame(&mut self) -> Option<&[u8]> {
        let span = self.next_span()?;
        self.buf.get(span)
    }

    /// The bytes held since the last [`push`](Self::push) dropped the framed prefix: every span
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    /// How many bytes are held that no frame yielded yet. A reader bounds this: a far end that
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len() - self.consumed
    }
}

impl Drop for SseFrames {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// A request head as a plane receives it: its fields in order, each name and value as bytes (the
pub type HeadFields<'a> = &'a [(&'a [u8], &'a [u8])];

/// The value of the FIRST field in `fields` named `name` (in any case) whose value is a legal header
#[must_use]
pub fn head_field<'a>(fields: HeadFields<'a>, name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, v)| {
            n.eq_ignore_ascii_case(name.as_bytes())
                && v.iter().all(|b| (*b >= 0x20 && *b != 0x7f) || *b == b'\t')
        })
        .map(|(_, v)| *v)
}

#[cfg(test)]
#[path = "tests/sse_frames_tests.rs"]
mod sse_frames_tests;
