// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared stateless framing helpers and established error/media vocabulary.
//! LLM dialect declarations and codecs live in their owning plane.

use zeroize::Zeroize;

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
/// Error `type` for a billing-quota exhaustion (HTTP 429).
pub const ERR_TYPE_INSUFFICIENT_QUOTA: &str = "insufficient_quota";
/// Error `type` for a generic upstream/API failure; also the agnostic forward-layer kind
pub const ERR_TYPE_API_ERROR: &str = "api_error";
/// Error `type` for an oversized request (HTTP 413); shared by the forward KIND bank and the
pub const ERR_TYPE_REQUEST_TOO_LARGE: &str = "request_too_large";

/// Agnostic forward kind for a generic upstream/API failure.
pub const KIND_API_ERROR: &str = ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from `ERR_TYPE_OVERLOADED` ("overloaded_error", one
pub const KIND_OVERLOADED: &str = "overloaded";
/// Caller-authentication failure forward kind (aliases the `authentication_error` type).
pub const KIND_AUTHENTICATION: &str = ERR_TYPE_AUTHENTICATION;
/// Caller-permission failure forward kind (aliases the `permission_error` type).
pub const KIND_PERMISSION: &str = ERR_TYPE_PERMISSION;
/// Rate-limit forward kind (aliases the `rate_limit_error` type).
pub const KIND_RATE_LIMIT: &str = ERR_TYPE_RATE_LIMIT;
/// Malformed/invalid-request forward kind (aliases the `invalid_request_error` type).
pub const KIND_INVALID_REQUEST: &str = ERR_TYPE_INVALID_REQUEST;
/// Quota-exhausted forward kind (aliases the `insufficient_quota` type).
pub const KIND_INSUFFICIENT_QUOTA: &str = ERR_TYPE_INSUFFICIENT_QUOTA;
/// Oversized-request forward kind (aliases the `request_too_large` type).
pub const KIND_REQUEST_TOO_LARGE: &str = ERR_TYPE_REQUEST_TOO_LARGE;

/// The failure-DISPOSITION metric-label value for a context-length result — the label a dialect's
pub const DISPOSITION_CONTEXT_LENGTH: &str = crate::upstream::Disposition::ContextLength.label();

/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
pub const APPLICATION_JSON: &str = "application/json";

/// The length of the terminator that ends the complete line whose bytes stop at `end`: CRLF, or a
/// lone CR or LF. A line holds no CR or LF of its own, so an LF after a CR is always one CRLF.
fn terminator_before(buf: &[u8], end: usize) -> usize {
    if end >= 2 && buf[end - 1] == b'\n' && buf[end - 2] == b'\r' {
        2
    } else {
        1
    }
}

/// Walk `buf`'s complete lines from the line starting at `line`, read by sseer's `parse_line`
/// (DEPENDENCY-LADDER C17). A blank line that is not the first line of the frame starting at
/// `frame` ends the frame: `Ok(its end)`. Otherwise `Err(the start of the first incomplete line)`,
/// which is where the next walk resumes (a final CR is incomplete: an LF may follow).
fn blank_line_end(buf: &[u8], mut line: usize, frame: usize) -> Result<usize, usize> {
    loop {
        let Some((kind, next)) = sseer::parser::parse_line(&buf[line..]) else {
            return Err(line);
        };
        let end = buf.len() - next.len();
        if matches!(kind, sseer::parser::RawEventLine::Empty) && line > frame {
            return Ok(end);
        }
        line = end;
    }
}

/// Find the first event-stream frame terminator (a blank line) in `buf`, returning `(offset,
pub fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let end = blank_line_end(buf, 0, 0).ok()?;
    let blank = end - terminator_before(buf, end);
    let first = blank - terminator_before(buf, blank);
    Some((first, end - first))
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
    let mut start = 0;
    while let Some((_, next)) = sseer::parser::parse_line(&bytes[start..]) {
        let end = bytes.len() - next.len();
        spans.push((start, end - terminator_before(bytes, end)));
        start = end;
    }
    // The text is whole: a last line with no terminator still counts, and a final CR ends its line
    // (`parse_line` holds a final CR back in case an LF follows).
    let rest = &bytes[start..];
    if !rest.is_empty() {
        spans.push((start, bytes.len() - usize::from(rest.ends_with(b"\r"))));
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
/// Lines are read by sseer's `parse_line` (DEPENDENCY-LADDER C17). Linear in the bytes fed, however
/// they are chunked: a walk starts at the first line not yet complete, and only once a CR or LF has
/// arrived past the last probe, so a line is read again at most once more for its terminator; and
/// the framed prefix is dropped once per [`push`](Self::push), not once per frame. A frame is copied nowhere: [`next_frame`](Self::next_frame) lends it, and
/// [`next_span`](Self::next_span) names it in [`buffer`](Self::buffer), which holds until the next
/// push.
#[derive(Debug, Clone, Default)]
pub struct SseFrames {
    buf: Vec<u8>,
    /// The end of the last frame yielded.
    consumed: usize,
    /// How far into `buf` a probe for a CR or LF has looked.
    scanned: usize,
    /// The start of the first line not yet complete (the frame's lines before it hold no blank line).
    line: usize,
}

impl SseFrames {
    /// An empty reassembler.
    #[must_use]
    pub const fn new() -> Self {
        SseFrames {
            buf: Vec::new(),
            consumed: 0,
            scanned: 0,
            line: 0,
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
            self.line -= self.consumed;
            self.consumed = 0;
        }
        let required = self
            .buf
            .len()
            .checked_add(chunk.len())
            .expect("SSE buffer length overflow");
        if required > self.buf.capacity() {
            // A fresh block of the final capacity (no reallocation of live bytes), then the old
            // one wiped (LINT-RULES LR-117).
            let mut grown = Vec::with_capacity(required.max(self.buf.capacity().saturating_mul(2)));
            grown.extend_from_slice(&self.buf);
            self.buf.zeroize();
            self.buf = grown;
        }
        self.buf.extend_from_slice(chunk);
    }

    /// The span in [`buffer`](Self::buffer) of the next complete frame (its terminator included),
    pub fn next_span(&mut self) -> Option<std::ops::Range<usize>> {
        let line = self.line.max(self.consumed);
        let probe = self.scanned.max(line).min(self.buf.len());
        if memchr::memchr2(b'\r', b'\n', &self.buf[probe..]).is_none() {
            self.line = line;
            self.scanned = self.buf.len();
            return None;
        }
        match blank_line_end(&self.buf, line, self.consumed) {
            Ok(end) => {
                let start = self.consumed;
                self.consumed = end;
                self.scanned = end;
                self.line = end;
                Some(start..end)
            }
            Err(incomplete) => {
                self.line = incomplete;
                // A final CR may yet become a CRLF: the next probe looks at it again.
                self.scanned = self.buf.len() - usize::from(self.buf.last() == Some(&b'\r'));
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
