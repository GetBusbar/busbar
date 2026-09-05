// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral SSE (Server-Sent Events) frame reader shared by the JSON-RPC plane relays.
//!
//! Bytes in, whole events out: an SSE stream does not arrive one event per chunk, so bytes
//! accumulate here and an event is emitted only on the blank line that terminates it. It lives in
//! the neutral substrate so a plane crate names it without reaching into `busbar-core`.

/// THE SSE FRAME READER: bytes in, whole events out.
///
/// A separate type rather than a closure because an SSE stream does NOT arrive one event per chunk.
/// A single TCP read can carry three events, half an event, or the tail of one and the head of the
/// next, and a reader that assumed a chunk was an event would corrupt a caller's stream under
/// exactly the conditions that are hardest to reproduce. So bytes accumulate here and an event is
/// emitted only on the blank line that terminates it.
#[derive(Default)]
pub struct SseReader {
    buf: Vec<u8>,
    /// How far into `buf` a terminator scan has already looked and found nothing. A stream that
    /// trickles one event across many chunks would otherwise re-walk the WHOLE accumulated buffer on
    /// every chunk — quadratic in the event's size, on a relay thread fed by an untrusted upstream
    /// whose only bound is the megabyte-scale body cap. Reset to zero whenever a framed event is
    /// drained, because the bytes that follow it have never been scanned in their new positions.
    scanned: usize,
}

/// The longest terminator (`\r\n\r\n`) is four bytes, so a scan that resumes THREE bytes behind the
/// previous end still sees any terminator that straddles the boundary between two chunks.
const TERMINATOR_REWIND: usize = 3;

impl SseReader {
    /// Feed a chunk and take every COMPLETE event it finished.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            // Resume where the last scan stopped (minus the rewind), and rebase the hit onto the
            // whole buffer so the drain arithmetic and the emitted frame are byte-identical to a
            // scan from zero. Nothing before `from` can hold the earliest terminator: that region
            // was already searched and every terminator it could still complete extends into the
            // rewind window.
            let from = self.scanned.saturating_sub(TERMINATOR_REWIND);
            let Some((pos, len)) = frame_end(&self.buf[from..]).map(|(pos, len)| (from + pos, len))
            else {
                self.scanned = self.buf.len();
                break;
            };
            self.scanned = 0;
            let frame = self.buf.drain(..pos + len).collect::<Vec<u8>>();
            match String::from_utf8(frame) {
                Ok(s) => out.push(s),
                // The event-stream format is UTF-8 by definition, so a non-UTF-8 frame is a
                // malformed backend. Dropping it (rather than lossily corrupting the payload) is
                // correct, but doing so SILENTLY hid the malformed stream — surface it so the drop
                // is diagnosable rather than a mystery missing event.
                Err(e) => crate::diag_warn!(
                    crate::diagnostics::PLANE_SSE_FRAME_NOT_UTF8,
                    bytes = e.as_bytes().len(),
                    "dropping a non-UTF-8 SSE frame (the event-stream format requires UTF-8)"
                ),
            }
        }
        out
    }

    /// How many bytes are held waiting for a terminator. The ceiling check reads this: a backend
    /// that streams megabytes with no blank line is an unbounded allocation it chose the size of.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

// Test-only tally of the bytes every terminator scan has walked, so a test can assert the reader's
// scanning work is linear in the bytes fed rather than in bytes × chunks. Thread-local, so parallel
// tests do not contaminate each other's count.
#[cfg(test)]
thread_local! {
    static SCANNED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Zero the scan tally and return what it held (test-only).
#[cfg(test)]
fn take_scanned_bytes() -> usize {
    SCANNED_BYTES.with(|c| c.replace(0))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    #[cfg(test)]
    SCANNED_BYTES.with(|c| c.set(c.get() + haystack.len()));
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// WHERE THE FIRST COMPLETE SSE EVENT ENDS, and how many bytes its terminator takes: the offset of
/// the blank line that ends it, plus that blank line's length.
///
/// THREE TERMINATORS, NOT ONE. An SSE line ends with CRLF, LF **or** a bare CR — that is the event
/// stream format's own rule, not a tolerance — so the blank line that ends an event is `\r\n\r\n`,
/// `\n\n` or `\r\r`. This reader accepted only `\n\n`, on the stated reasoning that a CRLF stream
/// would be handled by stripping the `\r` off each line when the fields are read. That is true of
/// the FIELDS and false of the FRAMING: the bytes `…}\r\n\r\n` contain no `\n\n` at all, so an
/// event terminated the CRLF way was never recognised as an event, the frame never left the buffer,
/// and the whole stream accumulated until the connection closed.
///
/// What that looked like from outside was a backend streaming perfectly well and busbar answering
/// `502 the backend agent did not complete this task`, having logged `the backend's stream carried
/// no event` about a stream that carried four. It was invisible for as long as the only streaming
/// peer this tree ever relayed used bare LF. The A2A Python SDK does not; measured against the
/// official TCK it read as `CORE-STREAM-001/002/003`, `STREAM-ORDER-001`, `JSONRPC-SSE-001` and
/// every requirement whose setup opens a stream.
///
/// The EARLIEST terminator wins, so a stream that mixes forms — which the format permits, line by
/// line — still frames at the right place, and a partial terminator (`\r\n\r` with the final `\n`
/// still in flight) matches nothing and correctly waits for the rest.
fn frame_end(buf: &[u8]) -> Option<(usize, usize)> {
    [
        b"\r\n\r\n".as_slice(),
        b"\n\n".as_slice(),
        b"\r\r".as_slice(),
    ]
    .into_iter()
    .filter_map(|t| find(buf, t).map(|pos| (pos, t.len())))
    .min_by_key(|(pos, len)| (*pos, std::cmp::Reverse(*len)))
}

/// The `data:` payload of one SSE frame, concatenated across continuation lines as the specification
/// requires.
pub fn sse_data(frame: &str) -> Option<String> {
    let mut data = String::new();
    let mut any = false;
    for line in frame.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        // A `data:`-prefixed line carries the value after the colon; a BARE `data` line (no colon)
        // is a `data` field with an EMPTY value per the event-stream format — both contribute to the
        // payload (the bare form as an empty continuation line), so recognise both.
        let rest = if let Some(rest) = line.strip_prefix("data:") {
            rest
        } else if line == "data" {
            ""
        } else {
            continue;
        };
        if any {
            data.push('\n');
        }
        any = true;
        data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
    }
    any.then_some(data)
}

#[cfg(test)]
#[path = "../tests/sse_tests.rs"]
mod tests;
