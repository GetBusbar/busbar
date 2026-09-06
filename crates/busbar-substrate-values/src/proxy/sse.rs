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
    ///
    /// Walks a local `consumed` cursor across `buf` and applies ONE `drain` at the end, rather than
    /// draining from the front once PER FRAME: `Vec::drain` from the front memmoves the entire
    /// remaining tail, so draining per frame cost O(frames × bytes) on a chunk carrying many small
    /// events (the same shape `eventstream::drain_frames_checked` fixed for the AWS framing). Nothing
    /// else observes `buf` mid-loop (this method holds the only `&mut`), so tracking a position and
    /// draining once at the end is behavior-identical.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut consumed = 0usize;
        // Resume where the last scan stopped (minus the rewind): nothing before this point can hold
        // the earliest terminator, since that region was already searched and every terminator it
        // could still complete extends into the rewind window. `buf` is not mutated mid-loop (the
        // drain happens once, after), so this absolute position stays valid across every iteration.
        let mut scan_from = self.scanned.saturating_sub(TERMINATOR_REWIND);
        while let Some((rel, len)) = {
            #[cfg(test)]
            SCANNED_BYTES.with(|c| c.set(c.get() + (self.buf.len() - scan_from)));
            frame_end(&self.buf[scan_from..])
        } {
            let end = scan_from + rel + len;
            let frame = self.buf[consumed..end].to_vec();
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
            consumed = end;
            scan_from = end;
        }
        self.scanned = self.buf.len() - consumed;
        self.drain_front(consumed);
        out
    }

    /// Drop the consumed prefix — THE ONE front-drain in this reader.
    ///
    /// The drained-work tally lives HERE, on the drain, rather than at the end of `feed`: a tally
    /// taken once per `feed` call measures the same number however many drains happened inside it,
    /// so the very regression the linearity test exists to catch (draining once per FRAME) would
    /// have left the count unchanged. Counted at the drain, a second drain counts a second time.
    fn drain_front(&mut self, upto: usize) {
        #[cfg(test)]
        DRAINED_BYTES.with(|c| c.set(c.get() + self.buf.len()));
        self.buf.drain(..upto);
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

// Test-only tally of the buffer length observed at each `drain` call, so a test can assert the
// reader's drain work is linear in the bytes fed rather than in bytes × frames-per-chunk. Thread-
// local, so parallel tests do not contaminate each other's count.
#[cfg(test)]
thread_local! {
    static DRAINED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Zero the drain tally and return what it held (test-only).
#[cfg(test)]
fn take_drained_bytes() -> usize {
    DRAINED_BYTES.with(|c| c.replace(0))
}

/// WHERE THE FIRST COMPLETE SSE EVENT ENDS, and how many bytes its terminator takes: the offset of
/// the blank line that ends it, plus that blank line's length.
///
/// THREE TERMINATORS, NOT ONE, IN EVERY PAIRING. An SSE line ends with CRLF, LF **or** a bare CR —
/// that is the event stream format's own rule, not a tolerance — and a blank line is any terminator
/// immediately followed by any terminator (nine pairings, not the three this reader once hard-coded
/// a lookup table for). This reader accepted only `\r\n\r\n`, `\n\n` and `\r\r`, on the stated
/// reasoning that a CRLF stream would be handled by stripping the `\r` off each line when the fields
/// are read. That is true of the FIELDS and false of the FRAMING: the bytes `…}\r\n\r` (a CRLF line
/// followed by a bare trailing CR) match none of the three literal needles, so an event terminated
/// that way was never recognised as an event, the frame never left the buffer, and the whole stream
/// accumulated until the connection closed.
///
/// What that looked like from outside was a backend streaming perfectly well and busbar answering
/// `502 the backend agent did not complete this task`, having logged `the backend's stream carried
/// no event` about a stream that carried four. It was invisible for as long as the only streaming
/// peer this tree ever relayed used bare LF. The A2A Python SDK does not; measured against the
/// official TCK it read as `CORE-STREAM-001/002/003`, `STREAM-ORDER-001`, `JSONRPC-SSE-001` and
/// every requirement whose setup opens a stream.
///
/// Delegates to the shared grammar-based scanner (see `crate::proto::find_frame_terminator`), which
/// walks the line-terminator grammar directly instead of matching a fixed table of literal byte
/// strings, so it names every pairing the grammar allows rather than the ones a table happened to
/// list. The EARLIEST terminator wins, so a stream that mixes forms — which the format permits, line
/// by line — still frames at the right place, and a partial terminator (`\r\n\r` with the final `\n`
/// still in flight) matches nothing and correctly waits for the rest.
fn frame_end(buf: &[u8]) -> Option<(usize, usize)> {
    crate::proto::find_frame_terminator(buf)
}

/// The `data:` payload of one SSE frame, concatenated across continuation lines as the specification
/// requires. Splits on [`crate::proto::sse_lines`], the grammar-based splitter (CRLF, lone LF, or
/// lone CR each end a line) — `str::lines()` does not split on a bare CR, so a bare-CR frame
/// yielded no data at all.
pub fn sse_data(frame: &str) -> Option<String> {
    let mut data = String::new();
    let mut any = false;
    for line in crate::proto::sse_lines(frame) {
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
