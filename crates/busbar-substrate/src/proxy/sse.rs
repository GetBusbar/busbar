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
}

impl SseReader {
    /// Feed a chunk and take every COMPLETE event it finished.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some((pos, len)) = frame_end(&self.buf) {
            let frame = self.buf.drain(..pos + len).collect::<Vec<u8>>();
            if let Ok(s) = String::from_utf8(frame) {
                out.push(s);
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

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
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
        let Some(rest) = line.strip_prefix("data:") else {
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
