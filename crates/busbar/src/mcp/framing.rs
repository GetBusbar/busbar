// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHERE ONE MESSAGE ENDS AND THE NEXT BEGINS.
//!
//! MCP's three transports differ, at this layer, in exactly one way: stdio delimits messages with a
//! newline, SSE delimits an event with a blank line, and streamable HTTP carries either a single
//! JSON body (one frame, no delimiter needed) or an SSE stream. So there is ONE reader with two
//! delimiters rather than a reader per transport, because a second reader is a second place for the
//! size cap, the poisoning rule and the truncation rule to be got subtly differently.
//!
//! ## Why this does not reuse the LLM stream translator
//!
//! `crate::proto::stream` also reads SSE, and it is deliberately not reused. That type is not a
//! frame reader: it is the cross-protocol response translator, fused to the IR decode state, the
//! per-provider terminator rules and the usage fold. Its SSE handling is a step inside a state
//! machine about LLM responses. Borrowing it here would couple the MCP plane to the LLM plane's
//! internals to save a hundred lines of line-splitting, which is the wrong trade in the direction
//! that matters (the planes are siblings, and siblings do not reach into each other).
//!
//! ## The one rule
//!
//! A framer that does not know where it is in the stream must STOP, never guess. Every design
//! decision below is that rule applied: an over-long frame poisons the reader rather than
//! resynchronising at the next delimiter, because the next delimiter is a byte the PEER chose, and
//! resynchronising there means the attacker picks where our next message starts.

/// One delivered frame: the bytes of exactly one JSON-RPC message, plus the SSE event name when the
/// transport supplied one (`Framing::Lines` has no such concept and always reports `None`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) event: Option<String>,
    pub(crate) payload: Vec<u8>,
}

/// How the byte stream is cut into frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    /// Newline-delimited JSON: the stdio transport, and the shape a JSON-RPC message must keep to
    /// survive it (no raw newline inside a frame, which is why every frame we emit is one line).
    Lines,
    /// Server-sent events: fields per line, dispatch on a blank line, `data` lines joined.
    Sse,
}

/// Why framing stopped. Each of these ends the CONNECTION rather than one message: after any of
/// them the reader has lost track of the message boundary, and the only safe recovery is a new
/// stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// A frame exceeded the size cap before its terminator arrived.
    FrameTooLarge { limit: usize, seen: usize },
    /// The stream ended part way through a frame, carrying this many undelivered bytes.
    TruncatedAtEof(usize),
    /// The reader was already poisoned by an earlier error and will never deliver another frame.
    Poisoned,
}

const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// An incremental frame reader. Bytes go in as the transport produces them, in whatever chunk sizes
/// it chooses; frames come out only when complete.
pub(crate) struct FrameReader {
    framing: Framing,
    /// The largest frame this reader will assemble. Not a tidiness rule: an unterminated frame with
    /// no cap is an unbounded allocation driven entirely by the peer.
    limit: usize,
    /// Bytes received and not yet consumed into a line.
    buf: Vec<u8>,
    /// The SSE data buffer for the event being assembled.
    data: Vec<u8>,
    /// Whether any `data:` field was seen for the event being assembled. Distinct from `data` being
    /// empty, because `data:` with an empty value is still a dispatch.
    data_present: bool,
    /// The SSE `event:` field for the event being assembled.
    event: Option<String>,
    /// Set once the reader has lost the message boundary. Terminal.
    poisoned: bool,
    /// The next error to hand back. Held rather than returned immediately because errors surface
    /// through `next_frame`, and the byte that triggered one may have arrived during `push`.
    pending: Option<FrameError>,
    /// Whether the leading byte-order mark question is settled.
    bom_done: bool,
}

impl FrameReader {
    pub(crate) fn new(framing: Framing, limit: usize) -> Self {
        FrameReader {
            framing,
            limit,
            buf: Vec::new(),
            data: Vec::new(),
            data_present: false,
            event: None,
            poisoned: false,
            pending: None,
            bom_done: false,
        }
    }

    /// How many bytes are held for a frame that is not complete yet. Bounded by `limit`.
    pub(crate) fn buffered(&self) -> usize {
        self.buf.len() + self.data.len()
    }

    /// Feed the reader. A poisoned reader accepts nothing: it buffers no bytes at all, so a peer
    /// that keeps sending after being cut off cannot make us hold its data.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        if self.poisoned {
            self.pending = Some(FrameError::Poisoned);
            return;
        }
        self.buf.extend_from_slice(bytes);
        self.strip_bom();
        // The cap is enforced HERE as well as at delivery, so the bound holds against a peer that
        // simply never sends a terminator: without this, `push` is the unbounded allocation.
        if !self.buf.contains(&b'\n') && self.buffered() > self.limit {
            self.poison(FrameError::FrameTooLarge {
                limit: self.limit,
                seen: self.buffered(),
            });
        }
    }

    /// The next complete frame, or `None` when more bytes are needed.
    pub(crate) fn next_frame(&mut self) -> Option<Result<Frame, FrameError>> {
        if let Some(e) = self.pending.take() {
            return Some(Err(e));
        }
        if self.poisoned {
            return None;
        }
        loop {
            let line = self.take_line()?;
            if let Some(e) = self.pending.take() {
                return Some(Err(e));
            }
            match self.framing {
                Framing::Lines => {
                    // A blank line is a keepalive, not an empty message. Delivering it would make
                    // every reader downstream carry an "ignore the empty one" special case.
                    if line.is_empty() {
                        continue;
                    }
                    return Some(Ok(Frame {
                        event: None,
                        payload: line,
                    }));
                }
                Framing::Sse => {
                    if let Some(frame) = self.sse_line(line) {
                        return Some(Ok(frame));
                    }
                    if let Some(e) = self.pending.take() {
                        return Some(Err(e));
                    }
                }
            }
        }
    }

    /// End of stream. Anything still held was a frame the peer never finished, and a half-message is
    /// exactly the prefix an attacker would most like delivered, so it is reported rather than
    /// flushed.
    pub(crate) fn finish(&mut self) -> Result<(), FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        let held = self.buffered();
        if held > 0 {
            return Err(FrameError::TruncatedAtEof(held));
        }
        Ok(())
    }

    fn poison(&mut self, e: FrameError) {
        self.poisoned = true;
        self.pending = Some(e);
        self.buf.clear();
        self.data.clear();
        self.data_present = false;
        self.event = None;
    }

    /// A leading byte-order mark belongs to the stream, not to the first frame, and is stripped
    /// once. Resolved only when enough bytes have arrived to tell, so a mark split across two
    /// chunks is still recognised.
    fn strip_bom(&mut self) {
        if self.bom_done {
            return;
        }
        if self.buf.len() >= BOM.len() {
            if self.buf.starts_with(BOM) {
                self.buf.drain(..BOM.len());
            }
            self.bom_done = true;
        } else if !self.buf.is_empty() && !BOM.starts_with(&self.buf) {
            self.bom_done = true;
        }
    }

    /// One complete line, terminator stripped, or `None` if no terminator has arrived. Enforces the
    /// size cap on the line itself so an over-long but eventually-terminated frame is refused too.
    fn take_line(&mut self) -> Option<Vec<u8>> {
        let nl = self.buf.iter().position(|b| *b == b'\n')?;
        let mut end = nl;
        if end > 0 && self.buf[end - 1] == b'\r' {
            end -= 1;
        }
        if end > self.limit {
            self.poison(FrameError::FrameTooLarge {
                limit: self.limit,
                seen: end,
            });
            return Some(Vec::new());
        }
        let line: Vec<u8> = self.buf[..end].to_vec();
        self.buf.drain(..=nl);
        Some(line)
    }

    /// One SSE line. Returns a frame when the line dispatched the event being assembled.
    fn sse_line(&mut self, line: Vec<u8>) -> Option<Frame> {
        // Blank line: dispatch. With no `data` field seen there is nothing to dispatch, and the
        // event-stream rules say so explicitly; emitting an empty payload instead would hand the
        // JSON-RPC parser a frame guaranteed to fail, once per keepalive.
        if line.is_empty() {
            let event = self.event.take();
            let dispatched = self.data_present;
            let payload = std::mem::take(&mut self.data);
            self.data_present = false;
            return dispatched.then_some(Frame { event, payload });
        }
        // A line starting with a colon is a comment: the standard keepalive.
        if line[0] == b':' {
            return None;
        }
        let (field, value) = match line.iter().position(|b| *b == b':') {
            Some(i) => {
                let mut v = &line[i + 1..];
                // Exactly one optional space after the colon belongs to the framing, not the value.
                if v.first() == Some(&b' ') {
                    v = &v[1..];
                }
                (&line[..i], v.to_vec())
            }
            // A field with no colon is a field with an empty value.
            None => (&line[..], Vec::new()),
        };
        match field {
            b"data" => {
                if self.data_present {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(&value);
                self.data_present = true;
                if self.data.len() > self.limit {
                    self.poison(FrameError::FrameTooLarge {
                        limit: self.limit,
                        seen: self.data.len(),
                    });
                }
            }
            b"event" => self.event = Some(String::from_utf8_lossy(&value).into_owned()),
            // `id`, `retry` and anything a future revision adds: not ours to interpret, and
            // deliberately not folded into the payload.
            _ => {}
        }
        None
    }
}

#[cfg(test)]
#[path = "tests/framing_tests.rs"]
mod framing_tests;
