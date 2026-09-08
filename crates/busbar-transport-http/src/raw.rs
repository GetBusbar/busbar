// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A minimal HTTP/1.1 message reader: just enough to split a raw byte blob (request line or
//! status line, headers, blank line, body) into its parts, and to read a chunked body across
//! however many reads it arrives in. Not a general-purpose parser — no header folding, and the only
//! transfer coding it reads is `chunked`. Good enough for the shapes this transport actually needs:
//! what its own `write` is handed, and what an ingress connection carries.

/// The message's first line, kept as whichever of the two shapes it turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawStartLine {
    /// `METHOD path HTTP/version`.
    Request {
        /// The request method.
        method: String,
        /// The request path.
        path: String,
    },
    /// `HTTP/version status reason`.
    Status {
        /// The status code.
        code: u16,
        /// The status reason phrase.
        reason: String,
    },
}

/// One parsed message: its start line, its headers in wire order, and its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawMessage {
    /// The request or status line.
    pub start: RawStartLine,
    /// Header name/value pairs, in the order they appeared.
    pub headers: Vec<(String, String)>,
    /// Everything after the blank line.
    pub body: Vec<u8>,
}

/// Split `bytes` into a start line, headers and body. `bytes` may end exactly at the header
/// terminator (body empty) or carry the body already appended. Returns `None` on anything that
/// does not look like an HTTP/1.x message (no CRLF-terminated start line, a header line with no
/// colon, or whitespace between a field name and its colon — which the wire forbids outright).
#[must_use]
pub fn parse_message(bytes: &[u8]) -> Option<RawMessage> {
    let text_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2) // keep the final lone CRLF as the header block's own terminator
        .unwrap_or(bytes.len());
    let header_block = &bytes[..text_end];
    let body = if text_end + 2 <= bytes.len() {
        bytes[text_end + 2..].to_vec()
    } else {
        Vec::new()
    };

    let text = std::str::from_utf8(header_block).ok()?;
    let mut lines = text.split("\r\n").filter(|l| !l.is_empty());
    let start_line = lines.next()?;
    let start = parse_start_line(start_line)?;

    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        // No whitespace is allowed between a field name and its colon. Trimming it here would
        // normalise a header no compliant peer would honour into one this transport does, and the
        // disagreement that opens between an intermediary and its upstream is exactly the
        // request-smuggling surface the rule exists to close. So: refuse the message.
        if name != name.trim() {
            return None;
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }

    Some(RawMessage {
        start,
        headers,
        body,
    })
}

fn parse_start_line(line: &str) -> Option<RawStartLine> {
    let mut parts = line.splitn(3, ' ');
    let a = parts.next()?;
    let b = parts.next()?;
    let c = parts.next().unwrap_or("");
    if let Some(version) = a.strip_prefix("HTTP/") {
        if !is_http1(version) {
            return None;
        }
        let code: u16 = b.parse().ok()?;
        return Some(RawStartLine::Status {
            code,
            reason: c.to_string(),
        });
    }
    // Otherwise: `METHOD path HTTP/version`. The version token is REQUIRED. Without the check a
    // two-word first line — anything at all, followed by a space — parses as a request, so a blob
    // that is not HTTP is read as one and its first two words become a method and a path this
    // transport then acts on. The wire says every request line names its version; a line that does
    // not is not a request line.
    let version = c.strip_prefix("HTTP/")?;
    if !is_http1(version) {
        return None;
    }
    Some(RawStartLine::Request {
        method: a.to_string(),
        path: b.to_string(),
    })
}

/// Whether a version token names the HTTP/1.x this reader frames.
///
/// The framing rules below — `Content-Length`, chunked transfer coding, a CRLF-terminated header
/// block — are 1.x's. A `2` or a `3` names a wire made of frames this reader has never seen, and
/// reading one with 1.x's rules would produce a message nobody sent.
fn is_http1(version: &str) -> bool {
    matches!(version, "1.0" | "1.1")
}

/// Find a header's value, case-insensitively, as the wire allows any casing.
#[must_use]
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// A field's WHOLE value: every line carrying that name, joined with `", "`, or `None` when no
/// line carries it.
///
/// RFC 9110 5.3 makes this the definition of a repeated field: a sender may split a comma-separated
/// list across several lines, and the meaning is the one line those values would have made. Reading
/// only the first line therefore reads a different field than the one that was sent — and for the
/// framing fields below that is not a cosmetic difference, it is a body length. `Transfer-Encoding:
/// chunked` followed by `Transfer-Encoding: gzip` is the list `chunked, gzip`, whose final coding is
/// not `chunked` and whose length RFC 9112 6.1 leaves undeterminable; a reader that saw only the
/// first line would frame a body the sender never described.
#[must_use]
pub fn field_list(headers: &[(String, String)], name: &str) -> Option<String> {
    let mut out: Option<String> = None;
    for (_, v) in headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)) {
        match &mut out {
            Some(acc) => {
                acc.push_str(", ");
                acc.push_str(v.trim());
            }
            None => out = Some(v.trim().to_string()),
        }
    }
    out
}

/// Whether a header block declares a chunked body, and one this transport can actually undo.
///
/// `Transfer-Encoding` names a list — across as many lines as the sender chose, which is why the
/// whole field is read rather than its first line — and this asks the wire's own two questions of
/// it. `chunked` must be the FINAL coding (RFC 9112 6.1): a sender applying any other coding applies
/// `chunked` last so the message stays framable, and a list where it is not last leaves the body
/// length undeterminable, so `chunked, gzip` is not a chunked body but a message to refuse. And
/// `chunked` may be applied only ONCE: `chunked, chunked` describes a body wrapped twice, of which
/// undoing one layer would hand up a framing still on the bytes as though it were the body.
#[must_use]
pub fn is_chunked(headers: &[(String, String)]) -> bool {
    let Some(list) = field_list(headers, "transfer-encoding") else {
        return false;
    };
    let codings: Vec<&str> = list.split(',').map(str::trim).collect();
    let applied = codings
        .iter()
        .filter(|c| c.eq_ignore_ascii_case("chunked"))
        .count();
    applied == 1
        && codings
            .last()
            .is_some_and(|c| c.eq_ignore_ascii_case("chunked"))
}

/// Whether a header block declares a transfer coding at all, chunked or otherwise.
///
/// The companion question to [`is_chunked`]: a message that names a coding this transport cannot
/// frame is a framing error, and telling that apart from a message that names none is what lets a
/// caller refuse the first without refusing the second.
#[must_use]
pub fn has_transfer_encoding(headers: &[(String, String)]) -> bool {
    field_list(headers, "transfer-encoding").is_some()
}

/// The declared body length, where the message declares one.
///
/// `Ok(None)` when no `Content-Length` header is present. `Err(())` when one is present and is not
/// exactly `1*DIGIT` fitting a `usize` — a leading sign, a non-decimal digit, an overflowing value,
/// or a second `Content-Length` disagreeing with the first. RFC 9112 6.3: an unparsable
/// `Content-Length` with no `Transfer-Encoding` is unrecoverable framing, never a body-less
/// message. RFC 9110 8.6 allows treating identical duplicate values as one, which this does.
///
/// # Errors
///
/// Returns `Err(())` when the header is present but does not name a single valid body length.
pub fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, ()> {
    // The whole field, however many lines it was spelled across: a second `Content-Length` line is
    // the same list a comma would have made, and reading only the first would take a message that
    // declares two lengths for one that declares one.
    let Some(list) = field_list(headers, "content-length") else {
        return Ok(None);
    };
    let mut values = list.split(',').map(str::trim);
    let Some(first) = values.next() else {
        return Ok(None);
    };
    for other in values {
        if other != first {
            return Err(());
        }
    }
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    first.parse::<usize>().map(Some).map_err(|_| ())
}

/// A chunked-transfer-encoding reader, fed whatever bytes have arrived so far.
///
/// Incremental and byte-at-a-time on purpose. A body arrives across as many reads as the network
/// chooses, and a chunk boundary is free to fall in the middle of a size line, in the middle of the
/// CRLF after one, or between the terminal chunk and its trailers. A decoder that re-scanned the
/// whole buffer on every read would be quadratic in the body size, which for the megabyte bodies
/// this path exists to carry is the difference between a transport and a stall.
#[derive(Debug, Default)]
pub struct ChunkedDecoder {
    state: ChunkState,
    line: Vec<u8>,
    want: usize,
    current: Vec<u8>,
    chunks: Vec<Vec<u8>>,
    trailers: Vec<(String, String)>,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ChunkState {
    /// Reading the hexadecimal size line that opens a chunk.
    #[default]
    Size,
    /// Reading `want` more bytes of the current chunk's data.
    Data,
    /// Reading the CRLF that closes a chunk's data.
    AfterData,
    /// Reading trailer lines, terminated by an empty one.
    Trailers,
    /// The terminal chunk and its trailers have both arrived.
    Done,
}

/// The bytes did not follow the chunked grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkedMalformed;

impl ChunkedDecoder {
    /// Feed everything that has arrived since the last call.
    ///
    /// # Errors
    ///
    /// The bytes are not chunked-transfer-encoding: a size line that is not hexadecimal, a chunk
    /// not closed by CRLF, or a trailer line with no colon.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), ChunkedMalformed> {
        for &b in bytes {
            if self.state == ChunkState::Done {
                // Anything after the terminal chunk belongs to the next message on the connection,
                // which this delivery does not read (one request per connection).
                break;
            }
            self.step(b)?;
        }
        Ok(())
    }

    fn step(&mut self, b: u8) -> Result<(), ChunkedMalformed> {
        match self.state {
            ChunkState::Data => {
                self.current.push(b);
                self.want -= 1;
                if self.want == 0 {
                    self.chunks.push(std::mem::take(&mut self.current));
                    self.state = ChunkState::AfterData;
                }
            }
            ChunkState::AfterData => {
                if b == b'\n' {
                    self.state = ChunkState::Size;
                } else if b != b'\r' {
                    return Err(ChunkedMalformed);
                }
            }
            ChunkState::Size | ChunkState::Trailers => {
                if b != b'\n' {
                    if b != b'\r' {
                        self.line.push(b);
                    }
                    return Ok(());
                }
                let line = String::from_utf8(std::mem::take(&mut self.line))
                    .map_err(|_| ChunkedMalformed)?;
                if self.state == ChunkState::Size {
                    // A size line may carry chunk extensions after a semicolon; none is read.
                    let size_text = line.split(';').next().unwrap_or("").trim();
                    let size =
                        usize::from_str_radix(size_text, 16).map_err(|_| ChunkedMalformed)?;
                    self.state = if size == 0 {
                        ChunkState::Trailers
                    } else {
                        self.want = size;
                        ChunkState::Data
                    };
                } else if line.is_empty() {
                    self.state = ChunkState::Done;
                } else {
                    let (name, value) = line.split_once(':').ok_or(ChunkedMalformed)?;
                    self.trailers
                        .push((name.trim().to_string(), value.trim().to_string()));
                }
            }
            ChunkState::Done => {}
        }
        Ok(())
    }

    /// Whether the terminal chunk and its trailer section have both arrived.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// The decoded chunks, in the order the sender wrote them, and the trailers that followed.
    ///
    /// The chunking is kept rather than flattened: a sender's chunk is the unit it chose to send,
    /// and a reader that concatenated them would be reporting a framing the wire never had.
    #[must_use]
    pub fn take(self) -> (Vec<Vec<u8>>, Vec<(String, String)>) {
        (self.chunks, self.trailers)
    }
}

#[cfg(test)]
#[path = "tests/raw.rs"]
mod tests;
