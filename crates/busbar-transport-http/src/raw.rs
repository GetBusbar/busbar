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

impl RawStartLine {
    /// The method, when this is a request line; otherwise a caller-supplied default.
    #[must_use]
    pub fn method_or<'a>(&'a self, default: &'a str) -> &'a str {
        match self {
            Self::Request { method, .. } => method,
            Self::Status { .. } => default,
        }
    }
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
/// does not look like an HTTP/1.x message (no CRLF-terminated start line, or unparsable headers).
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
        headers.push((name.trim().to_string(), value.trim().to_string()));
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
        let _ = version;
        let code: u16 = b.parse().ok()?;
        return Some(RawStartLine::Status {
            code,
            reason: c.to_string(),
        });
    }
    // Otherwise: `METHOD path HTTP/version`.
    Some(RawStartLine::Request {
        method: a.to_string(),
        path: b.to_string(),
    })
}

/// Find a header's value, case-insensitively, as the wire allows any casing.
#[must_use]
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Whether a header block declares a chunked body.
///
/// `Transfer-Encoding` may name a list; `chunked` is the last one when present, and it is the only
/// coding this transport reads. A message that declares one it does not carry is a framing error
/// rather than a body, which is why this is a question asked of the headers and not of the bytes.
#[must_use]
pub fn is_chunked(headers: &[(String, String)]) -> bool {
    header(headers, "transfer-encoding").is_some_and(|v| {
        v.split(',')
            .any(|c| c.trim().eq_ignore_ascii_case("chunked"))
    })
}

/// The declared body length, where the message declares one.
#[must_use]
pub fn content_length(headers: &[(String, String)]) -> Option<usize> {
    header(headers, "content-length").and_then(|v| v.trim().parse().ok())
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
mod tests {
    use super::*;

    #[test]
    fn parses_a_request_line_and_headers() {
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: example\r\nContent-Length: 3\r\n\r\nabc";
        let msg = parse_message(raw).unwrap();
        assert_eq!(
            msg.start,
            RawStartLine::Request {
                method: "GET".to_string(),
                path: "/v1/models".to_string()
            }
        );
        assert_eq!(msg.headers[0], ("Host".to_string(), "example".to_string()));
        assert_eq!(msg.body, b"abc");
    }

    #[test]
    fn a_chunked_body_survives_arriving_one_byte_at_a_time() {
        // The boundary that matters: a size line, a chunk's data, the CRLF after it and the
        // trailer section are all free to be split by the network wherever it likes.
        let wire = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: 7\r\n\r\n";
        let mut decoder = ChunkedDecoder::default();
        for byte in wire {
            assert!(!decoder.is_done());
            decoder.feed(&[*byte]).unwrap();
        }
        assert!(decoder.is_done());
        let (chunks, trailers) = decoder.take();
        assert_eq!(chunks, vec![b"Wiki".to_vec(), b"pedia".to_vec()]);
        assert_eq!(trailers, vec![("X-Checksum".to_string(), "7".to_string())]);
    }

    #[test]
    fn a_chunked_body_with_no_trailers_ends_at_the_terminal_chunk() {
        let mut decoder = ChunkedDecoder::default();
        decoder.feed(b"3\r\nabc\r\n0\r\n\r\n").unwrap();
        assert!(decoder.is_done());
        let (chunks, trailers) = decoder.take();
        assert_eq!(chunks, vec![b"abc".to_vec()]);
        assert!(trailers.is_empty());
    }

    #[test]
    fn a_size_line_that_is_not_hexadecimal_is_a_framing_error() {
        let mut decoder = ChunkedDecoder::default();
        assert_eq!(decoder.feed(b"zz\r\n"), Err(ChunkedMalformed));
    }

    #[test]
    fn chunk_extensions_are_ignored_rather_than_read() {
        let mut decoder = ChunkedDecoder::default();
        decoder.feed(b"3;name=value\r\nabc\r\n0\r\n\r\n").unwrap();
        assert!(decoder.is_done());
        assert_eq!(decoder.take().0, vec![b"abc".to_vec()]);
    }

    #[test]
    fn the_declared_length_and_coding_are_read_whatever_the_header_casing() {
        let headers = vec![
            ("CONTENT-length".to_string(), " 12 ".to_string()),
            ("Transfer-Encoding".to_string(), "gzip, Chunked".to_string()),
        ];
        assert_eq!(content_length(&headers), Some(12));
        assert!(is_chunked(&headers));
        assert!(!is_chunked(&[(
            "Transfer-Encoding".to_string(),
            "gzip".to_string()
        )]));
    }

    #[test]
    fn parses_a_status_line() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let msg = parse_message(raw).unwrap();
        assert_eq!(
            msg.start,
            RawStartLine::Status {
                code: 404,
                reason: "Not Found".to_string()
            }
        );
        assert!(msg.body.is_empty());
    }
}
