// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A minimal HTTP/1.1 message reader: just enough to split a raw byte blob (request line or
//! status line, headers, blank line, body) into its parts. Not a general-purpose parser — no
//! chunked transfer-encoding, no header folding, no trailers. Good enough for the shapes this
//! transport actually needs to read: what its own `write` is handed, and what an ingress
//! connection's header prefix looks like.

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
