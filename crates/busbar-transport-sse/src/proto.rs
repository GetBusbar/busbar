// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SSE frame terminator and frame parser, ported from `busbar_substrate::proto` (moved here
//! per the design's own rule: "adding a transport" means the wire-level pieces that only a
//! transport needs move into the transport crate, verbatim in behaviour). `busbar-substrate` is
//! outside this delivery's ownership, so its copy is left for that crate's own owner to retire;
//! this is the transport-owned copy `sse` actually runs on.

/// Find the first SSE frame terminator (a blank line) in `buf`, returning `(offset, terminator_len)`
/// where `offset` is the byte index of the first terminator byte. Recognizes both the LF-LF (`\n\n`,
/// 2 bytes) and the spec-legal CRLF (`\r\n\r\n`, 4 bytes) blank-line terminators per WHATWG SSE.
/// Returns `None` if no complete terminator is present yet.
#[must_use]
pub fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            if buf.get(i + 1) == Some(&b'\n') {
                return Some((i, 2));
            }
            if i >= 1
                && buf[i - 1] == b'\r'
                && buf.get(i + 1) == Some(&b'\r')
                && buf.get(i + 2) == Some(&b'\n')
            {
                return Some((i - 1, 4));
            }
        }
        i += 1;
    }
    None
}

/// Parse one SSE frame into `(event_type, data_payload)`. `event_type` is "" when the frame has
/// no `event:` line (OpenAI style). Multiple `data:` lines in a single frame are concatenated with
/// `\n` per the SSE spec. Returns `None` if the frame carries no `data:` line (including a frame
/// with only an `event:` line) or is invalid UTF-8.
#[must_use]
pub fn parse_sse_frame(frame: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event_type = String::new();
    let mut data_lines: Vec<&str> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data_lines.is_empty() {
        return None;
    }
    Some((event_type, data_lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_lf_lf_and_crlf_crlf_terminators() {
        assert_eq!(find_frame_terminator(b"data: a\n\nrest"), Some((7, 2)));
        assert_eq!(find_frame_terminator(b"data: a\r\n\r\nrest"), Some((7, 4)));
        assert_eq!(find_frame_terminator(b"data: a"), None);
    }

    #[test]
    fn parses_anthropic_and_openai_shapes() {
        assert_eq!(
            parse_sse_frame(b"event: message\ndata: {\"a\":1}"),
            Some(("message".to_string(), "{\"a\":1}".to_string()))
        );
        assert_eq!(
            parse_sse_frame(b"data: {\"a\":1}"),
            Some((String::new(), "{\"a\":1}".to_string()))
        );
        assert_eq!(parse_sse_frame(b"event: ping"), None);
    }

    #[test]
    fn joins_multiple_data_lines() {
        assert_eq!(
            parse_sse_frame(b"data: line1\ndata: line2"),
            Some((String::new(), "line1\nline2".to_string()))
        );
    }
}
