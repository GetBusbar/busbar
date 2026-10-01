// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REQUEST TARGET, AS 1.5.5 SENT IT. 1.5.5 built an upstream URL as text and handed it to its
//! client, whose URL parser serialised the path and query: a space in a model name went out as
//! `%20`, never refused. [`encode_target`] writes a target the same way, byte for byte, for an
//! `http(s)` URL (the WHATWG URL rules the parser follows for a special scheme):
//!
//! * the path: a `\` is a `/`; `.` and `..` segments (and their `%2e` spellings) are resolved; C0
//!   controls, space, `"`, `<`, `>`, `` ` ``, `{`, `}`, DEL and every non-ASCII byte are
//!   percent-encoded; an existing `%` is left as it is (no double encoding); an empty path is `/`;
//! * the query, after the first `?`: C0 controls, space, `"`, `#`, `<`, `>`, `'`, DEL and every
//!   non-ASCII byte are percent-encoded;
//! * a fragment, from the first `#`, is not part of a request and is dropped;
//! * leading and trailing C0 controls and spaces, and every tab, are removed first, as the parser
//!   removes them.
//!
//! CR, LF and NUL are REFUSED rather than stripped or encoded: a byte that ends a line on this wire
//! is the request-line injection shape, and the envelope renderer refuses it too.

/// Why a target cannot be written.
pub const REFUSED: &str = "a request target holds CR, LF or NUL";

fn hex(out: &mut Vec<u8>, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
}

fn in_path_set(b: u8) -> bool {
    b <= 0x20 || b >= 0x7f || matches!(b, b'"' | b'<' | b'>' | b'`' | b'{' | b'}')
}

fn in_query_set(b: u8) -> bool {
    b <= 0x20 || b >= 0x7f || matches!(b, b'"' | b'#' | b'<' | b'>' | b'\'')
}

fn is_dot(seg: &[u8]) -> bool {
    seg == b"." || seg.eq_ignore_ascii_case(b"%2e")
}

fn is_dot_dot(seg: &[u8]) -> bool {
    matches!(seg.len(), 2 | 4 | 6)
        && [&b".."[..], b".%2e", b"%2e.", b"%2e%2e"]
            .iter()
            .any(|d| seg.eq_ignore_ascii_case(d))
}

/// `target` as 1.5.5's client wrote it on the request line.
///
/// # Errors
///
/// [`REFUSED`]: the target holds CR, LF or NUL.
pub fn encode_target(target: &[u8]) -> Result<Vec<u8>, &'static str> {
    if target.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(REFUSED);
    }
    // As the parser reads its input: leading and trailing C0 controls and spaces go, and so does
    // every tab.
    let start = target
        .iter()
        .position(|b| *b > 0x20)
        .unwrap_or(target.len());
    let end = target
        .iter()
        .rposition(|b| *b > 0x20)
        .map_or(start, |at| at + 1);
    let target: Vec<u8> = target[start..end]
        .iter()
        .copied()
        .filter(|b| *b != b'\t')
        .collect();
    let target = target
        .iter()
        .position(|b| *b == b'#')
        .map_or(&target[..], |at| &target[..at]);
    let (path, query) = match target.iter().position(|b| *b == b'?') {
        Some(at) => (&target[..at], Some(&target[at + 1..])),
        None => (target, None),
    };
    // A path is absolute on the request line.
    let path: Vec<u8> = std::iter::once(b'/')
        .filter(|_| path.first().is_none_or(|b| *b != b'/' && *b != b'\\'))
        .chain(path.iter().map(|b| if *b == b'\\' { b'/' } else { *b }))
        .collect();
    let mut segments: Vec<&[u8]> = Vec::new();
    let raw: Vec<&[u8]> = path.split(|b| *b == b'/').skip(1).collect();
    let last = raw.len().saturating_sub(1);
    for (i, seg) in raw.iter().enumerate() {
        if is_dot_dot(seg) {
            segments.pop();
            if i == last {
                segments.push(b"");
            }
        } else if is_dot(seg) {
            if i == last {
                segments.push(b"");
            }
        } else {
            segments.push(seg);
        }
    }
    let mut out = Vec::with_capacity(target.len() + 8);
    if segments.is_empty() {
        out.push(b'/');
    }
    for seg in segments {
        out.push(b'/');
        for &b in seg {
            if in_path_set(b) {
                hex(&mut out, b);
            } else {
                out.push(b);
            }
        }
    }
    if let Some(query) = query {
        out.push(b'?');
        for &b in query {
            if in_query_set(b) {
                hex(&mut out, b);
            } else {
                out.push(b);
            }
        }
    }
    Ok(out)
}
