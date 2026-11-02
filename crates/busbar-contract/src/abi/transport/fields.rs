// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIELD BLOCK: a request's head fields, a reply's metadata, and what a

/// Between a field's name and its value.
pub const SEPARATOR: &[u8] = b": ";

/// After a field's value.
pub const LINE_END: &[u8] = b"\r\n";

/// The fields dropped from a dialled response block, the ONE list (K2's `NEVER_KEPT` names its hop half
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Whether the field `name` (lower-case) is hop-by-hop for an answer whose `connection` fields
#[must_use]
pub fn hop_by_hop<'a>(name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
    HOP_BY_HOP.contains(&name)
        || nominated.into_iter().any(|list| {
            list.split(|b| *b == b',')
                .any(|n| n.trim_ascii().eq_ignore_ascii_case(name.as_bytes()))
        })
}

/// A field block's fields, `(name, value)`, in order. A line without [`SEPARATOR`] or
pub fn lines(block: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    let mut rest = block;
    std::iter::from_fn(move || {
        let end = rest.windows(LINE_END.len()).position(|w| w == LINE_END)?;
        let line = &rest[..end];
        let at = line.windows(SEPARATOR.len()).position(|w| w == SEPARATOR)?;
        rest = &rest[end + LINE_END.len()..];
        Some((&line[..at], &line[at + SEPARATOR.len()..]))
    })
}
