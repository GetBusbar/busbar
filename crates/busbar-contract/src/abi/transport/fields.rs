// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIELD BLOCK: a request's head fields, a reply's metadata, and what a
//! [`PIECE_FIELDS`](super::PIECE_FIELDS) frame carries (the far end's head: a response's head
//! fields, a call's initial metadata), in one shape. One line per field, `name ": " value "\r\n"`,
//! and nothing else: no start line, no closing blank line; no field is the EMPTY block.
//!
//! * Names are lower-case, as the wire compares them.
//! * Fields keep the far end's order as 1.5.5's upstream client read it (its `HeaderMap`): names in
//!   the order each first arrived, and a repeated name's values each on their OWN line, in arrival
//!   order, directly after its first; never joined into one value.
//! * A value is the far end's bytes, unaltered (a field value never holds CR or LF).
//! * [`HOP_BY_HOP`] fields, and every field a `connection` field names, never enter the block: the
//!   framer drops them ([`hop_by_hop`]). Nor does `content-length`: the pieces carry the body the
//!   framer already unframed.
//!
//! A writer renders the block with [`SEPARATOR`] and [`LINE_END`]; a reader splits it with
//! [`lines`].

/// Between a field's name and its value.
pub const SEPARATOR: &[u8] = b": ";

/// After a field's value.
pub const LINE_END: &[u8] = b"\r\n";

/// The fields that never enter a field block, the ONE list (K2's `NEVER_KEPT` names its hop half
/// by this constant): HTTP's connection-specific fields, and `te`, `trailer`, `upgrade`,
/// `proxy-connection`, `proxy-authenticate` and `proxy-authorization`. 1.5.5 had no generic strip;
/// customer bytes are fixed by K2's keep allowlist (`Need::keep_response_headers`).
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
/// named `nominated` (each a comma-separated list, compared without case): a [`HOP_BY_HOP`] field,
/// or one a `connection` field names.
#[must_use]
pub fn hop_by_hop<'a>(name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
    HOP_BY_HOP.contains(&name)
        || nominated.into_iter().any(|list| {
            list.split(|b| *b == b',')
                .any(|n| n.trim_ascii().eq_ignore_ascii_case(name.as_bytes()))
        })
}

/// A field block's fields, `(name, value)`, in order. A line without [`SEPARATOR`] or
/// [`LINE_END`] ends the reading: the block is the framer's rendering, never the far end's raw
/// bytes, so a malformed tail is dropped rather than guessed at.
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
