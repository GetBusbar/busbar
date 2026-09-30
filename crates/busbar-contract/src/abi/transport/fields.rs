// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIELD BLOCK: a request's head fields and a reply's metadata, in one shape. One line per
//! field, `name ": " value "\r\n"`, in order, and nothing else: no start line, no closing blank
//! line; no field is the EMPTY block. A field value never holds CR or LF.
//!
//! A writer renders the block with [`SEPARATOR`] and [`LINE_END`]; a reader splits it with
//! [`lines`].

/// Between a field's name and its value.
pub const SEPARATOR: &[u8] = b": ";

/// After a field's value.
pub const LINE_END: &[u8] = b"\r\n";

/// A field block's fields, `(name, value)`, in order. A line without [`SEPARATOR`] or
/// [`LINE_END`] ends the reading: the block is a framer's rendering, never the far end's raw
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
