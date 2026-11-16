// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE R0 ROWS (MIGRATE-ON-BOOT §4, §A4): how a store's data step hands core its 1.5.5 logical
//! rows, and how core's records step reads them back. One codec on both sides, so a store never
//! encodes what core cannot read.
//!
//! A store writes each row with its own driver, inside its own transaction, under
//! [`IMPORT_NS`]: key = the table tag (one byte) followed by the row's primary-key cells; value =
//! the row's cells in the table's fixed column order ([`table`]). A cell is one record, byte for
//! byte the MIN-3 `CellRec`: the record head (`tag` u16 = [`CELL`], `_r` u16 = 0, `len` u32), the
//! cell head (`kind` u32, `_r` u32 = 0), the tail, then zero padding to the next multiple of 8.
//! INT: the tail is an `i64` LE; REAL: the `f64` bits LE; TEXT and BLOB: the bytes; NULL: none.
//!
//! Values are what 1.5.5's own read returns, never raw storage, and counts stay in 1.5.5 whole
//! units: a negative counter is clamped to 0 by the store, so every R0 counter is in `0..=i64::MAX`.

use crate::persistence::{control::IMPORT_NAMESPACE, NamespaceId};

/// The R0 import namespace: written only by the store's own data step, into a namespace verified
/// empty first; core reserves it at admission and drains it.
pub const IMPORT_NS: NamespaceId = IMPORT_NAMESPACE;

/// The record tag of one cell (MIN-3 `store::tag::CELL`).
pub const CELL: u16 = 0x0123;

/// A cell's `kind`.
pub const CELL_NULL: u32 = 0;
/// A cell's `kind`: an `i64`.
pub const CELL_INT: u32 = 1;
/// A cell's `kind`: an `f64`, by its bits.
pub const CELL_REAL: u32 = 2;
/// A cell's `kind`: UTF-8 text.
pub const CELL_TEXT: u32 = 3;
/// A cell's `kind`: bytes.
pub const CELL_BLOB: u32 = 4;

/// The R0 tables, by tag, and their columns in order (§A4).
pub mod table {
    /// One row, key `[SUMMARY]`: physical from-version, physical to-version; then per tag 1-7:
    /// `source_rows`, `emitted` (IMPORT rows written), `consumed` (0; core-maintained); then
    /// `headless_cells`, `ignored`, the source digest (BLOB). Core appends one more INT per tag
    /// 1-7 when it rewrites the row: the IMPORT rows it has consumed (absent = 0).
    pub const SUMMARY: u8 = 0;
    /// The sqlite v1.0.6 `keys` order: id, name, key_group, allowed_pools, labels, enabled,
    /// generation_hash, created_at, updated_at, expires_at, deleted_at, revision.
    pub const KEY: u8 = 1;
    /// The sqlite v1.0.6 `credentials` order: id, key_id, kind, slot, public_id, secret,
    /// secret_form, created_at, updated_at, expires_at, revoked_at, revoke_reason, revision.
    pub const CREDENTIAL: u8 = 2;
    /// The store revision (INT).
    pub const REVISION: u8 = 3;
    /// sub, reason, created_at.
    pub const DENY: u8 = 4;
    /// One cell per 1.5.5 read key: flags ([`super::HEADLESS`]), bucket, window_start, requests,
    /// billable_requests, then per model: model, requests, billable_requests, tokens_input,
    /// tokens_output, tokens_cache_read, tokens_cache_write.
    pub const USAGE: u8 = 5;
    /// The sqlite v1.0.6 `usage_metering` order: bucket, key_id, provider, model,
    /// key_group_at_use, pricing_version, requests, billable_requests, tokens_input,
    /// tokens_output, tokens_cache_read, tokens_cache_write.
    pub const METERING: u8 = 6;
    /// seq, ts, action, resource, outcome, principal, prev_hash, hash.
    pub const AUDIT: u8 = 7;
    /// The last tag.
    pub const LAST: u8 = AUDIT;
}

/// USAGE flag bit 0: the cell had no head row (what the missing head held reads as zero).
pub const HEADLESS: i64 = 1;

/// The SUMMARY row's cells before the core-maintained tail: 2 versions, 3 counters for each of the
/// 7 tables, `headless_cells`, `ignored` and the digest.
pub const SUMMARY_CELLS: usize = 2 + 3 * table::LAST as usize + 3;

/// One cell, borrowed from the bytes it was read from.
#[derive(Clone, Copy, PartialEq)]
pub enum Cell<'a> {
    /// NULL.
    Null,
    /// An integer.
    Int(i64),
    /// A real, by its IEEE-754 bits.
    Real(u64),
    /// UTF-8 text (checked on read).
    Text(&'a str),
    /// Bytes.
    Blob(&'a [u8]),
}

/// A row's cells may hold a credential: never printed.
impl std::fmt::Debug for Cell<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Int(v) => write!(f, "Int({v})"),
            Self::Real(_) => f.write_str("Real(..)"),
            Self::Text(_) => f.write_str("Text(..)"),
            Self::Blob(_) => f.write_str("Blob(..)"),
        }
    }
}

/// Bytes that are not a run of well-formed cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an R0 row is not a run of well-formed cells")
    }
}

impl std::error::Error for Malformed {}

/// Append `cells` to `out`, each as one record.
pub fn encode(cells: &[Cell<'_>], out: &mut Vec<u8>) {
    for cell in cells {
        let scalar;
        let (kind, tail): (u32, &[u8]) = match cell {
            Cell::Null => (CELL_NULL, &[]),
            Cell::Int(v) => {
                scalar = v.to_le_bytes();
                (CELL_INT, &scalar[..])
            }
            Cell::Real(bits) => {
                scalar = bits.to_le_bytes();
                (CELL_REAL, &scalar[..])
            }
            Cell::Text(text) => (CELL_TEXT, text.as_bytes()),
            Cell::Blob(bytes) => (CELL_BLOB, bytes),
        };
        let len = 8 + tail.len();
        out.extend_from_slice(&CELL.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(tail);
        out.resize(out.len() + (8 - len % 8) % 8, 0);
    }
}

/// An R0 key: the table `tag`, then the primary-key cells.
#[must_use]
pub fn key(tag: u8, primary: &[Cell<'_>]) -> Vec<u8> {
    let mut out = vec![tag];
    encode(primary, &mut out);
    out
}

/// An R0 value: the row's cells in its table's order.
#[must_use]
pub fn value(cells: &[Cell<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    encode(cells, &mut out);
    out
}

/// Every cell of `bytes`, which must be a whole run of well-formed cells.
///
/// # Errors
/// [`Malformed`]: a head that is not a cell's, a reserved word that is not zero, a length that
/// does not fit, non-zero padding, a non-UTF-8 text, or trailing bytes.
pub fn decode(mut bytes: &[u8]) -> Result<Vec<Cell<'_>>, Malformed> {
    let mut cells = Vec::new();
    while !bytes.is_empty() {
        let tag = u16::from_le_bytes(word::<2>(bytes, 0)?);
        let reserved = u16::from_le_bytes(word::<2>(bytes, 2)?);
        let len = u32::from_le_bytes(word::<4>(bytes, 4)?);
        let len = usize::try_from(len).map_err(|_| Malformed)?;
        if tag != CELL || reserved != 0 || len < 8 {
            return Err(Malformed);
        }
        let padded = len.checked_add(8 + (8 - len % 8) % 8).ok_or(Malformed)?;
        let record = bytes.get(..padded).ok_or(Malformed)?;
        let body = &record[8..8 + len];
        if record[8 + len..].iter().any(|b| *b != 0) {
            return Err(Malformed);
        }
        let kind = u32::from_le_bytes(body[..4].try_into().map_err(|_| Malformed)?);
        if body[4..8] != [0; 4] {
            return Err(Malformed);
        }
        let tail = &body[8..];
        let scalar = || -> Result<[u8; 8], Malformed> { tail.try_into().map_err(|_| Malformed) };
        cells.push(match kind {
            CELL_NULL if tail.is_empty() => Cell::Null,
            CELL_INT => Cell::Int(i64::from_le_bytes(scalar()?)),
            CELL_REAL => Cell::Real(u64::from_le_bytes(scalar()?)),
            CELL_TEXT => Cell::Text(std::str::from_utf8(tail).map_err(|_| Malformed)?),
            CELL_BLOB => Cell::Blob(tail),
            _ => return Err(Malformed),
        });
        bytes = &bytes[padded..];
    }
    Ok(cells)
}

/// `N` bytes of `bytes` at `at`.
fn word<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], Malformed> {
    bytes
        .get(at..at + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(Malformed)
}

/// The table tag of an R0 key (`None` for an empty key).
#[must_use]
pub fn tag_of(key: &[u8]) -> Option<u8> {
    key.first().copied()
}

#[cfg(test)]
#[path = "tests/cells_tests.rs"]
mod tests;
