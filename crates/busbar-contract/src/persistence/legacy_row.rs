// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Lossless physical cells for explicit historical import, never runtime Store
//! operations. Column meaning and source schema belong to a registered migration
//! edge. Integers retain their signed bit representation, real values their exact
//! IEEE bits, and text its original bytes. No coercion, JSON, or secret logging.

use crate::redacted::{OwnerSeal, Secret};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"BBLROW01";

/// A borrowed native cell. Its bytes may contain credentials or signed evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cell<'a> {
    /// SQL NULL, distinct from empty text or an empty blob.
    Null,
    /// Native signed integer, without conversion to a domain quantity.
    Integer(i64),
    /// Exact IEEE-754 binary64 representation, including signed zero.
    RealBits(u64),
    /// Native text bytes. The domain decoder decides whether UTF-8 is required.
    Text(&'a [u8]),
    /// Native binary bytes.
    Blob(&'a [u8]),
}

impl std::fmt::Debug for Cell<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cell([REDACTED])")
    }
}

/// Content-free import framing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Unknown version, type, truncation, or trailing input.
    Malformed,
    /// The caller's explicit output allocation budget is insufficient.
    Budget,
    /// A wire length cannot be represented.
    Overflow,
    /// Allocation failed before any result was published.
    Allocation,
}

/// Encode an import row into the physical reader's wiping ownership. The budget
/// counts the new output only; native buffers remain owned by the caller.
pub fn encode<O: OwnerSeal>(
    cells: &[Cell<'_>],
    budget: usize,
) -> Result<Secret<Vec<u8>, O>, Error> {
    let count = u32::try_from(cells.len()).map_err(|_| Error::Overflow)?;
    let mut size = 12usize;
    for cell in cells {
        let extra = match cell {
            Cell::Null => 1,
            Cell::Integer(_) | Cell::RealBits(_) => 9,
            Cell::Text(bytes) | Cell::Blob(bytes) => {
                u64::try_from(bytes.len()).map_err(|_| Error::Overflow)?;
                9usize.checked_add(bytes.len()).ok_or(Error::Overflow)?
            }
        };
        size = size.checked_add(extra).ok_or(Error::Overflow)?;
    }
    if size > budget {
        return Err(Error::Budget);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&count.to_le_bytes());
    for cell in cells {
        match cell {
            Cell::Null => bytes.push(0),
            Cell::Integer(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            Cell::RealBits(value) => {
                bytes.push(2);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            Cell::Text(value) | Cell::Blob(value) => {
                bytes.push(if matches!(cell, Cell::Text(_)) { 3 } else { 4 });
                bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
                bytes.extend_from_slice(value);
            }
        }
    }
    Ok(Secret::held(std::mem::take(&mut *bytes)))
}

/// Validated borrowed row. Parsing does not allocate or copy protected payloads.
/// Construct only while the underlying protected input remains lent by its owner.
#[derive(Clone, Copy)]
pub struct Row<'a> {
    cells: &'a [u8],
    count: u32,
}

impl std::fmt::Debug for Row<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyRow")
            .field("columns", &self.count)
            .finish_non_exhaustive()
    }
}

impl<'a> Row<'a> {
    /// Validate every cell and exact end of frame before exposing any value.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(Error::Malformed);
        }
        let count = u32::from_le_bytes(
            bytes
                .get(8..12)
                .ok_or(Error::Malformed)?
                .try_into()
                .map_err(|_| Error::Malformed)?,
        );
        let cells = bytes.get(12..).ok_or(Error::Malformed)?;
        // Even NULL consumes one byte: reject impossible counts in constant time.
        if u64::from(count) > cells.len() as u64 {
            return Err(Error::Malformed);
        }
        let mut remaining = cells;
        for _ in 0..count {
            take_cell(&mut remaining)?;
        }
        if !remaining.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self { cells, count })
    }

    /// Borrow cells in the schema's original ordinal order.
    pub fn cells(self) -> impl ExactSizeIterator<Item = Cell<'a>> {
        let mut bytes = self.cells;
        (0..self.count).map(move |_| take_cell(&mut bytes).expect("validated immutable row"))
    }
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    let value = bytes.get(..n).ok_or(Error::Malformed)?;
    *bytes = &bytes[n..];
    Ok(value)
}

fn take_cell<'a>(bytes: &mut &'a [u8]) -> Result<Cell<'a>, Error> {
    let tag = take(bytes, 1)?[0];
    match tag {
        0 => Ok(Cell::Null),
        1 => Ok(Cell::Integer(i64::from_le_bytes(
            take(bytes, 8)?.try_into().map_err(|_| Error::Malformed)?,
        ))),
        2 => Ok(Cell::RealBits(u64::from_le_bytes(
            take(bytes, 8)?.try_into().map_err(|_| Error::Malformed)?,
        ))),
        3 | 4 => {
            let len = u64::from_le_bytes(take(bytes, 8)?.try_into().map_err(|_| Error::Malformed)?);
            let value = take(bytes, usize::try_from(len).map_err(|_| Error::Malformed)?)?;
            Ok(if tag == 3 {
                Cell::Text(value)
            } else {
                Cell::Blob(value)
            })
        }
        _ => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    crate::own_seal!(Own);

    #[test]
    fn legacy_cells_preserve_exact_types_bits_and_protected_bytes() {
        let cells = [
            Cell::Null,
            Cell::Integer(i64::MIN),
            Cell::Integer(-1),
            Cell::RealBits((-0.0f64).to_bits()),
            Cell::RealBits(0x7ff8000000000001),
            Cell::Text(&[0xff, 0, 1]),
            Cell::Blob(b"credential"),
            Cell::Text(b""),
            Cell::Blob(b""),
        ];
        let encoded = encode::<Own>(&cells, 1024).unwrap();
        assert_eq!(
            Row::decode(encoded.expose_own(&Own::here()))
                .unwrap()
                .cells()
                .collect::<Vec<_>>(),
            cells
        );
        assert!(!format!("{cells:?}{encoded:?}").contains("credential"));
        assert_eq!(encode::<Own>(&cells, 12).unwrap_err(), Error::Budget);
    }

    #[test]
    fn rejects_every_truncation_unknown_version_tag_and_trailing_bytes() {
        let encoded = encode::<Own>(&[Cell::Text(b"one"), Cell::Integer(7)], 1024).unwrap();
        let bytes = encoded.expose_own(&Own::here());
        for end in 0..bytes.len() {
            assert!(Row::decode(&bytes[..end]).is_err());
        }
        for at in [0, 7, 12] {
            let mut changed = bytes.clone();
            changed[at] = 255;
            assert!(Row::decode(&changed).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(Row::decode(&changed).is_err());
        changed = bytes.clone();
        changed[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Row::decode(&changed).is_err());
    }
}
