// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Required collection declaration in `Statement::extensions` (`BLOB_OCTETS`, flags zero).
//! The value is little-endian u32 version, count, then count triples (kind, mode, parent).
//! Mode 1 is upsert, 2 append; parent `u32::MAX` means none. All indices are local to
//! this instance's record kinds. Unknown versions, fields and modes fail admission.
//! Retention remains the neutral `PlaneTail::record_retentions` declaration.

use super::check::{check_record_collections, Fault, Rule};
use crate::abi::mechanism::{check::fault, extensions};

/// Required collection descriptor; its payload explicitly negotiates its version.
pub const EXT_RECORD_COLLECTIONS: &str = "busbar.plane.record-collections";
/// The sole supported descriptor version.
pub const VERSION: u32 = 1;
/// No parent collection.
pub const NO_PARENT: u32 = u32::MAX;
/// Record identity behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionMode {
    /// Replace the record with the same id.
    Upsert,
    /// Append a new sequence entry.
    Append,
}
/// An instance-local collection, with no business-specific kind names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordCollection {
    /// Index into the declaring instance's record kinds.
    pub kind: u32,
    /// Identity behavior.
    pub mode: CollectionMode,
    /// Parent kind index; a parent must itself be declared in upsert mode.
    pub parent: Option<u32>,
}

/// Encode a descriptor value after checking every relationship.
pub fn encode(collections: &[RecordCollection], kinds: u64) -> Result<Vec<u8>, Fault> {
    check_record_collections(collections, kinds)?;
    let count = u32::try_from(collections.len())
        .map_err(|_| fault(Rule::Contradiction, "collections.count"))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    for c in collections {
        bytes.extend_from_slice(&c.kind.to_le_bytes());
        bytes.extend_from_slice(
            &(match c.mode {
                CollectionMode::Upsert => 1u32,
                CollectionMode::Append => 2,
            })
            .to_le_bytes(),
        );
        bytes.extend_from_slice(&c.parent.unwrap_or(NO_PARENT).to_le_bytes());
    }
    Ok(bytes)
}

/// Decode a required descriptor value. No trailing fields are silently ignored.
pub fn decode(bytes: &[u8], kinds: u64) -> Result<Vec<RecordCollection>, Fault> {
    let invalid = || fault(Rule::Contradiction, "collections.descriptor");
    let word = |at: usize| -> Result<u32, Fault> {
        Ok(u32::from_le_bytes(
            bytes
                .get(at..at + 4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ))
    };
    if word(0)? != VERSION {
        return Err(invalid());
    }
    let count = word(4)? as usize;
    if count > kinds as usize
        || count.checked_mul(12).and_then(|n| n.checked_add(8)) != Some(bytes.len())
    {
        return Err(invalid());
    }
    let mut collections = Vec::with_capacity(count);
    for i in 0..count {
        let at = 8 + i * 12;
        let parent = word(at + 8)?;
        collections.push(RecordCollection {
            kind: word(at)?,
            mode: match word(at + 4)? {
                1 => CollectionMode::Upsert,
                2 => CollectionMode::Append,
                _ => return Err(invalid()),
            },
            parent: (parent != NO_PARENT).then_some(parent),
        });
    }
    check_record_collections(&collections, kinds)?;
    Ok(collections)
}

/// Read the single descriptor from a complete extensions stream. Duplicate or malformed
/// entries fail closed; unrelated whole entries remain available to their owners.
pub fn from_extensions(bytes: &[u8], kinds: u64) -> Result<Vec<RecordCollection>, Fault> {
    let mut used = 0usize;
    let mut found = None;
    for (key, value) in extensions::entries(bytes) {
        used += 2 + key.len() + 4 + value.len();
        if key == EXT_RECORD_COLLECTIONS.as_bytes() {
            if found.is_some() {
                return Err(fault(Rule::Contradiction, "collections.twice"));
            }
            found = Some(decode(value, kinds)?);
        }
    }
    if used != bytes.len() {
        return Err(fault(Rule::Contradiction, "collections.extensions"));
    }
    Ok(found.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> RecordCollection {
        RecordCollection {
            kind: 0,
            mode: CollectionMode::Upsert,
            parent: None,
        }
    }
    #[test]
    fn version_fields_and_modes_are_required() {
        let good = encode(&[root()], 1).unwrap();
        assert_eq!(decode(&good, 1), Ok(vec![root()]));
        for (at, value) in [(0, 2u32), (12, 3u32)] {
            let mut bad = good.clone();
            bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(decode(&bad, 1).is_err());
        }
        let mut extra = good.clone();
        extra.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode(&extra, 1).is_err());
        assert!(decode(&good[..good.len() - 1], 1).is_err());
        assert!(decode(&good, 0).is_err());
    }
    #[test]
    fn relationships_reject_missing_duplicate_cyclic_and_append_parent() {
        let child = RecordCollection {
            kind: 1,
            mode: CollectionMode::Append,
            parent: Some(0),
        };
        assert!(encode(&[child], 2).is_err());
        assert!(encode(&[root(), root()], 2).is_err());
        let mut cyclic = root();
        cyclic.parent = Some(1);
        let other = RecordCollection {
            kind: 1,
            mode: CollectionMode::Upsert,
            parent: Some(0),
        };
        assert!(encode(&[cyclic, other], 2).is_err());
        let mut append = root();
        append.mode = CollectionMode::Append;
        assert!(encode(&[append, child], 2).is_err());
        let mut absent = child;
        absent.parent = Some(2);
        assert!(encode(&[root(), absent], 2).is_err());
    }
    #[test]
    fn new_unnamed_plane_needs_only_its_local_indices() {
        let rows = [
            root(),
            RecordCollection {
                kind: 1,
                mode: CollectionMode::Append,
                parent: Some(0),
            },
        ];
        let value = encode(&rows, 2).unwrap();
        let statement =
            extensions::encode(&[("unrelated", b"opaque"), (EXT_RECORD_COLLECTIONS, &value)]);
        assert_eq!(from_extensions(&statement, 2), Ok(rows.to_vec()));
        let duplicate = extensions::encode(&[
            (EXT_RECORD_COLLECTIONS, &value),
            (EXT_RECORD_COLLECTIONS, &value),
        ]);
        assert!(from_extensions(&duplicate, 2).is_err());
        let mut bad = statement;
        bad.push(0);
        assert!(from_extensions(&bad, 2).is_err());
    }
}
