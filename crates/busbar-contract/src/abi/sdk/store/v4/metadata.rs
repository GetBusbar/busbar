// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Fixed, versioned open-result metadata for the primitive Store contract.
//! These facts are a declaration, not independent proof of deployment durability.

use crate::persistence::{BackendInfo, DatasetId, Durability};

/// Open-result extension carrying these exact metadata bytes.
pub const EXTENSION: &str = "busbar.store.persistence/1";
/// Fixed encoded size; no unchecked allocation or trailing extension bytes.
pub const ENCODED_SIZE: usize = 64;
const PREFIX: [u8; 8] = [b'B', b'S', b'P', b'4', 1, 0, 0, 0];

/// Invalid or incomplete instance metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMetadata;

fn validate(info: &BackendInfo) -> Result<(), InvalidMetadata> {
    if info.dataset.0 == [0; 16]
        || info.atomic_domain == [0; 16]
        || info.clock_authority == [0; 16]
        || info.physical_version == 0
    {
        return Err(InvalidMetadata);
    }
    Ok(())
}

/// Encode complete instance facts without changing or deriving any identity.
pub fn encode(info: BackendInfo) -> Result<[u8; ENCODED_SIZE], InvalidMetadata> {
    validate(&info)?;
    let mut bytes = [0; ENCODED_SIZE];
    bytes[..8].copy_from_slice(&PREFIX);
    bytes[8..24].copy_from_slice(&info.dataset.0);
    bytes[24..40].copy_from_slice(&info.atomic_domain);
    bytes[40..56].copy_from_slice(&info.clock_authority);
    bytes[56..60].copy_from_slice(&info.physical_version.to_le_bytes());
    bytes[60] = match info.durability {
        Durability::Ephemeral => 0,
        Durability::Local => 1,
        Durability::Quorum => 2,
    };
    Ok(bytes)
}

/// Decode strict metadata; missing, newer, partial and ambiguous formats refuse.
pub fn decode(bytes: &[u8]) -> Result<BackendInfo, InvalidMetadata> {
    let bytes: &[u8; ENCODED_SIZE] = bytes.try_into().map_err(|_| InvalidMetadata)?;
    if bytes[..8] != PREFIX || bytes[61..] != [0; 3] {
        return Err(InvalidMetadata);
    }
    let info = BackendInfo {
        dataset: DatasetId(bytes[8..24].try_into().map_err(|_| InvalidMetadata)?),
        atomic_domain: bytes[24..40].try_into().map_err(|_| InvalidMetadata)?,
        clock_authority: bytes[40..56].try_into().map_err(|_| InvalidMetadata)?,
        physical_version: u32::from_le_bytes(
            bytes[56..60].try_into().map_err(|_| InvalidMetadata)?,
        ),
        durability: match bytes[60] {
            0 => Durability::Ephemeral,
            1 => Durability::Local,
            2 => Durability::Quorum,
            _ => return Err(InvalidMetadata),
        },
    };
    validate(&info)?;
    Ok(info)
}

#[cfg(test)]
#[path = "tests/metadata_tests.rs"]
mod tests;
