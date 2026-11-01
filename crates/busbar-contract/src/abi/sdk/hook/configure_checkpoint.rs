// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plugin-owned complete configuration, carried by the existing configure reply extension.
//! The host stores opaque bytes, never merges settings, and retains one checkpoint per instance.

use zeroize::Zeroizing;

use crate::abi::mechanism::{check::HARD_MAX_BYTES, extensions};

/// The existing extension entry carrying one complete configuration after an acknowledged push.
pub const KEY: &str = "hook.configure_checkpoint.v1";
/// The existing mechanism bound applies to the entire extended reply, not a history of pushes.
pub const MAX_BYTES: usize = HARD_MAX_BYTES as usize;
const HEADER: usize = 16;

/// A normalized complete settings object accepted by this hook's `configure` method on a fresh
/// instance. Construct it before committing a configuration; return it while still holding the
/// same plugin configuration lock. Never expose these secret bytes through status or diagnostics.
pub struct ConfigureCheckpoint {
    /// Strictly increasing successful configuration sequence within one physical instance.
    /// A stale version returns the current sequence and settings without changing either.
    pub revision: u64,
    /// The version of the effective settings, which can exceed a stale push's acknowledged version.
    pub settings_version: u64,
    settings: Zeroizing<Vec<u8>>,
}

impl ConfigureCheckpoint {
    /// Own a complete, normalized JSON settings object. Its semantics belong to the plugin; the
    /// SDK and host do not interpret keys. The plugin must construct this before mutating state.
    pub fn new(revision: u64, settings_version: u64, settings: Vec<u8>) -> Result<Self, String> {
        let settings = Zeroizing::new(settings);
        if revision == 0
            || settings.is_empty()
            || settings.len() > MAX_BYTES.saturating_sub(extensions::entry_len(KEY, &[]) + HEADER)
        {
            return Err("invalid complete hook configuration checkpoint".into());
        }
        Ok(Self {
            revision,
            settings_version,
            settings,
        })
    }

    /// The complete effective settings, borrowed from their wiping owner.
    #[must_use]
    pub fn settings(&self) -> &[u8] {
        &self.settings
    }

    /// Encode the one extension entry. The returned bytes must remain in wiping custody.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let length = HEADER + self.settings.len();
        let mut bytes =
            Zeroizing::new(Vec::with_capacity(extensions::entry_len(KEY, &[]) + length));
        bytes.extend_from_slice(&(KEY.len() as u16).to_le_bytes());
        bytes.extend_from_slice(KEY.as_bytes());
        bytes.extend_from_slice(&(length as u32).to_le_bytes());
        bytes.extend_from_slice(&self.revision.to_le_bytes());
        bytes.extend_from_slice(&self.settings_version.to_le_bytes());
        bytes.extend_from_slice(&self.settings);
        bytes
    }

    /// Copy one checkpoint out of a still-leased extensions blob. Unknown entries are ignored;
    /// malformed or duplicate checkpoint entries are refused, never mistaken for old-plugin absence.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, &'static str> {
        const INVALID: &str = "invalid hook configuration checkpoint reply";
        if bytes.len() > MAX_BYTES {
            return Err(INVALID);
        }
        let mut rest = bytes;
        let mut found = None;
        while !rest.is_empty() {
            let key_len = usize::from(u16::from_le_bytes(
                rest.get(..2)
                    .ok_or(INVALID)?
                    .try_into()
                    .map_err(|_| INVALID)?,
            ));
            rest = &rest[2..];
            let key = rest.get(..key_len).ok_or(INVALID)?;
            rest = &rest[key_len..];
            let len = usize::try_from(u32::from_le_bytes(
                rest.get(..4)
                    .ok_or(INVALID)?
                    .try_into()
                    .map_err(|_| INVALID)?,
            ))
            .map_err(|_| INVALID)?;
            rest = &rest[4..];
            let value = rest.get(..len).ok_or(INVALID)?;
            rest = &rest[len..];
            if key == KEY.as_bytes() {
                if found.is_some() || value.len() <= HEADER {
                    return Err(INVALID);
                }
                let revision = u64::from_le_bytes(value[..8].try_into().map_err(|_| INVALID)?);
                let version = u64::from_le_bytes(value[8..HEADER].try_into().map_err(|_| INVALID)?);
                found = Some(
                    Self::new(revision, version, value[HEADER..].to_vec()).map_err(|_| INVALID)?,
                );
            }
        }
        Ok(found)
    }
}

impl std::fmt::Debug for ConfigureCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigureCheckpoint")
            .field("revision", &self.revision)
            .field("settings_version", &self.settings_version)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_bytes_are_bounded_redacted_and_strictly_framed() {
        let checkpoint = ConfigureCheckpoint::new(
            3,
            7,
            br#"{"url":"https://secret@example.invalid"}"#.to_vec(),
        )
        .unwrap();
        let bytes = checkpoint.encode();
        let restored = ConfigureCheckpoint::decode(&bytes).unwrap().unwrap();
        assert_eq!((restored.revision, restored.settings_version), (3, 7));
        assert_eq!(restored.settings(), checkpoint.settings());
        assert!(!format!("{restored:?}").contains("secret"));
        assert!(ConfigureCheckpoint::new(0, 7, b"{}".to_vec()).is_err());
        assert!(ConfigureCheckpoint::new(1, 7, vec![b'x'; MAX_BYTES]).is_err());
        assert!(ConfigureCheckpoint::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut duplicate = bytes.to_vec();
        duplicate.extend_from_slice(&bytes);
        assert!(ConfigureCheckpoint::decode(&duplicate).is_err());
        let unknown = extensions::encode(&[("other.feature", b"opaque")]);
        assert!(ConfigureCheckpoint::decode(&unknown).unwrap().is_none());
        let mut combined = unknown;
        combined.extend_from_slice(&bytes);
        assert_eq!(
            ConfigureCheckpoint::decode(&combined)
                .unwrap()
                .unwrap()
                .settings(),
            checkpoint.settings()
        );
    }
}
