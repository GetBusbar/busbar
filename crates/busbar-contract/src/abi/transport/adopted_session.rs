// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's inherited session on an Adopt crossing, encoded without pointers.

use crate::abi::host::service::UnitRef;

/// An Adopt input's host-issued session reference, in the shared extensions envelope.
pub const EXT_ADOPTED_SESSION: &str = "session.adopted";

/// A Statement advertises this extension value when its Adopt consumes inherited sessions.
pub const SUPPORT_ADOPTED_SESSION: &[u8] = b"1";

/// The session already admitted by the host. The reference belongs to the adopting owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptedSession {
    /// The external stream identity, retained across the protocol switch. Zero is valid.
    pub stream: u64,
    /// The inherited unit with a fresh destination-owner-bound MAC.
    pub unit: UnitRef,
}

impl AdoptedSession {
    /// Encode the complete value for [`EXT_ADOPTED_SESSION`].
    #[must_use]
    pub fn encode(self) -> [u8; 28] {
        let mut bytes = [0; 28];
        bytes[..4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.stream.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.unit.id.to_le_bytes());
        bytes[20..28].copy_from_slice(&self.unit.mac.to_le_bytes());
        bytes
    }

    /// Decode a complete value, copying everything before the input loan ends.
    ///
    /// # Errors
    /// Unknown versions, an absent unit, truncation or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let bytes: &[u8; 28] = bytes
            .try_into()
            .map_err(|_| "invalid adopted session length")?;
        if bytes[..4] != 1_u32.to_le_bytes() {
            return Err("unknown adopted session version");
        }
        let word = |at| {
            let mut word = [0; 8];
            word.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(word)
        };
        let session = Self {
            stream: word(4),
            unit: UnitRef {
                id: word(12),
                mac: word(20),
            },
        };
        if session.unit.is_none() {
            return Err("an adopted session has no unit");
        }
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_reference_survives_the_extension_loan() {
        let session = AdoptedSession {
            stream: 0,
            unit: UnitRef { id: 7, mac: 93 },
        };
        let blob =
            crate::abi::mechanism::extensions::encode(&[(EXT_ADOPTED_SESSION, &session.encode())]);
        let decoded = AdoptedSession::decode(
            crate::abi::mechanism::extensions::get(&blob, EXT_ADOPTED_SESSION).unwrap(),
        )
        .unwrap();
        drop(blob);
        assert_eq!(decoded, session);
        assert!(AdoptedSession::decode(&session.encode()[..27]).is_err());
        let mut unknown = session.encode();
        unknown[0] = 2;
        assert!(AdoptedSession::decode(&unknown).is_err());
        assert!(AdoptedSession::decode(
            &AdoptedSession {
                unit: UnitRef::NONE,
                ..session
            }
            .encode()
        )
        .is_err());
    }
}
