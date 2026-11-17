// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Fixed response intent checkpoint codec. Historical facts never confer live release authority.

use busbar_contract::response_delivery::{FinalResponseIntent, ResponseDisposition, ResponseKey};

use crate::AuditKeySet;

/// The independently signed response-control checkpoint domain.
pub const DOMAIN: &str = "response.final-intent.v1";
const PAYLOAD_BYTES: usize = 88;
const KEY_BYTES: usize = 16;
const KEY_AT: usize = 8 + DOMAIN.len() + 8;
const PAYLOAD_AT: usize = KEY_AT + KEY_BYTES + 8;
const SIGNING_BYTES: usize = PAYLOAD_AT + PAYLOAD_BYTES;
const BODY_BYTES: usize = SIGNING_BYTES + 8 + 64;

/// Captured once at final publication from the actual writer and root clock/policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseIntentStamp {
    /// The native Store writer lease epoch authorizing the same journal attachment.
    pub lease_epoch: u64,
    /// The captured policy epoch in force for this final publication.
    pub policy_epoch: u64,
    /// Wall-clock seconds at the frozen final intent.
    pub wall: u64,
    /// The original node's checked monotonic reading.
    pub mono: u64,
}

/// A malformed, mismatched or unauthenticated matching-domain intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentError {
    /// The fixed envelope or fields are not canonical.
    Malformed,
    /// The signed identity/epochs/clocks differ from the containing journal header.
    Header,
    /// The signed exact deployment key is unavailable.
    MissingKey,
    /// The signature does not authenticate this exact envelope under its named key.
    Signature,
}

/// Immutable fixed-domain input accepted by the response-purpose signer alone.
pub struct PreparedResponseIntent {
    bytes: [u8; SIGNING_BYTES],
}

impl PreparedResponseIntent {
    /// Prepare the exact u64-length-prefixed checkpoint body before its signature field.
    pub fn new(
        intent: FinalResponseIntent,
        stamp: ResponseIntentStamp,
        key_id: &str,
    ) -> Result<Self, IntentError> {
        validate(intent)?;
        if key_id.len() != KEY_BYTES
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IntentError::Malformed);
        }
        let mut bytes = [0; SIGNING_BYTES];
        let mut cursor = bytes.as_mut_slice();
        put(&mut cursor, &(DOMAIN.len() as u64).to_le_bytes());
        put(&mut cursor, DOMAIN.as_bytes());
        put(&mut cursor, &(KEY_BYTES as u64).to_le_bytes());
        put(&mut cursor, key_id.as_bytes());
        put(&mut cursor, &(PAYLOAD_BYTES as u64).to_le_bytes());
        put(&mut cursor, &1u16.to_le_bytes());
        let (kind, mut flags, status) = match intent.disposition {
            ResponseDisposition::End { status } => {
                (1, u8::from(status.is_some()), status.unwrap_or(0))
            }
            ResponseDisposition::Refuse { status, head_sent } => {
                (2, 1 | (u8::from(head_sent) << 1), status)
            }
        };
        flags |= u8::from(intent.key.unit.is_some()) << 2;
        put(&mut cursor, &[kind, flags]);
        put(&mut cursor, &status.to_le_bytes());
        put(&mut cursor, &0u16.to_le_bytes());
        for value in [
            intent.key.node,
            intent.key.incarnation,
            intent
                .key
                .unit
                .map_or(0, busbar_contract::ids::UnitKey::get),
            intent.key.connection_generation,
            intent.key.stream,
            intent.final_publication_ordinal,
            stamp.lease_epoch,
            stamp.policy_epoch,
            stamp.wall,
            stamp.mono,
        ] {
            put(&mut cursor, &value.to_le_bytes());
        }
        Ok(Self { bytes })
    }

    /// The exact fixed-domain body signed through the existing checkpoint preimage.
    pub fn signing_body(&self) -> &[u8] {
        &self.bytes
    }

    /// The signed key identifier, validated and captured before submission.
    pub fn key_id(&self) -> &str {
        // The only constructor validates ASCII and fixes this field's length.
        std::str::from_utf8(&self.bytes[KEY_AT..KEY_AT + KEY_BYTES]).unwrap_or("")
    }

    /// Append the one existing raw checkpoint signature using BodyWriter-compatible framing.
    pub fn signed_body(&self, signature: &[u8]) -> Result<Vec<u8>, IntentError> {
        if signature.len() != 64 {
            return Err(IntentError::Signature);
        }
        let mut body = Vec::with_capacity(BODY_BYTES);
        body.extend_from_slice(&self.bytes);
        body.extend_from_slice(&64u64.to_le_bytes());
        body.extend_from_slice(signature);
        Ok(body)
    }
}

fn put(cursor: &mut &mut [u8], value: &[u8]) {
    let (field, rest) = std::mem::take(cursor).split_at_mut(value.len());
    field.copy_from_slice(value);
    *cursor = rest;
}

fn validate(intent: FinalResponseIntent) -> Result<(), IntentError> {
    if intent.final_publication_ordinal == 0
        || intent.key.connection_generation == 0
        || intent.key.stream == 0
        || intent.key.unit.is_some_and(|unit| unit.get() == 0)
    {
        return Err(IntentError::Malformed);
    }
    match intent.disposition {
        ResponseDisposition::End { status: Some(0) } => Err(IntentError::Malformed),
        ResponseDisposition::Refuse { status, .. } if !(400..=599).contains(&status) => {
            Err(IntentError::Malformed)
        }
        _ => Ok(()),
    }
}

/// Whether the first field is this exact domain; this is classification, not verification.
pub fn is_response_intent(body: &[u8]) -> bool {
    body.get(..8) == Some((DOMAIN.len() as u64).to_le_bytes().as_slice())
        && body.get(8..8 + DOMAIN.len()) == Some(DOMAIN.as_bytes())
}

/// Authenticated historical intent facts. No constructor here grants a live release permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedResponseIntent {
    /// The exact authenticated response identity, ordinal and command.
    pub intent: FinalResponseIntent,
    /// The exact authenticated header epochs and clocks.
    pub stamp: ResponseIntentStamp,
}

/// Verify a matching Checkpoint body against its containing header and the exact retained key.
/// An unrelated domain returns `Ok(None)`; damage after a matching domain is always an error.
pub fn verify_response_intent(
    body: &[u8],
    header_node: u64,
    header: ResponseIntentStamp,
    keys: &AuditKeySet,
) -> Result<Option<VerifiedResponseIntent>, IntentError> {
    if !is_response_intent(body) {
        return Ok(None);
    }
    if body.len() != BODY_BYTES
        || body.get(KEY_AT - 8..KEY_AT) != Some((KEY_BYTES as u64).to_le_bytes().as_slice())
        || body.get(PAYLOAD_AT - 8..PAYLOAD_AT)
            != Some((PAYLOAD_BYTES as u64).to_le_bytes().as_slice())
        || body.get(SIGNING_BYTES..SIGNING_BYTES + 8) != Some(64u64.to_le_bytes().as_slice())
    {
        return Err(IntentError::Malformed);
    }
    let key_id = std::str::from_utf8(&body[KEY_AT..KEY_AT + KEY_BYTES])
        .map_err(|_| IntentError::Malformed)?;
    let payload: &[u8; PAYLOAD_BYTES] = body[PAYLOAD_AT..SIGNING_BYTES]
        .try_into()
        .map_err(|_| IntentError::Malformed)?;
    let version = u16::from_le_bytes([payload[0], payload[1]]);
    let kind = payload[2];
    let flags = payload[3];
    let status = u16::from_le_bytes([payload[4], payload[5]]);
    if version != 1
        || flags & !7 != 0
        || payload[6..8] != [0, 0]
        || (flags & 1 == 0) != (status == 0)
    {
        return Err(IntentError::Malformed);
    }
    let number = |offset: usize| -> Result<u64, IntentError> {
        Ok(u64::from_le_bytes(
            payload
                .get(offset..offset + 8)
                .ok_or(IntentError::Malformed)?
                .try_into()
                .map_err(|_| IntentError::Malformed)?,
        ))
    };
    let raw_unit = number(24)?;
    let unit = match (flags & 4 != 0, raw_unit) {
        (false, 0) => None,
        (true, value) if value != 0 => Some(busbar_contract::ids::UnitKey::new(value)),
        _ => return Err(IntentError::Malformed),
    };
    let disposition = match kind {
        1 if flags & 2 == 0 => ResponseDisposition::End {
            status: (flags & 1 != 0).then_some(status),
        },
        2 if flags & 1 != 0 => ResponseDisposition::Refuse {
            status,
            head_sent: flags & 2 != 0,
        },
        _ => return Err(IntentError::Malformed),
    };
    let intent = FinalResponseIntent {
        key: ResponseKey {
            node: number(8)?,
            incarnation: number(16)?,
            unit,
            connection_generation: number(32)?,
            stream: number(40)?,
        },
        final_publication_ordinal: number(48)?,
        disposition,
    };
    let stamp = ResponseIntentStamp {
        lease_epoch: number(56)?,
        policy_epoch: number(64)?,
        wall: number(72)?,
        mono: number(80)?,
    };
    let prepared = PreparedResponseIntent::new(intent, stamp, key_id)?;
    if intent.key.node != header_node || stamp != header {
        return Err(IntentError::Header);
    }
    let key = keys.get(key_id).ok_or(IntentError::MissingKey)?;
    let mut singleton = AuditKeySet::new();
    singleton.insert(key.clone());
    singleton
        .verify_checkpoint_body(prepared.signing_body(), &body[SIGNING_BYTES + 8..])
        .map_err(|_| IntentError::Signature)?;
    Ok(Some(VerifiedResponseIntent { intent, stamp }))
}
