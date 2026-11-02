// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Negotiated raw-usage correction over ADD_USAGE_BATCH without a C layout change.

pub use crate::records::correction::{
    canonical_ledger, canonical_metering, reserved_bucket, Decision, Request, UsageAddress,
    UsageChange, ADJUST_DOWN_BUCKET, ADJUST_UP_BUCKET, CAPABILITY, INTENT, RESULT, SLOT_SEP,
    VERSION,
};

use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::check::HARD_MAX_BYTES;

/// Capability value for the supported codec version.
pub const CAPABILITY_VALUE: &[u8] = b"1";
const APPLIED: u8 = 0;
const CONDITION_CONFLICT: u8 = 1;
const WIRE: &str = "invalid usage correction extension bytes";

/// Explicit opt-in Statement entry. Unsupported stores must omit it.
#[must_use]
pub const fn capability<B: super::StoreSlots>() -> Option<(&'static str, &'static [u8])> {
    if B::USAGE_CORRECTION {
        Some((CAPABILITY, CAPABILITY_VALUE))
    } else {
        None
    }
}

/// Whether a complete Statement advertises the exact supported version once.
#[must_use]
pub fn supported(extensions: &[u8]) -> bool {
    strict_entry(extensions, CAPABILITY).is_ok_and(|v| v == Some(CAPABILITY_VALUE))
}

/// Decode recognized intent before reaching any legacy batch implementation.

pub fn intent(extensions: &[u8]) -> Result<Option<Request>, &'static str> {
    let mut reader = Reader::new(extensions)?;
    let mut recognized = false;
    while !reader.0.is_empty() {
        let entry = (|| {
            let key_len =
                u16::from_le_bytes(reader.take(2)?.try_into().map_err(|_| WIRE)?) as usize;
            let key = reader.take(key_len)?;
            recognized |= key == INTENT.as_bytes();
            let value_len = u32::from_le_bytes(reader.take(4)?.try_into().map_err(|_| WIRE)?);
            reader.take(usize::try_from(value_len).map_err(|_| WIRE)?)?;
            Ok::<_, &'static str>(())
        })();
        if entry.is_err() {
            return if recognized { Err(WIRE) } else { Ok(None) };
        }
    }
    if !recognized {
        return Ok(None);
    }
    strict_entry(extensions, INTENT)?
        .map(Request::decode)
        .transpose()
}

/// Encode a result bound to every predicate, replacement and operation identity.
#[must_use]
pub fn encode_result(request: &Request, decision: Decision) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&request.op_id.0);
    bytes.extend_from_slice(&request.fingerprint());
    bytes.push(match decision {
        Decision::Applied => APPLIED,
        Decision::ConditionConflict => CONDITION_CONFLICT,
    });
    bytes
}

/// Read only a complete leased READY result for this exact immutable candidate.

pub fn read_result(
    outcome: Outcome,
    leased: bool,
    extensions: &[u8],
    request: &Request,
) -> Result<Decision, &'static str> {
    if outcome != Outcome::Ready || !leased {
        return Err("usage correction outcome unknown");
    }
    let bytes = strict_entry(extensions, RESULT)?.ok_or("missing usage correction result")?;
    let mut reader = Reader::new(bytes)?;
    let version = u32::from_le_bytes(reader.take(4)?.try_into().map_err(|_| WIRE)?);
    let op_id = reader.take(16)?;
    let fingerprint = reader.take(32)?;
    let decision = match reader.take(1)?[0] {
        APPLIED => Decision::Applied,
        CONDITION_CONFLICT => Decision::ConditionConflict,
        _ => return Err(WIRE),
    };
    if !reader.0.is_empty() {
        return Err(WIRE);
    }
    if version != VERSION
        || version != request.version
        || op_id != request.op_id.0
        || fingerprint != request.fingerprint()
    {
        return Err("uncorrelated usage correction result");
    }
    Ok(decision)
}

fn strict_entry<'a>(bytes: &'a [u8], wanted: &str) -> Result<Option<&'a [u8]>, &'static str> {
    let mut reader = Reader::new(bytes)?;
    let mut found = None;
    while !reader.0.is_empty() {
        let key_len = u16::from_le_bytes(reader.take(2)?.try_into().map_err(|_| WIRE)?) as usize;
        let key = reader.take(key_len)?;
        let value_len = u32::from_le_bytes(reader.take(4)?.try_into().map_err(|_| WIRE)?);
        let value = reader.take(usize::try_from(value_len).map_err(|_| WIRE)?)?;
        if key == wanted.as_bytes() {
            if found.is_some() {
                return Err(WIRE);
            }
            found = Some(value);
        }
    }
    Ok(found)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() as u64 > HARD_MAX_BYTES {
            return Err(WIRE);
        }
        Ok(Self(bytes))
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let bytes = self.0.get(..len).ok_or(WIRE)?;
        self.0 = &self.0[len..];
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "../tests/store_correction_tests.rs"]
mod tests;
