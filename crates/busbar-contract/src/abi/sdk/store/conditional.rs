// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Negotiated, atomic conditional record writes over the existing RECORD_GET carrier.
//!
//! Every predicate observes the pre-mutation snapshot. Duplicate addresses within either list
//! and overlapping mutation selectors are refused; predicates may overlap any mutation. A store checks the applied
//! receipt before the predicates, then commits all mutations and that receipt atomically. A
//! condition conflict changes nothing and records nothing. The existing applied-only, 24-hour
//! dedupe rule applies: after an ambiguous answer replay exactly the same id and body, never
//! infer application from current rows. Only a definitive condition conflict permits replanning.
//! No ordinary record write or replay-token claim implements this operation.

use super::dedupe::{Body, Dedupe};
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::check::HARD_MAX_BYTES;
use crate::abi::mechanism::extensions;
use crate::abi::store::OpId;
use crate::bounded::MAX_RECORD_BYTES;

/// The request and result codec version.
pub const VERSION: u32 = 1;
/// Explicit Statement capability; its value is `b"1"`.
pub const CAPABILITY: &str = "busbar.store.record-transaction/1";
/// RECORD_GET input extension carrying the complete encoded request.
pub const INTENT: &str = "busbar.store.record-transaction";
/// Mandatory leased READY result extension.
pub const RESULT: &str = "busbar.store.record-transaction.result";

/// The exact state a predicate requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// No record at this address.
    Absent,
    /// Exactly these bytes at this address.
    Bytes(Vec<u8>),
}

/// One exact, opaque record comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    /// The record schema.
    pub schema: String,
    /// The opaque key; never interpreted as text.
    pub key: Vec<u8>,
    /// The required pre-mutation value.
    pub expected: Expected,
}

/// One mutation in the atomic batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Store a nonempty record. Empty legacy puts mean deletion, so use `Delete` explicitly.
    Put {
        /// The record schema.
        schema: String,
        /// The opaque key.
        key: Vec<u8>,
        /// The record bytes.
        value: Vec<u8>,
    },
    /// Remove the record, if present.
    Delete {
        /// The record schema.
        schema: String,
        /// The opaque key.
        key: Vec<u8>,
    },
    /// Delete every key with this raw prefix and exact byte length in the named schema.
    DeleteRange {
        /// The record schema.
        schema: String,
        /// The opaque byte prefix.
        prefix: Vec<u8>,
        /// Exact key byte length, checked for the platform and at least the prefix length.
        exact_key_length: u64,
    },
}

impl Mutation {
    /// This mutation's schema and selector bytes: a point key or a range prefix.
    #[must_use]
    pub fn address(&self) -> (&str, &[u8]) {
        match self {
            Self::Put { schema, key, .. } | Self::Delete { schema, key } => (schema, key),
            Self::DeleteRange { schema, prefix, .. } => (schema, prefix),
        }
    }
}

/// One immutable conditional write candidate, including its replay identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Must equal `VERSION`.
    pub version: u32,
    /// Replay with this exact id and body after an unknown commit outcome.
    pub op_id: OpId,
    /// Nonempty, distinct addresses; all comparisons use the pre-mutation snapshot.
    pub predicates: Vec<Predicate>,
    /// Nonempty, disjoint mutation selectors; applied together with the dedupe receipt.
    pub mutations: Vec<Mutation>,
}

/// A definitive transaction decision, distinct from an operation-id body conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// All mutations and their applied receipt committed, or that exact receipt replayed.
    Applied,
    /// A predicate failed; no mutations or receipt were written.
    ConditionConflict,
}

impl Request {
    /// Validate the semantics and existing record-byte bound. No batch-count limit is imposed.
    ///
    /// # Errors
    /// Unknown version, empty lists, duplicate or overlapping selectors, invalid range length,
    /// or an invalid record value.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != VERSION {
            return Err("unsupported record transaction version");
        }
        if self.predicates.is_empty() || self.mutations.is_empty() {
            return Err("record transaction requires predicates and mutations");
        }
        let mut predicates = std::collections::HashSet::new();
        for predicate in &self.predicates {
            if !predicates.insert((predicate.schema.as_str(), predicate.key.as_slice())) {
                return Err("duplicate record transaction predicate address");
            }
            if let Expected::Bytes(bytes) = &predicate.expected {
                if bytes.len() > MAX_RECORD_BYTES {
                    return Err("record transaction predicate exceeds record byte bound");
                }
            }
        }
        let mut points = std::collections::BTreeSet::new();
        let mut ranges = std::collections::BTreeSet::new();
        for mutation in &self.mutations {
            let (schema, selector) = mutation.address();
            match mutation {
                Mutation::Put { .. } | Mutation::Delete { .. } => {
                    if !points.insert((schema, selector.len(), selector)) {
                        return Err("duplicate record transaction mutation address");
                    }
                }
                Mutation::DeleteRange {
                    exact_key_length, ..
                } => {
                    let length = usize::try_from(*exact_key_length)
                        .map_err(|_| "invalid record transaction range length")?;
                    if length < selector.len() {
                        return Err("record transaction range shorter than prefix");
                    }
                    if !ranges.insert((schema, length, selector)) {
                        return Err("overlapping record transaction ranges");
                    }
                }
            }
            if let Mutation::Put { value, .. } = mutation {
                if value.is_empty() || value.len() > MAX_RECORD_BYTES {
                    return Err("record transaction put requires nonempty bounded bytes");
                }
            }
        }
        let mut previous: Option<(&str, usize, &[u8])> = None;
        for &(schema, length, prefix) in &ranges {
            if let Some(&(point_schema, point_length, point_key)) =
                points.range((schema, length, prefix)..).next()
            {
                if point_schema == schema && point_length == length && point_key.starts_with(prefix)
                {
                    return Err("overlapping record transaction point and range");
                }
            }
            if let Some((previous_schema, previous_length, previous_prefix)) = previous {
                if previous_schema == schema
                    && previous_length == length
                    && prefix.starts_with(previous_prefix)
                {
                    return Err("overlapping record transaction ranges");
                }
            }
            previous = Some((schema, length, prefix));
        }
        Ok(())
    }

    /// The first actual predicate address, used as RECORD_GET's harmless legacy read carrier.
    #[must_use]
    pub fn carrier(&self) -> Option<(&str, &[u8])> {
        self.predicates
            .first()
            .map(|p| (p.schema.as_str(), p.key.as_slice()))
    }

    /// Canonical body fingerprint used by the existing applied-only dedupe log.
    #[must_use]
    pub fn fingerprint(&self) -> Body {
        *Dedupe::record_transaction(self).body()
    }

    /// Encode one bounded, versioned request. Lengths and counts are little-endian `u64`.
    ///
    /// # Errors
    /// Invalid semantics or an encoding beyond the existing ABI byte bound.
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let mut writer = Writer(Vec::new());
        writer.push(&self.version.to_le_bytes())?;
        writer.push(&self.op_id.0)?;
        writer.count(self.predicates.len())?;
        for predicate in &self.predicates {
            writer.bytes(predicate.schema.as_bytes())?;
            writer.bytes(&predicate.key)?;
            match &predicate.expected {
                Expected::Absent => writer.push(&[0])?,
                Expected::Bytes(bytes) => {
                    writer.push(&[1])?;
                    writer.bytes(bytes)?;
                }
            }
        }
        writer.count(self.mutations.len())?;
        for mutation in &self.mutations {
            let (schema, key) = mutation.address();
            writer.push(&[match mutation {
                Mutation::Put { .. } => 0,
                Mutation::Delete { .. } => 1,
                Mutation::DeleteRange { .. } => 2,
            }])?;
            writer.bytes(schema.as_bytes())?;
            writer.bytes(key)?;
            if let Mutation::Put { value, .. } = mutation {
                writer.bytes(value)?;
            }
            if let Mutation::DeleteRange {
                exact_key_length, ..
            } = mutation
            {
                writer.push(&exact_key_length.to_le_bytes())?;
            }
        }
        // Include the enclosing keyed entry in the same existing ABI bound.
        if extensions::entry_len(INTENT, &writer.0) as u64 > HARD_MAX_BYTES {
            return Err("record transaction exceeds ABI byte bound");
        }
        Ok(writer.0)
    }

    /// Decode one complete request, refusing unknown versions and trailing or truncated bytes.
    ///
    /// # Errors
    /// Invalid wire bytes or invalid request semantics.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut reader = Reader::new(bytes)?;
        let version = u32::from_le_bytes(reader.take(4)?.try_into().map_err(|_| WIRE)?);
        if version != VERSION {
            return Err("unsupported record transaction version");
        }
        let op_id = OpId(reader.take(16)?.try_into().map_err(|_| WIRE)?);
        let mut predicates = Vec::new();
        let count = reader.count()?;
        for _ in 0..count {
            let schema = reader.text()?;
            let key = reader.bytes()?.to_vec();
            let expected = match reader.byte()? {
                0 => Expected::Absent,
                1 => Expected::Bytes(reader.bytes()?.to_vec()),
                _ => return Err(WIRE),
            };
            predicates.push(Predicate {
                schema,
                key,
                expected,
            });
        }
        let mut mutations = Vec::new();
        let count = reader.count()?;
        for _ in 0..count {
            let tag = reader.byte()?;
            let schema = reader.text()?;
            let key = reader.bytes()?.to_vec();
            mutations.push(match tag {
                0 => Mutation::Put {
                    schema,
                    key,
                    value: reader.bytes()?.to_vec(),
                },
                1 => Mutation::Delete { schema, key },
                2 => Mutation::DeleteRange {
                    schema,
                    prefix: key,
                    exact_key_length: u64::from_le_bytes(
                        reader.take(8)?.try_into().map_err(|_| WIRE)?,
                    ),
                },
                _ => return Err(WIRE),
            });
        }
        reader.finish()?;
        let request = Self {
            version,
            op_id,
            predicates,
            mutations,
        };
        request.validate()?;
        Ok(request)
    }
}

/// An opt-in Statement entry. Set support only on an implementation that serves the primitive.
#[must_use]
pub const fn capability<B: super::StoreSlots>() -> Option<(&'static str, &'static [u8])> {
    if B::RECORD_TRANSACTION {
        Some((CAPABILITY, b"1"))
    } else {
        None
    }
}

/// Whether a Statement advertises this exact supported version. Malformed statements fail closed.
#[must_use]
pub fn supported(statement_extensions: &[u8]) -> bool {
    strict_entry(statement_extensions, CAPABILITY).is_ok_and(|v| v == Some(b"1".as_slice()))
}

/// Decode input intent before an ordinary GET. Malformed recognized intent never falls back.
///
/// # Errors
/// Malformed, duplicate or unsupported transaction intent.
pub fn intent(input_extensions: &[u8]) -> Result<Option<Request>, &'static str> {
    // Preserve the ordinary extensions reader's tolerance when this key is absent. Once the key
    // is recognized, the complete framing is checked before anything can reach the backend.
    let mut reader = Reader::new(input_extensions)?;
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
    strict_entry(input_extensions, INTENT)?
        .map(Request::decode)
        .transpose()
}

/// Encode the correlated result value; the door must place it under an answer lease.
#[must_use]
pub fn encode_result(request: &Request, decision: Decision) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&request.op_id.0);
    bytes.extend_from_slice(&request.fingerprint());
    bytes.push(match decision {
        Decision::Applied => 0,
        Decision::ConditionConflict => 1,
    });
    bytes
}

/// Validate a complete leased READY result against the exact immutable candidate.
///
/// # Errors
/// Every non-READY answer, missing lease/result, malformed result, or correlation mismatch.
/// These errors never prove application; the caller retains the exact id and body for replay.
pub fn read_result(
    outcome: Outcome,
    leased: bool,
    output_extensions: &[u8],
    request: &Request,
) -> Result<Decision, &'static str> {
    if outcome != Outcome::Ready || !leased {
        return Err("record transaction outcome unknown");
    }
    let bytes =
        strict_entry(output_extensions, RESULT)?.ok_or("missing record transaction result")?;
    let mut reader = Reader::new(bytes)?;
    let version = u32::from_le_bytes(reader.take(4)?.try_into().map_err(|_| WIRE)?);
    let op_id = reader.take(16)?;
    let fingerprint = reader.take(32)?;
    let decision = match reader.byte()? {
        0 => Decision::Applied,
        1 => Decision::ConditionConflict,
        _ => return Err(WIRE),
    };
    reader.finish()?;
    if version != VERSION
        || version != request.version
        || op_id != request.op_id.0
        || fingerprint != request.fingerprint()
    {
        return Err("uncorrelated record transaction result");
    }
    Ok(decision)
}

const WIRE: &str = "invalid record transaction wire bytes";

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

struct Writer(Vec<u8>);
impl Writer {
    fn push(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        let len = self.0.len().checked_add(bytes.len()).ok_or(WIRE)?;
        if len as u64 > HARD_MAX_BYTES {
            return Err(WIRE);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn count(&mut self, count: usize) -> Result<(), &'static str> {
        self.push(&u64::try_from(count).map_err(|_| WIRE)?.to_le_bytes())
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        self.count(bytes.len())?;
        self.push(bytes)
    }
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
    fn byte(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }
    fn length(&mut self) -> Result<usize, &'static str> {
        usize::try_from(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| WIRE)?,
        ))
        .map_err(|_| WIRE)
    }
    fn count(&mut self) -> Result<usize, &'static str> {
        let count = self.length()?;
        if count > self.0.len() {
            return Err(WIRE);
        }
        Ok(count)
    }
    fn bytes(&mut self) -> Result<&'a [u8], &'static str> {
        let len = self.length()?;
        self.take(len)
    }
    fn text(&mut self) -> Result<String, &'static str> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_owned)
            .map_err(|_| WIRE)
    }
    fn finish(self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WIRE)
        }
    }
}

#[cfg(test)]
#[path = "../tests/store_conditional_tests.rs"]
mod tests;
