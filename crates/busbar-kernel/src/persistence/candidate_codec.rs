// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact, guarded recovery custody for immutable persistence candidates.
//!
//! This encoding is not encryption. Its bytes retain `Secret` custody and must use
//! the existing protected recovery storage. Codec and candidate versions are
//! independent: an unsupported version is refused, never translated for replay.

use busbar_contract::persistence::{
    Address, AttemptId, Candidate, DatasetId, ExpectedValue, InvalidCandidate, Mutation,
    NamespaceId, Predicate, PreparedCandidate, TimeGuard, CANDIDATE_VERSION,
};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::redacted::constant_time_eq;
use busbar_contract::Secret;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"BBCAND\0\0";
const VERSION: u32 = 1;

/// Content-free recovery decoding and admission failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodecError {
    Version,
    Malformed,
    Overflow,
    Budget,
    Allocation,
    Invalid(InvalidCandidate),
    Fingerprint,
}

/// Encode after checking the complete wire length and reserving it fallibly.
/// `allocation_budget` covers the new wire payload, excluding the borrowed input.
pub(crate) fn encode<S: KernelSeal + ?Sized>(
    prepared: &PreparedCandidate,
    allocation_budget: usize,
    seal: &S,
) -> Result<Secret<Vec<u8>>, CodecError> {
    let mut size = Output::Count(0);
    write_candidate(&mut size, prepared, seal)?;
    let Output::Count(length) = size else {
        unreachable!()
    };
    if length > allocation_budget {
        return Err(CodecError::Budget);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CodecError::Allocation)?;
    write_candidate(&mut Output::Bytes(&mut bytes), prepared, seal)?;
    debug_assert_eq!(bytes.len(), length);
    Ok(Secret::new(std::mem::take(&mut *bytes)))
}

/// Decode only after a complete allocation-free framing pass and aggregate
/// admission. The budget counts owned keys/values, descriptor vectors, contract
/// validation scratch and the candidate's Arc allocation. The caller-held input,
/// stack values and allocator bookkeeping are excluded. There are no item caps.
pub(crate) fn decode<S: KernelSeal + ?Sized>(
    encoded: &Secret<Vec<u8>>,
    allocation_budget: usize,
    seal: &S,
) -> Result<PreparedCandidate, CodecError> {
    let bytes = encoded.expose(seal);
    let layout = preflight(bytes)?;
    if layout.owned_bytes()? > allocation_budget {
        return Err(CodecError::Budget);
    }
    let mut reader = Reader { bytes, offset: 0 };
    let header = reader.header()?;
    let mut candidate = Candidate {
        id: header.id,
        codec: header.codec,
        time: header.time,
        predicates: Vec::new(),
        mutations: Vec::new(),
        result: Secret::default(),
    };
    candidate
        .predicates
        .try_reserve_exact(layout.predicates)
        .map_err(|_| CodecError::Allocation)?;
    candidate
        .mutations
        .try_reserve_exact(layout.mutations)
        .map_err(|_| CodecError::Allocation)?;
    for _ in 0..reader.count()? {
        let (namespace, key, expected) = reader.predicate()?;
        // Allocate the protected value before transferring an unprotected key.
        let expected = match expected {
            None => ExpectedValue::Absent,
            Some(value) => ExpectedValue::Exact(Secret::new(copy(value)?)),
        };
        candidate.predicates.push(Predicate {
            address: Address {
                namespace,
                key: copy(key)?,
            },
            expected,
        });
    }
    for _ in 0..reader.count()? {
        let mutation = match reader.mutation()? {
            BorrowedMutation::Put(namespace, key, value) => {
                let value = Secret::new(copy(value)?);
                Mutation::Put {
                    address: Address {
                        namespace,
                        key: copy(key)?,
                    },
                    value,
                }
            }
            BorrowedMutation::Delete(namespace, key) => Mutation::Delete(Address {
                namespace,
                key: copy(key)?,
            }),
            BorrowedMutation::Range(namespace, prefix, exact_key_length) => Mutation::DeleteRange {
                namespace: NamespaceId(namespace),
                prefix: copy(prefix)?,
                exact_key_length,
            },
        };
        candidate.mutations.push(mutation);
    }
    candidate.result = Secret::new(copy(reader.payload()?)?);
    reader.finish()?;
    // Secret values already own wiping on every error. Keys are opaque identifiers,
    // not credential bytes; use the canonical candidate's single validation pass.
    let prepared = PreparedCandidate::new(candidate).map_err(CodecError::Invalid)?;
    if !constant_time_eq(&prepared.fingerprint(), &header.fingerprint) {
        return Err(CodecError::Fingerprint);
    }
    Ok(prepared)
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut result = Zeroizing::new(Vec::new());
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| CodecError::Allocation)?;
    result.extend_from_slice(bytes);
    Ok(std::mem::take(&mut *result))
}

enum Output<'a> {
    Count(usize),
    Bytes(&'a mut Vec<u8>),
}
impl Output<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        match self {
            Self::Count(count) => {
                *count = count.checked_add(bytes.len()).ok_or(CodecError::Overflow)?
            }
            Self::Bytes(output) => output.extend_from_slice(bytes),
        }
        Ok(())
    }
    fn count(&mut self, count: usize) -> Result<(), CodecError> {
        self.put(
            &u64::try_from(count)
                .map_err(|_| CodecError::Overflow)?
                .to_le_bytes(),
        )
    }
    fn payload(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.count(bytes.len())?;
        self.put(bytes)
    }
    fn address(&mut self, address: &Address) -> Result<(), CodecError> {
        self.put(&address.namespace)?;
        self.payload(&address.key)
    }
    fn optional(&mut self, time: Option<u64>) -> Result<(), CodecError> {
        self.put(&[u8::from(time.is_some())])?;
        if let Some(time) = time {
            self.put(&time.to_le_bytes())?;
        }
        Ok(())
    }
}

fn write_candidate<S: KernelSeal + ?Sized>(
    out: &mut Output<'_>,
    prepared: &PreparedCandidate,
    seal: &S,
) -> Result<(), CodecError> {
    let candidate = prepared.candidate();
    if candidate.codec != CANDIDATE_VERSION {
        return Err(CodecError::Version);
    }
    out.put(MAGIC)?;
    out.put(&VERSION.to_le_bytes())?;
    out.put(&prepared.fingerprint())?;
    out.put(&candidate.codec.to_le_bytes())?;
    out.put(&candidate.id.dataset.0)?;
    out.put(&candidate.id.writer_epoch.to_le_bytes())?;
    out.put(&candidate.id.writer)?;
    out.put(&candidate.id.execution_epoch.to_le_bytes())?;
    out.put(&candidate.id.operation)?;
    out.put(&[u8::from(candidate.time.is_some())])?;
    if let Some(time) = candidate.time {
        out.optional(time.not_before)?;
        out.optional(time.before)?;
    }
    out.count(candidate.predicates.len())?;
    for predicate in &candidate.predicates {
        out.address(&predicate.address)?;
        match &predicate.expected {
            ExpectedValue::Absent => out.put(&[0])?,
            ExpectedValue::Exact(value) => {
                out.put(&[1])?;
                out.payload(value.expose(seal))?;
            }
        }
    }
    out.count(candidate.mutations.len())?;
    for mutation in &candidate.mutations {
        match mutation {
            Mutation::Put { address, value } => {
                out.put(&[0])?;
                out.address(address)?;
                out.payload(value.expose(seal))?;
            }
            Mutation::Delete(address) => {
                out.put(&[1])?;
                out.address(address)?;
            }
            Mutation::DeleteRange {
                namespace,
                prefix,
                exact_key_length,
            } => {
                out.put(&[2])?;
                out.put(&namespace.0)?;
                out.payload(prefix)?;
                out.put(&exact_key_length.to_le_bytes())?;
            }
        }
    }
    out.payload(candidate.result.expose(seal))
}

struct Header {
    fingerprint: [u8; 32],
    codec: u32,
    id: AttemptId,
    time: Option<TimeGuard>,
}
struct Layout {
    predicates: usize,
    mutations: usize,
    payload: usize,
}
impl Layout {
    fn add(&mut self, bytes: usize) -> Result<(), CodecError> {
        self.payload = self
            .payload
            .checked_add(bytes)
            .ok_or(CodecError::Overflow)?;
        Ok(())
    }
    fn owned_bytes(&self) -> Result<usize, CodecError> {
        let descriptors = self
            .predicates
            .checked_mul(std::mem::size_of::<Predicate>())
            .and_then(|n| {
                self.mutations
                    .checked_mul(std::mem::size_of::<Mutation>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(CodecError::Overflow)?;
        let validation =
            Candidate::<busbar_contract::redacted::Kernel>::validation_workspace_bytes(
                self.predicates,
                self.mutations,
            )
            .ok_or(CodecError::Overflow)?;
        self.payload
            .checked_add(descriptors)
            .and_then(|n| n.checked_add(validation))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Candidate>() + 2 * std::mem::size_of::<usize>())
            })
            .ok_or(CodecError::Overflow)
    }
}

fn preflight(bytes: &[u8]) -> Result<Layout, CodecError> {
    let mut reader = Reader { bytes, offset: 0 };
    let header = reader.header()?;
    let tail_start = reader.offset;
    let mut layout = Layout {
        predicates: reader.count()?,
        mutations: 0,
        payload: 0,
    };
    // Each predicate needs at least namespace + counted key + one flag.
    if layout.predicates > reader.remaining() / 25 {
        return Err(CodecError::Malformed);
    }
    for _ in 0..layout.predicates {
        let (_, key, value) = reader.predicate()?;
        layout.add(key.len())?;
        if let Some(value) = value {
            layout.add(value.len())?;
        }
    }
    layout.mutations = reader.count()?;
    if layout.mutations > reader.remaining() / 25 {
        return Err(CodecError::Malformed);
    }
    for _ in 0..layout.mutations {
        match reader.mutation()? {
            BorrowedMutation::Put(_, key, value) => {
                layout.add(key.len())?;
                layout.add(value.len())?;
            }
            BorrowedMutation::Delete(_, key) | BorrowedMutation::Range(_, key, _) => {
                layout.add(key.len())?
            }
        }
    }
    layout.add(reader.payload()?.len())?;
    reader.finish()?;
    if !constant_time_eq(
        &semantic_fingerprint(&header, &bytes[tail_start..]),
        &header.fingerprint,
    ) {
        return Err(CodecError::Fingerprint);
    }
    Ok(layout)
}

// Tail fields use the contract's exact semantic framing. The outer time-presence
// bit is preserved on disk but omitted from the semantic digest, matching the
// contract's normalization of None and Some(unbounded). This definition is pinned
// to CANDIDATE_VERSION=1; unsupported versions cannot reach it.
fn semantic_fingerprint(header: &Header, tail: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"busbar.persistence.candidate/1\0");
    hash.update(header.codec.to_le_bytes());
    hash.update(header.id.dataset.0);
    hash.update(header.id.writer_epoch.to_le_bytes());
    hash.update(header.id.writer);
    hash.update(header.id.execution_epoch.to_le_bytes());
    hash.update(header.id.operation);
    let time = header.time.unwrap_or(TimeGuard {
        not_before: None,
        before: None,
    });
    for bound in [time.not_before, time.before] {
        hash.update([u8::from(bound.is_some())]);
        if let Some(bound) = bound {
            hash.update(bound.to_le_bytes());
        }
    }
    hash.update(tail);
    hash.finalize().into()
}

enum BorrowedMutation<'a> {
    Put([u8; 16], &'a [u8], &'a [u8]),
    Delete([u8; 16], &'a [u8]),
    Range([u8; 16], &'a [u8], u64),
}
type BorrowedPredicate<'a> = ([u8; 16], &'a [u8], Option<&'a [u8]>);

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CodecError::Overflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::Malformed)?;
        self.offset = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Malformed)
    }
    fn byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.array::<1>()?[0])
    }
    fn flag(&mut self) -> Result<bool, CodecError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::Malformed),
        }
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self) -> Result<usize, CodecError> {
        usize::try_from(self.u64()?).map_err(|_| CodecError::Overflow)
    }
    fn payload(&mut self) -> Result<&'a [u8], CodecError> {
        let length = self.count()?;
        self.take(length)
    }
    fn optional(&mut self) -> Result<Option<u64>, CodecError> {
        if self.flag()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }
    fn header(&mut self) -> Result<Header, CodecError> {
        if self.take(MAGIC.len())? != MAGIC {
            return Err(CodecError::Malformed);
        }
        if self.u32()? != VERSION {
            return Err(CodecError::Version);
        }
        let fingerprint = self.array()?;
        let codec = self.u32()?;
        if codec != CANDIDATE_VERSION {
            return Err(CodecError::Version);
        }
        let id = AttemptId {
            dataset: DatasetId(self.array()?),
            writer_epoch: self.u64()?,
            writer: self.array()?,
            execution_epoch: self.u64()?,
            operation: self.array()?,
        };
        let time = if self.flag()? {
            Some(TimeGuard {
                not_before: self.optional()?,
                before: self.optional()?,
            })
        } else {
            None
        };
        Ok(Header {
            fingerprint,
            codec,
            id,
            time,
        })
    }
    fn predicate(&mut self) -> Result<BorrowedPredicate<'a>, CodecError> {
        let namespace = self.array()?;
        let key = self.payload()?;
        let value = if self.flag()? {
            Some(self.payload()?)
        } else {
            None
        };
        Ok((namespace, key, value))
    }
    fn mutation(&mut self) -> Result<BorrowedMutation<'a>, CodecError> {
        let kind = self.byte()?;
        let namespace = self.array()?;
        let key = self.payload()?;
        match kind {
            0 => Ok(BorrowedMutation::Put(namespace, key, self.payload()?)),
            1 => Ok(BorrowedMutation::Delete(namespace, key)),
            2 => Ok(BorrowedMutation::Range(namespace, key, self.u64()?)),
            _ => Err(CodecError::Malformed),
        }
    }
    fn finish(self) -> Result<(), CodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::Malformed)
        }
    }
}

#[cfg(test)]
#[path = "candidate_codec_tests.rs"]
mod tests;
