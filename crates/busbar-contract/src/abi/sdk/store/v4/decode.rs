// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Borrowed v4 inputs copied into bounded, owned persistence requests.

use core::mem::{align_of, size_of};

use crate::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_OCTETS, BLOB_SECRET};
use crate::abi::store::v4 as wire;
use crate::persistence as owned;
use crate::redacted::{OwnerSeal, Secret};

/// Structural input refusal; diagnostics never contain keys or values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A pointer/count pair is null, misaligned, or arithmetically impossible.
    Span,
    /// The aggregate owned allocation exceeds the caller's budget.
    Budget,
    /// A fallible allocation failed.
    Allocation,
    /// A reserved field or unknown flag is present.
    Flags,
    /// A value has an unsupported format or an inconsistent absence encoding.
    Blob,
    /// A predicate or mutation tag is unknown or has inconsistent fields.
    Tag,
    /// An identity is unregistered (zero).
    Identity,
    /// A temporal guard is malformed or empty.
    Time,
    /// A scan continuation lacks its generation or has inconsistent fields.
    Scan,
    /// The candidate failed neutral structural validation.
    Candidate(owned::InvalidCandidate),
}

struct Budget(usize);

impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<(), DecodeError> {
        self.0 = self.0.checked_sub(bytes).ok_or(DecodeError::Budget)?;
        Ok(())
    }

    fn descriptors<T>(&mut self, count: usize) -> Result<(), DecodeError> {
        let bytes = count.checked_mul(size_of::<T>()).ok_or(DecodeError::Span)?;
        if bytes > isize::MAX as usize {
            return Err(DecodeError::Span);
        }
        self.charge(bytes)
    }

    fn bytes(&mut self, bytes: wire::Bytes) -> Result<(), DecodeError> {
        span(bytes.ptr, bytes.len)?;
        self.charge(bytes.len)
    }
}

fn span<T>(ptr: *const T, count: usize) -> Result<(), DecodeError> {
    let bytes = count.checked_mul(size_of::<T>()).ok_or(DecodeError::Span)?;
    if bytes > isize::MAX as usize
        || (ptr.is_null() && count != 0)
        || (!ptr.is_null() && !(ptr as usize).is_multiple_of(align_of::<T>()))
        || (ptr as usize).checked_add(bytes).is_none()
    {
        return Err(DecodeError::Span);
    }
    Ok(())
}

// The public caller guarantees provenance, liveness and immutability. Arithmetic
// and budget admission must already have succeeded before this helper is called.
unsafe fn slice<'a, T>(ptr: *const T, count: usize) -> &'a [T] {
    if count == 0 {
        &[]
    } else {
        // SAFETY: guaranteed by the caller and the span preflight.
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }
}

fn reserve<T>(count: usize) -> Result<Vec<T>, DecodeError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| DecodeError::Allocation)?;
    Ok(result)
}

unsafe fn copy(bytes: wire::Bytes) -> Result<Vec<u8>, DecodeError> {
    let mut result = reserve(bytes.len)?;
    // SAFETY: all spans and the full aggregate budget passed preflight.
    result.extend_from_slice(unsafe { slice(bytes.ptr, bytes.len) });
    Ok(result)
}

unsafe fn secret<O>(
    blob: Blob,
    wrap: impl Fn(Vec<u8>) -> Secret<Vec<u8>, O>,
) -> Result<Secret<Vec<u8>, O>, DecodeError> {
    // Establish wiping custody before any sensitive bytes are copied.
    let mut result = wrap(reserve(blob.len)?);
    // SAFETY: all spans and the full aggregate budget passed preflight.
    result
        .0
        .extend_from_slice(unsafe { slice(blob.ptr, blob.len) });
    #[cfg(test)]
    crate::abi::sdk::secret_bytes::watch(&result.0);
    Ok(result)
}

fn blob(blob: Blob, absent: bool, budget: &mut Budget) -> Result<(), DecodeError> {
    if blob.flags & !BLOB_SECRET != 0 {
        return Err(DecodeError::Flags);
    }
    if absent {
        if blob.len != 0
            || !matches!(blob.fmt, BLOB_ABSENT | BLOB_OCTETS)
            || (blob.fmt == BLOB_ABSENT && (!blob.ptr.is_null() || blob.flags != 0))
        {
            return Err(DecodeError::Blob);
        }
    } else if blob.fmt != BLOB_OCTETS || u32::try_from(blob.len).is_err() {
        return Err(DecodeError::Blob);
    }
    budget.bytes(wire::Bytes {
        ptr: blob.ptr,
        len: blob.len,
    })
}

pub(super) fn time(raw: wire::TimeGuard) -> Result<Option<owned::TimeGuard>, DecodeError> {
    if raw._reserved != 0 || raw.flags & !(wire::TIME_NOT_BEFORE | wire::TIME_BEFORE) != 0 {
        return Err(DecodeError::Flags);
    }
    if (raw.flags & wire::TIME_NOT_BEFORE == 0 && raw.not_before != 0)
        || (raw.flags & wire::TIME_BEFORE == 0 && raw.before != 0)
    {
        return Err(DecodeError::Time);
    }
    let lower = (raw.flags & wire::TIME_NOT_BEFORE != 0).then_some(raw.not_before);
    let upper = (raw.flags & wire::TIME_BEFORE != 0).then_some(raw.before);
    if matches!((lower, upper), (Some(a), Some(b)) if a >= b) {
        return Err(DecodeError::Time);
    }
    Ok((raw.flags != 0).then_some(owned::TimeGuard {
        not_before: lower,
        before: upper,
    }))
}

fn identity(id: [u8; 16]) -> Result<(), DecodeError> {
    if id == [0; 16] {
        Err(DecodeError::Identity)
    } else {
        Ok(())
    }
}

unsafe fn address(raw: wire::Address) -> Result<owned::Address, DecodeError> {
    Ok(owned::Address {
        namespace: raw.namespace,
        // SAFETY: address key passed aggregate preflight.
        key: unsafe { copy(raw.key)? },
    })
}

/// Copy and seal an immutable commit candidate within an aggregate allocation budget.
///
/// # Safety
/// Every nonempty span, including nested spans, must name a live allocation of
/// its stated length containing initialized values of the declared type. All
/// input storage must remain immutable for this call. Arithmetic checks cannot
/// establish allocation ownership, provenance or liveness. Empty spans may be NULL.
pub unsafe fn candidate(
    raw: &wire::Candidate,
    budget: usize,
) -> Result<owned::PreparedCandidate, DecodeError> {
    // SAFETY: caller guarantees all nested input lifetimes and provenance.
    unsafe { candidate_with(raw, budget, Secret::new) }
}

/// Decode a backend's input into its own sealed, wiping custody.
///
/// This grants no access to kernel-held values: it copies only the Store request
/// bytes already lent to this adapter. Core owns the meaning of those bytes.
///
/// # Safety
/// The same live-allocation and immutable-span requirements as [`candidate`] apply.
pub unsafe fn candidate_owned<O: OwnerSeal>(
    raw: &wire::Candidate,
    budget: usize,
    _owner: &O,
) -> Result<owned::PreparedCandidate<O>, DecodeError> {
    // SAFETY: caller guarantees all nested input lifetimes and provenance.
    unsafe { candidate_with(raw, budget, Secret::held) }
}

unsafe fn candidate_with<O>(
    raw: &wire::Candidate,
    budget: usize,
    wrap: impl Fn(Vec<u8>) -> Secret<Vec<u8>, O>,
) -> Result<owned::PreparedCandidate<O>, DecodeError> {
    if raw._reserved != 0 {
        return Err(DecodeError::Flags);
    }
    identity(raw.id.dataset)?;
    identity(raw.id.writer)?;
    identity(raw.id.operation)?;
    if raw.id.writer_epoch == 0 || raw.id.execution_epoch == 0 {
        return Err(DecodeError::Identity);
    }
    if raw.codec != owned::CANDIDATE_VERSION {
        return Err(DecodeError::Candidate(owned::InvalidCandidate::Version));
    }
    let time = time(raw.time)?;
    span(raw.predicates, raw.predicates_len)?;
    span(raw.mutations, raw.mutations_len)?;
    let mut budget = Budget(budget);
    budget.descriptors::<owned::Predicate<O>>(raw.predicates_len)?;
    budget.descriptors::<owned::Mutation<O>>(raw.mutations_len)?;
    budget.charge(
        owned::Candidate::<O>::validation_workspace_bytes(raw.predicates_len, raw.mutations_len)
            .ok_or(DecodeError::Span)?,
    )?;
    // SAFETY: caller owns live descriptor spans; sizes and budget checked above.
    let predicates = unsafe { slice(raw.predicates, raw.predicates_len) };
    // SAFETY: same contract as predicates.
    let mutations = unsafe { slice(raw.mutations, raw.mutations_len) };
    for item in predicates {
        if item._reserved != 0 {
            return Err(DecodeError::Flags);
        }
        budget.bytes(item.address.key)?;
        match item.tag {
            wire::PREDICATE_ABSENT => blob(item.expected, true, &mut budget)?,
            wire::PREDICATE_EXACT => blob(item.expected, false, &mut budget)?,
            _ => return Err(DecodeError::Tag),
        }
    }
    for item in mutations {
        if item._reserved != 0 {
            return Err(DecodeError::Flags);
        }
        budget.bytes(item.address.key)?;
        match item.tag {
            wire::MUTATION_PUT | wire::MUTATION_DELETE => {
                if item.exact_length != 0 {
                    return Err(DecodeError::Tag);
                }
                blob(item.value, item.tag == wire::MUTATION_DELETE, &mut budget)?;
            }
            wire::MUTATION_DELETE_RANGE => {
                let length = usize::try_from(item.exact_length).map_err(|_| DecodeError::Span)?;
                if length < item.address.key.len {
                    return Err(DecodeError::Candidate(owned::InvalidCandidate::RangeLength));
                }
                blob(item.value, true, &mut budget)?;
            }
            _ => return Err(DecodeError::Tag),
        }
    }
    blob(raw.result, false, &mut budget)?;
    let mut copied_predicates = reserve(predicates.len())?;
    let mut copied_mutations = reserve(mutations.len())?;
    for item in predicates {
        copied_predicates.push(owned::Predicate {
            // SAFETY: complete preflight above and caller's live allocation contract.
            address: unsafe { address(item.address)? },
            expected: if item.tag == wire::PREDICATE_ABSENT {
                owned::ExpectedValue::Absent
            } else {
                // SAFETY: expected octets passed preflight.
                owned::ExpectedValue::Exact(unsafe { secret(item.expected, &wrap)? })
            },
        });
    }
    for item in mutations {
        // SAFETY: complete preflight above and caller's live allocation contract.
        let address = unsafe { address(item.address)? };
        copied_mutations.push(match item.tag {
            wire::MUTATION_PUT => owned::Mutation::Put {
                address,
                // SAFETY: value passed preflight; custody is wiping from first copy.
                value: unsafe { secret(item.value, &wrap)? },
            },
            wire::MUTATION_DELETE => owned::Mutation::Delete(address),
            wire::MUTATION_DELETE_RANGE => owned::Mutation::DeleteRange {
                namespace: owned::NamespaceId(address.namespace),
                prefix: address.key,
                exact_key_length: item.exact_length,
            },
            _ => unreachable!("preflight checked mutation tag"),
        });
    }
    owned::PreparedCandidate::new(owned::Candidate {
        id: owned::AttemptId {
            dataset: owned::DatasetId(raw.id.dataset),
            writer_epoch: raw.id.writer_epoch,
            writer: raw.id.writer,
            execution_epoch: raw.id.execution_epoch,
            operation: raw.id.operation,
        },
        codec: raw.codec,
        predicates: copied_predicates,
        mutations: copied_mutations,
        time,
        // SAFETY: result octets passed preflight.
        result: unsafe { secret(raw.result, &wrap)? },
    })
    .map_err(DecodeError::Candidate)
}

/// Copy coherent-read addresses within an aggregate allocation budget.
///
/// # Safety
/// All nonempty input spans must refer to live, initialized allocations of their
/// stated lengths, immutable throughout this call, including every nested key.
/// Arithmetic validation does not prove pointer ownership or liveness.
/// Output-buffer fields and the mechanism call head are handled by the call driver.
pub unsafe fn read(raw: &wire::ReadIn, budget: usize) -> Result<owned::Read, DecodeError> {
    identity(raw.dataset)?;
    let time = time(raw.time)?;
    span(raw.addresses, raw.addresses_len)?;
    let mut budget = Budget(budget);
    budget.descriptors::<owned::Address>(raw.addresses_len)?;
    // SAFETY: caller guarantees a live descriptor array; checked arithmetic above.
    let addresses = unsafe { slice(raw.addresses, raw.addresses_len) };
    for item in addresses {
        budget.bytes(item.key)?;
    }
    let mut result = reserve(addresses.len())?;
    for item in addresses {
        // SAFETY: all keys passed aggregate preflight.
        result.push(unsafe { address(*item)? });
    }
    Ok(owned::Read {
        dataset: owned::DatasetId(raw.dataset),
        addresses: result,
        time,
    })
}

/// Copy a generation-checked scan within an aggregate allocation budget.
///
/// # Safety
/// Nonempty prefix/cursor spans must refer to initialized live allocations of
/// their stated lengths, immutable throughout this call. Arithmetic checks do
/// not prove ownership or liveness. The driver handles the head/output buffers.
pub unsafe fn scan(raw: &wire::ScanIn, budget: usize) -> Result<owned::Scan, DecodeError> {
    identity(raw.dataset)?;
    if raw._reserved != 0
        || raw.flags & !(wire::SCAN_AFTER | wire::SCAN_GENERATION | wire::SCAN_ALLOW_CHANGE) != 0
    {
        return Err(DecodeError::Flags);
    }
    let allow_change = raw.flags & wire::SCAN_ALLOW_CHANGE != 0;
    let after = raw.flags & wire::SCAN_AFTER != 0;
    let generation = raw.flags & wire::SCAN_GENERATION != 0;
    if (after && !generation && !allow_change)
        || (allow_change && generation)
        || (!after && raw.after.len != 0)
        || (!generation && raw.generation != 0)
    {
        return Err(DecodeError::Scan);
    }
    let max_items = usize::try_from(raw.max_items).map_err(|_| DecodeError::Span)?;
    let max_bytes = usize::try_from(raw.max_bytes).map_err(|_| DecodeError::Span)?;
    if max_items == 0 || max_bytes == 0 {
        return Err(DecodeError::Scan);
    }
    let mut budget = Budget(budget);
    budget.bytes(raw.prefix)?;
    budget.bytes(raw.after)?;
    Ok(owned::Scan {
        dataset: owned::DatasetId(raw.dataset),
        namespace: owned::NamespaceId(raw.namespace),
        // SAFETY: spans and full aggregate budget passed preflight.
        prefix: unsafe { copy(raw.prefix)? },
        // SAFETY: spans and full aggregate budget passed preflight.
        after: if after {
            Some(unsafe { copy(raw.after)? })
        } else {
            None
        },
        generation: generation.then_some(raw.generation),
        allow_change,
        max_items,
        max_bytes,
    })
}

#[cfg(test)]
#[path = "tests/decode_tests.rs"]
mod tests;
