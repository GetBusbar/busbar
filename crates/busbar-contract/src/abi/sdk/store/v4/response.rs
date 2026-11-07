// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Safe decoding from retained, initialized host output allocations.
//!
//! Returned pointers are numeric offsets only; native memory is never dereferenced.
//! Callers retain the original input and host allocations through decoding.

use crate::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_OCTETS, BLOB_SECRET};
use crate::abi::mechanism::check::Fault;
use crate::abi::store::{v4 as wire, HostBuf};
use crate::persistence as owned;
use crate::redacted::Secret;

/// A failed response. For commits, every malformed response must be treated as
/// unknown execution, retaining the exact original candidate and identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// The primitive's fixed envelope is inconsistent.
    Envelope(Fault),
    /// A pointer, descriptor, or semantic invariant is inconsistent.
    Malformed,
    /// The host must retry the same request with these full capacities.
    Short {
        needed_items: u64,
        needed_bytes: u64,
    },
    /// An explicit transport/admission failure, never an empty observation.
    Failure(owned::Failure),
    /// The owned response exceeds the caller's aggregate allocation budget.
    Budget,
    /// A fallible allocation failed.
    Allocation,
    /// Native completion has not occurred; retain all call allocations.
    Pending,
}

fn head<T>(outcome: Outcome, head: &OutHead) -> Result<(), ResponseError> {
    if head.size as usize != core::mem::size_of::<T>()
        || head.outcome.0 != outcome as u8
        || head._reserved != [0; 3]
    {
        return Err(ResponseError::Malformed);
    }
    Ok(())
}

fn status(outcome: Outcome, commit: bool, items: u64, bytes: u64) -> Result<(), ResponseError> {
    match outcome {
        Outcome::Ready => Ok(()),
        Outcome::Pending => Err(ResponseError::Pending),
        Outcome::Refused => Err(ResponseError::Failure(owned::Failure::Refused)),
        Outcome::Failed if items != 0 || bytes != 0 => Err(ResponseError::Short {
            needed_items: items,
            needed_bytes: bytes,
        }),
        Outcome::Failed => Err(ResponseError::Failure(if commit {
            owned::Failure::Unknown
        } else {
            owned::Failure::Unavailable
        })),
        Outcome::Fault => Err(ResponseError::Malformed),
    }
}

fn host<T>(ptr: *const T, cap: usize, items: &[T]) -> Result<(), ResponseError> {
    if cap != items.len() || (ptr != items.as_ptr() && !(cap == 0 && ptr.is_null())) {
        return Err(ResponseError::Malformed);
    }
    Ok(())
}

fn written(buf: HostBuf, bytes: &[u8], count: u64) -> Result<&[u8], ResponseError> {
    host(buf.ptr.cast_const(), buf.cap, bytes)?;
    bytes
        .get(..usize::try_from(count).map_err(|_| ResponseError::Malformed)?)
        .ok_or(ResponseError::Malformed)
}

fn span(bytes: &[u8], ptr: *const u8, len: usize) -> Result<&[u8], ResponseError> {
    if ptr.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(ResponseError::Malformed)
        };
    }
    let offset = (ptr as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .ok_or(ResponseError::Malformed)?;
    let end = offset.checked_add(len).ok_or(ResponseError::Malformed)?;
    bytes.get(offset..end).ok_or(ResponseError::Malformed)
}

fn blob(bytes: &[u8], value: Blob) -> Result<&[u8], ResponseError> {
    if value.fmt != BLOB_OCTETS || value.flags & !BLOB_SECRET != 0 {
        return Err(ResponseError::Malformed);
    }
    span(bytes, value.ptr, value.len)
}

fn observation(
    authority: [u8; 16],
    unix_seconds: u64,
) -> Result<owned::ClockObservation, ResponseError> {
    if authority == [0; 16] {
        return Err(ResponseError::Malformed);
    }
    Ok(owned::ClockObservation {
        authority,
        unix_seconds,
    })
}

struct Budget(usize);
impl Budget {
    fn reserve<T>(&mut self, count: usize) -> Result<Vec<T>, ResponseError> {
        let bytes = count
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(ResponseError::Budget)?;
        if bytes > isize::MAX as usize {
            return Err(ResponseError::Budget);
        }
        self.0 = self.0.checked_sub(bytes).ok_or(ResponseError::Budget)?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| ResponseError::Allocation)?;
        Ok(result)
    }
    fn secret(&mut self, bytes: &[u8]) -> Result<Secret<Vec<u8>>, ResponseError> {
        let mut result = Secret::new(self.reserve(bytes.len())?);
        result.0.extend_from_slice(bytes);
        Ok(result)
    }
    fn copy(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ResponseError> {
        let mut result = self.reserve(bytes.len())?;
        result.extend_from_slice(bytes);
        Ok(result)
    }
}

/// Decode a coherent read without reading any native pointer.
pub fn read(
    outcome: Outcome,
    input: &wire::ReadIn,
    out: &wire::ReadOut,
    items: &[wire::ReadValue],
    bytes: &[u8],
    allocation_budget: usize,
) -> Result<owned::ReadResult, ResponseError> {
    head::<wire::ReadOut>(outcome, &out.head)?;
    wire::check::read(outcome, input, out).map_err(ResponseError::Envelope)?;
    host(
        input.values.items.cast_const(),
        input.values.items_cap,
        items,
    )?;
    let bytes = written(input.values.bytes, bytes, out.bytes_written)?;
    status(outcome, false, out.needed_items, out.needed_bytes)?;
    let observed_at = observation(out.authority, out.observed_at)?;
    let permitted = super::decode::time(input.time)
        .map_err(|_| ResponseError::Malformed)?
        .is_none_or(|guard| guard.permits(observed_at.unix_seconds));
    if (out.code == wire::READ_TIME_GUARD_FAILED) == permitted {
        return Err(ResponseError::Malformed);
    }
    if out.code == wire::READ_TIME_GUARD_FAILED {
        return Ok(owned::ReadResult::TimeGuardFailed { observed_at });
    }
    let mut budget = Budget(allocation_budget);
    let mut values = budget.reserve(input.addresses_len)?;
    for item in items
        .get(..input.addresses_len)
        .ok_or(ResponseError::Malformed)?
    {
        if item._reserved != 0 {
            return Err(ResponseError::Malformed);
        }
        values.push(match item.found {
            wire::VALUE_ABSENT => {
                if !item.value.ptr.is_null()
                    || item.value.len != 0
                    || item.value.fmt != 0
                    || item.value.flags != 0
                {
                    return Err(ResponseError::Malformed);
                }
                None
            }
            wire::VALUE_FOUND => Some(budget.secret(blob(bytes, item.value)?)?),
            _ => return Err(ResponseError::Malformed),
        });
    }
    Ok(owned::ReadResult::Values {
        observed_at,
        values,
    })
}

fn input_span(raw: wire::Bytes, actual: &[u8]) -> bool {
    raw.len == actual.len() && (raw.ptr == actual.as_ptr() || (raw.len == 0 && raw.ptr.is_null()))
}

/// Decode an ordered page, binding raw input spans to the retained request.
pub fn scan(
    outcome: Outcome,
    source: &owned::Scan,
    input: &wire::ScanIn,
    out: &wire::ScanOut,
    items: &[wire::ScanRow],
    bytes: &[u8],
    allocation_budget: usize,
) -> Result<owned::Page, ResponseError> {
    head::<wire::ScanOut>(outcome, &out.head)?;
    wire::check::scan(outcome, input, out).map_err(ResponseError::Envelope)?;
    let flags = (u32::from(source.after.is_some()) * wire::SCAN_AFTER)
        | (u32::from(source.generation.is_some()) * wire::SCAN_GENERATION)
        | (u32::from(source.allow_change) * wire::SCAN_ALLOW_CHANGE);
    if input.dataset != source.dataset.0
        || input.namespace != source.namespace.0
        || input.flags != flags
        || input._reserved != 0
        || input.generation != source.generation.unwrap_or(0)
        || input.max_items != source.max_items as u64
        || input.max_bytes != source.max_bytes as u64
        || !input_span(input.prefix, &source.prefix)
        || !input_span(input.after, source.after.as_deref().unwrap_or_default())
        || (source.after.is_some() && source.generation.is_none() && !source.allow_change)
    {
        return Err(ResponseError::Malformed);
    }
    host(input.rows.items.cast_const(), input.rows.items_cap, items)?;
    let bytes = written(input.rows.bytes, bytes, out.bytes_written)?;
    status(outcome, false, out.needed_items, out.needed_bytes)?;
    if out.code == wire::SCAN_STALE {
        if source.generation.is_none() || source.allow_change || !out.next.ptr.is_null() {
            return Err(ResponseError::Malformed);
        }
        return Err(ResponseError::Failure(owned::Failure::StaleScan));
    }
    if !source.allow_change
        && source
            .generation
            .is_some_and(|generation| generation != out.generation)
    {
        return Err(ResponseError::Malformed);
    }
    let count = usize::try_from(out.items_written).map_err(|_| ResponseError::Malformed)?;
    let mut budget = Budget(allocation_budget);
    let mut rows = budget.reserve(count)?;
    let mut previous = source.after.as_deref();
    let mut total = 0usize;
    for row in items.get(..count).ok_or(ResponseError::Malformed)? {
        let key = span(bytes, row.key.ptr, row.key.len)?;
        let value = blob(bytes, row.value)?;
        if !key.starts_with(&source.prefix) || previous.is_some_and(|previous| key <= previous) {
            return Err(ResponseError::Malformed);
        }
        total = total
            .checked_add(key.len())
            .and_then(|sum| sum.checked_add(value.len()))
            .ok_or(ResponseError::Malformed)?;
        if total > source.max_bytes {
            return Err(ResponseError::Malformed);
        }
        rows.push((
            owned::Address {
                namespace: input.namespace,
                key: budget.copy(key)?,
            },
            budget.secret(value)?,
        ));
        previous = Some(key);
    }
    let next = if out.continuation == wire::SCAN_CONTINUE {
        let next = span(bytes, out.next.ptr, out.next.len)?;
        if count == 0 || previous != Some(next) {
            return Err(ResponseError::Malformed);
        }
        Some(budget.copy(next)?)
    } else {
        if !out.next.ptr.is_null() || out.next.len != 0 {
            return Err(ResponseError::Malformed);
        }
        None
    };
    Ok(owned::Page {
        generation: out.generation,
        rows,
        next,
    })
}

/// Decode a commit decision. Errors never imply that execution had no effect.
pub fn commit(
    outcome: Outcome,
    input: &wire::CommitIn,
    out: &wire::CommitOut,
    bytes: &[u8],
    allocation_budget: usize,
) -> Result<owned::Decision, ResponseError> {
    head::<wire::CommitOut>(outcome, &out.head)?;
    wire::check::commit(outcome, input, out).map_err(ResponseError::Envelope)?;
    let bytes = written(input.result, bytes, out.written)?;
    status(outcome, true, 0, out.needed)?;
    let observed_at = observation(out.authority, out.observed_at)?;
    let permitted = super::decode::time(input.candidate.time)
        .map_err(|_| ResponseError::Malformed)?
        .is_none_or(|guard| guard.permits(observed_at.unix_seconds));
    if (out.code == wire::COMMIT_APPLIED && !permitted)
        || (out.code == wire::COMMIT_TIME_GUARD_FAILED && permitted)
    {
        return Err(ResponseError::Malformed);
    }
    Ok(match out.code {
        wire::COMMIT_APPLIED => owned::Decision::Applied(Budget(allocation_budget).secret(bytes)?),
        wire::COMMIT_CONDITION_CONFLICT => owned::Decision::ConditionConflict,
        wire::COMMIT_TIME_GUARD_FAILED => owned::Decision::TimeGuardFailed { observed_at },
        wire::COMMIT_OPID_CONFLICT => owned::Decision::OpIdConflict,
        wire::COMMIT_EXPIRED_UNKNOWN => owned::Decision::ExpiredUnknown,
        _ => return Err(ResponseError::Malformed),
    })
}

/// Decode authoritative time; authority binding is supplied by future admission.
pub fn clock(
    outcome: Outcome,
    out: &wire::ClockOut,
) -> Result<owned::ClockObservation, ResponseError> {
    head::<wire::ClockOut>(outcome, &out.head)?;
    status(outcome, false, 0, 0)?;
    observation(out.authority, out.observed_at)
}

#[cfg(test)]
#[path = "tests/v4_response_tests.rs"]
mod tests;
