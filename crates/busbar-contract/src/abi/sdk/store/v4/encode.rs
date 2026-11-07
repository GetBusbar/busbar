// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Allocation-free backend replies into retained, initialized host buffers.
//!
//! Raw output pointers are compared with supplied slices, never dereferenced.
//! Every invariant and full capacity requirement is checked before the first
//! write. The driver remains responsible for envelope metadata and leases.

use crate::abi::mechanism::call::{Blob, OutHead, Outcome, RawOutcome, BLOB_OCTETS, BLOB_SECRET};
use crate::abi::sdk::door::{blank_out, AbiOut};
use crate::abi::store::{v4 as wire, HostBuf};
use crate::persistence as owned;

/// A response cannot be represented faithfully; host buffers remain untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// Host pointer/capacity fields do not match the supplied slices.
    Buffer,
    /// A result or retained request violates the primitive contract.
    Malformed,
    /// A count or aggregate byte length is not representable.
    Overflow,
}

fn output<T: AbiOut>() -> T {
    blank_out()
}

fn head<T>(head: &mut OutHead, outcome: Outcome) {
    head.size = core::mem::size_of::<T>() as u32;
    head.outcome = RawOutcome::of(outcome);
}

fn failure(value: owned::Failure) -> Result<Outcome, EncodeError> {
    Ok(match value {
        owned::Failure::Refused | owned::Failure::Overloaded => Outcome::Refused,
        owned::Failure::Unknown | owned::Failure::Unavailable => Outcome::Failed,
        owned::Failure::Corrupt => Outcome::Fault,
        owned::Failure::StaleScan => return Err(EncodeError::Malformed),
    })
}

fn host<T>(ptr: *const T, cap: usize, slice: &[T]) -> Result<(), EncodeError> {
    if cap != slice.len() || (ptr != slice.as_ptr() && !(cap == 0 && ptr.is_null())) {
        return Err(EncodeError::Buffer);
    }
    Ok(())
}

fn buffer(raw: HostBuf, bytes: &[u8]) -> Result<(), EncodeError> {
    host(raw.ptr.cast_const(), raw.cap, bytes)
}

fn count(value: usize) -> Result<u64, EncodeError> {
    u64::try_from(value).map_err(|_| EncodeError::Overflow)
}

fn add(total: usize, len: usize) -> Result<usize, EncodeError> {
    total.checked_add(len).ok_or(EncodeError::Overflow)
}

fn observation(value: owned::ClockObservation) -> Result<(), EncodeError> {
    if value.authority == [0; 16] {
        return Err(EncodeError::Malformed);
    }
    Ok(())
}

fn guard(raw: wire::TimeGuard, seconds: u64) -> Result<bool, EncodeError> {
    let guard = super::decode::time(raw).map_err(|_| EncodeError::Malformed)?;
    Ok(guard.is_none_or(|guard| guard.permits(seconds)))
}

fn copy(bytes: &mut [u8], offset: &mut usize, value: &[u8]) -> wire::Bytes {
    let start = *offset;
    *offset += value.len();
    bytes[start..*offset].copy_from_slice(value);
    wire::Bytes {
        ptr: bytes[start..].as_ptr(),
        len: value.len(),
    }
}

fn blob(bytes: wire::Bytes) -> Blob {
    Blob {
        ptr: bytes.ptr,
        len: bytes.len,
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

/// Encode a coherent exact-address result, preserving absent and empty values.
pub fn read<O>(
    input: &wire::ReadIn,
    result: Result<&owned::ReadResult<O>, owned::Failure>,
    items: &mut [wire::ReadValue],
    bytes: &mut [u8],
) -> Result<wire::ReadOut, EncodeError> {
    host(
        input.values.items.cast_const(),
        input.values.items_cap,
        items,
    )?;
    buffer(input.values.bytes, bytes)?;
    let mut out: wire::ReadOut = output();
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            head::<wire::ReadOut>(&mut out.head, failure(error)?);
            return Ok(out);
        }
    };
    let (observed_at, values) = match result {
        owned::ReadResult::Values {
            observed_at,
            values,
        } => {
            if values.len() != input.addresses_len {
                return Err(EncodeError::Malformed);
            }
            (*observed_at, Some(values))
        }
        owned::ReadResult::TimeGuardFailed { observed_at } => (*observed_at, None),
    };
    observation(observed_at)?;
    if guard(input.time, observed_at.unix_seconds)? != values.is_some() {
        return Err(EncodeError::Malformed);
    }
    out.observed_at = observed_at.unix_seconds;
    out.authority = observed_at.authority;
    let Some(values) = values else {
        out.code = wire::READ_TIME_GUARD_FAILED;
        head::<wire::ReadOut>(&mut out.head, Outcome::Ready);
        return Ok(out);
    };
    let needed = values.iter().try_fold(0, |total, value| {
        add(total, value.as_ref().map_or(0, |value| value.0.len()))
    })?;
    let nitems = count(values.len())?;
    let nbytes = count(needed)?;
    if values.len() > items.len() || needed > bytes.len() {
        out.needed_items = nitems;
        out.needed_bytes = nbytes;
        head::<wire::ReadOut>(&mut out.head, Outcome::Failed);
        return Ok(out);
    }
    let mut offset = 0;
    for (item, value) in items.iter_mut().zip(values) {
        *item = wire::ReadValue {
            found: if value.is_some() {
                wire::VALUE_FOUND
            } else {
                wire::VALUE_ABSENT
            },
            _reserved: 0,
            value: value.as_ref().map_or(Blob::ABSENT, |value| {
                blob(copy(bytes, &mut offset, &value.0))
            }),
        };
    }
    out.code = wire::READ_VALUES;
    out.items_written = nitems;
    out.bytes_written = nbytes;
    head::<wire::ReadOut>(&mut out.head, Outcome::Ready);
    Ok(out)
}

fn input_span(raw: wire::Bytes, actual: &[u8]) -> bool {
    raw.len == actual.len() && (raw.ptr == actual.as_ptr() || (raw.len == 0 && raw.ptr.is_null()))
}

fn scan_input(source: &owned::Scan, input: &wire::ScanIn) -> Result<(), EncodeError> {
    let flags = (u32::from(source.after.is_some()) * wire::SCAN_AFTER)
        | (u32::from(source.generation.is_some()) * wire::SCAN_GENERATION)
        | (u32::from(source.allow_change) * wire::SCAN_ALLOW_CHANGE);
    if input.dataset != source.dataset.0
        || input.namespace != source.namespace.0
        || input.flags != flags
        || input._reserved != 0
        || input.generation != source.generation.unwrap_or(0)
        || input.max_items != count(source.max_items)?
        || input.max_bytes != count(source.max_bytes)?
        || source.max_items == 0
        || source.max_bytes == 0
        || !input_span(input.prefix, &source.prefix)
        || !input_span(input.after, source.after.as_deref().unwrap_or_default())
        || (source.after.is_some() && source.generation.is_none() && !source.allow_change)
        || (source.allow_change && source.generation.is_some())
    {
        return Err(EncodeError::Malformed);
    }
    Ok(())
}

/// Encode a strictly ordered page or an explicit stale-generation response.
/// `source` binds retained input spans without dereferencing raw request pointers.
pub fn scan<O>(
    source: &owned::Scan,
    input: &wire::ScanIn,
    result: Result<&owned::Page<O>, owned::Failure>,
    items: &mut [wire::ScanRow],
    bytes: &mut [u8],
) -> Result<wire::ScanOut, EncodeError> {
    host(input.rows.items.cast_const(), input.rows.items_cap, items)?;
    buffer(input.rows.bytes, bytes)?;
    scan_input(source, input)?;
    let mut out: wire::ScanOut = output();
    let page = match result {
        Ok(page) => page,
        Err(owned::Failure::StaleScan) => {
            if source.generation.is_none() || source.allow_change {
                return Err(EncodeError::Malformed);
            }
            out.code = wire::SCAN_STALE;
            head::<wire::ScanOut>(&mut out.head, Outcome::Ready);
            return Ok(out);
        }
        Err(error) => {
            head::<wire::ScanOut>(&mut out.head, failure(error)?);
            return Ok(out);
        }
    };
    if page.rows.len() > source.max_items
        || (!source.allow_change
            && source
                .generation
                .is_some_and(|value| value != page.generation))
    {
        return Err(EncodeError::Malformed);
    }
    let mut total = 0;
    let mut previous = source.after.as_deref();
    for (address, value) in &page.rows {
        if address.namespace != source.namespace.0
            || !address.key.starts_with(&source.prefix)
            || previous.is_some_and(|previous| address.key.as_slice() <= previous)
        {
            return Err(EncodeError::Malformed);
        }
        total = add(add(total, address.key.len())?, value.0.len())?;
        previous = Some(&address.key);
    }
    if total > source.max_bytes
        || page
            .next
            .as_deref()
            .is_some_and(|next| page.rows.is_empty() || previous != Some(next))
    {
        return Err(EncodeError::Malformed);
    }
    let needed = add(total, page.next.as_ref().map_or(0, Vec::len))?;
    let nitems = count(page.rows.len())?;
    let nbytes = count(needed)?;
    if page.rows.len() > items.len() || needed > bytes.len() {
        out.needed_items = nitems;
        out.needed_bytes = nbytes;
        head::<wire::ScanOut>(&mut out.head, Outcome::Failed);
        return Ok(out);
    }
    let mut offset = 0;
    for (item, (address, value)) in items.iter_mut().zip(&page.rows) {
        *item = wire::ScanRow {
            key: copy(bytes, &mut offset, &address.key),
            value: blob(copy(bytes, &mut offset, &value.0)),
        };
    }
    out.code = wire::SCAN_PAGE;
    out.generation = page.generation;
    out.continuation = if let Some(next) = &page.next {
        out.next = copy(bytes, &mut offset, next);
        wire::SCAN_CONTINUE
    } else {
        wire::SCAN_EXHAUSTED
    };
    out.items_written = nitems;
    out.bytes_written = nbytes;
    head::<wire::ScanOut>(&mut out.head, Outcome::Ready);
    Ok(out)
}

/// Encode a decision using its original receipt observation on replay.
/// A short result requires replay of the exact original candidate and identity.
pub fn commit<O>(
    input: &wire::CommitIn,
    observed_at: owned::ClockObservation,
    result: Result<&owned::Decision<O>, owned::Failure>,
    bytes: &mut [u8],
) -> Result<wire::CommitOut, EncodeError> {
    buffer(input.result, bytes)?;
    let mut out: wire::CommitOut = output();
    let decision = match result {
        Ok(decision) => decision,
        Err(error) => {
            head::<wire::CommitOut>(&mut out.head, failure(error)?);
            return Ok(out);
        }
    };
    observation(observed_at)?;
    let in_time = guard(input.candidate.time, observed_at.unix_seconds)?;
    if matches!(decision, owned::Decision::Applied(_)) && !in_time
        || matches!(decision, owned::Decision::TimeGuardFailed { .. }) && in_time
    {
        return Err(EncodeError::Malformed);
    }
    out.authority = observed_at.authority;
    out.observed_at = observed_at.unix_seconds;
    out.code = match decision {
        owned::Decision::Applied(value) => {
            let needed = count(value.0.len())?;
            if value.0.len() > bytes.len() {
                out.needed = needed;
                head::<wire::CommitOut>(&mut out.head, Outcome::Failed);
                return Ok(out);
            }
            bytes[..value.0.len()].copy_from_slice(&value.0);
            out.written = needed;
            wire::COMMIT_APPLIED
        }
        owned::Decision::ConditionConflict => wire::COMMIT_CONDITION_CONFLICT,
        owned::Decision::TimeGuardFailed {
            observed_at: actual,
        } => {
            if *actual != observed_at {
                return Err(EncodeError::Malformed);
            }
            wire::COMMIT_TIME_GUARD_FAILED
        }
        owned::Decision::OpIdConflict => wire::COMMIT_OPID_CONFLICT,
        owned::Decision::ExpiredUnknown => wire::COMMIT_EXPIRED_UNKNOWN,
    };
    head::<wire::CommitOut>(&mut out.head, Outcome::Ready);
    Ok(out)
}

/// Encode authoritative time with a registered, nonzero authority identity.
pub fn clock(
    result: Result<owned::ClockObservation, owned::Failure>,
) -> Result<wire::ClockOut, EncodeError> {
    let mut out: wire::ClockOut = output();
    match result {
        Ok(value) => {
            observation(value)?;
            out.observed_at = value.unix_seconds;
            out.authority = value.authority;
            head::<wire::ClockOut>(&mut out.head, Outcome::Ready);
        }
        Err(error) => head::<wire::ClockOut>(&mut out.head, failure(error)?),
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/encode_tests.rs"]
mod tests;
