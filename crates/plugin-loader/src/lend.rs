// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S LENDING (status row 194): the one place host code makes an [`AbiStr`] or a [`Blob`]
//! over runtime memory it lends a plugin for ONE call (settings, a public URL, a request's bytes).
//! The contract keeps their pointer and length private and makes such a value only through its
//! `unsafe` `from_raw_parts`; these two functions hold that `unsafe` for every host crate, the
//! loader's own doors and the crates that may not write `unsafe` (busbar's root).
//!
//! THE CALL-LENDING CONTRACT: the caller keeps the bytes alive, unmoved and unwritten until the
//! call whose `in` carries the value returns (for a submitted op, until the op completes: lend
//! memory the op owns), and never hands the value to data read after that. Every read of the
//! value is itself `unsafe` ([`AbiStr::bytes`], [`Blob::bytes`]) and states that it holds.
//!
//! Host-only: no plugin depends on this crate (the dependency wall), so no plugin can make a value
//! here that outlives what it names; a plugin lends through its op's generation borrow
//! ([`AbiStr::lent`], [`Blob::lent`]).
//!
//! An empty `bytes` is present and empty (a non-NULL pointer, length `0`), never absent: a caller
//! that lends "none" for empty says so with [`AbiStr::ABSENT`] / [`Blob::ABSENT`].

use busbar_contract::abi::mechanism::call::{AbiStr, Blob};

/// `bytes` as a string the host lends one call, under the call-lending contract (module docs).
#[must_use]
pub fn str(bytes: &[u8]) -> AbiStr {
    // SAFETY: the call-lending contract: the caller keeps `bytes` alive, unmoved and unwritten
    // for every read of the value, until the call it lends the `in` to returns.
    unsafe { AbiStr::from_raw_parts(bytes.as_ptr(), bytes.len()) }
}

/// `bytes` as a payload of `fmt` (`BLOB_JSON`, `BLOB_OCTETS` ...) the host lends one call, under
/// the call-lending contract (module docs); flag it with [`Blob::with_flags`].
#[must_use]
pub fn blob(bytes: &[u8], fmt: u32) -> Blob {
    // SAFETY: as `str`: the call-lending contract.
    unsafe { Blob::from_raw_parts(bytes.as_ptr(), bytes.len(), fmt, 0) }
}
