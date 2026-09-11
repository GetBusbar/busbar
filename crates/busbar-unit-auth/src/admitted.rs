// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ADMITTED-IDENTITY handle table — what an admission hands out instead of the identity itself.
//!
//! An inbound admission resolves to something SENSITIVE and something UNMARSHALLABLE at the same
//! time: the principal, and beside it the enforcement key the rest of the request is spent against
//! — its material, its group chain, its budget buckets. It is not a fixed-size value, and the
//! admission runs ONCE (the chain touches the credential cache and whatever offload the caller
//! gave it), so re-running it to re-marshal a field would be a SECOND admission and a second answer
//! to who is calling.
//!
//! So the admission keeps the resolved thing HERE and hands out a bare `u64` — a handle with no
//! structure to read and nothing to forge a claim out of. The caller carries the handle and
//! consumes it ONCE ([`Admitted::take`]) to recover the EXACT object the admission produced: not a
//! copy, not a re-resolution, the same value. A refusal stashes nothing and names
//! [`Admitted::NONE`].
//!
//! ## Single use is the whole discipline
//!
//! [`take`](Admitted::take) REMOVES. A handle answers once and every later presentation of it —
//! the replay, the double-consume, the handle a slow caller kept — reads as unknown and is refused.
//! The caller cannot tell those cases apart and does not need to: all of them are "this handle no
//! longer names an admission", which is the fail-closed reading. `0` is reserved for "no handle at
//! all", so a zeroed or defaulted field can never accidentally name a live admission.
//!
//! The table is generic over what it holds because the handle discipline is the same whatever the
//! admission resolved to: this unit knows a resolved identity is a thing it must not hand out, and
//! nothing else about it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A table of admitted identities held behind opaque handles, each recoverable exactly once.
///
/// `T` is whatever the admission resolved to — the principal and the enforcement context that came
/// with it. This table never reads it, compares it or copies it; it holds it and gives it back.
pub struct Admitted<T> {
    /// The resolved values, keyed by the opaque handle the caller holds.
    held: Mutex<HashMap<u64, T>>,
    /// The next handle. `0` is the reserved "none" handle, so handles start at `1` and a handle is
    /// never reused within the life of the table.
    next: AtomicU64,
}

impl<T> Admitted<T> {
    /// The reserved handle that names NO admission: what a refusal carries, and what a zeroed or
    /// defaulted field reads as. [`take`](Admitted::take) always answers `None` for it.
    pub const NONE: u64 = 0;

    /// An empty table.
    #[must_use]
    pub fn new() -> Admitted<T> {
        Admitted {
            held: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }
    }

    /// Stash `resolved` and return the opaque handle that names it — the ONLY thing about the
    /// admitted identity that the caller is given. The value stays here until it is consumed.
    ///
    /// The handle is never [`NONE`](Admitted::NONE), so "there is an admission" and "there is not"
    /// are distinguishable without the caller holding a second flag that could disagree.
    #[must_use]
    pub fn stash(&self, resolved: T) -> u64 {
        let handle = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(handle, resolved);
        handle
    }

    /// Consume `handle`, recovering the resolved value and REMOVING it — a handle is single-use —
    /// or `None` when the handle is [`NONE`](Admitted::NONE) or unknown (never minted, or already
    /// consumed). The `None` is the fail-closed reading: an admission that cannot be recovered is
    /// an admission that did not happen.
    #[must_use]
    pub fn take(&self, handle: u64) -> Option<T> {
        if handle == Admitted::<T>::NONE {
            return None;
        }
        self.lock().remove(&handle)
    }

    /// Poison-recovering lock, the discipline every request-path lock takes: a panic mid-update must
    /// not wedge the table for every later admission.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, T>> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T> Default for Admitted<T> {
    fn default() -> Admitted<T> {
        Admitted::new()
    }
}
