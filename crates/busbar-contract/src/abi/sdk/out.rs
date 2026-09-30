// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SLOT'S `out`, WRITTEN BY THE SDK (THE DESIGN, plugins: a plugin crate stays
//! `#![forbid(unsafe_code)]`; memory a plugin returns stays valid for as long as the ABI says).
//! A [`SafeSlot`](crate::abi::sdk::safe::SafeSlot) body is handed its `out` as an [`Out`], never as
//! `&mut`: it READS any field, SETS a pointer-free field ([`Scalar`]) directly, and hands every
//! pointer-bearing field — a string, a blob, a list, a published value, a view into a host buffer —
//! to an SDK writer that takes the memory it points into from a place that outlives the answer:
//!
//! * [`Out::fail`] — the answer's error text (`abi::sdk::life::fail`);
//! * [`Out::lease`] / [`Out::lease_secret`] — owned bytes, held under a lease until `release`;
//! * [`Out::text`] / [`Out::list`] — `'static` strings and lists;
//! * [`Out::publish`] — generation data the SDK owns until that generation's `retire`;
//! * [`Out::host_str`] / [`Out::host_list`] — a view into a host buffer lent for the call.
//!
//! So safe code cannot store a pointer the host would read after its memory is gone.
//!
//! ```compile_fail,E0277
//! use busbar_contract::abi::mechanism::call::{AbiStr, OutHead};
//! fn body(mut out: busbar_contract::abi::sdk::Out<'_, OutHead>, s: &String) {
//!     // An `AbiStr` is not a `Scalar`: its pointer would outlive `s`.
//!     out.set(|o| &o.error, AbiStr { ptr: s.as_ptr(), len: s.len() });
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use busbar_contract::abi::plane::{PlaneOpenOut, PlaneSnapshot};
//! fn body(mut out: busbar_contract::abi::sdk::Out<'_, PlaneOpenOut>, snap: &PlaneSnapshot) {
//!     out.set(|o| &o.snapshot, std::ptr::from_ref(snap)); // a raw pointer is not a `Scalar`
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use busbar_contract::abi::mechanism::call::Blob;
//! use busbar_contract::abi::export::StatusOut;
//! fn body(mut out: busbar_contract::abi::sdk::Out<'_, StatusOut>, b: &[u8]) {
//!     out.set(|o| &o.status, Blob { ptr: b.as_ptr(), len: b.len(), fmt: 1, flags: 0 });
//! }
//! ```
//!
//! ```compile_fail,E0594
//! use busbar_contract::abi::mechanism::call::{AbiStr, OutHead};
//! fn body(out: busbar_contract::abi::sdk::Out<'_, OutHead>, s: &'static str) {
//!     out.get().error = AbiStr { ptr: s.as_ptr(), len: s.len() }; // `get` is read-only
//! }
//! ```

use std::mem::size_of;
use std::ptr;

use crate::abi::mechanism::call::{AbiStr, Blob, OutHead, Outcome};
use crate::abi::sdk::door::AbiOut;
use crate::abi::sdk::lent::HostBuf;
use crate::abi::sdk::life::{fail, Leases, Refusal};
use crate::abi::sdk::publish::{Generations, Publish};

/// A value with no pointer in it, anywhere: a safe body may set it into an `out` directly.
///
/// # Safety
/// The implementor holds no pointer, reference or union reaching one, at any depth.
pub unsafe trait Scalar: Copy + 'static {}

macro_rules! scalar {
    ($($t:ty),* $(,)?) => {$(
        // SAFETY: a plain number (or an array of them); no pointer.
        unsafe impl Scalar for $t {}
    )*};
}
scalar!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, f32, f64);
// SAFETY: an array of pointer-free values holds no pointer.
unsafe impl<T: Scalar, const N: usize> Scalar for [T; N] {}
// SAFETY (all below): fixed-layout ABI structs of integers only.
unsafe impl Scalar for crate::abi::mechanism::call::RawOutcome {}
unsafe impl Scalar for crate::abi::mechanism::ticket::Ticket {}
unsafe impl Scalar for crate::abi::plane::Span {}
unsafe impl Scalar for crate::abi::plane::UnitCount {}
unsafe impl Scalar for crate::abi::plane::RecordWrite {}
unsafe impl Scalar for crate::abi::plane::OutField {}
unsafe impl Scalar for crate::abi::transport::FramePiece {}
unsafe impl Scalar for crate::abi::transport::FramerYield {}

/// A slot's `out`, as a safe body is handed it: read anything, set scalars, and hand pointers to
/// the SDK's writers. Only the SDK makes one; it lives for the call.
#[derive(Debug)]
pub struct Out<'a, T> {
    out: &'a mut T,
}

impl<'a, T: AbiOut> Out<'a, T> {
    pub(crate) fn new(out: &'a mut T) -> Self {
        Self { out }
    }

    /// The `out` as the SDK's own code writes it (the kind SDKs in this crate).
    pub(crate) fn raw(&mut self) -> &mut T {
        self.out
    }

    /// Read the `out`.
    #[must_use]
    pub fn get(&self) -> &T {
        self.out
    }

    /// The address of the field `pick` names, checked to lie inside the `out`.
    fn at<F>(&mut self, pick: impl FnOnce(&T) -> &F) -> *mut F {
        let base = ptr::from_ref::<T>(self.out) as usize;
        let at = ptr::from_ref(pick(self.out)) as usize;
        assert!(
            at >= base && at.saturating_add(size_of::<F>()) <= base + size_of::<T>(),
            "Out: the picked reference is not a field of the out"
        );
        // The same allocation as `self.out`, derived from the `&mut` so writing through it is
        // allowed.
        ptr::from_mut::<T>(self.out)
            .cast::<u8>()
            .wrapping_add(at - base)
            .cast::<F>()
    }

    /// Write `value` into the field `pick` names (any field, however nested).
    fn put<F>(&mut self, pick: impl FnOnce(&T) -> &F, value: F) {
        let p = self.at(pick);
        // SAFETY: `p` is a field of `*self.out` (checked by `at`), derived from the exclusive
        // borrow this `Out` holds; `write_unaligned` needs no alignment and drops nothing (the ABI
        // structs are `Copy`).
        unsafe { p.write_unaligned(value) };
    }

    /// Set the pointer-free field `pick` names to `value`.
    ///
    /// # Panics
    /// When `pick` answers a reference that is not a field of the `out`.
    pub fn set<F: Scalar>(&mut self, pick: impl FnOnce(&T) -> &F, value: F) {
        self.put(pick, value);
    }

    /// The `out`'s head (every `out` leads with an [`OutHead`], [`AbiOut`]).
    fn head(&mut self) -> &mut OutHead {
        // SAFETY: `AbiOut`'s contract: the implementor's first field is an `OutHead`.
        unsafe { &mut *ptr::from_mut::<T>(self.out).cast::<OutHead>() }
    }

    /// Answer `refusal`: its outcome, the head's error naming its text (`abi::sdk::life::fail`).
    pub fn fail(&mut self, refusal: Refusal) -> Outcome {
        fail(self.head(), refusal)
    }

    /// Name `text`, which lives for the program, as the answer's error text; the outcome is the
    /// caller's to answer.
    pub fn error(&mut self, text: &'static str) {
        self.head().error = AbiStr {
            ptr: text.as_ptr(),
            len: text.len(),
        };
    }

    /// Hold `bytes` in `leases` under a new lease (named in the head) and set the blob `pick`
    /// names over them, of format `fmt`.
    pub fn lease(
        &mut self,
        pick: impl FnOnce(&T) -> &Blob,
        leases: &Leases,
        bytes: Vec<u8>,
        fmt: u32,
    ) {
        let blob = leases.blob(self.head(), bytes, fmt);
        self.put(pick, blob);
    }

    /// As [`Out::lease`], for secret material (flagged secret, zeroized on release).
    pub fn lease_secret(
        &mut self,
        pick: impl FnOnce(&T) -> &Blob,
        leases: &Leases,
        bytes: Vec<u8>,
        fmt: u32,
    ) {
        let blob = leases.secret_blob(self.head(), bytes, fmt);
        self.put(pick, blob);
    }

    /// Set the string field `pick` names to `text`, which lives for the program.
    pub fn text(&mut self, pick: impl FnOnce(&T) -> &AbiStr, text: &'static str) {
        self.put(
            pick,
            AbiStr {
                ptr: text.as_ptr(),
                len: text.len(),
            },
        );
    }

    /// Set the list `ptr`/`len` name to `items`, which live for the program (NULL when empty).
    pub fn list<E: 'static>(
        &mut self,
        ptr: impl FnOnce(&T) -> &*const E,
        len: impl FnOnce(&T) -> &usize,
        items: &'static [E],
    ) {
        let p = if items.is_empty() {
            ptr::null()
        } else {
            items.as_ptr()
        };
        self.put(ptr, p);
        self.put(len, items.len());
    }

    /// Publish `spec` as `generation` in `gens` and set the field `pick` names to the published
    /// value, which the SDK holds until that generation's `retire`.
    pub fn publish<P: Publish>(
        &mut self,
        pick: impl FnOnce(&T) -> &*const P,
        gens: &Generations<P>,
        generation: u64,
        spec: &P::Spec,
    ) {
        let p = gens.publish(generation, spec);
        self.put(pick, p);
    }

    /// Set the string field `pick` names to the bytes `span` names in the host buffer `buf`,
    /// which the host lent for this call and reads when it returns.
    pub fn host_str(
        &mut self,
        pick: impl FnOnce(&T) -> &AbiStr,
        buf: &HostBuf<'_, u8>,
        span: crate::abi::plane::Span,
    ) {
        let s = buf.str_at(span);
        self.put(pick, s);
    }

    /// Set the list `ptr`/`len` name to what `buf`, a host buffer lent for this call, holds.
    pub fn host_list<E: Copy>(
        &mut self,
        ptr: impl FnOnce(&T) -> &*const E,
        len: impl FnOnce(&T) -> &usize,
        buf: &HostBuf<'_, E>,
    ) {
        let p = buf.as_ptr().cast_const();
        self.put(ptr, p);
        self.put(len, buf.written());
    }
}

#[cfg(test)]
#[path = "tests/out_tests.rs"]
mod tests;
