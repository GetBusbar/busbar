// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SLOT'S `in`, BUILT FOR A TEST AND BORROWING WHAT IT NAMES (status row 194). An `in` struct
//! keeps its fields pub for the host, so a hand-built one can name any pointer; once #1471 lands,
//! [`reply::call`] does not take one. It takes a [`TestIn<'a, I>`], which only this module makes
//! (here first, so a test builds its `in` this way before the switch): it starts all
//! zero (every pointer NULL, every list empty) and each builder sets a pointer only over memory
//! borrowed for `'a` (a string, a payload, a list, a buffer, a nested `in` built the same way) or
//! held by the `TestIn` itself. So every pointer the slot receives is live for the whole call, and
//! the `TestIn` cannot outlive the bytes it names.
//!
//! ```
//! use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! use busbar_contract::abi::sdk::test_support::test_in::TestIn;
//! let settings = String::from(r#"{"timeout_ms": 5}"#);
//! let input = TestIn::<OpenIn>::new().settings(settings.as_bytes());
//! # drop(input);
//! ```
//!
//! RED: a `TestIn` does not outlive the settings it names.
//!
//! ```compile_fail,E0597
//! use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! use busbar_contract::abi::sdk::test_support::test_in::TestIn;
//! let input;
//! {
//!     let settings = String::from("{}");
//!     input = TestIn::<OpenIn>::new().settings(settings.as_bytes());
//! }
//! drop(input);
//! ```
//!
//! GREEN, its twin: the same `TestIn` used while the settings live.
//!
//! ```
//! use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! use busbar_contract::abi::sdk::test_support::test_in::TestIn;
//! let input;
//! let settings = String::from("{}");
//! {
//!     input = TestIn::<OpenIn>::new().settings(settings.as_bytes());
//! }
//! drop(input);
//! ```
//!
//! [`reply::call`]: super::reply::call

use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr;
use std::any::Any;

use crate::abi::mechanism::call::{AbiStr, Blob, Field, BLOB_JSON};
use crate::abi::sdk::door::AbiIn;
use crate::abi::sdk::out::Scalar;

use super::{zeroed, AllZero};

mod sealed {
    /// Only this module implements it.
    pub trait Lendable {}
    /// Only this module implements it.
    pub trait Settled {}
}

/// An element a [`TestIn`] list may name: a number, or a row of numbers, sealed strings and sealed
/// payloads alone, so no pointer a test could state by hand. Sealed.
pub trait Lendable: sealed::Lendable + Copy + 'static {}
macro_rules! lendable {
    ($($t:ty),+ $(,)?) => {$(
        impl sealed::Lendable for $t {}
        impl Lendable for $t {}
    )+};
}
lendable!(
    u8,
    u16,
    u32,
    u64,
    usize,
    i64,
    crate::abi::mechanism::call::Span,
    AbiStr,
    Blob,
    Field,
    crate::abi::auth::NamedValue,
    crate::abi::store::UnitCell,
    crate::abi::store::UsageCell,
    crate::abi::store::WindowCap,
    crate::abi::store::ReleaseItem,
    crate::abi::export::CheckInstance,
);

/// An `in` with a settings payload: its builder states it as JSON. Sealed.
pub trait Settled: sealed::Settled + AbiIn {
    /// The settings field.
    #[doc(hidden)]
    fn settings_field(&mut self) -> &mut Blob;
}
macro_rules! settled {
    ($($t:ty => $($f:ident).+),+ $(,)?) => {$(
        impl sealed::Settled for $t {}
        impl Settled for $t {
            fn settings_field(&mut self) -> &mut Blob {
                &mut self.$($f).+
            }
        }
    )+};
}
settled!(
    crate::abi::mechanism::lifecycle::ValidateIn => settings,
    crate::abi::mechanism::lifecycle::OpenIn => settings,
    crate::abi::mechanism::lifecycle::RefreshIn => settings,
    crate::abi::plane::PlaneOpenIn => open.settings,
    crate::abi::secret::CheckIn => settings,
);

/// A slot's `in` built for a test: every pointer in it borrows memory that lives for `'a`, or is
/// held by the `TestIn` itself. Only this module makes one; [`super::reply::call`] takes it once
/// #1471 lands.
#[derive(Debug)]
pub struct TestIn<'a, I> {
    pub(crate) input: I,
    /// Lists the builders made (strings, payloads, fields over borrowed bytes), each on the heap
    /// and never moved, freed with the `TestIn`.
    held: Vec<Box<dyn Any>>,
    _lent: PhantomData<&'a ()>,
}

impl<I: AllZero> Default for TestIn<'_, I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, I: AllZero> TestIn<'a, I> {
    /// The all-zero `in`: every number `0`, every pointer NULL, every list empty.
    #[must_use]
    pub fn new() -> Self {
        Self {
            input: zeroed(),
            held: Vec::new(),
            _lent: PhantomData,
        }
    }

    /// The byte offset of the field `pick` names, checked to lie inside an `I`; `pick` is handed a
    /// zeroed `I`, never this one.
    fn offset<F>(pick: impl FnOnce(&I) -> &F) -> usize {
        let blank: I = zeroed();
        let base = ptr::from_ref(&blank) as usize;
        let at = ptr::from_ref(pick(&blank)) as usize;
        assert!(
            at >= base && at.saturating_add(size_of::<F>()) <= base + size_of::<I>(),
            "TestIn: the picked reference is not a field of the in"
        );
        at - base
    }

    /// Write `value` into the field `pick` names.
    fn put<F>(&mut self, pick: impl FnOnce(&I) -> &F, value: F) {
        let at = Self::offset(pick);
        // SAFETY: `at` is the offset of a field of type `F` inside `self.input` (checked by
        // `offset`); `write_unaligned` needs no alignment and drops nothing (`F` here is plain
        // ABI data).
        unsafe {
            ptr::from_mut(&mut self.input)
                .cast::<u8>()
                .add(at)
                .cast::<F>()
                .write_unaligned(value);
        }
    }

    /// Set the pointer-free field `pick` names (a [`Scalar`]: a number, a span, a ticket).
    #[must_use]
    pub fn set<F: Scalar>(mut self, pick: impl FnOnce(&I) -> &F, value: F) -> Self {
        self.put(pick, value);
        self
    }

    /// Set the string field `pick` names to `bytes`, borrowed for `'a`.
    #[must_use]
    pub fn string(mut self, pick: impl FnOnce(&I) -> &AbiStr, bytes: &'a [u8]) -> Self {
        self.put(pick, lend_str(bytes));
        self
    }

    /// Set the payload field `pick` names to `bytes` of `fmt`, borrowed for `'a`.
    #[must_use]
    pub fn blob(mut self, pick: impl FnOnce(&I) -> &Blob, bytes: &'a [u8], fmt: u32) -> Self {
        self.put(pick, lend_blob(bytes, fmt));
        self
    }

    /// Set the list `ptr`/`len` name to `items`, borrowed for `'a`.
    #[must_use]
    pub fn list<T: Lendable>(
        mut self,
        ptr: impl FnOnce(&I) -> &*const T,
        len: impl FnOnce(&I) -> &usize,
        items: &'a [T],
    ) -> Self {
        self.put(ptr, items.as_ptr());
        self.put(len, items.len());
        self
    }

    /// Set the list of strings `ptr`/`len` name to one string over each of `items`, borrowed for
    /// `'a`; the list itself is held by the `TestIn`.
    #[must_use]
    pub fn strings(
        mut self,
        ptr: impl FnOnce(&I) -> &*const AbiStr,
        len: impl FnOnce(&I) -> &usize,
        items: &[&'a [u8]],
    ) -> Self {
        let list: Box<[AbiStr]> = items.iter().map(|b| lend_str(b)).collect();
        self.put(ptr, list.as_ptr());
        self.put(len, list.len());
        self.held.push(Box::new(list));
        self
    }

    /// Set the list of payloads `ptr`/`len` name to one payload of `fmt` over each of `items`,
    /// borrowed for `'a`; the list itself is held by the `TestIn`.
    #[must_use]
    pub fn blobs(
        mut self,
        ptr: impl FnOnce(&I) -> &*const Blob,
        len: impl FnOnce(&I) -> &usize,
        items: &[&'a [u8]],
        fmt: u32,
    ) -> Self {
        let list: Box<[Blob]> = items.iter().map(|b| lend_blob(b, fmt)).collect();
        self.put(ptr, list.as_ptr());
        self.put(len, list.len());
        self.held.push(Box::new(list));
        self
    }

    /// Set the list of fields `ptr`/`len` name to one field over each `(name, value)` of
    /// `items`, borrowed for `'a`; the list itself is held by the `TestIn`.
    #[must_use]
    pub fn fields(
        mut self,
        ptr: impl FnOnce(&I) -> &*const Field,
        len: impl FnOnce(&I) -> &usize,
        items: &[(&'a [u8], &'a [u8])],
    ) -> Self {
        let list: Box<[Field]> = items
            .iter()
            .map(|(n, v)| Field {
                name: lend_str(n),
                value: lend_str(v),
            })
            .collect();
        self.put(ptr, list.as_ptr());
        self.put(len, list.len());
        self.held.push(Box::new(list));
        self
    }

    /// Lend the host buffer `ptr`/`cap` name: `buf`, borrowed mutably for `'a`, for the slot to
    /// fill. A test reads what it wrote through [`super::written`] once the call returns.
    ///
    /// # Panics
    ///
    /// `buf` is longer than the capacity field can state.
    #[must_use]
    pub fn buffer<T: Scalar, C: Scalar + TryFrom<usize>>(
        mut self,
        ptr: impl FnOnce(&I) -> &*mut T,
        cap: impl FnOnce(&I) -> &C,
        buf: &'a mut [T],
    ) -> Self {
        let Ok(n) = C::try_from(buf.len()) else {
            panic!("TestIn::buffer: the buffer is longer than its capacity field states");
        };
        self.put(ptr, buf.as_mut_ptr());
        self.put(cap, n);
        self
    }

    /// Point the field `ptr` names at `nested`, an `in` struct built the same way and borrowed for
    /// `'a` (a dial's destination, a datagram lane).
    #[must_use]
    pub fn nested<T: AllZero>(
        mut self,
        ptr: impl FnOnce(&I) -> &*const T,
        nested: &'a TestIn<'a, T>,
    ) -> Self {
        self.put(ptr, ptr::from_ref(&nested.input));
        self
    }
}

impl<'a, I: Settled> TestIn<'a, I> {
    /// The `in`'s settings: `json`, borrowed for `'a`.
    #[must_use]
    pub fn settings(mut self, json: &'a [u8]) -> Self {
        *self.input.settings_field() = lend_blob(json, BLOB_JSON);
        self
    }
}

/// A string over `bytes`, which the caller's `TestIn<'a, _>` borrows for `'a`.
fn lend_str(bytes: &[u8]) -> AbiStr {
    // SAFETY: every caller stores the string in a `TestIn` whose `'a` the bytes are borrowed for
    // (or in a list that `TestIn` holds), so they outlive every read the slot makes during the
    // call the `TestIn` is lent to.
    unsafe { AbiStr::from_raw_parts(bytes.as_ptr(), bytes.len()) }
}

/// As [`lend_str`], a payload of `fmt`.
fn lend_blob(bytes: &[u8], fmt: u32) -> Blob {
    // SAFETY: as `lend_str`.
    unsafe { Blob::from_raw_parts(bytes.as_ptr(), bytes.len(), fmt, 0) }
}
