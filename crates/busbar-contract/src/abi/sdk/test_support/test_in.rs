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
    crate::abi::store::UsageCell,
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
    pub(crate) held: Vec<Box<dyn Any>>,
    /// Every pointer and length the builders set together (status row 194): `(pointer's offset,
    /// length's offset, length's width, pointer, length)`, as written. A call checks the `in`
    /// against it before the slot reads a byte.
    lent: Vec<(usize, usize, usize, u64, u64)>,
    _lent: PhantomData<&'a ()>,
}

impl<I: AllZero> Default for TestIn<'_, I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: 'static> TestIn<'_, I> {
    /// Every pointer and length pair an `I` carries, its embedded structs' included:
    /// `(pointer's offset, length's offset, length's width)`.
    fn pairs() -> Vec<(usize, usize, usize)> {
        super::pairs::lent_pairs(std::any::TypeId::of::<I>())
    }

    /// The `width`-byte unsigned value at byte `at` of the `in`.
    fn read(&self, at: usize, width: usize) -> u64 {
        // SAFETY: `at + width` lies inside `self.input` (an offset `offset` checked, or one of the
        // `in`'s own pairs), and every byte of an `AllZero` `in` is initialised.
        unsafe {
            let p = ptr::from_ref(&self.input).cast::<u8>().add(at);
            match width {
                1 => u64::from(p.read()),
                2 => u64::from(p.cast::<u16>().read_unaligned()),
                4 => u64::from(p.cast::<u32>().read_unaligned()),
                8 => p.cast::<u64>().read_unaligned(),
                _ => panic!("TestIn: a length field of {width} bytes"),
            }
        }
    }

    /// THE `in` IS WHAT ITS BUILDERS SET (status row 194): every pointer and length pair holds what
    /// a builder wrote there together, and every other pair is NULL and empty. A call runs this
    /// before the slot reads a byte.
    ///
    /// # Panics
    ///
    /// A pair holds anything else.
    pub(crate) fn check(&self) {
        let word = size_of::<usize>();
        let mut pairs = Self::pairs();
        pairs.extend(self.lent.iter().map(|e| (e.0, e.1, e.2)));
        for (p, n, w) in pairs {
            let now = (self.read(p, word), self.read(n, w));
            let set = match self.lent.iter().find(|e| e.0 == p) {
                Some(e) => (e.3, e.4),
                // A pair no builder set is NULL; its length is empty, unless another list the
                // builders set shares it (a decide's candidates and their dynamics).
                None => match self.lent.iter().find(|e| e.1 == n) {
                    Some(e) => (0, e.4),
                    None => (0, 0),
                },
            };
            assert_eq!(
                now, set,
                "TestIn: the pointer at byte {p} and its length at byte {n} are not what the \
                 builders set"
            );
        }
    }
}

impl<'a, I: AllZero> TestIn<'a, I> {
    /// The all-zero `in`: every number `0`, every pointer NULL, every list empty.
    #[must_use]
    pub fn new() -> Self {
        Self {
            input: zeroed(),
            held: Vec::new(),
            lent: Vec::new(),
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

    /// The width of the length at `len` that is the pointer at `ptr`'s own: a pair the `in`
    /// states, never two fields a test names apart.
    ///
    /// # Panics
    ///
    /// The two are not one of the `in`'s pairs.
    fn paired(ptr: usize, len: usize) -> usize {
        Self::pairs()
            .into_iter()
            .find(|&(p, n, _)| (p, n) == (ptr, len))
            .map(|(_, _, w)| w)
            .unwrap_or_else(|| {
                panic!(
                    "TestIn: the pointer at byte {ptr} and the length at byte {len} are not one \
                     of the in's pointer and length pairs"
                )
            })
    }

    /// Keep what the builders just wrote at the pair `ptr`/`len`.
    fn record(&mut self, ptr: usize, len: usize, width: usize) {
        let word = size_of::<usize>();
        let stated = (self.read(ptr, word), self.read(len, width));
        self.lent.retain(|e| e.0 != ptr);
        self.lent.push((ptr, len, width, stated.0, stated.1));
    }

    /// Write `value` into the field `pick` names.
    fn put<F>(&mut self, pick: impl FnOnce(&I) -> &F, value: F) {
        let at = Self::offset(pick);
        self.put_at(at, value);
    }

    /// Write `value` at byte `at` of the `in`, the offset of a field of type `F` ([`Self::offset`]).
    fn put_at<F>(&mut self, at: usize, value: F) {
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
        let at = Self::offset(pick);
        let end = at + size_of::<F>();
        let word = size_of::<usize>();
        let mut pairs = Self::pairs();
        pairs.extend(self.lent.iter().map(|e| (e.0, e.1, e.2)));
        for (p, n, w) in pairs {
            assert!(
                end <= p || at >= p + word,
                "TestIn::set: byte {at} is a pointer the builders set (status row 194)"
            );
            assert!(
                end <= n || at >= n + w,
                "TestIn::set: byte {at} is the length of the pointer at byte {p}, set with it"
            );
        }
        self.put_at(at, value);
        self
    }

    /// Set the string field `pick` names to `bytes`, borrowed for `'a`.
    #[must_use]
    pub fn string(mut self, pick: impl FnOnce(&I) -> &AbiStr, bytes: &'a [u8]) -> Self {
        let at = Self::offset(pick);
        self.put_at(at, lend_str(bytes));
        self.record(at, at + size_of::<usize>(), size_of::<usize>());
        self
    }

    /// Set the payload field `pick` names to `bytes` of `fmt`, borrowed for `'a`.
    #[must_use]
    pub fn blob(mut self, pick: impl FnOnce(&I) -> &Blob, bytes: &'a [u8], fmt: u32) -> Self {
        let at = Self::offset(pick);
        self.put_at(at, lend_blob(bytes, fmt));
        self.record(at, at + size_of::<usize>(), size_of::<usize>());
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
        let (p, n) = (Self::offset(ptr), Self::offset(len));
        let w = Self::paired(p, n);
        self.put_at(p, items.as_ptr());
        self.put_at(n, items.len());
        self.record(p, n, w);
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
        let (p, n) = (Self::offset(ptr), Self::offset(len));
        let w = Self::paired(p, n);
        self.put_at(p, list.as_ptr());
        self.put_at(n, list.len());
        self.record(p, n, w);
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
        let (p, n) = (Self::offset(ptr), Self::offset(len));
        let w = Self::paired(p, n);
        self.put_at(p, list.as_ptr());
        self.put_at(n, list.len());
        self.record(p, n, w);
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
        let (p, n) = (Self::offset(ptr), Self::offset(len));
        let w = Self::paired(p, n);
        self.put_at(p, list.as_ptr());
        self.put_at(n, list.len());
        self.record(p, n, w);
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
        let (p, c) = (Self::offset(ptr), Self::offset(cap));
        let w = Self::paired(p, c);
        assert_eq!(
            w,
            size_of::<C>(),
            "TestIn::buffer: the capacity field's width"
        );
        self.put_at(p, buf.as_mut_ptr());
        self.put_at(c, n);
        self.record(p, c, w);
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
        nested.check();
        self.put(ptr, ptr::from_ref(&nested.input));
        self
    }
}

impl<'a, I: Settled + AllZero> TestIn<'a, I> {
    /// The `in`'s settings: `json`, borrowed for `'a`.
    #[must_use]
    pub fn settings(mut self, json: &'a [u8]) -> Self {
        let field = ptr::from_mut(self.input.settings_field()) as usize;
        let at = field - ptr::from_ref(&self.input) as usize;
        self.put_at(at, lend_blob(json, BLOB_JSON));
        self.record(at, at + size_of::<usize>(), size_of::<usize>());
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
