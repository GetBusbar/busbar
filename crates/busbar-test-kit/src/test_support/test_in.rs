// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A slot's input built for a test owns or borrows everything it names. Only this module constructs [`TestIn<'a, I>`]. It starts zeroed, with null pointers and empty lists. Each builder then points only to memory borrowed for `'a` or held by the `TestIn` itself, including strings, payloads, lists, buffers, and nested inputs. The safe typed crossing uses this backing information so no input pointer outlives its storage.
//!
//!
//!
//!
//!
//!
//!
//!
//! ```
//! use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! use busbar_test_kit::test_support::test_in::TestIn;
//! let settings = String::from(r#"{"timeout_ms": 5}"#);
//! let input = TestIn::<OpenIn>::new().settings(settings.as_bytes());
//! # drop(input);
//! ```
//!
//! RED: a `TestIn` does not outlive the settings it names.
//!
//! ```compile_fail,E0597
//! use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! use busbar_test_kit::test_support::test_in::TestIn;
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
//! use busbar_test_kit::test_support::test_in::TestIn;
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

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, BLOB_JSON};
use busbar_contract::abi::sdk::door::AbiIn;
use busbar_contract::abi::sdk::out::Scalar;

use super::{zeroed, AllZero};

mod sealed {

    pub trait Lendable {}

    pub trait Settled {}
}

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
    busbar_contract::abi::mechanism::call::Span,
    AbiStr,
    Blob,
    Field,
    busbar_contract::abi::auth::NamedValue,
    busbar_contract::abi::store::UsageCell,
    busbar_contract::abi::export::CheckInstance,
);

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
    busbar_contract::abi::mechanism::lifecycle::ValidateIn => settings,
    busbar_contract::abi::mechanism::lifecycle::OpenIn => settings,
    busbar_contract::abi::mechanism::lifecycle::RefreshIn => settings,
    busbar_contract::abi::plane::PlaneOpenIn => open.settings,
    busbar_contract::abi::secret::CheckIn => settings,
);

/// A test input whose pointers borrow memory for `'a` or name backing held by the `TestIn` itself. Only this module constructs it; safe typed crossings validate that backing.
///
///
#[derive(Debug)]
pub struct TestIn<'a, I> {
    pub(crate) input: I,
    /// Lists the builders made (strings, payloads, fields over borrowed bytes), each on the heap
    /// and never moved, freed with the `TestIn`.
    pub(crate) held: Vec<Box<dyn Any>>,
    /// Every pointer and length the builders set together: `(pointer's offset,
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
    fn pairs() -> Vec<(usize, usize, usize)> {
        busbar_contract::abi::sdk::test_support::lent_pairs(std::any::TypeId::of::<I>())
    }

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

    pub(crate) fn check(&self) {
        let word = size_of::<usize>();
        let mut pairs = Self::pairs();
        pairs.extend(self.lent.iter().map(|e| (e.0, e.1, e.2)));
        for (p, n, w) in pairs {
            let now = (self.read(p, word), self.read(n, w));
            let set = match self.lent.iter().find(|e| e.0 == p) {
                Some(e) => (e.3, e.4),

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
    #[must_use]
    pub fn new() -> Self {
        Self {
            input: zeroed(),
            held: Vec::new(),
            lent: Vec::new(),
            _lent: PhantomData,
        }
    }

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

    fn record(&mut self, ptr: usize, len: usize, width: usize) {
        let word = size_of::<usize>();
        let stated = (self.read(ptr, word), self.read(len, width));
        self.lent.retain(|e| e.0 != ptr);
        self.lent.push((ptr, len, width, stated.0, stated.1));
    }

    fn put<F>(&mut self, pick: impl FnOnce(&I) -> &F, value: F) {
        let at = Self::offset(pick);
        self.put_at(at, value);
    }

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

    #[must_use]
    pub fn string(mut self, pick: impl FnOnce(&I) -> &AbiStr, bytes: &'a [u8]) -> Self {
        let at = Self::offset(pick);
        self.put_at(at, lend_str(bytes));
        self.record(at, at + size_of::<usize>(), size_of::<usize>());
        self
    }

    #[must_use]
    pub fn blob(mut self, pick: impl FnOnce(&I) -> &Blob, bytes: &'a [u8], fmt: u32) -> Self {
        let at = Self::offset(pick);
        self.put_at(at, lend_blob(bytes, fmt));
        self.record(at, at + size_of::<usize>(), size_of::<usize>());
        self
    }

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
    #[must_use]
    pub fn settings(mut self, json: &'a [u8]) -> Self {
        let field = ptr::from_mut(self.input.settings_field()) as usize;
        let at = field - ptr::from_ref(&self.input) as usize;
        self.put_at(at, lend_blob(json, BLOB_JSON));
        self.record(at, at + size_of::<usize>(), size_of::<usize>());
        self
    }
}

fn lend_str(bytes: &[u8]) -> AbiStr {
    // SAFETY: every caller stores the string in a `TestIn` whose `'a` the bytes are borrowed for
    // (or in a list that `TestIn` holds), so they outlive every read the slot makes during the
    // call the `TestIn` is lent to.
    unsafe { AbiStr::from_raw_parts(bytes.as_ptr(), bytes.len()) }
}

fn lend_blob(bytes: &[u8], fmt: u32) -> Blob {
    // SAFETY: as `lend_str`.
    unsafe { Blob::from_raw_parts(bytes.as_ptr(), bytes.len(), fmt, 0) }
}
