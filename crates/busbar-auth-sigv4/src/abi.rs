// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOUNDARY: every raw pointer this plugin reads or writes, in one module.
//!
//! The auth kind has no typed SDK wrapper yet (KERNEL<>PLUGINS ABI-b3, `busbar-contract/src/abi/sdk/`),
//! so the reads of the host's `in` structs, the writes into the host's field buffer, the instance
//! pointer and the host tables are done here, each `unsafe` block stating the contract it relies
//! on. Everything outside this module is safe code. When ABI-b3 lands the auth wrappers, this module
//! is what moves into `abi/sdk/` and the crate becomes `#![forbid(unsafe_code)]` (BUSBAR-1.6.0.md THE DESIGN, §2).

#![allow(unsafe_code)]

use std::ffi::c_void;

use busbar_contract::abi::auth::{FieldSpan, FieldsIn, FieldsOut};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_ABSENT};

/// Borrowed bytes of an [`AbiStr`] the host handed in for this call; `None` when absent.
pub(crate) fn text(s: &AbiStr) -> Option<&str> {
    if s.ptr.is_null() {
        return None;
    }
    // SAFETY: a non-NULL `AbiStr` in a host `in` addresses `len` readable bytes for the call (the
    // mechanism's call convention); the borrow does not outlive the `in` it was read from.
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    std::str::from_utf8(bytes).ok()
}

/// Borrowed bytes of a [`Blob`] the host handed in for this call; `None` when absent.
pub(crate) fn blob(b: &Blob) -> Option<&[u8]> {
    if b.ptr.is_null() || b.fmt == BLOB_ABSENT {
        return None;
    }
    // SAFETY: a present `Blob` in a host `in` addresses `len` readable bytes for the call.
    Some(unsafe { std::slice::from_raw_parts(b.ptr, b.len) })
}

/// An [`AbiStr`] over bytes this plugin holds.
pub(crate) fn abi(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The instance behind the pointer `open` answered.
pub(crate) fn instance<'a, T>(p: *mut c_void) -> Option<&'a T> {
    // SAFETY: a non-NULL instance pointer is the `Box::into_raw` of this plugin's `open`, live until
    // `close` (the host never calls an instance after `close`).
    unsafe { p.cast::<T>().as_ref() }
}

/// Hand `value` to the host as the instance pointer.
pub(crate) fn into_instance<T>(value: Box<T>) -> *mut c_void {
    Box::into_raw(value).cast()
}

/// Take the instance back at `close` and drop it.
pub(crate) fn drop_instance<T>(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: `close` is the instance's last call; the pointer came from `into_instance`.
    drop(unsafe { Box::from_raw(p.cast::<T>()) });
}

/// Write `fields` into the host's field buffer and array (`FieldsIn::field_buf`/`fields`) under
/// the SHORT-BUFFER rule: when they do not fit, write nothing and answer FAILED with the FULL sizes.
pub(crate) fn write_fields(
    input: &FieldsIn,
    out: &mut FieldsOut,
    fields: &[(&str, &str)],
    flags: u32,
) -> Outcome {
    let bytes: usize = fields.iter().map(|(n, v)| n.len() + v.len()).sum();
    let count = fields.len();
    let fits = count <= input.fields_cap as usize
        && bytes <= input.field_buf_cap
        && (count == 0 || (!input.fields.is_null() && !input.field_buf.is_null()));
    if !fits {
        out.needed_fields = u32::try_from(count).unwrap_or(u32::MAX);
        out.needed_bytes = bytes as u64;
        return Outcome::Failed;
    }
    let mut at = 0_usize;
    for (i, (name, value)) in fields.iter().enumerate() {
        let name_span = put(input, &mut at, name.as_bytes());
        let value_span = put(input, &mut at, value.as_bytes());
        let span = FieldSpan {
            name: name_span,
            value: value_span,
            flags,
            _reserved: 0,
        };
        // SAFETY: `fields` addresses `fields_cap >= count > i` writable spans for the call.
        unsafe { input.fields.add(i).write_unaligned(span) };
    }
    out.fields_len = count as u32;
    Outcome::Ready
}

/// Copy `b` into the host's field buffer at `*at`, answering its span.
fn put(input: &FieldsIn, at: &mut usize, b: &[u8]) -> Span {
    let span = Span {
        offset: *at as u32,
        len: b.len() as u32,
    };
    // SAFETY: `write_fields` checked the whole write fits `field_buf_cap`, and `field_buf` addresses
    // that many writable bytes for the call; `b` is this plugin's own memory, not overlapping it.
    unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), input.field_buf.add(*at), b.len()) };
    *at += b.len();
    span
}

/// An all-zero `in` (the unit tests build frames as a host does).
#[cfg(test)]
pub(crate) fn zeroed_in<T: busbar_contract::abi::sdk::door::AbiIn>() -> T {
    // SAFETY: `AbiIn` promises every bit pattern, all-zero included, is a valid value.
    unsafe { std::mem::zeroed() }
}

/// An all-zero `out`.
#[cfg(test)]
pub(crate) fn zeroed_out<T: busbar_contract::abi::sdk::door::AbiOut>() -> T {
    // SAFETY: `AbiOut` promises every bit pattern, all-zero included, is a valid value.
    unsafe { std::mem::zeroed() }
}
