// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::mem::MaybeUninit;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};

use crate::dispatch::{in_head, out_head, Called, Frame, InFrame, Kind, OutFrame, Plugin};

pub(crate) fn octets(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

pub(crate) fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, floats, raw pointers and unions of those, for
    // which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

pub(crate) fn output<T: OutFrame>() -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe {
        std::ptr::addr_of_mut!(v)
            .cast::<OutHead>()
            .write(out_head())
    };
    v
}

pub(crate) fn open<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    o.input.settings = octets(settings);
    o.input.generation = 1;
    p.call(slot::OPEN, &mut o)
}

pub(crate) fn close<K: Kind>(p: &Plugin<K>) -> Called {
    let mut c: Frame<InHead, OutHead> = Frame::new(input(), output());
    p.call(slot::CLOSE, &mut c)
}

pub(crate) fn line(step: &str, c: &Called) -> String {
    let error = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{step}: {:?} lease={} error={error:?}", c.outcome, c.lease)
}
