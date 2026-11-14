// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-built frames: zeroed `in`/`out` structs with their heads, and lent ranges.

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, OutHead, BLOB_JSON, BLOB_OCTETS,
};
use busbar_plugin_loader::dispatch::{in_head, out_head, InFrame, OutFrame};

/// A kind's `in`, all zero but its head.
pub fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, raw pointers, `Option<fn>` and nested plain
    // structs, for which all-zero is valid; `T: InFrame` leads with an `InHead`, written below.
    let mut v: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

/// A kind's `out`, all zero but its head (sized to `T`).
pub fn output<T: OutFrame>() -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe {
        std::ptr::addr_of_mut!(v).cast::<OutHead>().write(OutHead {
            size: size_of::<T>() as u32,
            ..out_head()
        })
    };
    v
}

pub fn octets(b: &[u8]) -> Blob {
    if b.is_empty() {
        return Blob::ABSENT;
    }
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

pub fn json(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

pub fn abi(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: if b.is_empty() {
            std::ptr::null()
        } else {
            b.as_ptr()
        },
        len: b.len(),
    }
}

/// Field descriptors over owned `(name, value)` pairs; the pairs must outlive the descriptors.
pub fn fields(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<Field> {
    pairs
        .iter()
        .map(|(n, v)| Field {
            name: abi(n),
            value: abi(v),
        })
        .collect()
}

pub fn pairs(list: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    list.iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}
