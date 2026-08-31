// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! P0 SPIKE cdylib — a `govern_admit` reached across a real `dlopen` boundary, to measure the PLT
//! delta of the repr(C) POD host-call versus the in-process fn-pointer proxy in `plane-abi-spike`.
//!
//! This crate shares NO Rust types with the host: it re-declares the frozen `#[repr(C)]`
//! `Facts`/`Decision` layout, which IS the ABI. The exported symbol is `extern "C-unwind"` with a
//! `#[no_mangle]` stable name the bench looks up.

/// Mirror of the frozen ABI `Facts` layout (see `plane-abi-spike::Facts`).
#[repr(C)]
pub struct Facts {
    pub size: u32,
    pub version: u16,
    pub _reserved: u16,
    pub tokens: u64,
    pub budget_remaining: u64,
    pub tenant_id: u64,
    pub priority: u32,
    pub flags: u32,
    pub pool_name_ptr: *const u8,
    pub pool_name_len: usize,
}

/// Mirror of the frozen ABI `Decision` layout.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Deny = 0,
    Admit = 1,
    Throttle = 2,
}

const ABI_VERSION: u16 = 1;

/// The exported host-call. Same kernel as the in-core baseline, reached via the process PLT.
///
/// # Safety
/// `f` must point to a live `Facts` whose borrowed pool-name range is live and initialized.
// Exported ABI seam: a plain `extern "C-unwind" fn(*const Facts)`; deref contract documented above.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C-unwind" fn spike_govern_admit(f: *const Facts) -> Decision {
    // SAFETY: contract above upheld by the caller.
    let f = unsafe { &*f };
    if f.size < core::mem::size_of::<Facts>() as u32 || f.version != ABI_VERSION {
        return Decision::Deny;
    }
    if f.tokens > f.budget_remaining {
        return Decision::Deny;
    }
    // SAFETY: borrowed range live per the contract.
    let name = if f.pool_name_ptr.is_null() || f.pool_name_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(f.pool_name_ptr, f.pool_name_len) }
    };
    let mut fold: u32 = f.priority ^ (f.tenant_id as u32);
    for &b in name {
        fold = fold.rotate_left(5) ^ (b as u32);
    }
    let trusted = f.flags & 1 != 0;
    let headroom = f.budget_remaining - f.tokens;
    if trusted || headroom >= f.tokens {
        Decision::Admit
    } else if fold & 1 == 0 {
        Decision::Throttle
    } else {
        Decision::Deny
    }
}
