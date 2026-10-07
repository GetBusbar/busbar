// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.5.5-SHAPED PLUGIN: an `auth` library on the JSON contract alone. It exports the frozen
//! symbols a 1.5.5 plugin exported (`busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`,
//! `busbar_free`, `busbar_close`) and NO `busbar_plugin_door`. The subject of the loader's
//! no-legacy-loading arm (THE DESIGN §11.8, ruling C21/ABI-o1): the upload vet, the plugins inventory
//! and the kind gate classify it by its kind symbol only to REFUSE it, naming the rebuild.
//!
//! Self-contained on purpose: it names no `busbar-contract` item, so the contract's own copy of these
//! symbols (the SDK's door-backed ones) is never linked in and the six below are the library's.
//! Every symbol is a stub that refuses: nothing here may ever run as a plugin. An example, not a
//! crate: `cargo test` builds it and it never ships.

#![allow(unsafe_code)]

use std::ffi::c_void;

/// The 1.5.5 transport version (`busbar_contract::abi::cold::TRANSPORT_VERSION`, frozen at 1).
const TRANSPORT_VERSION: u32 = 1;
/// The 1.5.5 error status.
const STATUS_ERR: i32 = 1;

/// The plugin-ABI handshake a 1.5.5 plugin answered.
#[no_mangle]
pub extern "C-unwind" fn busbar_abi() -> u32 {
    TRANSPORT_VERSION
}

/// The ONE kind this 1.5.5 library speaks.
#[no_mangle]
pub extern "C-unwind" fn busbar_plugin_kind() -> *const u8 {
    c"auth".as_ptr().cast()
}

/// Refuses: no instance is ever made.
#[no_mangle]
pub extern "C-unwind" fn busbar_open(
    _cfg: *const u8,
    _cfg_len: usize,
    _out_handle: *mut *mut c_void,
    _out_err: *mut *mut u8,
    _out_err_len: *mut usize,
) -> i32 {
    STATUS_ERR
}

/// Refuses: there is no instance to call.
#[no_mangle]
pub extern "C-unwind" fn busbar_call(
    _handle: *mut c_void,
    _req: *const u8,
    _req_len: usize,
    _out: *mut *mut u8,
    _out_len: *mut usize,
) -> i32 {
    STATUS_ERR
}

/// Nothing is ever allocated.
#[no_mangle]
pub extern "C-unwind" fn busbar_free(_ptr: *mut u8, _len: usize) {}

/// Nothing is ever opened.
#[no_mangle]
pub extern "C-unwind" fn busbar_close(_handle: *mut c_void) {}
