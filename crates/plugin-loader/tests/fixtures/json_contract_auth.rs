// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(unsafe_code)]

use std::ffi::c_void;

const TRANSPORT_VERSION: u32 = 1;

const STATUS_ERR: i32 = 1;

#[no_mangle]
pub extern "C-unwind" fn busbar_abi() -> u32 {
    TRANSPORT_VERSION
}

#[no_mangle]
pub extern "C-unwind" fn busbar_plugin_kind() -> *const u8 {
    c"auth".as_ptr().cast()
}

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

#[no_mangle]
pub extern "C-unwind" fn busbar_free(_ptr: *mut u8, _len: usize) {}

#[no_mangle]
pub extern "C-unwind" fn busbar_close(_handle: *mut c_void) {}
