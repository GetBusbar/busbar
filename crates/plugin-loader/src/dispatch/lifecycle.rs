// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, BLOB_ABSENT, BLOB_JSON,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, ReleaseIn, ValidateIn,
};

use super::{in_head, out_head, Called, Frame, Kind, Plugin, NO_BLOB};

/// A string the host lends for a call.
pub(crate) fn lend(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// A string the host lends for a call; empty is absent (NULL).
pub(crate) fn lend_or_null(s: &str) -> AbiStr {
    AbiStr {
        ptr: if s.is_empty() {
            std::ptr::null()
        } else {
            s.as_ptr()
        },
        len: s.len(),
    }
}

/// An optional string the host lends; `None` is absent (NULL).
pub(crate) fn lend_opt(s: Option<&str>) -> AbiStr {
    s.map_or(
        AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        lend,
    )
}

/// Bytes the host lends for a call, as a blob of `fmt` with `flags`; empty is absent.
pub(crate) fn blob(b: &[u8], fmt: u32, flags: u32) -> Blob {
    if b.is_empty() {
        return NO_BLOB;
    }
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

/// A plugin-owned blob's bytes, copied (the dispatcher's checks bounded them).
pub(crate) fn copy_blob(b: Blob) -> Vec<u8> {
    if b.len == 0 || b.ptr.is_null() || b.fmt == BLOB_ABSENT {
        return Vec::new();
    }
    // SAFETY: a checked plugin-owned blob, live under its lease until `release`.
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
}

/// A plugin's error text, or the outcome's name.
pub(crate) fn why(outcome: Outcome, error: Option<Vec<u8>>) -> String {
    error.map_or_else(
        || format!("{outcome:?}"),
        |e| String::from_utf8_lossy(&e).into_owned(),
    )
}

/// A plugin's error text, lossily UTF-8; empty is none.
pub(crate) fn text(error: Option<Vec<u8>>) -> Option<String> {
    error
        .map(|e| String::from_utf8_lossy(&e).into_owned())
        .filter(|t| !t.is_empty())
}

/// An `open` `in` over `settings`, lending no secrets; set `secrets`/`secrets_len` for a door
/// that is handed material.
pub(crate) fn open_in(settings: Blob) -> OpenIn {
    OpenIn {
        head: in_head(),
        host: std::ptr::null(),
        settings,
        secrets: std::ptr::null(),
        secrets_len: 0,
        generation: 1,
        err_buf: std::ptr::null_mut(),
        err_cap: 0,
    }
}

/// A fresh `open` `out`.
pub(crate) fn open_out() -> OpenOut {
    OpenOut {
        head: out_head(),
        instance: std::ptr::null_mut(),
        err_len: 0,
    }
}

/// An `open` frame over `settings`, lending no secrets.
pub(crate) fn open_frame(settings: Blob) -> Frame<OpenIn, OpenOut> {
    Frame::new(open_in(settings), open_out())
}

/// A `validate` frame over `settings`; the dispatcher lends the reason buffer at the crossing.
pub(crate) fn validate_frame(settings: Blob) -> Frame<ValidateIn, OutHead> {
    Frame::new(
        ValidateIn {
            head: in_head(),
            settings,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    )
}

/// `validate` `settings` on `plugin` (ticket-less; it never pends).
pub(crate) fn validate_call<K: Kind>(plugin: &Plugin<K>, settings: Blob) -> Called {
    plugin.call(life::VALIDATE, &mut validate_frame(settings))
}

/// `validate` JSON `settings` on `plugin` (ticket-less; it never pends): `Ok` when READY, else the
/// plugin's words (the outcome's name when it wrote none).
pub(crate) fn validate_json<K: Kind>(plugin: &Plugin<K>, settings: &[u8]) -> Result<(), String> {
    let c = validate_call(plugin, blob(settings, BLOB_JSON, 0));
    match c.outcome {
        Outcome::Ready => Ok(()),
        o => Err(text(c.error).unwrap_or_else(|| format!("{o:?}"))),
    }
}

/// Hand a lease back (ticket-less; a release never pends). `0` is none.
pub(crate) fn release<K: Kind>(plugin: &Plugin<K>, lease: u64) {
    if lease == 0 {
        return;
    }
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    let _ = plugin.call(life::RELEASE, &mut f);
}

/// `close` `plugin` (ticket-less).
pub(crate) fn close<K: Kind>(plugin: &Plugin<K>) {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    let _ = plugin.call(life::CLOSE, &mut f);
}
