// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, BLOB_ABSENT, BLOB_JSON,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, ReleaseIn, ValidateIn,
};

use super::{in_head, out_head, Called, Frame, Kind, Plugin, NO_BLOB};

pub(crate) struct AnswerLease<'a, K: Kind> {
    plugin: &'a Plugin<K>,
    lease: u64,
}

impl<'a, K: Kind> AnswerLease<'a, K> {
    pub(crate) fn new(plugin: &'a Plugin<K>, lease: u64) -> Self {
        Self { plugin, lease }
    }
}

impl<K: Kind> Drop for AnswerLease<'_, K> {
    fn drop(&mut self) {
        release(self.plugin, self.lease);
    }
}

pub(crate) fn lend(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

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

pub(crate) fn lend_opt(s: Option<&str>) -> AbiStr {
    s.map_or(
        AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        lend,
    )
}

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

pub(crate) fn copy_blob(b: Blob) -> Vec<u8> {
    if b.len == 0 || b.ptr.is_null() || b.fmt == BLOB_ABSENT {
        return Vec::new();
    }
    // SAFETY: a checked plugin-owned blob, live under its lease until `release`.
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
}

pub(crate) fn why(outcome: Outcome, error: Option<Vec<u8>>) -> String {
    error.map_or_else(
        || format!("{outcome:?}"),
        |e| String::from_utf8_lossy(&e).into_owned(),
    )
}

pub(crate) fn text(error: Option<Vec<u8>>) -> Option<String> {
    error
        .map(|e| String::from_utf8_lossy(&e).into_owned())
        .filter(|t| !t.is_empty())
}

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

pub(crate) fn open_out() -> OpenOut {
    OpenOut {
        head: out_head(),
        instance: std::ptr::null_mut(),
        err_len: 0,
    }
}

pub(crate) fn open_frame(settings: Blob) -> Frame<OpenIn, OpenOut> {
    Frame::new(open_in(settings), open_out())
}

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

pub(crate) fn validate_call<K: Kind>(plugin: &Plugin<K>, settings: Blob) -> Called {
    plugin.call(life::VALIDATE, &mut validate_frame(settings))
}

pub(crate) fn validate_json<K: Kind>(plugin: &Plugin<K>, settings: &[u8]) -> Result<(), String> {
    let c = validate_call(plugin, blob(settings, BLOB_JSON, 0));
    let _lease = AnswerLease::new(plugin, c.lease);
    match c.outcome {
        Outcome::Ready => Ok(()),
        o => Err(text(c.error).unwrap_or_else(|| format!("{o:?}"))),
    }
}

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

pub(crate) fn close<K: Kind>(plugin: &Plugin<K>) {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    let _ = plugin.call(life::CLOSE, &mut f);
}
