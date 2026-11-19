// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Stating a Statement by hand: the borrowed string and the blank Statement a host test fills in.

use std::ptr;

use crate::abi::host::conn::connector::Need;
use crate::abi::mechanism::call::{AbiStr, Blob};
use crate::abi::mechanism::door::{
    KindTailHead, MarkWord, MetricFamily, Rewrite, Section, Statement,
};

/// Borrowed `'static` UTF-8 as an [`AbiStr`].
#[must_use]
pub const fn abi_str(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// A Statement naming the plugin, with no families, no diagnostic ids, no kind tail, no
/// rewrites, sections, needs or claims: the caller adds what the plugin declares.
#[must_use]
pub const fn statement(name: &'static str, version: &'static str, max_inflight: u32) -> Statement {
    Statement {
        max_inflight,
        name: abi_str(name),
        version: abi_str(version),
        families: ptr::null::<MetricFamily>(),
        diag_ids: ptr::null::<AbiStr>(),
        secret_refs: ptr::null::<AbiStr>(),
        settings_schema: Blob::ABSENT,
        kind_tail: ptr::null::<KindTailHead>(),
        extensions: Blob::ABSENT,
        mark_words: ptr::null::<MarkWord>(),
        rewrites: ptr::null::<Rewrite>(),
        sections: ptr::null::<Section>(),
        needs: ptr::null::<Need>(),
        target_from: ABSENT,
        trust_from: ABSENT,
        answers: ptr::null::<AbiStr>(),
        claims: ptr::null::<AbiStr>(),
        ..Statement::ZERO
    }
}

/// An absent string.
const ABSENT: AbiStr = AbiStr::ZERO;
