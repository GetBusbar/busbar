// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S ANSWER VALIDATORS, beside the shapes they judge: one pure `check_<op>` per
//! answer, `u64` math, no statics, each answering the shared [`Fault`] (one [`Rule`] and one
//! distinct field per arm). The dispatcher turns an `Err` into FAULT; no host re-implements a
//! check.
//!
//! Per outcome: a blob's or list's pointer/length pairing and its size are judged on every outcome
//! (a PENDING or REFUSED `out` the host zeroed passes them). A lease (memory class iv) is judged on
//! READY only: required exactly when the answer carries material. `scrape` is the one op with a
//! short path: its `needed` is non-zero only on FAILED, under the short-buffer rule
//! ([`OutHead`](crate::abi::mechanism::call::OutHead)).

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{CheckOut, ExportStream, Route, ScrapeOut, ServeOut, StatusOut, Tail};
use super::{ROUTE_AUTH_ADMIN, ROUTE_AUTH_NONE};
use crate::abi::mechanism::call::OutHead;
use crate::abi::mechanism::check::{
    code, failed_error, fault, leased_blob, listed, result, served, text, HARD_MAX_BYTES,
};

/// The most entries `serve`'s `headers_out` may carry: 64 headers, as (name, value) pairs.
pub const HARD_MAX_HEADERS_OUT_LEN: u64 = 128;

/// Validates `deliver`'s `out` (the shared [`OutHead`]; `deliver` reads nothing back beyond it).
/// A FAILED answer's error text is judged; other outcomes state nothing here.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_deliver(out: &OutHead) -> Result<(), Fault> {
    failed_error(out, "deliver.error")
}

/// Validates `scrape`'s `out` against the capacity [`super::ScrapeIn::cap`] gave the plugin.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_scrape(out: &ScrapeOut, cap: usize) -> Result<(), Fault> {
    result(
        out.head.outcome.outcome(),
        out.written as u64,
        out.needed as u64,
        cap as u64,
        HARD_MAX_BYTES,
        "scrape.bytes",
    )?;
    Ok(())
}

/// Validates `status`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_status(out: &StatusOut) -> Result<(), Fault> {
    leased_blob!(out, "status", status)
}

/// Validates `check`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_check(out: &CheckOut) -> Result<(), Fault> {
    leased_blob!(out, "check", findings)
}

/// Validates `serve`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_serve(out: &ServeOut) -> Result<(), Fault> {
    let (h, n) = (out.headers_out, out.headers_out_len);
    served(&out.head, h, n, HARD_MAX_HEADERS_OUT_LEN, &out.body)
}

/// The most routes one export instance may declare.
pub const HARD_MAX_ROUTES: u64 = 64;

/// Validates the export Statement tail's lists, before any entry is read: a count never comes
/// with a NULL pointer, `streams` holds at most one of each [`ExportStream`], and `routes` at most
/// [`HARD_MAX_ROUTES`]. The loader checks the entries with [`check_tail_entries`].
///
/// # Errors
/// The rule the tail breaks.
pub fn check_tail(t: &Tail) -> Result<(), Fault> {
    listed(t.streams, t.streams_len, "tail.streams")?;
    if t.streams_len as u64 > ExportStream::ALL.len() as u64 {
        return Err(fault(Rule::OverMax, "tail.streams_len"));
    }
    listed(t.routes, t.routes_len, "tail.routes")?;
    if t.routes_len as u64 > HARD_MAX_ROUTES {
        return Err(fault(Rule::OverMax, "tail.routes_len"));
    }
    Ok(())
}

/// Validates the export tail's ENTRIES, once [`check_tail`] passed: every stream byte is an
/// [`ExportStream`] and none repeats; every route names a path starting with `/`, a method, and a
/// `ROUTE_AUTH_*` code.
///
/// # Errors
/// The rule an entry breaks.
pub fn check_tail_entries(streams: &[u8], routes: &[Route]) -> Result<(), Fault> {
    for (i, s) in streams.iter().enumerate() {
        code(
            u64::from(*s),
            0,
            ExportStream::ALL.len() as u64 - 1,
            "tail.streams.code",
        )?;
        if streams[..i].contains(s) {
            return Err(fault(Rule::Contradiction, "tail.streams.repeat"));
        }
    }
    for r in routes {
        text(r.path, "tail.routes.path")?;
        text(r.method, "tail.routes.method")?;
        // SAFETY: `text` checked a non-empty path is not NULL; one byte is read.
        if r.path.len == 0 || unsafe { *r.path.ptr } != b'/' {
            return Err(fault(Rule::Missing, "tail.routes.path.root"));
        }
        if r.method.len == 0 {
            return Err(fault(Rule::Missing, "tail.routes.method.empty"));
        }
        code(
            u64::from(r.auth),
            u64::from(ROUTE_AUTH_NONE),
            u64::from(ROUTE_AUTH_ADMIN),
            "tail.routes.auth",
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/export_validate_tests.rs"]
mod tests;
