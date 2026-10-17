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
use crate::abi::mechanism::call::{OutHead, Outcome};
use crate::abi::mechanism::check::{
    blob, code, fault, lease, listed, result, text, HARD_MAX_BYTES,
};

/// The most entries `serve`'s `headers_out` may carry: 64 headers, as (name, value) pairs.
pub const HARD_MAX_HEADERS_OUT_LEN: u64 = 128;

/// Validates `deliver`'s `out` (the shared [`OutHead`]; `deliver` reads nothing back beyond it).
/// A FAILED answer's error text is judged; other outcomes state nothing here.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_deliver(out: &OutHead) -> Result<(), Fault> {
    if out.outcome.0 == (Outcome::Failed as u8) && out.error.len > 0 && out.error.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, "deliver.error"));
    }
    Ok(())
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
    blob(&out.status, "status.status", "status.status.len")?;
    lease(
        out.head.outcome,
        out.head.lease,
        out.status.len > 0,
        "status.lease",
        "status.lease_without_material",
    )
}

/// Validates `check`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_check(out: &CheckOut) -> Result<(), Fault> {
    blob(&out.findings, "check.findings", "check.findings.len")?;
    lease(
        out.head.outcome,
        out.head.lease,
        out.findings.len > 0,
        "check.lease",
        "check.lease_without_material",
    )
}

/// Validates `serve`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_serve(out: &ServeOut) -> Result<(), Fault> {
    if out.headers_out_len > 0 && out.headers_out.is_null() {
        return Err(fault(Rule::NullWithCount, "serve.headers_out"));
    }
    if out.headers_out_len as u64 > HARD_MAX_HEADERS_OUT_LEN {
        return Err(fault(Rule::OverMax, "serve.headers_out_len"));
    }
    blob(&out.body, "serve.body", "serve.body.len")?;
    lease(
        out.head.outcome,
        out.head.lease,
        out.headers_out_len > 0 || out.body.len > 0,
        "serve.lease",
        "serve.lease_without_material",
    )
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
