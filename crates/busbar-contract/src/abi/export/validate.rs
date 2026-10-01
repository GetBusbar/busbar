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

use super::{CheckOut, ScrapeOut, ServeOut, StatusOut};
use crate::abi::mechanism::call::{OutHead, Outcome};
use crate::abi::mechanism::check::{blob, fault, lease, result, HARD_MAX_BYTES};

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

#[cfg(test)]
#[path = "../tests/export_validate_tests.rs"]
mod tests;
