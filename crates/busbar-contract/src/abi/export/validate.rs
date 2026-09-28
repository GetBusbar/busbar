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
use crate::abi::mechanism::call::{Blob, OutHead, Outcome, RawOutcome};
use crate::abi::mechanism::check::fault;

/// The largest blob or `needed` one answer may state, in bytes (16 MiB).
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The most entries `serve`'s `headers_out` may carry: 64 headers, as (name, value) pairs.
pub const HARD_MAX_HEADERS_OUT_LEN: u64 = 128;

/// A blob: a length above zero never comes with a NULL pointer, and never exceeds
/// [`HARD_MAX_BYTES`]. `null` and `over` name the two arms.
fn check_blob(null: &'static str, over: &'static str, b: &Blob) -> Result<(), Fault> {
    if b.len > 0 && b.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, null));
    }
    if b.len as u64 > HARD_MAX_BYTES {
        return Err(fault(Rule::OverMax, over));
    }
    Ok(())
}

/// On READY, a lease is required exactly when the answer carries material; `missing` and
/// `spurious` name the two arms. Other outcomes carry no lease rule.
fn check_lease(
    missing: &'static str,
    spurious: &'static str,
    outcome: RawOutcome,
    lease: u64,
    has_material: bool,
) -> Result<(), Fault> {
    if outcome.0 != (Outcome::Ready as u8) {
        return Ok(());
    }
    if has_material && lease == 0 {
        return Err(fault(Rule::Missing, missing));
    }
    if !has_material && lease != 0 {
        return Err(fault(Rule::Contradiction, spurious));
    }
    Ok(())
}

/// `scrape`'s `written`/`needed` pair against the capacity the host gave, under the short-buffer
/// rule: `written <= cap`; a non-zero `needed` only on FAILED, with nothing written, within
/// `u32::MAX` and [`HARD_MAX_BYTES`], and above `cap`.
fn check_written_needed(
    cap: usize,
    written: usize,
    needed: usize,
    failed: bool,
) -> Result<(), Fault> {
    if written > cap {
        return Err(fault(Rule::OverCap, "scrape.written"));
    }
    if written > 0 && needed != 0 {
        return Err(fault(Rule::WrittenOnShort, "scrape.written_on_short"));
    }
    if needed != 0 {
        if !failed {
            return Err(fault(Rule::NeededNotFailed, "scrape.needed"));
        }
        if needed as u64 > u32::MAX as u64 {
            return Err(fault(Rule::OverMax, "scrape.needed_u32"));
        }
        if needed as u64 > HARD_MAX_BYTES {
            return Err(fault(Rule::OverMax, "scrape.needed_max"));
        }
        if needed <= cap {
            return Err(fault(Rule::WastedRecall, "scrape.needed_within_cap"));
        }
    }
    Ok(())
}

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
    let failed = out.head.outcome.0 == (Outcome::Failed as u8);
    check_written_needed(cap, out.written, out.needed, failed)
}

/// Validates `status`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_status(out: &StatusOut) -> Result<(), Fault> {
    check_blob("status.status", "status.status.len", &out.status)?;
    check_lease(
        "status.lease",
        "status.lease_without_material",
        out.head.outcome,
        out.head.lease,
        out.status.len > 0,
    )
}

/// Validates `check`'s `out`.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_check(out: &CheckOut) -> Result<(), Fault> {
    check_blob("check.findings", "check.findings.len", &out.findings)?;
    check_lease(
        "check.lease",
        "check.lease_without_material",
        out.head.outcome,
        out.head.lease,
        out.findings.len > 0,
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
    check_blob("serve.body", "serve.body.len", &out.body)?;
    check_lease(
        "serve.lease",
        "serve.lease_without_material",
        out.head.outcome,
        out.head.lease,
        out.headers_out_len > 0 || out.body.len > 0,
    )
}

#[cfg(test)]
#[path = "../tests/export_validate_tests.rs"]
mod tests;
