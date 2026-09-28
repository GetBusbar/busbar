// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ANSWER VALIDATORS FOR THE EXPORT KIND (ARCHITECT RULING, 2026-09-28, all kinds): "each kind's
//! Out-validation is a PURE fn in `abi/<kind>/` beside its shapes ... uses `u64` math, has no
//! statics, and ships RED tests, one per rule, each failing if its check is removed. M1's
//! dispatcher calls it; no host re-implements it." Nothing dispatches through this yet (M3-wire);
//! this is the validator M1 will call.

use super::{CheckOut, ScrapeOut, ServeOut, StatusOut};
use crate::abi::mechanism::call::{Blob, OutHead, Outcome};

/// Why a validator refused an `out` — FAULT, never a safe default
/// ([`Outcome::Fault`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault(pub &'static str);

/// The hard per-answer byte cap this kind's validators enforce. ASSUMPTION (M3-SHAPES): no
/// specific number is stated for export; 16 MiB matches the inbound cap set for a comparable
/// sans-IO backend (SANSIO-LDAP, `m3-inputs.md`'s OWNER SIGN-OFF batch).
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// A count > 0 with a NULL pointer is FAULT; a blob's `len` and `ptr` must agree the same way.
fn check_blob(field: &'static str, b: &Blob) -> Result<(), Fault> {
    if b.len > 0 && b.ptr.is_null() {
        return Err(Fault(field));
    }
    if b.len as u64 > HARD_MAX_BYTES {
        return Err(Fault(field));
    }
    Ok(())
}

/// Validates a `may_pend` request-path op's `written`/`needed` pair against the capacity the
/// plugin was given: "FAILED with a non-zero `needed_*` that is <= the given capacity is FAULT,
/// because it wastes the one re-call", and `needed_bytes <= u32::MAX` (and this kind's hard max).
fn check_written_needed(cap: usize, written: usize, needed: usize) -> Result<(), Fault> {
    if written > cap {
        return Err(Fault("written exceeds the given capacity"));
    }
    if written > 0 && needed != 0 {
        return Err(Fault(
            "a successful write must not also claim more is needed",
        ));
    }
    if written == 0 && needed != 0 {
        if needed as u64 > u32::MAX as u64 {
            return Err(Fault("needed exceeds u32::MAX"));
        }
        if needed as u64 > HARD_MAX_BYTES {
            return Err(Fault("needed exceeds the kind's hard max"));
        }
        if needed <= cap {
            return Err(Fault("needed <= the given capacity wastes the one re-call"));
        }
    }
    Ok(())
}

/// Validates `deliver`'s `out` (the shared [`OutHead`]; `deliver` reads nothing back beyond it).
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_deliver(out: &OutHead) -> Result<(), Fault> {
    if out.outcome.0 == (Outcome::Failed as u8) && out.error.len > 0 && out.error.ptr.is_null() {
        return Err(Fault("deliver: error.len > 0 with a NULL error.ptr"));
    }
    Ok(())
}

/// Validates `scrape`'s `out` against the capacity [`super::ScrapeIn::cap`] gave the plugin.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_scrape(out: &ScrapeOut, cap: usize) -> Result<(), Fault> {
    check_written_needed(cap, out.written, out.needed)
}

/// Validates `status`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_status(out: &StatusOut) -> Result<(), Fault> {
    check_blob(
        "status: status.len > 0 with a NULL status.ptr, or oversized",
        &out.status,
    )
}

/// Validates `check`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_check(out: &CheckOut) -> Result<(), Fault> {
    check_blob(
        "check: findings.len > 0 with a NULL findings.ptr, or oversized",
        &out.findings,
    )
}

/// Validates `serve`'s `out`.
///
/// # Errors
/// Returns [`Fault`] when `out` cannot be a legal answer.
pub fn check_serve(out: &ServeOut) -> Result<(), Fault> {
    if out.headers_out_len > 0 && out.headers_out.is_null() {
        return Err(Fault("serve: headers_out_len > 0 with a NULL headers_out"));
    }
    check_blob(
        "serve: body.len > 0 with a NULL body.ptr, or oversized",
        &out.body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::mechanism::call::{AbiStr, Envelope, RawOutcome};

    fn head(outcome: Outcome) -> OutHead {
        OutHead {
            size: 0,
            outcome: RawOutcome(outcome as u8),
            _reserved: [0; 3],
            wake_at_ns: 0,
            lease: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            envelope: Envelope {
                metrics: std::ptr::null(),
                metrics_len: 0,
                diags: std::ptr::null(),
                diags_len: 0,
            },
            extensions: Blob {
                ptr: std::ptr::null(),
                len: 0,
                fmt: 0,
                flags: 0,
            },
        }
    }

    fn blob_absent() -> Blob {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: 0,
            flags: 0,
        }
    }

    /// RED: `written` beyond the given capacity is FAULT.
    #[test]
    fn written_beyond_cap_faults() {
        assert_eq!(
            check_written_needed(4, 5, 0),
            Err(Fault("written exceeds the given capacity"))
        );
    }

    /// RED: a successful write also claiming `needed` is FAULT.
    #[test]
    fn written_and_needed_together_faults() {
        assert_eq!(
            check_written_needed(4, 2, 1),
            Err(Fault(
                "a successful write must not also claim more is needed"
            ))
        );
    }

    /// RED: `needed <= cap` when nothing was written wastes the one re-call.
    #[test]
    fn needed_not_larger_than_cap_faults() {
        assert_eq!(
            check_written_needed(4, 0, 4),
            Err(Fault("needed <= the given capacity wastes the one re-call"))
        );
    }

    /// RED: `needed` past the hard max is FAULT.
    #[test]
    fn needed_past_hard_max_faults() {
        assert_eq!(
            check_written_needed(0, 0, (HARD_MAX_BYTES + 1) as usize),
            Err(Fault("needed exceeds the kind's hard max"))
        );
    }

    /// The legitimate re-call shape passes: nothing written, `needed` bigger than `cap`.
    #[test]
    fn legitimate_too_small_answer_passes() {
        assert!(check_written_needed(4, 0, 8).is_ok());
    }

    /// RED: `scrape`'s `out` is checked against `cap`.
    #[test]
    fn scrape_out_checked_against_cap() {
        let out = ScrapeOut {
            head: head(Outcome::Ready),
            written: 10,
            needed: 0,
        };
        assert_eq!(
            check_scrape(&out, 4),
            Err(Fault("written exceeds the given capacity"))
        );
    }

    /// RED: `status`'s blob with a non-null-required NULL pointer is FAULT.
    #[test]
    fn status_null_with_len_faults() {
        let mut out = StatusOut {
            head: head(Outcome::Ready),
            status: blob_absent(),
        };
        out.status.len = 4;
        assert!(check_status(&out).is_err());
    }

    /// RED: `serve`'s `headers_out_len > 0` with a NULL pointer is FAULT.
    #[test]
    fn serve_headers_null_with_len_faults() {
        let out = ServeOut {
            head: head(Outcome::Ready),
            status_code: 200,
            _reserved: [0; 6],
            headers_out: std::ptr::null(),
            headers_out_len: 1,
            body: blob_absent(),
        };
        assert_eq!(
            check_serve(&out),
            Err(Fault("serve: headers_out_len > 0 with a NULL headers_out"))
        );
    }

    /// A well-formed `check` answer passes.
    #[test]
    fn check_out_absent_findings_passes() {
        let out = CheckOut {
            head: head(Outcome::Ready),
            findings: blob_absent(),
        };
        assert!(check_check(&out).is_ok());
    }

    /// A well-formed `deliver` answer passes.
    #[test]
    fn deliver_out_passes() {
        assert!(check_deliver(&head(Outcome::Ready)).is_ok());
    }
}
