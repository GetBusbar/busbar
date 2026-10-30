// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S ANSWER VALIDATOR, beside the shapes it judges: one pure `check_<op>`, `u64`
//! math, no statics, answering the shared [`Fault`] (one [`Rule`] and one distinct field per arm).
//! The dispatcher turns an `Err` into FAULT; no host re-implements a check.
//!
//! Per outcome: the secret blob's pointer/length pairing, its size and the `error_kind` range are
//! judged on every outcome (a PENDING or REFUSED `out` the host zeroed passes them). No answer
//! carries a lease: the material is in the HOST'S buffer (the credential chip, row 6: host-owned secret bytes). READY states no
//! `error_kind` and names at least one byte, flagged [`BLOB_SECRET`], at the start of that buffer,
//! within its capacity; FAILED carries no
//! material and either names its `error_kind` or is the short-buffer answer (M-SB: `needed` above
//! the capacity, `error_kind` unset).

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{ResolveOut, ERROR_KIND_INTERNAL, ERROR_KIND_UNSET, MAX_SECRET_BYTES};
use crate::abi::mechanism::call::{Outcome, BLOB_SECRET};
use crate::abi::mechanism::check::{blob, fault, result, Filled};

/// Validates `resolve`'s `out` against the host buffer the call was lent: its address `buf` and
/// capacity `cap` (`ResolveIn::secret_buf`/`secret_cap`). Pure, `u64` math, no statics.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_resolve(out: &ResolveOut, buf: usize, cap: u64) -> Result<(), Fault> {
    blob(&out.secret, "resolve.secret", "resolve.secret.len")?;
    if out.error_kind as u64 > ERROR_KIND_INTERNAL as u64 {
        return Err(fault(Rule::UnknownCode, "resolve.error_kind"));
    }
    // The material is the host's: a lease names plugin memory, which a resolve no longer keeps.
    if out.head.lease != 0 {
        return Err(fault(Rule::Contradiction, "resolve.lease"));
    }
    let outcome = out.head.outcome.outcome();
    let ready = matches!(outcome, Outcome::Ready);
    let failed = matches!(outcome, Outcome::Failed);
    if ready && out.error_kind != ERROR_KIND_UNSET {
        return Err(fault(Rule::Contradiction, "resolve.error_kind_on_ready"));
    }
    // A secret-bearing answer is secret on the host side whatever its flags say: a FAILED answer
    // carries no material at all.
    if failed && !out.secret.ptr.is_null() {
        return Err(fault(Rule::Contradiction, "resolve.secret_on_failed"));
    }
    let written = if ready { out.secret.len as u64 } else { 0 };
    match result(
        outcome,
        written,
        out.needed,
        cap,
        // The kind's own cap, below the mechanism's hard max (which `blob` holds `len` to).
        MAX_SECRET_BYTES as u64,
        "resolve.needed",
    )? {
        Filled::Short => {
            if out.error_kind != ERROR_KIND_UNSET {
                return Err(fault(Rule::Contradiction, "resolve.error_kind_on_short"));
            }
        }
        Filled::Written => {
            if failed && out.error_kind == ERROR_KIND_UNSET {
                return Err(fault(Rule::Missing, "resolve.error_kind_on_failed"));
            }
            // READY material starts at the host's buffer: any other address is memory the host
            // never lent, and would have to be copied and released.
            if written > 0 && out.secret.ptr as usize != buf {
                return Err(fault(Rule::Foreign, "resolve.secret_outside_buffer"));
            }
            // A READY resolve IS its material: none is no secret (fail-closed, never resolved
            // empty), and what it names is secret on the host side, so it says so.
            if ready && written == 0 {
                return Err(fault(Rule::Missing, "resolve.secret_on_ready"));
            }
            if ready && out.secret.flags & BLOB_SECRET == 0 {
                return Err(fault(Rule::Missing, "resolve.secret.flags"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/secret_validate_tests.rs"]
mod tests;
