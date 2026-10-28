// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S ANSWER VALIDATOR, beside the shapes it judges: one pure `check_<op>`, `u64`
//! math, no statics, answering the shared [`Fault`] (one [`Rule`] and one distinct field per arm).
//! The dispatcher turns an `Err` into FAULT; no host re-implements a check.
//!
//! Per outcome: the secret blob's pointer/length pairing, its size and the `error_kind` range are
//! judged on every outcome (a PENDING or REFUSED `out` the host zeroed passes them). No answer
//! carries a lease: the material is in the HOST'S buffer (the credential chip, row 6: host-owned secret bytes). READY states no
//! `error_kind` and names bytes at the start of that buffer, within its capacity; FAILED carries no
//! material and either names its `error_kind` or is the short-buffer answer (M-SB: `needed` above
//! the capacity, `error_kind` unset).

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{ResolveOut, ERROR_KIND_INTERNAL, ERROR_KIND_UNSET};
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::check::{fault, result, Filled, HARD_MAX_BYTES};
use crate::abi::mechanism::decl::abi_op;

abi_op! {
    /// Validates `resolve`'s `out` against the host buffer the call was lent: its address `buf` and
    /// capacity `cap` (`ResolveIn::secret_buf`/`secret_cap`). Pure, `u64` math, no statics.
    ///
    /// # Errors
    /// The rule `out` breaks.
    pub fn check_resolve(out: &ResolveOut, buf: usize, cap: u64) as "resolve", RESOLVE_RULES {
        blob(secret);
        code(error_kind, ERROR_KIND_UNSET, ERROR_KIND_INTERNAL);
        // The material is the host's: a lease names plugin memory, which a resolve no longer keeps.
        zero(head.lease, Contradiction) as "resolve.lease";
        then resolved(out, buf, cap);
    }
}

/// `resolve`'s cross-field rules, after its per-field ones: the outcome against `error_kind`, the
/// material and the short-buffer answer.
fn resolved(out: &ResolveOut, buf: usize, cap: u64) -> Result<(), Fault> {
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
        HARD_MAX_BYTES,
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
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/secret_validate_tests.rs"]
mod tests;
