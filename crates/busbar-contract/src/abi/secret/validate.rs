// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S ANSWER VALIDATOR, beside the shapes it judges: one pure `check_<op>`, `u64`

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{ResolveOut, ERROR_KIND_INTERNAL, ERROR_KIND_UNSET, MAX_SECRET_BYTES};
use crate::abi::mechanism::call::{Outcome, BLOB_SECRET};
use crate::abi::mechanism::check::{fault, result, Filled};
use crate::abi::mechanism::decl::abi_op;

abi_op! {
    /// Validates `resolve`'s `out` against the host buffer the call was lent: its address `buf` and
    /// capacity `cap` (`ResolveIn::secret_buf`/`secret_cap`). Pure, `u64` math, no statics.
    ///
    /// # Errors
    /// The rule `out` breaks.
    pub fn check_resolve(out: &ResolveOut, buf: usize, cap: u64) as "resolve", RESOLVE_RULES for out: ResolveOut {
        blob(secret);
        code(error_kind, ERROR_KIND_UNSET, ERROR_KIND_INTERNAL);
        // The material is the host's: a lease names plugin memory, which a resolve no longer keeps.
        zero(head.lease, Contradiction) as "resolve.lease";
        then resolved(out, buf, cap);
    }
}

/// `resolve`'s cross-field rules, after its per-field ones: the outcome against `error_kind`, the
fn resolved(out: &ResolveOut, buf: usize, cap: u64) -> Result<(), Fault> {
    let outcome = out.head.outcome.outcome();
    let ready = matches!(outcome, Outcome::Ready);
    let failed = matches!(outcome, Outcome::Failed);
    if ready && out.error_kind != ERROR_KIND_UNSET {
        return Err(fault(Rule::Contradiction, "resolve.error_kind_on_ready"));
    }

    if failed && !out.secret.ptr.is_null() {
        return Err(fault(Rule::Contradiction, "resolve.secret_on_failed"));
    }
    let written = if ready { out.secret.len as u64 } else { 0 };
    match result(
        outcome,
        written,
        out.needed,
        cap,
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

            if written > 0 && out.secret.ptr as usize != buf {
                return Err(fault(Rule::Foreign, "resolve.secret_outside_buffer"));
            }

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
