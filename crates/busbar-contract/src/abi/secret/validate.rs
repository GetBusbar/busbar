// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S ANSWER VALIDATOR, beside the shapes it judges: one pure `check_<op>`, `u64`
//! math, no statics, answering the shared [`Fault`] (one [`Rule`] and one distinct field per arm).
//! The dispatcher turns an `Err` into FAULT; no host re-implements a check.
//!
//! Per outcome: the secret blob's pointer/length pairing, its size and the `error_kind` range are
//! judged on every outcome (a PENDING or REFUSED `out` the host zeroed passes them). READY states
//! no `error_kind` and leases exactly the material it carries; FAILED carries no material and
//! names its `error_kind`.

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{ResolveOut, ERROR_KIND_INTERNAL, ERROR_KIND_UNSET};
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::check::fault;

/// The largest secret one answer may carry, in bytes (16 MiB).
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Validates `resolve`'s `out`. Pure, `u64` math, no statics.
///
/// # Errors
/// The rule `out` breaks.
pub fn check_resolve(out: &ResolveOut) -> Result<(), Fault> {
    if out.secret.len > 0 && out.secret.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, "resolve.secret"));
    }
    if out.secret.len as u64 > HARD_MAX_BYTES {
        return Err(fault(Rule::OverMax, "resolve.secret.len"));
    }
    if out.error_kind as u64 > ERROR_KIND_INTERNAL as u64 {
        return Err(fault(Rule::UnknownCode, "resolve.error_kind"));
    }
    let ready = out.head.outcome.0 == (Outcome::Ready as u8);
    let failed = out.head.outcome.0 == (Outcome::Failed as u8);
    if ready && out.error_kind != ERROR_KIND_UNSET {
        return Err(fault(Rule::Contradiction, "resolve.error_kind_on_ready"));
    }
    // A secret-bearing answer is secret on the host side whatever its flags say: a FAILED answer
    // carries no material at all.
    if failed && !out.secret.ptr.is_null() {
        return Err(fault(Rule::Contradiction, "resolve.secret_on_failed"));
    }
    if failed && out.error_kind == ERROR_KIND_UNSET {
        return Err(fault(Rule::Missing, "resolve.error_kind_on_failed"));
    }
    // The lease (memory class iv) is required exactly when a READY answer carries material.
    let has_material = out.secret.len > 0;
    if ready && has_material && out.head.lease == 0 {
        return Err(fault(Rule::Missing, "resolve.lease"));
    }
    if ready && !has_material && out.head.lease != 0 {
        return Err(fault(Rule::Contradiction, "resolve.lease_without_material"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/secret_validate_tests.rs"]
mod tests;
