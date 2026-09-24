// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S SEAT ON THE NODE AMENDMENT JOURNAL (item 404). The audit unit's `amend` module
//! holds the journal; this is where the kernel's own authority mints the audit step's token for it.
//!
//! - an ACCESS: the hook seam records one per hook it hands content to, the export dispatch one
//!   per sink it hands a record to. Field NAMES only, never values.
//! - an ADJUSTMENT: [`correct_counts`], the kernel half of the root correction verb. It amends a
//!   recorded unit's COUNTS (owner ruling Q9, #71) and never a money figure; money stays what the
//!   ledger's one function (`cost::Tally`) derives from the corrected counts ([`counts_now`]) at
//!   the card epoch the correction names.

use busbar_contract::{
    authz::Scope,
    caps::{Audit, Pass},
};
pub use busbar_kernel_audit::{
    amend::{
        self as journal, counts_now, node_corrections, node_recent, AmendBody, Amendment,
        ClassCounts, CorrectionError, CorrectionRefused, CountCorrection, Reader,
    },
    Access, Adjust, Subject,
};

static KERNEL: std::sync::OnceLock<crate::teller::Kernel> = std::sync::OnceLock::new();

fn pass() -> Pass<Audit> {
    Pass::<Audit>::mint(KERNEL.get_or_init(crate::teller::Kernel::new).seal())
}

/// A hook was handed a unit's content — and the caller's identity, when granted.
pub(crate) fn hook_read(name: &str, principal: Option<&str>, op: &str, identity: bool) {
    let mut fields = vec!["content".to_string()];
    fields.extend(identity.then(|| "identity".to_string()));
    let now = busbar_kernel::store::now();
    journal::record_read(&pass(), Reader::Hook, name, principal, op, fields, now);
}

/// An export sink was handed `payload`; the fields that crossed are exactly its keys.
pub(crate) fn export_read(module: &str, op: &str, payload: &serde_json::Value) {
    let fields = payload.as_object().map(|o| o.keys().cloned().collect());
    let (fields, now) = (fields.unwrap_or_default(), busbar_kernel::store::now());
    journal::record_read(&pass(), Reader::Export, module, None, op, fields, now);
}

/// THE CORRECTION VERB'S KERNEL HALF — see [`journal::correct_counts`].
///
/// # Errors
///
/// Below the root scope, or a correction that would take a count below zero or gives no reason.
pub fn correct_counts(
    scope: Scope,
    recorded: &ClassCounts,
    c: CountCorrection<'_>,
) -> Result<Amendment, CorrectionError> {
    journal::correct_counts(&pass(), scope, recorded, c, busbar_kernel::store::now())
}

#[cfg(test)]
#[path = "tests/amend_tests.rs"]
mod amend_tests;
