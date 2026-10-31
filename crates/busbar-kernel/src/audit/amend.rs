// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S SEAT ON THE NODE AMENDMENT JOURNAL (item 404). The audit unit's `amend` module
//! defines the journal ([`NodeAmendments`]); the node's one instance is held by its governance state
//! and carried on every `App` generation (`App::amendments`), and this is where the kernel's own
//! authority mints the audit step's token for it.
//! An ACCESS is the one class written: the hook seam records one per hook it hands content to, the
//! export dispatch one per sink it hands a record to. Field NAMES only, never values.

use busbar_contract::caps::{Audit, Pass};
pub use busbar_kernel_audit::{
    amend::{AmendBody, AmendSink, Amendment, NodeAmendments, Reader},
    Access, Subject,
};

/// The audit step's pass for a journal record, minted where it is used from the kernel's seal
/// (`crate::seal::acquire`: a kernel service that mints a kernel value takes the seal where it
/// mints). No second `Kernel` kept in a process static: THE DESIGN §11.11 adds no kernel `OnceLock`
/// seam beyond the two R6 exempts (audit K4 #1).
fn pass() -> Pass<Audit> {
    Pass::<Audit>::mint(&crate::seal::acquire())
}

/// A hook was handed a unit's content — and the caller's identity, when granted — recorded on the
/// node's journal `amendments`.
pub(crate) fn hook_read(
    amendments: &NodeAmendments,
    name: &str,
    principal: Option<&str>,
    op: &str,
    identity: bool,
) {
    let mut fields = vec!["content".to_string()];
    fields.extend(identity.then(|| "identity".to_string()));
    let now = busbar_kernel::store::now();
    amendments.record_read(&pass(), Reader::Hook, name, principal, op, fields, now);
}

/// An export sink was handed `payload`; the fields that crossed are exactly its keys. Recorded on
/// the node's journal `amendments`.
pub(crate) fn export_read(
    amendments: &NodeAmendments,
    module: &str,
    op: &str,
    payload: &serde_json::Value,
) {
    let fields = payload.as_object().map(|o| o.keys().cloned().collect());
    let (fields, now) = (fields.unwrap_or_default(), busbar_kernel::store::now());
    amendments.record_read(&pass(), Reader::Export, module, None, op, fields, now);
}

#[cfg(test)]
#[path = "tests/amend_tests.rs"]
mod tests;
