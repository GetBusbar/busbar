// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{Audit, Pass};
pub use busbar_kernel_audit::{
    amend::{AmendBody, AmendSink, Amendment, NodeAmendments, Reader},
    Access, Subject,
};

fn pass() -> Pass<Audit> {
    Pass::<Audit>::mint(&crate::seal::acquire())
}

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

#[cfg(any(test, feature = "test-support"))]
pub fn record_test_hook_read(
    amendments: &NodeAmendments,
    name: &str,
    principal: Option<&str>,
    op: &str,
    identity: bool,
) {
    hook_read(amendments, name, principal, op, identity);
}
