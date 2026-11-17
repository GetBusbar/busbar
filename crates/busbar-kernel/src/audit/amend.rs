// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{Audit, Pass};
pub use busbar_kernel_audit::{
    amend::{AmendBody, AmendSink, Amendment, NodeAmendments, ReadFact, Reader},
    Access, Subject,
};

pub type ReadConfirmation<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<(), busbar_kernel_audit::amend::AmendPersistError>>
            + Send
            + 'a,
    >,
>;

fn pass() -> Pass<Audit> {
    Pass::<Audit>::mint(&crate::seal::acquire())
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) async fn hook_read(
    amendments: &NodeAmendments,
    name: &str,
    principal: Option<&str>,
    op: &str,
    identity: bool,
) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
    hook_reads(amendments, &[name], principal, op, identity).await
}

/// Record that every hook in `names` is handed the unit's content: one amendment per hook, staged
/// and confirmed together (one durable commit for the whole set).
pub(crate) async fn hook_reads(
    amendments: &NodeAmendments,
    names: &[&str],
    principal: Option<&str>,
    op: &str,
    identity: bool,
) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
    let mut fields = vec!["content".to_string()];
    fields.extend(identity.then(|| "identity".to_string()));
    let wall = busbar_kernel::store::now();
    let facts: Vec<ReadFact<'_>> = names
        .iter()
        .map(|&name| ReadFact {
            reader: Reader::Hook,
            name,
            principal,
            op_class: op,
            fields: fields.clone(),
            wall,
        })
        .collect();
    amendments.record_reads(&pass(), &facts).await.map(|_| ())
}

/// Record that each `(module, members)` export sink was handed its record's members under `op`:
/// one amendment per sink, staged and confirmed together (one durable commit per event).
pub(crate) async fn export_reads(
    amendments: &NodeAmendments,
    op: &str,
    handed: &[(std::sync::Arc<str>, crate::export::projection::Members)],
) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
    let wall = busbar_kernel::store::now();
    let facts: Vec<ReadFact<'_>> = handed
        .iter()
        .map(|(module, members)| ReadFact {
            reader: Reader::Export,
            name: module.as_ref(),
            principal: None,
            op_class: op,
            fields: members.names().map(str::to_owned).collect(),
            wall,
        })
        .collect();
    amendments.record_reads(&pass(), &facts).await.map(|_| ())
}

#[cfg(test)]
#[path = "tests/amend_tests.rs"]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub async fn record_test_hook_read(
    amendments: &NodeAmendments,
    name: &str,
    principal: Option<&str>,
    op: &str,
    identity: bool,
) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
    hook_reads(amendments, &[name], principal, op, identity).await
}
