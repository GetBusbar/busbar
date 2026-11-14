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
    members: crate::export::projection::Members,
) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
    let fields = members.names().map(str::to_owned).collect();
    let now = busbar_kernel::store::now();
    amendments
        .record_read(&pass(), Reader::Export, module, None, op, fields, now)
        .await
        .map(|_| ())
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
    hook_read(amendments, name, principal, op, identity).await
}
