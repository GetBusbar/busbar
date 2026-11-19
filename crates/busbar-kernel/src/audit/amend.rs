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

/// The content fields a hook is handed, in order: the content, then the caller's identity when the
/// hook is granted it.
const HOOK_FIELDS: [&str; 2] = ["content", "identity"];

/// Record that every hook in `names` is handed the unit's content: one amendment per hook, staged
/// and confirmed together (one durable commit for the whole set).
pub(crate) async fn hook_reads(
    amendments: &NodeAmendments,
    names: &[&str],
    principal: Option<&str>,
    op: &str,
    identity: bool,
) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
    let fields = &HOOK_FIELDS[..1 + usize::from(identity)];
    let wall = busbar_kernel::store::now();
    let facts = names.iter().map(|&name| ReadFact {
        reader: Reader::Hook,
        name,
        principal,
        op_class: op,
        fields,
        wall,
    });
    amendments.record_reads(&pass(), facts).await
}

/// Record that each `(module, members)` export sink was handed its record's members under `op`:
/// one amendment per sink, staged and confirmed together (one durable commit per event).
pub(crate) async fn export_reads(
    amendments: &NodeAmendments,
    op: &str,
    handed: &[(std::sync::Arc<str>, crate::export::projection::Members)],
) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
    let wall = busbar_kernel::store::now();
    let facts = handed.iter().map(|(module, members)| ReadFact {
        reader: Reader::Export,
        name: module.as_ref(),
        principal: None,
        op_class: op,
        fields: members.names(),
        wall,
    });
    amendments.record_reads(&pass(), facts).await
}

#[cfg(test)]
#[path = "tests/amend_tests.rs"]
mod tests;
