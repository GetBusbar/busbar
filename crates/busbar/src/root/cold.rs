// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the request-path modules beside it need,
//! called out of line: refusal text, spelled only when a request or a unit is refused. Every fn is
//! `#[cold]`; none holds a loop or sweeps request data.

/// `plane_node`: the native journal refused a held flush.
#[cold]
pub(crate) fn native_journal_refused(error: &dyn std::fmt::Debug) -> String {
    format!("native journal: {error:?}")
}

/// `plane_node`: a unit's terminal audit could not be confirmed durable.
#[cold]
pub(crate) fn terminal_audit_unconfirmed(error: &dyn std::fmt::Debug) -> String {
    format!("terminal audit is unconfirmed: {error:?}")
}

/// Staging refused the terminal original, so no confirmation can authorize success.
#[cold]
pub(crate) fn terminal_audit_stage_failed(error: &dyn std::fmt::Debug) -> String {
    metrics::counter!(busbar_kernel::snapshot::AUDIT_STAGE_FAILURES_TOTAL).increment(1);
    busbar_kernel::diagnostics::diag_error!(
        busbar_kernel::diagnostics::TERMINAL_AUDIT_STAGE_FAILED,
        "terminal audit staging failed; the request cannot report success"
    );
    terminal_audit_unconfirmed(error)
}

/// `auth_bindings`: the planned config's `plugins:` block does not read as the current block, so
/// the operator credential cannot be judged from it.
#[cold]
pub(crate) fn upgraded_plugins_unreadable(e: &busbar_contract::yaml::Error) -> String {
    format!("the upgraded `plugins:` block does not read: {e}")
}
