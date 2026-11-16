// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the directory reports (IF §12.29): audit rows and alerts. The directory names the event; the sink that
//! boot wires in writes the audit row and raises the alert. No event carries a document, an index value or a
//! principal.

/// One directory event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirEvent<'a> {
    /// Audit `directory_contended`: a write lost the optimistic race MAX_ATTEMPTS times.
    Contended { instance: &'a str },
    /// Audit `directory_guard{instance, would_move}`: the mass-deprovision guard answered GUARD.
    Guard { instance: &'a str, would_move: u32 },
    /// Alert `provisioning_guard_tripped{instance}`: raised once per guard window.
    GuardTripped { instance: &'a str },
    /// Audit `directory_guard_released` with the admin principal.
    GuardReleased {
        instance: &'a str,
        admin: &'a str,
        for_s: u64,
    },
    /// Audit and alert `provisioning_held_full`: a write would hold more than MAX_HELD principals.
    HeldFull { instance: &'a str },
    /// Alert `provisioning_hold_stale`: the hold refresh failed 3 times in a row.
    HoldStale { instance: &'a str },
}

/// Where directory events go.
pub trait DirectoryEvents: Send + Sync + 'static {
    fn event(&self, event: DirEvent<'_>);
}

/// Events as structured log lines (the default until boot wires the audit sink).
pub struct LogEvents;

impl DirectoryEvents for LogEvents {
    fn event(&self, event: DirEvent<'_>) {
        tracing::warn!(target: "busbar::directory", ?event, "directory event");
    }
}
