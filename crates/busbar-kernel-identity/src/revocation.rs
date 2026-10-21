// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The revocation set the authenticate step gates an identification with.

/// The revocation set, as the node keeps it.
///
/// It gates NEW units only. A unit already in flight runs to its own end: revoking mid-unit would
/// tear down work already paid for and observed, and the very next unit is refused anyway. The
/// composition root implements it over the node's governance state and asks it once an admin
/// request's credential has identified.
pub trait RevocationView: Send + Sync {
    /// Whether this credential is revoked as of the current policy epoch.
    fn is_revoked(&self, credential: &str) -> bool;
}
