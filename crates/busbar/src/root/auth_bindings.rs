// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The revocation set the admin authenticate step is handed and cannot own.
//!
//! `busbar-kernel-identity` names no kernel crate, so the one thing the step needs from the node's
//! governance state arrives as a trait the root implements: **the revocation set**, the gate that
//! applies to a NEW unit once its credential has identified ([`RevocationView`]).
//!
//! This module is where the root holds it, because the root is the only thing that sees both the
//! step and the state the answer comes from.
//!
//! ## Why there is a port in the middle
//!
//! The view could name the governance state directly. It does not, because the one fact the step
//! needs — is this credential's subject revoked — is a far smaller surface than the state that
//! answers it, and a root that named the whole state would make every reader of this file reason
//! about the whole state. So the shape is: a port with one method ([`VirtualKeyDirectory`]),
//! an adapter that turns it into the trait the step asks for ([`AuthBindings`]), and a deployment
//! supplying the one implementor it has. `GovernanceDirectory` is that implementor for a node whose
//! keys are busbar's own; a deployment whose keys come from somewhere else writes its own and
//! nothing here changes.
//!
//! ## What an unbound node does
//!
//! [`AuthBindings::without_directory`] is a real posture and not a placeholder: a node with no
//! governance state keeps no revocation set, and a set nothing supplies revokes nothing.
//!
//! ## No credential cache
//!
//! The kernel holds no verified-credential cache (THE DESIGN 11.11 R3): an auth plugin that caches
//! its verdicts does so inside itself, and the admin cache flush reaches it through its `refresh`.

use busbar_kernel_identity::RevocationView;
use std::sync::Arc;

/// The port the root reaches a node's virtual-key directory through.
///
/// It answers about a PRESENTED credential and hands back nothing that could be presented again,
/// which is what makes the port safe to hold behind a shared handle: there is no method on it that
/// leaks a secret and no method that mutates the directory.
pub trait VirtualKeyDirectory: Send + Sync {
    /// Whether the subject a credential names is on the revocation denylist.
    ///
    /// This is the gate for a NEW unit and for nothing else — a unit already in flight is never
    /// asked, because revoking mid-unit would tear down work already paid for and observed while
    /// the very next unit is refused anyway.
    ///
    /// It is not the place a signed token's revocation is enforced: the kernel's signed-key
    /// verifier consults the same denylist itself, so a revoked token is already refused before
    /// this is reached. What this covers is the credential shapes whose subject IS the credential's
    /// own id, where there is no signature to read a subject out of. An implementor that cannot
    /// resolve a credential to a subject answers `false` and loses nothing.
    fn revoked(&self, credential: &str) -> bool;
}

/// The revocation view the step asks for, over one directory.
struct DirectoryArm(Arc<dyn VirtualKeyDirectory>);

impl RevocationView for DirectoryArm {
    fn is_revoked(&self, credential: &str) -> bool {
        self.0.revoked(credential)
    }
}

/// Everything the authenticate step is handed beside the request itself.
///
/// Built at boot and borrowed by every unit that authenticates.
pub struct AuthBindings {
    directory: Option<DirectoryArm>,
}

impl AuthBindings {
    /// Bind a virtual-key directory.
    #[must_use]
    pub fn new(directory: Arc<dyn VirtualKeyDirectory>) -> Self {
        AuthBindings {
            directory: Some(DirectoryArm(directory)),
        }
    }

    /// Bind nothing — the posture of a node that keeps no revocation set.
    ///
    /// Not a degraded build and not a placeholder: with no revocation view the NEW-unit gate does
    /// not run, and a set nothing supplies revokes nothing.
    #[must_use]
    pub fn without_directory() -> Self {
        AuthBindings { directory: None }
    }

    /// The revocation view, when a directory was bound.
    #[must_use]
    pub fn revocations(&self) -> Option<&dyn RevocationView> {
        self.directory.as_ref().map(|d| d as &dyn RevocationView)
    }
}

impl std::fmt::Debug for AuthBindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBindings")
            .field("directory", &self.directory.is_some())
            .finish()
    }
}

/// The virtual-key directory a node whose keys are busbar's own has: the governance state.
///
/// A delegation and nothing more. It forwards to the state's own published answer, so there is no
/// second denylist here, and nothing this type could get wrong that the state has not already
/// decided.
pub struct GovernanceDirectory {
    state: Arc<busbar_kernel::governance::GovState>,
}

impl GovernanceDirectory {
    /// Bind the directory to one governance state.
    #[must_use]
    pub fn new(state: Arc<busbar_kernel::governance::GovState>) -> Self {
        GovernanceDirectory { state }
    }
}

impl VirtualKeyDirectory for GovernanceDirectory {
    fn revoked(&self, credential: &str) -> bool {
        // The denylist is keyed by SUBJECT id. A signed token's own revocation is enforced inside
        // the state's `verify_token`, so what this answers for is a credential that IS its subject's
        // id.
        // A credential that is neither is not on the denylist and answers `false`, which is the same
        // answer the gate would have reached by any other route.
        self.state.is_revoked(credential)
    }
}

/// The fixed id the operator's admin credential identifies as.
///
/// The previous release's own literal, and the reason the scope rule can be written as an equality:
/// the operator credential is the root credential a deployment is born with, so what it identifies
/// as is a constant of the surface rather than a value a configuration picks.
pub const ADMIN_PRINCIPAL_ID: &str = "admin";

/// THE ROOT LEGACY TABLE: the operator credential's provider, as configuration spells it (the
/// `auth.admin_auth:` default, the one `module:` whose definition may carry `token:`, and a reserved
/// hook name). Frozen operator-visible config text the root hands to the kernel with its linked auth
/// rows, so the kernel spells it nowhere (ARCHITECT 2026-09-30, KERNEL-AUTH-ZERO Q2;
/// BUSBAR-1.6.0.md:173, "sit in the root legacy table"). The word is the manifest's: the registry key
/// of the row its `[package.metadata.busbar.operator-auth]` table names, stated in packaging whether
/// or not this build links that row, so no source here names the module. Its value is v1.5.5's
/// (v1.5.5:crates/busbar/src/config/mod.rs:795; :1874,1891, the hook-name reservation).
#[must_use]
pub fn operator_auth_module() -> &'static str {
    crate::LINKED.operator_auth
}

/// THE OPERATOR CREDENTIAL'S WORDS, off the root legacy table: [`operator_auth_module`] and
/// [`ADMIN_PRINCIPAL_ID`] (v1.5.5's operator principal id).
#[must_use]
pub fn operator_words() -> busbar_kernel_identity::operator::OperatorWords {
    busbar_kernel_identity::operator::OperatorWords {
        provider: operator_auth_module(),
        principal_id: ADMIN_PRINCIPAL_ID,
    }
}

#[cfg(test)]
#[path = "tests/auth_bindings.rs"]
mod tests;
