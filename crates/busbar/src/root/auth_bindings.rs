// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two seams the authenticate unit is handed and cannot own.
//!
//! `busbar-unit-auth` depends on the capability crate and on nothing else — its own manifest states
//! the rule and gives the reason: a unit that could name the kernel could reach past its token, and
//! a unit that could name a transport would grow a second opinion about what a credential is. The
//! price of that rule is that two things the chain genuinely needs arrive as traits the caller
//! implements:
//!
//! 1. **The key verifier.** The built-in signed-key arm resolves a whole enforced key, which is a
//!    thing the boxed-module answer type has no shape for. Resolving it means reading a signature, an
//!    expiry, a denylist and a rotation generation — four facts that live with the governance state.
//! 2. **The revocation set.** The gate that applies to a NEW unit, over the same denylist.
//!
//! This module is where the root holds both, because the root is the only thing that sees both
//! the unit and the state the answers come from.
//!
//! ## Why there is a port in the middle
//!
//! The verifier could name the governance state directly. It does not, because the three facts the
//! chain needs out of a key — does this credential verify, what id does it resolve to, and is that
//! subject revoked — are a far smaller surface than the state that answers them, and a root that
//! named the whole state would make every later reader of this file reason about the whole state.
//! So the shape is: a port with three methods ([`VirtualKeyDirectory`]), an adapter that turns it
//! into the two traits the unit asks for ([`AuthBindings`]), and a deployment supplying the one
//! implementor it has. `GovernanceDirectory` is that implementor for a node whose keys are busbar's
//! own; a deployment whose keys come from somewhere else writes its own and nothing here changes.
//!
//! ## What an unbound node does
//!
//! [`AuthBindings::without_directory`] is a real posture and not a placeholder: a node that resolves
//! no busbar-minted keys has no verifier to bind, and the chain's own answer for that is already the
//! right one — the signed-key arm denies, because a signed key cannot be verified without a verifier.
//!
//! ## No credential cache
//!
//! The kernel holds no verified-credential cache (THE DESIGN 11.11 R3): an auth plugin that caches
//! its verdicts does so inside itself, and the admin cache flush reaches it through its `refresh`.

use busbar_kernel_identity::chain::{KeyVerifier, ResolvedKey, RevocationView};
use std::sync::Arc;

/// The facts the chain reads out of a verified key.
///
/// Two strings, because two strings are what the unit's own `ResolvedKey` carries and what the
/// principal it builds is made of. The key's policy — its group, its pools, its labels — is the
/// governance state's business and is deliberately not in this shape: a value carried through here
/// would be a value the authenticate step could act on, and the authenticate step decides who is
/// calling and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFacts {
    /// The key's stable subject id — the principal's id, the ledger bucket, the audit attribution.
    pub id: String,
    /// The key's operator-facing label.
    pub name: String,
}

pub trait VirtualKeyDirectory: Send + Sync {
    fn verify(&self, credential: &str, now: u64, expected_aud: Option<&str>) -> Option<KeyFacts>;

    fn revoked(&self, credential: &str) -> bool;
}

struct DirectoryArm(Arc<dyn VirtualKeyDirectory>);

impl KeyVerifier for DirectoryArm {
    fn verify_token(
        &self,
        token: &str,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Option<ResolvedKey> {
        self.0
            .verify(token, now, expected_aud)
            .map(|facts| ResolvedKey {
                id: facts.id,
                name: facts.name,
            })
    }
}

impl RevocationView for DirectoryArm {
    fn is_revoked(&self, credential: &str) -> bool {
        self.0.revoked(credential)
    }
}

pub struct AuthBindings {
    directory: Option<DirectoryArm>,
}

impl AuthBindings {
    #[must_use]
    pub fn new(directory: Arc<dyn VirtualKeyDirectory>) -> Self {
        AuthBindings {
            directory: Some(DirectoryArm(directory)),
        }
    }

    #[must_use]
    pub fn without_directory() -> Self {
        AuthBindings { directory: None }
    }

    #[must_use]
    pub fn keys(&self) -> Option<&dyn KeyVerifier> {
        self.directory.as_ref().map(|d| d as &dyn KeyVerifier)
    }

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

pub struct GovernanceDirectory {
    state: Arc<busbar_kernel::governance::GovState>,
}

impl GovernanceDirectory {
    #[must_use]
    pub fn new(state: Arc<busbar_kernel::governance::GovState>) -> Self {
        GovernanceDirectory { state }
    }
}

impl VirtualKeyDirectory for GovernanceDirectory {
    fn verify(&self, credential: &str, now: u64, expected_aud: Option<&str>) -> Option<KeyFacts> {
        self.state
            .verify_token(credential, now, expected_aud)
            .map(|key| KeyFacts {
                id: key.id.clone(),
                name: key.name.clone(),
            })
    }

    fn revoked(&self, credential: &str) -> bool {
        self.state.is_revoked(credential)
    }
}

pub const ADMIN_PRINCIPAL_ID: &str = "admin";

#[must_use]
pub fn operator_auth_module() -> &'static str {
    crate::LINKED.operator_auth
}

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
