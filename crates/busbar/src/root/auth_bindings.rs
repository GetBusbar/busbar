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

/// The port the root reaches a node's virtual-key directory through.
///
/// Both methods answer about a PRESENTED credential and neither hands anything back that could be
/// presented again, which is what makes the port safe to hold behind a shared handle: there is no
/// method on it that leaks a secret and no method that mutates the directory.
pub trait VirtualKeyDirectory: Send + Sync {
    /// Verify a busbar-minted signed key and resolve the facts behind it. `None` for anything that
    /// is not a currently-valid key: unknown, unsigned, expired, rotated, revoked or disabled.
    ///
    /// `expected_aud` is the plane boundary, and it is threaded rather than checked by a caller for
    /// the reason the unit's own trait doc gives: a route added to an audience-bound plane later
    /// cannot forget a check that happens inside the verifier. `None` means the residual plane,
    /// where a token that CARRIES an audience is inadmissible.
    ///
    /// The order an implementor must follow is the ladder the design pins — signature, then the
    /// token's own expiry, then the denylist, then the rotation generation — each step
    /// short-circuiting the ones after it, so the FIRST reason a token failed is the one the design
    /// names rather than a later one that happened to also be true.
    fn verify(&self, credential: &str, now: u64, expected_aud: Option<&str>) -> Option<KeyFacts>;

    /// Whether the subject a credential names is on the revocation denylist.
    ///
    /// This is the gate for a NEW unit and for nothing else — a unit already in flight is never
    /// asked, because revoking mid-unit would tear down work already paid for and observed while
    /// the next unit is refused a fraction of a second later anyway.
    ///
    /// It is deliberately NOT the only place revocation is enforced, and it is not the place a
    /// signed token's revocation is enforced: [`VirtualKeyDirectory::verify`] consults the same
    /// denylist as its third step, so a revoked token is already refused before this is reached.
    /// What this covers is the credential shapes whose subject IS the credential's own id, where
    /// there is no signature to read a subject out of. An implementor that cannot resolve a
    /// credential to a subject answers `false` and loses nothing: the verifier has already refused
    /// everything this would have refused.
    fn revoked(&self, credential: &str) -> bool;
}

/// The two traits the unit asks for, over one directory.
///
/// One value implementing both, rather than two, because they answer from the same source and
/// binding them separately is how a deployment ends up with a verifier and a denylist that disagree.
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

    /// Bind nothing — the posture of a node that resolves no busbar-minted keys.
    ///
    /// Not a degraded build and not a placeholder. With no verifier the signed-key arm denies, which
    /// is the fail-closed answer the chain already documents for exactly this case; with no
    /// revocation view the NEW-unit gate does not run, which changes nothing a verifier that denies
    /// everything had not already decided.
    #[must_use]
    pub fn without_directory() -> Self {
        AuthBindings { directory: None }
    }

    /// The signed-key verifier, when a directory was bound.
    #[must_use]
    pub fn keys(&self) -> Option<&dyn KeyVerifier> {
        self.directory.as_ref().map(|d| d as &dyn KeyVerifier)
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
/// A delegation and nothing more. Both methods forward to the state's own published answer, so
/// there is no second opinion here about what a valid key is, no second denylist, and nothing this
/// type could get wrong that the state has not already decided.
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
    fn verify(&self, credential: &str, now: u64, expected_aud: Option<&str>) -> Option<KeyFacts> {
        self.state
            .verify_token(credential, now, expected_aud)
            .map(|key| KeyFacts {
                id: key.id.clone(),
                name: key.name.clone(),
            })
    }

    fn revoked(&self, credential: &str) -> bool {
        // The denylist is keyed by SUBJECT id. A signed token's own revocation was already enforced
        // inside `verify_token`, so what this answers for is a credential that IS its subject's id.
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
/// hook name). Frozen operator-visible config text naming an auth module no crate in this tree
/// declares (GetBusbar/busbar-auth-admin-tokens); the root hands it to the kernel with its linked
/// auth rows, so the kernel spells it nowhere (ARCHITECT 2026-09-30, KERNEL-AUTH-ZERO Q2;
/// BUSBAR-1.6.0.md:173, "sit in the root legacy table"). Moved from busbar-kernel's
/// `data/operator_credential.toml`, value unchanged. A module name a build compiles in is declared
/// as a `*_MODULE` constant, which is how the kind-isolation instance axis learns it.
/// v1.5.5:crates/busbar/src/config/mod.rs:795 (ADMIN_TOKENS_MODULE); :1874,1891 (the hook-name
/// reservation).
pub const OPERATOR_AUTH_MODULE: &str = "admin-tokens";

/// THE OPERATOR CREDENTIAL'S WORDS, off the root legacy table: [`OPERATOR_AUTH_MODULE`] and
/// [`ADMIN_PRINCIPAL_ID`] (v1.5.5:crates/auth-admin-tokens/src/lib.rs:19, ADMIN_TOKENS_PRINCIPAL_ID).
#[must_use]
pub fn operator_words() -> busbar_kernel_identity::operator::OperatorWords {
    busbar_kernel_identity::operator::OperatorWords {
        provider: OPERATOR_AUTH_MODULE,
        principal_id: ADMIN_PRINCIPAL_ID,
    }
}

#[cfg(test)]
#[path = "tests/auth_bindings.rs"]
mod tests;
