// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The three seams the authenticate unit is handed and cannot own.
//!
//! `busbar-unit-auth` depends on the capability crate and on nothing else — its own manifest states
//! the rule and gives the reason: a unit that could name the kernel could reach past its token, and
//! a unit that could name a transport would grow a second opinion about what a credential is. The
//! price of that rule is that three things the chain genuinely needs arrive as traits the caller
//! implements:
//!
//! 1. **The credential digest.** The cache stores a digest of a credential and never the credential,
//!    and the digest has to be the same one the rest of the node uses or two components disagree
//!    about what one credential is.
//! 2. **The key verifier.** The built-in signed-key arm resolves a whole enforced key, which is a
//!    thing the boxed-module answer type has no shape for. Resolving it means reading a signature, an
//!    expiry, a denylist and a rotation generation — four facts that live with the governance state.
//! 3. **The revocation set.** The gate that applies to a NEW unit, over the same denylist.
//!
//! This module is where the root holds all three, because the root is the only thing that sees both
//! the unit and the state the answers come from.
//!
//! ## Why there is a port in the middle
//!
//! The verifier could name the governance state directly. It does not, because the three facts the
//! chain needs out of a key — does this credential verify, what id does it resolve to, and is that
//! subject revoked — are a far smaller surface than the state that answers them, and a root that
//! named the whole state would make every later reader of this file reason about the whole state.
//! The port is the contract's [`VirtualKeyDirectory`] face — declared there, beside the other kind
//! faces, because the unit that asks and the root that answers may not name each other. This file
//! is the root's side of it: an adapter that turns the face into the two traits the unit asks for
//! ([`AuthBindings`]), and the one implementor this deployment has. `GovernanceDirectory` is that
//! implementor for a node whose keys are busbar's own; a deployment whose keys come from somewhere
//! else writes its own and nothing here changes.
//!
//! ## What an unbound node does
//!
//! [`AuthBindings::without_directory`] is a real posture and not a placeholder: a node that resolves
//! no busbar-minted keys has no verifier to bind, and the chain's own answer for that is already the
//! right one — the signed-key arm denies, because a signed key cannot be verified without a verifier.
//! The cache is still built, because a cache is not an authority: it holds what a module already
//! decided, for less time than the module suggested, and never holds a rejection at all.

use busbar_contract::{KeyFacts, KeyScope, VirtualKeyDirectory};
use busbar_unit_auth::cache::CredentialCache;
use busbar_unit_auth::chain::{KeyVerifier, ResolvedKey, RevocationView};
use std::sync::Arc;

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
        self.0.is_revoked(credential)
    }
}

/// Everything the authenticate step is handed beside the request itself.
///
/// Built once, at boot, and borrowed by every unit of every plane that authenticates. One per node
/// rather than one per plane: two caches would be two answers to "has this credential been seen",
/// and a flush an operator performed on one would leave the other serving a verdict the flush was
/// meant to have killed.
pub struct AuthBindings {
    cache: CredentialCache,
    directory: Option<DirectoryArm>,
}

impl AuthBindings {
    /// Bind the cache and a virtual-key directory.
    #[must_use]
    pub fn new(directory: Arc<dyn VirtualKeyDirectory>) -> Self {
        AuthBindings {
            cache: credential_cache(),
            directory: Some(DirectoryArm(directory)),
        }
    }

    /// Bind the cache alone — the posture of a node that resolves no busbar-minted keys.
    ///
    /// Not a degraded build and not a placeholder. With no verifier the signed-key arm denies, which
    /// is the fail-closed answer the chain already documents for exactly this case; with no
    /// revocation view the NEW-unit gate does not run, which changes nothing a verifier that denies
    /// everything had not already decided.
    #[must_use]
    pub fn without_directory() -> Self {
        AuthBindings {
            cache: credential_cache(),
            directory: None,
        }
    }

    /// The credential cache, as the unit takes it.
    #[must_use]
    pub fn cache(&self) -> Option<&CredentialCache> {
        Some(&self.cache)
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
            .field("cached", &self.cache.len())
            .field("directory", &self.directory.is_some())
            .finish()
    }
}

/// The cache, over the node's own credential digest.
///
/// The digest is the kernel's hex SHA-256 — the same function every other component in this tree
/// digests a credential with — reached through the published `busbar-api` surface rather than
/// re-implemented here, because two spellings of one digest is how two components come to disagree
/// about what one credential is. The unit ships the identical algorithm as `cache::Sha256Digest`
/// behind its `sha256` feature, and its own parity test pins the two equal; the feature is off in
/// this binary's manifest today, and turning it on is a manifest change rather than a change here.
fn credential_cache() -> CredentialCache {
    CredentialCache::new(busbar_api::sha256_hex as fn(&[u8]) -> String)
}

/// The virtual-key directory a node whose keys are busbar's own has: the governance state.
///
/// A delegation and nothing more. Every method forwards to the state's own published answer, so
/// there is no second opinion here about what a valid key is, no second denylist, no second copy
/// of the operator's credential digest, and nothing this type could get wrong that the state has
/// not already decided.
pub struct GovernanceDirectory {
    state: Arc<busbar_core::governance::GovState>,
}

impl GovernanceDirectory {
    /// Bind the directory to one governance state.
    #[must_use]
    pub fn new(state: Arc<busbar_core::governance::GovState>) -> Self {
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
                scopes: key.allowed_scopes.as_ref().map(|scopes| {
                    scopes
                        .iter()
                        .map(|s| KeyScope {
                            kind: s.kind.clone(),
                            value: s.value.clone(),
                        })
                        .collect()
                }),
                enabled: key.enabled,
                expires_at: key.expires_at,
                deleted_at: key.deleted_at,
            })
    }

    fn is_revoked(&self, credential: &str) -> bool {
        // The denylist is keyed by SUBJECT id. A signed token's own revocation was already enforced
        // inside `verify_token`, so what this answers for is a credential that IS its subject's id.
        // A credential that is neither is not on the denylist and answers `false`, which is the same
        // answer the gate would have reached by any other route.
        self.state.is_revoked(credential)
    }

    fn operator_token_hash(&self) -> Option<String> {
        // Read through to the state on every call rather than copied at boot: an operator who
        // rotates the credential expects the next request to be judged against the new one.
        self.state.admin_token_hash()
    }
}

/// The fixed id the operator's admin credential identifies as.
///
/// The previous release's own literal, and the reason the scope rule can be written as an equality:
/// the operator credential is the root credential a deployment is born with, so what it identifies
/// as is a constant of the surface rather than a value a configuration picks.
pub const ADMIN_PRINCIPAL_ID: &str = "admin";

/// The provider name this module reports as, which is the previous release's.
pub const ADMIN_TOKENS_MODULE: &str = "admin-tokens";

/// The chain module for the one operator admin token.
///
/// The digest is recomputed here through the published `busbar-api` surface rather than reached for
/// through the module crate the previous release links, because that crate is not a dependency of
/// this binary and making it one would be a manifest change for one hash. It is the SAME function —
/// the same one the credential cache digests with, a few lines up — so there is no second spelling
/// of the digest in this file, only one function named twice.
pub struct AdminTokens {
    directory: Arc<dyn VirtualKeyDirectory>,
}

impl AdminTokens {
    /// Bind the module to the directory that holds the configured hash.
    ///
    /// The hash is read PER CALL through [`VirtualKeyDirectory::operator_token_hash`] rather than
    /// captured at boot, because an operator who rotates the credential expects the next request
    /// to be judged against the new one — a copy taken here would keep admitting the old
    /// credential until the process restarted.
    #[must_use]
    pub fn new(directory: Arc<dyn VirtualKeyDirectory>) -> Self {
        AdminTokens { directory }
    }
}

impl busbar_unit_auth::module::AuthModule for AdminTokens {
    fn name(&self) -> &'static str {
        ADMIN_TOKENS_MODULE
    }

    fn authenticate(&self, candidate: Option<&str>) -> busbar_unit_auth::module::AuthOutcome {
        use busbar_unit_auth::module::AuthOutcome;
        // No token configured is not a refusal and not an admission: this module has nothing to
        // judge, so it defers. What that means for the node is decided by the chain around it — an
        // all-pass chain denies — and not by an opinion invented here.
        let Some(configured) = self.directory.operator_token_hash() else {
            return AuthOutcome::Pass;
        };
        // No credential presented is likewise this module's to defer on rather than to refuse: the
        // request may be carrying somebody else's credential shape entirely.
        let Some(candidate) = candidate else {
            return AuthOutcome::Pass;
        };
        if busbar_api::constant_time_eq(&busbar_api::sha256_hex(candidate.as_bytes()), &configured)
        {
            AuthOutcome::Identify(busbar_unit_auth::principal::Principal::from_id(
                ADMIN_PRINCIPAL_ID,
            ))
        } else {
            // Recognised and refused. Not `Pass`: a credential presented on the administrative
            // carriers against a node that HAS an admin token is this module's credential, and
            // deferring it would let a later module answer for the operator's own door.
            AuthOutcome::Reject
        }
    }

    fn cacheable(&self) -> bool {
        // A verdict here is a hash comparison against a value that can be rotated under it, and the
        // cache is what would keep serving the pre-rotation answer. The compare costs one SHA-256.
        false
    }
}

/// The chain a node whose administrative door is its own admin token runs.
///
/// One position, because that is what the deployment configured: the operator credential. A node
/// with no configured token gets a chain whose one module passes, and an all-pass chain denies —
/// which is the previous release's "the admin API is disabled without a token", reached the same
/// way rather than restated here.
#[must_use]
pub fn admin_chain(directory: Arc<dyn VirtualKeyDirectory>) -> busbar_unit_auth::AuthChain {
    busbar_unit_auth::AuthChain::new(
        vec![busbar_unit_auth::chain::ChainEntry {
            provider: ADMIN_TOKENS_MODULE.to_string(),
            module: Box::new(AdminTokens::new(directory)),
        }],
        // The signed-key arm is not in the administrative chain: the previous release's admin door
        // is the operator token, and naming the arm here would open a second one.
        false,
    )
}

#[cfg(test)]
#[path = "tests/auth_bindings.rs"]
mod tests;
