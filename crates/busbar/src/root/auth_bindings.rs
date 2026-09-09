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
//! The cache is still built, because a cache is not an authority: it holds what a module already
//! decided, for less time than the module suggested, and never holds a rejection at all.

use busbar_unit_auth::cache::CredentialCache;
use busbar_unit_auth::chain::{KeyVerifier, ResolvedKey, RevocationView};
use std::sync::Arc;

/// The facts the chain reads out of a verified key.
///
/// Two strings and a RUNG. The key's policy — its group, its pools, its labels — is the governance
/// state's business and is deliberately not in this shape: a value carried through here would be a
/// value the authenticate step could act on, and the authenticate step decides who is calling and
/// nothing else.
///
/// The rung is the exception, and it is one because it is not a policy this step acts on: it is
/// what the credential CONFERS, established by the same verification that established the id, and
/// carried so that the step which does act on it — APPROVE, several steps later, on whichever plane
/// the unit belongs to — is handed it rather than left to guess. While this port carried only the
/// two strings, every plane behind it had to supply a grant of its own from somewhere, and the A2A
/// plane supplied a constant decided before the chain had run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFacts {
    /// The key's stable subject id — the principal's id, the ledger bucket, the audit attribution.
    pub id: String,
    /// The key's operator-facing label.
    pub name: String,
    /// THE RUNG THIS KEY CONFERS. `None` is a directory that names no rung, which every reader
    /// collapses to the bottom of the chain — an implementor that cannot answer loses nothing it
    /// was entitled to and grants nothing it did not mean to.
    pub scope: Option<busbar_contract::CallerScope>,
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
                scope: facts.scope,
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
/// A delegation and nothing more. Both methods forward to the state's own published answer, so
/// there is no second opinion here about what a valid key is, no second denylist, and nothing this
/// type could get wrong that the state has not already decided.
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
                scope: Some(key_rung(&key)),
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

/// THE RUNG A NODE'S OWN VIRTUAL KEY CONFERS, read off the key the governance state resolved.
///
/// `Full`, and the reason is what a virtual key IS on this deployment rather than an opinion about
/// what would be convenient. A minted key is the credential a caller spends on the DATA planes, and
/// the shipped release lets a live key that resolves at all perform every operation of the plane it
/// was minted for; what narrows a key is `allowed_scopes` — WHICH pool, WHICH server, WHICH agent —
/// enforced by the trust unit against the destination, and it is a different axis entirely. A row
/// in the key table carries no rung at all, so there is nothing narrower here to read: answering
/// `ReadOnly` would not be caution, it would be inventing a restriction no operator configured and
/// refusing every send on every plane.
///
/// This is the ONE place that judgement is made, so the day the key row grows a rung of its own is
/// the day this function reads it — and nothing above it changes.
fn key_rung(_key: &busbar_api::VirtualKey) -> busbar_contract::CallerScope {
    busbar_contract::CallerScope::Full
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
    state: Arc<busbar_core::governance::GovState>,
}

impl AdminTokens {
    /// Bind the module to the governance state that holds the configured hash.
    ///
    /// The hash is read PER CALL rather than captured at boot, because an operator who rotates the
    /// admin token expects the next request to be judged against the new one — a copy taken here
    /// would keep admitting the old credential until the process restarted.
    #[must_use]
    pub fn new(state: Arc<busbar_core::governance::GovState>) -> Self {
        AdminTokens { state }
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
        let Some(configured) = self.state.admin_token_hash() else {
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
pub fn admin_chain(state: Arc<busbar_core::governance::GovState>) -> busbar_unit_auth::AuthChain {
    busbar_unit_auth::AuthChain::new(
        vec![busbar_unit_auth::chain::ChainEntry {
            provider: ADMIN_TOKENS_MODULE.to_string(),
            module: Box::new(AdminTokens::new(state)),
        }],
        // The signed-key arm is not in the administrative chain: the previous release's admin door
        // is the operator token, and naming the arm here would open a second one.
        false,
    )
}

#[cfg(test)]
#[path = "tests/auth_bindings.rs"]
mod tests;
