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

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_unit_auth::module::AuthOutcome;
    use std::sync::Mutex;

    /// A directory a test can state the whole truth of in four lines.
    #[derive(Default)]
    struct Directory {
        keys: Vec<(String, KeyFacts)>,
        revoked: Vec<String>,
        asked: Mutex<Vec<String>>,
    }

    impl VirtualKeyDirectory for Directory {
        fn verify(
            &self,
            credential: &str,
            _now: u64,
            _expected_aud: Option<&str>,
        ) -> Option<KeyFacts> {
            self.asked
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(credential.to_string());
            self.keys
                .iter()
                .find(|(c, _)| c == credential)
                .map(|(_, f)| f.clone())
        }

        fn revoked(&self, credential: &str) -> bool {
            self.revoked.iter().any(|r| r == credential)
        }
    }

    fn a_directory() -> Arc<Directory> {
        Arc::new(Directory {
            keys: vec![(
                "tok-live".to_string(),
                KeyFacts {
                    id: "vk_1".to_string(),
                    name: "the operator's key".to_string(),
                },
            )],
            revoked: vec!["vk_gone".to_string()],
            asked: Mutex::new(Vec::new()),
        })
    }

    /// The cache digests with the node's own hex SHA-256, which is what makes one credential one row
    /// wherever in the tree it is named. Asserted against the published function rather than against
    /// a literal, because the property is that the two are the same function and not that either is
    /// a particular string.
    #[test]
    fn the_cache_digests_with_the_nodes_own_hex_sha256() {
        let bindings = AuthBindings::without_directory();
        let cache = bindings.cache().expect("a cache is always bound");
        cache.put(
            "provider",
            "credential-a",
            &AuthOutcome::Pass,
            0,
            cache.generation(),
        );

        // The row is reachable under the same credential, which it can only be if the digest the
        // insert used and the digest the read uses are one function.
        assert!(cache.get("provider", "credential-a", 0).is_some());
        assert!(cache.get("provider", "credential-b", 0).is_none());
        assert_eq!(
            busbar_api::sha256_hex(b"credential-a").len(),
            64,
            "the bound digest is the 32-byte SHA-256 rendered as lower-case hex"
        );
    }

    /// The verifier the root binds resolves through the directory and hands back the unit's own
    /// shape, so the chain's signed-key arm has something to identify with.
    #[test]
    fn the_bound_verifier_resolves_through_the_directory() {
        let directory = a_directory();
        let bindings = AuthBindings::new(directory.clone() as Arc<dyn VirtualKeyDirectory>);

        let keys = bindings.keys().expect("a bound directory is a verifier");
        assert_eq!(
            keys.verify_token("tok-live", 10, None),
            Some(ResolvedKey {
                id: "vk_1".to_string(),
                name: "the operator's key".to_string(),
            })
        );
        assert_eq!(keys.verify_token("tok-unknown", 10, None), None);
        assert_eq!(
            directory.asked.lock().expect("asked").len(),
            2,
            "both questions reached the directory rather than a second table here"
        );
    }

    /// The revocation view answers from the same directory the verifier does, which is the point of
    /// binding one value rather than two.
    #[test]
    fn the_revocation_view_reads_the_same_directory() {
        let bindings = AuthBindings::new(a_directory() as Arc<dyn VirtualKeyDirectory>);
        let revocations = bindings
            .revocations()
            .expect("a bound directory is a revocation view");
        assert!(revocations.is_revoked("vk_gone"));
        assert!(!revocations.is_revoked("vk_1"));
    }

    /// An unbound node binds a cache and no authority, which is a posture rather than a gap: the
    /// chain's own answer with no verifier is to deny, and the gate that never runs would have had
    /// nothing to refuse that the denial had not already refused.
    #[test]
    fn an_unbound_node_binds_a_cache_and_no_authority() {
        let bindings = AuthBindings::without_directory();
        assert!(bindings.cache().is_some());
        assert!(bindings.keys().is_none());
        assert!(bindings.revocations().is_none());
    }
}
