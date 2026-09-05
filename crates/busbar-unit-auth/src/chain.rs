// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The chain walk: config order, first identification wins, a rejection stops, a pass continues.
//!
//! ## When the door is open
//!
//! Exactly one condition: the chain declares no module AND names no keys arm. The keys arm is an
//! engine-side verifier rather than a boxed module, so a chain that names only the keys arm has an
//! empty module list and still keeps the door SHUT — the arm runs. The mandatory in-tree lease and
//! local-secret plugins are never members of either counted list, so an operator who writes an
//! empty chain still gets the anonymous-admit posture they asked for.
//!
//! ## Where the keys arm sits, and why it is not a module
//!
//! It runs after every boxed module, because a module that positively identified has already
//! returned. It is not boxed because the module answer type can only hand back a principal, and the
//! keys arm resolves a whole enforced key — a thing the module contract has no shape for. It is
//! also cache-exempt: revocation on that path is a per-request verification plus a short denylist
//! sync, and caching its verdict would widen the revocation window to the cache lifetime.

use crate::cache::CredentialCache;
use crate::module::{AuthModule, AuthOutcome};
use crate::principal::Principal;

/// One resolved chain position: the provider NAME the config referenced, and the module behind it.
///
/// The name, not the module's self-reported name, is the identity that role bindings bind and that
/// scope ceilings key off — so two named providers sharing one module stay two identities.
pub struct ChainEntry {
    /// The provider name from the configuration.
    pub provider: String,
    /// The module resolved for that position.
    pub module: Box<dyn AuthModule>,
}

/// The enforced key the built-in signed-key arm resolves.
///
/// Opaque here on purpose: this unit needs to carry it, never to read it.
// contract: the governance crate's `VirtualKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKey {
    /// The key's stable id — the principal's id.
    pub id: String,
    /// The key's operator-facing label.
    pub name: String,
}

/// The built-in signed-key verifier, as the chain reaches it.
///
/// The audience argument is the plane boundary: `None` on the residual plane, where the verifier
/// rejects any token that CARRIES an audience; the plane's own canonical name on an audience-bound
/// ingress, where it rejects a token whose audience is absent or different. Threading it through
/// the verifier rather than a caller is what stops a route added to that plane later from forgetting
/// the check.
pub trait KeyVerifier: Send + Sync {
    /// Verify a signed key. `None` for unknown, expired, rotated, revoked or disabled.
    fn verify_token(
        &self,
        token: &str,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Option<ResolvedKey>;
}

/// The revocation set, as the kernel derives it from the journal tail.
///
/// It gates NEW units only. A unit already in flight runs to its own end: revoking mid-unit would
/// tear down work already paid for and observed, and the next unit is refused a fraction of a
/// second later anyway.
pub trait RevocationView: Send + Sync {
    /// Whether this credential is revoked as of the current policy epoch.
    fn is_revoked(&self, credential: &str) -> bool;
}

/// The whole chain's verdict for one unit.
#[derive(Debug, Clone, PartialEq)]
pub enum ChainVerdict {
    /// Admitted with an identity: the provider that identified, the principal, and — only on an
    /// engine arm — the enforced key it resolved. A boxed module can never populate the key,
    /// because its answer type cannot carry one.
    Identified {
        /// The provider name that identified.
        module: String,
        /// Who is calling.
        principal: Principal,
        /// The enforced key, when an engine arm resolved one.
        resolved: Option<ResolvedKey>,
    },
    /// Admitted anonymously — the open front door.
    Open,
    /// Not admitted.
    Denied,
}

/// The name the built-in signed-key arm reports as its provider.
pub const KEYS_MODULE: &str = "keys";

/// The resolved chain.
pub struct AuthChain {
    /// Whether the configuration names the built-in signed-key arm.
    keys_in_chain: bool,
    /// The ordered modules, in config order.
    chain: Vec<ChainEntry>,
}

impl std::fmt::Debug for AuthChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthChain")
            .field("keys_in_chain", &self.keys_in_chain)
            .field("chain_len", &self.chain.len())
            .finish()
    }
}

impl AuthChain {
    /// Build a chain from its resolved positions and whether the keys arm was named.
    pub fn new(chain: Vec<ChainEntry>, keys_in_chain: bool) -> Self {
        AuthChain {
            keys_in_chain,
            chain,
        }
    }

    /// The ordered module names, for the plugin catalogue. A module name is an identifier, never a
    /// credential.
    pub fn chain_names(&self) -> Vec<&'static str> {
        self.chain.iter().map(|e| e.module.name()).collect()
    }

    /// Whether the module list is empty. Note that this alone is NOT the open door — see
    /// [`AuthChain::is_open`], which also asks about the keys arm.
    pub fn has_no_modules(&self) -> bool {
        self.chain.is_empty()
    }

    /// Whether the front door is open: no boxed module and no keys arm.
    pub fn is_open(&self) -> bool {
        self.chain.is_empty() && !self.keys_in_chain
    }

    /// Whether the configuration named the built-in signed-key arm.
    pub fn keys_in_chain(&self) -> bool {
        self.keys_in_chain
    }

    /// Run the chain with no cache and no key verifier — the thin form for callers that only need
    /// the shape of the verdict.
    pub fn run_chain(&self, candidate: Option<&str>) -> ChainVerdict {
        self.run_chain_cached(candidate, None, None, 0, None)
    }

    /// Run the chain with the credential cache consulted around each cacheable module.
    ///
    /// The cache stores the module's RAW verdict; anything that narrows an identity afterwards is
    /// applied on retrieval, so a configuration change to those ceilings takes effect immediately
    /// even for a cached identity.
    pub fn run_chain_cached(
        &self,
        candidate: Option<&str>,
        cache: Option<&CredentialCache>,
        keys: Option<&dyn KeyVerifier>,
        now: u64,
        expected_aud: Option<&str>,
    ) -> ChainVerdict {
        // The open front door: no boxed module and no keys arm. The arm keeps the door shut even
        // when the module list is empty, so a chain naming only the arm runs it rather than
        // short-circuiting to an anonymous admit.
        if self.chain.is_empty() && !self.keys_in_chain {
            return ChainVerdict::Open;
        }
        // Pass verdicts are BUFFERED, not admitted, until the chain identifies. An all-pass chain
        // ends denied, so admitting them eagerly let an unauthenticated caller fill the cache with
        // rows that then evict real identities under the oldest-inserted rule. Committing only on
        // the identified return means unauthenticated traffic causes no admissions at all. A cache
        // HIT is never re-inserted: that would refresh its lifetime and quietly widen revocation.
        let mut pending_pass: Vec<&str> = Vec::new();
        // The flush generation as of BEFORE the first module is consulted. Every insert below
        // carries it, so a flush landing anywhere inside this run drops every verdict the run
        // computed — they all predate it.
        let cache_gen = cache.map(CredentialCache::generation);
        for entry in &self.chain {
            let provider = entry.provider.as_str();
            let cache_here = match (cache, candidate) {
                (Some(c), Some(cred)) if entry.module.cacheable() => Some((c, cred)),
                _ => None,
            };
            // The cache key is the PROVIDER name, not the module's self-reported name: two named
            // providers backed by one module are different verifiers with different settings, so a
            // shared row would let one provider's verdict admit the other's credential.
            let outcome = match cache_here.and_then(|(c, cred)| c.get(provider, cred, now)) {
                Some(hit) => hit,
                None => {
                    let o = entry.module.authenticate(candidate);
                    if cache_here.is_some() && matches!(o, AuthOutcome::Pass) {
                        pending_pass.push(provider);
                    }
                    o
                }
            };
            match outcome {
                AuthOutcome::Identify(principal) => {
                    if let (Some(c), Some(cred), Some(g)) = (cache, candidate, cache_gen) {
                        for name in &pending_pass {
                            c.put(name, cred, &AuthOutcome::Pass, now, g);
                        }
                        if cache_here.is_some() {
                            c.put(
                                provider,
                                cred,
                                &AuthOutcome::Identify(principal.clone()),
                                now,
                                g,
                            );
                        }
                    }
                    // No per-module role filter here: the nested role-binding table IS the
                    // allow-list, so a role this module asserts grants nothing unless that table
                    // binds it. A boxed module never resolves a key, because its answer cannot
                    // carry one.
                    return ChainVerdict::Identified {
                        module: provider.to_string(),
                        principal,
                        resolved: None,
                    };
                }
                AuthOutcome::Reject => return ChainVerdict::Denied,
                AuthOutcome::Pass => {}
            }
        }
        // The built-in signed-key arm — a sibling to the boxed modules above, run after them.
        // Cache-exempt by construction: it neither reads nor writes the cache.
        if self.keys_in_chain {
            return keys_arm_verdict(keys, candidate, now, expected_aud);
        }
        ChainVerdict::Denied
    }

    /// Run the chain and then apply the revocation gate for a NEW unit.
    ///
    /// The gate is deliberately not inside the walk: an in-flight unit re-running some part of the
    /// chain must not be torn down by a revocation that landed after it started. Only the arrival
    /// of a new unit asks this question.
    pub fn run_chain_for_new_unit(
        &self,
        candidate: Option<&str>,
        cache: Option<&CredentialCache>,
        keys: Option<&dyn KeyVerifier>,
        now: u64,
        expected_aud: Option<&str>,
        revocations: Option<&dyn RevocationView>,
    ) -> ChainVerdict {
        let verdict = self.run_chain_cached(candidate, cache, keys, now, expected_aud);
        if let (Some(r), Some(cred)) = (revocations, candidate) {
            if r.is_revoked(cred) {
                return ChainVerdict::Denied;
            }
        }
        verdict
    }

    /// A thin admit-or-deny view over the walk, for callers that do not need the principal.
    pub fn validate_token(&self, token: Option<&str>) -> bool {
        !matches!(self.run_chain(token), ChainVerdict::Denied)
    }
}

/// The built-in signed-key arm's verdict for one unit.
///
/// - Nothing presented, or an empty credential, denies. The arm is the terminal authenticator, so
///   it fails closed.
/// - No verifier available denies: a signed key cannot be verified without one.
/// - A token that resolves to an enabled key identifies, carrying the key.
/// - Anything else — unknown, expired, rotated, revoked, disabled — denies. A disabled key is
///   refused HERE and never handed onward to be quietly re-admitted by an identity synthesis.
fn keys_arm_verdict(
    keys: Option<&dyn KeyVerifier>,
    candidate: Option<&str>,
    now: u64,
    expected_aud: Option<&str>,
) -> ChainVerdict {
    let Some(token) = candidate.filter(|t| !t.is_empty()) else {
        return ChainVerdict::Denied;
    };
    let Some(keys) = keys else {
        return ChainVerdict::Denied;
    };
    match keys.verify_token(token, now, expected_aud) {
        Some(key) => ChainVerdict::Identified {
            module: KEYS_MODULE.to_string(),
            principal: principal_from_key(&key),
            resolved: Some(key),
        },
        None => ChainVerdict::Denied,
    }
}

/// The principal for a resolved key: the stable key id, its label as the name, and no roles — a key
/// is a direct grant rather than a group membership resolved through bindings.
fn principal_from_key(key: &ResolvedKey) -> Principal {
    Principal {
        id: key.id.clone(),
        name: Some(key.name.clone()),
        roles: Vec::new(),
        ttl_secs: None,
    }
}
