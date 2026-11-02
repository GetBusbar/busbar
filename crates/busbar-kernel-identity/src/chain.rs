// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The chain walk: config order, first identification wins, a rejection stops, a pass continues.

use crate::module::{AuthModule, AuthOutcome};
use crate::principal::Principal;

/// One resolved chain position: the provider NAME the config referenced, and the module behind it.

pub struct ChainEntry {
    /// The provider name from the configuration.
    pub provider: String,
    /// The module resolved for that position.
    pub module: Box<dyn AuthModule>,
}

/// The enforced key the built-in signed-key arm resolves.
///
/// Opaque here on purpose: this unit needs to carry it, never to read it.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKey {
    /// The key's stable id — the principal's id.
    pub id: String,
    /// The key's operator-facing label.
    pub name: String,
}

/// The built-in signed-key verifier, as the chain reaches it.

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

    pub fn chain_names(&self) -> Vec<&'static str> {
        self.chain.iter().map(|e| e.module.name()).collect()
    }

    /// Whether the front door is open: no boxed module and no keys arm.
    pub fn is_open(&self) -> bool {
        self.chain.is_empty() && !self.keys_in_chain
    }

    /// Whether the configuration named the built-in signed-key arm.
    pub fn keys_in_chain(&self) -> bool {
        self.keys_in_chain
    }

    /// Run the chain with no key verifier — the thin form for callers that only need the shape of

    pub fn run_chain(&self, candidate: Option<&str>) -> ChainVerdict {
        self.run_chain_with(candidate, None, 0, None)
    }

    /// Run the chain: config order, the first module to identify admits, a reject stops the walk, a

    pub fn run_chain_with(
        &self,
        candidate: Option<&str>,
        keys: Option<&dyn KeyVerifier>,
        now: u64,
        expected_aud: Option<&str>,
    ) -> ChainVerdict {
        if self.chain.is_empty() && !self.keys_in_chain {
            return ChainVerdict::Open;
        }
        for entry in &self.chain {
            match entry.module.authenticate(candidate) {
                AuthOutcome::Identify(principal) => {
                    return ChainVerdict::Identified {
                        module: entry.provider.clone(),
                        principal,
                        resolved: None,
                    };
                }
                AuthOutcome::Reject => return ChainVerdict::Denied,
                AuthOutcome::Pass => {}
            }
        }

        if self.keys_in_chain {
            return keys_arm_verdict(keys, candidate, now, expected_aud);
        }
        ChainVerdict::Denied
    }

    /// A thin admit-or-deny view over the walk, for callers that do not need the principal.
    pub fn validate_token(&self, token: Option<&str>) -> bool {
        !matches!(self.run_chain(token), ChainVerdict::Denied)
    }
}

/// The built-in signed-key arm's verdict for one unit.

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

fn principal_from_key(key: &ResolvedKey) -> Principal {
    Principal {
        id: key.id.clone(),
        name: Some(key.name.clone()),
        roles: Vec::new(),
        ttl_secs: None,
    }
}
