// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's tests, ported with their assertions intact from the shipped chain's own suite.

mod cache_tests;
mod carrier_tests;
mod chain_tests;
mod detect_tests;
mod exchange_tests;
mod unit_tests;

use crate::chain::{ChainEntry, ResolvedKey};
use crate::module::{AuthModule, AuthOutcome};
use crate::principal::Principal;

/// A stand-in module with a canned answer and a declared cacheability, so a test can state exactly
/// the chain shape it means and nothing else.
pub(crate) struct Canned {
    pub(crate) name: &'static str,
    pub(crate) outcome: AuthOutcome,
    pub(crate) cacheable: bool,
    /// How many times the module was actually consulted — the only way to tell a cache hit from a
    /// re-verification. Shared so a test can watch it after the module is boxed into the chain.
    pub(crate) calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Canned {
    pub(crate) fn new(name: &'static str, outcome: AuthOutcome) -> Self {
        Canned {
            name,
            outcome,
            cacheable: false,
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub(crate) fn cacheable(name: &'static str, outcome: AuthOutcome) -> Self {
        Canned {
            name,
            outcome,
            cacheable: true,
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl AuthModule for Canned {
    fn name(&self) -> &'static str {
        self.name
    }
    fn authenticate(&self, _candidate: Option<&str>) -> AuthOutcome {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.outcome.clone()
    }
    fn cacheable(&self) -> bool {
        self.cacheable
    }
}

/// A module whose cacheability is left at the trait default — the shape that proves the default is
/// "not cacheable" rather than "cacheable".
pub(crate) struct DefaultCacheability;

impl AuthModule for DefaultCacheability {
    fn name(&self) -> &'static str {
        "default-cacheability"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> AuthOutcome {
        AuthOutcome::Identify(Principal::from_id("someone"))
    }
}

pub(crate) fn entry(provider: &str, module: Box<dyn AuthModule>) -> ChainEntry {
    ChainEntry {
        provider: provider.to_string(),
        module,
    }
}

/// A key verifier that admits exactly one token, and only for the audience it was minted for.
pub(crate) struct OneKey {
    pub(crate) token: &'static str,
    pub(crate) aud: Option<&'static str>,
}

impl crate::chain::KeyVerifier for OneKey {
    fn verify_token(
        &self,
        token: &str,
        _now: u64,
        expected_aud: Option<&str>,
    ) -> Option<ResolvedKey> {
        if token != self.token || expected_aud != self.aud {
            return None;
        }
        Some(ResolvedKey {
            id: "vk_one".to_string(),
            name: "the one key".to_string(),
        })
    }
}

/// A stand-in credential digest. It is not a hash and does not need to be: the cache's rules are
/// about lifetimes, eviction and the flush generation, none of which depend on the digest being
/// one-way. Distinct credentials still map to distinct keys, which is all the rules require.
pub(crate) fn test_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Headers as a plain list of pairs, for the carrier and ladder tests.
pub(crate) struct Headers(pub(crate) Vec<(&'static str, &'static str)>);

impl crate::carrier::HeaderView for Headers {
    fn header(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }
}

impl crate::detect::HeaderProbe for Headers {
    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|(n, _)| *n == name)
    }
    fn value(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }
}
