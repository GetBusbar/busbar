// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's tests, ported with their assertions intact from the shipped chain's own suite.

mod caller_ref_tests;
mod chain_tests;
mod exchange_tests;
mod hardening;
mod invariants;
mod operator_tests;
mod unit_tests;

use crate::chain::{ChainEntry, ResolvedKey};
use crate::module::{AuthModule, AuthOutcome};

/// A stand-in module with a canned answer, so a test can state exactly
/// the chain shape it means and nothing else.
pub(crate) struct Canned {
    pub(crate) name: &'static str,
    pub(crate) outcome: AuthOutcome,
    /// How many times the module was actually consulted. Shared so a test can watch it after the module is boxed into the chain.
    pub(crate) calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Canned {
    pub(crate) fn new(name: &'static str, outcome: AuthOutcome) -> Self {
        Canned {
            name,
            outcome,
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
