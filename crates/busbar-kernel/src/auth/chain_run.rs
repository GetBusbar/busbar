// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 auth chain walk with the verdict cache wired in (IF §12.11, §12.28 rules 1, 4 and 6). For each
//! instance of the route's effective chain, in chain order: an eligible instance (rule 1) asks the cache first
//! (a hit answers without calling the plugin; a standing lead is followed and its outcome shared; otherwise this
//! request leads, verifies and settles); an ineligible one verifies unshared. The first identity admits,
//! NOT_MINE moves on, a rejection or a port error ends the walk, and all NOT_MINE is "no identity".

use busbar_contract::crypto::Sha256;
use busbar_plugin_abi::auth::KEYS_STALE;
use busbar_plugin_abi::types::Pair;
use busbar_plugin_loader::ports::auth::{AuthIn, AuthPort, Identity, Verdict, Verify};
use busbar_plugin_loader::ports::{CallCx, PortError};

use super::verdicts::{eligible, CredentialHash, VerdictCache, VerdictGet, VerdictKey};

/// One instance of a route's effective chain: its auth instance id (the verdict cache's key) and its port.
#[derive(Clone, Copy)]
pub struct ChainInstance<'a> {
    pub id: u64,
    pub port: &'a dyn AuthPort,
}

/// How a walk ended.
#[derive(Debug)]
pub enum ChainEnd {
    /// The first identity of the chain.
    Admitted { instance: u64, identity: Identity },
    /// Every instance answered NOT_MINE (or the chain is empty): R_AUTH_REQUIRED.
    NoIdentity,
    /// An instance refused the credential; `code` is the plugin's (a kind code core maps before any client
    /// sees it, §12.15). The plugin's text goes to audit only.
    Rejected {
        instance: u64,
        code: u32,
        text: Box<str>,
    },
    /// CA-5: the identity is held by a provisioning instance that links this inbound instance: R_DENIED, no plugin
    /// is asked (the principal-held audit is the caller's). Checked after the verdict, so a cached identity is
    /// held the same.
    Held { instance: u64 },
    /// An instance failed (FAILED or a call error).
    Failed { instance: u64, error: PortError },
}

/// `VerdictKey.credential` (§12.28): SHA-256, through the facade, over, for each D_CRED_HEADER name in declared
/// order, the u32 LE name length, the name, the u32 LE count of that header's values on the request and each
/// value with its u32 LE length. No allocation.
#[must_use]
pub fn credential_hash(cred_headers: &[Box<str>], headers: &[Pair<'_>]) -> [u8; 32] {
    let mut h = Sha256::new();
    for name in cred_headers {
        h.update(&len_le(name.len()));
        h.update(name.as_bytes());
        let values = || {
            headers
                .iter()
                .filter(|p| p.name.get().eq_ignore_ascii_case(name))
        };
        h.update(&len_le(values().count()));
        for pair in values() {
            let value = pair.value.get();
            h.update(&len_le(value.len()));
            h.update(value);
        }
    }
    h.finish()
}

fn len_le(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_le_bytes()
}

/// Runs the effective chain over one request.
pub async fn run_chain(
    cache: &dyn VerdictCache,
    chain: &[ChainInstance<'_>],
    cx: CallCx,
    req: &AuthIn<'_>,
) -> ChainEnd {
    for instance in chain {
        match verify_cached(cache, *instance, cx, req).await {
            Ok(Verdict::Identity(identity)) => {
                if crate::holds::held_by_id(instance.id, identity.subject()) {
                    return ChainEnd::Held {
                        instance: instance.id,
                    };
                }
                return ChainEnd::Admitted {
                    instance: instance.id,
                    identity,
                };
            }
            Ok(Verdict::NotMine) => {}
            Ok(Verdict::Rejected { code, text }) => {
                return ChainEnd::Rejected {
                    instance: instance.id,
                    code,
                    text,
                }
            }
            Err(error) => {
                return ChainEnd::Failed {
                    instance: instance.id,
                    error,
                }
            }
        }
    }
    ChainEnd::NoIdentity
}

/// One instance's verdict through the cache (§12.28 rule 4). A KEYS_STALE answer flushes the instance (rule 6).
pub async fn verify_cached(
    cache: &dyn VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &AuthIn<'_>,
) -> Result<Verdict, PortError> {
    let port = instance.port;
    if !eligible(port.cred_headers().len(), port.facts()) {
        return verify(port, cx, req).await;
    }
    let key = VerdictKey {
        auth_instance: instance.id,
        credential: CredentialHash(credential_hash(port.cred_headers(), req.headers)),
    };
    let lead = match cache.begin(key, req.now_s) {
        VerdictGet::Hit(identity) => return Ok(Verdict::Identity(identity)),
        VerdictGet::Bypass => return verify(port, cx, req).await,
        VerdictGet::Lead(lead) => lead,
        VerdictGet::Follow(follow) => match follow.await {
            Ok(shared) => return shared,
            Err(lead) => lead,
        },
    };
    let outcome = verify(port, cx, req).await;
    lead.settle(&outcome, req.now_s);
    if matches!(&outcome, Ok(Verdict::Rejected { code, .. }) if *code == KEYS_STALE) {
        cache.flush_instance(instance.id);
    }
    outcome
}

/// Rule 6: a `refresh` that completed OK (scheduled, or after KEYS_STALE) drops every entry of the instance.
pub fn refreshed(
    cache: &dyn VerdictCache,
    auth_instance: u64,
    result: &Result<Option<u32>, PortError>,
) {
    if result.is_ok() {
        cache.flush_instance(auth_instance);
    }
}

async fn verify(port: &dyn AuthPort, cx: CallCx, req: &AuthIn<'_>) -> Result<Verdict, PortError> {
    match port.verify(cx, req) {
        Verify::Done(done) => done,
        Verify::Io(io) => io.await,
    }
}

#[cfg(test)]
#[path = "tests/chain_policy_tests.rs"]
mod policy_tests;
