// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ENGINE-OWNED CONNECTION POOLING to upstream MCP servers, keyed by the PINNED address.
//!
//! ## Why the pool key includes the address and not just the host
//!
//! The dispatch-time resolve-then-pin in `super::ssrf` is only a defence if the connection actually
//! goes to the address that was checked. `reqwest` resolves per connection, so a pooled client
//! built for a hostname would re-resolve on the next new connection and could reach an address
//! nobody validated — the TOCTOU this whole path exists to close, reintroduced by the cache in
//! front of it.
//!
//! So the pool is keyed `(host, pinned-address)` and each entry is a `reqwest::Client` whose
//! resolver is pinned to that one address. A rebinding resolver that answers differently produces a
//! DIFFERENT key, which means a new client, which means the check runs again — the cache cannot
//! launder an unvalidated destination, because an unvalidated destination is not in it.
//!
//! Keep-alive is safe under this scheme and it is worth saying why explicitly, because it invites
//! exactly one confusion: busbar's HTTP connection reuse is NOT a protocol session. It carries
//! no negotiated authority, nothing was established over it, and there is nothing on it to
//! invalidate when a pin changes. What must be re-checked on a pin change is the CATALOGUE
//! generation, and that is `super::catalogue`'s job, per request.
//!
//! ## Why not reuse `App.client`
//!
//! `state::UpstreamClients` is a set of shards for LLM provider traffic with no per-destination
//! pinning; its whole design is that any shard can serve any host. Pinning is per destination by
//! definition, so it cannot be a property of a shared shard. This pool is small — one client per
//! live upstream address, bounded and evicted — and it reuses the same construction settings so the
//! two do not drift on timeouts, HTTP/2 or the redirect policy.
//!
//! `redirect: none` is inherited from that construction and is load-bearing here for a second
//! reason: a redirect is a destination that was never pinned, arriving at the moment the upstream
//! credential is already on the wire.

use super::ssrf::{SsrfPolicy, SsrfRefusal};
use crate::net_guard::PinnedTarget;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

/// The cap on distinct pinned clients held at once.
///
/// A bound rather than an unbounded map because the key contains a RESOLVED ADDRESS, and an upstream
/// whose DNS round-robins across a large pool would otherwise grow one client per address it ever
/// answered with. Eviction is whole-entry: dropping a `reqwest::Client` closes its idle sockets.
const MAX_PINNED_CLIENTS: usize = 64;

/// One upstream's pooled clients, keyed by pinned address.
#[derive(Default)]
pub(crate) struct McpConnectionPool {
    clients: Mutex<HashMap<(String, SocketAddr), reqwest::Client>>,
}

impl std::fmt::Debug for McpConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `reqwest::Client` has no useful Debug and printing the map's keys would put resolved
        // internal addresses into logs. Presence and size only.
        let n = self.clients.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("McpConnectionPool")
            .field("pinned_clients", &n)
            .finish()
    }
}

impl McpConnectionPool {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The number of live pinned clients. Read by the tests, which is the point: "the pool reuses a
    /// client for a repeated destination" is a claim about this number, and asserting it is how the
    /// claim stops being an assertion about intent.
    // Reached only by the connect/refresh path, which has no verb yet.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.clients.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Resolve, check, pin, and return a client bound to the checked address.
    ///
    /// The check runs BEFORE the cache is consulted for a NEW address and the cache is keyed on the
    /// result, so there is no ordering in which an unchecked address gets a client.
    pub(crate) async fn client_for(
        &self,
        url: &str,
        policy: SsrfPolicy,
        timeout: Duration,
    ) -> Result<(reqwest::Client, PinnedTarget), SsrfRefusal> {
        let target = super::ssrf::pin_upstream(url, policy).await?;
        // THE KEY CONTAINS THE PINNED ADDRESS. Keying by host alone would let a pooled client
        // re-resolve on its next new connection — the TOCTOU the pin closes, reintroduced by the
        // cache in front of it. `socket_addr()` is the pinned address, never a fresh lookup.
        let key = (target.host().to_string(), target.socket_addr());
        if let Ok(map) = self.clients.lock() {
            if let Some(c) = map.get(&key) {
                return Ok((c.clone(), target));
            }
        }
        let client = build_pinned_client(&target, timeout)?;
        if let Ok(mut map) = self.clients.lock() {
            if map.len() >= MAX_PINNED_CLIENTS {
                // Evict one arbitrary entry rather than growing without bound. Arbitrary is honest:
                // an LRU would need a second structure and a lock held longer, to choose between
                // clients that are interchangeable except for their destination.
                if let Some(victim) = map.keys().next().cloned() {
                    map.remove(&victim);
                }
            }
            map.insert(key, client.clone());
        }
        Ok((client, target))
    }
}

/// Build a `reqwest::Client` whose resolution for this one host is pinned to this one address.
///
/// The hostname is preserved for `Host` and SNI, so the certificate is still validated against the
/// name the operator registered. Pinning the address without preserving the name would turn a
/// validated TLS connection into an unvalidated one, which trades one hole for a bigger one.
fn build_pinned_client(
    target: &PinnedTarget,
    timeout: Duration,
) -> Result<reqwest::Client, SsrfRefusal> {
    reqwest::Client::builder()
        .resolve_to_addrs(target.host(), &[target.socket_addr()])
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(super::ssrf::DISPATCH_CONNECT_TIMEOUT)
        .timeout(timeout)
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| SsrfRefusal::Unresolvable {
            host: target.host().to_string(),
            reason: format!("could not build a pinned HTTP client: {e}"),
        })
}

#[cfg(test)]
#[path = "tests/pool_tests.rs"]
mod pool_tests;
