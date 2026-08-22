// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST-OWNED OUTBOUND SURFACE, shared by every protocol plane.
//!
//! One outbound hop looks the same whatever framing sits on top of it: a request goes to an address
//! the SSRF guard already judged and pinned, and a reply comes back with a status, a body, and — on
//! a TLS hop — the peer's observed public-key identity. This module owns the neutral RETURN types of
//! that hop so no single plane owns them. A plane composes protocol bytes; it never holds a client,
//! a socket, a resolver, or the vocabulary of the wire round trip.
//!
//! The types here are deliberately protocol-blind. There is nowhere in [`Response`] to record which
//! plane made the hop, and that absence is the point: the same buffered round trip serves an A2A
//! card fetch, an A2A task relay and an MCP dispatch, and a field that named one of them would be a
//! field the other two had to leave meaningless.

/// One buffered outbound round trip, reduced to what a caller reads back.
///
/// `Default` is the empty response — status `0`, no location, no body, no observed identity — used
/// by a fixture that answers without a socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Response {
    /// The HTTP status the peer answered with.
    pub(crate) status: u16,
    /// The `Location` header, verbatim, for a 3xx. NEVER followed by the backend itself — a redirect
    /// is a fresh, unguarded URL handed back for the caller's own guard to judge.
    pub(crate) location: Option<String>,
    /// The response body, read to the caller's ceiling.
    pub(crate) body: Vec<u8>,
    /// THE TRANSPORT-LAYER IDENTITY OF THE PEER: the `sha256/…` pin of the leaf certificate's
    /// SubjectPublicKeyInfo, where this hop ran over TLS.
    ///
    /// `None` on a plaintext hop, and `None` where the certificate could not be walked. It is a fact
    /// about the connection THIS response arrived over, so it travels on the response rather than
    /// being fetched separately: a second look at "the certificate that host serves" would be a
    /// second connection a rebinding attacker gets to answer differently. A caller that requires a
    /// pin refuses on `None` — "we could not look" and "it matched" are the two answers a pin exists
    /// to keep apart.
    pub(crate) peer_spki: Option<String>,
    /// BUSBAR'S OWN END OF THE HANDSHAKE: whether this hop carried a client certificate into the
    /// handshake, so it was presented if the peer asked for one.
    ///
    /// The OTHER direction from [`Response::peer_spki`], and it travels on the response for the same
    /// reason: it is a fact about the connection this reply arrived over. `false` means there was
    /// nothing to present at all — it cannot mean "the peer did not ask", because TLS gives a client
    /// no way to tell, after the fact, a handshake in which the peer sent no `CertificateRequest`
    /// from one in which it did.
    pub(crate) client_identity_offered: bool,
}

/// The head of a streaming reply: what the backend answered before any body byte arrived.
///
/// The status is knowable before the first chunk because a caller that has already written bytes to
/// its own consumer cannot then change its mind and answer an error — so the decision "is this a
/// stream at all" is made on the head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StreamHead {
    /// The HTTP status the peer answered with.
    pub(crate) status: u16,
    /// The backend's `content-type`, lower-cased, or empty. A backend that answers a stream request
    /// with `application/json` has answered a NON-stream, and relaying that as event-stream framing
    /// would be busbar inventing a framing the backend never used.
    pub(crate) content_type: String,
    /// The body, for a reply the backend did NOT stream. Empty on a real stream: those bytes were
    /// handed to the chunk sink instead.
    pub(crate) body: Vec<u8>,
}

/// What a chunk sink says about continuing. A sink whose consumer has gone away asks the hop to
/// STOP rather than being written to forever: a caller that disconnected mid-stream must not leave
/// busbar holding a thread against an upstream that is happy to keep talking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChunkFlow {
    Continue,
    Stop,
}

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long the connect phase of one hop may take. Bounds only the connect, not the whole request —
/// the total deadline rides the REQUEST (see [`PinnedClientPool`]), because a pooled client is
/// shared across callers with different total deadlines and a client-level total would silently make
/// the first caller's deadline every later caller's.
pub(crate) const EGRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a pooled connection may sit idle before busbar drops it.
///
/// FOUR SECONDS, because the peer decides how long an idle connection lives and the most common
/// server default is FIVE (Node's `keepAliveTimeout`; nginx and friends are longer). A pool that
/// idles connections for 90 seconds reuses sockets most upstreams closed a minute ago, and the reuse
/// race surfaces as an `error sending request` on the FIRST call after a quiet spell — a
/// non-idempotent POST hyper will not retry. Staying under the shortest common peer timeout means an
/// idle connection is dropped by US before the peer can close it under us; the cost is a fresh TCP
/// handshake on loopback-or-LAN scale after four quiet seconds.
pub(crate) const EGRESS_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(4);

/// The client's own resolver, in production: one that refuses every name.
///
/// A pinned client (see [`build_pinned_client`]) never needs to resolve anything — the host override
/// sends the socket to the address the guard already judged. Installing a resolver that REFUSES
/// makes the difference between "never needs to" and "cannot" observable: if the pin is ever
/// dropped, the hop fails LOUDLY with this message rather than quietly resolving the name a second
/// time — which is the lookup a DNS-rebinding attacker needs and must not exist. The message names
/// the invariant ("exactly once") and the name it was asked about, so a log line is actionable.
pub(crate) struct RefuseSecondLookup;

impl reqwest::dns::Resolve for RefuseSecondLookup {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_string();
        Box::pin(std::future::ready(Err(Box::<
            dyn std::error::Error + Send + Sync,
        >::from(format!(
            "a governed egress resolves each name exactly once, before the guard judges the answer, \
             and connects to the address that survived; the HTTP client asked to resolve `{name}` a \
             second time, which is the DNS-rebind window the pin exists to close and must not happen"
        )))))
    }
}

/// Hands a shared resolver to the client, which wants a concrete type. Lets a test install a counting
/// resolver where production installs [`RefuseSecondLookup`], so "the client performed no lookup of
/// its own" is an assertion rather than an intention.
struct DelegatingDns(Arc<dyn reqwest::dns::Resolve>);

impl reqwest::dns::Resolve for DelegatingDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.0.resolve(name)
    }
}

/// A transport error WITH ITS CAUSE CHAIN, flattened.
///
/// `reqwest::Error`'s own `Display` is the request that failed and nothing about why — the
/// certificate refusal, the connection reset and the timeout all render identically, so the reason
/// in the `source()` chain is appended here. An operator reading a refused hop is entitled to the
/// reason. The caller strips the url first (`without_url()`) where it must not appear in the message.
pub(crate) fn with_cause(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut cause = err.source();
    while let Some(c) = cause {
        out.push_str(": ");
        out.push_str(&c.to_string());
        cause = c.source();
    }
    out
}

/// THE ONE CANONICAL PINNED CLIENT, built to the strongest posture every plane now shares.
///
/// Every knob here is load-bearing:
/// * `redirect: none` — a 3xx is a fresh, fully untrusted URL that the GUARD must see; a client that
///   followed it would perform the next hop with no guard at all.
/// * `tls_info(true)` — the peer certificate is readable on the response AFTERWARDS. This asks for
///   nothing and changes which certificates are accepted not at all; it only lets busbar OBSERVE the
///   one that was accepted, for its own SPKI pinning and audit.
/// * `tcp_nodelay`, `pool_idle_timeout`, `connect_timeout` — the connection-management posture; none
///   is wire-observable.
/// * `dns_resolver` — the caller's resolver (production: [`RefuseSecondLookup`]).
/// * `.resolve(host, addr)` — THE PIN: a host→address override so the socket goes to the address the
///   guard already judged. The REQUEST is unchanged — it still carries the hostname, so the `Host`
///   header, TLS SNI and the certificate's name check are all still about the hostname. Rewriting
///   the URL to the address would connect to the same socket and silently change all three.
///
/// There is deliberately NO total-request timeout on the client: it is applied per REQUEST, because a
/// pooled client serves callers with different deadlines. Turning certificate verification off
/// appears nowhere — a pin obtained that way would be strictly worse than no pin.
pub(crate) fn build_pinned_client(
    host: &str,
    addr: SocketAddr,
    dns: Arc<dyn reqwest::dns::Resolve>,
    identity: Option<reqwest::Identity>,
    extra_roots: &[reqwest::Certificate],
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .tls_info(true)
        .tcp_nodelay(true)
        .connect_timeout(EGRESS_CONNECT_TIMEOUT)
        .pool_idle_timeout(EGRESS_POOL_IDLE_TIMEOUT)
        .dns_resolver(Arc::new(DelegatingDns(dns)))
        .resolve(host, addr);
    for root in extra_roots {
        builder = builder.add_root_certificate(root.clone());
    }
    // BUSBAR'S OWN END OF A MUTUAL HANDSHAKE. Offering a certificate ASKS FOR NOTHING and WEAKENS
    // NOTHING: it is presented only when the peer's `CertificateRequest` asks for one, and the peer's
    // certificate is still verified by the ordinary chain-and-name check. `None` presents nothing,
    // which against an mTLS peer means the peer closes the handshake itself rather than busbar
    // forging an identity it was not asked to hold.
    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }
    builder.build()
}

/// A pool of pinned clients, keyed by the PINNED (host, address) pair, shared by every plane.
///
/// ## Why the key includes the address and not just the host
///
/// The resolve-then-pin guard is only a defence if the connection goes to the address that was
/// checked. `reqwest` resolves per connection, so a pooled client keyed by hostname would re-resolve
/// on its next new connection and could reach an address nobody validated — the TOCTOU the whole
/// path exists to close, reintroduced by the cache in front of it. Keying on the RESOLVED address
/// means a rebinding resolver that answers differently produces a DIFFERENT key → a new client → the
/// check runs again: the cache cannot launder an unvalidated destination, because an unvalidated
/// destination is not in it. (The pinned clients themselves also refuse a second lookup, so reuse is
/// only ever to the already-judged target.)
///
/// The owner supplies the client BUILD closure, so a per-registration identity or a test trust
/// anchor stays a property of the owner and never has to enter this key: all clients in one pool
/// share the owner's fixed posture, and only the destination varies.
pub(crate) struct PinnedClientPool {
    clients: Mutex<HashMap<(String, SocketAddr), reqwest::Client>>,
    max: usize,
}

impl std::fmt::Debug for PinnedClientPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `reqwest::Client` has no useful Debug and the keys are resolved internal addresses. Size
        // only.
        f.debug_struct("PinnedClientPool")
            .field("pinned_clients", &self.len())
            .finish()
    }
}

/// The cap a [`PinnedClientPool::default`] holds — enough distinct pinned clients that a busy fleet
/// keeps its live upstreams warm, bounded so a DNS round-robin cannot grow the map without end. A
/// pool that wants a different cap builds with [`PinnedClientPool::with_capacity`].
const DEFAULT_MAX_PINNED_CLIENTS: usize = 64;

impl Default for PinnedClientPool {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_PINNED_CLIENTS)
    }
}

impl PinnedClientPool {
    /// A pool that holds at most `max` distinct pinned clients. A bound rather than an unbounded map
    /// because the key contains a RESOLVED ADDRESS, and an upstream whose DNS round-robins across a
    /// large pool would otherwise grow one client per address it ever answered with. Eviction is
    /// whole-entry: dropping a `reqwest::Client` closes its idle sockets.
    pub(crate) fn with_capacity(max: usize) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            max,
        }
    }

    /// The number of live pinned clients. Read by tests: "the pool reuses a client for a repeated
    /// destination" is a claim about this number, and asserting it is how the claim stops being an
    /// assertion about intent.
    pub(crate) fn len(&self) -> usize {
        self.clients.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Return a client pinned to `(host, addr)`, building one with `build` on a miss. The build runs
    /// only for a NEW destination; a repeated one returns the cached clone.
    pub(crate) fn client_for<E>(
        &self,
        host: &str,
        addr: SocketAddr,
        build: impl FnOnce() -> Result<reqwest::Client, E>,
    ) -> Result<reqwest::Client, E> {
        let key = (host.to_string(), addr);
        if let Ok(map) = self.clients.lock() {
            if let Some(c) = map.get(&key) {
                return Ok(c.clone());
            }
        }
        let client = build()?;
        if let Ok(mut map) = self.clients.lock() {
            if map.len() >= self.max {
                // Evict one arbitrary entry rather than growing without bound. Arbitrary is honest:
                // an LRU would need a second structure and a lock held longer, to choose between
                // clients that are interchangeable except for their destination.
                if let Some(victim) = map.keys().next().cloned() {
                    map.remove(&victim);
                }
            }
            map.insert(key, client.clone());
        }
        Ok(client)
    }
}

#[cfg(test)]
#[path = "egress/tests.rs"]
mod tests;
