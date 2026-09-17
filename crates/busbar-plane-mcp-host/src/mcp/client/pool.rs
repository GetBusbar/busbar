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
use busbar_substrate::net_guard::PinnedTarget;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One upstream's pooled clients, keyed by pinned address — and the live stdio children.
///
/// The children ride here rather than on a second field of `AppState` because they are the same
/// thing at the same lifetime: busbar's live connections to registered MCP upstreams, owned by the
/// engine, threaded to every send site already. A separate handle would be a second thing to
/// remember to pass, and the site that forgot would be the one that could not reach a stdio server.
#[derive(Default)]
pub(crate) struct McpConnectionPool {
    /// The pinned-client pool, keyed by the judged `(host, address)` — now the shared core backend
    /// ([`busbar_substrate::egress::PinnedClientPool`]), so mcp's dispatch hops are built to the same posture
    /// every plane shares (the refusing resolver, `tls_info` so the peer SPKI is observable, and the
    /// canonical connection knobs).
    clients: busbar_substrate::egress::PinnedClientPool,
    /// The supervised child processes. Empty on every deployment that registers no stdio server,
    /// and it costs a `BTreeMap` to be so.
    pub(crate) children: super::stdio::StdioPool,
    /// PEER-SIGNALLED REFRESHES, rate-limited. See [`RefreshTriggers`].
    pub(crate) triggers: RefreshTriggers,
    /// PEER-ANNOUNCED RESOURCE UPDATES, bounded. See [`ResourceUpdates`].
    pub(crate) updates: ResourceUpdates,
}

/// EVERY `…/list_changed` A PEER HAS SIGNALLED SINCE THE LAST SWEEP READ THIS, rate-limited per
/// server.
///
/// ## Why the trigger is a SET OF NAMES and never a payload
///
/// A `notifications/tools/list_changed` is a message from an UNTRUSTED peer. `super::catalogue`'s
/// rule is that such a message may bring a re-pull FORWARD and may not choose its content: the
/// authoritative `tools/list` is re-fetched and re-hashed exactly as a scheduled refresh would do
/// it. This structure is that rule made structural — there is nowhere in it to put a tool
/// definition, so there is no version of "the peer told us what changed" that this can express.
///
/// ## Why it is rate-limited, and why the limiter lives per server
///
/// Without a floor interval a peer can drive busbar's own outbound fetch rate by writing one line
/// per millisecond, which is an amplifier with a config file behind it. [`RefreshGate`] enforces the
/// floor, and there is one gate per server so a chatty registration cannot starve a quiet one's
/// trigger by consuming a shared budget.
///
/// ## Why it lives on the POOL
///
/// The same argument the stdio children ride here on: this is engine-owned state at the lifetime of
/// busbar's connections to upstreams, and the pool is already threaded to every send site. A
/// separate handle would be a second thing to remember to pass, and the site that forgot would be
/// the one that could not record a trigger.
#[derive(Debug, Default)]
pub(crate) struct RefreshTriggers {
    gates: Mutex<HashMap<String, super::catalogue::RefreshGate>>,
    pending: Mutex<std::collections::BTreeSet<String>>,
}

/// The floor between two peer-signalled refreshes of the SAME server.
///
/// Sixty seconds: long enough that a peer emitting a notification per tool per change cannot turn
/// one edit into a fetch storm, short enough that an operator who edits a child's tool set sees the
/// change land within a minute rather than only at the next call's `verify_ttl:` window.
const PEER_TRIGGER_FLOOR_MS: u64 = 60_000;

impl RefreshTriggers {
    /// A peer signalled that `server`'s catalogue moved. Returns whether the signal was ACCEPTED —
    /// `false` means the rate limiter swallowed it, which is a fact a caller logs rather than a
    /// failure.
    pub(crate) fn signal(&self, server: &str, now_ms: u64) -> bool {
        let allowed = {
            let mut gates = match self.gates.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            gates
                .entry(server.to_string())
                .or_insert_with(|| super::catalogue::RefreshGate::new(PEER_TRIGGER_FLOOR_MS))
                .allow(now_ms)
        };
        if allowed {
            match self.pending.lock() {
                Ok(mut p) => p.insert(server.to_string()),
                Err(p) => p.into_inner().insert(server.to_string()),
            };
        }
        allowed
    }

    /// CONSUME one server's pending signal, if any — returns whether `server` had been signalled. Used
    /// by verify-on-call to mark that server's snapshot STALE so the NEXT `tools/call` re-verifies
    /// even inside its `verify_ttl`. Consuming rather than reading, so one accepted signal brings
    /// forward exactly one re-verification: a flag the call path only read would re-fetch on every
    /// call until the ttl lapsed, on the strength of a notification already acted on. The
    /// notification's CONTENTS are never read — this moves TIMING only, and what follows is the
    /// authoritative `tools/list`, re-hashed.
    pub(crate) fn take_if_pending(&self, server: &str) -> bool {
        match self.pending.lock() {
            Ok(mut p) => p.remove(server),
            Err(p) => p.into_inner().remove(server),
        }
    }

    /// DRAIN the whole pending set — the test-only reader that asserts [`Self::signal`] populated it.
    /// Production consumes per server through [`Self::take_if_pending`] on the call path.
    #[cfg(all(test, feature = "test-support"))]
    pub(crate) fn take_pending(&self) -> std::collections::BTreeSet<String> {
        match self.pending.lock() {
            Ok(mut p) => std::mem::take(&mut *p),
            Err(p) => std::mem::take(&mut *p.into_inner()),
        }
    }
}

/// EVERY `notifications/resources/updated` A PEER HAS ANNOUNCED, as `(sequence, server, uri)` —
/// the one peer message whose PAYLOAD is read, and the reading is one string field under two
/// gates.
///
/// ## Why this one breaks the "names, never payloads" rule, and how far it breaks it
///
/// [`RefreshTriggers`]' rule is that an untrusted peer's message moves TIMING and never CONTENT,
/// because the four list-changed names all mean "re-pull the authoritative list" and the list is
/// re-fetched from scratch. `resources/updated` is different in kind: it names WHICH resource
/// moved, and a relay that dropped the name would have nothing to relay — the whole point of the
/// downstream category (`resourceSubscriptions` on `subscriptions/listen`) is that a subscriber
/// asked about specific URIs. So exactly ONE field is read (`params.uri`, a string, length-capped
/// here), and it is BELIEVED nowhere: the server-leg relay in `crate::mcp::subscribe` emits an
/// event only when the recorded uri resolves, under the SUBSCRIBER'S OWN grant, to an
/// operator-declared resource of the SAME server that announced it. An upstream can therefore
/// choose the timing of a notification about a resource the operator declared on ITS registration,
/// and nothing else — it cannot name another server's resource, invent a uri the operator never
/// wrote, or reach a subscriber whose grant does not cover the resource.
///
/// ## Why a bounded ring with per-reader CURSORS, not a drained set
///
/// `take_if_pending` consumes because ONE call acts on a `list_changed` trigger exactly once. An
/// update has MANY readers — every open listen stream holds its own position — so consuming would
/// deliver each
/// event to whichever stream polled first and silence to the rest. Readers keep a sequence cursor
/// and ask for what they have not seen; the ring keeps [`MAX_RESOURCE_UPDATES`] events and evicts
/// the oldest, so a slow stream misses old events rather than growing memory — a missed
/// notification costs a client one re-read of a resource it can re-read at any time, which is the
/// same trade the change-key hash makes.
#[derive(Debug, Default)]
pub(crate) struct ResourceUpdates {
    events: Mutex<std::collections::VecDeque<(u64, String, String)>>,
    next_seq: std::sync::atomic::AtomicU64,
}

/// The ring bound. Enough that a burst across a busy fleet reaches every 250ms poller; small
/// enough that a hostile upstream writing one notification per millisecond evicts its OWN noise.
const MAX_RESOURCE_UPDATES: usize = 256;

/// The cap on one announced uri. A resource uri an operator actually declared fits here with room;
/// a longer one is a payload wearing a uri's clothes, dropped before it is stored.
const MAX_ANNOUNCED_URI_BYTES: usize = 2048;

impl ResourceUpdates {
    /// RECORD one announcement from `server` about `uri`. Oversized uris are dropped — they cannot
    /// match any operator declaration, so storing them would spend the ring on noise.
    pub(crate) fn record(&self, server: &str, uri: &str) {
        if uri.is_empty() || uri.len() > MAX_ANNOUNCED_URI_BYTES {
            return;
        }
        let mut events = match self.events.lock() {
            Ok(e) => e,
            Err(p) => p.into_inner(),
        };
        // Allocate the sequence UNDER the events lock, together with the push — never before it.
        // `since` returns `latest()` as the cursor a reader holds next, and `since` also takes this
        // lock, so allocating here makes the two indivisible: a reader either sees `latest()` NOT
        // yet advanced (and the event is still to come), or sees it advanced AND finds the event in
        // the ring. Allocating before the lock left a window in which a reader read the advanced
        // `latest()`, found the event not yet pushed, and moved its cursor past an event it would
        // then never be returned — a silently skipped notification.
        let seq = self
            .next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if events.len() >= MAX_RESOURCE_UPDATES {
            events.pop_front();
        }
        events.push_back((seq, server.to_string(), uri.to_string()));
    }

    /// The newest sequence number — where a fresh reader starts, so a subscription relays what
    /// happens AFTER it was opened rather than replaying a history it never asked for.
    pub(crate) fn latest(&self) -> u64 {
        self.next_seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Every event newer than `cursor`, oldest first, plus the cursor the reader should hold next.
    pub(crate) fn since(&self, cursor: u64) -> (Vec<(String, String)>, u64) {
        let events = match self.events.lock() {
            Ok(e) => e,
            Err(p) => p.into_inner(),
        };
        let out = events
            .iter()
            .filter(|(seq, _, _)| *seq > cursor)
            .map(|(_, server, uri)| (server.clone(), uri.clone()))
            .collect();
        (out, self.latest())
    }
}

impl std::fmt::Debug for McpConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `reqwest::Client` has no useful Debug and printing the map's keys would put resolved
        // internal addresses into logs. Presence and size only.
        f.debug_struct("McpConnectionPool")
            .field("pinned_clients", &self.clients.len())
            .field("stdio_children", &self.children.len())
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
    #[allow(dead_code, clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> usize {
        self.clients.len()
    }

    /// Resolve, check, pin, and return a client bound to the checked address.
    ///
    /// The check runs BEFORE the cache is consulted for a NEW address and the cache is keyed on the
    /// result, so there is no ordering in which an unchecked address gets a client. The client is
    /// built by the ONE egress engine ([`busbar_substrate::egress::engine::build_client`] on the
    /// `EngineSpec::pinned` posture): the pin IS the resolver (the socket goes to the judged
    /// address, every other name refuses with the doctrine text), the peer SPKI is observed at
    /// connect, and the connection knobs are the canonical reqwest-parity values. No total deadline
    /// is baked into the pooled client — every send site applies its own on the request (see
    /// [`super::transport::HttpTransport::send`] and [`crate::mcp::upstream::exchange`]).
    pub(crate) async fn client_for(
        &self,
        url: &str,
        policy: SsrfPolicy,
    ) -> Result<(busbar_substrate::egress::engine::EngineClient, PinnedTarget), SsrfRefusal> {
        let target = super::ssrf::pin_upstream(url, policy).await?;
        // THE KEY CONTAINS THE PINNED ADDRESS (`busbar_substrate::egress::PinnedClientPool` keys on it): keying
        // by host alone would let a pooled client re-resolve on its next new connection — the TOCTOU
        // the pin closes, reintroduced by the cache in front of it.
        let client =
            self.clients
                .client_for((target.host().to_string(), target.socket_addr()), || {
                    busbar_substrate::egress::engine::build_client(
                        &busbar_substrate::egress::engine::EngineSpec::pinned(
                            Arc::from(target.host()),
                            target.socket_addr().ip(),
                            None,
                            Vec::new(),
                        ),
                    )
                    .map_err(|e| SsrfRefusal::Unresolvable {
                        host: target.host().to_string(),
                        reason: format!("could not build a pinned HTTP client: {e}"),
                    })
                })?;
        Ok((client, target))
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/pool_tests.rs"]
mod pool_tests;
