// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP CLIENT DIRECTION: busbar calling OUT to external MCP tool servers — the "7th wire
//! protocol", so named because it sits beside the six stateless HTTP provider families in
//! `crate::proto` and is nothing like them.
//!
//! `crate::mcp` (the parent) is the SERVER direction: busbar's own front door. This module is the
//! other half of the same governance boundary. They share the trust lifecycle, the scope kinds, the
//! plane and the protocol revision; they differ only in who initiates the JSON-RPC call.
//!
//! ## What lives where
//!
//! | module | owns |
//! |---|---|
//! | [`identity`] | `{server}_{tool}` as THE routing key — bound identity, never the description |
//! | [`catalogue`] | the versioned tool-list snapshot, per-tool hash-pinning, drift detection |
//! | [`jsonrpc`] | the `2026-07-28` outbound wire, and the rules for answering an upstream's ask |
//! | [`wire`] | the vtable one built JSON-RPC message rides, and the two channels' shared types |
//! | [`transport`] | the streamable-HTTP stateless transport — the primary target |
//! | [`stdio`] | the child-process transport: spawn, supervise, backoff, crash-loop quarantine |
//! | [`pool`] | engine-owned connection pooling, keyed by the PINNED address |
//! | [`ssrf`] | dispatch-time resolve-then-pin |
//! | [`argguard`] | the schema-aware walk of nested tool arguments for URL and host fields |
//! | [`egress`] | per-server credentials, RFC 8707/8693, and the transitive confused-deputy gate |
//! | [`dispatch`] | selection, and the re-validation that runs on every single request |
//! | [`verb`] | the CLOSED set of methods busbar issues, and how each becomes a request |
//! | [`peer`] | what a peer sends BUSBAR, and the deny-by-default gate on its three authority asks |
//! | [`issue`] | the ONE governed path a verb travels: gate, send, correlate, record |
//!
//! ## The revision, stated once
//!
//! `2026-07-28`, streamable-HTTP stateless. This plane was designed when that was an unratified RC
//! and building primarily against an unratified RC was the wrong bet to take; that caveat is
//! spent — it is the current
//! revision, and it is the only one busbar speaks. There is no `initialize`, no session, no
//! `Mcp-Session-Id`, no GET stream, no resumability, and a server cannot send a JSON-RPC request.
//! The rule that follows governs every check in here: **under on-demand negotiation every defence
//! is a per-request check.** Anything phrased "at the handshake" or "for the session" is a
//! per-request check or it is nothing.
//!
//! ## The trust lifecycle is REUSED, not rebuilt
//!
//! `crate::trust` already landed the plane-neutral `Approval` / `Sighting` / `TrustState` /
//! `Drift` machine, generic over its pinned artifact, with the state DERIVED rather than stored.
//! This plane supplies one adapter, [`catalogue::TransportPin`], and gets the whole lifecycle:
//! register, connect, approve, per-capability approve/reject, `approve_pin`, suspend, unpin,
//! quarantine-on-drift and the changes queue. Nothing here re-implements a transition, which is
//! also what choke point F in `structure-lint.sh` exists to keep true.
//!
//! ## WHAT IS AND IS NOT WIRED, stated plainly so nobody plans against it
//!
//! There IS a production caller now: `crate::mcp::upstream` joins this direction to the server
//! direction's `tools/call`. An authenticated inbound tool call resolves to a `VirtualKey`, that key
//! is handed to [`egress::plan_credential`], and the request that goes out is built, credentialled,
//! SSRF-checked, address-pinned and pooled by the modules in this table. The transitive
//! confused-deputy defence is therefore proven AS A PAIR — against an inbound MCP client that
//! authenticated to busbar's own resource server — in `crate::mcp::tests/deputy_pair_tests.rs`,
//! rather than against a principal a test constructed.
//!
//! **stdio IS A TRANSPORT THIS BUILD HAS, OUTBOUND.** A `tools:` entry carrying `transport: stdio`
//! and a `command:` spawns a supervised child and dispatches `tools/call` down its stdin; the arm is
//! [`crate::transport::Transport::upstream_wire`] and the supervisor is [`stdio`]. It was DELETED once,
//! as unreachable security-relevant code that read as shipped, and it is back with a caller rather
//! than with an `#![allow(dead_code)]` — which is the only difference that ever mattered. The
//! INBOUND direction (busbar itself launched as a child by an agent, serving MCP on its own stdin)
//! is not built YET: its old waiver's own text called it "a product decision, not a technical
//! block", so per the 2026-08-14 waiver-list-to-zero ruling the whole family is owed work, pinned
//! in `qa/method-coverage.missing` as the queue's next unit.
//!
//! What is still NOT wired, and is stated rather than softened:
//!
//! - **[`catalogue`]'s live cache and the background refresh that would feed it.** The dispatch path
//!   validates against the SERVER direction's config-built snapshot, which carries the operator's
//!   approved digests; nothing in this build polls an upstream's `tools/list` to detect a rug-pull in
//!   flight. The detection machinery is complete and proven; the job that drives it is not written.
//! - **[`pool`]'s eviction under real load**, which has no production traffic to be measured against.
//! - **The admin verbs** (`connect`, `approve`, `changes`, `approve-pin`, `health`), which need a
//!   store-side sighting table.

pub(crate) mod argguard;
pub(crate) mod catalogue;
pub(crate) mod dispatch;
pub(crate) mod egress;
pub(crate) mod identity;
/// THE ONE GOVERNED ISSUANCE PATH for every method busbar sends an upstream. One gate, one audit
/// record, one vtable send — see the module header for why a second one is a hole and not a feature.
pub(crate) mod issue;
pub(crate) mod jsonrpc;
/// WHAT A CHILD SENDS BUSBAR: the `busbar-as-client / server-originated` half of the matrix, and
/// the deny-by-default gate on the three asks that would spend busbar's own authority.
pub(crate) mod peer;
pub(crate) mod pool;
pub(crate) mod ssrf;
pub(crate) mod stdio;
pub(crate) mod transport;
/// THE CLOSED SET OF METHODS BUSBAR ISSUES to an upstream MCP server — one enum, so the column of
/// the coverage matrix this leg owns is a value a test can enumerate rather than a property of its
/// call sites.
pub(crate) mod verb;
pub(crate) mod wire;

use catalogue::{CatalogueCache, ServerCatalogue, TransportPin};
use egress::UpstreamCredential;
use identity::ServerId;
use jsonrpc::ServerRequestGrants;
use ssrf::SsrfPolicy;

// ── NOT YET WIRED, AND NAMED RATHER THAN BLANKET-ALLOWED ────────────────────────────────────────
//
// `tools/call` reaches an upstream through `mcp::upstream`, which composes this module's PARTS
// directly — `egress` for the grant gate and credential plan, `identity` for the bound name,
// `jsonrpc`, `pool`, `ssrf`, `transport`. Those all have production callers.
//
// The three items below are the CONNECT path, which does not exist yet: an operator-driven fetch of
// an upstream's tool list, turned into an observation the trust lifecycle can approve. Until the
// `connect` verb lands there is nothing to construct them from, and inventing a caller to satisfy
// the linter would be worse than the warning.
//
// The allow is on these three items ONLY, not the module, so the moment anything else here loses
// its caller the build says so. That is the point: the gap stays visible in the code rather than in
// a tracking document nobody reads.
#[allow(dead_code)]
/// How busbar reaches one upstream. TWO ARMS, because this build speaks two transports.
///
/// An enum rather than the bare URL it once held: the type is the place a transport is ADDED, and
/// every match on it is a place that is then forced to decide. A `String` would have let stdio be
/// bolted on with no such prompt — and stdio has no URL to put in one.
#[derive(Clone, Debug)]
pub(crate) enum Endpoint {
    /// Streamable HTTP, stateless. THE primary target of this revision.
    Http { url: String },
    /// A supervised child process. Carries the operator's spawn recipe verbatim; see
    /// [`stdio::StdioCommand`] for why every field of it is operator-only.
    Stdio { command: stdio::StdioCommand },
}

#[allow(dead_code)]
/// ONE REGISTERED UPSTREAM, everything the dispatch path needs about it in one place.
///
/// Deliberately not `serde`-derived. The config face of this record is goal item 17's `tools:`
/// block, and deriving a wire shape now would freeze a grammar before the section that owns it
/// exists — exactly the trap the locked `tools:` grammar records against `tools_allow`: once
/// operators have written a key into their files, re-typing it is a breaking change.
#[derive(Clone, Debug)]
pub(crate) struct McpServerRegistration {
    pub(crate) id: ServerId,
    pub(crate) endpoint: Endpoint,
    /// The out-of-band operator pin: an authenticity root supplied at registration, never a key the
    /// endpoint offered on first contact, which is what keeps this out of trust-on-first-use.
    /// `None` is the explicitly-and-loudly `unpinned` case, permitted for low-risk dev use only;
    /// the trust lifecycle refuses to APPROVE without one, so an unpinned server is `Pending` and
    /// serves nothing until the operator supplies a pin or accepts a captured candidate.
    pub(crate) pin: Option<TransportPin>,
    pub(crate) credential: UpstreamCredential,
    /// Per-server addressing posture for the dispatch-time SSRF check.
    pub(crate) ssrf: SsrfPolicy,
    /// Per-server grants for the three asks an upstream can make of busbar's OWN authority —
    /// sampling, elicitation, roots. All false unless an operator set them.
    pub(crate) grants: ServerRequestGrants,
    /// The hard cap on input-required rounds for one logical dispatch. Without it a hostile
    /// upstream can ask forever, and every satisfied sampling round is a real, budgeted LLM call.
    pub(crate) max_input_required_rounds: u32,
}

#[allow(dead_code)]
impl McpServerRegistration {
    /// A registration with every optional posture at its fail-closed default: no pin, no credential,
    /// no private addressing, no server-request grants, one input-required round.
    pub(crate) fn new(id: ServerId, endpoint: Endpoint) -> Self {
        Self {
            id,
            endpoint,
            pin: None,
            credential: UpstreamCredential::None,
            ssrf: SsrfPolicy::default(),
            grants: ServerRequestGrants::default(),
            max_input_required_rounds: 1,
        }
    }
}

#[allow(dead_code)]
/// THE CLIENT-DIRECTION ENGINE STATE: the registry, the catalogue cache and the connection pool.
///
/// One object because the three are coupled by a single invariant — the pool must only ever be
/// asked for a destination that the registry declared and the catalogue approved — and three
/// separately-held pieces is three chances to consult them in the wrong order.
#[derive(Debug, Default)]
pub(crate) struct McpClientEngine {
    registry: std::sync::RwLock<std::collections::BTreeMap<String, McpServerRegistration>>,
    pub(crate) catalogue: CatalogueCache,
    pub(crate) pool: pool::McpConnectionPool,
}

#[allow(dead_code)]
impl McpClientEngine {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register an upstream. The catalogue entry is created in the fail-closed `Pending` state:
    /// registration reaches no network and approves nothing (OQ8's answer — `connect` is its own
    /// explicit, audited act, so "registered but never contacted" is a real inspectable state).
    pub(crate) fn register(&self, reg: McpServerRegistration) {
        let id = reg.id.clone();
        if let Ok(mut r) = self.registry.write() {
            r.insert(id.as_str().to_string(), reg);
        }
        self.catalogue.apply(|servers| {
            servers
                .entry(id.as_str().to_string())
                .or_insert_with(|| ServerCatalogue::registered(id.clone()));
        });
    }

    pub(crate) fn registration(&self, id: &ServerId) -> Option<McpServerRegistration> {
        self.registry
            .read()
            .ok()
            .and_then(|r| r.get(id.as_str()).cloned())
    }

    /// Remove an upstream. Bumps the catalogue generation, which is what makes a call already
    /// resolved against it fail its dispatch-time re-validation, revocation included.
    pub(crate) fn deregister(&self, id: &ServerId) {
        if let Ok(mut r) = self.registry.write() {
            r.remove(id.as_str());
        }
        self.catalogue.apply(|servers| {
            servers.remove(id.as_str());
        });
    }
}

// Shared fixtures. Declared here rather than duplicated per test file so a test that varies one
// thing varies one thing; `pub(super)` on its items makes them reachable from every test module
// nested under `client`.
#[cfg(test)]
#[path = "tests/support.rs"]
mod support;

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod engine_tests;

// The accessors the not-yet-written refresh job will need, exercised while it does not exist.
#[cfg(test)]
#[path = "tests/surface_tests.rs"]
mod surface_tests;

// The adversarial no-passthrough battery spans `egress` (which plans the credential) and `jsonrpc`
// (which serializes the request), so it hangs off the module that owns both rather than off either
// one.
#[cfg(test)]
#[path = "tests/no_key_passthrough_tests.rs"]
mod no_key_passthrough_tests;
