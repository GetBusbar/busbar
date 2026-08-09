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
//! | [`transport`] | the streamable-HTTP stateless transport — the primary target |
//! | [`stdio`] | spawn + supervise, with the `spawning → ready → draining → dead` state machine |
//! | [`pool`] | engine-owned connection pooling, keyed by the PINNED address |
//! | [`ssrf`] | dispatch-time resolve-then-pin |
//! | [`egress`] | per-server credentials, RFC 8707/8693, and the transitive confused-deputy gate |
//! | [`dispatch`] | selection, and the re-validation that runs on every single request |
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
//! ## WHAT IS NOT BUILT, stated plainly so nobody plans against it
//!
//! There is **no production caller**: no `tools:` config section (goal item 17), no admin verbs
//! (item 18), no store-side sighting table, and therefore no path by which a real request reaches
//! this code today. That is the same posture the trust lifecycle shipped under and for the same
//! reason — the parts with a dependant waiting land ahead of the wiring. The consequence is stated
//! rather than softened: every property below is proven at the unit and integration seam, and none
//! of it is proven end-to-end through a live deployment.
//!
//! The **inbound half of the egress gate** is likewise unproven as a pair.
//! [`egress::authorise_egress`] binds outbound credential selection to a `busbar_api::VirtualKey`,
//! which is the real principal type both directions resolve to — but until the server direction's
//! `tools/call` resolves a caller into one and hands it here, the transitive confused-deputy
//! defence is proven against a constructed principal, not against an inbound MCP client. A defence
//! that only means anything once both halves exist is precisely why the two directions ship as one
//! unit; this module holds up its end and says so precisely.

// NO PRODUCTION CALLER YET — see the module header. Landed ahead of the config section and the admin
// verbs deliberately, because the integrity properties are the part worth settling and pinning
// before a wire is built on top of them. Same posture as `crate::trust` and `crate::plane`.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod catalogue;
pub(crate) mod dispatch;
pub(crate) mod egress;
pub(crate) mod identity;
pub(crate) mod jsonrpc;
pub(crate) mod pool;
pub(crate) mod ssrf;
pub(crate) mod stdio;
pub(crate) mod transport;

use catalogue::{CatalogueCache, ServerCatalogue, TransportPin};
use egress::UpstreamCredential;
use identity::ServerId;
use jsonrpc::ServerRequestGrants;
use ssrf::SsrfPolicy;

/// How busbar reaches one upstream.
#[derive(Clone, Debug)]
pub(crate) enum Endpoint {
    /// Streamable HTTP, stateless. THE primary target of this revision.
    Http { url: String },
    /// A local child process speaking newline-delimited JSON-RPC over stdio.
    Stdio { program: String, args: Vec<String> },
}

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

// The accessors a production caller will need, exercised while there is no production caller.
#[cfg(test)]
#[path = "tests/surface_tests.rs"]
mod surface_tests;

// The adversarial no-passthrough battery spans `egress` (which plans the credential) and `jsonrpc`
// (which serializes the request), so it hangs off the module that owns both rather than off either
// one.
#[cfg(test)]
#[path = "tests/no_key_passthrough_tests.rs"]
mod no_key_passthrough_tests;
