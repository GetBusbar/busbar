// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `lineage` — the neutral cross-plane request-lineage id. See
//! `docs/design/1.6.0-abi-solidification.md` (primitive B / gap G4).
//!
//! # What this is, and why it is CORE
//!
//! A neutral correlation+causation id joining a *triggering* request (say an LLM completion) with the
//! sub-requests it *induces* in other planes (an MCP tool-call, an MCP→core→LLM sampling completion,
//! an A2A task step) into one causal tree — **without any plane naming another.** It generalizes the
//! `u64` request id core already mints and threads; a root/parent pair turns a flat id into a tree.
//!
//! It is core **by definition**: lineage is cross-plane. No single plugin can own "the request that
//! caused me was in another plane." By the decision rule this is unambiguously a core primitive.
//!
//! # What it unlocks
//!
//! Cost *trees* (spend-by-LLM-request, not just per-tool-call), full request tracing, latency
//! attribution, induced-spend / amplification caps, and incident forensics — all from one neutral id
//! threaded across plane boundaries and joinable in the ledger. This is a *different axis* from the
//! internal span tree (export `TraceId/SpanId`): those describe execution spans; this describes which
//! governed request caused which.
//!
//! # Trust (owner-ruled, D6)
//!
//! A [`Lineage`] value is a fact core threads, not something a caller dictates. Core mints a fresh
//! root ([`Lineage::root`]) unless the inbound peer is trusted (mTLS/signed); it must NOT adopt a
//! forgeable caller-supplied root, or a caller could poison or join another tenant's cost tree. That
//! trust check lives at the wire edge, not in this type — [`Lineage::adopt`] exists for the trusted
//! path and is deliberately explicit so the boundary is visible at the call site.

/// A neutral request id (the `u64` core already mints via its request-id source).
pub type RequestId = u64;

/// The lineage of one governed request: itself, its inducing parent (if any), and the root of its
/// causal tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lineage {
    /// The top of the causal tree. Equals [`Self::id`] for a root request.
    root: RequestId,
    /// The request that induced this one. `None` for a root (a caller-originated request).
    parent: Option<RequestId>,
    /// This request's own id.
    self_id: RequestId,
}

impl Lineage {
    /// A root request — no inducing parent; it is the top of its own tree.
    pub fn root(self_id: RequestId) -> Lineage {
        Lineage {
            root: self_id,
            parent: None,
            self_id,
        }
    }

    /// Derive the lineage of a request this one INDUCES in another plane: same root, this request as
    /// the parent, and the child's own id. This is the cross-plane edge — the only way a tree grows —
    /// and it names no plane.
    pub fn induce(&self, child_id: RequestId) -> Lineage {
        Lineage {
            root: self.root,
            parent: Some(self.self_id),
            self_id: child_id,
        }
    }

    /// Adopt a lineage continued from a TRUSTED inbound peer (distributed continuation). The caller is
    /// responsible for having verified peer trust (mTLS/signed) BEFORE calling this — an untrusted
    /// root is forgeable. Prefer [`Self::root`] for any untrusted ingress.
    pub fn adopt(root: RequestId, parent: Option<RequestId>, self_id: RequestId) -> Lineage {
        Lineage {
            root,
            parent,
            self_id,
        }
    }

    /// The root of the causal tree.
    pub fn root_id(&self) -> RequestId {
        self.root
    }

    /// The inducing parent, if any.
    pub fn parent_id(&self) -> Option<RequestId> {
        self.parent
    }

    /// This request's own id.
    pub fn id(&self) -> RequestId {
        self.self_id
    }

    /// Whether this is a root (caller-originated) request.
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }
}

#[cfg(test)]
#[path = "tests/lineage_tests.rs"]
mod lineage_tests;
