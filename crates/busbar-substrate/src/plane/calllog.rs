// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL per-call record INPUT — the fields a plane supplies for one MCP call-log record.
//!
//! This is a pure POD: it names no core type, only `std`. It lives in the substrate so a plane crate
//! builds a [`CallInput`] and hands it to the `EngineHost::call_log_emit` / `call_log_emit_hostless`
//! seam without naming `busbar_core::calllog`; the core call-log engine consumes it unchanged
//! (core re-exports this type, so `busbar_core::calllog::CallInput` still resolves in core).

/// The fields a caller supplies for one call record. `seq`, `prev_hash` and `hash` are NOT here:
/// they are the chain's own business and are supplied by `busbar_core::audit::Chain::append`, so no
/// call site can supply a sequence number or a link of its own choosing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallInput {
    /// Unix seconds the record was minted at, read through the host clock seam.
    pub ts: u64,
    /// The upstream server the call was routed to (empty on a pre-resolution refusal).
    pub server: String,
    /// The namespaced tool (or `verb:`-prefixed client-leg verb) the call named.
    pub tool: String,
    /// The stable audit outcome word (`dispatched` / `refused`).
    pub outcome: &'static str,
    /// The stable reason word for a refusal (empty on a dispatch).
    pub reason: String,
    /// The approved schema digest the call rode (empty where none was vouched for).
    pub tool_digest: String,
    /// The pin generation the call was admitted under (`0` where none applies).
    pub pin_generation: u64,
    /// The caller's per-dispatch correlation id, as a string join key.
    pub request_id: String,
}

/// The NEUTRAL per-call record OUTPUT — what the core call-log engine hands back after minting one
/// record's chain link. It is the CORE-NEUTRAL twin of the plane's own call record: it names no
/// core or plane type, only `std`, so the call-log mechanism stays generic-in-core while the plane
/// crate owns the protocol-named struct. It carries the caller's own fields ([`CallInput`]) plus the
/// three the chain minted (`seq`, `prev_hash`, `hash`) and the chain scope (`principal`). A plane
/// crate reconstructs its typed call record from this where it wants one; core never names one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecorded {
    /// The chain scope — the authenticated caller this record belongs to.
    pub principal: String,
    /// The sequence the chain minted for this record, 1-based within `principal`.
    pub seq: u64,
    /// Unix seconds the record was minted at.
    pub ts: u64,
    /// The upstream server the call was routed to (empty on a pre-resolution refusal).
    pub server: String,
    /// The namespaced tool (or `verb:`-prefixed client-leg verb) the call named.
    pub tool: String,
    /// The stable audit outcome word (`dispatched` / `refused`).
    pub outcome: String,
    /// The stable reason word for a refusal (empty on a dispatch).
    pub reason: String,
    /// The approved schema digest the call rode (empty where none was vouched for).
    pub tool_digest: String,
    /// The pin generation the call was admitted under (`0` where none applies).
    pub pin_generation: u64,
    /// The caller's per-dispatch correlation id. From a neutral stored body this comes back EMPTY:
    /// it is a join key, never in the digest and so never in the neutral content.
    pub request_id: String,
    /// The preceding record's `hash` for this principal (empty for the first of a chain).
    pub prev_hash: String,
    /// The tamper-evidence digest over this record's chained fields.
    pub hash: String,
}
