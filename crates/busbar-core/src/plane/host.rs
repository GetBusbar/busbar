// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane::host` — the inbound host-capability seam: what a plane calls BACK into core.
//!
//! The plugin ABI's outbound direction (host→plugin: `busbar_call` etc.) already exists; the
//! **inbound** direction — a plane asking core to `govern_admit`, `meter_charge`, `journal_append`,
//! `egress_open`, … — did not. This seam is that direction: every governance/audit/egress capability
//! is compiled-in-only until a plane can reach it.
//!
//! # In-process for 1.6.0 (owner ruling D8)
//!
//! The design describes this as a `#[repr(C)] PlaneHostVtable` of `Option<HostCall>` slots crossing a
//! `dlopen` boundary. For 1.6.0 planes are **compiled-in and the seam is exercised in-process**, which
//! **defers the first-ever `repr(C)` crossing** — so here it is a plain Rust trait, not a C ABI. A
//! later release lifts it to the `repr(C)` vtable additively (the method set and grant model are the
//! same shape either way).
//!
//! # Neutral by construction: opaque request, opaque response
//!
//! Every capability takes an **opaque request the plane serialized** and returns an **opaque response
//! core produced** — core routes by *which capability*, never interpreting the plane's payload. This
//! is the design's `HostCall(token, req, req_len, out, out_len)` shape rendered in-process. Core stays
//! protocol-blind; the plane owns the wire shape of its own request to a capability.
//!
//! # Grant model
//!
//! A capability a plane was not granted returns [`HostCallError::NotGranted`]. The DEFAULT trait impl
//! grants **nothing** — a host must override each capability it grants a plane, so a plane can reach
//! exactly what core decided to expose and no more. (This is the in-process analogue of a NULL vtable
//! slot: absent = not granted.)

use std::fmt;

/// Why an inbound host call did not produce a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCallError {
    /// The plane was not granted this capability (the in-process analogue of a NULL vtable slot).
    NotGranted,
    /// The host-side handle the plane holds is stale (its session/lifecycle has ended). Analogous to
    /// the design's `STATUS_GONE` for a stale generational token.
    Gone,
    /// The plane's opaque request was malformed for this capability, or the operation was refused.
    /// The message is host-authored (never echoes plane bytes verbatim into a place they could leak).
    Refused(String),
}

impl fmt::Display for HostCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostCallError::NotGranted => f.write_str("capability not granted to this plane"),
            HostCallError::Gone => f.write_str("host handle is gone (stale session/lifecycle)"),
            HostCallError::Refused(m) => write!(f, "host call refused: {m}"),
        }
    }
}

impl std::error::Error for HostCallError {}

/// One opaque inbound call: the plane hands core bytes it serialized, core returns bytes it produced.
pub type HostCallResult = Result<Vec<u8>, HostCallError>;

/// The inbound host-capability surface a compiled-in plane calls back into. Every method defaults to
/// [`HostCallError::NotGranted`]; a host grants a capability by overriding its method. `Send + Sync`
/// because a plane may hold the host across `.await` and across its worker threads.
///
/// The eleven capabilities are the plane→core vtable. `secrets_resolve` is deliberately ABSENT
/// — a `Redacted<String>` survives no boundary; secret resolution is by-reference at `egress_open`,
/// so a plane names a secret ref, never receives the secret.
pub trait PlaneHost: Send + Sync {
    /// Admit (authorize + budget-reserve) a unit of work; returns a grant the plane spends. Rate-
    /// limited per plane by core.
    fn govern_admit(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Charge consumption against a grant/budget. Self-reported by construction (a plane can charge
    /// zero); core bounds by scope but does not audit the amount — billing-grade metering runs through
    /// a core-owned chokepoint, not this call.
    fn meter_charge(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Append to the plane's hash-chained audit journal. The chain lives in core; the plane supplies
    /// subject + payload, core supplies `prev_hash`/`hash` — so a plane cannot forge or truncate it.
    fn journal_append(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Read back the plane's audit journal.
    fn journal_read(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Durable task-store operation (put/get/append-event/…), for a plane with long-running work.
    fn tasks_op(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Redeem an approval / single-use nonce.
    fn approvals_redeem(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Quarantine / demote-on-drift operation.
    fn quarantine_op(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Catalogue read/publish.
    fn catalogue_op(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Open a duplex upstream by POOL (never a URL) — core keeps the SSRF guard, breaker, failover,
    /// and resolves any secret ref at the socket.
    fn egress_open(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// Emit a per-plane metric series (label-passthrough; core interprets no label).
    fn metrics_emit(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
    /// The host clock (for TTLs, task timers) — so a plane takes no ambient clock of its own.
    fn clock_now(&self, _req: &[u8]) -> HostCallResult {
        Err(HostCallError::NotGranted)
    }
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod host_tests;
