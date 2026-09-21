// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DRAIN FACADE — the one stable per-step re-export surface for busbar-core's own workflow
//! steps (1.6.0 wave W1.e; DECISIONS #27b).
//!
//! ## What it is
//!
//! The Teller loop is a fixed sequence of workflow steps (`qa/teller-steps.json`, the step matrix
//! the `teller-steps` gate reads): **arrival → decode → authenticate → verify → approve → admit →
//! route → meter → audit → exit**. Each step's implementation still physically lives in
//! `busbar-core` today, spread across the modules the engine grew up around (`auth/`, `trust/`,
//! `governance/`, `limits/`, `egress*/`, `proxy/`, `billing`, `audit*/`, `calllog`, `ingress/`,
//! `proto/`, …). This module gives EACH step ONE canonical import path —
//! `busbar_core::drain::<step>::…` — that names, per step, the core module(s) that implement it.
//!
//! ## Why it exists (DECISIONS #27b — "no step waits on another where a seam decouples it")
//!
//! The busbar-core DRAIN relocates each engine step out to its own `busbar-unit-<step>` crate. If
//! every consumer named the step through this facade instead of reaching straight into
//! `crate::auth`, `crate::egress`, … then relocating a step becomes a ONE-LINE edit here (swap
//! `pub use crate::auth;` for `pub use busbar_kernel_identity;`), and the steps can move **in ANY order**
//! with nothing downstream moving — exactly the property W1.e's GREEN condition requires
//! ("steps relocatable in any order"). It is the same behavior-neutral visibility-lift discipline
//! the sibling [`crate::engine_facade`] uses for the plane→core DOWN edge — wire the seam in place
//! FIRST, relocate LATER.
//!
//! ## What it is NOT
//!
//! Pure, additive, DORMANT plumbing: every line is a `pub use` of an ALREADY-`pub` module at its
//! existing declared visibility. It moves no code, rewrites no step, and changes no behavior — the
//! shipped execution path is byte-untouched (money sacred), so the oracle stays byte-identical.
//! Nothing in core consumes this module yet; it is the stable target consumers migrate ONTO ahead
//! of the physical drain, not a swap of the shipped path.
//!
//! Each `pub use` re-exports the source module under its OWN name (`drain::audit::calllog`, not a
//! renamed alias) so the facade transparently mirrors core's real module layout: the facade path is
//! a stable synonym, never a disguise.

// ── step 0: arrival — the kernel's size/rate/source/cursor/spill budgets + the arrival hold ──────
// The arrival gate reads `cfg.limits` (the admission door's budgets) and mints the in-memory
// arrival hold on the ingress path. Relocates to `busbar-unit-admission` (arrival half).
pub mod arrival {
    pub use crate::ingress;
    pub use crate::limits;
}

// ── step 1: decode — frame → typed ingress, over the protocol registry ───────────────────────────
// The claimed plane owns the decode; core's own decode-support is the protocol dialect registry and
// the ingress arrival host. The plane's half relocates with the plane; core's proto/ingress support
// drains with the loop.
pub mod decode {
    pub use crate::ingress;
    pub use crate::proto;
}

// ── step 2: authenticate — principal resolution + the pass cache ─────────────────────────────────
// Relocates to `busbar-unit-auth` (the `AuthUnit::resolve` seam + its digest/pass cache).
pub mod authenticate {
    pub use crate::auth;
    pub use crate::auth_cache;
}

// ── step 3: verify — trust/lane admissibility, consulting the breaker view ───────────────────────
// Relocates to `busbar-unit-trust` (+ the `busbar-unit-breaker` `BreakerView` it reads at verify).
pub mod verify {
    pub use crate::breaker;
    pub use crate::trust;
}

// ── step 4: approve — scope/policy authorization + the hook facts at the four seats ──────────────
// Relocates to `busbar-unit-scope` (the `PolicyView` / required-scope decision).
pub mod approve {
    pub use crate::governance;
}

// ── step 5: admit — the admission FSM + the cost pricer it consults ──────────────────────────────
// Relocates to `busbar-unit-admission` (+ `busbar-unit-cost` for the `Pricer`).
pub mod admit {
    pub use crate::cost;
    pub use crate::limits;
}

// ── step 6: route — the outbound leg: egress engine, credential decorate, failover, lane naming ──
// Relocates to `busbar-unit-egress` (+ `-egress-auth`, `-breaker`, `-transport-key`); the proxy
// engine + failover disposition + the neutral lane-protocol-name resolver are the primitives it
// drives (already surfaced on the DOWN edge in `engine_facade`).
pub mod route {
    pub use crate::egress;
    pub use crate::egress_auth;
    pub use crate::failover;
    pub use crate::proto;
    pub use crate::proxy;
}

// ── step 7: meter — usage accrual against the rate card ──────────────────────────────────────────
// Relocates to `busbar-unit-usage` (the `meter(..) -> Metered` free fn); `billing` carries core's
// `Billing`/`TokenUsage` accrual surface.
pub mod meter {
    pub use crate::billing;
}

// ── step 8: audit — the hash-chained record seal, then the ledger settle ─────────────────────────
// Relocates to `busbar-unit-audit` then `busbar-unit-ledger`; core's audit chain, the admin-mutation
// ring, the durable per-call log and the lineage stamp are the record shapes it seals.
pub mod audit {
    pub use crate::audit;
    pub use crate::audit_ring;
    pub use crate::calllog;
    pub use crate::lineage;
}

// ── step 9: exit — the finish/settle tail: metrics + request-log/audit append + conditional refund
// The post-admission terminals (`finish_admitted`/`finish_rejected`, already on the DOWN edge in
// `engine_facade`) and the durable per-call log the settle writes through.
pub mod exit {
    pub use crate::calllog;
    pub use crate::ingress;
}
