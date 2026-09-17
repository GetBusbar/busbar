// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAILOVER SEAM — RELOCATED DOWN to the neutral `busbar_substrate::failover` leaf.
//!
//! Deletion-wave byte-safe move (DECISIONS #19): the whole neutral seam — the candidate/stage/
//! refusal/admitted/attempt/order/walk_with family (relocated in Phase-B B1) PLUS the residual
//! operator config type ([`CandidatePoolCfg`]) and the disposition halves a plugin's dispatch engine
//! drives ([`walk`], [`record_outcome`], [`record_success`]) — now lives wholly in
//! `busbar_substrate::failover`, over `busbar_substrate::store::LaneRuntime` and
//! `busbar_substrate::breaker`, so a plane crate reaches it through the neutral ABI rather than back
//! into `busbar-core` (the reverse-edge rule). It names ONLY the neutral spine and no App/money/plane
//! type, which is why it could move byte-identically.
//!
//! This module is the re-export shim that keeps every historical `crate::failover::X` /
//! `busbar_core::failover::X` path resolving unchanged — core's config lowering
//! (`config::mod`'s `tool_pools`/`agent_pools` projection to [`CandidatePoolCfg`]), `state.rs`'s pool
//! fields, `engine_facade`'s `{walk, record_outcome, record_success}` re-export, and the acceptance
//! suite below all compile against the substrate types through this glob. The values are byte-identical.

// Glob, so the re-export is never an unused import when a plane consumer is out.
pub use busbar_substrate::failover::*;

#[cfg(test)]
#[path = "tests/failover_tests.rs"]
mod failover_tests;
