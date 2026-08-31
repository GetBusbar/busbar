// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral IR seam. Busbar-core holds ONLY the operation-blind pieces here — the `IrFacts`
//! projection the shared pipeline reads, the sealed `IrHandle` the engine drives translation
//! through, and the genuinely cross-plane `invoke`/`subscribe` leaves (mcp + a2a). The CONCRETE
//! chat IR and the LLM leaf-op IR (`IrRequest`/`IrResponse`/`IrBlock`/`Embeddings*`/… — everything
//! that names an LLM wire shape) RELOCATED to the `busbar-llm` plugin at the G6 A4b cutover, so core
//! reads a request only through the neutral projection and never names a concrete LLM family type in
//! production. The freeze witness (`scripts/g6-freeze-witness.sh`) gates that to zero.
//!
//! THE DUAL COMPILE. Core's `test`/`test-support` build `#[path]`-includes the plugin's concrete IR
//! back in at THIS module root (`crate::ir::IrRequest` etc.), so the pre-extraction fixture surface
//! keeps exercising the real types from inside core's own test binary — the same mechanism the
//! dialects use under `crate::proto::{anthropic, …}`. Production core compiles none of it.

// ── NEUTRAL IR — stays in busbar-core (the operation-blind engine holds these) ───────────────────

/// The neutral resolved-primitives param bag a cross-protocol egress hop passes to a handle's
/// `prepare_for_egress` (all primitives — no concrete IR).
pub mod egress_prep;
/// THE ONE PROJECTION — what the shared pipeline (hooks, governance, taps) is allowed to know about
/// a request, read from the IR and from nothing else. Beside the IR rather than beside the hooks so
/// that "a hook sees the IR" is a compile-time fact; see the module header.
pub mod facts;
/// **G6 A4b dissolve.** The sealed, neutral `IrHandle` the operation-blind engine holds now that
/// `IrReq`/`IrResp` have dissolved. The dialect handlers (in the plugin) implement it; core drives
/// translation through it and never names a concrete IR variant.
pub mod handle;
/// The genuinely cross-plane INVOKE leaf (mcp + a2a) — neutral, stays in core.
pub mod invoke;
/// **G6 A4b dissolve.** Core-owned neutral `IrHandle`s for `Invoke`/`Subscribe` (trait defaults +
/// `Billing::Flat`); busbar-mcp's codec yields these.
pub mod neutral_handles;
/// The genuinely cross-plane SUBSCRIBE leaf (mcp + a2a) — neutral, stays in core.
pub mod subscribe;

// ── CONCRETE IR — RELOCATED to busbar-llm (G6 A4b) ───────────────────────────────────────────────
//
// The concrete chat IR and the LLM leaf-op IR (`IrRequest`/`IrResponse`/`IrBlock`/`Embeddings*`/… —
// the five leaf-op IR modules and the `IrFacts for IrRequest` projection) live wholly in the
// `busbar-llm` plugin crate (`crates/busbar-llm/src/ir/*`). Their `#[path]` witness re-includes into
// core (which made `crate::ir::IrRequest` etc. resolve at this module root for core's own test binary)
// were DELETED once Phase 1.6 drained core's own suite of any dependence on the witnessed concrete IR:
// the concrete-IR unit tests moved to `busbar-llm/src/ir/tests/`, beside the types they exercise.
// Production core reads a request only through the neutral projection (`facts`) and drives translation
// through the sealed neutral `IrHandle` (`handle`); it names no concrete LLM family type.

// The concrete-IR unit tests (`tests.rs` + the leaf-op `*_tests.rs`) RELOCATED with their types to
// `crates/busbar-llm/src/ir/tests/`, declared by the plugin's own IR modules; core's neutral IR keeps
// only its own tests (`subscribe.rs` → `tests/subscribe_tests.rs`, etc.). Nothing to declare here.
