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

// ── CONCRETE IR — RELOCATED to busbar-llm (G6 A4b); re-included for TEST BUILDS ONLY ─────────────
//
// The type DEFINITIONS live in `crates/busbar-llm/src/ir/*` (they address core as `busbar_core::`,
// which the `extern crate self as busbar_core` alias resolves here). Core's PRODUCTION build names
// none of them; the `#[path]` re-include below makes `crate::ir::IrRequest` (and the five leaf-op
// IR modules + the `IrFacts for IrRequest` projection) resolve at this module root for core's test
// binary, exactly as before the relocation.

/// The concrete chat IR TYPES (`IrRequest`/`IrResponse`/`IrBlock`/…), re-exported flat so every
/// pre-cutover `crate::ir::<Type>` path still resolves in the test build.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir/types.rs"]
mod types;
#[cfg(any(test, feature = "test-support"))]
pub use types::*;

#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir/audio.rs"]
pub mod audio;
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir/embeddings.rs"]
pub mod embeddings;
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir/image.rs"]
pub mod image;
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir/moderation.rs"]
pub mod moderation;
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir/rerank.rs"]
pub mod rerank;

/// `impl IrFacts for IrRequest` + `project` — relocated with the concrete chat IR (G6 A4b).
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir/facts_impl.rs"]
mod facts_impl;
#[cfg(any(test, feature = "test-support"))]
pub use facts_impl::project;

// The concrete-IR unit tests (`tests.rs` + the leaf-op `*_tests.rs`) RELOCATED with their types to
// `crates/busbar-llm/src/ir/tests/`, declared by the plugin's own IR modules; core's neutral IR keeps
// only its own tests (`subscribe.rs` → `tests/subscribe_tests.rs`, etc.). Nothing to declare here.
