// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral IR seam, now a RETIRING re-export shim. Every neutral IR type — the `IrFacts`
//! projection, the sealed `IrHandle`, the cross-plane `invoke`/`subscribe` leaves, `EgressPrep` and
//! the four neutral handles — lives in `busbar-substrate-values` and is named through
//! `busbar_substrate::ir::…`. Core declares no IR of its own. The CONCRETE chat IR and the LLM
//! leaf-op IR (`IrRequest`/`IrResponse`/`IrBlock`/`Embeddings*`/… — everything that names an LLM wire
//! shape) RELOCATED to the `busbar-llm` plugin at the G6 A4b cutover, so core reads a request only
//! through the neutral projection and never names a concrete LLM family type in production. The
//! freeze witness (`scripts/g6-freeze-witness.sh`) gates that to zero.

// ── THE REMAINING RE-EXPORT SHIMS — retiring (D33 wave 5, row `ir/`) ─────────────────────────────
//
// Every type this module ever declared now lives in `busbar-substrate-values` and is reached through
// `busbar_substrate::ir::…`. The historical `crate::ir::…` spellings were retired in place; the two
// below survive only because `crate::hooks` still names them, and they go with that module's own
// retirement cut. `egress_prep`, `handle`, `neutral_handles` and `subscribe` had no caller left at
// all and were DELETED rather than relocated — there was no body to move, only a `pub use`.

/// THE ONE PROJECTION — what the shared pipeline (hooks, governance, taps) is allowed to know about
/// a request, read from the IR and from nothing else. Re-export shim; the surface is
/// `busbar_substrate::ir::facts`.
pub mod facts;
/// The genuinely cross-plane INVOKE leaf (mcp + a2a). Re-export shim; the data is
/// `busbar_substrate::ir::invoke`.
pub mod invoke;

// ── CONCRETE IR — RELOCATED to busbar-llm (G6 A4b) ───────────────────────────────────────────────
//
// The concrete chat IR and the LLM leaf-op IR (`IrRequest`/`IrResponse`/`IrBlock`/`Embeddings*`/… —
// the five leaf-op IR modules and the `IrFacts for IrRequest` projection) live wholly in the
// `busbar-llm` plugin crate (`crates/busbar-llm/src/ir/*`). Their `#[path]` witness re-includes into
// core (which made `crate::ir::IrRequest` etc. resolve at this module root for core's own test binary)
// were DELETED once Phase 1.6 drained core's own suite of any dependence on the witnessed concrete IR:
// the concrete-IR unit tests moved to `busbar-llm/src/ir/tests/`, beside the types they exercise.
// Production core reads a request only through the neutral projection and names no concrete LLM
// family type.

// The concrete-IR unit tests RELOCATED with their types to `crates/busbar-llm/src/ir/tests/`, and
// this module's own last test (the `SubscribeReq` projection) travelled with `subscribe.rs` to
// `busbar-substrate-values/src/ir/tests/subscribe.rs`. Nothing to declare here.
