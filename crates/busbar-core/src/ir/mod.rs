// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The superset intermediate representation (IR) — request and response/stream sides — that every
//! protocol's Reader/Writer maps to and from, so any ingress protocol can reach any backend
//! losslessly. (See `docs/adr/0005-ir-fidelity.md` for the fidelity contract.)
//!
//! OPACITY IS AN IR FACT, NOT A WIRE FACT. Three protocols carry assistant reasoning busbar cannot
//! decrypt, in three different shapes; [`IrBlock::is_opaque`] is the single place that knows all
//! three, so a consumer deciding "show this content or substitute a marker" never has to re-sniff
//! the wire body to get the answer right. It is a PREDICATE rather than a flag flip on
//! `Thinking.redacted` because `redacted` is a writer instruction with client-visible egress
//! consequences — the full reasoning is on `is_opaque` itself.

// Per-operation IR variants. Chat is the `IrRequest`/`IrResponse` below; the other
// operations live in submodules and are assembled into `enum IrReq`/`enum IrResp`.
pub(crate) mod audio;
pub(crate) mod embeddings;
/// THE ONE PROJECTION — what the shared pipeline (hooks, governance, taps) is allowed to know about
/// a request, read from the IR and from nothing else. Beside the IR rather than beside the hooks so
/// that "a hook sees the IR" is a compile-time fact; see the module header.
pub(crate) mod facts;
pub(crate) mod image;
pub(crate) mod invoke;
pub(crate) mod moderation;
pub(crate) mod rerank;
pub(crate) mod subscribe;
pub(crate) mod variant; // IrReq / IrResp enums + the operation-blind surface

// ── THE IR IS THE PROTOCOL ABI, AND IT LIVES IN `busbar-api` ────────────────────────────────────
//
// A reader turns a wire body into an `IrRequest`; a writer turns an `IrResponse` back out. Neither
// can be expressed without these types, so a protocol plugin that could not name them could not be
// written against `busbar-api` alone — which is the whole bar. They therefore live in the ABI crate
// and core re-exports them here, unchanged and under the same paths, so that `crate::ir::IrRequest`
// still resolves at the ~thousands of call sites that use it. THIS RE-EXPORT IS THE MOVE: there is
// no second definition, and `busbar-api` is the only place these shapes are stated.
//
// What did NOT move, and is still defined below/beside this line: `facts` (the disclosure
// projection a hook may see), the per-operation `IrReq`/`IrResp` assembly in `variant`, and the
// egress preparation that applies lane gating, clamping and cap enforcement. Those are ENGINE
// POLICY — a plugin that could name them could rewrite the rules it is meant to be governed by.
pub use busbar_api::ir::*;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
