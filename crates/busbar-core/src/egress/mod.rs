// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST-OWNED OUTBOUND SURFACE, shared by every protocol plane.
//!
//! The neutral outbound TRANSPORT — the SSRF-pinned reqwest client, its bounded pool, and the
//! protocol-blind return vocabulary (`Response`, `StreamHead`, `ChunkFlow`) of one buffered/streamed
//! hop — now lives in `busbar_substrate::egress` so a plane crate names it without reaching into
//! busbar-core; it is re-exported here unchanged for core's own `crate::egress::*` call sites.
//!
//! What STAYS here is [`seam`]: the host-mediated resolve-and-inject adapter that takes a plane's
//! SecretRef HANDLE + hop spec, resolves the credential and drives the governed egress through the
//! `plane_host` FFI vtable. That is the secret path and is deliberately NOT neutral — a third-party
//! plugin must never hold plaintext, so this half is core's alone.

pub use busbar_substrate::egress::*;

/// THE NEUTRAL FETCH ADAPTER: re-express a host-owned governed egress as the buffered / streamed
/// return shapes the protocol planes already consume, so an extracted plane never holds a concrete
/// `reqwest::Response`. Gated on the neutral `egress-seam` capability marker — enabled by whichever
/// plane feature supplies its consumers (the plane transports: card-fetch/relay, dispatch), so the
/// gate names a capability rather than a plane. Its truth value is that of the former
/// `any(plane-mcp, plane-a2a)`.
#[cfg(feature = "egress-seam")]
pub mod seam;
