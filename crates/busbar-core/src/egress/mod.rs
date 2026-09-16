// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST-OWNED OUTBOUND SURFACE, shared by every protocol plane.
//!
//! The neutral outbound TRANSPORT — the SSRF-pinned reqwest client, its bounded pool, and the
//! protocol-blind return vocabulary (`Response`, `StreamHead`, `ChunkFlow`) of one buffered/streamed
//! hop — now lives in `busbar_substrate::egress` so a plane crate names it without reaching into
//! busbar-core; it is re-exported here unchanged for core's own `crate::egress::*` call sites.
//!
//! What STAYS here is [`seam`]: the host-mediated adapter that takes a plane's already-built hop spec
//! (its opaque client-identity / trust-anchor refs, and — where the plane already resolved-then-pinned
//! an address itself — that address) and drives the governed egress through the `plane_host` FFI
//! vtable. That vtable is core's internal driver, reachable only from code compiled into core, unlike
//! the neutral `busbar_substrate` client above which any plane crate can call on its own — so this half
//! is deliberately NOT neutral, and stays core's alone.

pub use busbar_substrate::egress::*;

/// THE NEUTRAL FETCH ADAPTER: re-express a host-owned governed egress as the buffered / streamed
/// return shapes a protocol plane already consumes, so an extracted plane never holds a concrete
/// `reqwest::Response`. Gated on the neutral `egress-seam` capability marker, so the gate names a
/// capability rather than any one plane; it is enabled by whichever plane feature needs this adapter.
#[cfg(feature = "egress-seam")]
pub mod seam;
