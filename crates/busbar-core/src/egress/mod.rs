// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST-MEDIATED OUTBOUND SEAM. The neutral outbound transport — the SSRF-pinned client, its
//! bounded pool and the protocol-blind `Response` / `StreamHead` / `ChunkFlow` vocabulary — is
//! `busbar_substrate::egress`, and every caller names it there (the `crate::egress::*` facade that
//! used to re-export it is deleted). What is core's alone is [`seam`]: the resolve-and-inject adapter
//! that takes a plane's SecretRef HANDLE + hop spec, resolves the credential and drives the governed
//! egress through the `plane_host` FFI vtable. That is the secret path and is deliberately NOT
//! neutral — a third-party plugin must never hold plaintext.

/// THE NEUTRAL FETCH ADAPTER: re-express a host-owned governed egress as the buffered / streamed
/// return shapes the protocol planes already consume, so an extracted plane never holds a concrete
/// `reqwest::Response`. Gated on the neutral `egress-seam` capability marker — enabled by whichever
/// plane feature supplies its consumers (the plane transports: card-fetch/relay, dispatch), so the
/// gate names a capability rather than a plane. Its truth value is that of the former
/// `any(plane-mcp, plane-a2a)`.
#[cfg(feature = "egress-seam")]
pub mod seam;
