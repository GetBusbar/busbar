// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-a2a — the Agent2Agent protocol, as ONE plugin crate.
//!
//! WHAT THIS CRATE HOLDS. The A2A plane and codec, folded together (today's former
//! `crates/busbar-core/src/a2a`): the agent card, the task store, the delegating and inbound
//! JSON-RPC/gRPC/REST transports, the `agents:` config sections, boot hydration, the router mount and
//! the admin API. A2A the protocol and A2A the plane are the same protocol, so they sit behind ONE
//! on/off switch, not two — an operator's choice is "can this busbar speak A2A", never "can it speak
//! the wire format but not run the plane behind it".
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-llm` states for its six LLM dialects and `busbar-mcp`
//! for MCP: nothing about the seam changes because this plugin also carries a plane's worth of state.
//! Everything the plane consumes from the engine comes through the neutral `busbar-substrate` surface
//! (and `busbar-api`); nothing in `busbar-core` names this crate in production, and the `busbar` BINARY
//! — the composition root — links it and hands [`PLANE_DECL`] to
//! `busbar_core::plane::registry::install_planes` at boot.
//!
//! A2A IS PLANE-ONLY. Unlike `busbar-mcp` (which also carries a `PROTO_DECL` on the LLM-style proto
//! axis), A2A contributes ONLY a `PlaneDecl` — there is no separate protocol-codec declaration to
//! register.

// THE PLANE'S TEST-ONLY RESIDUAL SURFACE (the trust verbs `connect` did not bring — `sync`,
// `suspend`, `resume` — push-notification DELIVERY, and the task-read verbs) has NO production caller;
// it is exercised only by the plane tests, which run in `busbar-core`'s dual-compile binary and are
// gated OUT of THIS crate's own test binary (`not(busbar_a2a_native)`). So in the `busbar_a2a_native`
// test build those items read as dead — not because they are unused, but because their only consumers
// were configured out. Allow it there ONLY: production (`not(test)`) and core's dual-compile
// (`not(busbar_a2a_native)`) keep the full per-file dead-code discipline the plane's modules rely on.
#![cfg_attr(all(test, busbar_a2a_native), allow(dead_code))]

pub mod a2a;

/// A2A'S PLANE DECLARATION — the `&'static PlaneDecl` the composition root installs at boot so the
/// `busbar` binary names one stable path (`busbar_a2a::PLANE_DECL`). See [`a2a`] for the declaration.
pub use a2a::PLANE_DECL;
