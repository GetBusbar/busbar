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
//! the host's plane installer at boot.
//!
//! A2A IS PLANE-ONLY. Unlike `busbar-mcp` (which also carries a `PROTO_DECL` on the LLM-style proto
//! axis), A2A contributes ONLY a `PlaneDecl` — there is no separate protocol-codec declaration to
//! register.

// THE PLANE'S TEST-ONLY RESIDUAL SURFACE (the trust verbs `connect` did not bring — `sync`,
// `suspend`, `resume` — push-notification DELIVERY, and the task-read verbs) has NO production caller;
// it is exercised only by the plane tests, which run in `busbar-core`'s dual-compile binary and are
// gated OUT of THIS crate's own test binary (`feature = "test-support"`). So in the `not(feature = "test-support")`
// test build those items read as dead — not because they are unused, but because their only consumers
// were configured out. Allow it there ONLY: production (`not(test)`) and core's dual-compile
// (`feature = "test-support"`) keep the full per-file dead-code discipline the plane's modules rely on.
#![cfg_attr(all(test, not(feature = "test-support")), allow(dead_code))]

pub mod a2a;
pub mod diagnostics;
pub mod record;
pub mod taskstore;

/// THE A2A PLANE'S OWN DURABLE RECORD TYPES — relocated here from `busbar-api` (1.7.0 plane
/// extraction), re-exported at the crate root so `busbar_a2a::TaskRow` / `busbar_a2a::TaskEventRow`
/// resolve. The neutral crates name neither.
pub use record::{TaskEventRow, TaskRow};

/// THE A2A PLANE'S TEST-KIT (feature `test-support` only): the fixture builders that name A2A plane
/// types, kept on the plane so busbar-core's neutral `test_support::TestApp` names none of them. This
/// is the seam that lets core drop the `#[path]` dual-compile of `src/a2a` for its own tests.
#[cfg(feature = "test-support")]
pub mod testkit;

/// A2A'S PLANE DECLARATION — the `&'static PlaneDecl` the composition root installs at boot so the
/// `busbar` binary names one stable path (`busbar_a2a::PLANE_DECL`). See [`a2a`] for the declaration.
pub use a2a::PLANE_DECL;

/// A2A'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the composition root
/// hands to `busbar_substrate::diagnostics::install_diagnostics` at boot, re-exported at the crate
/// root so the `busbar` binary names one stable path (`busbar_a2a::DIAGNOSTICS`). See [`diagnostics`].
pub use diagnostics::DIAGNOSTICS;
