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
//! — the composition root — links it and hands [`PLANE_DECLARATION`] (with [`PLANE_HOOKS`]) to
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
pub mod taskstore;

/// THE A2A PLANE'S DIAGNOSTICS CATALOG.
///
/// The `A2A_*` catalog entries and the `DIAGNOSTICS` slice previously lived in the standalone
/// `busbar-plane-a2a-host` crate (the first byte-safe step of the fat-crate collapse — DECISIONS
/// #19/#20/#21) and re-exported here under this path; that crate has since folded back into this
/// one (#19/#39: mirrors `busbar-plane-mcp-host`'s deletion), so the module lives here directly now.
/// Every `busbar_a2a::diagnostics::…` / `crate::diagnostics::…` caller still resolves exactly what
/// it always did.
pub mod diagnostics;

/// THE DURABLE RECORD VOCABULARY. The row STRUCTS are this crate's: they name the store seam, which a pure kind may not. Their two KIND strings are the plane's schema ids and are read from there.
///
/// The task and task-event row shapes moved to the pure half of this plugin — split out so
/// `busbar-plane-a2a` can name the record kinds without linking this crate's axum routes, tonic
/// binding and reqwest relay leg. Re-exported HERE, under its old name, so every caller that spells
/// `busbar_a2a::record::…` resolves exactly what it always did.
pub mod record;

/// THE A2A PLANE'S OWN DURABLE RECORD TYPES — relocated here from `busbar-api` (1.7.0 plane
/// extraction), re-exported at the crate root so `busbar_a2a::TaskRow` / `busbar_a2a::TaskEventRow`
/// resolve. The neutral crates name neither.
pub use record::{TaskEventRow, TaskRow};

/// A2A'S PLANE CAPABILITY KEY (`"a2a"`) — the string the composition root flips onto the unified
/// kernel loop and the same string the A2A invoke plane reports from its
/// `GauntletPlane::capability_key`. Re-exported at the crate root so the `busbar` binary names ONE
/// stable path (`busbar_a2a::PLANE_KEY`) and the plane and the flip cannot drift onto two literals.
pub use busbar_plane_a2a::PLANE_KEY;

/// THE A2A PLANE'S TEST-KIT (feature `test-support` only): the fixture builders that name A2A plane
/// types, kept on the plane so busbar-core's neutral `test_support::TestApp` names none of them. This
/// is the seam that lets core drop the `#[path]` dual-compile of `src/a2a` for its own tests.
#[cfg(feature = "test-support")]
pub mod testkit;

/// A2A'S PLANE DECLARATION — the contract data the composition root registers
/// (`busbar_a2a::PLANE_DECLARATION`) and the behaviour table the kernel joins to it
/// (`PLANE_HOOKS`, through `PlaneDecl::assemble`). See [`a2a`] for both.
pub use a2a::{PLANE_DECLARATION, PLANE_HOOKS};

/// A2A'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the composition root
/// hands to `busbar_substrate_values::diagnostics::install_diagnostics` at boot, re-exported at the crate
/// root so the `busbar` binary names one stable path (`busbar_a2a::DIAGNOSTICS`). See [`diagnostics`].
pub use diagnostics::DIAGNOSTICS;

/// THE ONE ENTRY THIS PLUGIN IS REGISTERED THROUGH — everything a composition root that linked it
/// wires, one item per registration axis, read off the crate rather than spelled at the root. The
/// root's manifest names this crate and the axes it registers on
/// (`[package.metadata.busbar.linked-axes]`: the plane — no protocol declaration — its owned
/// diagnostics, and the three root-bound seams it drives: the governed outbound hop, the parse-time
/// section list its cross-plane hook refusal reads, and the envelope its self-enveloping verbs build
/// through); its build script turns that into one table per axis over these items, and the root's
/// source names no item of this crate.
pub mod linked {
    /// The diagnostics axis.
    pub use crate::DIAGNOSTICS;
    /// The plane axis: the contract declaration, joined kernel-side to the behaviour table.
    pub use crate::{PLANE_DECLARATION, PLANE_HOOKS};
}
