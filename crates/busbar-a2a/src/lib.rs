// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-a2a — the Agent2Agent protocol, as ONE plugin crate. SHELL ONLY, so far.
//!
//! Step 3.B.0 of the plane split creates this crate empty on purpose: the manifest and this doc
//! comment, wired into the workspace and into `crates/busbar/Cargo.toml` behind a `plane-a2a`
//! feature that nothing yet turns on and nothing yet consumes. No plane or codec code has moved
//! here — that is later steps in the same split.
//!
//! WHAT THIS CRATE WILL HOLD. The A2A protocol codec — the agent-card and task JSON-RPC/gRPC/REST
//! wire vocabulary — folded TOGETHER with the A2A plane — today's `crates/busbar-core/src/a2a` (the
//! agent card, the task store, the delegating and inbound transports, the config sections, boot
//! hydration, the router mount and the admin API). A2A the protocol and A2A the plane are the same
//! protocol, so they end up behind ONE on/off switch, not two — an operator's choice is "can this
//! busbar speak A2A", never "can it speak the wire format but not run the plane behind it".
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-llm` states for its six LLM dialects: nothing
//! about the seam changes because this plugin happens to also carry a plane's worth of state.
