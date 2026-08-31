// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S OWN TEST-BINARY BUILT-IN PROTOCOL LIST — the extracted dialects (`busbar_llm::DECLS`) and
//! the MCP protocol (`busbar_mcp::PROTO_DECL`), named HERE in a `tests/` file the neutral-purity lint
//! excludes so the neutral source (`proto/registry.rs`) spells no protocol crate.
//!
//! This is the exact analogue of `plane::tests::registry_tests::TEST_BUILTIN_PLANE_DECLS`. It replaces
//! the deleted `#[path]` witness re-includes of the dialect sources: those existed only because a
//! `ProtocolDecl` was once a `busbar-core` type, so an externally-linked crate's `&DECL` was a
//! DIFFERENT crate's type the registry could not hold. `ProtocolDecl` now lives in `busbar-substrate`,
//! so `busbar_llm::DECLS` and `busbar_mcp::PROTO_DECL` are the SAME `ProtocolDecl` type — core's own
//! test binary links the real plugin crates as dev-dependencies and reads their declarations
//! directly, reproducing the shipped protocol set and its operator-visible ORDER for the
//! pre-extraction fixture surface WITHOUT re-compiling the dialect sources into core.
//!
//! THE ORDER IS `busbar_llm::DECLS`' ORDER, then MCP — the same sequence the composition root installs
//! in production (`crates/busbar/src/main.rs::register_protocols`), so `known_protocols()`'s order (the
//! metric-family index and the config-error `must be one of:` order) is byte-identical to the shipped
//! binary's.

use busbar_core::proto::registry::ProtocolDecl;

/// The shipped protocol set for core's test binary: the six LLM dialects in `busbar_llm::DECLS`' order
/// (anthropic, gemini, openai, bedrock, responses, cohere), then the codec-less MCP protocol.
pub static TEST_BUILTIN_DECLS: &[&ProtocolDecl] = &[
    &busbar_llm::anthropic::DECL,
    &busbar_llm::gemini::DECL,
    &busbar_llm::openai_chat::DECL,
    &busbar_llm::bedrock::DECL,
    &busbar_llm::openai_responses::DECL,
    &busbar_llm::cohere::DECL,
    &busbar_mcp::PROTO_DECL,
];
