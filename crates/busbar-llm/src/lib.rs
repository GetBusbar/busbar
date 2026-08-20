// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PROTOCOL — six dialects, ONE plugin.
//!
//! Anthropic Messages, OpenAI Chat Completions, Google Gemini, AWS Bedrock Converse, OpenAI
//! Responses and Cohere v2 are six ways of saying the same thing, and busbar translates between any
//! pair of them through one neutral IR. That is what makes them DIALECTS rather than protocols: the
//! unit an operator installs, versions and deletes is "can this busbar speak LLM", never "can it
//! speak anthropic but not gemini". So they ship as one crate with six modules, and a seventh
//! dialect is a seventh module here — not a seventh crate and not a seventh feature flag.
//!
//! WHAT EACH DIALECT MODULE OWNS: its `ProtocolDecl`, its wire codec (`reader.rs`/`writer.rs`), its
//! `RequestHandler` and operation cells (`handler.rs`), its own wire constant bank, and its tests.
//! Nothing here is reachable from `busbar-core`: core names no dialect, and this crate names
//! `busbar-core` and no other busbar crate. Registration belongs to the composition root alone —
//! `crates/busbar/src/main.rs::register_protocols` installs [`DECLS`] behind the `proto-llm`
//! feature, which carries the dependency edge too, so dropping the feature drops the whole LLM
//! protocol and the deletion gate watches busbar refuse all six names at boot.
//!
//! WHAT IS DELIBERATELY *NOT* HERE. `busbar_core::proto::openai_family` — the `ERR_TYPE_*` bank,
//! `bearer_error_code`, `tool_arguments_to_string`, `MESSAGE_NAMES_SENTINEL` — reads like it should
//! have travelled with the OpenAI dialects, and it must not: `busbar-core` itself consumes it in
//! PRODUCTION (`proxy`'s whole `KIND_*` vocabulary, `admin`'s error envelopes, `auth`'s bearer error
//! code, `ir::variant`'s sentinel). Moving it here would make core depend on this plugin, inverting
//! the seam this crate exists to create. It stays in core and every dialect reaches it there.
//!
//! THE DUAL COMPILE. `busbar-core`'s test and `test-support` builds compile these same source files
//! back in under `crate::proto::{anthropic, …}` via `#[path]`, so core's pre-extraction fixture
//! surface keeps exercising the real codecs from inside core's own test binary. Two consequences
//! bind every file here: dialect sources address core as `busbar_core::…` (core's
//! `extern crate self as busbar_core` alias resolves that to itself), and a dialect referring to a
//! SIBLING dialect must do it RELATIVELY — `super::gemini::…` from a `mod.rs`, `super::super::…`
//! from one file deeper — because the parent module is this crate's root in one shape and
//! `crate::proto` in the other, and only a relative path is correct in both.

pub mod anthropic;
pub mod bedrock;
pub mod cohere;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;

/// EVERY DIALECT THIS PLUGIN DECLARES, in the order an operator sees.
///
/// THE ORDER IS LOAD-BEARING AND IT IS NOT ALPHABETICAL. The composition root hands this slice to
/// `busbar_core::proto::registry::install_protocols`, which folds it AHEAD of whatever built-in
/// declarations core still carries; the resulting sequence is what `known_protocols()` reports (the
/// "must be one of:" tail an operator reads on a bad `protocol:`) and what `telemetry` banks its
/// per-protocol metric families against — it finds a family again by POSITION in that list. So this
/// order reproduces, exactly, the operator-visible list from before the dialects were plugins:
/// `anthropic, gemini, openai, bedrock, responses, cohere`. A dialect appended here rather than
/// inserted keeps every existing family's index; inserting one silently renumbers all of them.
pub static DECLS: &[&busbar_core::proto::ProtocolDecl] = &[
    &anthropic::DECL,
    &gemini::DECL,
    &openai_chat::DECL,
    &bedrock::DECL,
    &openai_responses::DECL,
    &cohere::DECL,
];

#[cfg(test)]
#[path = "tests/write_error_frame_tests.rs"]
mod write_error_frame_tests;
