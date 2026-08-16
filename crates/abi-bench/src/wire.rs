// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE IR WIRE MIRROR — the schema a protocol/plane plugin would have to marshal.
//!
//! # Why a mirror and not `busbar_core::ir::IrRequest` itself
//!
//! `IrRequest` **cannot be marshalled at all today**: nothing in `crates/busbar-core/src/ir/` derives
//! `Serialize`/`Deserialize` (verified by grep on this branch). The IR was built to be translated
//! to/from `serde_json::Value` by a reader/writer pair that lives INSIDE the process; it was never a
//! wire type. So "put the IR on the plugin ABI" is not a matter of turning a crank — it means
//! authoring an IR wire schema. This module IS that schema, drawn deliberately, and the act of
//! drawing it surfaced the two facts the design decision turns on:
//!
//! 1. **`serde_json::Value` does not survive a zero-copy schema.** Five IR sites are `Value`
//!    (`IrTool::input_schema`, `IrBlock::ToolUse::input`, `IrBlock::Json`, `IrResponseFormat::schema`,
//!    `IrRequest::extra`) plus `IrImageSource::Vendor::value`. FlatBuffers, Cap'n Proto and rkyv all
//!    need a closed, statically-known layout; none of them has a `Value`. Here they are carried as
//!    opaque JSON TEXT (`String`), which is what any archived layout would have to do — and note what
//!    that means for the hot path: a plugin that actually READS a tool schema pays a JSON parse the
//!    archive was supposed to eliminate.
//! 2. **`IrImageSource::Vendor::vendor` is a `&'static str`.** No wire format carries a borrow of the
//!    producing binary's rodata; it becomes an owned string on any wire.
//!
//! The mirror is shape-faithful to `IrRequest` field-for-field (same field names, same cardinality,
//! same optionality) so that the encode/decode volume measured here is the encode/decode volume the
//! real IR would cost. It is deliberately NOT a superset: only the chat IR is modelled, because chat
//! is the hot path the owner's bar is about.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Mirror of `busbar_core::ir::IrRequest`.
#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, Default)]
pub struct WireRequest {
    pub system: Vec<WireBlock>,
    pub messages: Vec<WireMessage>,
    pub tools: Vec<WireTool>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub top_k: Option<u32>,
    pub frequency_penalty: Option<f64>,
    pub presence_penalty: Option<f64>,
    pub seed: Option<i64>,
    pub n: Option<u32>,
    pub reasoning: Option<WireReasoning>,
    pub reasoning_budgets: Option<[u32; 4]>,
    pub logprobs: Option<bool>,
    pub top_logprobs: Option<u32>,
    pub response_format: Option<WireResponseFormat>,
    pub stop: Vec<String>,
    pub tool_choice: Option<WireToolChoice>,
    pub user: Option<String>,
    pub parallel_tool_calls: Option<bool>,
    pub stream: bool,
    /// `IrRequest::extra` (a `serde_json::Map`) as opaque JSON text — see the module header.
    pub extra_json: String,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct WireMessage {
    pub role: WireRole,
    pub content: Vec<WireBlock>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, Copy)]
pub enum WireRole {
    System,
    User,
    Assistant,
    Tool,
}

/// Mirror of `busbar_core::ir::IrBlock`. `ToolResult::content` keeps the real nesting.
///
/// # FINDING — the IR is RECURSIVE, and a zero-copy derive does not accept that for free
///
/// `IrBlock::ToolResult::content` is a `Vec<IrBlock>`: a block contains blocks. `serde`'s derive
/// handles that without comment, but `rkyv`'s does NOT — the derived `Archive`/`Serialize`/
/// `Deserialize` bounds are structural, so a self-referential type makes the trait solver recurse
/// until it hits the recursion limit (`E0275: overflow evaluating the requirement
/// WireBlock: Archive`, 20 instances, verified on this branch against rkyv 0.8.16).
///
/// The fix is `#[rkyv(omit_bounds)]` on the recursive field plus HAND-WRITTEN bounds for all four
/// contexts (serialize, deserialize, and — separately — bytecheck's validation context). This is a
/// real cost the design has to budget for, not a detail of this harness: every nested IR type
/// (`ToolResult`, and anything the VPN/plane IR nests) needs the same treatment, and getting the
/// bytecheck bound wrong is what silently turns a *validated* archive read into an unvalidated one.
/// FlatBuffers and Cap'n Proto do not have this problem in the same form because their schemas are
/// compiled from an IDL rather than derived from Rust types — but they pay for it with a codegen
/// step and a second source of truth for the IR.
#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(bounds(
    __C: rkyv::validation::ArchiveContext,
    __C::Error: rkyv::rancor::Source,
)))]
pub enum WireBlock {
    Text {
        text: String,
        cache_control: Option<WireCacheControl>,
        citations: Vec<WireCitation>,
    },
    Thinking {
        text: String,
        signature: Option<String>,
        redacted: bool,
        cache_control: Option<WireCacheControl>,
    },
    ToolUse {
        id: String,
        name: String,
        /// `IrBlock::ToolUse::input` — a `Value` in the IR, opaque JSON text on any wire.
        input_json: String,
        cache_control: Option<WireCacheControl>,
        thought_signature: Option<String>,
    },
    ToolResult {
        tool_use_id: String,
        /// THE recursive field — see the type's doc comment.
        #[rkyv(omit_bounds)]
        content: Vec<WireBlock>,
        is_error: bool,
        cache_control: Option<WireCacheControl>,
    },
    Image {
        source: WireImageSource,
        cache_control: Option<WireCacheControl>,
    },
    Media {
        kind: WireMediaKind,
        source: WireImageSource,
        name: Option<String>,
        cache_control: Option<WireCacheControl>,
    },
    /// `IrBlock::Json(Value)` — opaque JSON text.
    Json(String),
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum WireImageSource {
    Base64 { media_type: String, data: String },
    Url(String),
    /// `IrImageSource::Vendor` — `vendor` is a `&'static str` in the IR; owned here (module header).
    Vendor { vendor: String, value_json: String },
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, Copy)]
pub enum WireMediaKind {
    Document,
    Audio,
    Video,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, Copy)]
pub struct WireCacheControl {
    pub ephemeral: bool,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct WireCitation {
    pub kind: Option<String>,
    pub cited_text: Option<String>,
    pub title: Option<String>,
    pub url: Option<String>,
    pub document_index: Option<i64>,
    pub start_index: Option<i64>,
    pub end_index: Option<i64>,
    pub encrypted_index: Option<String>,
    pub raw_json: Option<String>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct WireTool {
    pub name: String,
    pub description: Option<String>,
    /// `IrTool::input_schema` — a `Value` in the IR; the single biggest `Value` in a real request.
    pub input_schema_json: String,
    pub cache_control: Option<WireCacheControl>,
    pub hosted_json: Option<String>,
    pub strict: Option<bool>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum WireToolChoice {
    Auto,
    None,
    Required,
    Tool { name: String },
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, Copy)]
pub enum WireReasoning {
    Effort(u8),
    Budget(u32),
    Dynamic,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct WireResponseFormat {
    pub json: bool,
    pub schema_json: Option<String>,
    pub name: Option<String>,
    pub strict: Option<bool>,
    pub description: Option<String>,
}

// ── the streaming frame ─────────────────────────────────────────────────────────────────────────
// Mirror of `busbar_core::ir::IrStreamEvent` / `IrDelta`. This is the DECISIVE payload: an SSE text
// delta is tens of bytes and a completion emits hundreds to thousands of them, so whatever a single
// crossing costs is multiplied by the frame count.

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum WireStreamEvent {
    MessageStart {
        role: WireRole,
        id: Option<String>,
        created: Option<u64>,
        model: Option<String>,
        usage: WireUsage,
    },
    BlockStart {
        index: u32,
        block: WireBlockMeta,
    },
    BlockDelta {
        index: u32,
        delta: WireDelta,
    },
    BlockStop {
        index: u32,
    },
    MessageDelta {
        stop_reason: Option<u8>,
        stop_sequence: Option<String>,
        usage: WireUsage,
    },
    MessageStop,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum WireBlockMeta {
    Text,
    Thinking,
    ToolUse { id: String, name: String },
    Image,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum WireDelta {
    TextDelta(String),
    ThinkingDelta(String),
    InputJsonDelta(String),
    SignatureDelta(String),
    RedactedReasoningDelta(String),
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, Copy, Default,
)]
pub struct WireUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
}
