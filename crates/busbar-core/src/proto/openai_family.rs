// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared helpers and constants for the OpenAI-family protocols (Chat Completions and Responses).
//! Both wire formats belong to the same provider family; items that are identical across them
//! live here so they are single-sourced rather than copy-pasted (and risking drift).

// The OpenAI-family error helpers (`CODE_INVALID_API_KEY`, `PROVIDER_SIGNAL_CONTEXT_LENGTH`,
// `MESSAGE_NAMES_SENTINEL`, `openai_context_length_prose_scan`, `bearer_error_code`,
// `openai_classify`) RELOCATED DOWN to the neutral `busbar_substrate::proto` leaf so the
// `busbar-llm` OpenAI-family dialects name them without reaching into `busbar-core`. Re-exported here
// at their historical `proto::openai_family::…` paths so every existing in-core / plugin caller
// compiles unchanged; the string values and classifier logic are byte-identical. (`bearer_error_code`
// named six core-only `proxy::KIND_*` aliases before the move; it now names the byte-identical
// substrate `ERR_TYPE_*` consts directly.)
pub use busbar_substrate::proto::{
    bearer_error_code, openai_context_length_prose_scan, CODE_INVALID_API_KEY,
    MESSAGE_NAMES_SENTINEL,
};
#[cfg(any(test, feature = "test-support"))]
pub use busbar_substrate::proto::{openai_classify, PROVIDER_SIGNAL_CONTEXT_LENGTH};

// The openai-family DIALECT consts (`OPENAI_FAMILY_DEFAULT_MODEL`/`OPENAI_FAMILY_MAX_OPEN_TOOLS`)
// moved UP into `busbar-llm` (its openai_chat module) — they had zero core production users.

// CANONICAL error-`type` vocabulary — the whole ERR_TYPE_* bank RELOCATED DOWN to the neutral
// `busbar_substrate::proto` leaf so every consumer (core's forward `proxy::KIND_*`, the admin API,
// the anthropic writer, and the OpenAI-family writers in `busbar-llm`) names it without reaching into
// `busbar-core`. Re-exported here at their historical `proto::openai_family::ERR_TYPE_*` paths so
// every existing in-core / plugin caller compiles unchanged; the string values are byte-identical.
pub use busbar_substrate::proto::{
    ERR_TYPE_API_ERROR, ERR_TYPE_AUTHENTICATION, ERR_TYPE_INSUFFICIENT_QUOTA,
    ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_OVERLOADED, ERR_TYPE_PERMISSION,
    ERR_TYPE_RATE_LIMIT, ERR_TYPE_REQUEST_TOO_LARGE, ERR_TYPE_SERVER_ERROR,
};

// SHARED ACROSS THE OPENAI-FAMILY DIALECTS AND COHERE (tool-call argument stringification): cohere's
// and the openai writers/readers call this too, so it stays at this shared crossing rather than
// becoming a cross-protocol-crate dependency. It names no concrete IR, so it is a neutral string
// helper that legitimately lives in core. (The url-citation projection that used to sit here HAS
// moved to `busbar-llm/src/openai_annotations.rs` — it names `IrCitation`, so it belongs beside the
// openai codecs that own it, reached through the reader/writer vtable.)
// `tool_arguments_to_string` RELOCATED DOWN to `busbar_substrate::proto` (it carries no dialect
// knowledge — only the `Value::String` passthrough rule — so the dialect writers name it there
// without reaching into `busbar-core`); re-exported here at its historical
// `busbar_core::proto::openai_family::tool_arguments_to_string` path so any in-core caller is unchanged.
pub use busbar_substrate::proto::tool_arguments_to_string;

// `tests/openai_family_tests.rs` RELOCATED to `busbar-llm/src/tests/proto/openai_family_tests.rs`
// it drives `protocol_for("openai")` — a witnessed codec item — so
// it moved to the plugin beside the codec it exercises.
