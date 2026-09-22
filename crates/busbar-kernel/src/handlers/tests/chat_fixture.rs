// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE TEST-BINARY CHAT FIXTURE — a const `OpDispatch` over the real `busbar-llm` chat cell
//! (`busbar_llm::chat_handle::ChatOperation`), named HERE in a `tests/` file the neutral-purity lint
//! excludes so the neutral source (`handlers/mod.rs`) spells no protocol crate.
//!
//! It replaces the deleted `#[path]` witness re-include of `chat_handle.rs` into core: `ChatOperation`
//! lives in the plugin because it names the concrete chat IR, and core's own test binary now links the
//! plugin as a dev-dependency and constructs the cell directly. Re-exported at `crate::handlers::CHAT`
//! for the proxy/engine test suites that hold a chat dispatch cell by value.

/// A const chat dispatch cell over the real LLM chat codec — the openai-shaped `ChatOperation`, framed
/// on HTTP, byte-identical to what the witnessed `crate::proto::chat_handle::ChatOperation("openai")`
/// produced before the dialect extraction completed.
pub(crate) const CHAT: super::Op = super::frame(
    crate::transport::Transport::Http,
    crate::operation::Operation::CHAT,
    &busbar_llm::chat_handle::ChatOperation("openai"),
);
