// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE TEST-BINARY STREAM-TRANSLATOR FACTORY FIXTURE — forwards `new_stream_translator` straight
//! to the real `busbar_llm::new_stream_translator`, named HERE in a `tests/` file the neutral-purity
//! lint excludes so the neutral source (`proto/stream_translator.rs`) spells no protocol crate.
//!
//! It replaces the deleted `#[path]` witness re-include of `proto_stream.rs` into core: the concrete
//! `StreamTranslate` names the concrete LLM stream IR, so it lives in the plugin; core's own test
//! binary links the plugin as a dev-dependency and reaches its registry-resolved factory directly,
//! byte-identical to what the netted `super::stream::new_stream_translator` returned before.

use busbar_substrate::proto::StreamTranslator;

/// Forward to the LLM plugin's registry-resolved streaming-translator factory. Same signature the
/// production `install_stream_translator_factory` pointer has, so the routing is byte-identical.
pub(crate) fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    busbar_llm::proto_stream::new_stream_translator(ingress, egress, is_sse)
}
