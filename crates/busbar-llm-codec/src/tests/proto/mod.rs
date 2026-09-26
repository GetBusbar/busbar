// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CODEC/IR TEST SUITES, RELOCATED HERE from `busbar-core`'s `proto/tests/*`. They NAME DIALECTS
//! and the concrete wire codecs (`Protocol`/`protocol_for`/
//! `StreamTranslate`/the six dialect modules), which a neutral crate's tests must not — so they live
//! beside the types they exercise, in the LLM plugin, linking `busbar-core` as a `test-support`
//! dev-dependency for the neutral seams (registry accessors, `proxy`/`handlers`/`egress_auth`,
//! substrate atoms). Every assertion is BYTE-IDENTICAL to the pre-relocation suite: these are the
//! detection / translate-parity / streaming / IR / round-trip goldens.
//!
//! This module reconstructs the `crate::proto` prelude surface the suites were written against (they
//! open with `use super::*`), so `super::*` inside each relocated file resolves the codec vocabulary
//! HERE — `Protocol`, `protocol_for`, the dialect modules, the stream translator, the IR types — the
//! same names it saw when they were `mod`ules of `busbar-core`'s `proto`. Fully-qualified paths in
//! the suites were repointed mechanically: `crate::proto::{dialect}` → `crate::{dialect}`,
//! `crate::proto::{proto_codec,proto_stream}` → `crate::{proto_codec,proto_stream}`, and every
//! neutral `crate::proto::…` name to its home: a contract shape to `busbar_contract::`, a dialect
//! helper to this plane's `crate::dialect`, a registry read to the host (`busbar_kernel::`).

#![allow(unused_imports)]

// The witnessed codec surface, at this crate's OWN paths (production `busbar-llm`), so `super::*`
// resolves the dialect vocabulary the suites use bare. (`pub(crate)` throughout: these re-exports
// serve the child suite modules within THIS crate; several source modules are themselves
// `pub(crate)`, so a `pub` re-export would be an over-export error.)
pub use crate::proto_codec::*;
pub use crate::proto_stream::*;
pub use crate::{anthropic, bedrock, cohere, gemini, openai_chat, openai_responses};
pub use crate::{
    chat_handle, ir, ir_encode, leaf_codec, leaf_handles, openai_annotations, synth_rng, usage_tail,
};

// The dialect codec structs the suites construct bare (they were bare-imported into `crate::proto`
// for exactly this surface, pre-relocation — see the `#[cfg(test)] use anthropic::{…}` block that
// remains in core's `proto/mod.rs` for the witness build).
pub use crate::anthropic::{synth_anthropic_request_id, AnthropicReader, AnthropicWriter};
// `pub(crate)` in its home module, so it is re-exported at the same visibility here (a `pub`
// re-export of a crate-visible item is an over-export error).
pub(crate) use crate::anthropic::anthropic_writer;
pub use crate::bedrock::{BedrockReader, BedrockWriter};
pub use crate::cohere::{CohereReader, CohereWriter};
pub use crate::gemini::{GeminiJsonArrayFramer, GeminiReader, GeminiWriter};
pub use crate::openai_chat::{OpenAiReader, OpenAiWriter};
// Same `pub(crate)` fresh-value helper as `anthropic_writer`, for the same lint reason.
pub(crate) use crate::openai_chat::openai_writer;
pub use crate::openai_responses::{ResponsesReader, ResponsesWriter};

// The neutral proto atoms the suites reach bare via `super::*`: the dialect helpers at this plane's
// own home, the frame-boundary scan and the IR-parse vocabulary at the contract.
pub use crate::dialect::{
    bearer_error_code, context_length_prose_scan, parse_sse_frame, sse_event_type,
    strip_top_level_usage_member, write_sse_frame, BASE62_ALPHABET, HDR_AUTHORIZATION,
    SSE_DONE_FRAME, SSE_DONE_SENTINEL,
};
pub use busbar_contract::protocol::{find_frame_terminator, IrError, SIGNAL_IR_PARSE};
// The by-name views the suites read, over THIS PLANE'S OWN declarations (#83a SD-3: the codec's
// tests prove the codec's own seam and never reach the host). `decl_for` is the plane's own lookup;
// the list views are the plane's declaration table read in its declared order, which is the order
// the host's fold reports it in (the host tests the fold itself).
pub use crate::decl_of as decl_for;

/// Every protocol this plane declares, in declaration order.
pub fn known_protocols() -> &'static [&'static str] {
    static NAMES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| crate::DECLS.iter().map(|d| d.name).collect())
}

/// The distinct streaming content types this plane's dialects declare, sorted.
pub fn streaming_content_types() -> &'static [&'static str] {
    static TYPES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    TYPES.get_or_init(|| {
        let mut out: Vec<&'static str> = crate::DECLS
            .iter()
            .filter_map(|d| d.streaming_content_type)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    })
}

/// The array-stream shim keys this plane's dialects declare, in declaration order.
pub fn array_stream_shim_keys() -> &'static [&'static str] {
    static KEYS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        crate::DECLS
            .iter()
            .filter_map(|d| d.array_stream_shim_key)
            .collect()
    })
}

/// The global `max_tokens` fallback a caller hands the egress preparation when neither the request
/// nor the lane names one (the host's configured default, 4096 unless an operator sets another).
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

// Substrate atoms the suites name bare (breaker signal + the neutral framing seam types).
pub use busbar_contract::protocol::{ArrayStreamFramer, DialectCodec};
pub use busbar_contract::upstream::{CanonicalSignal, StatusClass};

#[path = "adversarial_tests.rs"]
mod adversarial_tests;
#[path = "billing_parity_tests.rs"]
mod billing_parity_tests;
#[path = "citation_stream_carriage_tests.rs"]
mod citation_stream_carriage_tests;
#[path = "context_length_tests.rs"]
mod context_length_tests;
#[path = "cross_protocol_extra_tests.rs"]
mod cross_protocol_extra_tests;
#[path = "declared_scheme_tests.rs"]
mod declared_scheme_tests;
#[path = "gemini_integration_tests.rs"]
mod gemini_integration_tests;
#[path = "gemini_tests.rs"]
mod gemini_tests;
#[path = "hook_ir_differential_tests.rs"]
mod hook_ir_differential_tests;
#[path = "image_source_matrix_tests.rs"]
mod image_source_matrix_tests;
#[path = "max_tokens_precedence_tests.rs"]
mod max_tokens_precedence_tests;
#[path = "openai_family_tests.rs"]
mod openai_family_tests;
#[path = "phase1_5_relocated_tests.rs"]
mod phase1_5_relocated_tests;
#[path = "published_spec_shape_tests.rs"]
mod published_spec_shape_tests;
#[path = "response_format_matrix_tests.rs"]
mod response_format_matrix_tests;
#[path = "roundtrip_fidelity_tests.rs"]
mod roundtrip_fidelity_tests;
#[path = "same_proto_fidelity_tests.rs"]
mod same_proto_fidelity_tests;
#[path = "stop_reason_matrix_tests.rs"]
mod stop_reason_matrix_tests;
#[path = "stream_fanout_tests.rs"]
mod stream_fanout_tests;
#[path = "stream_identity_tests.rs"]
mod stream_identity_tests;
#[path = "stream_tap_usage_tests.rs"]
mod stream_tap_usage_tests;
#[path = "stream_translate_tests.rs"]
mod stream_translate_tests;
#[path = "tests.rs"]
mod tests;
#[path = "translate_parity_cross_pairs_tests.rs"]
mod translate_parity_cross_pairs_tests;
#[path = "translate_parity_golden_tests.rs"]
mod translate_parity_golden_tests;
