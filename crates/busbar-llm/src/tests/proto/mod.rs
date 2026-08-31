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
//! neutral `crate::proto::…` / substrate re-export to its `busbar_core::` / `busbar_substrate::` home.

#![allow(unused_imports)]

// The witnessed codec surface, at this crate's OWN paths (production `busbar-llm`), so `super::*`
// resolves the dialect vocabulary the suites use bare. (`pub(crate)` throughout: these re-exports
// serve the child suite modules within THIS crate; several source modules are themselves
// `pub(crate)`, so a `pub` re-export would be an over-export error.)
pub(crate) use crate::proto_codec::*;
pub(crate) use crate::proto_stream::*;
pub(crate) use crate::{anthropic, bedrock, cohere, gemini, openai_chat, openai_responses};
pub(crate) use crate::{
    chat_handle, ir, ir_encode, leaf_codec, leaf_handles, openai_annotations, synth_rng, usage_tail,
};

// The dialect codec structs the suites construct bare (they were bare-imported into `crate::proto`
// for exactly this surface, pre-relocation — see the `#[cfg(test)] use anthropic::{…}` block that
// remains in core's `proto/mod.rs` for the witness build).
pub(crate) use crate::anthropic::{synth_anthropic_request_id, AnthropicReader, AnthropicWriter};
pub(crate) use crate::bedrock::{BedrockReader, BedrockWriter};
pub(crate) use crate::cohere::{CohereReader, CohereWriter};
pub(crate) use crate::gemini::{GeminiJsonArrayFramer, GeminiReader, GeminiWriter};
pub(crate) use crate::openai_chat::{OpenAiReader, OpenAiWriter};
pub(crate) use crate::openai_responses::{ResponsesReader, ResponsesWriter};

// The NEUTRAL registry accessors + proto atoms the suites reach bare via `super::*` — reached
// through `busbar-core`'s public (`test-support`-widened) surface, NOT a second witnessed copy (a
// glob of `busbar_core::proto::*` would collide with `crate::proto_codec::*` on `Protocol` &c.).
pub(crate) use busbar_core::proto::{
    array_stream_shim_key_for, array_stream_shim_keys, bearer_auth_headers, decl_for,
    find_frame_terminator, known_protocols, lane_protocol_name, parse_sse_frame, sse_event_type,
    streaming_content_types, strip_top_level_usage_member, write_sse_frame, IrError,
    BASE62_ALPHABET, DEFAULT_MAX_TOKENS, HDR_AUTHORIZATION, PROTO_ANTHROPIC, PROTO_BEDROCK,
    PROTO_COHERE, PROTO_GEMINI, PROTO_OPENAI, PROTO_RESPONSES, SIGNAL_IR_PARSE, SSE_DONE_FRAME,
    SSE_DONE_SENTINEL,
};
pub(crate) use busbar_core::proto::{openai_family, registry};
// `openai_family_tests.rs` was `mod tests` inside `openai_family.rs`, so its `super::` reached these
// two free fns; re-exported here so that `super::` (now this prelude) still resolves them.
pub(crate) use busbar_core::proto::openai_family::{
    bearer_error_code, openai_context_length_prose_scan,
};

// Substrate atoms the suites name bare (breaker signal + the neutral framing seam types).
pub(crate) use busbar_substrate::breaker::{CanonicalSignal, StatusClass};
pub(crate) use busbar_substrate::proto::{ArrayStreamFramer, DialectCodec};

#[path = "adversarial_tests.rs"]
mod adversarial_tests;
#[path = "billing_parity_tests.rs"]
mod billing_parity_tests;
#[path = "context_length_tests.rs"]
mod context_length_tests;
#[path = "cross_protocol_extra_tests.rs"]
mod cross_protocol_extra_tests;
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
#[path = "registry_tests.rs"]
mod registry_tests;
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
