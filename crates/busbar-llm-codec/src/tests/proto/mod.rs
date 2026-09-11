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
//! neutral `crate::proto::…` / substrate re-export to its `busbar_core::` / `busbar_substrate_values::` home.

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

// The NEUTRAL proto atoms the suites reach bare via `super::*` — named at their canonical
// `busbar_substrate_values::proto` home (core merely re-exports each by identity), NOT a second witnessed
// copy (a glob of `busbar_substrate_values::proto::*` would collide with `crate::proto_codec::*` on
// `Protocol` &c.).
pub use busbar_substrate_values::proto::{
    array_stream_shim_key_for, array_stream_shim_keys, bearer_auth_headers, bearer_error_code,
    find_frame_terminator, known_protocols, lane_protocol_name, openai_context_length_prose_scan,
    parse_sse_frame, sse_event_type, streaming_content_types, strip_top_level_usage_member,
    write_sse_frame, IrError, BASE62_ALPHABET, HDR_AUTHORIZATION, SIGNAL_IR_PARSE, SSE_DONE_FRAME,
    SSE_DONE_SENTINEL,
};
// The registry LOOKUP against the boot-installed registry, at its own home: `decl_for`, the
// `registry` accessor and the OpenAI-family error helpers are the SUBSTRATE's (core re-exports each
// by identity), and the six dialect-name fixtures are THIS crate's own — `crate::proto_codec`
// declares them, and the glob above already brings them in.
pub use busbar_substrate_values::proto::{decl_for, registry};
// The one item still owned by core: the translation-boundary `max_tokens` fallback, which lives at
// `busbar_substrate::config::limits` — a crate this pure half may not name (it carries the egress
// engine). It resolves here through core's re-export until the limits family reaches the values
// crate.
pub use busbar_core::proto::DEFAULT_MAX_TOKENS;

// Substrate atoms the suites name bare (breaker signal + the neutral framing seam types).
pub use busbar_substrate_values::breaker::{CanonicalSignal, StatusClass};
pub use busbar_substrate_values::proto::{ArrayStreamFramer, DialectCodec};

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
#[path = "published_spec_shape_tests.rs"]
mod published_spec_shape_tests;
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
