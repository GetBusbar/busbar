// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE THINGS A SESSION IS CONFIGURED AND CORRELATED BY — the tool-call id every reply is matched
//! on, the VAD numbers an unstated config falls back to, and the one sentinel that means "no
//! ceiling".
//!
//! Three clusters of mutation survivors, one theme: values that are read on every session and
//! asserted on none.
//!
//! `IrDuplexTool::call_id` could return `""` or a constant for EVERY variant. That accessor is the
//! raw dialect id the wire correlates on — the header on the type says the stateless writer
//! re-frames `function_call_output` from it without consulting the `CallRef` map. An accessor that
//! answers the empty string does not fail loudly: it produces a well-formed tool result addressed
//! to a call nobody opened. On the governed path that is a legal reply the reply table cannot
//! match, and an unmatched reply is a refused one — the model waits for a result that will never
//! correlate, and the turn simply stops.
//!
//! `default_threshold`, `default_prefix_padding_ms`, `default_silence_duration_ms` and
//! `default_true` are what a `turn_detection` object that omits a knob actually gets. Mutation
//! could return `0.0`, `1.0`, `-1.0`, `0`, `1` and `false` respectively, all green. A VAD threshold
//! of `0.0` treats silence as speech and a threshold of `1.0` never hears anyone; a silence window
//! of `0` ends a turn on the first sample. None of those is a subtle degradation — each is a
//! session that does not work — and none was asserted.

use crate::ir::config::MaxOutputTokens;
use crate::ir::control::IrVad;
use crate::ir::tool::{CallRef, IrDuplexTool};
use bytes::Bytes;

/// The four tool variants, each carrying the SAME call id, so a single accessor that answered a
/// constant would still have to answer the right constant four times — and one that answered `""`
/// fails on the first.
fn every_variant_with(call_id: &str) -> Vec<IrDuplexTool> {
    vec![
        IrDuplexTool::CallOpen {
            call_ref: CallRef(7),
            call_id: call_id.to_string(),
            name: "lookup".to_string(),
        },
        IrDuplexTool::CallArgs {
            call_ref: CallRef(7),
            call_id: call_id.to_string(),
            json_delta: Bytes::from_static(b"{\"a\":1}"),
        },
        IrDuplexTool::CallClose {
            call_ref: CallRef(7),
            call_id: call_id.to_string(),
        },
        IrDuplexTool::CallResult {
            call_ref: CallRef(7),
            call_id: call_id.to_string(),
            name: "lookup".to_string(),
            output: Bytes::from_static(b"{\"ok\":true}"),
        },
    ]
}

/// EVERY variant reports the dialect id it was built with. This is the accessor a stateless writer
/// re-frames a tool result from, so a variant that lost its arm addresses the result to the wrong
/// call — or, with the empty-string mutant, to no call at all.
#[test]
fn every_tool_variant_reports_the_dialect_call_id_it_carries() {
    for tool in every_variant_with("call_abc123") {
        assert_eq!(
            tool.call_id(),
            "call_abc123",
            "{tool:?} did not report the dialect id it was built with"
        );
    }
}

/// The accessor is not a constant: two different ids give two different answers. This is what
/// separates a real accessor from `"xyzzy"`, and it is the property the correlation depends on —
/// two concurrent calls in one session differ ONLY by this string.
#[test]
fn two_calls_in_one_session_are_told_apart_by_their_dialect_ids() {
    let first = every_variant_with("call_first");
    let second = every_variant_with("call_second");
    for (a, b) in first.iter().zip(second.iter()) {
        assert_ne!(
            a.call_id(),
            b.call_id(),
            "two distinct calls report the same dialect id — a reply cannot be routed to either"
        );
    }
    for tool in &first {
        assert!(
            !tool.call_id().is_empty(),
            "an empty dialect id addresses a tool result to a call nobody opened; on a governed \
             session the reply table cannot match it, so a LEGAL reply is refused and the turn stops"
        );
    }
}

/// The correlation handle and the dialect id are DIFFERENT things and both survive. The type's own
/// header says the raw id is kept precisely so the writer need not consult the `CallRef` map; if
/// the accessor collapsed to the ref's rendering, that independence would be gone.
#[test]
fn the_correlation_handle_and_the_dialect_id_are_carried_independently() {
    for tool in every_variant_with("call_abc123") {
        assert_eq!(tool.call_ref(), CallRef(7));
        assert_ne!(
            tool.call_id(),
            "7",
            "the dialect id collapsed to the correlation handle's rendering"
        );
    }
}

/// THE VAD DEFAULTS AN OMITTED KNOB ACTUALLY GETS, reached the only way a real session reaches
/// them: by deserializing a `turn_detection` object that omits them.
///
/// Written as a wire fixture rather than by calling the `default_*` functions, because those are
/// private serde glue and because what matters is the value a REAL config lands on.
#[test]
fn a_server_vad_config_that_omits_its_knobs_lands_on_usable_defaults() {
    let vad: IrVad = serde_json::from_str(r#"{"type":"server_vad"}"#).expect("deserializes");
    let IrVad::ServerVad {
        threshold,
        prefix_padding_ms,
        silence_duration_ms,
        ..
    } = vad
    else {
        panic!("expected server_vad, got {vad:?}");
    };

    // 0.0 treats silence as speech (the model is interrupted by nothing at all); 1.0 never trips,
    // so the caller is never heard. Both are sessions that do not work, and both were reachable.
    assert!(
        threshold > 0.0 && threshold < 1.0,
        "the default VAD threshold is {threshold}: at 0.0 silence reads as speech, at 1.0 nobody \
         is ever heard"
    );
    assert!(
        (threshold - 0.5).abs() < f32::EPSILON,
        "the default VAD threshold moved from 0.5 to {threshold}"
    );

    // A zero silence window ends a turn on the first quiet sample — the caller is cut off mid-word.
    assert!(
        silence_duration_ms > 0,
        "a default silence window of 0 ms ends a turn on the first quiet sample"
    );
    assert_eq!(silence_duration_ms, 200);

    // Zero prefix padding clips the start of every utterance, which is where the first phoneme is.
    assert!(
        prefix_padding_ms > 0,
        "a default prefix padding of 0 ms clips the opening of every utterance"
    );
    assert_eq!(prefix_padding_ms, 300);
}

/// The boolean knob's default is `true`, and it is reached the same way. Mutation could flip it to
/// `false` silently; a default that turns a behaviour OFF for every config that does not mention it
/// is the kind of change that ships and is noticed weeks later.
#[test]
fn the_boolean_turn_detection_knob_defaults_to_on() {
    let stated: IrVad =
        serde_json::from_str(r#"{"type":"server_vad","create_response":false}"#).expect("ok");
    let omitted: IrVad = serde_json::from_str(r#"{"type":"server_vad"}"#).expect("ok");
    let (
        IrVad::ServerVad {
            create_response: stated_flag,
            ..
        },
        IrVad::ServerVad {
            create_response: omitted_flag,
            ..
        },
    ) = (&stated, &omitted)
    else {
        panic!("expected two server_vad configs");
    };
    assert!(
        *omitted_flag,
        "an omitted create_response defaulted to off, silently disabling response creation for \
         every config that does not mention it"
    );
    assert!(
        !*stated_flag,
        "a STATED false was overwritten by the default"
    );
}

/// `"inf"` IS A SENTINEL, NOT A PREFIX AND NOT ANY STRING. Mutation replaced the match guard
/// `s == "inf"` with `true`, which makes EVERY string deserialize to "no ceiling" — including a
/// typo, including `"0"`, including a string that was meant to be a number. A max-output ceiling
/// that silently becomes unlimited is a metering surprise, not a parse error.
#[test]
fn only_the_exact_inf_sentinel_means_no_ceiling() {
    assert_eq!(
        serde_json::from_str::<MaxOutputTokens>(r#""inf""#).expect("the sentinel parses"),
        MaxOutputTokens::Inf
    );
    for not_the_sentinel in [r#""infinity""#, r#""INF""#, r#""in""#, r#""0""#, r#""""#] {
        assert!(
            serde_json::from_str::<MaxOutputTokens>(not_the_sentinel).is_err(),
            "{not_the_sentinel} was accepted as the no-ceiling sentinel — a ceiling silently \
             became unlimited"
        );
    }
}

/// A number is a limit, and a number that cannot be a `u32` is refused rather than truncated. A
/// silently truncated ceiling is a ceiling nobody set.
#[test]
fn a_numeric_ceiling_is_a_limit_and_an_out_of_range_one_is_refused() {
    assert_eq!(
        serde_json::from_str::<MaxOutputTokens>("4096").expect("parses"),
        MaxOutputTokens::Limit(4096)
    );
    assert!(
        serde_json::from_str::<MaxOutputTokens>("99999999999").is_err(),
        "a value beyond u32 was accepted, so the ceiling that took effect is not the one written"
    );
    assert!(serde_json::from_str::<MaxOutputTokens>("null").is_err());
}
