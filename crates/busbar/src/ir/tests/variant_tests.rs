// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/variant.rs`.

use super::*;

#[test]
fn wants_stream_true_only_for_chat_and_audio() {
    assert!(!IrReq::Embeddings(Default::default()).wants_stream());
    assert!(!IrReq::Moderation(Default::default()).wants_stream());
    assert!(!IrReq::Image(Default::default()).wants_stream());
    let s = SpeechReq {
        stream: true,
        ..Default::default()
    };
    assert!(IrReq::Speech(s).wants_stream());
    assert!(!IrReq::Speech(SpeechReq::default()).wants_stream());
}

#[test]
fn usage_projects_per_operation() {
    // moderation → flat
    assert!(matches!(
        IrResp::Moderation(Default::default()).usage(),
        Some(Billing::Flat)
    ));
    // embeddings → tokens
    let e = EmbeddingsResp {
        usage: Some(TokenUsage {
            input: 5,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(matches!(
        IrResp::Embeddings(e).usage(),
        Some(Billing::Tokens(_))
    ));
    // image with no usage/cost_basis → None
    assert!(IrResp::Image(Default::default()).usage().is_none());
}

#[test]
fn token_usage_maps_token_meter_and_none_for_flat() {
    // A token-metered embeddings response projects its input tokens into an IrUsage.
    let e = EmbeddingsResp {
        usage: Some(TokenUsage {
            input: 12,
            output: 0,
            ..Default::default()
        }),
        ..Default::default()
    };
    let tu = IrResp::Embeddings(e)
        .token_usage()
        .expect("token-metered op yields Some");
    assert_eq!(tu.input_tokens, 12);
    // A flat-metered moderation response has no token usage.
    assert!(IrResp::Moderation(Default::default())
        .token_usage()
        .is_none());
}

#[test]
fn operation_tag_matches_variant_both_directions() {
    assert_eq!(
        IrReq::Image(Default::default()).operation(),
        Operation::Image
    );
    assert_eq!(
        IrResp::Transcription(Default::default()).operation(),
        Operation::Transcription
    );
}
