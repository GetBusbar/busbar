// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/audio.rs`.

use super::*;
use crate::media::{MediaBlob, MediaPayload};

#[test]
fn transcription_translation_folds_via_target_language() {
    let transcribe = TranscriptionReq {
        model: "whisper-1".into(),
        ..Default::default()
    };
    assert!(
        transcribe.target_language.is_none(),
        "no target = transcribe"
    );
    let translate = TranscriptionReq {
        model: "whisper-1".into(),
        target_language: Some("en".into()),
        ..Default::default()
    };
    assert_eq!(
        translate.target_language.as_deref(),
        Some("en"),
        "target set = translate"
    );
}

#[test]
fn transcription_billing_is_model_dependent() {
    let whisper = TranscriptionResp {
        text: "hi".into(),
        usage: Some(Billing::Duration { seconds: 3.2 }),
        ..Default::default()
    };
    assert!(matches!(whisper.billing(), Some(Billing::Duration { .. })));
}

#[test]
fn speech_carries_binary_out_and_char_or_token_billing() {
    let resp = SpeechResp {
        audio: Some(MediaBlob {
            payload: MediaPayload::Bytes(bytes::Bytes::from_static(b"\xff\xfb")),
            mime_type: "audio/mpeg".into(),
            pcm: None,
        }),
        usage: Some(Billing::Characters { count: 11 }),
        ..Default::default()
    };
    assert!(resp.audio.is_some());
    assert!(matches!(
        resp.billing(),
        Some(Billing::Characters { count: 11 })
    ));
}
