// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/audio.rs`.

use super::*;
use busbar_core::media::{MediaBlob, MediaPayload};

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

// ── IrFacts projection (close-non-chat-gate-blindness) ───────────────────────────────────────────

use busbar_core::ir::facts::{ContentItem, IrFacts, OPAQUE_CONTENT_MARKER};
use busbar_core::operation::Operation;

fn screened(items: &[ContentItem<'_>]) -> Vec<String> {
    items
        .iter()
        .map(|i| i.screenable_text().into_owned())
        .collect()
}

#[test]
fn transcription_projects_prompt_as_text_and_audio_as_opaque() {
    let req = TranscriptionReq {
        audio: Some(busbar_core::media::MediaBlob {
            payload: busbar_core::media::MediaPayload::B64("AAAA".into()),
            mime_type: "audio/mp3".into(),
            pcm: None,
        }),
        model: "whisper-1".into(),
        prompt: Some("proper nouns to expect".into()),
        stream: true,
        ..Default::default()
    };
    assert_eq!(IrFacts::verb(&req), Operation::TRANSCRIPTION);
    assert!(IrFacts::wants_stream(&req));
    let items = req.content();
    // The audio blob is opaque (present-but-unscreenable); the caller `prompt` is screenable text —
    // reachable only through the byte-aware hook seam (FATAL-1), and it must not read as empty.
    assert!(matches!(items[0], ContentItem::Opaque { .. }));
    assert_eq!(items[0].screenable_text(), OPAQUE_CONTENT_MARKER);
    assert!(screened(&items)
        .iter()
        .any(|t| t == "proper nouns to expect"));
}

#[test]
fn speech_projects_input_instructions_and_speaker_names() {
    let req = SpeechReq {
        input: "hello world".into(),
        model: "gpt-4o-mini-tts".into(),
        voice: "alloy".into(),
        instructions: Some("speak cheerfully".into()),
        speakers: vec![("Dr. Smith".into(), "verse".into())],
        stream: false,
        ..Default::default()
    };
    assert_eq!(IrFacts::verb(&req), Operation::SPEECH);
    let screened = screened(&req.content());
    // FATAL-2: `instructions` is caller free-text forwarded verbatim; it must be screenable.
    assert!(screened.iter().any(|t| t == "hello world"));
    assert!(screened.iter().any(|t| t == "speak cheerfully"));
    assert!(screened.iter().any(|t| t == "Dr. Smith"));
    // The voice id is a provider knob, not caller free-text, and stays out of the gate view.
    assert!(!screened.iter().any(|t| t == "verse"));
}

#[test]
fn speech_instructions_alone_are_screened() {
    // Forcing-function witness for FATAL-2: a request whose ONLY extra field is `instructions`
    // surfaces it — a projection that dropped the field would fail here.
    let req = SpeechReq {
        input: "x".into(),
        instructions: Some("SECRET-INSTRUCTIONS".into()),
        ..Default::default()
    };
    assert!(screened(&req.content())
        .iter()
        .any(|t| t == "SECRET-INSTRUCTIONS"));
}
