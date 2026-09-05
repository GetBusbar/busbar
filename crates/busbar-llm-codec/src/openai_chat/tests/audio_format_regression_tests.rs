// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regression net: OpenAI Chat audio egress must map an audio mime onto the CLOSED
//! `input_audio.format` enum (`{wav, mp3}`, openai-openapi
//! `ChatCompletionRequestMessageContentPartAudio`), not emit the raw mime subtype. The old
//! `media_type.rsplit('/')` produced `format:"mpeg"` for `audio/mpeg`, which the API 400-rejects.

use super::*;
use busbar_substrate_values::testkit::warn_capture::WarnCapture;
use tracing_subscriber::layer::SubscriberExt as _;

fn audio_req(media_type: &str) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Audio,
                source: crate::ir::IrImageSource::Base64 {
                    media_type: media_type.to_string(),
                    data: "AAAA".to_string(),
                },
                name: None,
                cache_control: None,
            }],
        }],
        ..Default::default()
    }
}

fn input_audio_part(out: &serde_json::Value) -> Option<serde_json::Value> {
    out["messages"]
        .as_array()?
        .last()?
        .get("content")?
        .as_array()?
        .iter()
        .find(|p| p.get("type").and_then(|t| t.as_str()) == Some("input_audio"))
        .cloned()
}

#[test]
fn gemini_audio_mpeg_to_openai_chat_emits_mp3_format() {
    let out = OpenAiWriter.write_request(&audio_req("audio/mpeg"));
    let part = input_audio_part(&out).expect("an input_audio part");
    assert_eq!(
        part["input_audio"]["format"], "mp3",
        "audio/mpeg must map to the `mp3` enum token, not the raw `mpeg` subtype: {out}"
    );
}

#[test]
fn audio_wav_aliases_map_to_wav_format() {
    for mime in ["audio/wav", "audio/x-wav", "audio/wave"] {
        let out = OpenAiWriter.write_request(&audio_req(mime));
        let part = input_audio_part(&out).unwrap_or_else(|| panic!("input_audio for {mime}"));
        assert_eq!(
            part["input_audio"]["format"], "wav",
            "{mime} must map to `wav`"
        );
    }
}

#[test]
fn unsupported_audio_mime_dropped_with_warn_not_invalid_format() {
    // `audio/ogg` has no `{wav, mp3}` representation, so no input_audio part is emitted (emitting
    // `format:"ogg"` would 400) and the drop is observable.
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        OpenAiWriter.write_request(&audio_req("audio/ogg"))
    });
    assert!(
        input_audio_part(&out).is_none(),
        "an unrepresentable audio mime must not emit an off-enum format: {out}"
    );
    assert!(
        cap.contains("dropping audio attachment on OpenAI Chat egress"),
        "the drop must warn: {:?}",
        cap.messages()
    );
}
