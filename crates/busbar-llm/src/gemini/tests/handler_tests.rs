// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/handlers/gemini.rs`.

use super::*;

#[test]
fn protocol_name_is_gemini() {
    assert_eq!(GeminiRequestHandler.protocol_name(), "gemini");
}

#[test]
fn path_model_extracts_the_segment_before_the_last_colon() {
    let h = GeminiRequestHandler;
    assert_eq!(
        h.path_model("/v1beta/models/gemini-2.0-flash:generateContent"),
        Some("gemini-2.0-flash".to_string())
    );
    assert_eq!(
        h.path_model("/v1beta/models/gemini-1.5-pro:streamGenerateContent"),
        Some("gemini-1.5-pro".to_string())
    );
    // No `/models/` segment at all -> None.
    assert_eq!(h.path_model("/v1beta/foo:bar"), None);
    // No trailing `:action` -> None (rsplit_once finds no colon).
    assert_eq!(h.path_model("/v1beta/models/gemini-2.0-flash"), None);
    // Empty model segment (colon right after `/models/`) -> None, not Some("").
    assert_eq!(h.path_model("/v1beta/models/:generateContent"), None);
}

#[test]
fn path_base_reshapes_the_gemini_url_for_vertex() {
    let h = GeminiRequestHandler;
    let model = "gemini-2.0-flash";
    let ctx = |path_base| EgressCtx {
        operation: Operation::CHAT,
        model,
        stream: false,
        path_base,
    };
    // Default (no override): the native Generative Language layout is unchanged.
    assert_eq!(
        h.upstream_path(&ctx(None)),
        "/v1beta/models/gemini-2.0-flash:generateContent"
    );
    // With a Vertex path_base: the base segment is replaced; the `/{model}:verb` suffix survives,
    // so a `gemini`-protocol provider reaches the Vertex URL by config alone.
    let vbase = "/v1/projects/my-proj/locations/us-central1/publishers/google/models";
    assert_eq!(
            h.upstream_path(&ctx(Some(vbase))),
            "/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent"
        );
    // Embeddings keep their verb on the overridden base too.
    assert_eq!(
            h.upstream_path(&EgressCtx {
                operation: Operation::EMBEDDINGS,
                model,
                stream: false,
                path_base: Some(vbase),
            }),
            "/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.0-flash:embedContent"
        );
}

#[test]
fn transcription_read_request_captures_inline_audio() {
    // A generateContent body with a valid-base64 inline_data audio part → IR Transcription
    // carrying the audio blob (and any text part as the prompt).
    let audio_b64 = base64_encode(b"pretend-audio-bytes");
    let body = serde_json::to_vec(&json!({
        "contents": [{ "role": "user", "parts": [
            { "text": "please transcribe" },
            { "inline_data": { "mime_type": "audio/wav", "data": audio_b64 } },
        ]}],
    }))
    .unwrap();
    let ir = super::super::super::leaf_codec::transcription_read_request(
        "gemini",
        &body,
        "application/json",
    )
    .expect("valid inline audio body");
    let r = ir;
    let blob = r.audio.expect("audio captured");
    assert_eq!(blob.mime_type, "audio/wav");
    assert_eq!(r.prompt.as_deref(), Some("please transcribe"));
    match blob.payload {
        MediaPayload::B64(s) => assert_eq!(s, base64_encode(b"pretend-audio-bytes")),
        _ => panic!("expected B64 payload"),
    }
}

#[test]
fn transcription_read_request_invalid_base64_is_bad_request() {
    // Malformed base64 in inline_data.data must 400 at this trust boundary rather than
    // silently truncate to an empty audio body downstream.
    let body = serde_json::to_vec(&json!({
        "contents": [{ "role": "user", "parts": [
            { "inline_data": { "mime_type": "audio/wav", "data": "!!!not base64!!!" } },
        ]}],
    }))
    .unwrap();
    let err = super::super::super::leaf_codec::transcription_read_request(
        "gemini",
        &body,
        "application/json",
    )
    .expect_err("invalid base64 must reject");
    assert!(matches!(err, IngressReject::BadRequest(_)));
}

#[test]
fn transcription_read_response_captures_input_and_output_token_counts() {
    // input and output must map from DIFFERENT usageMetadata fields (promptTokenCount vs
    // candidatesTokenCount) - a dropped `output:` field would silently read back as 0
    // regardless of the real candidatesTokenCount.
    let wire = serde_json::to_vec(&json!({
        "candidates": [{ "content": { "parts": [{ "text": "hello" }] } }],
        "usageMetadata": { "promptTokenCount": 11, "candidatesTokenCount": 7 },
    }))
    .unwrap();
    let ir = super::super::super::leaf_codec::transcription_read_response("gemini", &wire)
        .expect("valid response");
    let r = ir;
    assert_eq!(r.text, "hello");
    let Some(busbar_core::billing::Billing::Tokens(usage)) = r.usage else {
        panic!("expected token usage");
    };
    assert_eq!(usage.input, 11);
    assert_eq!(usage.output, 7);
}

#[test]
fn transcription_read_request_without_inline_data_is_bad_request() {
    // No inline_data audio part → the specific "requires an inline_data audio part" 400.
    let body = serde_json::to_vec(&json!({
        "contents": [{ "role": "user", "parts": [{ "text": "just text" }]}],
    }))
    .unwrap();
    let err = super::super::super::leaf_codec::transcription_read_request(
        "gemini",
        &body,
        "application/json",
    )
    .expect_err("no audio part must reject");
    match err {
        IngressReject::BadRequest(m) => {
            assert!(m.contains("inline_data audio part"), "message was: {m}");
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn resolve_operation_audio_out_is_speech() {
    // responseModalities:["AUDIO"] on generateContent ⇒ Speech (TTS).
    let h = GeminiRequestHandler;
    let body = serde_json::to_vec(&json!({
        "contents": [{ "role": "user", "parts": [{ "text": "say hi" }]}],
        "generationConfig": { "responseModalities": ["AUDIO"] },
    }))
    .unwrap();
    assert_eq!(
        h.resolve_operation("/v1beta/models/gemini-x:generateContent", &body),
        Some(Operation::SPEECH),
    );
}

#[test]
fn resolve_operation_audio_in_is_transcription() {
    // An inline_data part with an audio/* mime ⇒ Transcription.
    let body = serde_json::to_vec(&json!({
        "contents": [{ "role": "user", "parts": [
            { "inline_data": { "mime_type": "audio/wav", "data": "AAAA" } },
        ]}],
    }))
    .unwrap();
    let h = GeminiRequestHandler;
    assert_eq!(
        h.resolve_operation("/v1beta/models/gemini-x:generateContent", &body),
        Some(Operation::TRANSCRIPTION),
    );
}

#[test]
fn resolve_operation_multiple_markers_prefers_speech_over_transcription() {
    // A body carrying BOTH responseModalities:AUDIO and an inline_data audio part exercises
    // the single-pass pre-filter's "any marker present" gate with more than one marker
    // actually present, then leaves the existing JSON-pointer logic (unchanged by this fix)
    // to disambiguate — which checks audio_out (Speech) before audio_in (Transcription), so
    // Speech wins. Locks in that the combined-scan pre-filter doesn't change which branch the
    // downstream classifier picks when multiple markers co-occur.
    let body = serde_json::to_vec(&json!({
        "contents": [{ "role": "user", "parts": [
            { "inline_data": { "mime_type": "audio/wav", "data": "AAAA" } },
        ]}],
        "generationConfig": { "responseModalities": ["AUDIO"] },
    }))
    .unwrap();
    let h = GeminiRequestHandler;
    assert_eq!(
        h.resolve_operation("/v1beta/models/gemini-x:generateContent", &body),
        Some(Operation::SPEECH),
    );
}

#[test]
fn resolve_operation_no_markers_at_all_is_chat() {
    // An empty-ish body with none of the three markers must fall through to Chat without
    // attempting a JSON parse of a body that isn't even valid JSON — this is the pre-filter's
    // "false || false || false" common case the single-pass scan exists to speed up.
    let h = GeminiRequestHandler;
    assert_eq!(
        h.resolve_operation(
            "/v1beta/models/gemini-x:generateContent",
            b"not json at all"
        ),
        Some(Operation::CHAT),
    );
}

#[test]
fn resolve_operation_plain_text_is_chat() {
    // A plain text chat body (no audio modalities, no inline_data) ⇒ Chat.
    let body = serde_json::to_vec(&json!({
        "contents": [{ "role": "user", "parts": [{ "text": "hello" }]}],
    }))
    .unwrap();
    let h = GeminiRequestHandler;
    assert_eq!(
        h.resolve_operation("/v1beta/models/gemini-x:generateContent", &body),
        Some(Operation::CHAT),
    );
}

#[test]
fn embeddings_read_request_captures_content_text() {
    // embedContent body → IR Embeddings carrying content.parts[].text.
    let body = serde_json::to_vec(&json!({
        "content": { "parts": [{ "text": "embed me" }] },
    }))
    .unwrap();
    let ir = super::super::super::leaf_codec::embeddings_read_request(
        "gemini",
        &body,
        "application/json",
    )
    .expect("valid embedContent body");
    let r = ir;
    assert_eq!(r.input, EmbInput::Text(vec!["embed me".to_string()]));
}

#[test]
fn embeddings_read_request_without_text_is_bad_request() {
    // No content.parts text ⇒ 400.
    let body = serde_json::to_vec(&json!({ "content": { "parts": [] } })).unwrap();
    let err = super::super::super::leaf_codec::embeddings_read_request(
        "gemini",
        &body,
        "application/json",
    )
    .expect_err("empty content must reject");
    assert!(matches!(err, IngressReject::BadRequest(_)));
}

#[test]
fn image_read_request_captures_prompt_and_count() {
    // Imagen :predict body → IR Image with instances[0].prompt and parameters.sampleCount.
    let body = serde_json::to_vec(&json!({
        "instances": [{ "prompt": "a fox" }],
        "parameters": { "sampleCount": 3 },
    }))
    .unwrap();
    let ir =
        super::super::super::leaf_codec::image_read_request("gemini", &body, "application/json")
            .expect("valid predict body");
    let r = ir;
    assert_eq!(r.prompt.as_deref(), Some("a fox"));
    assert_eq!(r.n, Some(3));
}

#[test]
fn image_read_request_captures_aspect_ratio() {
    let body = serde_json::to_vec(&json!({
        "instances": [{ "prompt": "a fox" }],
        "parameters": { "aspectRatio": "16:9" },
    }))
    .unwrap();
    let ir =
        super::super::super::leaf_codec::image_read_request("gemini", &body, "application/json")
            .expect("valid predict body");
    let r = ir;
    assert_eq!(r.aspect_ratio.as_deref(), Some("16:9"));
}

#[test]
fn image_read_response_captures_base64_image_bytes() {
    let wire = serde_json::to_vec(&json!({
        "predictions": [{ "bytesBase64Encoded": "cHJldGVuZC1pbWFnZQ==", "mimeType": "image/png" }],
    }))
    .unwrap();
    let ir = super::super::super::leaf_codec::image_read_response("gemini", &wire)
        .expect("valid predictions body");
    let r = ir;
    assert_eq!(r.images.len(), 1);
    assert_eq!(r.images[0].b64.as_deref(), Some("cHJldGVuZC1pbWFnZQ=="));
    assert_eq!(r.images[0].mime_type.as_deref(), Some("image/png"));
}

// FIND (money): a token-metered Gemini image response carries a `usageMetadata` token object; the
// reader must surface it so `billing()` token-meters the request instead of billing nothing. Fails
// pre-fix (usage left unset → `billing()` is None).
#[test]
fn image_response_with_usage_metadata_bills_tokens() {
    let wire = serde_json::to_vec(&json!({
        "predictions": [{ "bytesBase64Encoded": "AAAA", "mimeType": "image/png" }],
        "usageMetadata": { "promptTokenCount": 20, "candidatesTokenCount": 10 },
    }))
    .unwrap();
    let resp = super::read_image_response(&wire).unwrap();
    match resp.billing() {
        Some(busbar_core::billing::Billing::Tokens(t)) => {
            assert_eq!(t.input, 20);
            assert_eq!(t.output, 10);
        }
        other => panic!("token-metered Gemini image must token-bill, got {other:?}"),
    }
}

// FIND (money): an Imagen `:predict` response has NO `usageMetadata`; the reader must record a cost
// basis from the N returned images so `billing()` is `Images{count:N}`, not `None`. Fails pre-fix.
#[test]
fn image_response_without_usage_bills_per_image() {
    let wire = serde_json::to_vec(&json!({
        "predictions": [
            { "bytesBase64Encoded": "AAAA", "mimeType": "image/png" },
            { "bytesBase64Encoded": "BBBB", "mimeType": "image/png" },
        ],
    }))
    .unwrap();
    let resp = super::read_image_response(&wire).unwrap();
    match resp.billing() {
        Some(busbar_core::billing::Billing::Images { count, .. }) => assert_eq!(count, 2),
        other => panic!("per-image Imagen response must bill Images, got {other:?}"),
    }
}

#[test]
fn image_write_read_roundtrip_preserves_prompt() {
    // write_request emits instances[].prompt + parameters.sampleCount; read_request recovers.
    let req = crate::ir::image::ImageReq {
        prompt: Some("roundtrip fox".to_string()),
        n: Some(2),
        ..Default::default()
    };
    let wire = super::super::super::leaf_codec::image_write_request("gemini", &req);
    let back =
        super::super::super::leaf_codec::image_read_request("gemini", &wire, "application/json")
            .expect("emitted body reparses");
    let r = back;
    assert_eq!(r.prompt.as_deref(), Some("roundtrip fox"));
    assert_eq!(r.n, Some(2));
}

#[test]
fn embeddings_write_request_carries_dimensions_task_type_and_title() {
    // Gemini `:embedContent` supports these natively; dropping `outputDimensionality` returned
    // full-width vectors, and taskType/title steer retrieval quality.
    let ir = crate::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Text(vec!["hi".into()]),
        dimensions: Some(256),
        task_type: Some("RETRIEVAL_DOCUMENT".into()),
        title: Some("doc".into()),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::embeddings_write_request("gemini", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["outputDimensionality"], 256);
    assert_eq!(v["taskType"], "RETRIEVAL_DOCUMENT");
    assert_eq!(v["title"], "doc");
}

#[test]
fn embeddings_taps_usage_is_true() {
    // Token-metered same-protocol path: extract_usage must actually read this response's
    // usage object to bill the virtual key.
    assert!(EMB.taps_usage());
}

#[test]
fn embeddings_read_request_captures_task_type() {
    let body = serde_json::to_vec(&json!({
        "content": { "parts": [{ "text": "hi" }] },
        "taskType": "RETRIEVAL_QUERY",
    }))
    .unwrap();
    let ir = super::super::super::leaf_codec::embeddings_read_request(
        "gemini",
        &body,
        "application/json",
    )
    .expect("valid embedContent body");
    let r = ir;
    assert_eq!(r.task_type.as_deref(), Some("RETRIEVAL_QUERY"));
}

#[test]
fn embeddings_read_response_captures_vector_and_usage() {
    let wire = serde_json::to_vec(&json!({
        "embedding": { "values": [0.1, 0.2, 0.3] },
        "usageMetadata": { "promptTokenCount": 5 },
    }))
    .unwrap();
    let ir = super::super::super::leaf_codec::embeddings_read_response("gemini", &wire)
        .expect("valid embedContent response");
    let r = ir;
    assert_eq!(r.embeddings.len(), 1);
    match r.embeddings[0].vectors.get(&EncFmt::Float) {
        Some(VectorData::Float(v)) => assert_eq!(v, &[0.1_f32, 0.2, 0.3]),
        other => panic!("expected a Float vector, got {other:?}"),
    }
    assert_eq!(r.usage.expect("usage present").input, 5);
}

#[test]
fn embeddings_write_response_emits_the_float_vector() {
    let mut item = EmbeddingItem::default();
    item.vectors
        .insert(EncFmt::Float, VectorData::Float(vec![1.0, 2.0, 3.0]));
    let ir = EmbeddingsResp {
        embeddings: vec![item],
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::embeddings_write_response("gemini", &ir);
    let v: Value = serde_json::from_slice(&out.bytes).unwrap();
    assert_eq!(v["embedding"]["values"], json!([1.0, 2.0, 3.0]));
}

#[test]
fn embeddings_write_request_warns_on_dropped_non_text_input() {
    use busbar_core::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let ir = crate::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Images(vec!["data:image/png;base64,AA==".into()]),
        ..Default::default()
    };
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        super::super::super::leaf_codec::embeddings_write_request("gemini", &ir)
    });

    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["content"]["parts"][0]["text"], json!(""));

    assert!(
        cap.contains("dropping a non-text embeddings input"),
        "a dropped non-text embeddings input must warn: {:?}",
        cap.messages()
    );
}

#[test]
fn image_write_request_carries_aspect_ratio_and_person_generation() {
    // Imagen generation controls must ride under `parameters`; dropping them fell back to
    // Imagen's defaults (1:1 aspect, default person-generation policy).
    let ir = crate::ir::image::ImageReq {
        prompt: Some("a fox".into()),
        aspect_ratio: Some("16:9".into()),
        person_generation: Some("allow_adult".into()),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::image_write_request("gemini", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["parameters"]["aspectRatio"], "16:9");
    assert_eq!(v["parameters"]["personGeneration"], "allow_adult");
}

#[test]
fn speech_read_response_invalid_base64_is_malformed() {
    // A corrupt inline base64 audio payload must fail LOUD (CodecError) at this trust boundary
    // rather than reach the egress writer, where a decode failure would silently become an
    // empty 200 audio body.
    let body = br#"{"candidates":[{"content":{"parts":[{"inlineData":{"data":"!!!not-base64!!!","mimeType":"audio/L16;codec=pcm;rate=24000"}}]}}]}"#;
    let res = super::super::super::leaf_codec::speech_read_response("gemini", body);
    assert!(matches!(res, Err(CodecError::Malformed(_))));
}

#[test]
fn speech_read_response_valid_base64_returns_audio_blob() {
    // The valid-base64 case returns Ok with the audio blob carried as a B64 payload.
    let data = base64_encode(b"pretend-pcm-audio");
    let body = serde_json::to_vec(&json!({
        "candidates": [{ "content": { "parts": [{ "inlineData": {
            "data": data, "mimeType": "audio/L16;codec=pcm;rate=24000",
        } }] } }],
    }))
    .unwrap();
    let ir = super::super::super::leaf_codec::speech_read_response("gemini", &body)
        .expect("valid base64 must decode");
    let r = ir;
    let blob = r.audio.expect("audio blob present");
    match blob.payload {
        MediaPayload::B64(s) => assert_eq!(s, base64_encode(b"pretend-pcm-audio")),
        _ => panic!("expected B64 payload"),
    }
}

#[test]
fn speech_read_request_captures_prompt_text() {
    // A generateContent TTS body → IR Speech carrying the joined parts[].text as `input`.
    let body = serde_json::to_vec(&json!({
        "contents": [{ "parts": [{ "text": "hello" }] }],
        "generationConfig": { "responseModalities": ["AUDIO"] },
    }))
    .unwrap();
    let ir =
        super::super::super::leaf_codec::speech_read_request("gemini", &body, "application/json")
            .expect("valid speech body");
    let r = ir;
    assert_eq!(r.input, "hello");
}

#[test]
fn speech_write_request_prefixes_instructions_to_prompt_not_language_code() {
    // OpenAI-style free-text `instructions` steer Gemini TTS through the PROMPT, not the BCP-47
    // `speechConfig.languageCode` (the old, request-corrupting behavior). Assert the prefix lands
    // in parts[0].text as "<instr>: <input>" and no languageCode key is emitted.
    let ir = crate::ir::audio::SpeechReq {
        input: "hello".into(),
        voice: "Kore".into(),
        instructions: Some("speak cheerfully".into()),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::speech_write_request("gemini", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    let text = v
        .pointer("/contents/0/parts/0/text")
        .and_then(Value::as_str)
        .expect("prompt text present");
    assert_eq!(text, "speak cheerfully: hello");
    assert!(
        !serde_json::to_string(&v).unwrap().contains("languageCode"),
        "instructions must not corrupt speechConfig.languageCode: {v}"
    );
}

// FIND-2 (money): Gemini TTS response must be billed (non-None) so the synthesis is metered.
#[test]
fn gemini_speech_response_is_billed() {
    let resp = super::read_speech_response(b"\x00\x01raw-audio").unwrap();
    assert!(
        resp.billing().is_some(),
        "gemini TTS synthesis must be billed (non-None), got None"
    );
}

// FIND-3 (money): whisper-1 transcription bills audio DURATION. On an openai->gemini transcription
// hop the gemini response writer previously surfaced only `Billing::Tokens` and DROPPED a
// `Billing::Duration`. Assert the seconds survive the hop. Fails pre-fix (usageMetadata absent).
#[test]
fn openai_whisper_duration_carries_through_gemini_transcription_write() {
    // A `Billing::Duration` is exactly what the OpenAI whisper-1 transcription reader produces from
    // `usage.type == "duration"`; feed it to the gemini response writer and assert it is not dropped.
    let ir = TranscriptionResp {
        text: "hi".into(),
        usage: Some(busbar_core::billing::Billing::Duration { seconds: 12.5 }),
        ..Default::default()
    };
    let out = super::write_transcription_response(&ir).bytes;
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        v.pointer("/usageMetadata/audioDurationSeconds")
            .and_then(Value::as_f64),
        Some(12.5),
        "gemini transcription writer must carry the whisper duration through: {v}"
    );
}

// carryable-flatten #6: the gemini transcription writer REPLACED the caller's prompt with a fixed
// directive (while the IR screens `prompt` as forwarded — the screening gate said "sent" and the wire
// silently dropped it) and dropped `temperature`. Carry both. Fails pre-fix: no prompt part, no
// generationConfig.temperature. Round-trips through the reader (which skips the synthetic directive).
#[test]
fn gemini_transcription_forwards_caller_prompt_and_temperature() {
    let ir = crate::ir::audio::TranscriptionReq {
        model: "gemini-2.0-flash".into(),
        prompt: Some("Spell Busbar correctly.".into()),
        temperature: Some(0.5),
        audio: Some(busbar_core::media::MediaBlob {
            payload: busbar_core::media::MediaPayload::Bytes(bytes::Bytes::from_static(b"x")),
            mime_type: "audio/mpeg".into(),
            pcm: None,
        }),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::transcription_write_request("gemini", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    let parts = v
        .pointer("/contents/0/parts")
        .and_then(Value::as_array)
        .expect("parts array");
    assert!(
        parts
            .iter()
            .any(|p| p.get("text").and_then(Value::as_str) == Some("Spell Busbar correctly.")),
        "the caller's prompt must be forwarded as a text part, not replaced by the directive: {v}"
    );
    assert_eq!(
        v.pointer("/generationConfig/temperature")
            .and_then(Value::as_f64),
        Some(0.5),
        "temperature must be forwarded via generationConfig: {v}"
    );
    // And it round-trips: the reader recovers the caller prompt (skipping the synthetic directive).
    let back = super::super::super::leaf_codec::transcription_read_request(
        "gemini",
        &out,
        "application/json",
    )
    .expect("re-read");
    assert_eq!(back.prompt.as_deref(), Some("Spell Busbar correctly."));
    assert_eq!(back.temperature, Some(0.5));
}

// carryable-flatten #5: Gemini multi-speaker TTS (`multiSpeakerVoiceConfig.speakerVoiceConfigs[]`) is
// modelled by `SpeechReq::speakers` but the writer never read the field and the reader never parsed
// the wire — a two-speaker request collapsed to a single voice. Read + emit. Fails pre-fix.
#[test]
fn gemini_speech_two_speaker_request_round_trips() {
    let ir = crate::ir::audio::SpeechReq {
        model: "gemini-2.5-flash-preview-tts".into(),
        input: "Joe: Hi. Jane: Hello.".into(),
        speakers: vec![
            ("Joe".into(), "Kore".into()),
            ("Jane".into(), "Puck".into()),
        ],
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::speech_write_request("gemini", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    let configs = v
        .pointer("/generationConfig/speechConfig/multiSpeakerVoiceConfig/speakerVoiceConfigs")
        .and_then(Value::as_array)
        .expect("speakerVoiceConfigs must be emitted");
    assert_eq!(configs.len(), 2, "both speakers must be emitted: {v}");
    assert_eq!(configs[0]["speaker"], "Joe");
    assert_eq!(
        configs[1].pointer("/voiceConfig/prebuiltVoiceConfig/voiceName"),
        Some(&json!("Puck"))
    );
    let back =
        super::super::super::leaf_codec::speech_read_request("gemini", &out, "application/json")
            .expect("re-read");
    assert_eq!(
        back.speakers,
        vec![
            ("Joe".to_string(), "Kore".to_string()),
            ("Jane".to_string(), "Puck".to_string())
        ]
    );
}
