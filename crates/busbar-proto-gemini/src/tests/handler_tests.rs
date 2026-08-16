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
    let ir = TRANSCRIPTION
        .read_request(&body, "application/json")
        .expect("valid inline audio body");
    let IrReq::Transcription(r) = ir else {
        panic!("expected IrReq::Transcription");
    };
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
    let err = TRANSCRIPTION
        .read_request(&body, "application/json")
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
    let ir = TRANSCRIPTION.read_response(&wire).expect("valid response");
    let IrResp::Transcription(r) = ir else {
        panic!("expected IrResp::Transcription");
    };
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
    let err = TRANSCRIPTION
        .read_request(&body, "application/json")
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
    let ir = EMB
        .read_request(&body, "application/json")
        .expect("valid embedContent body");
    let IrReq::Embeddings(r) = ir else {
        panic!("expected IrReq::Embeddings");
    };
    assert_eq!(r.input, EmbInput::Text(vec!["embed me".to_string()]));
}

#[test]
fn embeddings_read_request_without_text_is_bad_request() {
    // No content.parts text ⇒ 400.
    let body = serde_json::to_vec(&json!({ "content": { "parts": [] } })).unwrap();
    let err = EMB
        .read_request(&body, "application/json")
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
    let ir = IMG
        .read_request(&body, "application/json")
        .expect("valid predict body");
    let IrReq::Image(r) = ir else {
        panic!("expected IrReq::Image");
    };
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
    let ir = IMG
        .read_request(&body, "application/json")
        .expect("valid predict body");
    let IrReq::Image(r) = ir else {
        panic!("expected IrReq::Image");
    };
    assert_eq!(r.aspect_ratio.as_deref(), Some("16:9"));
}

#[test]
fn image_read_response_captures_base64_image_bytes() {
    let wire = serde_json::to_vec(&json!({
        "predictions": [{ "bytesBase64Encoded": "cHJldGVuZC1pbWFnZQ==", "mimeType": "image/png" }],
    }))
    .unwrap();
    let ir = IMG.read_response(&wire).expect("valid predictions body");
    let IrResp::Image(r) = ir else {
        panic!("expected IrResp::Image");
    };
    assert_eq!(r.images.len(), 1);
    assert_eq!(r.images[0].b64.as_deref(), Some("cHJldGVuZC1pbWFnZQ=="));
    assert_eq!(r.images[0].mime_type.as_deref(), Some("image/png"));
}

#[test]
fn image_write_read_roundtrip_preserves_prompt() {
    // write_request emits instances[].prompt + parameters.sampleCount; read_request recovers.
    let req = IrReq::Image(busbar_core::ir::image::ImageReq {
        prompt: Some("roundtrip fox".to_string()),
        n: Some(2),
        ..Default::default()
    });
    let wire = IMG.write_request(&req);
    let back = IMG
        .read_request(&wire, "application/json")
        .expect("emitted body reparses");
    let IrReq::Image(r) = back else {
        panic!("expected IrReq::Image");
    };
    assert_eq!(r.prompt.as_deref(), Some("roundtrip fox"));
    assert_eq!(r.n, Some(2));
}

#[test]
fn embeddings_write_request_carries_dimensions_task_type_and_title() {
    // Gemini `:embedContent` supports these natively; dropping `outputDimensionality` returned
    // full-width vectors, and taskType/title steer retrieval quality.
    let ir = IrReq::Embeddings(busbar_core::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Text(vec!["hi".into()]),
        dimensions: Some(256),
        task_type: Some("RETRIEVAL_DOCUMENT".into()),
        title: Some("doc".into()),
        ..Default::default()
    });
    let out = EMB.write_request(&ir);
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
    let ir = EMB
        .read_request(&body, "application/json")
        .expect("valid embedContent body");
    let IrReq::Embeddings(r) = ir else {
        panic!("expected IrReq::Embeddings");
    };
    assert_eq!(r.task_type.as_deref(), Some("RETRIEVAL_QUERY"));
}

#[test]
fn embeddings_read_response_captures_vector_and_usage() {
    let wire = serde_json::to_vec(&json!({
        "embedding": { "values": [0.1, 0.2, 0.3] },
        "usageMetadata": { "promptTokenCount": 5 },
    }))
    .unwrap();
    let ir = EMB
        .read_response(&wire)
        .expect("valid embedContent response");
    let IrResp::Embeddings(r) = ir else {
        panic!("expected IrResp::Embeddings");
    };
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
    let ir = IrResp::Embeddings(EmbeddingsResp {
        embeddings: vec![item],
        ..Default::default()
    });
    let out = EMB.write_response(&ir);
    let v: Value = serde_json::from_slice(&out.bytes).unwrap();
    assert_eq!(v["embedding"]["values"], json!([1.0, 2.0, 3.0]));
}

#[test]
fn embeddings_write_request_warns_on_dropped_non_text_input() {
    use busbar_core::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let ir = IrReq::Embeddings(busbar_core::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Images(vec!["data:image/png;base64,AA==".into()]),
        ..Default::default()
    });
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || EMB.write_request(&ir));

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
    let ir = IrReq::Image(busbar_core::ir::image::ImageReq {
        prompt: Some("a fox".into()),
        aspect_ratio: Some("16:9".into()),
        person_generation: Some("allow_adult".into()),
        ..Default::default()
    });
    let out = IMG.write_request(&ir);
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
    let res = SPEECH.read_response(body);
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
    let ir = SPEECH
        .read_response(&body)
        .expect("valid base64 must decode");
    let IrResp::Speech(r) = ir else {
        panic!("expected speech IR");
    };
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
    let ir = SPEECH
        .read_request(&body, "application/json")
        .expect("valid speech body");
    let IrReq::Speech(r) = ir else {
        panic!("expected speech IR");
    };
    assert_eq!(r.input, "hello");
}

#[test]
fn speech_write_request_prefixes_instructions_to_prompt_not_language_code() {
    // OpenAI-style free-text `instructions` steer Gemini TTS through the PROMPT, not the BCP-47
    // `speechConfig.languageCode` (the old, request-corrupting behavior). Assert the prefix lands
    // in parts[0].text as "<instr>: <input>" and no languageCode key is emitted.
    let ir = IrReq::Speech(busbar_core::ir::audio::SpeechReq {
        input: "hello".into(),
        voice: "Kore".into(),
        instructions: Some("speak cheerfully".into()),
        ..Default::default()
    });
    let out = SPEECH.write_request(&ir);
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
