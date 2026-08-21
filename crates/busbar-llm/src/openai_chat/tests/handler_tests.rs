// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/handlers/openai.rs`.

use super::*;

#[test]
fn no_cell_lookup() {
    let h = OpenAiRequestHandler;
    // OpenAI serves every operation (chat now via its OperationHandler too). The no-handler 404 is exercised on a
    // protocol that lacks an op — e.g. anthropic embeddings — in the OperationHandlers registry tests.
    assert!(h.operation_handler(Operation::MODERATION).is_some());
    assert!(h.operation_handler(Operation::CHAT).is_some());
}

#[test]
fn moderation_request_round_trips_openai_shape() {
    let wire = json!({ "model": "omni-moderation-latest", "input": "hello" });
    let ir = super::super::super::leaf_codec::moderation_read_request(
        "openai",
        &serde_json::to_vec(&wire).unwrap(),
        "application/json",
    )
    .unwrap();
    let back: Value = serde_json::from_slice(
        &super::super::super::leaf_codec::moderation_write_request("openai", &ir),
    )
    .unwrap();
    assert_eq!(back["model"], "omni-moderation-latest");
    assert_eq!(back["input"], "hello"); // single text → bare string, round-tripped
}

#[test]
fn moderation_response_round_trips() {
    let wire = br#"{"id":"modr-1","model":"m","results":[{"flagged":true,
            "categories":{"violence":true},"category_scores":{"violence":0.9},
            "category_applied_input_types":{"violence":["text"]}}]}"#;
    let ir = super::super::super::leaf_codec::moderation_read_response("openai", wire).unwrap();
    let back: Value = serde_json::from_slice(
        &super::super::super::leaf_codec::moderation_write_response("openai", &ir).bytes,
    )
    .unwrap();
    assert_eq!(back["results"][0]["flagged"], true);
    assert_eq!(back["results"][0]["categories"]["violence"], true);
    assert_eq!(back["results"][0]["category_scores"]["violence"], 0.9);
    assert_eq!(back["id"], "modr-1");
}

/// Real OpenAI transcription usage (captured from the live API 2026-07-10): whisper-1 reports
/// DURATION (`{type:"duration",seconds}` → `Billing::Duration`); gpt-4o-transcribe reports TOKENS.
/// The OperationHandler must parse both from the wire and re-emit them in OpenAI's own transcription shape.
#[test]
fn transcription_usage_duration_round_trips() {
    let wire = br#"{"text":"Hello there?","usage":{"type":"duration","seconds":1}}"#;
    let ir = super::super::super::leaf_codec::transcription_read_response("openai", wire).unwrap();
    let r = &ir;
    assert!(matches!(r.usage, Some(Billing::Duration { seconds }) if (seconds - 1.0).abs() < 1e-9));
    let back: Value = serde_json::from_slice(
        &super::super::super::leaf_codec::transcription_write_response("openai", &ir).bytes,
    )
    .unwrap();
    assert_eq!(back["text"], "Hello there?");
    assert_eq!(back["usage"]["type"], "duration");
    assert_eq!(back["usage"]["seconds"], 1.0);
}

#[test]
fn transcription_usage_tokens_round_trips() {
    // A cross-protocol transcript whose usage arrived as tokens (e.g. Gemini) → OpenAI token shape.
    let ir = crate::ir::audio::TranscriptionResp {
        text: "hi".into(),
        usage: Some(Billing::Tokens(busbar_core::billing::TokenUsage {
            input: 11,
            output: 3,
            ..Default::default()
        })),
        ..Default::default()
    };
    let back: Value = serde_json::from_slice(
        &super::super::super::leaf_codec::transcription_write_response("openai", &ir).bytes,
    )
    .unwrap();
    assert_eq!(back["usage"]["type"], "tokens");
    assert_eq!(back["usage"]["input_tokens"], 11);
    assert_eq!(back["usage"]["output_tokens"], 3);
    assert_eq!(back["usage"]["total_tokens"], 14);
}

#[test]
fn embeddings_base64_encoding_format_survives_to_openai_egress() {
    // A base64 embeddings request must emit `encoding_format: "base64"` on OpenAI egress, or
    // the backend defaults to float and the caller silently gets the wrong encoding.
    let ir = crate::ir::embeddings::EmbeddingsReq {
        model: "text-embedding-3-small".into(),
        input: crate::ir::embeddings::EmbInput::Text(vec!["hi".into()]),
        encoding_formats: vec![crate::ir::embeddings::EncFmt::Base64],
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::embeddings_write_request("openai", &ir);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["encoding_format"], "base64");
    // A plain (float) request must NOT gain a spurious encoding_format key.
    let ir2 = crate::ir::embeddings::EmbeddingsReq {
        model: "m".into(),
        input: crate::ir::embeddings::EmbInput::Text(vec!["hi".into()]),
        encoding_formats: vec![crate::ir::embeddings::EncFmt::Float],
        ..Default::default()
    };
    let out2 = super::super::super::leaf_codec::embeddings_write_request("openai", &ir2);
    let v2: serde_json::Value = serde_json::from_slice(&out2).unwrap();
    assert!(v2.get("encoding_format").is_none());
}

#[test]
fn embeddings_write_request_warns_on_dropped_non_text_input() {
    use busbar_core::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let ir = crate::ir::embeddings::EmbeddingsReq {
        input: crate::ir::embeddings::EmbInput::Tokens(vec![vec![1, 2, 3]]),
        ..Default::default()
    };
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        super::super::super::leaf_codec::embeddings_write_request("openai", &ir)
    });

    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["input"], serde_json::json!([]));

    assert!(
        cap.contains("dropping a non-text embeddings input"),
        "a dropped non-text embeddings input must warn: {:?}",
        cap.messages()
    );
}

#[test]
fn egress_multipart_sanitizes_mime_from_any_ingress() {
    // A poisoned mime_type reaching the IR from ANY reader (not just the openai multipart
    // parser) must not inject headers into the egress multipart. Build the transcription IR
    // directly with a CR/LF mime (as a gemini inline_data reader could) and assert the egress
    // bytes carry no injected header.
    let ir = crate::ir::audio::TranscriptionReq {
        model: "whisper-1".into(),
        audio: Some(busbar_core::media::MediaBlob {
            payload: busbar_core::media::MediaPayload::Bytes(bytes::Bytes::from_static(b"x")),
            mime_type: "audio/mp3\r\nX-Injected: evil".into(),
            pcm: None,
        }),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::transcription_write_request("openai", &ir);
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("X-Injected"),
        "egress must not carry the injected header: {text}"
    );
    assert!(
        text.contains("Content-Type: audio/mp3\r\n"),
        "sanitized mime should remain"
    );
}

#[test]
fn mime_type_sanitizer_strips_header_injection() {
    // A CR/LF in the client's multipart Content-Type must never survive into the IR, or it
    // would inject headers into busbar's egress multipart request on a cross-protocol hop.
    assert_eq!(
        super::sanitize_mime_type("audio/mp3\r\nX-Injected: evil"),
        "audio/mp3"
    );
    assert_eq!(super::sanitize_mime_type("audio/wav"), "audio/wav");
    assert_eq!(
        super::sanitize_mime_type("audio/mpeg; codecs=mp3"),
        "audio/mpeg; codecs=mp3"
    );
    // A value that is only control chars degrades to the safe default, never empty.
    assert_eq!(
        super::sanitize_mime_type("\r\n\r\n"),
        "application/octet-stream"
    );
}

#[test]
fn total_tokens_saturate_on_upstream_overflow() {
    // The three egress token sums must saturate (operands are upstream-controlled), matching
    // the billing.rs invariant — bare `+` would panic in debug / wrap to 0 in release.
    use busbar_core::billing::{Billing, TokenUsage};
    let huge = TokenUsage {
        input: u64::MAX,
        output: 5,
        ..Default::default()
    };
    // openai transcription write path
    let ir = crate::ir::audio::TranscriptionResp {
        text: "x".into(),
        usage: Some(Billing::Tokens(huge.clone())),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::transcription_write_response("openai", &ir);
    let v: serde_json::Value = serde_json::from_slice(&out.bytes).unwrap();
    assert_eq!(v["usage"]["total_tokens"], u64::MAX); // saturated, not panicked/wrapped
}

// Builds a well-formed multipart body with the given Content-Type boundary spelling.
fn multipart_body(delim_boundary: &str) -> Vec<u8> {
    format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n\
             Content-Type: audio/wav\r\n\r\nRIFFDATA\r\n--{b}--\r\n",
        b = delim_boundary
    )
    .into_bytes()
}

#[test]
fn multipart_boundary_ignores_trailing_content_type_params() {
    // RFC 2046 permits params after the boundary token: `boundary=abc; charset=utf-8`. The
    // parser must key on `abc`, not `abc; charset=utf-8` (which matches no real delimiter and
    // used to drop every part, 400-ing a well-formed request).
    let body = multipart_body("abc");
    let ir = super::super::super::leaf_codec::transcription_read_request(
        "openai",
        &body,
        "multipart/form-data; boundary=abc; charset=utf-8",
    )
    .expect("well-formed body must parse despite trailing CT params");
    let r = ir;
    assert_eq!(r.model, "whisper-1");
    assert!(r.audio.is_some());
}

#[test]
fn multipart_empty_boundary_is_rejected_not_amplified() {
    // An empty boundary yields delim `--`, whose 2-byte scan could push ~body/2 offsets into a
    // Vec (heap amplification). It must short-circuit to a clean BadRequest, never scan.
    let body = vec![b'-'; 4096];
    let err = super::super::super::leaf_codec::transcription_read_request(
        "openai",
        &body,
        "multipart/form-data; boundary=",
    )
    .unwrap_err();
    assert!(matches!(err, IngressReject::BadRequest(_)));
}

#[test]
fn transcription_egress_carries_language_prompt_and_format() {
    // A cross-protocol transcription (e.g. Gemini ingress -> OpenAI egress) must not silently
    // drop the caller's language hint, prompt, or response_format on the multipart body.
    let ir = crate::ir::audio::TranscriptionReq {
        model: "whisper-1".into(),
        source_language: Some("fr".into()),
        prompt: Some("Glossary: API, SDK".into()),
        response_format: Some("verbose_json".into()),
        audio: Some(MediaBlob {
            payload: MediaPayload::Bytes(Bytes::from_static(b"x")),
            mime_type: "audio/wav".into(),
            pcm: None,
        }),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::transcription_write_request("openai", &ir);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("name=\"language\"\r\n\r\nfr\r\n"),
        "language: {text}"
    );
    assert!(
        text.contains("name=\"prompt\"\r\n\r\nGlossary: API, SDK\r\n"),
        "prompt: {text}"
    );
    assert!(
        text.contains("name=\"response_format\"\r\n\r\nverbose_json\r\n"),
        "format: {text}"
    );
}

#[test]
fn transcription_egress_field_strips_crlf_injection() {
    // A CR/LF in any text field (here the operator-supplied model) must not terminate the part
    // and inject new MIME parts into the egress request.
    let ir = crate::ir::audio::TranscriptionReq {
        model: "whisper-1\r\nContent-Disposition: form-data; name=\"evil\"\r\n\r\npwn".into(),
        audio: Some(MediaBlob {
            payload: MediaPayload::Bytes(Bytes::from_static(b"x")),
            mime_type: "audio/wav".into(),
            pcm: None,
        }),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::transcription_write_request("openai", &ir);
    let text = String::from_utf8_lossy(&out);
    // The CR/LF is stripped, so the injection text collapses INLINE into the model value line
    // and can no longer start a MIME header line — the danger is a `\r\n`-prefixed injected part,
    // which must not exist.
    assert!(
        !text.contains("\r\nContent-Disposition: form-data; name=\"evil\""),
        "injected part must not begin a header line: {text}"
    );
    // No injected part boundary either: the only `--boundary` delimiters are the two the writer
    // frames (model, file) plus the closing one — the flattened injection cannot add its own.
    assert_eq!(text.matches("------busbaraudioMIME").count(), 3);
}

#[test]
fn embeddings_taps_usage_and_extract_usage_reads_prompt_tokens() {
    // Embeddings is token-metered same-protocol: it must tap usage, and the default
    // extract_usage (read_response + token_usage) must surface prompt_tokens as the neutral `input`.
    assert!(OpenAiEmbeddings.taps_usage());
    let body = br#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],"usage":{"prompt_tokens":7,"total_tokens":7}}"#;
    let usage = OpenAiEmbeddings
        .extract_usage("openai", body)
        .expect("token-metered embeddings yields usage");
    assert_eq!(usage.input, 7);
}

#[test]
fn embeddings_integer_input_is_rejected_not_silently_emptied() {
    // Pre-tokenized integer input does not translate cross-protocol; it must 400 loudly rather
    // than filter_map to an empty batch that confuses the backend.
    let err = super::super::super::leaf_codec::embeddings_read_request(
        "openai",
        br#"{"model":"text-embedding-3-small","input":[1,2,3]}"#,
        "application/json",
    )
    .unwrap_err();
    assert!(matches!(err, IngressReject::BadRequest(_)));
    // An empty array is likewise rejected.
    assert!(super::super::super::leaf_codec::embeddings_read_request(
        "openai",
        br#"{"model":"m","input":[]}"#,
        "application/json"
    )
    .is_err());
    // A normal string-array batch still parses.
    assert!(super::super::super::leaf_codec::embeddings_read_request(
        "openai",
        br#"{"model":"m","input":["a","b"]}"#,
        "application/json"
    )
    .is_ok());
}

#[test]
fn speech_write_request_carries_instructions_and_speed() {
    // gpt-4o-mini-tts style `instructions` and playback `speed` must survive to OpenAI egress;
    // dropping them made the synthesized audio ignore the request on a cross-protocol hop.
    let ir = crate::ir::audio::SpeechReq {
        input: "hello world".into(),
        model: "gpt-4o-mini-tts".into(),
        voice: "alloy".into(),
        instructions: Some("speak cheerfully".into()),
        speed: Some(1.25),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::speech_write_request("openai", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["instructions"], "speak cheerfully");
    assert_eq!(v["speed"], 1.25);
}

#[test]
fn speech_read_write_roundtrip_preserves_speed() {
    // A wire body carrying `speed` must read into the IR and re-emit on egress (not be dropped).
    let body = br#"{"model":"tts-1","input":"hi","voice":"alloy","speed":0.75}"#;
    let ir =
        super::super::super::leaf_codec::speech_read_request("openai", body, "application/json")
            .expect("valid speech body");
    let r = &ir;
    assert_eq!(r.speed, Some(0.75));
    let out = super::super::super::leaf_codec::speech_write_request("openai", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["speed"], 0.75);
}

#[test]
fn image_write_request_carries_quality_style_response_format_user_and_auto_size() {
    // The generation controls the reader captures must survive to egress; dropping them silently
    // downgraded the request (e.g. a `b64_json` ask fell back to URL, `hd` to standard).
    let ir = crate::ir::image::ImageReq {
        op: ImageOp::Generate,
        model: "gpt-image-1".into(),
        prompt: Some("a fox".into()),
        response_format: Some("b64_json".into()),
        quality: Some("hd".into()),
        style: Some("vivid".into()),
        size: Some(ImageSize::Auto),
        user: Some("user-42".into()),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::image_write_request("openai", &ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["quality"], "hd");
    assert_eq!(v["style"], "vivid");
    assert_eq!(v["response_format"], "b64_json");
    assert_eq!(v["user"], "user-42");
    assert_eq!(v["size"], "auto");
}

#[test]
fn speech_write_response_decodes_b64_payload_to_raw_bytes() {
    // A Speech response whose audio rides as base64 must be decoded to the raw bytes on egress
    // (routed through decode_ir_b64), not emitted as the base64 string.
    let raw = b"\xff\xfb\x90\x00some-audio";
    let b64 = busbar_core::media::base64_encode(raw);
    let ir = crate::ir::audio::SpeechResp {
        audio: Some(MediaBlob {
            payload: MediaPayload::B64(b64),
            mime_type: "audio/mpeg".into(),
            pcm: None,
        }),
        ..Default::default()
    };
    let out = super::super::super::leaf_codec::speech_write_response("openai", &ir);
    assert_eq!(out.bytes.as_ref(), raw);
}

#[test]
fn parse_multipart_caps_at_64_parts() {
    // A crafted body with far more than 64 minimal parts must yield at most 64 fields, bounding
    // heap amplification.
    let boundary = "b";
    let mut body = Vec::new();
    for i in 0..100 {
        body.extend_from_slice(b"--b\r\n");
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n").as_bytes(),
        );
    }
    body.extend_from_slice(b"--b--\r\n");
    let fields = parse_multipart(&body, &format!("multipart/form-data; boundary={boundary}"));
    assert!(
        fields.len() <= 64,
        "expected at most 64 parts, got {}",
        fields.len()
    );
}

#[test]
fn image_read_request_parses_size_quality_and_response_format() {
    let body = br#"{"model":"dall-e-3","prompt":"a cat","size":"1024x1024","quality":"hd","response_format":"b64_json"}"#;
    let ir =
        super::super::super::leaf_codec::image_read_request("openai", body, "application/json")
            .expect("valid image body");
    let r = ir;
    assert_eq!(
        r.size,
        Some(ImageSize::Wh {
            width: 1024,
            height: 1024
        })
    );
    assert_eq!(r.quality.as_deref(), Some("hd"));
    assert_eq!(r.response_format.as_deref(), Some("b64_json"));
    assert_eq!(r.prompt.as_deref(), Some("a cat"));
}

#[test]
fn image_read_request_parses_auto_size() {
    let body = br#"{"model":"gpt-image-1","prompt":"a cat","size":"auto"}"#;
    let ir =
        super::super::super::leaf_codec::image_read_request("openai", body, "application/json")
            .expect("valid image body");
    let r = ir;
    assert_eq!(r.size, Some(ImageSize::Auto));
}

#[test]
fn openai_images_edit_request_is_rejected_as_unsupported_sub_op() {
    // `/v1/images/edits` and `/v1/images/generations` both resolve to `Operation::IMAGE`
    // (handlers/openai.rs:79); read_request sees only body+content-type, so the edit/variation
    // sub-op is distinguished by the body naming an `image` to edit, not by the path. No 1.5.0
    // egress writer emits anything but generations, so this must be the second 404, not a
    // silent fall-through to Generate.
    let body = br#"{"model":"dall-e-2","image":"data:image/png;base64,AA==","mask":"data:image/png;base64,BB==","prompt":"add a hat"}"#;
    let err =
        super::super::super::leaf_codec::image_read_request("openai", body, "multipart/form-data")
            .expect_err("an edit body must be rejected, not silently treated as a generation");
    assert_eq!(
        err,
        IngressReject::UnsupportedSubOp {
            op: Operation::IMAGE,
            model: "dall-e-2".into(),
        }
    );
}

#[test]
fn image_read_response_reads_b64_and_revised_prompt() {
    let body = br#"{"data":[{"b64_json":"AAA","revised_prompt":"a big cat"}]}"#;
    let ir = super::super::super::leaf_codec::image_read_response("openai", body)
        .expect("valid image response");
    let r = ir;
    assert_eq!(r.images.len(), 1);
    assert_eq!(r.images[0].b64.as_deref(), Some("AAA"));
    assert_eq!(r.images[0].revised_prompt.as_deref(), Some("a big cat"));
}

#[test]
fn multipart_single_char_boundary_parses_correctly() {
    // The single-pass parse_multipart rewrite must still handle a 1-character boundary
    // (`boundary=a`): both the `model` and `file` parts must be extracted, proving the rewrite
    // didn't break short boundaries (the case that previously drove the heap-amplification Vec).
    let body = multipart_body("a");
    let ir = super::super::super::leaf_codec::transcription_read_request(
        "openai",
        &body,
        "multipart/form-data; boundary=a",
    )
    .expect("well-formed body with 1-char boundary must parse");
    let r = ir;
    assert_eq!(r.model, "whisper-1");
    assert!(r.audio.is_some());
}

// FIND-1 (money): a gpt-image-1 response carries a token `usage` object; the reader must surface it
// so `billing()` token-meters the request instead of billing nothing. Fails pre-fix (usage unset).
#[test]
fn image_response_with_usage_object_bills_tokens() {
    let wire = json!({
        "created": 1,
        "data": [{ "b64_json": "AAAA" }],
        "usage": { "total_tokens": 30, "input_tokens": 20, "output_tokens": 10 },
    });
    let resp = super::read_image_response(&serde_json::to_vec(&wire).unwrap()).unwrap();
    match resp.billing() {
        Some(busbar_core::billing::Billing::Tokens(t)) => {
            assert_eq!(t.input, 20);
            assert_eq!(t.output, 10);
        }
        other => panic!("gpt-image-1 usage must token-bill, got {other:?}"),
    }
}

// FIND-1 (money): a per-image (dall-e-style) response has NO usage object; the reader must record a
// cost basis from the N returned images so `billing()` is `Images{..}`, not `None`. Fails pre-fix.
#[test]
fn image_response_without_usage_bills_per_image() {
    let wire = json!({
        "created": 1,
        "data": [{ "url": "https://x/1.png" }, { "url": "https://x/2.png" }],
    });
    let resp = super::read_image_response(&serde_json::to_vec(&wire).unwrap()).unwrap();
    match resp.billing() {
        Some(busbar_core::billing::Billing::Images { count, .. }) => assert_eq!(count, 2),
        other => panic!("per-image response must bill Images, got {other:?}"),
    }
}

// FIND-2 (money): TTS returns a raw-audio body with no usage object; without a marker the synthesis
// was billed nothing. The reader must set a `Flat` marker so `billing()` is `Some`. Fails pre-fix.
#[test]
fn speech_response_is_billed() {
    let resp = super::read_speech_response(b"\x00\x01audio-bytes").unwrap();
    assert!(
        resp.billing().is_some(),
        "TTS synthesis must be billed (non-None), got None"
    );
}
