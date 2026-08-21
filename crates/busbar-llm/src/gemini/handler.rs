// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Gemini `RequestHandler` + cells. Embeddings via `models/{id}:embedContent`.

use busbar_core::handlers::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody,
};
use busbar_core::ir::audio::{SpeechResp, TranscriptionResp};
use busbar_core::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};
use busbar_core::ir::variant::{IrReq, IrResp};
use busbar_core::media::{base64_encode, MediaBlob, MediaPayload};
use busbar_core::operation::Operation;
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct GeminiRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: busbar_core::handlers::chat::ChatOperation =
    busbar_core::handlers::chat::ChatOperation("gemini");
static EMB: GeminiEmbeddings = GeminiEmbeddings;
static IMG: GeminiImage = GeminiImage;
static TRANSCRIPTION: GeminiTranscription = GeminiTranscription;
static SPEECH: GeminiSpeech = GeminiSpeech;

/// GEMINI'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent from
/// it is the standard no-handler 404: Gemini has no moderation/rerank surface.
static CELLS: &[busbar_core::handlers::Cell] = &[
    (Operation::CHAT, &CHAT),
    (Operation::EMBEDDINGS, &EMB),
    (Operation::IMAGE, &IMG),
    (Operation::TRANSCRIPTION, &TRANSCRIPTION),
    (Operation::SPEECH, &SPEECH),
];

/// The `:verb` suffix each verb's egress URL ends in — this protocol's own vocabulary, keyed by
/// this protocol's own verb constants. The three that ride `generateContent` are absent because
/// that is the fallback below; the two stream-aware ones are decided there too.
static ACTIONS: &[(Operation, &str)] = &[
    (Operation::EMBEDDINGS, "embedContent"),
    (Operation::IMAGE, "predict"),
];

impl RequestHandler for GeminiRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "gemini"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        busbar_core::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        let m = ctx.model;
        // The base segment before `/{model}:verb`. Native Gemini is `/v1beta/models`; a provider may
        // override it via `path_base` (e.g. Vertex AI's `/v1/projects/{p}/locations/{l}/publishers/
        // google/models`). The `:verb` suffix and streaming selection are unchanged.
        let base = ctx.path_base.unwrap_or("/v1beta/models");
        if let Some(action) = busbar_core::handlers::path_of(ACTIONS, ctx.operation) {
            return format!("{base}/{m}:{action}");
        }
        // Chat + audio understanding/TTS all ride generateContent (stream-aware). So does every
        // verb with no cell above, which is unreachable in practice and answers the same thing —
        // the pre-1.6.0 answer, verbatim. `stream` is already false for those, because a shape that
        // cannot stream never sets it (`OpDispatch::wants_stream`'s shape floor).
        let action = if ctx.stream {
            "streamGenerateContent"
        } else {
            "generateContent"
        };
        format!("{base}/{m}:{action}")
    }
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation> {
        // Gemini multiplexes: the ACTION names embeddings/image; `generateContent` serves chat AND
        // audio, split by BODY — `responseModalities:["AUDIO"]` ⇒ speech, an `inline_data` part with
        // an audio mime ⇒ transcription, an inline IMAGE part is multimodal CHAT. The byte-scan is a
        // cheap pre-filter so plain chat never pays the JSON parse.
        if path.contains(":embedContent") || path.contains(":batchEmbedContents") {
            return Some(Operation::EMBEDDINGS);
        }
        if path.contains(":predict") {
            return Some(Operation::IMAGE);
        }
        if !(path.contains(":generateContent") || path.contains(":streamGenerateContent")) {
            return None;
        }
        // Single pass over the body for all three markers instead of three independent
        // `.windows().any()` scans (each a full traversal on its own): the old code, for
        // `false || false || false` (the common plain-chat case, where none of the markers are
        // present), always paid for three full scans before concluding "chat" — `||` cannot
        // short-circuit when every operand is false. Only the disjunction is ever consulted
        // downstream, so one pass that stops at the FIRST marker found (of any of the three) is
        // both a correct drop-in (same presence/absence result as the old `has(a) || has(b) ||
        // has(c)`) and strictly cheaper on every input: chat still degrades to one full scan
        // (not three), and any input that does carry a marker returns as soon as it's seen
        // instead of scanning per-pattern first.
        let hit = (0..body.len()).any(|i| {
            let rest = &body[i..];
            rest.starts_with(b"responseModalities")
                || rest.starts_with(b"inline_data")
                || rest.starts_with(b"inlineData")
        });
        if hit {
            if let Ok(v) = serde_json::from_slice::<Value>(body) {
                let audio_out = v
                    .pointer("/generationConfig/responseModalities")
                    .and_then(Value::as_array)
                    .is_some_and(|m| m.iter().any(|x| x.as_str() == Some("AUDIO")));
                if audio_out {
                    return Some(Operation::SPEECH);
                }
                let audio_in = v
                    .pointer("/contents/0/parts")
                    .and_then(Value::as_array)
                    .is_some_and(|parts| {
                        parts.iter().any(|p| {
                            p.get("inline_data")
                                .or_else(|| p.get("inlineData"))
                                .and_then(|d| d.get("mime_type").or_else(|| d.get("mimeType")))
                                .and_then(Value::as_str)
                                .is_some_and(|m| m.starts_with("audio/"))
                        })
                    });
                if audio_in {
                    return Some(Operation::TRANSCRIPTION);
                }
            }
        }
        Some(Operation::CHAT)
    }
    fn path_model(&self, path: &str) -> Option<String> {
        // `/{v1,v1beta}/models/{model}:{action}` — model is the last segment up to the LAST colon.
        let rest = path.split("/models/").nth(1)?;
        let (model, _action) = rest.rsplit_once(':')?;
        (!model.is_empty()).then(|| model.to_string())
    }
}

/// Gemini transcription — audio understood via `models/{id}:generateContent` with inline audio data.
/// Egress-only (openai→gemini): audio IR → generateContent request; candidates text → transcription.
struct GeminiTranscription;

impl OperationHandler for GeminiTranscription {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        busbar_core::handlers::protocol_error("gemini", status, body)
    }
    /// gemini `generateContent`-with-audio wire → IR (gemini as INGRESS): `inline_data` part is the
    /// audio, a text part (if any) is the instruction/prompt. Model rides the PATH.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let mut audio = None;
        let mut prompt = None;
        if let Some(parts) = wire.pointer("/contents/0/parts").and_then(Value::as_array) {
            for p in parts {
                let inline = p.get("inline_data").or_else(|| p.get("inlineData"));
                if let Some(d) = inline {
                    // Validate the client-supplied base64 at this trust boundary: a malformed
                    // payload must 400 here, not silently become an empty audio body downstream
                    // (the egress writer decodes it and any `unwrap_or_default` would truncate).
                    let data = d
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    if busbar_core::media::base64_decode(&data).is_none() {
                        return Err(IngressReject::BadRequest(
                            "inline_data.data is not valid base64".into(),
                        ));
                    }
                    audio = Some(MediaBlob {
                        payload: MediaPayload::B64(data),
                        mime_type: d
                            .get("mime_type")
                            .or_else(|| d.get("mimeType"))
                            .and_then(Value::as_str)
                            .unwrap_or("application/octet-stream")
                            .to_string(),
                        pcm: None,
                    });
                } else if let Some(t) = p.get("text").and_then(Value::as_str) {
                    prompt = Some(t.to_string());
                }
            }
        }
        let Some(audio) = audio else {
            return Err(IngressReject::BadRequest(
                "transcription requires an inline_data audio part".into(),
            ));
        };
        Ok(IrReq::Transcription(
            busbar_core::ir::audio::TranscriptionReq {
                audio: Some(audio),
                prompt,
                ..Default::default()
            },
        ))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Transcription(r) = ir else {
            return Bytes::new();
        };
        let (mime, data) = match &r.audio {
            Some(blob) => {
                let d = match &blob.payload {
                    MediaPayload::B64(s) => s.clone(),
                    MediaPayload::Bytes(b) => base64_encode(b),
                };
                (blob.mime_type.clone(), d)
            }
            None => (String::new(), String::new()),
        };
        // `target_language` set ⇒ translate (folds /audio/translations); else transcribe.
        let instruction = if r.target_language.is_some() {
            "Translate the following audio to text."
        } else {
            "Transcribe the following audio verbatim."
        };
        let body = json!({
            "contents": [{ "role": "user", "parts": [
                { "text": instruction },
                { "inline_data": { "mime_type": mime, "data": data } },
            ]}],
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let text = v
            .pointer("/candidates/0/content/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        let usage = v.get("usageMetadata").map(|u| {
            busbar_core::billing::Billing::Tokens(busbar_core::billing::TokenUsage {
                input: u
                    .get("promptTokenCount")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                output: u
                    .get("candidatesTokenCount")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                ..Default::default()
            })
        });
        Ok(IrResp::Transcription(TranscriptionResp {
            text,
            usage,
            ..Default::default()
        }))
    }
    /// IR → gemini candidates response (gemini as INGRESS): transcript text as the model turn.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Transcription(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let mut body = json!({
            "candidates": [{
                "content": { "parts": [{ "text": r.text }], "role": "model" },
                "finishReason": "STOP",
            }],
        });
        if let Some(busbar_core::billing::Billing::Tokens(t)) = &r.usage {
            body["usageMetadata"] = json!({
                "promptTokenCount": t.input,
                "candidatesTokenCount": t.output,
                "totalTokenCount": t.input.saturating_add(t.output),
            });
        }
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

/// Gemini speech (TTS) — `models/{id}:generateContent` with `responseModalities: [AUDIO]`.
/// Gemini returns inline base64 PCM; a raw-binary body (mock/other) is wrapped verbatim.
struct GeminiSpeech;

impl OperationHandler for GeminiSpeech {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        busbar_core::handlers::protocol_error("gemini", status, body)
    }
    /// gemini TTS wire → IR (gemini as INGRESS): text part is the input; voice from speechConfig.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let input = wire
            .pointer("/contents/0/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if input.is_empty() {
            return Err(IngressReject::BadRequest(
                "speech requires a text part".into(),
            ));
        }
        let voice = wire
            .pointer("/generationConfig/speechConfig/voiceConfig/prebuiltVoiceConfig/voiceName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(IrReq::Speech(busbar_core::ir::audio::SpeechReq {
            input,
            voice,
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Speech(r) = ir else {
            return Bytes::new();
        };
        let speech_config = json!({
            "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": r.voice } }
        });
        // OpenAI's `instructions` is FREE-TEXT style guidance ("speak cheerfully"), not a locale.
        // The old code put it into `speechConfig.languageCode` (a BCP-47 field), producing an
        // invalid Gemini request. Gemini steers TTS style through the PROMPT itself, so prefix the
        // text (its documented style-control mechanism) instead of corrupting languageCode.
        let text = match &r.instructions {
            Some(instr) if !instr.trim().is_empty() => format!("{}: {}", instr.trim(), r.input),
            _ => r.input.clone(),
        };
        let body = json!({
            "contents": [{ "role": "user", "parts": [{ "text": text }]}],
            "generationConfig": { "responseModalities": ["AUDIO"], "speechConfig": speech_config },
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        // Real Gemini → JSON with inline base64 audio; mock/raw → binary body. Try JSON, fall back.
        if let Ok(v) = serde_json::from_slice::<Value>(wire) {
            if let Some(data) = v
                .pointer("/candidates/0/content/parts/0/inlineData/data")
                .and_then(Value::as_str)
            {
                let mime = v
                    .pointer("/candidates/0/content/parts/0/inlineData/mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("audio/L16;codec=pcm;rate=24000")
                    .to_string();
                let pcm = mime
                    .contains("pcm")
                    .then_some(busbar_core::media::PcmParams {
                        sample_rate: 24000,
                        channels: 1,
                        bit_depth: 16,
                    });
                // Validate the backend's base64 at this trust boundary: a corrupt payload must fail
                // loud here (CodecError) rather than reach the egress writer, where a decode failure
                // would silently become an empty 200 audio body. This is the response-side twin of
                // the ingress inline_data validation.
                if busbar_core::media::base64_decode(data).is_none() {
                    return Err(CodecError::Malformed(
                        "gemini speech inlineData.data is not valid base64".into(),
                    ));
                }
                return Ok(IrResp::Speech(SpeechResp {
                    audio: Some(MediaBlob {
                        payload: MediaPayload::B64(data.to_string()),
                        mime_type: mime,
                        pcm,
                    }),
                    ..Default::default()
                }));
            }
        }
        Ok(IrResp::Speech(SpeechResp {
            audio: Some(MediaBlob {
                payload: MediaPayload::Bytes(Bytes::copy_from_slice(wire)),
                mime_type: "audio/mpeg".into(),
                pcm: None,
            }),
            ..Default::default()
        }))
    }
    /// IR → gemini TTS response (gemini as INGRESS): inline base64 audio as the model turn. Real
    /// Gemini answers TTS in JSON (`inlineData`), never raw binary — the caller's dialect rules.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Speech(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let (data, mime) = match &r.audio {
            Some(blob) => {
                let d = match &blob.payload {
                    MediaPayload::B64(s) => s.clone(),
                    MediaPayload::Bytes(b) => base64_encode(b),
                };
                (d, blob.mime_type.clone())
            }
            None => (String::new(), "audio/mpeg".into()),
        };
        let body = json!({
            "candidates": [{
                "content": { "parts": [{ "inlineData": { "mimeType": mime, "data": data } }], "role": "model" },
                "finishReason": "STOP",
            }],
        });
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

/// Gemini/Imagen image generation (`models/{id}:predict`). prompt in → `predictions[].bytesBase64Encoded` out.
struct GeminiImage;

impl OperationHandler for GeminiImage {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        busbar_core::handlers::protocol_error("gemini", status, body)
    }
    /// Imagen `:predict` wire → IR (gemini as INGRESS): `instances[].prompt` + `parameters`.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let params = wire.get("parameters").cloned().unwrap_or_default();
        Ok(IrReq::Image(busbar_core::ir::image::ImageReq {
            prompt: wire
                .pointer("/instances/0/prompt")
                .and_then(Value::as_str)
                .map(str::to_string),
            n: params
                .get("sampleCount")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            aspect_ratio: params
                .get("aspectRatio")
                .and_then(Value::as_str)
                .map(str::to_string),
            person_generation: params
                .get("personGeneration")
                .and_then(Value::as_str)
                .map(str::to_string),
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Image(r) = ir else {
            return Bytes::new();
        };
        let mut params = json!({ "sampleCount": r.n.unwrap_or(1) });
        // Carry the Imagen generation controls the reader captures; dropping them fell back to
        // Imagen's defaults (1:1 aspect, default person-generation policy) instead of the request.
        if let Some(a) = &r.aspect_ratio {
            params["aspectRatio"] = json!(a);
        }
        if let Some(p) = &r.person_generation {
            params["personGeneration"] = json!(p);
        }
        let body = json!({
            "instances": [{ "prompt": r.prompt.clone().unwrap_or_default() }],
            "parameters": params,
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let images = v
            .get("predictions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|p| busbar_core::media::ImageOutput {
                        b64: p
                            .get("bytesBase64Encoded")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        mime_type: p
                            .get("mimeType")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        ..Default::default()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(IrResp::Image(busbar_core::ir::image::ImageResp {
            images,
            ..Default::default()
        }))
    }
    /// IR → Imagen `:predict` response (gemini as INGRESS): `predictions[].bytesBase64Encoded`.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Image(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let predictions: Vec<Value> = r
            .images
            .iter()
            .map(|img| {
                let mut p = json!({});
                if let Some(b64) = &img.b64 {
                    p["bytesBase64Encoded"] = json!(b64);
                }
                p["mimeType"] = json!(img.mime_type.clone().unwrap_or_else(|| "image/png".into()));
                p
            })
            .collect();
        WireBody::json(Bytes::from(
            serde_json::to_vec(&json!({ "predictions": predictions })).unwrap_or_default(),
        ))
    }
}

/// Gemini embeddings (`models/{id}:embedContent`). Single content in, `embedding.values` out.
struct GeminiEmbeddings;

impl OperationHandler for GeminiEmbeddings {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        busbar_core::handlers::protocol_error("gemini", status, body)
    }
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
    /// Gemini `:embedContent` embeds a SINGLE input. v1.5.4-restored: a cross-protocol request
    /// carrying N > 1 inputs (e.g. an OpenAI-family embeddings batch) is NOT rejected here. The
    /// egress `write_request` embeds the FIRST input, emits a `warn!` naming how many were dropped,
    /// and returns HTTP 200 with one vector — the silent-degrade v1.5.4 shipped. Fail-loud (a 400 up
    /// front) is a deliberate future opt-in, not a 1.6.0 default, so this reports the request as
    /// representable. (`:batchEmbedContents` support is the larger follow-up that would embed all N.)
    fn egress_representable(&self, _ir: &IrReq) -> Result<(), String> {
        Ok(())
    }
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        // gemini `:embedContent` wire → IR (gemini as INGRESS). Model rides the PATH (routing fills
        // it via `IrReq::set_model`); the body carries `content.parts[].text`.
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let text = wire
            .pointer("/content/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if text.is_empty() {
            return Err(IngressReject::BadRequest(
                "embedContent requires `content.parts[].text`".into(),
            ));
        }
        Ok(IrReq::Embeddings(
            busbar_core::ir::embeddings::EmbeddingsReq {
                input: EmbInput::Text(vec![text]),
                task_type: wire
                    .get("taskType")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                title: wire
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                dimensions: wire
                    .get("outputDimensionality")
                    .and_then(Value::as_u64)
                    .and_then(|d| u32::try_from(d).ok()),
                encoding_formats: vec![EncFmt::Float],
                ..Default::default()
            },
        ))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else {
            return Bytes::new();
        };
        super::super::leaf_codec::embeddings_write_request("gemini", r)
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let mut item = EmbeddingItem::default();
        if let Some(f) = v
            .get("embedding")
            .and_then(|e| e.get("values"))
            .and_then(Value::as_array)
        {
            item.vectors.insert(
                EncFmt::Float,
                VectorData::Float(
                    f.iter()
                        .filter_map(|x| x.as_f64().map(|n| n as f32))
                        .collect(),
                ),
            );
        }
        let usage = v
            .get("usageMetadata")
            .and_then(|u| u.get("promptTokenCount"))
            .and_then(Value::as_u64)
            .map(|n| busbar_core::billing::TokenUsage {
                input: n,
                ..Default::default()
            });
        Ok(IrResp::Embeddings(EmbeddingsResp {
            embeddings: vec![item],
            usage,
            ..Default::default()
        }))
    }
    /// IR → gemini `:embedContent` response (gemini as INGRESS): `{"embedding":{"values":[..]}}`.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Embeddings(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        super::super::leaf_codec::embeddings_write_response("gemini", r)
    }
}

/// IR → gemini `:embedContent` request wire (the body of the gemini embeddings
/// `OperationHandler::write_request`, moved behind the `(embeddings, gemini)` key — G6 A4b option-a).
/// Byte-identical to the pre-cutover inline write.
pub(crate) fn write_embeddings_request(r: &EmbeddingsReq) -> Bytes {
    let text = match &r.input {
        EmbInput::Text(v) => {
            // Gemini `:embedContent` embeds a SINGLE content; a multi-input request can only
            // embed the first here (batch would need `:batchEmbedContents`, a 1.3 item). Warn
            // rather than silently drop the rest.
            if v.len() > 1 {
                tracing::warn!(
                    dropped = v.len() - 1,
                    "Gemini :embedContent takes one input; embedding only the first of a \
                     multi-input request (the rest are not sent)"
                );
            }
            v.first().cloned().unwrap_or_default()
        }
        other => {
            tracing::warn!(
                dropped = 1,
                "Gemini :embedContent takes text input only; dropping a non-text embeddings \
                 input ({other:?} kind) with no analog"
            );
            String::new()
        }
    };
    // Carry the retrieval/shape controls the reader captures — Gemini `:embedContent` supports
    // them natively. Dropping `outputDimensionality` returned full-width vectors instead of the
    // requested size (a wrong-length response); `taskType`/`title` steer retrieval quality.
    let mut body = json!({ "content": { "parts": [{ "text": text }] } });
    if let Some(d) = r.dimensions {
        body["outputDimensionality"] = json!(d);
    }
    if let Some(t) = &r.task_type {
        body["taskType"] = json!(t);
    }
    if let Some(t) = &r.title {
        body["title"] = json!(t);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → gemini `:embedContent` response wire (the body of the gemini embeddings
/// `OperationHandler::write_response`, moved behind the `(embeddings, gemini)` key — G6 A4b
/// option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_embeddings_response(r: &EmbeddingsResp) -> WireBody {
    let values: Vec<f32> = r
        .embeddings
        .first()
        .and_then(|item| match item.vectors.get(&EncFmt::Float) {
            Some(VectorData::Float(v)) => Some(v.clone()),
            _ => None,
        })
        .unwrap_or_default();
    WireBody::json(Bytes::from(
        serde_json::to_vec(&json!({ "embedding": { "values": values } })).unwrap_or_default(),
    ))
}

#[cfg(test)]
#[path = "tests/handler_tests.rs"]
mod tests;
