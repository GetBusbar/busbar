// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Gemini `RequestHandler` + cells. Embeddings via `models/{id}:embedContent`.

use crate::ir::audio::{SpeechResp, TranscriptionResp};
use crate::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};
use busbar_api::operation::Operation;
use busbar_substrate::handlers::{CodecError, IngressReject, OperationHandler, RequestHandler};
use busbar_substrate::ir::handle::IrHandle;
use busbar_substrate::media::{base64_encode, MediaBlob, MediaPayload};
use busbar_substrate::wire::{EgressCtx, WireBody};
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct GeminiRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: super::super::chat_handle::ChatOperation =
    super::super::chat_handle::ChatOperation("gemini");
static EMB: GeminiEmbeddings = GeminiEmbeddings;
static IMG: GeminiImage = GeminiImage;
static TRANSCRIPTION: GeminiTranscription = GeminiTranscription;
static SPEECH: GeminiSpeech = GeminiSpeech;

/// GEMINI'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent from
/// it is the standard no-handler 404: Gemini has no moderation/rerank surface.
static CELLS: &[busbar_substrate::handlers::Cell] = &[
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
        busbar_substrate::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        let m = ctx.model;
        // The base segment before `/{model}:verb`. Native Gemini is `/v1beta/models`; a provider may
        // override it via `path_base` (e.g. Vertex AI's `/v1/projects/{p}/locations/{l}/publishers/
        // google/models`). The `:verb` suffix and streaming selection are unchanged.
        let base = ctx.path_base.unwrap_or("/v1beta/models");
        if let Some(action) = busbar_substrate::handlers::path_of(ACTIONS, ctx.operation) {
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
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("gemini", status, body)
    }
    /// gemini `generateContent`-with-audio wire → IR (gemini as INGRESS): `inline_data` part is the
    /// audio, a text part (if any) is the instruction/prompt. Model rides the PATH.
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::TranscriptionReqHandle(
            read_transcription_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(
            Box::new(super::super::leaf_handles::TranscriptionRespHandle(
                read_transcription_response(wire)?,
            )) as Box<dyn IrHandle>,
        )
    }
}

/// The two synthetic directive texts the transcription writer prepends. Kept as named constants so the
/// reader can recognize and skip them when recovering the caller's own `prompt` text (see
/// `read_transcription_request`) — otherwise a round-trip would mistake the directive for the prompt.
const TRANSCRIBE_INSTRUCTION: &str = "Transcribe the following audio verbatim.";
const TRANSLATE_INSTRUCTION: &str = "Translate the following audio to text.";

/// IR → gemini candidates transcription request wire (the body of [`GeminiTranscription::write_request`],
/// moved behind the `(transcription, gemini)` key — G6 A4b option-a). Byte-identical to the inline write.
pub(crate) fn write_transcription_request(r: &crate::ir::audio::TranscriptionReq) -> Bytes {
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
        TRANSLATE_INSTRUCTION
    } else {
        TRANSCRIBE_INSTRUCTION
    };
    let mut parts = vec![json!({ "text": instruction })];
    // Carry the caller's transcription `prompt` as its OWN text part. The IR projects `prompt` to a
    // forwarded ContentItem::Text (it is screened as sent upstream), but the old writer emitted only
    // the fixed instruction and dropped the caller's text — the screening gate said "forwarded" while
    // the wire silently discarded it. A distinct part keeps the instruction and the caller hint both
    // recoverable on read (the reader skips the known instruction literals).
    if let Some(prompt) = &r.prompt {
        if !prompt.is_empty() {
            parts.push(json!({ "text": prompt }));
        }
    }
    parts.push(json!({ "inline_data": { "mime_type": mime, "data": data } }));
    let mut body = json!({ "contents": [{ "role": "user", "parts": parts }] });
    // Carry `temperature` — Gemini exposes it natively via generationConfig; dropping it silently
    // changed sampling behavior on a cross-protocol transcription hop.
    if let Some(t) = r.temperature {
        body["generationConfig"] = json!({ "temperature": t });
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → gemini candidates transcription response wire (the body of
/// [`GeminiTranscription::write_response`], moved behind the `(transcription, gemini)` key — G6 A4b
/// option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_transcription_response(r: &crate::ir::audio::TranscriptionResp) -> WireBody {
    let mut body = json!({
        "candidates": [{
            "content": { "parts": [{ "text": r.text }], "role": "model" },
            "finishReason": "STOP",
        }],
    });
    match &r.usage {
        Some(busbar_substrate::billing::Billing::Tokens(t)) => {
            body["usageMetadata"] = json!({
                "promptTokenCount": t.input,
                "candidatesTokenCount": t.output,
                "totalTokenCount": t.input.saturating_add(t.output),
            });
        }
        // whisper-1 bills audio DURATION (produced by the OpenAI transcription reader). Gemini's
        // usageMetadata is token-shaped and has no seconds field, so surfacing this as a token count
        // would fabricate tokens and corrupt downstream token pricing. Instead carry the exact
        // seconds through under an explicit duration field so the billable quantity is not dropped
        // on an openai->gemini transcription hop (the closest faithful representation).
        Some(busbar_substrate::billing::Billing::Duration { seconds }) => {
            body["usageMetadata"] = json!({ "audioDurationSeconds": seconds });
        }
        _ => {}
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

/// Gemini speech (TTS) — `models/{id}:generateContent` with `responseModalities: [AUDIO]`.
/// Gemini returns inline base64 PCM; a raw-binary body (mock/other) is wrapped verbatim.
struct GeminiSpeech;

impl OperationHandler for GeminiSpeech {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("gemini", status, body)
    }
    /// gemini TTS wire → IR (gemini as INGRESS): text part is the input; voice from speechConfig.
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::SpeechReqHandle(
            read_speech_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::SpeechRespHandle(
            read_speech_response(wire)?,
        )) as Box<dyn IrHandle>)
    }
}

/// IR → gemini TTS request wire (the body of [`GeminiSpeech::write_request`], moved behind the
/// `(speech, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_speech_request(r: &crate::ir::audio::SpeechReq) -> Bytes {
    // Gemini multi-speaker TTS: when the request names per-speaker voices, emit
    // `multiSpeakerVoiceConfig.speakerVoiceConfigs[]` (the native shape) instead of the single
    // `voiceConfig`. The old writer never read `SpeechReq::speakers`, so a two-speaker request was
    // silently collapsed to one voice on a same-/cross-protocol hop.
    let speech_config = if r.speakers.is_empty() {
        json!({ "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": r.voice } } })
    } else {
        let configs: Vec<Value> = r
            .speakers
            .iter()
            .map(|(speaker, voice)| {
                json!({
                    "speaker": speaker,
                    "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": voice } },
                })
            })
            .collect();
        json!({ "multiSpeakerVoiceConfig": { "speakerVoiceConfigs": configs } })
    };
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

/// IR → gemini TTS response wire (the body of [`GeminiSpeech::write_response`], moved behind the
/// `(speech, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_speech_response(r: &SpeechResp) -> WireBody {
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

/// Gemini/Imagen image generation (`models/{id}:predict`). prompt in → `predictions[].bytesBase64Encoded` out.
struct GeminiImage;

impl OperationHandler for GeminiImage {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("gemini", status, body)
    }
    // Buffer the same-protocol non-stream 2xx body so the default `extract_usage` can read the
    // response's usage and bill the virtual key's TPM/spend. Token-metered image models expose a
    // `usageMetadata` object (billed as tokens); Imagen `:predict` per-image responses have none, so
    // the tap bills 0 tokens and the request still meters once via the per-image cost basis on the
    // cross-protocol seam — mirrors the OpenAI image cell.
    fn taps_usage(&self) -> bool {
        true
    }
    /// Imagen `:predict` wire → IR (gemini as INGRESS): `instances[].prompt` + `parameters`.
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::ImageReqHandle(
            read_image_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::ImageRespHandle(
            read_image_response(wire)?,
        )) as Box<dyn IrHandle>)
    }
}

/// IR → Imagen `:predict` request wire (the body of [`GeminiImage::write_request`], moved behind the
/// `(image, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_image_request(r: &crate::ir::image::ImageReq) -> Bytes {
    let mut params = json!({ "sampleCount": r.n.unwrap_or(1) });
    // Carry the Imagen generation controls the reader captures; dropping them fell back to
    // Imagen's defaults (1:1 aspect, default person-generation policy) instead of the request.
    if let Some(a) = &r.aspect_ratio {
        params["aspectRatio"] = json!(a);
    }
    if let Some(p) = &r.person_generation {
        params["personGeneration"] = json!(p);
    }
    // Carry the Imagen sampling/guidance controls the reader captures, in Imagen's native parameter
    // names. Dropping them lost the negative prompt, determinism seed, guidance strength, and size
    // tier on a cross-protocol image hop (e.g. bedrock->gemini), silently falling back to defaults.
    if let Some(neg) = &r.negative_prompt {
        params["negativePrompt"] = json!(neg);
    }
    if let Some(seed) = r.seed {
        params["seed"] = json!(seed);
    }
    if let Some(g) = r.guidance_scale {
        params["guidanceScale"] = json!(g);
    }
    if let Some(tier) = &r.image_size_tier {
        params["sampleImageSize"] = json!(tier);
    }
    let body = json!({
        "instances": [{ "prompt": r.prompt.clone().unwrap_or_default() }],
        "parameters": params,
    });
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → Imagen `:predict` response wire (the body of [`GeminiImage::write_response`], moved behind
/// the `(image, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_image_response(r: &crate::ir::image::ImageResp) -> WireBody {
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
    let mut body = json!({ "predictions": predictions });
    // Re-emit the token usage the response reader parses (`read_image_response` captures
    // `usageMetadata` for token-metered gemini image models). The old writer dropped it, so a
    // token-metered gemini->gemini image response lost its usage in the client-facing body —
    // asymmetric with the OpenAI image writer. Emitted only when the IR carries usage.
    if let Some(u) = &r.usage {
        body["usageMetadata"] = json!({
            "promptTokenCount": u.input,
            "candidatesTokenCount": u.output,
            "totalTokenCount": u.input.saturating_add(u.output),
        });
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

/// Gemini embeddings (`models/{id}:embedContent`). Single content in, `embedding.values` out.
struct GeminiEmbeddings;

impl OperationHandler for GeminiEmbeddings {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("gemini", status, body)
    }
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
    // Gemini `:embedContent` embeds a SINGLE input. v1.5.4-restored: a cross-protocol request
    // carrying N > 1 inputs (e.g. an OpenAI-family embeddings batch) is NOT rejected — the egress
    // writer embeds the FIRST input, warns how many were dropped, and returns HTTP 200 with one
    // vector (the silent-degrade v1.5.4 shipped). Representability is the leaf handle's default
    // (`EmbeddingsReqHandle`), so no override is needed now the enum dissolved.
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::EmbeddingsReqHandle(
            read_embeddings_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::EmbeddingsRespHandle(
            read_embeddings_response(wire)?,
        )) as Box<dyn IrHandle>)
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

/// Wire -> concrete `TranscriptionReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_transcription_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::audio::TranscriptionReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let mut audio = None;
    let mut prompt = None;
    let mut target_language = None;
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
                if busbar_substrate::media::base64_decode(&data).is_none() {
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
                // Skip the writer's synthetic directive texts; only a caller-supplied prompt part is
                // the real `prompt`. The last such text wins (a request carries at most one).
                if t == TRANSLATE_INSTRUCTION {
                    // The writer emits TRANSLATE_INSTRUCTION iff `target_language` was set (translate
                    // mode); recognizing it reconstructs that mode so a gemini-ingress TRANSLATE
                    // request reads back AS translate instead of silently downgrading to transcribe
                    // on re-emit. The writer only checks `target_language.is_some()`; OpenAI
                    // `/audio/translations` targets English, so "en" is the faithful reconstruction.
                    target_language = Some("en".to_string());
                } else if t != TRANSCRIBE_INSTRUCTION {
                    prompt = Some(t.to_string());
                }
            }
        }
    }
    let Some(audio) = audio else {
        return Err(IngressReject::BadRequest(
            "transcription requires an inline_data audio part".into(),
        ));
    };
    let temperature = wire
        .pointer("/generationConfig/temperature")
        .and_then(Value::as_f64)
        .map(|t| t as f32);
    Ok(crate::ir::audio::TranscriptionReq {
        audio: Some(audio),
        prompt,
        target_language,
        temperature,
        ..Default::default()
    })
}

/// Wire -> concrete `TranscriptionResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_transcription_response(
    wire: &[u8],
) -> Result<crate::ir::audio::TranscriptionResp, CodecError> {
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
        // The transcription writer emits `audioDurationSeconds` (not a token count) when the source
        // billing was whisper-1's `Billing::Duration` (an openai->gemini hop). Reading it back as
        // Duration preserves the billable seconds; forcing Tokens{0,0} — as the old reader did —
        // silently discarded the duration. Real Gemini upstreams emit only the token fields, which
        // take the Tokens branch as before.
        if let Some(seconds) = u.get("audioDurationSeconds").and_then(Value::as_f64) {
            busbar_substrate::billing::Billing::Duration { seconds }
        } else {
            busbar_substrate::billing::Billing::Tokens(busbar_substrate::billing::TokenUsage {
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
        }
    });
    Ok(TranscriptionResp {
        text,
        usage,
        ..Default::default()
    })
}

/// Wire -> concrete `SpeechReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_speech_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::audio::SpeechReq, IngressReject> {
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
    // Multi-speaker: recover each (speaker, voiceName) pair so a two-speaker request survives the
    // hop (the writer re-emits `multiSpeakerVoiceConfig` when this is non-empty).
    let speakers = wire
        .pointer("/generationConfig/speechConfig/multiSpeakerVoiceConfig/speakerVoiceConfigs")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let speaker = c.get("speaker").and_then(Value::as_str)?;
                    let voice_name = c
                        .pointer("/voiceConfig/prebuiltVoiceConfig/voiceName")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Some((speaker.to_string(), voice_name.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(crate::ir::audio::SpeechReq {
        input,
        voice,
        speakers,
        ..Default::default()
    })
}

/// Wire -> concrete `SpeechResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_speech_response(
    wire: &[u8],
) -> Result<crate::ir::audio::SpeechResp, CodecError> {
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
                .then_some(busbar_substrate::media::PcmParams {
                    sample_rate: 24000,
                    channels: 1,
                    bit_depth: 16,
                });
            // Validate the backend's base64 at this trust boundary: a corrupt payload must fail
            // loud here (CodecError) rather than reach the egress writer, where a decode failure
            // would silently become an empty 200 audio body. This is the response-side twin of
            // the ingress inline_data validation.
            if busbar_substrate::media::base64_decode(data).is_none() {
                return Err(CodecError::Malformed(
                    "gemini speech inlineData.data is not valid base64".into(),
                ));
            }
            return Ok(SpeechResp {
                audio: Some(MediaBlob {
                    payload: MediaPayload::B64(data.to_string()),
                    mime_type: mime,
                    pcm,
                }),
                // Mark the synthesis billable so `billing()` is not `None` (see the raw-body arm).
                usage: Some(busbar_substrate::billing::Billing::Flat),
                ..Default::default()
            });
        }
    }
    Ok(SpeechResp {
        audio: Some(MediaBlob {
            payload: MediaPayload::Bytes(Bytes::copy_from_slice(wire)),
            mime_type: "audio/mpeg".into(),
            pcm: None,
        }),
        // TTS carries no usage object in its audio body; without a marker `billing()` returned
        // `None` and the request was billed nothing. The true per-character unit needs the request
        // `input` and is resolved at the request seam by `crate::ir::audio::SpeechReq::billing`;
        // this `Flat` marker only records that a request was delivered.
        usage: Some(busbar_substrate::billing::Billing::Flat),
        ..Default::default()
    })
}

/// Wire -> concrete `ImageReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_image_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::image::ImageReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let params = wire.get("parameters").cloned().unwrap_or_default();
    Ok(crate::ir::image::ImageReq {
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
        // Imagen sampling/guidance controls — carried through so egress re-emits them.
        negative_prompt: params
            .get("negativePrompt")
            .and_then(Value::as_str)
            .map(str::to_string),
        seed: params.get("seed").and_then(Value::as_u64),
        guidance_scale: params
            .get("guidanceScale")
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        image_size_tier: params
            .get("sampleImageSize")
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
}

/// Wire -> concrete `ImageResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_image_response(wire: &[u8]) -> Result<crate::ir::image::ImageResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let images: Vec<busbar_substrate::media::ImageOutput> = v
        .get("predictions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|p| busbar_substrate::media::ImageOutput {
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
    // Token-metered image models (gemini `generateContent`-shaped) carry a `usageMetadata` token
    // object; Imagen `:predict` per-image responses carry none. Without this the response was billed
    // NOTHING — `ImageResp::billing()` returns `None` when BOTH `usage` and `cost_basis` are unset.
    // Parse the token object when present so `billing()` yields `Billing::Tokens` (same field mapping
    // as the Gemini transcription/embeddings usage readers).
    let usage = v
        .get("usageMetadata")
        .map(|u| busbar_substrate::billing::TokenUsage {
            input: u
                .get("promptTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output: u
                .get("candidatesTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            ..Default::default()
        });
    // Per-image (Imagen `:predict`) responses carry no `usageMetadata` — record the per-image cost
    // basis so the op bills as `Billing::Images` rather than nothing. The billable COUNT is
    // recoverable from the response itself (one image per `predictions` entry). Size/quality tiers
    // live on the request params, which this response-only reader cannot see, so they stay `None`.
    let cost_basis = if usage.is_none() {
        Some(crate::ir::image::CostBasis {
            count: u32::try_from(images.len()).unwrap_or(u32::MAX),
            ..Default::default()
        })
    } else {
        None
    };
    Ok(crate::ir::image::ImageResp {
        images,
        usage,
        cost_basis,
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_embeddings_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::embeddings::EmbeddingsReq, IngressReject> {
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
    Ok(crate::ir::embeddings::EmbeddingsReq {
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
    })
}

/// Wire -> concrete `EmbeddingsResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_embeddings_response(
    wire: &[u8],
) -> Result<crate::ir::embeddings::EmbeddingsResp, CodecError> {
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
        .map(|n| busbar_substrate::billing::TokenUsage {
            input: n,
            ..Default::default()
        });
    Ok(EmbeddingsResp {
        embeddings: vec![item],
        usage,
        ..Default::default()
    })
}
