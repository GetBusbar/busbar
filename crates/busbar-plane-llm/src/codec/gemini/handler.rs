// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Gemini `RequestHandler` + cells. Embeddings via `models/{id}:embedContent`.

use super::{
    COUNT_LABEL, FIELD_ASPECT_RATIO, FIELD_AUDIO_DURATION_SECONDS, FIELD_BYTES_BASE64_ENCODED,
    FIELD_CANDIDATES, FIELD_CANDIDATES_TOKEN_COUNT, FIELD_CONTENTS, FIELD_FINISH_REASON,
    FIELD_GENERATE_CONTENT, FIELD_GENERATION_CONFIG, FIELD_GUIDANCE_SCALE, FIELD_INLINE_DATA,
    FIELD_INLINE_DATA_SNAKE, FIELD_MIME_TYPE, FIELD_MIME_TYPE_SNAKE, FIELD_NEGATIVE_PROMPT,
    FIELD_OUTPUT_DIMENSIONALITY, FIELD_PARTS, FIELD_PERSON_GENERATION, FIELD_PREDICTIONS,
    FIELD_PROMPT_TOKEN_COUNT, FIELD_RESPONSE_MODALITIES, FIELD_SAMPLE_COUNT,
    FIELD_SAMPLE_IMAGE_SIZE, FIELD_STREAM_GENERATE_CONTENT, FIELD_TOTAL_TOKEN_COUNT,
    FIELD_USAGE_METADATA, FIELD_VALUES, GEMINI_AUDIO, GEMINI_FINISH_STOP,
};
use crate::codec::ir::audio::{SpeechResp, TranscriptionResp};
use crate::codec::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};
use crate::codec::keys;
use crate::codec::leaf_codec::LeafCodec;
use busbar_contract::codec::{CodecError, IngressReject, RequestHandler};
// The leaf cells' trait, which the dialect's handler tests call through.
#[cfg(test)]
use busbar_contract::codec::OperationHandler;
use busbar_contract::codec::{EgressCtx, WireBody};
use busbar_contract::media::{base64_encode, MediaBlob, MediaPayload};
use busbar_contract::operation::OpVerb;
use busbar_contract::SlabBytes;
use bytes::Bytes;
use serde_json::{json, Value};

pub struct GeminiRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: super::super::chat_handle::ChatOperation =
    super::super::chat_handle::ChatOperation(COUNT_LABEL);
static EMB: GeminiEmbeddings = GeminiEmbeddings;
static IMG: GeminiImage = GeminiImage;
static TRANSCRIPTION: GeminiTranscription = GeminiTranscription;
static SPEECH: GeminiSpeech = GeminiSpeech;

/// GEMINI'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent from
/// it is the standard no-handler 404: Gemini has no moderation/rerank surface.
static CELLS: &[busbar_contract::codec::Cell] = &[
    (OpVerb::CHAT, &CHAT),
    (OpVerb::EMBEDDINGS, &EMB),
    (OpVerb::IMAGE, &IMG),
    (OpVerb::TRANSCRIPTION, &TRANSCRIPTION),
    (OpVerb::SPEECH, &SPEECH),
];

/// The `:verb` suffix each verb's egress URL ends in — this protocol's own vocabulary, keyed by
/// this protocol's own verb constants. The three that ride `generateContent` are absent because
/// that is the fallback below; the two stream-aware ones are decided there too.
static ACTIONS: &[(OpVerb, &str)] = &[
    (OpVerb::EMBEDDINGS, "embedContent"),
    (OpVerb::IMAGE, "predict"),
];

impl RequestHandler for GeminiRequestHandler {
    dialect_identity!(COUNT_LABEL);
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        let m = ctx.model;
        // The base segment before `/{model}:verb`. Native Gemini is `/v1beta/models`; a provider may
        // override it via `path_base` (e.g. Vertex AI's `/v1/projects/{p}/locations/{l}/publishers/
        // google/models`). The `:verb` suffix and streaming selection are unchanged.
        let base = ctx.path_base.unwrap_or("/v1beta/models");
        if let Some(action) = busbar_contract::codec::path_of(ACTIONS, ctx.operation) {
            return format!("{base}/{m}:{action}");
        }
        // Chat + audio understanding/TTS all ride generateContent (stream-aware). So does every
        // verb with no cell above, which is unreachable in practice and answers the same thing —
        // the pre-1.6.0 answer, verbatim. `stream` is already false for those, because a shape that
        // cannot stream never sets it (`OpDispatch::wants_stream`'s shape floor).
        let action = if ctx.stream {
            FIELD_STREAM_GENERATE_CONTENT
        } else {
            FIELD_GENERATE_CONTENT
        };
        format!("{base}/{m}:{action}")
    }
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<OpVerb> {
        // Gemini multiplexes: the ACTION names embeddings/image; `generateContent` serves chat AND
        // audio, split by BODY — `responseModalities:["AUDIO"]` ⇒ speech, an `inline_data` part with
        // an audio mime ⇒ transcription, an inline IMAGE part is multimodal CHAT. The byte-scan is a
        // cheap pre-filter so plain chat never pays the JSON parse.
        if path.contains(":embedContent") || path.contains(":batchEmbedContents") {
            return Some(OpVerb::EMBEDDINGS);
        }
        if path.contains(":predict") {
            return Some(OpVerb::IMAGE);
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
            rest.starts_with(FIELD_RESPONSE_MODALITIES.as_bytes())
                || rest.starts_with(FIELD_INLINE_DATA_SNAKE.as_bytes())
                || rest.starts_with(FIELD_INLINE_DATA.as_bytes())
        });
        if hit {
            if let Ok(v) = serde_json::from_slice::<Value>(body) {
                let audio_out = v
                    .pointer("/generationConfig/responseModalities")
                    .and_then(Value::as_array)
                    .is_some_and(|m| m.iter().any(|x| x.as_str() == Some(GEMINI_AUDIO)));
                if audio_out {
                    return Some(OpVerb::SPEECH);
                }
                let audio_in = v
                    .pointer("/contents/0/parts")
                    .and_then(Value::as_array)
                    .is_some_and(|parts| {
                        parts.iter().any(|p| {
                            p.get(FIELD_INLINE_DATA_SNAKE)
                                .or_else(|| p.get(FIELD_INLINE_DATA))
                                .and_then(|d| {
                                    d.get(FIELD_MIME_TYPE_SNAKE)
                                        .or_else(|| d.get(FIELD_MIME_TYPE))
                                })
                                .and_then(Value::as_str)
                                .is_some_and(|m| m.starts_with("audio/"))
                        })
                    });
                if audio_in {
                    return Some(OpVerb::TRANSCRIPTION);
                }
            }
        }
        Some(OpVerb::CHAT)
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
///
/// gemini `generateContent`-with-audio wire → IR (gemini as INGRESS): `inline_data` part is the
/// audio, a text part (if any) is the instruction/prompt. Model rides the PATH.
struct GeminiTranscription;

leaf_op! {
    GeminiTranscription: COUNT_LABEL,
    TranscriptionReqHandle = read_transcription_request,
    TranscriptionRespHandle = read_transcription_response;
}

/// The two synthetic directive texts the transcription writer prepends. Kept as named constants so the
/// reader can recognize and skip them when recovering the caller's own `prompt` text (see
/// `read_transcription_request`) — otherwise a round-trip would mistake the directive for the prompt.
const TRANSCRIBE_INSTRUCTION: &str = "Transcribe the following audio verbatim.";
const TRANSLATE_INSTRUCTION: &str = "Translate the following audio to text.";

/// IR → gemini candidates transcription request wire (the body of [`GeminiTranscription::write_request`],
/// moved behind the `(transcription, gemini)` key — G6 A4b option-a). Byte-identical to the inline write.
pub fn write_transcription_request(r: &crate::codec::ir::audio::TranscriptionReq) -> Bytes {
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
    let mut parts = vec![json!({ (keys::TEXT): instruction })];
    // Carry the caller's transcription `prompt` as its OWN text part. The IR projects `prompt` to a
    // forwarded ContentItem::Text (it is screened as sent upstream), but the old writer emitted only
    // the fixed instruction and dropped the caller's text — the screening gate said "forwarded" while
    // the wire silently discarded it. A distinct part keeps the instruction and the caller hint both
    // recoverable on read (the reader skips the known instruction literals).
    if let Some(prompt) = &r.prompt {
        if !prompt.is_empty() {
            parts.push(json!({ (keys::TEXT): prompt }));
        }
    }
    parts.push(
        json!({ (FIELD_INLINE_DATA_SNAKE): { (FIELD_MIME_TYPE_SNAKE): mime, (keys::DATA): data } }),
    );
    let mut body =
        json!({ (FIELD_CONTENTS): [{ (keys::ROLE): keys::USER, (FIELD_PARTS): parts }] });
    // Carry `temperature` — Gemini exposes it natively via generationConfig; dropping it silently
    // changed sampling behavior on a cross-protocol transcription hop.
    if let Some(t) = r.temperature {
        body[FIELD_GENERATION_CONFIG] = json!({ "temperature": t });
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → gemini candidates transcription response wire (the body of
/// [`GeminiTranscription::write_response`], moved behind the `(transcription, gemini)` key — G6 A4b
/// option-a). Byte-identical to the pre-cutover inline write.
pub fn write_transcription_response(r: &crate::codec::ir::audio::TranscriptionResp) -> WireBody {
    let mut body = json!({
        (FIELD_CANDIDATES): [{
            (keys::CONTENT): { (FIELD_PARTS): [{ (keys::TEXT): r.text }], (keys::ROLE): keys::MODEL },
            (FIELD_FINISH_REASON): GEMINI_FINISH_STOP,
        }],
    });
    match &r.usage {
        Some(busbar_contract::billing::Billing::Tokens(t)) => {
            body[FIELD_USAGE_METADATA] = json!({
                (FIELD_PROMPT_TOKEN_COUNT): t.input,
                (FIELD_CANDIDATES_TOKEN_COUNT): t.output,
                (FIELD_TOTAL_TOKEN_COUNT): t.input.saturating_add(t.output),
            });
        }
        // whisper-1 bills audio DURATION (produced by the OpenAI transcription reader). Gemini's
        // usageMetadata is token-shaped and has no seconds field, so surfacing this as a token count
        // would fabricate tokens and corrupt downstream token pricing. Instead carry the exact
        // seconds through under an explicit duration field so the billable quantity is not dropped
        // on an openai->gemini transcription hop (the closest faithful representation).
        Some(busbar_contract::billing::Billing::Duration { seconds }) => {
            // The one render boundary — byte-identical to what this wrote before the quantity
            // became exact (see `billing::duration_seconds_to_wire`).
            let seconds = busbar_contract::billing::duration_seconds_to_wire(*seconds);
            body[FIELD_USAGE_METADATA] = json!({ (FIELD_AUDIO_DURATION_SECONDS): seconds });
        }
        _ => {}
    }
    WireBody::json(SlabBytes::from(
        serde_json::to_vec(&body).unwrap_or_default(),
    ))
}

/// Gemini speech (TTS) — `models/{id}:generateContent` with `responseModalities: [AUDIO]`.
/// Gemini returns inline base64 PCM; a raw-binary body (mock/other) is wrapped verbatim.
///
/// gemini TTS wire → IR (gemini as INGRESS): text part is the input; voice from speechConfig.
struct GeminiSpeech;

leaf_op! {
    GeminiSpeech: COUNT_LABEL,
    SpeechReqHandle = read_speech_request,
    SpeechRespHandle = read_speech_response;
}

/// The `text` parts of the parts array at `pointer`, joined (empty when there are none).
fn joined_text(v: &Value, pointer: &str) -> String {
    v.pointer(pointer)
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get(keys::TEXT).and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

/// One named prebuilt speaker: `{voiceConfig: {prebuiltVoiceConfig: {voiceName}}}` (the single
/// speaker's config, and each multi-speaker entry's beside its `speaker`).
fn prebuilt_speaker(name: &str) -> Value {
    json!({ "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": name } } })
}

/// IR → gemini TTS request wire (the body of [`GeminiSpeech::write_request`], moved behind the
/// `(speech, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_speech_request(r: &crate::codec::ir::audio::SpeechReq) -> Bytes {
    // Gemini multi-speaker TTS: when the request names per-speaker voices, emit
    // `multiSpeakerVoiceConfig.speakerVoiceConfigs[]` (the native shape) instead of the single
    // `voiceConfig`. The old writer never read `SpeechReq::speakers`, so a two-speaker request was
    // silently collapsed to one voice on a same-/cross-protocol hop.
    let speech_config = if r.speakers.is_empty() {
        prebuilt_speaker(&r.voice)
    } else {
        let configs: Vec<Value> = r
            .speakers
            .iter()
            .map(|(speaker, voice)| {
                let mut config = prebuilt_speaker(voice);
                config[keys::SPEAKER] = json!(speaker);
                config
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
        (FIELD_CONTENTS): [{ (keys::ROLE): keys::USER, (FIELD_PARTS): [{ (keys::TEXT): text }]}],
        (FIELD_GENERATION_CONFIG): { (FIELD_RESPONSE_MODALITIES): [GEMINI_AUDIO], "speechConfig": speech_config },
    });
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → gemini TTS response wire (the body of [`GeminiSpeech::write_response`], moved behind the
/// `(speech, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_speech_response(r: &SpeechResp) -> WireBody {
    let (data, mime) = match &r.audio {
        Some(blob) => {
            let d = match &blob.payload {
                MediaPayload::B64(s) => s.clone(),
                MediaPayload::Bytes(b) => base64_encode(b),
            };
            (d, blob.mime_type.clone())
        }
        None => (String::new(), keys::AUDIO_MPEG.into()),
    };
    let body = json!({
        (FIELD_CANDIDATES): [{
            (keys::CONTENT): { (FIELD_PARTS): [{ (FIELD_INLINE_DATA): { (FIELD_MIME_TYPE): mime, (keys::DATA): data } }], (keys::ROLE): keys::MODEL },
            (FIELD_FINISH_REASON): GEMINI_FINISH_STOP,
        }],
    });
    WireBody::json(SlabBytes::from(
        serde_json::to_vec(&body).unwrap_or_default(),
    ))
}

/// Gemini/Imagen image generation (`models/{id}:predict`). prompt in → `predictions[].bytesBase64Encoded` out.
///
/// Imagen `:predict` wire → IR (gemini as INGRESS): `instances[].prompt` + `parameters`.
struct GeminiImage;

leaf_op! {
    GeminiImage: COUNT_LABEL,
    ImageReqHandle = read_image_request,
    ImageRespHandle = read_image_response;
    // Buffer the same-protocol non-stream 2xx body so the default `extract_usage` can read the
    // response's usage and bill the virtual key's TPM/spend. Token-metered image models expose a
    // `usageMetadata` object (billed as tokens); Imagen `:predict` per-image responses have none, so
    // the tap bills 0 tokens and the request still meters once via the per-image cost basis on the
    // cross-protocol seam — mirrors the OpenAI image cell.
    fn taps_usage(&self) -> bool {
        true
    }
}

/// IR → Imagen `:predict` request wire (the body of [`GeminiImage::write_request`], moved behind the
/// `(image, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_image_request(r: &crate::codec::ir::image::ImageReq) -> Bytes {
    let mut params = json!({ (FIELD_SAMPLE_COUNT): r.n.unwrap_or(1) });
    // Carry the Imagen generation controls the reader captures; dropping them fell back to
    // Imagen's defaults (1:1 aspect, default person-generation policy) instead of the request.
    if let Some(a) = &r.aspect_ratio {
        params[FIELD_ASPECT_RATIO] = json!(a);
    }
    if let Some(p) = &r.person_generation {
        params[FIELD_PERSON_GENERATION] = json!(p);
    }
    // Carry the Imagen sampling/guidance controls the reader captures, in Imagen's native parameter
    // names. Dropping them lost the negative prompt, determinism seed, guidance strength, and size
    // tier on a cross-protocol image hop (e.g. bedrock->gemini), silently falling back to defaults.
    if let Some(neg) = &r.negative_prompt {
        params[FIELD_NEGATIVE_PROMPT] = json!(neg);
    }
    if let Some(seed) = r.seed {
        params[keys::SEED] = json!(seed);
    }
    if let Some(g) = r.guidance_scale {
        params[FIELD_GUIDANCE_SCALE] = json!(g);
    }
    if let Some(tier) = &r.image_size_tier {
        params[FIELD_SAMPLE_IMAGE_SIZE] = json!(tier);
    }
    let body = json!({
        "instances": [{ "prompt": r.prompt.clone().unwrap_or_default() }],
        (keys::PARAMETERS): params,
    });
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → Imagen `:predict` response wire (the body of [`GeminiImage::write_response`], moved behind
/// the `(image, gemini)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_image_response(r: &crate::codec::ir::image::ImageResp) -> WireBody {
    let predictions: Vec<Value> = r
        .images
        .iter()
        .map(|img| {
            let mut p = json!({});
            if let Some(b64) = &img.b64 {
                p[FIELD_BYTES_BASE64_ENCODED] = json!(b64);
            }
            p[FIELD_MIME_TYPE] = json!(img.mime_type.clone().unwrap_or_else(|| "image/png".into()));
            p
        })
        .collect();
    let mut body = json!({ (FIELD_PREDICTIONS): predictions });
    // Re-emit the token usage the response reader parses (`read_image_response` captures
    // `usageMetadata` for token-metered gemini image models). The old writer dropped it, so a
    // token-metered gemini->gemini image response lost its usage in the client-facing body —
    // asymmetric with the OpenAI image writer. Emitted only when the IR carries usage.
    if let Some(u) = &r.usage {
        body[FIELD_USAGE_METADATA] = json!({
            (FIELD_PROMPT_TOKEN_COUNT): u.input,
            (FIELD_CANDIDATES_TOKEN_COUNT): u.output,
            (FIELD_TOTAL_TOKEN_COUNT): u.input.saturating_add(u.output),
        });
    }
    WireBody::json(SlabBytes::from(
        serde_json::to_vec(&body).unwrap_or_default(),
    ))
}

/// Gemini embeddings (`models/{id}:embedContent`). Single content in, `embedding.values` out.
// Gemini `:embedContent` embeds a SINGLE input. v1.5.4-restored: a cross-protocol request
// carrying N > 1 inputs (e.g. an OpenAI-family embeddings batch) is NOT rejected — the egress
// writer embeds the FIRST input, warns how many were dropped, and returns HTTP 200 with one
// vector (the silent-degrade v1.5.4 shipped). Representability is the leaf handle's default
// (`EmbeddingsReqHandle`), so no override is needed now the enum dissolved.
struct GeminiEmbeddings;

leaf_op! {
    GeminiEmbeddings: COUNT_LABEL,
    EmbeddingsReqHandle = read_embeddings_request,
    EmbeddingsRespHandle = read_embeddings_response;
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
}

/// IR → gemini `:embedContent` request wire (the body of the gemini embeddings
/// `OperationHandler::write_request`, moved behind the `(embeddings, gemini)` key — G6 A4b option-a).
/// Byte-identical to the pre-cutover inline write.
pub fn write_embeddings_request(r: &EmbeddingsReq) -> Bytes {
    let text = match &r.input {
        EmbInput::Text(v) => {
            // Gemini `:embedContent` embeds a SINGLE content; a multi-input request can only
            // embed the first here (batch would need `:batchEmbedContents`, a 1.3 item). Warn
            // rather than silently drop the rest.
            if v.len() > 1 {
                crate::codec::drops::writer_drop!(
                    crate::codec::drops::member(keys::INPUT),
                    &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                    [dropped = v.len() - 1,],
                    "Gemini :embedContent takes one input; embedding only the first of a \
                     multi-input request (the rest are not sent)"
                );
            }
            v.first().cloned().unwrap_or_default()
        }
        other => {
            crate::codec::drops::writer_drop!(
                crate::codec::drops::member(keys::INPUT),
                &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                [dropped = 1,],
                "Gemini :embedContent takes text input only; dropping a non-text embeddings \
                 input ({other:?} kind) with no analog"
            );
            String::new()
        }
    };
    // Carry the retrieval/shape controls the reader captures — Gemini `:embedContent` supports
    // them natively. Dropping `outputDimensionality` returned full-width vectors instead of the
    // requested size (a wrong-length response); `taskType`/`title` steer retrieval quality.
    let mut body = json!({ (keys::CONTENT): { (FIELD_PARTS): [{ (keys::TEXT): text }] } });
    if let Some(d) = r.dimensions {
        body[FIELD_OUTPUT_DIMENSIONALITY] = json!(d);
    }
    if let Some(t) = &r.task_type {
        body[keys::TASK_TYPE] = json!(t);
    }
    if let Some(t) = &r.title {
        body[keys::TITLE] = json!(t);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → gemini `:embedContent` response wire (the body of the gemini embeddings
/// `OperationHandler::write_response`, moved behind the `(embeddings, gemini)` key — G6 A4b
/// option-a). Byte-identical to the pre-cutover inline write.
pub fn write_embeddings_response(r: &EmbeddingsResp) -> WireBody {
    let values: Vec<f32> = r
        .embeddings
        .first()
        .and_then(|item| match item.vectors.get(&EncFmt::Float) {
            Some(VectorData::Float(v)) => Some(v.clone()),
            _ => None,
        })
        .unwrap_or_default();
    WireBody::json(SlabBytes::from(
        serde_json::to_vec(&json!({ (keys::EMBEDDING): { (FIELD_VALUES): values } }))
            .unwrap_or_default(),
    ))
}

#[cfg(test)]
#[path = "tests/handler_tests.rs"]
mod tests;

/// Wire -> concrete `TranscriptionReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_transcription_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::codec::ir::audio::TranscriptionReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let mut audio = None;
    let mut prompt = None;
    let mut target_language = None;
    if let Some(parts) = wire.pointer("/contents/0/parts").and_then(Value::as_array) {
        for p in parts {
            let inline = p
                .get(FIELD_INLINE_DATA_SNAKE)
                .or_else(|| p.get(FIELD_INLINE_DATA));
            if let Some(d) = inline {
                // Validate the client-supplied base64 at this trust boundary: a malformed
                // payload must 400 here, not silently become an empty audio body downstream
                // (the egress writer decodes it and any `unwrap_or_default` would truncate).
                let data = d
                    .get(keys::DATA)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if busbar_contract::media::base64_decode(&data).is_none() {
                    return Err(IngressReject::BadRequest(
                        "inline_data.data is not valid base64".into(),
                    ));
                }
                audio = Some(MediaBlob {
                    payload: MediaPayload::B64(data),
                    mime_type: d
                        .get(FIELD_MIME_TYPE_SNAKE)
                        .or_else(|| d.get(FIELD_MIME_TYPE))
                        .and_then(Value::as_str)
                        .unwrap_or("application/octet-stream")
                        .to_string(),
                    pcm: None,
                });
            } else if let Some(t) = p.get(keys::TEXT).and_then(Value::as_str) {
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
    Ok(crate::codec::ir::audio::TranscriptionReq {
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
pub fn read_transcription_response(
    wire: &[u8],
) -> Result<crate::codec::ir::audio::TranscriptionResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let text = joined_text(&v, "/candidates/0/content/parts");
    let usage = v
        .get(FIELD_USAGE_METADATA)
        .map(
            |u| -> Result<busbar_contract::billing::Billing, CodecError> {
                // The transcription writer emits `audioDurationSeconds` (not a token count) when the
                // source billing was whisper-1's `Billing::Duration` (an openai->gemini hop). Reading it
                // back as Duration preserves the billable seconds; forcing Tokens{0,0} — as the old
                // reader did — silently discarded the duration. Real Gemini upstreams emit only the
                // token fields, which take the Tokens branch as before.
                // THE DURATION IS A MEASUREMENT, so it is read from the wire's DECIMAL TEXT and never
                // through an `f64` (#81): a quantity that transits a double has already lost the
                // exactness no later conversion can give back. `u.get(..)` would hand back a `Value`
                // whose number is already a double, so the read goes to the ORIGINAL BYTES by pointer.
                if u.get(FIELD_AUDIO_DURATION_SECONDS).is_some() {
                    let seconds = busbar_contract::Count::read_at(
                        wire,
                        "/usageMetadata/audioDurationSeconds",
                    )
                    .map_err(|e| CodecError::Malformed(format!("audioDurationSeconds: {e}")))?
                    .ok_or_else(|| {
                        CodecError::Malformed("audioDurationSeconds: located then lost".to_string())
                    })?;
                    return Ok(busbar_contract::billing::Billing::Duration { seconds });
                }
                // BILLED COUNTS: absent is zero, UNREADABLE IS A REFUSAL (#81/#42). The old
                // `.unwrap_or(0)` wrote "no work happened" for a count the provider really sent and
                // this build could not read, and every money view over that row was then faithfully
                // wrong with nothing to show for it.
                Ok(busbar_contract::billing::Billing::Tokens(
                    busbar_contract::billing::TokenUsage {
                        input: crate::codec::usage_count::billed_count(u, FIELD_PROMPT_TOKEN_COUNT)
                            .map_err(|e| CodecError::Malformed(e.to_string()))?,
                        output: crate::codec::usage_count::billed_count(
                            u,
                            FIELD_CANDIDATES_TOKEN_COUNT,
                        )
                        .map_err(|e| CodecError::Malformed(e.to_string()))?,
                        ..Default::default()
                    },
                ))
            },
        )
        .transpose()?;
    Ok(TranscriptionResp {
        text,
        usage,
        ..Default::default()
    })
}

/// Wire -> concrete `SpeechReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_speech_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::codec::ir::audio::SpeechReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let input = joined_text(&wire, "/contents/0/parts");
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
                    let speaker = c.get(keys::SPEAKER).and_then(Value::as_str)?;
                    let voice_name = c
                        .pointer("/voiceConfig/prebuiltVoiceConfig/voiceName")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Some((speaker.to_string(), voice_name.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(crate::codec::ir::audio::SpeechReq {
        input,
        voice,
        speakers,
        ..Default::default()
    })
}

/// Wire -> concrete `SpeechResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_speech_response(
    wire: &[u8],
) -> Result<crate::codec::ir::audio::SpeechResp, CodecError> {
    // Real Gemini → JSON with inline base64 audio; mock/raw → binary body. Try JSON, fall back.
    //
    // WHICH BODY THE RAW FALLBACK IS FOR: a body that is NOT JSON at all. A body that DOES parse as
    // JSON claims to be a Gemini response, and the only Gemini response shape that carries synthesis
    // is the `inlineData` one — so a JSON body without it is a response this parse cannot read, not
    // an audio container. Handing those bytes back as `audio/mpeg` served a JSON object to a client
    // that asked for audio: an error envelope, a safety block, or a candidate with no audio part all
    // arrived as a 200 whose body a player cannot open, with the upstream's own explanation buried
    // inside bytes labelled as an MP3. It is refused here instead, and the buffered seam turns that
    // refusal into the upstream-shaped error the caller can actually read.
    if let Ok(v) = serde_json::from_slice::<Value>(wire) {
        let Some(data) = v
            .pointer("/candidates/0/content/parts/0/inlineData/data")
            .and_then(Value::as_str)
        else {
            return Err(CodecError::Malformed(
                "gemini speech response carries no candidates[0].content.parts[0].inlineData"
                    .into(),
            ));
        };
        let mime = v
            .pointer("/candidates/0/content/parts/0/inlineData/mimeType")
            .and_then(Value::as_str)
            .unwrap_or("audio/L16;codec=pcm;rate=24000")
            .to_string();
        let pcm = mime
            .contains("pcm")
            .then_some(busbar_contract::media::PcmParams {
                sample_rate: 24000,
                channels: 1,
                bit_depth: 16,
            });
        // Validate the backend's base64 at this trust boundary: a corrupt payload must fail
        // loud here (CodecError) rather than reach the egress writer, where a decode failure
        // would silently become an empty 200 audio body. This is the response-side twin of
        // the ingress inline_data validation.
        if busbar_contract::media::base64_decode(data).is_none() {
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
            usage: Some(busbar_contract::billing::Billing::Flat),
            ..Default::default()
        });
    }
    // NOT JSON at all — a raw audio container, which is what the mock and a direct-passthrough
    // upstream deliver. These bytes really are the audio.
    Ok(SpeechResp {
        audio: Some(MediaBlob {
            payload: MediaPayload::Bytes(SlabBytes::from(wire)),
            mime_type: keys::AUDIO_MPEG.into(),
            pcm: None,
        }),
        // TTS carries no usage object in its audio body; without a marker `billing()` returned
        // `None` and the request was billed nothing. The true per-character unit needs the request
        // `input` and is resolved at the request seam by `crate::codec::ir::audio::SpeechReq::billing`;
        // this `Flat` marker only records that a request was delivered.
        usage: Some(busbar_contract::billing::Billing::Flat),
        ..Default::default()
    })
}

/// Wire -> concrete `ImageReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_image_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::codec::ir::image::ImageReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let params = wire.get(keys::PARAMETERS).cloned().unwrap_or_default();
    Ok(crate::codec::ir::image::ImageReq {
        prompt: wire
            .pointer("/instances/0/prompt")
            .and_then(Value::as_str)
            .map(str::to_string),
        n: params
            .get(FIELD_SAMPLE_COUNT)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        aspect_ratio: params
            .get(FIELD_ASPECT_RATIO)
            .and_then(Value::as_str)
            .map(str::to_string),
        person_generation: params
            .get(FIELD_PERSON_GENERATION)
            .and_then(Value::as_str)
            .map(str::to_string),
        // Imagen sampling/guidance controls — carried through so egress re-emits them.
        negative_prompt: params
            .get(FIELD_NEGATIVE_PROMPT)
            .and_then(Value::as_str)
            .map(str::to_string),
        seed: params.get(keys::SEED).and_then(Value::as_u64),
        guidance_scale: params
            .get(FIELD_GUIDANCE_SCALE)
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        image_size_tier: params
            .get(FIELD_SAMPLE_IMAGE_SIZE)
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
}

/// Wire -> concrete `ImageResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_image_response(wire: &[u8]) -> Result<crate::codec::ir::image::ImageResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let images: Vec<busbar_contract::media::ImageOutput> = v
        .get(FIELD_PREDICTIONS)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|p| busbar_contract::media::ImageOutput {
                    b64: p
                        .get(FIELD_BYTES_BASE64_ENCODED)
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    mime_type: p
                        .get(FIELD_MIME_TYPE)
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
        .get(FIELD_USAGE_METADATA)
        .map(
            |u| -> Result<busbar_contract::billing::TokenUsage, CodecError> {
                // BILLED COUNTS: absent is zero, UNREADABLE IS A REFUSAL (#81/#42) — see
                // `usage_count::billed_count`.
                Ok(busbar_contract::billing::TokenUsage {
                    input: crate::codec::usage_count::billed_count(u, FIELD_PROMPT_TOKEN_COUNT)
                        .map_err(|e| CodecError::Malformed(e.to_string()))?,
                    output: crate::codec::usage_count::billed_count(
                        u,
                        FIELD_CANDIDATES_TOKEN_COUNT,
                    )
                    .map_err(|e| CodecError::Malformed(e.to_string()))?,
                    ..Default::default()
                })
            },
        )
        .transpose()?;
    // Per-image (Imagen `:predict`) responses carry no `usageMetadata` — record the per-image cost
    // basis so the op bills as `Billing::Images` rather than nothing. The billable COUNT is
    // recoverable from the response itself (one image per `predictions` entry). Size/quality tiers
    // live on the request params, which this response-only reader cannot see, so they stay `None`.
    let cost_basis = if usage.is_none() {
        Some(crate::codec::ir::image::CostBasis {
            count: u32::try_from(images.len()).unwrap_or(u32::MAX),
            ..Default::default()
        })
    } else {
        None
    };
    Ok(crate::codec::ir::image::ImageResp {
        images,
        usage,
        cost_basis,
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_embeddings_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::codec::ir::embeddings::EmbeddingsReq, IngressReject> {
    // gemini `:embedContent` wire → IR (gemini as INGRESS). Model rides the PATH (routing fills
    // it via `IrReq::set_model`); the body carries `content.parts[].text`.
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let text = joined_text(&wire, "/content/parts");
    if text.is_empty() {
        return Err(IngressReject::BadRequest(
            "embedContent requires `content.parts[].text`".into(),
        ));
    }
    Ok(crate::codec::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Text(vec![text]),
        task_type: wire
            .get(keys::TASK_TYPE)
            .and_then(Value::as_str)
            .map(str::to_string),
        title: wire
            .get(keys::TITLE)
            .and_then(Value::as_str)
            .map(str::to_string),
        dimensions: wire
            .get(FIELD_OUTPUT_DIMENSIONALITY)
            .and_then(Value::as_u64)
            .and_then(|d| u32::try_from(d).ok()),
        encoding_formats: vec![EncFmt::Float],
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_embeddings_response(
    wire: &[u8],
) -> Result<crate::codec::ir::embeddings::EmbeddingsResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let mut item = EmbeddingItem::default();
    if let Some(f) = v
        .get(keys::EMBEDDING)
        .and_then(|e| e.get(FIELD_VALUES))
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
    // BILLED COUNT (item 133): absent or `null` is no usage (unchanged); a present-but-UNREADABLE
    // count REFUSES rather than reading as "no usage reported".
    let usage = crate::codec::usage_count::billed_count_opt(
        v.get(FIELD_USAGE_METADATA),
        FIELD_PROMPT_TOKEN_COUNT,
    )
    .map_err(|e| CodecError::Malformed(e.to_string()))?
    .map(|n| busbar_contract::billing::TokenUsage {
        input: n,
        ..Default::default()
    });
    Ok(EmbeddingsResp {
        embeddings: vec![item],
        usage,
        ..Default::default()
    })
}

/// This dialect's row of the leaf-op `(operation, protocol)` dispatch, carried on `super::ENTRY`.
pub(crate) const LEAF: crate::codec::leaf_codec::LeafCodecs =
    crate::codec::leaf_codec::LeafCodecs {
        embeddings: Some(LeafCodec {
            write_request: write_embeddings_request,
            write_response: write_embeddings_response,
            read_request: read_embeddings_request,
            read_response: read_embeddings_response,
        }),
        image: Some(LeafCodec {
            write_request: write_image_request,
            write_response: write_image_response,
            read_request: read_image_request,
            read_response: read_image_response,
        }),
        transcription: Some(LeafCodec {
            write_request: write_transcription_request,
            write_response: write_transcription_response,
            read_request: read_transcription_request,
            read_response: read_transcription_response,
        }),
        speech: Some(LeafCodec {
            write_request: write_speech_request,
            write_response: write_speech_response,
            read_request: read_speech_request,
            read_response: read_speech_response,
        }),
        ..crate::codec::leaf_codec::LeafCodecs::NONE
    };
