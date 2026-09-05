// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI `RequestHandler` and its OperationHandlers. OperationHandlers are pure codecs — wire ↔ IR,
//! both directions, nothing else: moderation, embeddings, images, audio, and chat each get one.

use crate::ir::moderation::{ModerationInput, ModerationReq, ModerationResp, ModerationResult};
use busbar_api::operation::Operation;
use busbar_substrate::handlers::{CodecError, IngressReject, OperationHandler, RequestHandler};
use busbar_substrate::ir::handle::IrHandle;
use busbar_substrate::wire::{EgressCtx, WireBody};
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Endpoint paths — each appears on BOTH the egress side (`upstream_path`) and the ingress match
/// (`resolve_operation`); single-sourced so the two sides cannot drift.
const PATH_CHAT_COMPLETIONS: &str = "/v1/chat/completions";
const PATH_EMBEDDINGS: &str = "/v1/embeddings";
const PATH_MODERATIONS: &str = "/v1/moderations";
const PATH_IMAGES_GENERATIONS: &str = "/v1/images/generations";
const PATH_AUDIO_TRANSCRIPTIONS: &str = "/v1/audio/transcriptions";
const PATH_AUDIO_SPEECH: &str = "/v1/audio/speech";
/// Egress-only (OpenAI ships no rerank surface; the arm is unreachable in practice).
const PATH_RERANK: &str = "/v1/rerank";

pub struct OpenAiRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: super::super::chat_handle::ChatOperation =
    super::super::chat_handle::ChatOperation("openai");

static MODERATION: OpenAiModeration = OpenAiModeration;
static EMBEDDINGS: OpenAiEmbeddings = OpenAiEmbeddings;
static IMAGE: OpenAiImage = OpenAiImage;
static TRANSCRIPTION: OpenAiTranscription = OpenAiTranscription;
static SPEECH: OpenAiSpeech = OpenAiSpeech;

/// OPENAI'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent from
/// this table is the standard no-handler 404, which is what the enumerated `None` arm used to say:
/// OpenAI ships no rerank surface, and the protocol-surface verbs are MCP's and A2A's, so the pair
/// is unrepresentable rather than refused at runtime.
static CELLS: &[busbar_substrate::handlers::Cell] = &[
    (Operation::CHAT, &CHAT),
    (Operation::MODERATION, &MODERATION),
    (Operation::EMBEDDINGS, &EMBEDDINGS),
    (Operation::IMAGE, &IMAGE),
    (Operation::TRANSCRIPTION, &TRANSCRIPTION),
    (Operation::SPEECH, &SPEECH),
];

/// The egress half of the path constants above; `resolve_operation` reads the same constants on the
/// ingress side, so the two directions cannot drift.
static PATHS: &[(Operation, &str)] = &[
    (Operation::CHAT, PATH_CHAT_COMPLETIONS),
    (Operation::EMBEDDINGS, PATH_EMBEDDINGS),
    (Operation::MODERATION, PATH_MODERATIONS),
    (Operation::IMAGE, PATH_IMAGES_GENERATIONS),
    (Operation::TRANSCRIPTION, PATH_AUDIO_TRANSCRIPTIONS),
    (Operation::SPEECH, PATH_AUDIO_SPEECH),
];

impl RequestHandler for OpenAiRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "openai"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        busbar_substrate::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        // The fallback is unreachable in practice: a verb with no cell above never reaches egress
        // here. It keeps the pre-1.6.0 answer verbatim rather than inventing a new one.
        busbar_substrate::handlers::path_of(PATHS, ctx.operation)
            .unwrap_or(PATH_RERANK)
            .into()
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        // OpenAI names the operation in the path — the body is never needed.
        if path.ends_with(PATH_CHAT_COMPLETIONS) {
            Some(Operation::CHAT)
        } else if path.ends_with(PATH_EMBEDDINGS) {
            Some(Operation::EMBEDDINGS)
        } else if path.ends_with(PATH_MODERATIONS) {
            Some(Operation::MODERATION)
        } else if path.contains("/v1/images/") {
            Some(Operation::IMAGE)
        } else if path.ends_with(PATH_AUDIO_TRANSCRIPTIONS)
            || path.ends_with("/v1/audio/translations")
        {
            Some(Operation::TRANSCRIPTION)
        } else if path.ends_with(PATH_AUDIO_SPEECH) {
            Some(Operation::SPEECH)
        } else {
            None
        }
    }
}

// -------------------------------------------------- audio cells (real codecs, cross-protocol)

use crate::ir::audio::{SpeechReq, SpeechResp, TranscriptionReq, TranscriptionResp};
use busbar_substrate::billing::Billing;
use busbar_substrate::media::{base64_decode, MediaBlob, MediaPayload};

/// One decoded part of a `multipart/form-data` body (its value borrowed from the request bytes).
struct MultipartField<'a> {
    name: String,
    content_type: Option<String>,
    value: &'a [u8],
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header_attr(headers: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=\"");
    let i = headers.find(&key)? + key.len();
    let rest = &headers[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Sanitize a client-supplied MIME type before it enters the IR: a MIME type is `type/subtype`
/// plus optional `; param=value`, all printable ASCII. A CR/LF or other control char here is a
/// header-injection vector — on a cross-protocol transcription hop the value is written verbatim
/// into busbar's OUTGOING multipart `Content-Type` header, so `audio/mp3\r\nX-Injected: ...`
/// would inject headers (or a premature blank line) into the upstream request. Cut at the first
/// control character; if nothing survives, fall back to a safe default.
fn sanitize_mime_type(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .take_while(|c| !c.is_control())
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect();
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        "application/octet-stream".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Decode a `MediaPayload::B64` audio blob for egress. Every reader that stores a `B64` payload now
/// validates the base64 at its trust boundary (gemini inline_data ingress + gemini speech response),
/// so an invalid string here is an IR-invariant violation, not normal input. Decode defensively:
/// on the should-be-unreachable failure, log loudly rather than silently substitute empty audio.
fn decode_ir_b64(s: &str) -> Bytes {
    base64_decode(s).unwrap_or_else(|| {
        tracing::error!(
            "B64 audio payload in the IR failed to decode at egress — a reader's base64 \
             validation invariant was violated; emitting empty audio"
        );
        Bytes::new()
    })
}

/// Minimal byte-level `multipart/form-data` parser: enough for the OpenAI audio form (a `model` text
/// part + a binary `file` part). Boundary comes from the content-type; file bytes are preserved raw
/// (never lossily UTF-8'd) so audio survives the ingress→IR hop.
fn parse_multipart<'a>(body: &'a [u8], content_type: &str) -> Vec<MultipartField<'a>> {
    let Some(boundary) = content_type.split("boundary=").nth(1) else {
        return Vec::new();
    };
    // The boundary token ends at the next Content-Type parameter: `boundary=abc; charset=utf-8` is
    // spec-legal (RFC 2046) and must yield `abc`, not `abc; charset=utf-8` (which matches no real
    // delimiter and silently drops every part). Cut at the first `;`, then trim and unquote.
    let boundary = boundary.split(';').next().unwrap_or(boundary);
    let boundary = boundary.trim().trim_matches('"');
    // A real boundary is >=1 char; an empty (or absent) one is malformed. Reject it up front rather
    // than scan for the degenerate `--` delimiter. (Amplification is separately bounded by the
    // single-pass segment walk below, which stores no per-offset Vec.)
    if boundary.is_empty() {
        return Vec::new();
    }
    let delim = format!("--{boundary}");
    let delim_b = delim.as_bytes();
    // Single pass, tracking ONLY the previous delimiter offset — a short boundary against a body of
    // pure delimiter bytes used to push ~body/dl offsets into a `positions` Vec (heap amplification,
    // e.g. ~90 MB from a 32 MiB body with a 1-char boundary). Processing each segment as its closing
    // delimiter is found keeps memory bounded by the parsed fields, whatever the boundary length.
    // The OpenAI audio form carries a handful of named parts (model, file, language, prompt,
    // response_format). Cap the field count so a crafted body of hundreds of thousands of minimal
    // parts (short boundary) can't amplify into a large Vec of heap-allocated fields; a real request
    // never approaches this, and extra parts we don't model are ignored anyway.
    const MAX_MULTIPART_PARTS: usize = 64;
    let mut fields = Vec::new();
    let (n, dl) = (body.len(), delim_b.len());
    let mut i = 0;
    let mut prev: Option<usize> = None;
    while i + dl <= n {
        if &body[i..i + dl] == delim_b {
            if let Some(p) = prev {
                if let Some(field) = parse_multipart_segment(&body[p + dl..i]) {
                    fields.push(field);
                    if fields.len() >= MAX_MULTIPART_PARTS {
                        break;
                    }
                }
            }
            prev = Some(i);
            i += dl;
        } else {
            i += 1;
        }
    }
    fields
}

/// Parse ONE multipart segment (the bytes between two delimiters) into a field, or `None` if it has
/// no `\r\n\r\n` header terminator or no `name` attribute. `value` borrows from `seg` (the body).
fn parse_multipart_segment(seg: &[u8]) -> Option<MultipartField<'_>> {
    let seg = seg.strip_prefix(b"\r\n").unwrap_or(seg);
    let hpos = find_sub(seg, b"\r\n\r\n")?;
    let headers = String::from_utf8_lossy(&seg[..hpos]);
    let mut value = &seg[hpos + 4..];
    if value.ends_with(b"\r\n") {
        value = &value[..value.len() - 2];
    }
    let name = header_attr(&headers, "name")?;
    let content_type = headers.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix("Content-Type:")
            .or_else(|| l.strip_prefix("content-type:"))
            .map(|v| v.trim().to_string())
    });
    Some(MultipartField {
        name,
        content_type,
        value,
    })
}

/// Transcription (STT): multipart audio IN → `{text}` OUT.
///
/// KNOWN LIMITATION (1.3): OpenAI's `/v1/audio/translations` (translate-to-English) and
/// `/v1/audio/transcriptions` share an identical multipart body and differ only in the URL path,
/// which `resolve_operation` consumes and `read_request` never sees. So a `/translations` request
/// forwarded CROSS-PROTOCOL (e.g. to Gemini) is not tagged with `target_language` and transcribes
/// verbatim instead of translating. Same-protocol OpenAI→OpenAI is unaffected (the path is
/// preserved to the upstream). Fixing it cross-protocol requires threading the ingress path/sub-op
/// into the operation codec, which is a trait-signature change.
struct OpenAiTranscription;

impl OperationHandler for OpenAiTranscription {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("openai", status, body)
    }
    fn egress_request_content_type(&self) -> &'static str {
        // write_request rebuilds the multipart form with this FIXED boundary.
        "multipart/form-data; boundary=----busbaraudioMIME"
    }

    fn read_request(
        &self,
        body: &[u8],
        content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::TranscriptionReqHandle(
            read_transcription_request(body, content_type)?,
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

/// IR → openai multipart transcription request wire (the body of
/// [`OpenAiTranscription::write_request`], moved behind the `(transcription, openai)` key — G6 A4b
/// option-a). OpenAI-as-egress rebuilds the multipart form (fixed boundary — no randomness needed);
/// not on the harness path (openai is always ingress there), kept for cross-protocol symmetry.
/// Byte-identical to the pre-cutover inline write.
pub fn write_transcription_request(r: &TranscriptionReq) -> Bytes {
    let boundary = "----busbaraudioMIME";
    let mut out: Vec<u8> = Vec::new();
    let mut push_field = |name: &str, val: &str| {
        // Strip CR/LF from the value: any field (model, language, prompt, response_format) can
        // carry attacker- or misconfig-supplied text, and an embedded `\r\n--boundary` would
        // terminate this part and inject arbitrary new MIME parts. This is the one place these
        // fields are serialized, so sanitizing here covers every text field uniformly.
        let safe: String = val.chars().filter(|&c| c != '\r' && c != '\n').collect();
        out.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{safe}\r\n"
            )
            .as_bytes(),
        );
    };
    push_field("model", &r.model);
    // Carry the caller's transcription hints on cross-protocol egress (e.g. Gemini ingress ->
    // OpenAI Whisper): dropping these silently changed behavior (no language hint / prompt /
    // format). Emit each only when present, matching the OpenAI multipart form field names.
    if let Some(lang) = &r.source_language {
        push_field("language", lang);
    }
    if let Some(prompt) = &r.prompt {
        push_field("prompt", prompt);
    }
    if let Some(fmt) = &r.response_format {
        push_field("response_format", fmt);
    }
    // Carry the sampling `temperature` too — OpenAI's transcription form accepts it natively;
    // dropping it silently reset sampling to the default on a cross-protocol hop.
    if let Some(t) = r.temperature {
        push_field("temperature", &t.to_string());
    }
    if let Some(blob) = &r.audio {
        let bytes = match &blob.payload {
            MediaPayload::Bytes(b) => b.clone(),
            MediaPayload::B64(s) => decode_ir_b64(s),
        };
        // Sanitize at the EGRESS boundary too: mime_type can enter the IR from ANY ingress
        // reader (e.g. Gemini inline_data), not just the OpenAI multipart parser, so sanitizing
        // only at ingress left the gemini->openai transcription path exposed to CR/LF header
        // injection. This is the one place the outgoing header is built, so it covers all paths.
        let safe_mime = sanitize_mime_type(&blob.mime_type);
        out.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio\"\r\nContent-Type: {safe_mime}\r\n\r\n").as_bytes());
        out.extend_from_slice(&bytes);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Bytes::from(out)
}

/// IR → openai transcription response wire (the body of [`OpenAiTranscription::write_response`], moved
/// behind the `(transcription, openai)` key — G6 A4b option-a). Byte-identical to the inline write.
pub fn write_transcription_response(r: &TranscriptionResp) -> WireBody {
    // OpenAI serves the plain response formats (`text`/`srt`/`vtt`) as a raw `text/plain` body, not
    // a JSON envelope. When the response IR records one of those (the reader saw a non-JSON body),
    // re-emit the transcript verbatim under `text/plain` rather than JSON-wrapping it — otherwise a
    // WEBVTT/SRT response is mangled into `{"text":"WEBVTT..."}` with the wrong content-type.
    if matches!(r.response_format.as_deref(), Some("text" | "srt" | "vtt")) {
        return WireBody::typed(Bytes::from(r.text.clone().into_bytes()), "text/plain");
    }
    let mut body = json!({ "text": r.text });
    // `verbose_json` carries language/duration/segments/words alongside the text. These are all
    // modelled by the IR; emit each when present (a plain-`json` response leaves them unset, so an
    // absent field emits nothing rather than a fabricated empty array). Cross-protocol readers that
    // captured timestamps/diarization survive the openai egress hop instead of being flattened away.
    if let Some(lang) = &r.detected_language {
        body["language"] = json!(lang);
    }
    if let Some(d) = r.duration_seconds {
        body["duration"] = json!(d);
    }
    if !r.segments.is_empty() {
        body["segments"] = Value::Array(
            r.segments
                .iter()
                .map(|s| {
                    let mut o = json!({
                        "id": s.id, "start": s.start, "end": s.end, "text": s.text,
                    });
                    if let Some(v) = s.avg_logprob {
                        o["avg_logprob"] = json!(v);
                    }
                    if let Some(v) = s.no_speech_prob {
                        o["no_speech_prob"] = json!(v);
                    }
                    if let Some(v) = s.compression_ratio {
                        o["compression_ratio"] = json!(v);
                    }
                    if let Some(sp) = &s.speaker {
                        o["speaker"] = json!(sp);
                    }
                    o
                })
                .collect(),
        );
    }
    if !r.words.is_empty() {
        body["words"] = Value::Array(
            r.words
                .iter()
                .map(|w| json!({ "word": w.word, "start": w.start, "end": w.end }))
                .collect(),
        );
    }
    // Surface the billable usage in OpenAI's own transcription shape — duration or tokens.
    match &r.usage {
        Some(Billing::Duration { seconds }) => {
            body["usage"] = json!({ "type": "duration", "seconds": seconds });
        }
        Some(Billing::Tokens(t)) => {
            body["usage"] = json!({ "type": "tokens", "input_tokens": t.input,
                "output_tokens": t.output, "total_tokens": t.input.saturating_add(t.output) });
        }
        _ => {}
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

/// OpenAI transcription `usage` → `Billing`: `{type:"duration",seconds}` (whisper) or a token shape.
fn parse_transcription_usage(u: &Value) -> Option<Billing> {
    match u.get("type").and_then(Value::as_str) {
        Some("duration") => u
            .get("seconds")
            .and_then(Value::as_f64)
            .map(|seconds| Billing::Duration { seconds }),
        _ => u.get("input_tokens").and_then(Value::as_u64).map(|input| {
            Billing::Tokens(busbar_substrate::billing::TokenUsage {
                input,
                output: u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0),
                ..Default::default()
            })
        }),
    }
}

/// Speech (TTS): `{input}` IN → binary audio OUT.
struct OpenAiSpeech;

impl OperationHandler for OpenAiSpeech {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("openai", status, body)
    }
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

/// IR → openai speech (TTS) request wire (the body of [`OpenAiSpeech::write_request`], moved behind
/// the `(speech, openai)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_speech_request(r: &SpeechReq) -> Bytes {
    let mut body = json!({ "model": r.model, "input": r.input, "voice": r.voice });
    if let Some(f) = &r.response_format {
        body["response_format"] = json!(f);
    }
    // Carry the caller's style + playback controls (gpt-4o-mini-tts `instructions`, `speed`);
    // dropping them made the synthesized audio ignore the request on a cross-protocol hop.
    if let Some(instr) = &r.instructions {
        body["instructions"] = json!(instr);
    }
    if let Some(speed) = r.speed {
        body["speed"] = json!(speed);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → openai speech (TTS) response wire (the body of [`OpenAiSpeech::write_response`], moved behind
/// the `(speech, openai)` key — G6 A4b option-a): raw audio bytes with the blob's own content-type.
/// Byte-identical to the pre-cutover inline write.
pub fn write_speech_response(r: &SpeechResp) -> WireBody {
    let Some(blob) = &r.audio else {
        return WireBody::json(Bytes::new());
    };
    let bytes = match &blob.payload {
        MediaPayload::Bytes(b) => b.clone(),
        MediaPayload::B64(s) => decode_ir_b64(s),
    };
    WireBody::typed(bytes, &blob.mime_type)
}

// -------------------------------------------------- embeddings OperationHandler (real codec, cross-protocol)

use crate::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};

struct OpenAiEmbeddings;

impl OperationHandler for OpenAiEmbeddings {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("openai", status, body)
    }
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
    /// openai embeddings wire → IR (used when openai is the INGRESS of a cross-protocol call).
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::EmbeddingsReqHandle(
            read_embeddings_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }

    /// openai embeddings response wire → IR (used when openai is the EGRESS).
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::EmbeddingsRespHandle(
            read_embeddings_response(wire)?,
        )) as Box<dyn IrHandle>)
    }
}

/// IR → openai embeddings request wire (the body of [`OpenAiEmbeddings::write_request`], moved behind
/// the `(embeddings, openai)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_embeddings_request(r: &EmbeddingsReq) -> Bytes {
    let input = match &r.input {
        EmbInput::Text(v) if v.len() == 1 => json!(v[0]),
        EmbInput::Text(v) => json!(v),
        other => {
            tracing::warn!(
                dropped = 1,
                "openai embeddings input is text-only here; dropping a non-text embeddings \
                 input ({other:?} kind) with no analog"
            );
            json!([])
        }
    };
    let mut body = json!({ "model": r.model, "input": input });
    if let Some(d) = r.dimensions {
        body["dimensions"] = json!(d);
    }
    // Carry the caller's `user` abuse-tracking signal (read into the IR by `read_embeddings_request`)
    // so an openai->openai embeddings passthrough does not strip it — the writer previously emitted
    // neither, silently dropping the field on the round trip. Emitted only when present so a request
    // that never carried it gains no fabricated field.
    if let Some(u) = &r.user {
        body["user"] = json!(u);
    }
    // Honor a base64 encoding request (OpenAI supports float (default) and base64). Dropping
    // it made a cross-protocol base64 embeddings request silently come back as float; the
    // response reader decodes both, so emitting the field completes the round trip.
    if r.encoding_formats.contains(&EncFmt::Base64) {
        body["encoding_format"] = json!("base64");
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → openai embeddings response wire (the body of [`OpenAiEmbeddings::write_response`], moved
/// behind the `(embeddings, openai)` key — G6 A4b option-a). Byte-identical to the inline write.
pub fn write_embeddings_response(r: &EmbeddingsResp) -> WireBody {
    let data: Vec<Value> = r
        .embeddings
        .iter()
        .map(|item| {
            let emb = match item.vectors.get(&EncFmt::Float) {
                Some(VectorData::Float(f)) => json!(f),
                _ => match item.vectors.values().next() {
                    Some(VectorData::Base64(b)) => json!(b),
                    Some(VectorData::Int(v)) => json!(v),
                    _ => json!([]),
                },
            };
            json!({ "object": "embedding", "index": item.index, "embedding": emb })
        })
        .collect();
    let mut body = json!({ "object": "list", "data": data });
    if let Some(m) = &r.model {
        body["model"] = json!(m);
    }
    if let Some(u) = &r.usage {
        body["usage"] =
            json!({ "prompt_tokens": u.input, "total_tokens": u.input.saturating_add(u.output) });
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

// ---------------------------------------------------------------- image OperationHandler (real, cross-protocol)

use crate::ir::image::{ImageOp, ImageReq, ImageResp, ImageSize};
use busbar_substrate::media::ImageOutput;

struct OpenAiImage;

impl OperationHandler for OpenAiImage {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("openai", status, body)
    }
    // Token-metered for gpt-image-1: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend. The
    // cross-protocol path already bills via `translate_response`; this closes the same-protocol gap
    // (mirrors the embeddings cell). Per-image models return no `usage`, so the tap bills 0 tokens
    // and the request still meters once — unchanged for them.
    fn taps_usage(&self) -> bool {
        true
    }
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

/// IR → openai image request wire (the body of [`OpenAiImage::write_request`], moved behind the
/// `(image, openai)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_image_request(r: &ImageReq) -> Bytes {
    let mut body = json!({ "model": r.model });
    if let Some(p) = &r.prompt {
        body["prompt"] = json!(p);
    }
    if let Some(n) = r.n {
        body["n"] = json!(n);
    }
    match r.size {
        Some(ImageSize::Wh { width, height }) => {
            body["size"] = json!(format!("{width}x{height}"));
        }
        Some(ImageSize::Auto) => body["size"] = json!("auto"),
        None => {}
    }
    // Carry the generation controls the reader captures; dropping them silently downgraded the
    // request (e.g. a `b64_json` ask fell back to the default URL response, `hd` to standard).
    if let Some(q) = &r.quality {
        body["quality"] = json!(q);
    }
    if let Some(s) = &r.style {
        body["style"] = json!(s);
    }
    if let Some(f) = &r.response_format {
        body["response_format"] = json!(f);
    }
    // gpt-image-1 output controls the reader captures — dropping them downgraded the request
    // (a transparent-background/webp ask fell back to opaque PNG, a moderation policy was lost).
    if let Some(b) = &r.background {
        body["background"] = json!(b);
    }
    if let Some(f) = &r.output_format {
        body["output_format"] = json!(f);
    }
    if let Some(c) = r.output_compression {
        body["output_compression"] = json!(c);
    }
    if let Some(m) = &r.moderation {
        body["moderation"] = json!(m);
    }
    if let Some(u) = &r.user {
        body["user"] = json!(u);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → openai image response wire (the body of [`OpenAiImage::write_response`], moved behind the
/// `(image, openai)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_image_response(r: &ImageResp) -> WireBody {
    let data: Vec<Value> = r
        .images
        .iter()
        .map(|img| {
            let mut o = serde_json::Map::new();
            if let Some(b) = &img.b64 {
                o.insert("b64_json".into(), json!(b));
            }
            if let Some(u) = &img.url {
                o.insert("url".into(), json!(u));
            }
            if let Some(rp) = &img.revised_prompt {
                o.insert("revised_prompt".into(), json!(rp));
            }
            Value::Object(o)
        })
        .collect();
    let mut body = json!({ "data": data });
    // Emit `created` only when the upstream actually sent it — fabricating `created:0` invents a
    // 1970 timestamp on a response that carried none (gpt-image-1 omits it), a wrong wire value.
    if let Some(created) = r.created {
        body["created"] = json!(created);
    }
    // gpt-image-1 returns a token `usage` object; the reader parses it (for billing) but the writer
    // dropped it, so a same-/cross-protocol image hop lost the usage the client should see. Re-emit
    // it in OpenAI's own image-usage shape when present.
    if let Some(u) = &r.usage {
        body["usage"] = json!({
            "input_tokens": u.input,
            "output_tokens": u.output,
            "total_tokens": u.input.saturating_add(u.output),
        });
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

// ---------------------------------------------------------------- moderation cell

struct OpenAiModeration;

impl OperationHandler for OpenAiModeration {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("openai", status, body)
    }
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::ModerationReqHandle(
            read_moderation_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }

    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::ModerationRespHandle(
            read_moderation_response(wire)?,
        )) as Box<dyn IrHandle>)
    }
}

/// IR → openai moderation request wire (the body of [`OpenAiModeration::write_request`], moved behind
/// the `(moderation, openai)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_moderation_request(r: &ModerationReq) -> Bytes {
    let body = json!({ "model": r.model, "input": input_to_value(&r.input) });
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → openai moderation response wire (the body of [`OpenAiModeration::write_response`], moved
/// behind the `(moderation, openai)` key — G6 A4b option-a). Byte-identical to the inline write.
pub fn write_moderation_response(r: &ModerationResp) -> WireBody {
    let results: Vec<Value> = r
        .results
        .iter()
        .map(|res| {
            json!({
                "flagged": res.flagged,
                "categories": map_bool(&res.categories),
                "category_scores": map_f64(&res.category_scores),
                "category_applied_input_types": map_strs(&res.applied_input_types),
            })
        })
        .collect();
    let mut body = json!({ "results": results });
    if let Some(id) = &r.id {
        body["id"] = json!(id);
    }
    if let Some(m) = &r.model {
        body["model"] = json!(m);
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

// ---- helpers ----

fn parse_input(v: Option<&Value>) -> Result<Vec<ModerationInput>, IngressReject> {
    match v {
        Some(Value::String(s)) => Ok(vec![ModerationInput::Text(s.clone())]),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|item| match item {
                Value::String(s) => Ok(ModerationInput::Text(s.clone())),
                Value::Object(o) => match o.get("type").and_then(Value::as_str) {
                    Some("image_url") => o
                        .get("image_url")
                        .and_then(|iu| iu.get("url"))
                        .and_then(Value::as_str)
                        .map(|u| ModerationInput::ImageUrl(u.to_string()))
                        .ok_or_else(|| IngressReject::BadRequest("image_url missing url".into())),
                    _ => o
                        .get("text")
                        .and_then(Value::as_str)
                        .map(|t| ModerationInput::Text(t.to_string()))
                        .ok_or_else(|| IngressReject::BadRequest("input item missing text".into())),
                },
                _ => Err(IngressReject::BadRequest("invalid input item".into())),
            })
            .collect(),
        _ => Err(IngressReject::BadRequest(
            "moderation request missing `input`".into(),
        )),
    }
}

fn input_to_value(input: &[ModerationInput]) -> Value {
    // Round-trip: a single text input emits the bare string (OpenAI's common form); otherwise an array.
    if let [ModerationInput::Text(s)] = input {
        return json!(s);
    }
    Value::Array(
        input
            .iter()
            .map(|i| match i {
                ModerationInput::Text(t) => json!({ "type": "text", "text": t }),
                ModerationInput::ImageUrl(u) => {
                    json!({ "type": "image_url", "image_url": { "url": u } })
                }
            })
            .collect(),
    )
}

fn parse_result(v: &Value) -> ModerationResult {
    ModerationResult {
        flagged: v.get("flagged").and_then(Value::as_bool).unwrap_or(false),
        categories: obj_map(v.get("categories"), |x| x.as_bool()),
        category_scores: obj_map(v.get("category_scores"), |x| x.as_f64()),
        applied_input_types: obj_map(v.get("category_applied_input_types"), |x| {
            x.as_array().map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
        }),
    }
}

fn obj_map<T>(v: Option<&Value>, f: impl Fn(&Value) -> Option<T>) -> BTreeMap<String, T> {
    v.and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, val)| f(val).map(|t| (k.clone(), t)))
                .collect()
        })
        .unwrap_or_default()
}

fn map_bool(m: &BTreeMap<String, bool>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}
fn map_f64(m: &BTreeMap<String, f64>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}
fn map_strs(m: &BTreeMap<String, Vec<String>>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}

#[cfg(test)]
#[path = "tests/handler_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/speech_mime_regression_tests.rs"]
mod speech_mime_regression_tests;

/// Wire -> concrete `TranscriptionReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_transcription_request(
    body: &[u8],
    content_type: &str,
) -> Result<crate::ir::audio::TranscriptionReq, IngressReject> {
    let fields = parse_multipart(body, content_type);
    let mut req = TranscriptionReq::default();
    for f in &fields {
        match f.name.as_str() {
            "model" => req.model = String::from_utf8_lossy(f.value).trim().to_string(),
            "language" => {
                req.source_language = Some(String::from_utf8_lossy(f.value).trim().to_string())
            }
            "prompt" => req.prompt = Some(String::from_utf8_lossy(f.value).into_owned()),
            "response_format" => {
                req.response_format = Some(String::from_utf8_lossy(f.value).trim().to_string())
            }
            "temperature" => req.temperature = String::from_utf8_lossy(f.value).trim().parse().ok(),
            "file" => {
                req.audio = Some(MediaBlob {
                    payload: MediaPayload::Bytes(Bytes::copy_from_slice(f.value)),
                    mime_type: f
                        .content_type
                        .as_deref()
                        .map(sanitize_mime_type)
                        .unwrap_or_else(|| "application/octet-stream".into()),
                    pcm: None,
                })
            }
            _ => {}
        }
    }
    if req.audio.is_none() {
        return Err(IngressReject::BadRequest(
            "transcription requires a file part".into(),
        ));
    }
    Ok(req)
}

/// Wire -> concrete `TranscriptionResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_transcription_response(
    wire: &[u8],
) -> Result<crate::ir::audio::TranscriptionResp, CodecError> {
    // OpenAI transcription is `{"text": "..."}` (json) or bare text (response_format=text). The
    // real API also carries `usage` — whisper-1 DURATION (`{type:"duration",seconds}`), the
    // gpt-4o-transcribe models TOKENS — captured from the live API (2026-07-10). Both → Billing.
    // A `verbose_json` body additionally carries language/duration/segments/words — all modelled by
    // the IR. Parse them so timestamps/diarization survive the hop instead of being flattened to text.
    let v = match serde_json::from_slice::<Value>(wire) {
        Ok(v) => v,
        // A non-JSON body is one of OpenAI's plain formats (`text`/`srt`/`vtt`), all served as
        // `text/plain`. Record the plain shape so the writer re-emits `text/plain` rather than
        // JSON-wrapping (the reader cannot tell text from srt/vtt on the wire; `text` is the
        // normalized plain marker and the transcript bytes are carried verbatim regardless).
        Err(_) => {
            return Ok(TranscriptionResp {
                text: String::from_utf8_lossy(wire).into_owned(),
                response_format: Some("text".to_string()),
                ..Default::default()
            });
        }
    };
    let text = v
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let segments = v
        .get("segments")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|s| crate::ir::audio::Segment {
                    id: s.get("id").and_then(Value::as_i64).unwrap_or(0),
                    start: s.get("start").and_then(Value::as_f64).unwrap_or(0.0),
                    end: s.get("end").and_then(Value::as_f64).unwrap_or(0.0),
                    text: s
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    avg_logprob: s.get("avg_logprob").and_then(Value::as_f64),
                    no_speech_prob: s.get("no_speech_prob").and_then(Value::as_f64),
                    compression_ratio: s.get("compression_ratio").and_then(Value::as_f64),
                    speaker: s.get("speaker").and_then(Value::as_str).map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default();
    let words = v
        .get("words")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|w| crate::ir::audio::Word {
                    word: w
                        .get("word")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    start: w.get("start").and_then(Value::as_f64).unwrap_or(0.0),
                    end: w.get("end").and_then(Value::as_f64).unwrap_or(0.0),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(TranscriptionResp {
        text,
        detected_language: v
            .get("language")
            .and_then(Value::as_str)
            .map(str::to_string),
        duration_seconds: v.get("duration").and_then(Value::as_f64),
        segments,
        words,
        usage: v.get("usage").and_then(parse_transcription_usage),
        ..Default::default()
    })
}

/// Wire -> concrete `SpeechReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_speech_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::audio::SpeechReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let get = |k: &str| {
        wire.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Ok(SpeechReq {
        input: get("input"),
        model: get("model"),
        voice: get("voice"),
        response_format: wire
            .get("response_format")
            .and_then(Value::as_str)
            .map(str::to_string),
        instructions: wire
            .get("instructions")
            .and_then(Value::as_str)
            .map(str::to_string),
        speed: wire.get("speed").and_then(Value::as_f64).map(|s| s as f32),
        ..Default::default()
    })
}

/// Wire -> concrete `SpeechResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_speech_response(
    wire: &[u8],
) -> Result<crate::ir::audio::SpeechResp, CodecError> {
    // OpenAI speech is raw binary audio whose container is whatever the request's `response_format`
    // asked for (`mp3`|`opus`|`aac`|`flac`|`wav`|`pcm`, default `mp3` — openai-openapi
    // `CreateSpeechRequest.response_format`). This reader is the EGRESS codec reading the upstream
    // 2xx body; the cross-protocol response pipeline (`translate_response`) hands it ONLY the body
    // bytes — not the originating request nor the upstream `Content-Type` header — so the requested
    // `response_format` is not reachable here. Hardcoding `audio/mpeg` therefore mislabeled every
    // non-mp3 format the caller asked for (a wav/opus/flac blob surfaced to the client as
    // `Content-Type: audio/mpeg`). Recover the true container from the audio's own magic bytes
    // instead — the one in-band source of truth — which yields exactly the mime the requested
    // `response_format` implies for every format that carries a container signature.
    Ok(SpeechResp {
        audio: Some(MediaBlob {
            payload: MediaPayload::Bytes(Bytes::copy_from_slice(wire)),
            mime_type: sniff_speech_audio_mime(wire).into(),
            pcm: None,
        }),
        // TTS carries no usage object in its binary body, so without a marker `billing()` returned
        // `None` and the synthesis was billed nothing. The TRUE unit is per-input-character (tts-1)
        // counted from the REQUEST `input`, which this response-only reader cannot see — so the exact
        // count is resolved at the request seam by `crate::ir::audio::SpeechReq::billing`. This marker
        // stays `Flat` only to record that a request was delivered (as rerank does).
        usage: Some(Billing::Flat),
        ..Default::default()
    })
}

/// Recover the audio Content-Type of an OpenAI speech (TTS) response body from its container magic
/// bytes, mapping onto the mime for each `response_format` the endpoint can emit.
///
/// The reader has neither the originating request's `response_format` nor the upstream
/// `Content-Type` header (see [`read_speech_response`]), so the container signature is the only
/// in-band discriminant:
/// * `ID3` tag or raw MPEG frame-sync → mp3 → `audio/mpeg`
/// * `OggS` (Ogg-encapsulated Opus) → opus → `audio/opus`
/// * `fLaC` → flac → `audio/flac`
/// * `RIFF`…`WAVE` → wav → `audio/wav`
/// * ADTS syncword (`0xFF 0xF1`/`0xF9`) → aac → `audio/aac`
///
/// A headerless raw-PCM body carries no signature and falls to the `audio/mpeg` default alongside
/// bare frame-sync mp3 — the endpoint's own default `response_format` — the one residual ambiguity,
/// since PCM is byte-indistinguishable from an unlucky mp3 frame prefix.
fn sniff_speech_audio_mime(wire: &[u8]) -> &'static str {
    if wire.starts_with(b"ID3") {
        "audio/mpeg"
    } else if wire.starts_with(b"OggS") {
        "audio/opus"
    } else if wire.starts_with(b"fLaC") {
        "audio/flac"
    } else if wire.len() >= 12 && wire[0..4] == *b"RIFF" && wire[8..12] == *b"WAVE" {
        "audio/wav"
    } else if wire.len() >= 2 && wire[0] == 0xFF && (wire[1] == 0xF1 || wire[1] == 0xF9) {
        // ADTS AAC syncword (12-bit 0xFFF + layer/protection bits): 0xFFF1 (MPEG-4) / 0xFFF9
        // (MPEG-2). Distinct from the mp3 frame-sync second bytes (0xFB/0xFA/0xF3/0xF2/…).
        "audio/aac"
    } else {
        // Raw MPEG frame-sync mp3 (no ID3 tag) or headerless PCM → the endpoint's default format.
        "audio/mpeg"
    }
}

/// Wire -> concrete `EmbeddingsReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_embeddings_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::embeddings::EmbeddingsReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let model = wire
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let input = match wire.get("input") {
        Some(Value::String(s)) => EmbInput::Text(vec![s.clone()]),
        Some(Value::Array(a)) => {
            // An array of strings is the multi-text batch. An array of integers (or token-ID
            // sub-arrays) is OpenAI's pre-tokenized input form, which does not translate across
            // providers — reject it loudly rather than silently `filter_map` it to an empty batch
            // that reaches the backend as a confusing 400.
            if a.is_empty() || !a.iter().all(Value::is_string) {
                return Err(IngressReject::BadRequest(
                    "embeddings `input` must be a string or a non-empty array of strings \
                         (pre-tokenized integer input is not supported)"
                        .into(),
                ));
            }
            EmbInput::Text(
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
            )
        }
        _ => {
            return Err(IngressReject::BadRequest(
                "embeddings request missing `input`".into(),
            ))
        }
    };
    let dimensions = wire
        .get("dimensions")
        .and_then(Value::as_u64)
        .and_then(|d| u32::try_from(d).ok());
    let encoding_formats = match wire.get("encoding_format").and_then(Value::as_str) {
        Some("base64") => vec![EncFmt::Base64],
        _ => vec![EncFmt::Float],
    };
    Ok(EmbeddingsReq {
        model,
        input,
        dimensions,
        encoding_formats,
        user: wire.get("user").and_then(Value::as_str).map(str::to_string),
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_embeddings_response(
    wire: &[u8],
) -> Result<crate::ir::embeddings::EmbeddingsResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let embeddings = v
        .get("data")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .enumerate()
                .map(|(idx, d)| {
                    let index =
                        d.get("index").and_then(Value::as_u64).unwrap_or(idx as u64) as usize;
                    let mut item = EmbeddingItem {
                        index,
                        ..Default::default()
                    };
                    if let Some(f) = d.get("embedding").and_then(Value::as_array) {
                        item.vectors.insert(
                            EncFmt::Float,
                            VectorData::Float(
                                f.iter()
                                    .filter_map(|x| x.as_f64().map(|n| n as f32))
                                    .collect(),
                            ),
                        );
                    } else if let Some(b) = d.get("embedding").and_then(Value::as_str) {
                        item.vectors
                            .insert(EncFmt::Base64, VectorData::Base64(b.to_string()));
                    }
                    item
                })
                .collect()
        })
        .unwrap_or_default();
    let usage = v
        .get("usage")
        .map(|u| busbar_substrate::billing::TokenUsage {
            input: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
            ..Default::default()
        });
    Ok(EmbeddingsResp {
        model: v.get("model").and_then(Value::as_str).map(str::to_string),
        object_kind: Some("list".into()),
        embeddings,
        usage,
        ..Default::default()
    })
}

/// Wire -> concrete `ImageReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_image_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::image::ImageReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let model = wire
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // `read_request` sees the body + content-type, never the PATH — so `/v1/images/edits` vs
    // `/v1/images/generations` (both resolve to `Operation::IMAGE`, handlers/openai.rs:79) is
    // distinguished by BODY SHAPE, not the route: an `image` reference names an edit
    // (`mask` present) or variation sub-op. No 1.5.0 egress writer emits anything but
    // `/v1/images/generations` (`upstream_path`, below), so every edit/variation request is
    // unsupported today — the second 404 site, not a missing route.
    if wire.get("image").is_some() {
        return Err(IngressReject::UnsupportedSubOp {
            op: Operation::IMAGE,
            model,
        });
    }
    let size = wire.get("size").and_then(Value::as_str).and_then(|s| {
        if s == "auto" {
            Some(ImageSize::Auto)
        } else {
            s.split_once('x').and_then(|(w, h)| {
                Some(ImageSize::Wh {
                    width: w.parse().ok()?,
                    height: h.parse().ok()?,
                })
            })
        }
    });
    Ok(ImageReq {
        op: ImageOp::Generate,
        model,
        prompt: wire
            .get("prompt")
            .and_then(Value::as_str)
            .map(str::to_string),
        n: wire
            .get("n")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        size,
        quality: wire
            .get("quality")
            .and_then(Value::as_str)
            .map(str::to_string),
        style: wire
            .get("style")
            .and_then(Value::as_str)
            .map(str::to_string),
        response_format: wire
            .get("response_format")
            .and_then(Value::as_str)
            .map(str::to_string),
        // gpt-image-1 output controls — carried through so egress re-emits them (see write_image_request).
        background: wire
            .get("background")
            .and_then(Value::as_str)
            .map(str::to_string),
        output_format: wire
            .get("output_format")
            .and_then(Value::as_str)
            .map(str::to_string),
        output_compression: wire
            .get("output_compression")
            .and_then(Value::as_u64)
            .and_then(|c| u8::try_from(c).ok()),
        moderation: wire
            .get("moderation")
            .and_then(Value::as_str)
            .map(str::to_string),
        user: wire.get("user").and_then(Value::as_str).map(str::to_string),
        ..Default::default()
    })
}

/// Wire -> concrete `ImageResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_image_response(wire: &[u8]) -> Result<crate::ir::image::ImageResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let images: Vec<ImageOutput> = v
        .get("data")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|d| ImageOutput {
                    b64: d
                        .get("b64_json")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    url: d.get("url").and_then(Value::as_str).map(str::to_string),
                    revised_prompt: d
                        .get("revised_prompt")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    ..Default::default()
                })
                .collect()
        })
        .unwrap_or_default();
    // gpt-image-1 returns a token `usage` object (`{total_tokens,input_tokens,output_tokens}`);
    // per-image models (dall-e, etc.) return no usage body at all. Without this the response was
    // billed nothing — `ImageResp::billing()` returns `None` when BOTH `usage` and `cost_basis`
    // are unset. Parse the token object when present so `billing()` yields `Billing::Tokens`.
    let usage = v
        .get("usage")
        .map(|u| busbar_substrate::billing::TokenUsage {
            input: u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0),
            output: u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0),
            ..Default::default()
        });
    // Per-image (dall-e-style) providers carry no `usage` — record the per-image cost basis so the
    // op is billed as `Billing::Images` rather than nothing. The billable COUNT is recoverable from
    // the response itself (one image per `data` entry). The size/quality TIERS live on the request
    // params, which this response-only reader cannot see, so they stay `None` (count is the unit).
    let cost_basis = if usage.is_none() {
        Some(crate::ir::image::CostBasis {
            count: u32::try_from(images.len()).unwrap_or(u32::MAX),
            ..Default::default()
        })
    } else {
        None
    };
    Ok(ImageResp {
        created: v.get("created").and_then(Value::as_u64),
        images,
        usage,
        cost_basis,
        ..Default::default()
    })
}

/// Wire -> concrete `ModerationReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_moderation_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::moderation::ModerationReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let model = wire
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let input = parse_input(wire.get("input"))?;
    Ok(ModerationReq {
        model,
        input,
        extra: BTreeMap::new(),
    })
}

/// Wire -> concrete `ModerationResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_moderation_response(
    wire: &[u8],
) -> Result<crate::ir::moderation::ModerationResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let results = v
        .get("results")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_result).collect())
        .unwrap_or_default();
    Ok(ModerationResp {
        id: v.get("id").and_then(Value::as_str).map(str::to_string),
        model: v.get("model").and_then(Value::as_str).map(str::to_string),
        results,
        extra: BTreeMap::new(),
    })
}
