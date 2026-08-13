// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI `RequestHandler` and its OperationHandlers. OperationHandlers are pure codecs — wire ↔ IR,
//! both directions, nothing else: moderation, embeddings, images, audio, and chat each get one.

use crate::handlers::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody,
};
use crate::ir::moderation::{ModerationInput, ModerationReq, ModerationResp, ModerationResult};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
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

pub(crate) struct OpenAiRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation = crate::handlers::chat::ChatOperation("openai");

static MODERATION: OpenAiModeration = OpenAiModeration;
static EMBEDDINGS: OpenAiEmbeddings = OpenAiEmbeddings;
static IMAGE: OpenAiImage = OpenAiImage;
static TRANSCRIPTION: OpenAiTranscription = OpenAiTranscription;
static SPEECH: OpenAiSpeech = OpenAiSpeech;

/// OPENAI'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent from
/// this table is the standard no-handler 404, which is what the enumerated `None` arm used to say:
/// OpenAI ships no rerank surface, and the protocol-surface verbs are MCP's and A2A's, so the pair
/// is unrepresentable rather than refused at runtime.
static CELLS: &[crate::handlers::Cell] = &[
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
        crate::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        // The fallback is unreachable in practice: a verb with no cell above never reaches egress
        // here. It keeps the pre-1.6.0 answer verbatim rather than inventing a new one.
        crate::handlers::path_of(PATHS, ctx.operation)
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

use crate::billing::Billing;
use crate::ir::audio::{SpeechReq, SpeechResp, TranscriptionReq, TranscriptionResp};
use crate::media::{base64_decode, MediaBlob, MediaPayload};

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
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError {
        crate::handlers::protocol_error("openai", status, body)
    }
    fn egress_request_content_type(&self) -> &'static str {
        // write_request rebuilds the multipart form with this FIXED boundary.
        "multipart/form-data; boundary=----busbaraudioMIME"
    }

    fn read_request(&self, body: &[u8], content_type: &str) -> Result<IrReq, IngressReject> {
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
        Ok(IrReq::Transcription(req))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        // OpenAI-as-egress rebuilds the multipart form (fixed boundary — no randomness needed). Not on
        // the harness path (openai is always ingress there); kept for cross-protocol symmetry.
        let IrReq::Transcription(r) = ir else {
            return Bytes::new();
        };
        let boundary = "----busbaraudioMIME";
        let mut out: Vec<u8> = Vec::new();
        let mut push_field = |name: &str, val: &str| {
            // Strip CR/LF from the value: any field (model, language, prompt, response_format) can
            // carry attacker- or misconfig-supplied text, and an embedded `\r\n--boundary` would
            // terminate this part and inject arbitrary new MIME parts. This is the one place these
            // fields are serialized, so sanitizing here covers every text field uniformly.
            let safe: String = val.chars().filter(|&c| c != '\r' && c != '\n').collect();
            out.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{safe}\r\n").as_bytes());
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
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        // OpenAI transcription is `{"text": "..."}` (json) or bare text (response_format=text). The
        // real API also carries `usage` — whisper-1 DURATION (`{type:"duration",seconds}`), the
        // gpt-4o-transcribe models TOKENS — captured from the live API (2026-07-10). Both → Billing.
        let (text, usage) = match serde_json::from_slice::<Value>(wire) {
            Ok(v) => {
                let text = v
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                (text, v.get("usage").and_then(parse_transcription_usage))
            }
            Err(_) => (String::from_utf8_lossy(wire).into_owned(), None),
        };
        Ok(IrResp::Transcription(TranscriptionResp {
            text,
            usage,
            ..Default::default()
        }))
    }
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Transcription(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let mut body = json!({ "text": r.text });
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
}

/// OpenAI transcription `usage` → `Billing`: `{type:"duration",seconds}` (whisper) or a token shape.
fn parse_transcription_usage(u: &Value) -> Option<Billing> {
    match u.get("type").and_then(Value::as_str) {
        Some("duration") => u
            .get("seconds")
            .and_then(Value::as_f64)
            .map(|seconds| Billing::Duration { seconds }),
        _ => u.get("input_tokens").and_then(Value::as_u64).map(|input| {
            Billing::Tokens(crate::billing::TokenUsage {
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
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError {
        crate::handlers::protocol_error("openai", status, body)
    }
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let get = |k: &str| {
            wire.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Ok(IrReq::Speech(SpeechReq {
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
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Speech(r) = ir else {
            return Bytes::new();
        };
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
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        // OpenAI speech is raw binary audio (mp3 by default) — wrap the bytes verbatim.
        Ok(IrResp::Speech(SpeechResp {
            audio: Some(MediaBlob {
                payload: MediaPayload::Bytes(Bytes::copy_from_slice(wire)),
                mime_type: "audio/mpeg".into(),
                pcm: None,
            }),
            ..Default::default()
        }))
    }
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Speech(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let Some(blob) = &r.audio else {
            return WireBody::json(Bytes::new());
        };
        let bytes = match &blob.payload {
            MediaPayload::Bytes(b) => b.clone(),
            MediaPayload::B64(s) => decode_ir_b64(s),
        };
        WireBody::typed(bytes, &blob.mime_type)
    }
}

// -------------------------------------------------- embeddings OperationHandler (real codec, cross-protocol)

use crate::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};

struct OpenAiEmbeddings;

impl OperationHandler for OpenAiEmbeddings {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError {
        crate::handlers::protocol_error("openai", status, body)
    }
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
    /// openai embeddings wire → IR (used when openai is the INGRESS of a cross-protocol call).
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
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
        Ok(IrReq::Embeddings(EmbeddingsReq {
            model,
            input,
            dimensions,
            encoding_formats,
            user: wire.get("user").and_then(Value::as_str).map(str::to_string),
            ..Default::default()
        }))
    }

    /// IR → openai embeddings wire (used when openai is the EGRESS).
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else {
            return Bytes::new();
        };
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
        // Honor a base64 encoding request (OpenAI supports float (default) and base64). Dropping
        // it made a cross-protocol base64 embeddings request silently come back as float; the
        // response reader decodes both, so emitting the field completes the round trip.
        if r.encoding_formats.contains(&EncFmt::Base64) {
            body["encoding_format"] = json!("base64");
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }

    /// openai embeddings response wire → IR (used when openai is the EGRESS).
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
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
        let usage = v.get("usage").map(|u| crate::billing::TokenUsage {
            input: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
            ..Default::default()
        });
        Ok(IrResp::Embeddings(EmbeddingsResp {
            model: v.get("model").and_then(Value::as_str).map(str::to_string),
            object_kind: Some("list".into()),
            embeddings,
            usage,
            ..Default::default()
        }))
    }

    /// IR → openai embeddings response wire (used when openai is the INGRESS — the caller's dialect).
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Embeddings(r) = ir else {
            return WireBody::json(Bytes::new());
        };
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
            body["usage"] = json!({ "prompt_tokens": u.input, "total_tokens": u.input.saturating_add(u.output) });
        }
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

// ---------------------------------------------------------------- image OperationHandler (real, cross-protocol)

use crate::ir::image::{ImageOp, ImageReq, ImageResp, ImageSize};
use crate::media::ImageOutput;

struct OpenAiImage;

impl OperationHandler for OpenAiImage {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError {
        crate::handlers::protocol_error("openai", status, body)
    }
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
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
        Ok(IrReq::Image(ImageReq {
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
            user: wire.get("user").and_then(Value::as_str).map(str::to_string),
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Image(r) = ir else {
            return Bytes::new();
        };
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
        if let Some(u) = &r.user {
            body["user"] = json!(u);
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let images = v
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
        Ok(IrResp::Image(ImageResp {
            created: v.get("created").and_then(Value::as_u64),
            images,
            ..Default::default()
        }))
    }
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Image(r) = ir else {
            return WireBody::json(Bytes::new());
        };
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
        WireBody::json(Bytes::from(
            serde_json::to_vec(&json!({ "created": r.created.unwrap_or(0), "data": data }))
                .unwrap_or_default(),
        ))
    }
}

// ---------------------------------------------------------------- moderation cell

struct OpenAiModeration;

impl OperationHandler for OpenAiModeration {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError {
        crate::handlers::protocol_error("openai", status, body)
    }
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let model = wire
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let input = parse_input(wire.get("input"))?;
        Ok(IrReq::Moderation(ModerationReq {
            model,
            input,
            extra: BTreeMap::new(),
        }))
    }

    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Moderation(r) = ir else {
            // An OperationHandler only ever receives its own variant; anything else is a programming error, not a
            // runtime path. Emit an empty body rather than panic.
            return Bytes::new();
        };
        let body = json!({ "model": r.model, "input": input_to_value(&r.input) });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }

    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let results = v
            .get("results")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().map(parse_result).collect())
            .unwrap_or_default();
        Ok(IrResp::Moderation(ModerationResp {
            id: v.get("id").and_then(Value::as_str).map(str::to_string),
            model: v.get("model").and_then(Value::as_str).map(str::to_string),
            results,
            extra: BTreeMap::new(),
        }))
    }

    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Moderation(r) = ir else {
            return WireBody::json(Bytes::new());
        };
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
#[path = "tests/openai_tests.rs"]
mod tests;
