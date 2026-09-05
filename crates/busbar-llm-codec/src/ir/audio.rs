// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audio IRs — two structurally-opposite operations in one module:
//!
//! - **Transcription** (STT): multipart audio IN → text OUT. `target_language` folds translation in
//!   (not a third op). Billing is model-dependent: `Duration` (whisper-1) | `Tokens` (gpt-4o-transcribe).
//! - **Speech** (TTS): text IN → binary audio OUT. Billing: `Characters` (tts-1) | `Tokens` (gpt-4o-mini-tts).
//!
//! Both share the [`busbar_substrate_values::media::MediaBlob`] payload (audio in / audio out). Split request/response
//! per. Because audio billing is polymorphic per model, the response stores `Option<Billing>`
//! directly rather than a token struct.

use busbar_substrate_values::billing::Billing;
use busbar_substrate_values::lossless::SourceScopedExtra;
use busbar_substrate_values::media::MediaBlob;

/// Timestamp detail requested on a transcription (whisper-1 only; requires verbose_json).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampGranularity {
    /// whisper-1's `timestamp_granularities` are modelled by the superset IR; no 1.5.0
    /// transcription reader parses the parameter, so nothing constructs this variant yet.
    #[allow(dead_code)]
    Word,
    /// See `Word` above.
    #[allow(dead_code)]
    Segment,
}

/// A word with start/end offsets (seconds).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Word {
    pub word: String,
    pub start: f64,
    pub end: f64,
}

/// A transcription segment (verbose_json / diarized).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Segment {
    pub id: i64,
    pub start: f64,
    pub end: f64,
    pub text: String,
    pub avg_logprob: Option<f64>,
    pub no_speech_prob: Option<f64>,
    pub compression_ratio: Option<f64>,
    pub speaker: Option<String>, // diarization
}

// ---------- Transcription (STT): blob IN -> text OUT ----------

/// Transcription request IR. `audio` is `Option` only so `Default` derives; a real request always
/// carries it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TranscriptionReq {
    pub audio: Option<MediaBlob>,
    pub model: String,
    pub source_language: Option<String>, // ISO-639-1
    /// `None` = transcribe; `Some("en")` (or other) = TRANSLATE — folds `/audio/translations` in.
    pub target_language: Option<String>,
    pub prompt: Option<String>,
    pub response_format: Option<String>, // json/text/srt/verbose_json/vtt/diarized_json
    pub temperature: Option<f32>,
    pub timestamp_granularities: Vec<TimestampGranularity>,
    pub stream: bool,
    pub extra: SourceScopedExtra,
}

/// THE TRANSCRIPTION FAMILY'S WALK — this IR's answer to [`busbar_substrate_values::ir::facts::IrFacts`]. The audio
/// blob is BINARY and unscreenable → one [`busbar_substrate_values::ir::facts::ContentItem::Opaque`]
/// (present-but-unscreenable, never silently empty). The `prompt` is caller free-text forwarded
/// upstream — reachable ONLY through the byte-aware hook seam (a multipart body never reaches the
/// `&Value` path; FATAL-1) → [`busbar_substrate_values::ir::facts::ContentItem::Text`]. `source_language`/
/// `target_language`/`response_format` are enum roles, not content.
impl busbar_substrate_values::ir::facts::IrFacts for TranscriptionReq {
    fn verb(&self) -> busbar_api::operation::Operation {
        busbar_api::operation::Operation::TRANSCRIPTION
    }

    fn wants_stream(&self) -> bool {
        self.stream
    }

    fn end_user(&self) -> Option<&str> {
        None
    }

    fn shape(&self) -> busbar_substrate_values::ir::facts::Shape {
        let items = busbar_substrate_values::ir::facts::IrFacts::content(self);
        let (text_chars, system_chars) = busbar_substrate_values::ir::facts::Shape::counts_over(&items);
        busbar_substrate_values::ir::facts::Shape {
            turn_count: 1,
            has_tools: false,
            tool_count: 0,
            text_chars,
            system_chars,
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<busbar_substrate_values::ir::facts::ContentItem<'_>> {
        use busbar_substrate_values::ir::facts::{ContentItem, Slot, OPAQUE_CONTENT_MARKER};
        use std::borrow::Cow;
        let mut out = Vec::new();
        if self.audio.is_some() {
            out.push(ContentItem::Opaque {
                author: "user",
                slot: Slot::Turn(0),
                label: "audio",
                marker: OPAQUE_CONTENT_MARKER,
            });
        }
        if let Some(prompt) = &self.prompt {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(prompt.as_str()),
            });
        }
        out
    }
}

/// Transcription response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TranscriptionResp {
    pub text: String,
    pub detected_language: Option<String>,
    pub duration_seconds: Option<f64>,
    pub segments: Vec<Segment>,
    pub words: Vec<Word>,
    /// The response format the body was delivered in, so a writer can reproduce the wire SHAPE the
    /// caller asked for. OpenAI serves `text`/`srt`/`vtt` as a raw `text/plain` body (not JSON), so a
    /// reader that parsed a non-JSON body records the plain shape here and the writer re-emits
    /// `text/plain` instead of JSON-wrapping. `None`/`json`/`verbose_json` → the JSON envelope.
    pub response_format: Option<String>,
    /// `Duration{seconds}` (whisper-1) | `Tokens` (gpt-4o-transcribe) — model-dependent.
    pub usage: Option<Billing>,
    pub extra: SourceScopedExtra,
}

impl TranscriptionResp {
    pub fn billing(&self) -> Option<Billing> {
        self.usage.clone()
    }
}

// ---------- Speech (TTS): text IN -> blob OUT ----------

/// Speech request IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SpeechReq {
    pub input: String,
    pub model: String,
    pub voice: String,
    pub response_format: Option<String>, // mp3/opus/aac/flac/wav/pcm (Gemini → pcm)
    pub speed: Option<f32>,              // 0.25–4.0 (OpenAI)
    pub instructions: Option<String>,    // gpt-4o-mini-tts / Gemini style
    pub speakers: Vec<(String, String)>, // Gemini multi-speaker (speaker, voice)
    pub stream: bool,
    pub extra: SourceScopedExtra,
}

impl SpeechReq {
    /// THE TTS REQUEST-SEAM METER. TTS is billed by the SIZE OF THE INPUT (tts-1/-hd: characters),
    /// and that quantity is knowable ONLY here — the response is opaque audio with no usage object, so
    /// the response reader can only mark the synthesis `Billing::Flat` ("a request happened"), never
    /// the true unit (the `SpeechResp::billing` degrade the readers document). This method resolves the
    /// exact character count from the request `input` (the one place it exists), the faithful
    /// request-seam representation of the billable quantity. Token-metered TTS models
    /// (`gpt-4o-mini-tts`) re-derive tokens at pricing time; the exact character count carried here is
    /// strictly more information than the former response-side `Flat`.
    pub fn billing(&self) -> Option<Billing> {
        Some(Billing::Characters {
            count: self.input.chars().count() as u64,
        })
    }
}

/// THE SPEECH FAMILY'S WALK — this IR's answer to [`busbar_substrate_values::ir::facts::IrFacts`]. Every caller
/// free-text field is projected to [`busbar_substrate_values::ir::facts::ContentItem::Text`]: the `input` to
/// synthesize, the `instructions` style prompt when present (FATAL-2 — forwarded verbatim by both
/// writers), and each multi-speaker NAME. The speaker VOICE and `response_format`/`speed` are
/// provider knobs (voice ids, format enums), not caller free-text, and stay out.
impl busbar_substrate_values::ir::facts::IrFacts for SpeechReq {
    fn verb(&self) -> busbar_api::operation::Operation {
        busbar_api::operation::Operation::SPEECH
    }

    fn wants_stream(&self) -> bool {
        self.stream
    }

    fn end_user(&self) -> Option<&str> {
        None
    }

    fn shape(&self) -> busbar_substrate_values::ir::facts::Shape {
        let items = busbar_substrate_values::ir::facts::IrFacts::content(self);
        let (text_chars, system_chars) = busbar_substrate_values::ir::facts::Shape::counts_over(&items);
        busbar_substrate_values::ir::facts::Shape {
            turn_count: 1,
            has_tools: false,
            tool_count: 0,
            text_chars,
            system_chars,
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<busbar_substrate_values::ir::facts::ContentItem<'_>> {
        use busbar_substrate_values::ir::facts::{ContentItem, Slot};
        use std::borrow::Cow;
        let mut out = Vec::new();
        out.push(ContentItem::Text {
            author: "user",
            slot: Slot::Turn(0),
            text: Cow::Borrowed(self.input.as_str()),
        });
        if let Some(instructions) = &self.instructions {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(instructions.as_str()),
            });
        }
        for (name, _voice) in &self.speakers {
            out.push(ContentItem::Text {
                author: "user",
                slot: Slot::Turn(0),
                text: Cow::Borrowed(name.as_str()),
            });
        }
        out
    }
}

/// Speech response IR (binary audio out).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SpeechResp {
    pub audio: Option<MediaBlob>,
    /// `Characters{count}` (tts-1) | `Tokens` (gpt-4o-mini-tts) — model-dependent.
    pub usage: Option<Billing>,
    pub extra: SourceScopedExtra,
}

impl SpeechResp {
    pub fn billing(&self) -> Option<Billing> {
        self.usage.clone()
    }
}

#[cfg(test)]
#[path = "tests/audio_tests.rs"]
mod tests;
