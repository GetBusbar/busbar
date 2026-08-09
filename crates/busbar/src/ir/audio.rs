// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audio IRs — two structurally-opposite operations in one module:
//!
//! - **Transcription** (STT): multipart audio IN → text OUT. `target_language` folds translation in
//!   (not a third op). Billing is model-dependent: `Duration` (whisper-1) | `Tokens` (gpt-4o-transcribe).
//! - **Speech** (TTS): text IN → binary audio OUT. Billing: `Characters` (tts-1) | `Tokens` (gpt-4o-mini-tts).
//!
//! Both share the [`crate::media::MediaBlob`] payload (audio in / audio out). Split request/response
//! per. Because audio billing is polymorphic per model, the response stores `Option<Billing>`
//! directly rather than a token struct.

use crate::billing::Billing;
use crate::lossless::SourceScopedExtra;
use crate::media::MediaBlob;

/// Timestamp detail requested on a transcription (whisper-1 only; requires verbose_json).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimestampGranularity {
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
pub(crate) struct Word {
    pub(crate) word: String,
    pub(crate) start: f64,
    pub(crate) end: f64,
}

/// A transcription segment (verbose_json / diarized).
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Segment {
    pub(crate) id: i64,
    pub(crate) start: f64,
    pub(crate) end: f64,
    pub(crate) text: String,
    pub(crate) avg_logprob: Option<f64>,
    pub(crate) no_speech_prob: Option<f64>,
    pub(crate) compression_ratio: Option<f64>,
    pub(crate) speaker: Option<String>, // diarization
}

// ---------- Transcription (STT): blob IN -> text OUT ----------

/// Transcription request IR. `audio` is `Option` only so `Default` derives; a real request always
/// carries it.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct TranscriptionReq {
    pub(crate) audio: Option<MediaBlob>,
    pub(crate) model: String,
    pub(crate) source_language: Option<String>, // ISO-639-1
    /// `None` = transcribe; `Some("en")` (or other) = TRANSLATE — folds `/audio/translations` in.
    pub(crate) target_language: Option<String>,
    pub(crate) prompt: Option<String>,
    pub(crate) response_format: Option<String>, // json/text/srt/verbose_json/vtt/diarized_json
    pub(crate) temperature: Option<f32>,
    pub(crate) timestamp_granularities: Vec<TimestampGranularity>,
    pub(crate) stream: bool,
    pub(crate) extra: SourceScopedExtra,
}

/// Transcription response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct TranscriptionResp {
    pub(crate) text: String,
    pub(crate) detected_language: Option<String>,
    pub(crate) duration_seconds: Option<f64>,
    pub(crate) segments: Vec<Segment>,
    pub(crate) words: Vec<Word>,
    /// `Duration{seconds}` (whisper-1) | `Tokens` (gpt-4o-transcribe) — model-dependent.
    pub(crate) usage: Option<Billing>,
    pub(crate) extra: SourceScopedExtra,
}

impl TranscriptionResp {
    pub(crate) fn billing(&self) -> Option<Billing> {
        self.usage.clone()
    }
}

// ---------- Speech (TTS): text IN -> blob OUT ----------

/// Speech request IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct SpeechReq {
    pub(crate) input: String,
    pub(crate) model: String,
    pub(crate) voice: String,
    pub(crate) response_format: Option<String>, // mp3/opus/aac/flac/wav/pcm (Gemini → pcm)
    pub(crate) speed: Option<f32>,              // 0.25–4.0 (OpenAI)
    pub(crate) instructions: Option<String>,    // gpt-4o-mini-tts / Gemini style
    pub(crate) speakers: Vec<(String, String)>, // Gemini multi-speaker (speaker, voice)
    pub(crate) stream: bool,
    pub(crate) extra: SourceScopedExtra,
}

/// Speech response IR (binary audio out).
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct SpeechResp {
    pub(crate) audio: Option<MediaBlob>,
    /// `Characters{count}` (tts-1) | `Tokens` (gpt-4o-mini-tts) — model-dependent.
    pub(crate) usage: Option<Billing>,
    pub(crate) extra: SourceScopedExtra,
}

impl SpeechResp {
    pub(crate) fn billing(&self) -> Option<Billing> {
        self.usage.clone()
    }
}

#[cfg(test)]
#[path = "tests/audio_tests.rs"]
mod tests;
