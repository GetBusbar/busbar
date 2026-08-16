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

/// Transcription response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TranscriptionResp {
    pub text: String,
    pub detected_language: Option<String>,
    pub duration_seconds: Option<f64>,
    pub segments: Vec<Segment>,
    pub words: Vec<Word>,
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
