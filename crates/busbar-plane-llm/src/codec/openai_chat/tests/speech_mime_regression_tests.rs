// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regression net: `read_speech_response` must derive the audio Content-Type from the response's
//! own container signature rather than hardcoding `audio/mpeg`. The reader has no access to the
//! originating request's `response_format` nor the upstream header, so a wav/opus/flac/aac blob
//! previously surfaced to the caller mislabeled as `audio/mpeg`.

use super::*;

fn mime_of(wire: &[u8]) -> String {
    read_speech_response(wire)
        .expect("read")
        .audio
        .expect("audio blob")
        .mime_type
}

#[test]
fn wav_riff_wave_signature_is_audio_wav() {
    let mut b = b"RIFF\0\0\0\0WAVE".to_vec();
    b.extend_from_slice(&[0u8; 8]);
    assert_eq!(mime_of(&b), "audio/wav");
}

#[test]
fn flac_signature_is_audio_flac() {
    assert_eq!(mime_of(b"fLaC\0\0\0\x22"), "audio/flac");
}

#[test]
fn ogg_opus_signature_is_audio_opus() {
    assert_eq!(mime_of(b"OggS\0\x02\0\0"), "audio/opus");
}

#[test]
fn adts_aac_syncword_is_audio_aac() {
    assert_eq!(mime_of(&[0xFF, 0xF1, 0x50, 0x80]), "audio/aac");
    assert_eq!(mime_of(&[0xFF, 0xF9, 0x50, 0x80]), "audio/aac");
}

#[test]
fn id3_and_default_are_audio_mpeg() {
    // ID3-tagged mp3.
    assert_eq!(mime_of(b"ID3\x03\0\0\0"), "audio/mpeg");
    // Raw mp3 frame sync (0xFFFB) and any unrecognized/headerless (pcm) body default to mp3 —
    // the endpoint's own default response_format.
    assert_eq!(mime_of(&[0xFF, 0xFB, 0x90, 0x00]), "audio/mpeg");
    assert_eq!(mime_of(&[0u8; 16]), "audio/mpeg");
}
