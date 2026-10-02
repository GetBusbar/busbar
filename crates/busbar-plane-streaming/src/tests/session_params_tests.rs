// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/session_params.rs`.

use super::*;

fn locked() -> SessionConfig {
    SessionConfig {
        instructions: Some("stay on topic".into()),
        ..crate::config::StreamsCfg::default().session
    }
}

#[test]
fn the_telephony_lock_is_g711_both_ways() {
    let c = g711_config();
    assert_eq!(c.input_audio_format, Some(AudioFormat::G711Ulaw));
    assert_eq!(c.output_audio_format, Some(AudioFormat::G711Ulaw));
    assert_eq!(
        SessionConfig {
            input_audio_format: None,
            output_audio_format: None,
            ..c
        },
        SessionConfig::default()
    );
}

#[test]
fn a_rewrite_that_is_not_a_session_params_object_is_refused() {
    let locked = locked();
    assert!(committed_session_config(&locked, b"not json").is_err());
    for scalar in [&b"7"[..], br#""marin""#, b"null", b"[]", b"true"] {
        assert!(committed_session_config(&locked, scalar).is_err());
    }
    for bad in [
        &br#"{"output_audio_format":"flac"}"#[..],
        br#"{"voice":7}"#,
        br#"{"modalities":"audio"}"#,
    ] {
        assert!(committed_session_config(&locked, bad).is_err());
    }
}

#[test]
fn a_rewrite_patches_what_it_names_and_keeps_the_rest() {
    let locked = locked();
    assert_eq!(
        committed_session_config(&locked, b"{}").expect("identity"),
        locked
    );
    let cleared =
        committed_session_config(&locked, br#"{"instructions":null}"#).expect("an explicit null");
    assert_eq!(cleared.instructions, None);
    assert_eq!(cleared.turn_detection, locked.turn_detection);
    let voiced = committed_session_config(&locked, br#"{"voice":"marin"}"#).expect("one field");
    assert_eq!(voiced.voice.as_deref(), Some("marin"));
    assert_eq!(voiced.instructions, locked.instructions);
}
