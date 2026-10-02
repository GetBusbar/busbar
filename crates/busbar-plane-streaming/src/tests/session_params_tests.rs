// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/session_params.rs`.

use super::*;

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
