// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION PARAMS A SESSION IS LOCKED TO: the telephony lock.

use crate::codec::ir::config::SessionConfig;
use crate::codec::ir::media::AudioFormat;

/// THE LOCKED CONFIG for a telephony leg: `g711_ulaw` on BOTH the input and output audio formats so the
/// 8 kHz µ-law carrier passes straight through with no resample. Callers overlay their own
/// instructions/tools onto the returned config before locking it.
#[must_use]
pub fn g711_config() -> SessionConfig {
    SessionConfig {
        input_audio_format: Some(AudioFormat::G711Ulaw),
        output_audio_format: Some(AudioFormat::G711Ulaw),
        ..SessionConfig::default()
    }
}

#[cfg(test)]
#[path = "tests/session_params_tests.rs"]
mod tests;
