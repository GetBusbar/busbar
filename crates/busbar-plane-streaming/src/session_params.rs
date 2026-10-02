// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION PARAMS A SESSION IS LOCKED TO: the telephony lock, and how a committed rewrite of the
//! session-open params is read back over the locked ones.

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

/// A committed rewrite of the session-open params, read back over the `locked` ones.
///
/// The rewrite is a PATCH: the params are optional field by field on the wire, so the committed
/// object is merged over the locked params. A key the rewrite names wins (an explicit `null` clears
/// it); a key it does not name keeps the locked value. The merge happens before the decode, so a
/// patch naming one bad field refuses rather than being quietly dropped.
///
/// A well-formed JSON scalar is refused too: the params are an object on every wire the plane
/// speaks, and the value replaces the locked [`SessionConfig`].
///
/// # Errors
/// Output that is not JSON, not an object, or not a session config, each with its reason.
pub fn committed_session_config(
    locked: &SessionConfig,
    args_json: &[u8],
) -> Result<SessionConfig, String> {
    let patch: serde_json::Value =
        serde_json::from_slice(args_json).map_err(|e| format!("the output is not JSON: {e}"))?;
    let serde_json::Value::Object(patch) = patch else {
        return Err("the output is JSON but not a session-params object".to_string());
    };
    // The locked params as the rewrite was handed them, so the merge is over exactly the key set it
    // screened.
    let Ok(serde_json::Value::Object(mut merged)) = serde_json::to_value(locked) else {
        return Err(
            "the plane's own locked session params did not project to an object".to_string(),
        );
    };
    // A key the rewrite NAMED wins; a key it did not name keeps the locked value.
    merged.extend(patch);
    serde_json::from_value::<SessionConfig>(serde_json::Value::Object(merged))
        .map_err(|e| format!("the output is not a session config: {e}"))
}

#[cfg(test)]
#[path = "tests/session_params_tests.rs"]
mod tests;
