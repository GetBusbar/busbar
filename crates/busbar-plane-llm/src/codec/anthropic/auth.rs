// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Anthropic's native error envelope. (Its egress credential is not built here: the dialect
//! DECLARES its scheme on `DECL` and the kernel presents the lane credential under it.)

use super::*;

impl AnthropicWriter {
    /// Build the native Anthropic error envelope for a resolved `error.type`.
    ///
    /// Current Anthropic API error bodies carry a top-level `request_id` (`req_...`) alongside the
    /// `error` object. busbar synthesizes this envelope itself (no upstream request to forward), so
    /// we mint one to match the native shape — the SDK doesn't require it to decode the typed
    /// exception, but its absence is a distinguishability tell. Shared by every `write_error` exit
    /// so the status-driven and kind-driven paths emit byte-identical envelopes.
    pub(super) fn error_envelope(error_type: &str, message: &str) -> serde_json::Value {
        Self::error_envelope_with_request_id(error_type, message, &synth_request_id())
    }

    /// The same envelope, with the top-level `request_id` supplied rather than minted.
    ///
    /// This is the form a caller that may not read a random source uses: it builds the id from
    /// entropy it was handed (see [`request_id_from_entropy`]) and passes it in. Both forms produce
    /// the identical document — the only difference is where the id's bytes came from.
    pub fn error_envelope_with_request_id(
        error_type: &str,
        message: &str,
        request_id: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "type": "error",
            "error": {
                "type": error_type,
                "message": message,
            },
            "request_id": request_id,
        })
    }
}
