// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE LEGS EXPECT THE DOOR TO STATE AND ANSWER, written down here (ARCHITECT ruling R-18:
//! the harness is a black-box rig and reads nothing of the plane but its door). Each value is a
//! fact the door shows from outside: a name its Statement carries, an index into a table its
//! Statement states, a path it dials, a status it answers, the shape it renders a refusal in.
//! None of them is read from the plane's source; a door that states another is what a leg
//! exists to catch.

use busbar_contract::abi::plane::{class_of, reason_of, RefusalClass};
use serde_json::json;

/// The transport a session door's live socket rides.
pub const WS_TRANSPORT: &str = "ws";
/// The transport a one-request door's far request rides.
pub const HTTP_TRANSPORT: &str = "http";

/// The audit kind every door's unit is recorded under.
pub const AUDIT_KIND: &str = "streaming_session";
/// The one operation every door's unit is.
pub const SESSION_OPEN_ACTION: &str = "streaming.session.open";

/// The auth style a door verifying the telephony carrier's signature states.
pub const SIGNATURE_AUTH: &str = "webhook-signature";
/// The credential style OpenAI Realtime's far end takes.
pub const REALTIME_STYLE: &str = "bearer";
/// The credential style Gemini Live's far end takes.
pub const LIVE_STYLE: &str = "x-goog-api-key";

/// The dialect names the Statement states.
pub const OPENAI_REALTIME: &str = "openai_realtime";
/// See [`OPENAI_REALTIME`].
pub const GEMINI_LIVE: &str = "gemini_live";

/// The declared need (1-based, the Statement's order) an OpenAI Realtime session's frames ride.
pub const RIDES_REALTIME_SOCKET: u32 = 4;
/// The declared need a one-request door's far request to OpenAI rides.
pub const RIDES_REALTIME_PASS: u32 = 5;
/// The declared need a Gemini Live session's frames ride.
pub const RIDES_LIVE_SOCKET: u32 = 6;

/// The billable classes the Statement states, in order, as `class/family`: a unit count names its
/// class by its index here.
pub const BILLABLE_CLASSES: [&str; 9] = [
    "audio_tokens_in/token",
    "audio_tokens_out/token",
    "text_tokens_in/token",
    "text_tokens_out/token",
    "audio_seconds_in/duration",
    "tool_calls/count",
    "image_tokens_in/token",
    "video_tokens_in/token",
    "per_session/count",
];
/// The per-session fee's class: the last of [`BILLABLE_CLASSES`].
pub const PER_SESSION_CLASS: u32 = 8;

/// The plane's own refusal code for a claim the door does not serve.
pub const REFUSAL_NO_DOOR: u32 = 1;

/// The socket a Gemini Live session dials, under the member's base URL.
pub const GEMINI_SOCKET_PATH: &str =
    "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";

/// The status a failed mint is answered with.
pub const MINT_FAILED_STATUS: u16 = 502;

/// The tick a ceilinged generation asks for after the one it was ticked at: one second on.
pub const CEILING_TICK_NS: u64 = 1_000_000_000;
/// The reason code of the error frame a session past its configured ceiling is told.
pub const SESSION_CEILING_REASON: &str = "session_expired";

/// The vendor's own copy for a bad or missing credential, which an authentication refusal reads
/// as (never the kernel's word).
const AUTH_FAILURE_MESSAGE: &str = "Incorrect API key provided.";
/// The vendor's error code beside [`AUTH_FAILURE_MESSAGE`].
const AUTH_FAILURE_CODE: &str = "invalid_api_key";

/// The OpenAI REST error envelope: `status` read as the error's type.
fn error_envelope(status: u16, message: &str, code: Option<&str>) -> Vec<u8> {
    let kind = match status {
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        429 => "rate_limit_error",
        400..=499 => "invalid_request_error",
        _ => "server_error",
    };
    serde_json::to_vec(&json!({
        "error": {"message": message, "type": kind, "param": null, "code": code}
    }))
    .unwrap_or_default()
}

/// A kernel refusal as the realtime dialects render it: the status as the error's type, the
/// kernel's words as its message.
pub fn refusal_body(status: u16, text: &str) -> Vec<u8> {
    error_envelope(status, text, None)
}

/// A kernel refusal for `reason` as the realtime dialects render it: an authentication refusal in
/// the vendor's own terms, every other one as [`refusal_body`].
pub fn refusal_render(status: u16, reason: u32, text: &str) -> Vec<u8> {
    if reason_of(reason).is_some_and(|r| class_of(r) == RefusalClass::Unauthenticated) {
        error_envelope(status, AUTH_FAILURE_MESSAGE, Some(AUTH_FAILURE_CODE))
    } else {
        refusal_body(status, text)
    }
}

/// The browser's answer to a mint the far end answered with the secret `value` expiring at
/// `expires_at` (Unix seconds): the secret and its expiry, and nothing else.
pub fn minted_answer(value: &str, expires_at: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({"value": value, "expires_at_unix": expires_at})).unwrap_or_default()
}
