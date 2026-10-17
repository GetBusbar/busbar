// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR TERMINATES THE BROWSER'S MEDIA (row 132; `BUSBAR-1.6.0.md` l.758-766 and the ARCHITECT
//! ticket ruling): what the plane says and reads at its two browser doors.
//!
//! - THE MINT DOOR answers a TICKET busbar mints itself (`ticket.mint`), in the OpenAI-compatible
//!   shape SDKs read: `{value, expires_at_unix}`, the value led by [`TICKET_PREFIX`]. The ticket's
//!   record is the locked session config, read back once at the SDP door (`ticket.take`).
//! - THE SDP DOOR is a datagram session busbar answers with its own description. Its upstream leg
//!   is busbar's own call to the provider: one form carrying the locked session config and, as its
//!   last part, busbar's own description (the connector frames the form's end).
//! - BUSBAR'S CALL ID names the session in the SDP answer's `Location`; the sideband door resolves it
//!   to the provider's call id.
//!
//! Pure: nothing here sends a request, reads a clock or holds a key.

use crate::codec::ir::config::SessionConfig;

/// The prefix of every ticket the plane's mint door answers: the plane's issued-id prefix, declared
/// on its Statement, so the host leads every ticket it mints for the plane with it.
pub const TICKET_PREFIX: &str = "ek_";

/// The lifetime of a minted ticket when none is requested, in seconds.
pub const DEFAULT_TTL_SECS: u64 = 600;
/// The shortest lifetime a mint asks for, in seconds.
pub const MIN_TTL_SECS: u64 = 10;
/// The longest lifetime a mint asks for, in seconds.
pub const MAX_TTL_SECS: u64 = 7200;

/// The provider's call path, and busbar's own, under which a created call is named.
pub const CALLS_PATH: &str = "/v1/realtime/calls";

/// The media type of a session description.
pub const SDP_CONTENT_TYPE: &str = "application/sdp";

/// The boundary of the upstream call's form. A description never holds `\r\n--` and this word, and
/// the connector refuses one that does.
pub const FORM_BOUNDARY: &str = "busbar-call-form";

/// The prefix of a call id, busbar's and the provider's alike.
const CALL_ID_PREFIX: &str = "rtc_";

/// The lifetime a mint asks for: the requested one, else [`DEFAULT_TTL_SECS`], held inside
/// [`MIN_TTL_SECS`]..=[`MAX_TTL_SECS`].
#[must_use]
pub fn clamped_ttl_secs(requested: Option<u64>) -> u64 {
    requested
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}

/// The caller's answer to a mint: the ticket and its expiry, and nothing else.
#[must_use]
pub fn minted_answer(ticket: &str, expires_at_unix: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "value": ticket,
        "expires_at_unix": expires_at_unix,
    }))
    .unwrap_or_default()
}

/// The record stored with a ticket: the session config its session is locked to.
///
/// # Errors
///
/// The serializer's text when the config does not serialize.
pub fn ticket_record(locked: &SessionConfig) -> Result<Vec<u8>, String> {
    serde_json::to_vec(locked).map_err(|e| format!("the locked session did not serialize: {e}"))
}

/// The session config a ticket's record locks.
///
/// # Errors
///
/// The record is not a session config.
pub fn locked_by(record: &[u8]) -> Result<SessionConfig, String> {
    serde_json::from_slice(record).map_err(|_| "the ticket's record is not a session config".into())
}

/// The upstream call's form: its content type, and its body up to the opened part busbar's own
/// description fills (the locked session config first).
///
/// # Errors
///
/// The serializer's text when the config does not serialize.
pub fn call_form(locked: &SessionConfig) -> Result<(String, Vec<u8>), String> {
    let session = ticket_record(locked)?;
    let mut lead = Vec::with_capacity(session.len() + 256);
    lead.extend_from_slice(format!("--{FORM_BOUNDARY}\r\n").as_bytes());
    lead.extend_from_slice(b"Content-Disposition: form-data; name=\"session\"\r\n");
    lead.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    lead.extend_from_slice(&session);
    lead.extend_from_slice(format!("\r\n--{FORM_BOUNDARY}\r\n").as_bytes());
    lead.extend_from_slice(b"Content-Disposition: form-data; name=\"sdp\"\r\n");
    lead.extend_from_slice(format!("Content-Type: {SDP_CONTENT_TYPE}\r\n\r\n").as_bytes());
    Ok((
        format!("multipart/form-data; boundary={FORM_BOUNDARY}"),
        lead,
    ))
}

/// Busbar's own call id, from 16 bytes of the host's randomness.
#[must_use]
pub fn call_id(random: &[u8; 16]) -> String {
    let mut id = String::with_capacity(CALL_ID_PREFIX.len() + 32);
    id.push_str(CALL_ID_PREFIX);
    for b in random {
        id.push_str(&format!("{b:02x}"));
    }
    id
}

/// The `Location` of busbar's call `id`.
#[must_use]
pub fn call_location(id: &str) -> String {
    format!("{CALLS_PATH}/{id}")
}

/// A call id in a `Location`: the last path segment that is one, less any query or fragment.
#[must_use]
pub fn call_id_of(location: &str) -> Option<String> {
    location
        .split(['?', '#'])
        .next()
        .unwrap_or(location)
        .rsplit('/')
        .find(|seg| seg.starts_with(CALL_ID_PREFIX) && seg.len() > CALL_ID_PREFIX.len())
        .map(str::to_string)
}

#[cfg(test)]
#[path = "tests/ticket_tests.rs"]
mod tests;
