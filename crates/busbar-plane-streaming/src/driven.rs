// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S ANSWERS TO THE KERNEL PLANE DRIVER for its two one-request doors (`BUSBAR-1.6.0.md`
//! Part 3, section 12): the ephemeral-secret mint and the SDP offer. Each answer is plain data, in
//! the plane's own vocabulary; writing it into the host's buffers is the door's job.
//!
//! | driver crossing | here |
//! |---|---|
//! | `arrive` | [`arrive`]: which door the claim is, its dialect and its principal need |
//! | `on_piece`, ATTEMPT | [`mint_attempt`], [`sdp_attempt`]: the request bound for the far end |
//! | `on_piece`, from the far end | [`mint_reply`], [`sdp_reply`]: what the caller is answered |
//!
//! The caller's texts are the served plane's, byte for byte, where the far end answered. A far end
//! that could not be reached is the kernel's route terminal and is not answered here.

use crate::broker::{
    clamped_ttl_secs, mint_request_body, minted_answer, read_minted, rtc_call_id_of, CALLS_PATH,
    CLIENT_SECRETS_PATH, SAFETY_IDENTIFIER_HEADER, SDP_CONTENT_TYPE,
};
use crate::codec::ir::config::SessionConfig;

/// The media type of a JSON body.
pub const JSON_CONTENT_TYPE: &str = "application/json";
/// The head field naming a body's media type.
pub const FIELD_CONTENT_TYPE: &str = "content-type";
/// The head field naming where a created call lives.
pub const FIELD_LOCATION: &str = "location";

/// The door a claim is, by its index in the snapshot's claims (`crate::door::ROUTES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Door {
    /// `POST /v1/realtime/client_secrets`: one ephemeral secret for a browser session.
    Mint,
    /// `POST /v1/realtime/calls`: one SDP offer, relayed to the provider.
    Sdp,
    /// The browser's sideband socket.
    Sideband,
    /// The Gemini Live socket.
    Gemini,
    /// The telephony socket.
    Twilio,
    /// The protected-resource metadata document, read without a credential.
    Metadata,
}

impl Door {
    /// The door of claim `claim`; `None` for a claim the plane never published.
    #[must_use]
    pub const fn of(claim: u32) -> Option<Door> {
        match claim {
            0 => Some(Door::Mint),
            1 => Some(Door::Sdp),
            2 => Some(Door::Sideband),
            3 => Some(Door::Gemini),
            4 => Some(Door::Twilio),
            5 => Some(Door::Metadata),
            _ => None,
        }
    }

    /// The door's dialect, by its index in the tail's dialects.
    #[must_use]
    pub const fn dialect(self) -> u32 {
        match self {
            Door::Mint | Door::Sdp | Door::Sideband | Door::Metadata => 0,
            Door::Gemini => 1,
            Door::Twilio => 2,
        }
    }

    /// `true` for the door read without a credential.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Door::Metadata)
    }

    /// `true` for a door that opens a live session rather than answering one request.
    #[must_use]
    pub const fn is_session(self) -> bool {
        matches!(self, Door::Sideband | Door::Gemini | Door::Twilio)
    }
}

/// What `arrive` answers for a claimed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    /// The door.
    pub door: Door,
    /// Index into the tail's op classes: the session open, every door's one operation.
    pub op_class: u32,
    /// Index into the tail's dialects.
    pub dialect: u32,
}

/// `arrive` for claim `claim`: every keyed door opens a session (or brokers one) for a known
/// principal; the metadata door answers anyone.
#[must_use]
pub const fn arrive(claim: u32) -> Option<Arrival> {
    match Door::of(claim) {
        Some(door) => Some(Arrival {
            door,
            op_class: 0,
            dialect: door.dialect(),
        }),
        None => None,
    }
}

// ── the plane's answer at each loop step (THE DESIGN §1's order) ─────────────────────────────────

/// AUTHENTICATE: whom a unit on `door` needs. Every keyed door needs a principal; the metadata
/// document answers anyone.
#[must_use]
pub const fn authenticate(door: Door) -> u32 {
    if door.is_open() {
        busbar_contract::abi::plane::PRINCIPAL_NONE
    } else {
        busbar_contract::abi::plane::PRINCIPAL_REQUIRED
    }
}

/// VERIFY: where, inside the plane's section, the destination a session dials is named. The kernel
/// resolves it through the root models and judges it.
#[must_use]
pub const fn verify() -> &'static str {
    crate::door::EGRESS_TARGET
}

/// APPROVE: the grant a key must hold to open a session here: the `session` kind, for the one pool
/// every session is served on.
#[must_use]
pub const fn approve() -> (&'static str, &'static str) {
    (crate::door::SCOPE, crate::door::SESSION_POOL)
}

/// ADMIT: the units a unit on `door` is expected to cost before the far end reports any. None: a
/// session is admitted at open and pays for what the far end reports (and its per-session fee,
/// which the kernel counts); the one-request doors report nothing.
#[must_use]
pub fn admit(door: Door) -> Vec<(u32, u64)> {
    match door {
        Door::Mint | Door::Sdp | Door::Sideband | Door::Gemini | Door::Twilio | Door::Metadata => {
            Vec::new()
        }
    }
}

/// ROUTE: the request an attempt on `door` sends the far end. The session doors dial the dialect's
/// realtime socket (the credential is the kernel's, never in the target); the mint and SDP doors send
/// their one request; the metadata document is answered here and sends nothing.
///
/// # Errors
/// The mint body's serializer text.
pub fn route(
    door: Door,
    config: &SessionConfig,
    caller_ref: Option<&str>,
    body: &[u8],
) -> Result<Option<Attempt>, String> {
    Ok(match door {
        Door::Mint => Some(mint_attempt(config, caller_ref, None)?),
        Door::Sdp => Some(sdp_attempt(body)),
        Door::Sideband | Door::Twilio => Some(Attempt {
            verb: "GET",
            target: REALTIME_SOCKET_PATH,
            fields: Vec::new(),
            body: Vec::new(),
        }),
        Door::Gemini => Some(Attempt {
            verb: "GET",
            target: GEMINI_SOCKET_PATH,
            fields: Vec::new(),
            body: Vec::new(),
        }),
        Door::Metadata => None,
    })
}

/// METER: a session's units so far, per billable class index, the zero classes left out. Counts
/// only; the kernel prices nothing the plane names.
#[must_use]
pub fn meter(units: &crate::session_unit::CumulativeUnits) -> Vec<(u32, u64)> {
    units
        .0
        .iter()
        .enumerate()
        .filter(|(_, n)| **n != 0)
        .map(|(i, n)| (i as u32, *n))
        .collect()
}

/// AUDIT: the action a unit on `door` is audited under.
#[must_use]
pub const fn audit(door: Door) -> &'static str {
    match door {
        Door::Metadata => "streaming.metadata.read",
        _ => SESSION_OPEN_ACTION,
    }
}

/// The action a session open is audited under.
pub const SESSION_OPEN_ACTION: &str = "streaming.session.open";

/// The realtime socket an OpenAI Realtime session dials, under the member's base URL.
pub const REALTIME_SOCKET_PATH: &str = "/v1/realtime";

/// The socket a Gemini Live session dials, under the member's base URL.
pub const GEMINI_SOCKET_PATH: &str =
    "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";

/// A request bound for the far end: verb and target explicit, then its head fields and body. The
/// kernel adds the credential and sends it; the target is under the member's base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The verb.
    pub verb: &'static str,
    /// The target, under the member's base URL.
    pub target: &'static str,
    /// The head fields, in order.
    pub fields: Vec<(&'static str, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The mint's ATTEMPT: the locked session params the browser's session is bound to, the secret's
/// lifetime (the requested one held inside its bounds), and the caller named for attribution.
///
/// # Errors
/// The body's serializer text.
pub fn mint_attempt(
    config: &SessionConfig,
    caller: Option<&str>,
    requested_ttl_secs: Option<u64>,
) -> Result<Attempt, String> {
    let mut fields = vec![(FIELD_CONTENT_TYPE, JSON_CONTENT_TYPE.to_string())];
    if let Some(r) = caller.filter(|r| !r.is_empty()) {
        fields.push((SAFETY_IDENTIFIER_HEADER, r.to_string()));
    }
    Ok(Attempt {
        verb: "POST",
        target: CLIENT_SECRETS_PATH,
        fields,
        body: mint_request_body(clamped_ttl_secs(requested_ttl_secs), config)?,
    })
}

/// The SDP offer's ATTEMPT: the caller's offer, relayed as it arrived.
#[must_use]
pub fn sdp_attempt(offer: &[u8]) -> Attempt {
    Attempt {
        verb: "POST",
        target: CALLS_PATH,
        fields: vec![(FIELD_CONTENT_TYPE, SDP_CONTENT_TYPE.to_string())],
        body: offer.to_vec(),
    }
}

/// What the caller is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The status.
    pub status: u16,
    /// The head fields, in order.
    pub fields: Vec<(&'static str, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// For an SDP answer that names its call: the provider's `rtc_` call id, for the session record.
    pub rtc_call_id: Option<String>,
}

/// The status the served plane answers a failed mint with.
pub const MINT_FAILED_STATUS: u16 = 502;

fn mint_failed(reason: &str) -> Reply {
    Reply {
        status: MINT_FAILED_STATUS,
        fields: Vec::new(),
        body: format!(
            "streaming ephemeral-secret mint failed: ephemeral token mint failed: {reason}"
        )
        .into_bytes(),
        rtc_call_id: None,
    }
}

/// The caller's answer to the far end's mint answer (`status`, `body`): the secret and its expiry on
/// a success that carries one, else the served plane's 502 and its text.
#[must_use]
pub fn mint_reply(status: u16, body: &[u8]) -> Reply {
    if !(200..300).contains(&status) {
        return mint_failed(&format!(
            "client-secret endpoint returned {}",
            status_text(status)
        ));
    }
    match read_minted(body) {
        Ok(minted) => Reply {
            status: 200,
            fields: vec![(FIELD_CONTENT_TYPE, JSON_CONTENT_TYPE.to_string())],
            body: minted_answer(&minted),
            rtc_call_id: None,
        },
        Err(reason) => mint_failed(&reason),
    }
}

/// The caller's answer to the far end's SDP answer: its status, its body as an SDP answer, and its
/// `Location` when it named one; the call id in that `Location` goes to the session record.
#[must_use]
pub fn sdp_reply(status: u16, location: Option<&str>, body: &[u8]) -> Reply {
    let mut fields = vec![(FIELD_CONTENT_TYPE, SDP_CONTENT_TYPE.to_string())];
    if let Some(loc) = location {
        fields.push((FIELD_LOCATION, loc.to_string()));
    }
    Reply {
        status,
        fields,
        body: body.to_vec(),
        rtc_call_id: location.and_then(rtc_call_id_of),
    }
}

/// A status as the served plane printed it: the number and its canonical reason phrase, or the
/// number alone for one with none.
#[must_use]
pub fn status_text(status: u16) -> String {
    match reason_phrase(status) {
        Some(reason) => format!("{status} {reason}"),
        None => status.to_string(),
    }
}

/// The canonical reason phrase of a registered status (RFC 9110 and its registry).
#[must_use]
pub const fn reason_phrase(status: u16) -> Option<&'static str> {
    Some(match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => return None,
    })
}

#[cfg(test)]
#[path = "tests/driven_tests.rs"]
mod tests;

/// The protected-resource metadata document for `audience`: the audience a token at the plane's
/// doors must carry, and the one place a bearer token is accepted. The plane names no authorization
/// server: it is configured with none.
#[must_use]
pub fn metadata_reply(audience: &str) -> Reply {
    Reply {
        status: 200,
        fields: vec![
            ("cache-control", "public, max-age=3600".to_string()),
            (
                FIELD_CONTENT_TYPE,
                "application/json; charset=utf-8".to_string(),
            ),
        ],
        body: serde_json::to_vec(&serde_json::json!({
            "resource": audience,
            "bearer_methods_supported": ["header"],
        }))
        .unwrap_or_default(),
        rtc_call_id: None,
    }
}
