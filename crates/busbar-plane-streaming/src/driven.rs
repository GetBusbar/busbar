// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S ANSWERS TO THE KERNEL PLANE DRIVER (`BUSBAR-1.6.0.md` Part 3, section 12): which
//! door a claim is, and the request each session door sends its far end. Each answer is plain data,
//! in the plane's own vocabulary; writing it into the host's buffers is the door's job.
//!
//! | driver crossing | here |
//! |---|---|
//! | `arrive` | [`arrive`]: which door the claim is, its dialect and its principal need |
//! | the mint door's caller body | [`minted`], [`mint_failed`]: the ticket busbar minted, or why not |
//! | a session's far-end turn | [`Steps::route`]: the request bound for the far end |
//!
//! Busbar terminates the browser's media (row 132): the mint door answers a ticket busbar mints
//! itself and dials nothing; the SDP door is a datagram session whose far end is busbar's own call.

use crate::codec::ir::config::SessionConfig;
use crate::ticket::{call_form, minted_answer, CALLS_PATH};

/// The media type of a JSON body.
pub const JSON_CONTENT_TYPE: &str = "application/json";
/// The head field naming a body's media type.
pub const FIELD_CONTENT_TYPE: &str = "content-type";
/// The head field naming where a created call lives.
pub const FIELD_LOCATION: &str = "location";
/// The head field a whole answer states its length in.
pub const FIELD_CONTENT_LENGTH: &str = "content-length";

/// The door a claim is, by its index in the snapshot's claims (`crate::door::ROUTES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Door {
    /// `POST /v1/realtime/client_secrets`: one ticket for a browser session, minted by busbar.
    Mint,
    /// `POST /v1/realtime/calls`: one SDP offer, answered by busbar, which terminates the media.
    Sdp,
    /// The browser's sideband socket.
    Sideband,
    /// The Gemini Live socket.
    Gemini,
    /// The telephony socket.
    Twilio,
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
            _ => None,
        }
    }

    /// The door's line on the guest list: its claim (`crate::door::ROUTES`), in claim order.
    #[must_use]
    pub const fn line(self) -> crate::door::Route {
        crate::door::ROUTES[self as usize]
    }

    /// The door's dialect, by its index in the tail's dialects: its line's.
    #[must_use]
    pub const fn dialect(self) -> u32 {
        self.line().dialect
    }

    /// `true` for the door read without a credential.
    #[must_use]
    pub const fn is_open(self) -> bool {
        self.line().open()
    }

    /// `true` for a door that opens a live session rather than answering one request.
    #[must_use]
    pub const fn is_session(self) -> bool {
        matches!(
            self,
            Door::Sdp | Door::Sideband | Door::Gemini | Door::Twilio
        )
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

/// `arrive` for claim `claim`: every keyed door opens a session (or mints the ticket one opens
/// with) for a known principal.
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

// ── the plane's answer at each loop step, in the order the kernel's loop runs them ─────────────

/// THE PLANE'S ANSWER AT EACH LOOP STEP for a unit on one of its doors: what the kernel's loop asks
/// the plane at authenticate, verify, approve, admit, route, meter and audit. The door answers the
/// driver through these; nothing here reaches the kernel any other way.
pub trait Steps {
    /// AUTHENTICATE: whom a unit on this door needs.
    fn authenticate(&self) -> u32;
    /// VERIFY: where, inside the plane's section, the destination a session dials is named.
    fn verify(&self) -> &'static str;
    /// APPROVE: the grant a key must hold, as (kind, value).
    fn approve(&self) -> (&'static str, &'static str);
    /// ADMIT: the units a unit is expected to cost before the far end reports any.
    fn admit(&self) -> Vec<(u32, u64)>;
    /// ROUTE: the request a session's far-end turn sends, under its locked `config`; `call` is the
    /// provider's call id a sideband session controls. `None` when the door sends nothing.
    ///
    /// # Errors
    /// The request body's serializer text.
    fn route(&self, config: &SessionConfig, call: Option<&str>) -> Result<Option<Attempt>, String>;
    /// METER: a session's units so far, per billable class index, the zero classes left out.
    fn meter(&self, units: &crate::session_unit::CumulativeUnits) -> Vec<(u32, u64)>;
    /// AUDIT: the action a unit on this door is audited under.
    fn audit(&self) -> &'static str;
}

impl Steps for Door {
    /// Every keyed door needs a principal; a door read without a credential (none today) answers
    /// anyone.
    fn authenticate(&self) -> u32 {
        if self.is_open() {
            busbar_contract::abi::plane::PRINCIPAL_NONE
        } else {
            busbar_contract::abi::plane::PRINCIPAL_REQUIRED
        }
    }

    /// The kernel resolves `streams.session.model` through the root models and judges it.
    fn verify(&self) -> &'static str {
        crate::door::EGRESS_TARGET
    }

    /// The `session` kind, for the one pool every session is served on.
    fn approve(&self) -> (&'static str, &'static str) {
        (crate::door::SCOPE, crate::door::SESSION_POOL)
    }

    /// None: a session is admitted at open and pays for what the far end reports (and its
    /// per-session fee, which the kernel counts); the one-request doors report nothing.
    fn admit(&self) -> Vec<(u32, u64)> {
        match self {
            Door::Mint | Door::Sdp | Door::Sideband | Door::Gemini | Door::Twilio => Vec::new(),
        }
    }

    /// The socket doors dial the dialect's realtime socket (the credential is the kernel's, never
    /// in the target), a sideband session the provider's call it controls; the SDP door places
    /// busbar's own call, one form carrying the locked session and busbar's description; the mint
    /// door dials nothing.
    fn route(&self, config: &SessionConfig, call: Option<&str>) -> Result<Option<Attempt>, String> {
        Ok(match self {
            Door::Mint => None,
            Door::Sdp => Some(call_attempt(config)?),
            Door::Sideband => Some(Attempt {
                verb: "GET",
                target: match call {
                    Some(call) => format!("{REALTIME_SOCKET_PATH}?call_id={call}"),
                    None => REALTIME_SOCKET_PATH.to_string(),
                },
                fields: Vec::new(),
                body: Vec::new(),
            }),
            Door::Twilio => Some(Attempt {
                verb: "GET",
                target: REALTIME_SOCKET_PATH.to_string(),
                fields: Vec::new(),
                body: Vec::new(),
            }),
            Door::Gemini => Some(Attempt {
                verb: "GET",
                target: GEMINI_SOCKET_PATH.to_string(),
                fields: Vec::new(),
                body: Vec::new(),
            }),
        })
    }

    /// Counts only; the kernel prices nothing the plane names.
    fn meter(&self, units: &crate::session_unit::CumulativeUnits) -> Vec<(u32, u64)> {
        units
            .0
            .iter()
            .enumerate()
            .filter(|(_, n)| **n != 0)
            .map(|(i, n)| (i as u32, *n))
            .collect()
    }

    /// A session open.
    fn audit(&self) -> &'static str {
        SESSION_OPEN_ACTION
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
    pub target: String,
    /// The head fields, in order.
    pub fields: Vec<(&'static str, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The SDP door's far-end request: busbar's own call to the provider, one form carrying the locked
/// session and, as its last part, busbar's own description (the connector frames the form's end).
///
/// # Errors
/// The session's serializer text.
pub fn call_attempt(locked: &SessionConfig) -> Result<Attempt, String> {
    let (content_type, lead) = call_form(locked)?;
    Ok(Attempt {
        verb: "POST",
        target: CALLS_PATH.to_string(),
        fields: vec![(FIELD_CONTENT_TYPE, content_type)],
        body: lead,
    })
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
}

/// The status the served plane answers a failed mint with.
pub const MINT_FAILED_STATUS: u16 = 502;

/// The served plane's 502 for a mint that failed for `reason`.
#[must_use]
pub fn mint_failed(reason: &str) -> Reply {
    Reply {
        status: MINT_FAILED_STATUS,
        fields: Vec::new(),
        body: format!(
            "streaming ephemeral-secret mint failed: ephemeral token mint failed: {reason}"
        )
        .into_bytes(),
    }
}

/// The caller's answer to a mint busbar answered: the ticket and its expiry.
#[must_use]
pub fn minted(ticket: &str, expires_at_unix: u64) -> Reply {
    Reply {
        status: 200,
        fields: vec![(FIELD_CONTENT_TYPE, JSON_CONTENT_TYPE.to_string())],
        body: minted_answer(ticket, expires_at_unix),
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
