// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE ARRIVAL ON THE JSON-RPC LINE, decided once and purely: a reader over the request's head
//! fields and the body in, a [`Disposition`] out. The door's `arrive` states the disposition in the
//! plane ABI's words, and its `refusal` renders a refused one ([`render`]); this module is the
//! disposition and the words, so both are tested without a door.
//!
//! The order is the served engine's (`busbar-a2a` `receive::invoke_inner`, then the shared
//! JSON-RPC sequence it runs). The steps before it are the kernel's: whether the plane is present,
//! and governance (spec ruling log 2026-09-30, a2a plane: the kernel owns admission). What the plane
//! decides (spec ruling log 2026-09-30, new-plane refusals follow predev bytes):
//!
//! 0. An `Origin` that is neither loopback nor listed is `403` + `-32004`, judged first, by the
//!    contract's one rule ([`busbar_contract::jsonrpc::origin_admitted`]); this plane lists none.
//! 1. A declared `Content-Type` that is not a JSON media type is `415` + `-32005`, judged BEFORE the
//!    body is parsed, so a header fault is never answered as a body fault. No `Content-Type` at all
//!    is not refused here.
//! 2. An `A2A-Version` this endpoint does not speak is `400` + `-32009`. Absent or empty is `0.3`;
//!    negotiation is on `Major.Minor`.
//! 3. The body must be JSON (`400` + `-32700`) and one JSON-RPC message (`400` + `-32600`, the
//!    contract's reader, echoing the id it could read).
//! 4. A NOTIFICATION is acknowledged and never answered.
//! 5. A request names a method; [`crate::ops::relay_class`] classes it, a method the vocabulary
//!    does not list included: the engine relays that one verbatim, so it is never refused here.
//!
//! Every refusal before the body is read carries the id `null` (JSON-RPC 2.0 section 5).

use serde_json::{json, Value};

use crate::ops::{self, MethodRow};

/// The media type the JSON-RPC binding names.
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// The A2A protocol versions this endpoint speaks, oldest first (the engine's
/// `SUPPORTED_A2A_VERSIONS`).
pub const SUPPORTED_VERSIONS: &[&str] = &["0.3", "1.0"];

/// The version a caller that names none speaks: A2A's own default.
pub const DEFAULT_VERSION: &str = "0.3";

/// The head field naming the body's media type.
pub const H_CONTENT_TYPE: &str = "content-type";

/// The head field naming the protocol version the caller asks for.
pub const H_VERSION: &str = "a2a-version";

/// The head field naming the browser origin a request was driven from.
pub const H_ORIGIN: &str = "origin";

/// The message an `Origin` this plane does not admit is refused with.
pub const ORIGIN_REFUSED: &str =
    "this Origin is not allowed: a browser origin may drive this plane only from loopback";

/// The message a body that is not JSON is refused with.
pub const NOT_JSON: &str = "the request body is not JSON";

/// `-32700`: the body is not JSON.
pub const CODE_PARSE: i64 = busbar_contract::jsonrpc::PARSE_ERROR;

/// `-32004`: the operation is not supported here; the code a kernel refusal is rendered under.
pub const CODE_UNSUPPORTED_OPERATION: i64 = -32004;

/// `-32005`: the declared media type is not one this endpoint reads.
pub const CODE_CONTENT_TYPE_NOT_SUPPORTED: i64 = -32005;

/// `-32009`: the asked version is not one this endpoint speaks.
pub const CODE_VERSION_NOT_SUPPORTED: i64 = -32009;

/// The status every refusal before a method is read answers with, but the media-type one.
pub const STATUS_BAD_REQUEST: u32 = 400;

/// The status of a media type this endpoint does not read.
pub const STATUS_UNSUPPORTED_MEDIA_TYPE: u32 = 415;

/// The status of an `Origin` this plane does not admit.
pub const STATUS_FORBIDDEN: u32 = 403;

/// The status of a notification: received, never answered.
pub const STATUS_ACCEPTED: u32 = 202;

/// A refusal decided at arrival, or rendered for the kernel: its status, the id it echoes, its code
/// and its sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The status.
    pub status: u32,
    /// The request id the body echoes; `None` = `null`.
    pub id: Option<Value>,
    /// The JSON-RPC error code.
    pub code: i64,
    /// The sentence.
    pub message: String,
}

impl Refusal {
    /// A refusal before any id could be read.
    fn unnamed(status: u32, code: i64, message: impl Into<String>) -> Self {
        Refusal {
            status,
            id: None,
            code,
            message: message.into(),
        }
    }

    /// The words a refused `arrive` carries in its `head.error`, read back by [`Refusal::from_words`]:
    /// `<status> <code> <id as JSON>`, a newline, then the message AS IS. The message is never
    /// escaped, so words that echo a field line the caller sent are that line plus a fixed sentence,
    /// and stay under `MAX_REFUSAL_TEXT` for every field line a transport admits.
    #[must_use]
    pub fn words(&self) -> String {
        let id = self
            .id
            .as_ref()
            .map_or_else(|| "null".to_string(), Value::to_string);
        format!("{} {} {id}\n{}", self.status, self.code, self.message)
    }

    /// A refused arrival's words read back; `None` when they are not this plane's.
    #[must_use]
    pub fn from_words(text: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(text).ok()?;
        let (head, message) = text.split_once('\n')?;
        let mut head = head.splitn(3, ' ');
        let status = head.next()?.parse().ok()?;
        let code = head.next()?.parse().ok()?;
        let id: Value = serde_json::from_str(head.next()?).ok()?;
        Some(Refusal {
            status,
            id: (!id.is_null()).then_some(id),
            code,
            message: message.to_string(),
        })
    }

    /// The JSON-RPC error object, with the `google.rpc.ErrorInfo` entry an A2A-defined code carries
    /// (the engine's `rpcerror::body`, member for member).
    #[must_use]
    pub fn error(&self) -> Value {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let Some(reason) = reason_of(self.code) {
            error["data"] = json!([{
                "@type": crate::ERROR_INFO_TYPE,
                "domain": crate::ERROR_INFO_DOMAIN,
                "reason": reason,
            }]);
        }
        error
    }

    /// The JSON-RPC line's body: the one error envelope.
    #[must_use]
    pub fn envelope(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": self.id.clone().unwrap_or(Value::Null),
            "error": self.error(),
        })
    }

    /// The HTTP+JSON line's body: the AIP-193 error document the engine's `rest::reframe` turns a
    /// JSON-RPC error into (`rpcerror::aip193`).
    #[must_use]
    pub fn aip193(&self) -> Value {
        aip193(self.status, &self.error())
    }
}

/// A JSON-RPC `error` object at `http_status` as the AIP-193 error document the HTTP+JSON line
/// answers (the engine's `rpcerror::aip193`): the status name is the error code's when it has one,
/// else the HTTP status's; `details` is the error's `data` array, only when there is one.
#[must_use]
pub fn aip193(http_status: u32, error: &Value) -> Value {
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let status = error
        .get("code")
        .and_then(Value::as_i64)
        .and_then(status_name_of)
        .unwrap_or_else(|| status_name_of_http(http_status));
    let mut out = json!({
        "code": http_status,
        "status": status,
        "message": message,
    });
    if let Some(details) = error.get("data").filter(|d| d.is_array()) {
        out["details"] = details.clone();
    }
    json!({ "error": out })
}

/// The `ErrorInfo` reason an A2A-defined code carries ([`crate::ERRORS`]); JSON-RPC's own codes
/// carry none.
#[must_use]
pub fn reason_of(code: i64) -> Option<&'static str> {
    crate::ERRORS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, reason)| *reason)
}

/// The canonical status name a known code maps to: the `gRPC Status` column of A2A section 5.4,
/// which AIP-193 puts in `error.status`; `None` for a code A2A and JSON-RPC do not define.
#[must_use]
pub fn status_name_of(code: i64) -> Option<&'static str> {
    Some(match code {
        -32001 => "NOT_FOUND",
        -32002 | -32007 | -32008 => "FAILED_PRECONDITION",
        -32003 | -32004 | -32009 | -32601 => "UNIMPLEMENTED",
        -32005 | -32700 | -32600 | -32602 => "INVALID_ARGUMENT",
        -32006 | -32603 => "INTERNAL",
        _ => return None,
    })
}

/// The canonical status name of an HTTP status, for a code with none of its own (the engine's
/// `rpcerror::status_for_http`).
fn status_name_of_http(status: u32) -> &'static str {
    match status {
        400 | 415 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        409 => "FAILED_PRECONDITION",
        429 => "RESOURCE_EXHAUSTED",
        503 => "UNAVAILABLE",
        504 => "DEADLINE_EXCEEDED",
        _ => "INTERNAL",
    }
}

/// What one arrival on the JSON-RPC line is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// A request whose method the vocabulary classes.
    Request {
        /// Its row.
        row: &'static MethodRow,
        /// The request id.
        id: Value,
        /// The version it negotiated, restated on the hop.
        version: &'static str,
    },
    /// A request whose method the vocabulary does not class; the engine relays it verbatim.
    Unlisted {
        /// The method.
        method: String,
        /// The request id.
        id: Value,
        /// The version it negotiated.
        version: &'static str,
    },
    /// A notification: acknowledged, never answered.
    Notice {
        /// Its method.
        method: String,
    },
    /// Refused at arrival.
    Refused(Refusal),
}

impl Disposition {
    /// The operation class an admitted arrival is a unit of: its row's, or for a method the
    /// vocabulary does not list, the class the engine relays it as ([`crate::ops::relay_class`]).
    /// `None` for a refused arrival.
    #[must_use]
    pub fn op_class(&self) -> Option<busbar_contract::ids::OpClassId> {
        match self {
            Disposition::Request { row, .. } => Some(row.op),
            Disposition::Unlisted { method, .. } | Disposition::Notice { method } => {
                Some(ops::relay_class(method))
            }
            Disposition::Refused(_) => None,
        }
    }
}

/// Whether a declared media type is one this endpoint reads: `application/json`, or any RFC 6839
/// `+json` type.
#[must_use]
pub fn is_json_media_type(media: &str) -> bool {
    media.eq_ignore_ascii_case(JSON_MEDIA_TYPE)
        || media
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

/// The asked version at `Major.Minor`.
fn major_minor(asked: &str) -> String {
    let mut parts = asked.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => format!("{major}.{minor}"),
        _ => asked.to_string(),
    }
}

/// The request line's refusal, judged before the body: the media type, then the version. `Ok`
/// carries the negotiated version.
///
/// # Errors
///
/// The refusal the head earns.
pub fn head_refusal<'a>(field: impl Fn(&str) -> Option<&'a str>) -> Result<&'static str, Refusal> {
    if let Some(ct) = field(H_CONTENT_TYPE) {
        let media = ct.split(';').next().unwrap_or_default().trim();
        if !is_json_media_type(media) {
            return Err(Refusal::unnamed(
                STATUS_UNSUPPORTED_MEDIA_TYPE,
                CODE_CONTENT_TYPE_NOT_SUPPORTED,
                format!(
                    "this endpoint reads `{JSON_MEDIA_TYPE}` and any `+json` media type; the \
                     request declared `{media}`"
                ),
            ));
        }
    }
    let asked = field(H_VERSION).unwrap_or_default().trim();
    if asked.is_empty() {
        return Ok(DEFAULT_VERSION);
    }
    let wanted = major_minor(asked);
    match SUPPORTED_VERSIONS.iter().copied().find(|v| *v == wanted) {
        Some(v) => Ok(v),
        None => Err(Refusal::unnamed(
            STATUS_BAD_REQUEST,
            CODE_VERSION_NOT_SUPPORTED,
            format!(
                "this endpoint speaks A2A {}; the request asked for `{asked}`",
                SUPPORTED_VERSIONS.join(" and ")
            ),
        )),
    }
}

/// The `Origin` refusal: a request driven from a browser origin that is neither loopback nor one
/// this plane lists (it lists none). A request with no `Origin` is not a browser's and passes.
///
/// # Errors
///
/// The refusal the origin earns.
pub fn origin_refusal<'a>(field: impl Fn(&str) -> Option<&'a str>) -> Result<(), Refusal> {
    match field(H_ORIGIN) {
        Some(origin) if !busbar_contract::jsonrpc::origin_admitted(origin, &[]) => Err(
            Refusal::unnamed(STATUS_FORBIDDEN, CODE_UNSUPPORTED_OPERATION, ORIGIN_REFUSED),
        ),
        _ => Ok(()),
    }
}

/// DECIDE ONE ARRIVAL on the JSON-RPC line. `field` reads a request head field by its lower-case
/// name (the first, as sent; one that is not UTF-8 reads as absent).
pub fn decide<'a>(body: &[u8], field: impl Fn(&str) -> Option<&'a str> + Copy) -> Disposition {
    if let Err(refusal) = origin_refusal(field) {
        return Disposition::Refused(refusal);
    }
    let version = match head_refusal(field) {
        Ok(v) => v,
        Err(refusal) => return Disposition::Refused(refusal),
    };
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Disposition::Refused(Refusal::unnamed(STATUS_BAD_REQUEST, CODE_PARSE, NOT_JSON));
    };
    match busbar_contract::jsonrpc::read(&value) {
        Err(invalid) => Disposition::Refused(Refusal {
            status: STATUS_BAD_REQUEST,
            id: (!invalid.id.is_null()).then_some(invalid.id),
            code: invalid.code,
            message: invalid.message.to_string(),
        }),
        Ok(busbar_contract::jsonrpc::Envelope::Notification { method }) => {
            Disposition::Notice { method }
        }
        Ok(busbar_contract::jsonrpc::Envelope::Request { id, method }) => {
            match ops::row_for(&method) {
                Some(row) => Disposition::Request { row, id, version },
                None => Disposition::Unlisted {
                    method,
                    id,
                    version,
                },
            }
        }
    }
}

/// THE RENDERED REFUSAL: a status (`0` keeps the kernel's), the body, and the one head field it
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The status the rendering answers with; `0` = the kernel's.
    pub status: u32,
    /// The body.
    pub body: Vec<u8>,
    /// The `content-type` value.
    pub content_type: &'static str,
}

/// Which line's refusal dialect a rendering speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// The JSON-RPC line: the error envelope.
    JsonRpc,
    /// The HTTP+JSON line: the AIP-193 document.
    RestJson,
    /// The gRPC line: the JSON-RPC error envelope at the refusal's neutral status, which the grpc
    /// transport maps to `grpc-status` and its trailers exactly as the engine's gRPC bridge maps
    /// the envelope its ingress answered.
    Framed,
}

/// Render `refusal` in `dialect`. `own_status` is whether the status is the plane's own (a refused
/// arrival's) rather than the kernel's.
#[must_use]
pub fn render(dialect: Dialect, refusal: &Refusal, own_status: bool) -> Rendered {
    let doc = match dialect {
        Dialect::JsonRpc | Dialect::Framed => refusal.envelope(),
        Dialect::RestJson => refusal.aip193(),
    };
    Rendered {
        status: if own_status { refusal.status } else { 0 },
        body: serde_json::to_vec(&doc).unwrap_or_default(),
        content_type: JSON_MEDIA_TYPE,
    }
}

/// A refusal the kernel made (a key not live, a scope not held, a budget spent, a gate's no), as
/// the plane words it: the engine's admission rendering, `-32004` with the kernel's text and no id,
/// at the kernel's status.
#[must_use]
pub fn kernel_refusal(status: u32, text: &str) -> Refusal {
    Refusal::unnamed(status, CODE_UNSUPPORTED_OPERATION, text)
}

#[cfg(test)]
#[path = "tests/arrival.rs"]
mod tests;
