// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT ONE ARRIVAL IS, decided once and purely: the body, the carrier it came over and a reader
//! over its head fields in; a [`Decision`] out. The door's `arrive` states the decision in the
//! plane ABI's words; this module is the decision itself, so it is tested without a door.
//!
//! The order is the served engine's:
//!
//! 1. The body must be JSON (`-32700`) and one JSON-RPC message (`-32600`, the contract's reader).
//! 2. A NOTIFICATION is acknowledged and never answered. On the child-process carrier a
//!    `notifications/cancelled` names the request it cancels by its correlation.
//! 3. On the child-process carrier the four session verbs (`initialize`, `ping`,
//!    `logging/setLevel`, `resources/subscribe` and `resources/unsubscribe`) are answered by the
//!    plane before the envelope checks, because a client of that carrier's earlier revisions sends
//!    them without `params._meta`.
//! 4. The stateless revision's envelope checks ([`crate::checks`]). On the child-process carrier
//!    the mirrored fields are the body's own, so only the `params._meta` and revision checks can
//!    refuse there.
//! 5. A method this dispatch does not carry is `404` + `-32601`. A method only an upstream may send
//!    is one a caller may not, so it reads the same.

use serde_json::Value;

use crate::checks::{check_request, Refused, STATUS};
use crate::codec::{name_source_of, META_PROTOCOL_VERSION};
use crate::codec::{CODE_METHOD_NOT_FOUND, H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION};
use crate::ops::{self, MethodRow, Sender};

/// The notification that cancels a request by its id.
pub const METHOD_CANCELLED: &str = "notifications/cancelled";

/// The session verbs the child-process carrier answers before the envelope checks.
pub const SESSION_VERBS: &[&str] = &[
    "initialize",
    "ping",
    "logging/setLevel",
    "resources/subscribe",
    "resources/unsubscribe",
];

/// The message a body that is not JSON is refused with.
pub const NOT_JSON: &str = "Request body is not valid JSON.";

/// The status an unimplemented method is answered with.
pub const STATUS_NOT_FOUND: u32 = 404;

/// A refusal decided at arrival: its status, the id it echoes, and its code, sentence and data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The status.
    pub status: u32,
    /// The request id the body echoes, `None` = `null`.
    pub id: Option<Value>,
    /// The JSON-RPC error code.
    pub code: i64,
    /// The sentence.
    pub message: String,
    /// The `data` member, where it carries one.
    pub data: Option<Value>,
}

impl Refusal {
    fn of(id: Option<Value>, refused: Refused) -> Self {
        Refusal {
            status: STATUS,
            id,
            code: refused.code,
            message: refused.message.to_string(),
            data: refused.data,
        }
    }

    /// The refusal as the wire carries it: the one JSON-RPC error envelope.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let envelope = busbar_contract::jsonrpc::error_body(
            self.id.clone().unwrap_or(Value::Null),
            self.code,
            &self.message,
            self.data.clone(),
        );
        serde_json::to_vec(&envelope).unwrap_or_default()
    }
}

/// What one arrival is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A request this dispatch carries.
    Request {
        /// Its row in the vocabulary.
        row: &'static MethodRow,
        /// The request id.
        id: Value,
        /// Its correlation key where its carrier cancels by name, else `0`.
        correlation: u64,
    },
    /// A session verb the child-process carrier answers itself.
    Session {
        /// The verb.
        method: String,
        /// The request id.
        id: Value,
        /// Its correlation key.
        correlation: u64,
    },
    /// A notification: acknowledged, never answered.
    Notice {
        /// Its method.
        method: String,
        /// The correlation of the request it cancels, where it is a cancel on a carrier that
        /// cancels by name, else `0`.
        cancels: u64,
    },
    /// Refused at arrival.
    Refused(Refusal),
}

/// The correlation key of a request id: non-zero, and type-tagged so the string `"1"` and the
/// number `1`, which never correlate on the wire, never share a key.
#[must_use]
pub fn correlation_of(id: &Value) -> u64 {
    let tagged = match id {
        Value::String(s) => format!("s:{s}"),
        other => format!("n:{other}"),
    };
    // FNV-1a, 64-bit: stable across builds, which a cancel crossing two arrivals needs.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in tagged.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash.max(1)
}

/// DECIDE ONE ARRIVAL. `stdio` is whether it came over the child-process carrier; `field` reads a
/// request head field by its lower-case name.
pub fn decide<'a>(stdio: bool, body: &[u8], field: impl Fn(&str) -> Option<&'a str>) -> Decision {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Decision::Refused(Refusal {
            status: STATUS,
            id: None,
            code: busbar_contract::jsonrpc::PARSE_ERROR,
            message: NOT_JSON.to_string(),
            data: None,
        });
    };
    let envelope = match busbar_contract::jsonrpc::read(&value) {
        Ok(envelope) => envelope,
        Err(invalid) => {
            return Decision::Refused(Refusal {
                status: STATUS,
                id: (!invalid.id.is_null()).then_some(invalid.id),
                code: invalid.code,
                message: invalid.message.to_string(),
                data: None,
            })
        }
    };
    let (id, method) = match envelope {
        busbar_contract::jsonrpc::Envelope::Notification { method } => {
            let cancels = if stdio && method == METHOD_CANCELLED {
                value
                    .get("params")
                    .and_then(|p| p.get("requestId"))
                    .filter(|i| i.is_string() || i.is_number())
                    .map_or(0, correlation_of)
            } else {
                0
            };
            return Decision::Notice { method, cancels };
        }
        busbar_contract::jsonrpc::Envelope::Request { id, method } => (id, method),
    };
    let correlation = if stdio { correlation_of(&id) } else { 0 };
    if stdio && SESSION_VERBS.contains(&method.as_str()) {
        return Decision::Session {
            method,
            id,
            correlation,
        };
    }
    let checked = if stdio {
        // The child-process carrier has no head fields: the mirror is the body's own.
        let version = value
            .get("params")
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(META_PROTOCOL_VERSION))
            .and_then(Value::as_str)
            .map(str::to_string);
        let name = name_source_of(&method).and_then(|source| {
            value
                .get("params")
                .and_then(|p| p.get(source))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        let method_field = method.clone();
        check_request(&value, &method, |n: &str| {
            if n.eq_ignore_ascii_case(H_PROTOCOL_VERSION) {
                version.as_deref()
            } else if n.eq_ignore_ascii_case(H_MCP_METHOD) {
                Some(method_field.as_str())
            } else if n.eq_ignore_ascii_case(H_MCP_NAME) {
                name.as_deref()
            } else {
                None
            }
        })
    } else {
        check_request(&value, &method, field)
    };
    if let Err(refused) = checked {
        return Decision::Refused(Refusal::of(Some(id), refused));
    }
    match ops::row_for(&method).filter(|row| row.sender == Sender::Client) {
        Some(row) => Decision::Request {
            row,
            id,
            correlation,
        },
        None => Decision::Refused(Refusal {
            status: STATUS_NOT_FOUND,
            id: Some(id),
            code: CODE_METHOD_NOT_FOUND,
            message: format!("Method `{method}` is not implemented by this server."),
            data: None,
        }),
    }
}

#[cfg(test)]
#[path = "tests/arrival.rs"]
mod tests;
