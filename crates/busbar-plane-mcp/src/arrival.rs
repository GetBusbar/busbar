// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT ONE ARRIVAL IS, decided once and purely: the body and a reader over its head fields in; a
//! [`Decision`] out. The door's `arrive` states the decision in the plane ABI's words; this module
//! is the decision itself, so it is tested without a door.
//!
//! The order is the served engine's:
//!
//! 1. The body must be JSON (`-32700`) and one JSON-RPC message (`-32600`, the contract's reader).
//! 2. A NOTIFICATION is acknowledged and never answered.
//! 3. The stateless revision's envelope checks ([`crate::checks`]).
//! 4. A method this dispatch does not carry is `404` + `-32601`. A method only an upstream may send
//!    is one a caller may not, so it reads the same.

use serde_json::Value;

use crate::checks::{check_request, Refused, STATUS};
use crate::codec::CODE_METHOD_NOT_FOUND;
use crate::ops::{self, MethodRow, Sender};

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
    },
    /// A notification: acknowledged, never answered.
    Notice {
        /// Its method.
        method: String,
    },
    /// Refused at arrival.
    Refused(Refusal),
}

/// DECIDE ONE ARRIVAL. `field` reads a request head field by its lower-case name.
pub fn decide<'a>(body: &[u8], field: impl Fn(&str) -> Option<&'a str>) -> Decision {
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
            return Decision::Notice { method };
        }
        busbar_contract::jsonrpc::Envelope::Request { id, method } => (id, method),
    };
    let checked = check_request(&value, &method, field);
    if let Err(refused) = checked {
        return Decision::Refused(Refusal::of(Some(id), refused));
    }
    match ops::row_for(&method).filter(|row| row.sender == Sender::Client) {
        Some(row) => Decision::Request { row, id },
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
