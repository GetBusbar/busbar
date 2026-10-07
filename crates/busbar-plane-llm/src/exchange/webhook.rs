// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND RESPONSES WEBHOOK RECEIVER (new in 1.6.0; spec Part 3 "Inbound webhooks", F26;
//! ARCHITECT Q2 webhook receiver, 2026-10-06): when a client runs a Responses turn in `background`
//! mode, the far end delivers the finished turn as a signed webhook to a URL the operator registered.
//! This plane answers that webhook on a PUBLIC route it states in its snapshot, served by its
//! `serve` op.
//!
//! * It is CONFIG-REACHED (Law 7): the plane's own section `llm_webhooks: { openai: { style: <scheme> } }`
//!   states the route; absent, no route is stated and the path is the router's 404, so a 1.5.5
//!   configuration sees 1.5.5's bytes. No cargo feature and no environment variable switches it.
//! * The plane never sees the signing secret: the route names the auth SCHEME its callers are
//!   verified under (`webhook-signature`), and the kernel runs the inbound verify of the instances
//!   serving that scheme over the request and its body, and refuses a replayed message, before
//!   `serve` is called. A request that reaches [`receive`] is signed.
//! * Busbar is a translator, not a conversation store: the receiver acknowledges the verified event
//!   with its correlation id (`data.id`, the `resp_…` id the stateful leg threads) and its type.

use busbar_contract::abi::plane::ROUTE_PUBLIC;
use busbar_contract::abi::sdk::publish::AdminRouteSpec;
use serde_json::Value;

/// The plane's owned section that states its webhook routes.
pub const SECTION: &str = "llm_webhooks";

/// The OpenAI Responses webhook's path (1.6.0's T3 receiver's, unchanged).
pub const OPENAI_PATH: &str = "/v1/llm/webhooks/openai";

/// The verb the webhook is delivered with.
pub const VERB: &str = "POST";

/// THE ROUTES the owned sections state (`owned`: the JSON object of the plane's owned sections the
/// document writes, by section name; empty = none). Each is public and names the scheme its callers
/// are verified under.
///
/// # Errors
///
/// The section does not read: not an object, an unknown sender, or a sender without a non-empty
/// `style`.
pub fn routes(owned: &[u8]) -> Result<Vec<AdminRouteSpec>, String> {
    if owned.is_empty() {
        return Ok(Vec::new());
    }
    let all: Value =
        serde_json::from_slice(owned).map_err(|e| format!("its owned sections: {e}"))?;
    let Some(section) = all.get(SECTION).filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let senders = section
        .as_object()
        .ok_or_else(|| format!("{SECTION}: not a map of webhook senders"))?;
    let mut out = Vec::new();
    for (sender, cfg) in senders {
        let path = match sender.as_str() {
            "openai" => OPENAI_PATH,
            other => {
                return Err(format!(
                    "{SECTION}.{other}: no webhook receiver by that name"
                ))
            }
        };
        let fields = cfg
            .as_object()
            .ok_or_else(|| format!("{SECTION}.{sender}: not a map"))?;
        if let Some(unknown) = fields.keys().find(|k| k.as_str() != "style") {
            return Err(format!(
                "{SECTION}.{sender}.{unknown}: not a receiver setting"
            ));
        }
        let style = fields
            .get("style")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                format!("{SECTION}.{sender}.style: the auth scheme its callers are verified under")
            })?;
        out.push(AdminRouteSpec::new(VERB, path, ROUTE_PUBLIC).verified_by(style));
    }
    Ok(out)
}

/// A verified body that is not a Responses webhook event (answered 400).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedEvent;

/// A verified, parsed Responses webhook event.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// The event id (`evt_…`), when present.
    pub event_id: Option<String>,
    /// The event kind, verbatim (`response.completed`, …).
    pub event_type: String,
    /// Unix seconds the event was created, when present.
    pub created_at: Option<u64>,
    /// The `resp_…` correlation id (`data.id`).
    pub response_id: String,
}

/// PARSE a verified body under the receiver's leniency contract: absent and unknown fields are
/// tolerated; a modeled field present with the wrong type is refused; `type` and `data.id` are
/// required non-empty strings.
///
/// # Errors
///
/// The body is not such an event.
pub fn parse_event(body: &[u8]) -> Result<Event, MalformedEvent> {
    let value: Value = serde_json::from_slice(body).map_err(|_| MalformedEvent)?;
    let obj = value.as_object().ok_or(MalformedEvent)?;
    let event_type = match obj.get("type") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(MalformedEvent),
    };
    let data = obj
        .get("data")
        .and_then(Value::as_object)
        .ok_or(MalformedEvent)?;
    let response_id = match data.get("id") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(MalformedEvent),
    };
    let event_id = match obj.get("id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()).filter(|s| !s.is_empty()),
        Some(_) => return Err(MalformedEvent),
    };
    let created_at = match obj.get("created_at") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or(MalformedEvent)?),
    };
    Ok(Event {
        event_id,
        event_type,
        created_at,
        response_id,
    })
}

/// THE ANSWER to a verified webhook delivery: `200` with the acknowledgement
/// `{"received": true, "response_id", "type"}`, or `400` for a body that is not an event.
#[must_use]
pub fn receive(body: &[u8]) -> (u32, Vec<u8>) {
    match parse_event(body) {
        Ok(event) => (
            200,
            serde_json::json!({
                "received": true,
                "response_id": event.response_id,
                "type": event.event_type,
            })
            .to_string()
            .into_bytes(),
        ),
        Err(MalformedEvent) => (400, Vec::new()),
    }
}
