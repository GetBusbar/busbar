// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANSWERS THE PLANE GIVES ITSELF on the child-process carrier: `initialize`, `ping`,
//! `logging/setLevel`, and `resources/subscribe` / `resources/unsubscribe` over a session's bounded
//! subscription set. Pure: a request in, the answer's bytes (or a refusal) out, and the session's
//! state is a value the caller holds.
//!
//! Each answer is the served engine's, word for word: the same `initialize` result, the same empty
//! result for the others, the same `-32602` sentences and the same two ceilings.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::arrival::Refusal;
use crate::checks::STATUS;
use crate::codec::{CODE_INVALID_PARAMS, PROTOCOL_VERSION};

/// The ceiling on one session's retained subscription set.
pub const MAX_RESOURCE_SUBS: usize = 256;

/// The ceiling on one retained subscription uri, in bytes.
pub const MAX_RESOURCE_SUB_URI_BYTES: usize = 2048;

/// A result envelope: `{"jsonrpc": "2.0", "id": id, "result": result}`.
#[must_use]
pub fn result(id: &Value, result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
    .unwrap_or_default()
}

fn invalid_params(id: &Value, message: &str) -> Refusal {
    Refusal {
        status: STATUS,
        id: Some(id.clone()),
        code: CODE_INVALID_PARAMS,
        message: message.to_string(),
        data: None,
    }
}

/// The `initialize` answer. The plane implements ONE revision and says so: `protocolVersion`
/// names it, so a client of an earlier revision either speaks it from here on or disconnects. No
/// session is created, because the revision has none to create.
#[must_use]
pub fn initialize(id: &Value) -> Vec<u8> {
    result(
        id,
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": true },
                "prompts": { "listChanged": true },
                "resources": { "listChanged": true, "subscribe": true },
                "completions": {},
                "logging": {},
            },
            "serverInfo": {
                "name": "busbar",
                "version": crate::plane_door::VERSION,
            },
            "instructions": format!(
                "This server speaks MCP revision {PROTOCOL_VERSION}: no handshake is required, \
                 and every request states its protocol version and client capabilities in \
                 `params._meta`."
            ),
        }),
    )
}

/// The `ping` answer: an empty result.
#[must_use]
pub fn ping(id: &Value) -> Vec<u8> {
    result(id, json!({}))
}

/// `logging/setLevel`: the session's new logging floor, or the refusal when `params.level` is
/// absent. The answer to an accepted level is an empty result.
///
/// # Errors
///
/// `-32602` when `params.level` is not a string.
pub fn set_level(id: &Value, params: Option<&Value>) -> Result<String, Refusal> {
    params
        .and_then(|p| p.get("level"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            invalid_params(
                id,
                "`params.level` is required: the RFC 5424 severity this session's \
                 `notifications/message` records are filtered at.",
            )
        })
}

/// ONE SESSION'S SUBSCRIPTIONS: each uri the client subscribed to, with the fingerprint of the
/// resource as the caller could see it when it subscribed (the baseline a change is measured
/// from). Bounded by [`MAX_RESOURCE_SUBS`] and [`MAX_RESOURCE_SUB_URI_BYTES`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subscriptions {
    subs: BTreeMap<String, Option<u64>>,
}

impl Subscriptions {
    /// The subscribed uris and their baselines.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, Option<u64>> {
        &self.subs
    }

    /// `resources/subscribe` or `resources/unsubscribe`. `baseline` is the fingerprint of the
    /// resource as the caller can see it now; a subscribe takes it before anything is retained.
    /// Accepted for ANY uri, so the acceptance leaks nothing about what exists. A uri already held
    /// is always admitted: re-subscribing re-takes the baseline and grows nothing.
    ///
    /// # Errors
    ///
    /// `-32602` for a missing uri, an over-long uri, or a set already at its ceiling.
    pub fn apply(
        &mut self,
        id: &Value,
        subscribe: bool,
        params: Option<&Value>,
        baseline: impl FnOnce(&str) -> Option<u64>,
    ) -> Result<(), Refusal> {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return Err(invalid_params(
                id,
                "`params.uri` is required: the resource to watch (or stop watching).",
            ));
        };
        if !subscribe {
            self.subs.remove(uri);
            return Ok(());
        }
        if uri.len() > MAX_RESOURCE_SUB_URI_BYTES {
            return Err(invalid_params(
                id,
                "`params.uri` is longer than this session retains: a subscription uri is held for \
                 the session and re-read on every catalogue move, so it is bounded.",
            ));
        }
        if self.subs.len() >= MAX_RESOURCE_SUBS && !self.subs.contains_key(uri) {
            return Err(invalid_params(
                id,
                "this session already holds as many resource subscriptions as it will watch: \
                 unsubscribe from one before subscribing to another.",
            ));
        }
        self.subs.insert(uri.to_string(), baseline(uri));
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/local.rs"]
mod tests;
