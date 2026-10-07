// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen`: THE SERVER-TO-CLIENT CHANNEL OF REVISION `2026-07-28`, as a pure state
//! machine the door drives on whichever carrier holds it open (the served engine's
//! `subscribe.rs`, every rule kept).
//!
//! - THE ACKNOWLEDGEMENT IS A NARROWING ([`Listen::open`]): it carries the ACCEPTED subset, never
//!   the requested one: the three list-changed categories, and `resourceSubscriptions` narrowed per
//!   uri to what this caller is entitled to read. A request that opts in to nothing deliverable is
//!   refused: a stream that can deliver nothing is a connection held open to say nothing.
//! - WHAT COUNTS AS A CHANGE IS THIS CALLER'S CHANGE: a generation move is the cheap gate, followed
//!   by a comparison of the catalogue THIS CALLER CAN SEE ([`change_keys`]), so a registration the
//!   caller may not reach never wakes its stream.
//! - THE PERMISSION IS RE-ASKED ON EVERY FRAME (the door passes [`Standing`]): a principal that has
//!   stopped resolving live ends the stream on that frame, with the reason.
//! - THE STREAM IS BOUNDED ([`MAX_LIFETIME_NS`]) and ends by saying so: the revision's own
//!   `SubscriptionsListenResult`, correlated to the request that opened it.
//! - QUIET IS NOT NOTHING: an idle stream says it is alive every [`KEEPALIVE_NS`].

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::catalogue::{Catalogue, Lookup};

/// How long one subscription is held before it is closed with a graceful result. LOAD-BEARING FOR
/// AUTHORISATION as well as liveness: it bounds everything a frame cannot re-derive.
pub const MAX_LIFETIME_NS: u64 = 300 * 1_000_000_000;

/// How often a stream that has nothing to say says it is alive.
pub const KEEPALIVE_NS: u64 = 15 * 1_000_000_000;

/// The ceiling on distinct uris one `subscriptions/listen` may name under `resourceSubscriptions`,
/// checked on the raw (deduplicated) request, before entitlement narrows it, and refused, never
/// truncated.
pub const MAX_SUBSCRIBED_URIS: usize = 64;

/// The notification that acknowledges a subscription.
pub const ACKNOWLEDGED: &str = "notifications/subscriptions/acknowledged";

/// The `_meta` key a frame names its subscription under.
pub const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// The JSON-RPC code for invalid params.
const INVALID_PARAMS: i64 = -32602;

/// The base protocol's invalid request (a lapsed permission's closing frame).
const INVALID_REQUEST: i64 = -32600;

/// The three list-changed categories, and the notification each becomes.
const KINDS: [(&str, &str); 3] = [
    ("toolsListChanged", "notifications/tools/list_changed"),
    ("promptsListChanged", "notifications/prompts/list_changed"),
    (
        "resourcesListChanged",
        "notifications/resources/list_changed",
    ),
];

/// What a caller asked for, and what it is given: the subscription filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`.
    pub lists: [bool; 3],
    /// `resourceSubscriptions`; `None` = the category is not in it.
    pub resources: Option<Vec<String>>,
}

impl Filter {
    /// The filter as the wire carries it.
    #[must_use]
    pub fn render(&self) -> Value {
        let mut out = Map::new();
        for (on, (key, _)) in self.lists.iter().zip(KINDS) {
            if *on {
                out.insert(key.to_string(), Value::Bool(true));
            }
        }
        if let Some(uris) = &self.resources {
            out.insert("resourceSubscriptions".to_string(), json!(uris));
        }
        Value::Object(out)
    }

    /// Read a requested filter; a shape the protocol does not define reads as no category.
    fn read(notifications: Option<&Value>) -> Self {
        let Some(n) = notifications.and_then(Value::as_object) else {
            return Filter::default();
        };
        let mut lists = [false; 3];
        for (slot, (key, _)) in lists.iter_mut().zip(KINDS) {
            match n.get(key) {
                None => {}
                Some(Value::Bool(b)) => *slot = *b,
                Some(_) => return Filter::default(),
            }
        }
        let resources = match n.get("resourceSubscriptions") {
            None => None,
            Some(Value::Array(a)) => {
                // Deduplicated through a set, and read no further than the first uri past the
                // ceiling: the request is refused for it, so the rest of a long array costs nothing.
                let mut seen = BTreeSet::new();
                let mut uris = Vec::new();
                for u in a {
                    let Some(u) = u.as_str() else {
                        return Filter::default();
                    };
                    if seen.insert(u) {
                        uris.push(u.to_string());
                        if uris.len() > MAX_SUBSCRIBED_URIS {
                            break;
                        }
                    }
                }
                Some(uris)
            }
            Some(_) => return Filter::default(),
        };
        Filter { lists, resources }
    }
}

/// Whether the caller's permission still stands this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// It stands.
    Live,
    /// It lapsed, for this reason: the stream ends on this frame, saying so.
    Lapsed {
        /// The sentence.
        message: String,
        /// The machine reason.
        reason: String,
    },
}

/// Where the stream is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// The acknowledgement is owed, and owed first.
    Acknowledge,
    /// Acknowledged; watching the generation.
    Watch { generation: u64, seen: [u64; 3] },
    /// The final frame went: the next step closes it.
    Ended,
}

/// What one step came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Frames to write, in order; the stream goes on.
    Frames(Vec<Value>),
    /// Nothing happened for a keepalive's while: say it is alive.
    Keepalive,
    /// Nothing to say yet.
    Quiet,
    /// The last frames to write; the stream ends after them.
    End(Vec<Value>),
    /// The stream is over.
    Closed,
}

/// ONE SUBSCRIPTION.
#[derive(Debug, Clone)]
pub struct Listen {
    /// The listen request's own id: the subscription's only durable name.
    pub id: Value,
    accepted: Filter,
    meta: Value,
    phase: Phase,
    opened_ns: u64,
    last_write_ns: u64,
}

/// A refusal envelope for an invalid listen request.
fn invalid(id: &Value, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": INVALID_PARAMS, "message": message },
    })
}

impl Listen {
    /// OPEN one subscription for `params` under `id` at `now_ns`: the requested filter read,
    /// bounded, and narrowed by `entitled` (whether this caller's grant reaches a resource at a uri);
    /// `Err` is the refusal envelope.
    ///
    /// # Errors
    ///
    /// Too many uris, or nothing deliverable for this caller.
    pub fn open(
        params: Option<&Value>,
        id: Value,
        now_ns: u64,
        entitled: impl Fn(&str) -> bool,
    ) -> Result<Self, Value> {
        let requested = Filter::read(params.and_then(|p| p.get("notifications")));
        if let Some(uris) = &requested.resources {
            if uris.len() > MAX_SUBSCRIBED_URIS {
                return Err(invalid(
                    &id,
                    &format!(
                        "`params.notifications.resourceSubscriptions` names {} distinct uris; a \
                         `subscriptions/listen` call may watch at most {MAX_SUBSCRIBED_URIS} at \
                         once. Open a second subscription for the rest.",
                        uris.len()
                    ),
                ));
            }
        }
        let accepted = Filter {
            lists: requested.lists,
            resources: requested
                .resources
                .map(|uris| uris.into_iter().filter(|u| entitled(u)).collect::<Vec<_>>())
                .filter(|kept| !kept.is_empty()),
        };
        if !accepted.lists.iter().any(|on| *on) && accepted.resources.is_none() {
            return Err(invalid(
                &id,
                "`params.notifications` opts in to no category this server delivers for you. \
                 busbar delivers `toolsListChanged`, `promptsListChanged`, \
                 `resourcesListChanged`, and `resourceSubscriptions` for uris your grant reaches \
                 — a subscription naming only resources you cannot read is a stream with nothing \
                 to say.",
            ));
        }
        let meta = json!({ SUBSCRIPTION_ID: id });
        Ok(Listen {
            id,
            accepted,
            meta,
            phase: Phase::Acknowledge,
            opened_ns: now_ns,
            last_write_ns: now_ns,
        })
    }

    /// The accepted filter.
    #[must_use]
    pub fn accepted(&self) -> &Filter {
        &self.accepted
    }

    /// One notification tagged with this subscription.
    fn notification(&self, method: &str, extra: Value) -> Value {
        let mut params = match extra {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        params.insert("_meta".to_string(), self.meta.clone());
        json!({ "jsonrpc": "2.0", "method": method, "params": Value::Object(params) })
    }

    /// The revision's own graceful end, correlated to the request that opened the stream.
    fn complete(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": self.id,
            "result": { "resultType": "complete", "_meta": self.meta },
        })
    }

    /// THE NEXT STEP at `now_ns`, over the live `catalogue` under the caller's grants `admit`,
    /// with its permission re-asked (`standing`), and the upstream announcements `updates` (each
    /// `(server, uri)`) recorded since the last step.
    pub fn step(
        &mut self,
        catalogue: &Catalogue,
        admit: &impl Fn(&str, &str) -> bool,
        standing: &Standing,
        updates: &[(String, String)],
        now_ns: u64,
    ) -> Step {
        if self.phase == Phase::Ended {
            return Step::Closed;
        }
        if let Standing::Lapsed { message, reason } = standing {
            self.phase = Phase::Ended;
            return Step::End(vec![json!({
                "jsonrpc": "2.0",
                "id": self.id,
                "error": {
                    "code": INVALID_REQUEST,
                    "message": message,
                    "data": { "reason": reason },
                },
            })]);
        }
        if now_ns.saturating_sub(self.opened_ns) >= MAX_LIFETIME_NS {
            self.phase = Phase::Ended;
            return Step::End(vec![self.complete()]);
        }
        let generation = catalogue.generation();
        match &mut self.phase {
            Phase::Acknowledge => {
                let seen = change_keys(catalogue, admit);
                self.phase = Phase::Watch { generation, seen };
                self.last_write_ns = now_ns;
                let ack = self.notification(
                    ACKNOWLEDGED,
                    json!({ "notifications": self.accepted.render() }),
                );
                Step::Frames(vec![ack])
            }
            Phase::Watch {
                generation: at,
                seen,
            } => {
                let mut changed = Vec::new();
                if *at != generation {
                    *at = generation;
                    let fresh = change_keys(catalogue, admit);
                    for (i, (_, method)) in KINDS.into_iter().enumerate() {
                        if fresh[i] != seen[i] && self.accepted.lists[i] {
                            changed.push(method);
                        }
                    }
                    *seen = fresh;
                }
                let mut out: Vec<Value> = changed
                    .into_iter()
                    .map(|m| self.notification(m, json!({})))
                    .collect();
                // THE RESOURCE-UPDATE RELAY: an upstream's announcement reaches a subscriber only
                // when the subscriber asked for the uri, the uri resolves under its live grant to an
                // operator-declared resource, and that resource is the announcing server's.
                if let Some(uris) = &self.accepted.resources {
                    for (server, uri) in updates {
                        if !uris.iter().any(|u| u == uri) {
                            continue;
                        }
                        let entitled = matches!(
                            catalogue.resource_by_uri(admit, uri),
                            Lookup::One(entry) if entry.server == *server
                        );
                        if entitled {
                            out.push(self.notification(
                                "notifications/resources/updated",
                                json!({ "uri": uri }),
                            ));
                        }
                    }
                }
                if !out.is_empty() {
                    self.last_write_ns = now_ns;
                    return Step::Frames(out);
                }
                if now_ns.saturating_sub(self.last_write_ns) >= KEEPALIVE_NS {
                    self.last_write_ns = now_ns;
                    return Step::Keepalive;
                }
                Step::Quiet
            }
            Phase::Ended => Step::Closed,
        }
    }

    /// When the stream next has something to say with nothing changing: its keepalive or its bound.
    #[must_use]
    pub fn next_due_ns(&self) -> u64 {
        (self.last_write_ns.saturating_add(KEEPALIVE_NS))
            .min(self.opened_ns.saturating_add(MAX_LIFETIME_NS))
    }
}

/// A change key over one grant-scoped catalogue slice: FNV-1a, trusted for nothing (a collision
/// costs one missed re-read of a list the caller can re-read at any time).
fn change_key(mut parts: Vec<&str>) -> u64 {
    parts.sort_unstable();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.as_bytes().iter().chain(std::iter::once(&0u8)) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// The three change keys of what ONE CALLER can see. The tool key carries each tool's schema hash:
/// a tool whose arguments changed shape under an unchanged name is one a client must re-read for.
#[must_use]
pub fn change_keys(catalogue: &Catalogue, admit: &impl Fn(&str, &str) -> bool) -> [u64; 3] {
    let tools = catalogue.tools_for(admit);
    let mut tool_parts: Vec<&str> = Vec::with_capacity(tools.len() * 2);
    for tool in &tools {
        tool_parts.push(tool.namespaced.as_str());
        tool_parts.push(tool.schema_hash.as_deref().unwrap_or(""));
    }
    [
        change_key(tool_parts),
        change_key(
            catalogue
                .prompts_for(admit)
                .iter()
                .map(|p| p.namespaced.as_str())
                .collect(),
        ),
        change_key(
            catalogue
                .resources_for(admit)
                .iter()
                .map(|r| r.namespaced.as_str())
                .collect(),
        ),
    ]
}

#[cfg(test)]
#[path = "tests/subscribe_tests.rs"]
mod tests;
