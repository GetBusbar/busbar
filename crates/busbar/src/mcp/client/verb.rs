// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLOSED SET OF METHODS BUSBAR ISSUES TO AN UPSTREAM MCP SERVER.
//!
//! ## Why a closed enum and not a `&str` method name
//!
//! `qa/method-inventory.json` is a MATRIX and this module is one of its columns: `mcp × <transport>
//! × busbar-as-client × client-originated`. A builder that took the method as a string would make
//! the column's contents a property of its call sites, so a method could be added by one caller and
//! be invisible to every gate, every audit word and every test that enumerates the surface. The enum
//! is what makes an enumeration of the whole column possible, and
//! `tests/verb_tests.rs::the_issued_set_is_exactly_the_inventory_column` compares that enumeration
//! against the generated inventory IN BOTH DIRECTIONS — so a verb this file forgets is a RED TEST
//! rather than an absent row, and a verb it invents is a red test rather than a `-32601` in
//! production.
//!
//! ## busbar is a PROXY here, not an originator
//!
//! The owner's ruling on the coverage matrix, 2026-08-12, is the reason every one of these exists
//! rather than the obvious-looking subset:
//!
//! > *a gateway probably would not use this* is NOT a reason. busbar sits between a real client and
//! > a real server, so its client-side verb is not busbar originating anything — it is busbar
//! > PROXYING the real client's.
//!
//! So `resources/subscribe` is here because a caller subscribed; `notifications/cancelled` is here
//! because a caller cancelled; `initialize` is here because a CHILD PROCESS demands one. Which
//! brings us to the asymmetry with the HTTP leg, which is the one design decision in this file:
//!
//! ## WHY `initialize`, `ping` AND `logging/setLevel` ARE BUILT HERE AND WAIVED ON THE HTTP LEG
//!
//! `qa/method-coverage.status` waives `mcp|streamable-http|client|client|initialize` (and
//! `notifications/initialized`, `ping`, `logging/setLevel`, `resources/subscribe`,
//! `resources/unsubscribe`) as *removed by SEP-2575*. That waiver is correct for HTTP and WRONG for
//! stdio, and the difference is not a preference:
//!
//! - Over streamable HTTP, busbar's peer is a server that speaks the same revision busbar's own
//!   front door serves. That revision deleted the handshake, so there is nothing to send.
//! - Over stdio, busbar's peer is a LOCAL CHILD PROCESS the operator named in `command:`. It is
//!   whatever binary the operator installed — overwhelmingly an SDK server speaking a revision in
//!   which `initialize` is a MUST and a server may refuse every other request until it arrives.
//!   busbar does not get to choose the child's revision; the operator chose it by installing it.
//!
//! A leg that could not send a handshake could not talk to the stdio ecosystem at all. So the
//! handshake is BUILT, and it is sent as the child's first message by
//! [`super::stdio`] — see `StdioChild::handshake`.
//!
//! ## Params are DATA, never argv
//!
//! Every variant's payload is serialised into the JSON-RPC `params` object and travels on the
//! child's stdin. Nothing here can reach `StdioCommand::args`, which is config-only. That is the
//! fourth spawn decision in `super::stdio`'s header, expressed here as the absence of any path from
//! a verb to an argument vector.

use super::jsonrpc::{envelope, OutboundRequest};
use crate::mcp::ingress::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION, PROTOCOL_VERSION};

/// THE PROTOCOL REVISION BUSBAR OFFERS A CHILD IN ITS HANDSHAKE.
///
/// The same string busbar's own front door serves, and it is offered rather than imposed: a child
/// that answers `initialize` with a different `protocolVersion` has told busbar what it speaks, and
/// that answer is recorded rather than argued with. busbar is a gateway, not a conformance test.
pub(crate) const CLIENT_PROTOCOL_VERSION: &str = PROTOCOL_VERSION;

/// What busbar calls itself to a child. A constant, not a config key: an operator who could rename
/// busbar in a handshake could make one deployment impersonate another in the child's own logs.
const CLIENT_NAME: &str = "busbar";

/// ONE METHOD BUSBAR SENDS TO AN UPSTREAM, with its parameters.
///
/// Every variant carries the data its `params` needs and nothing else. There is deliberately no
/// `Other(String)` arm: an arm that accepted an arbitrary method name would reopen exactly the
/// hole this enum closes, and `-32601` from an upstream is a better answer than a method busbar
/// invented.
///
/// `PartialEq` and NOT `Eq`: `notifications/progress` carries an `f64`, which is the wire type the
/// specification gives it. Quantising progress to an integer to buy `Eq` would be lying about the
/// wire to satisfy a derive.
///
/// ## WHAT HAS A PRODUCTION CALLER TODAY, and what does not
///
/// `ToolsList` is built by `crate::mcp::connect::refresh` on every scheduled and operator-driven
/// re-pull, and `ToolsCall`'s wire form is `super::jsonrpc::tools_call` on the dispatch path. The
/// other twenty-one variants are reached by `super::issue::issue` — which is itself reached today
/// only from the batteries in `crate::mcp::tests/stdio_client_leg_tests.rs`, because busbar's own
/// FRONT DOOR does not yet expose a `prompts/list` that proxies through to an upstream's. The verb
/// exists, is governed, is audited and is proven against a real child process; what is missing is
/// the inbound method that would call it, and that is the server plane's surface rather than this
/// module's.
///
/// The allow is on the ENUM and states that, rather than being a blanket over the module: anything
/// else in this file losing its caller still breaks the build. Deleting the variants instead would
/// be deleting a proven, security-reviewed leg so that a linter is quiet, which is the trade the
/// stdio transport was already deleted over once.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum UpstreamVerb {
    /// The handshake. See the module header for why this exists here and is waived on HTTP.
    Initialize,
    /// The handshake's acknowledgement. A NOTIFICATION: it has no reply, and a client that waited
    /// for one would hang against every conformant server.
    NotificationsInitialized,
    /// Liveness. Sent by busbar's own supervisor as a readiness probe, and proxied when a caller
    /// pings a specific upstream.
    Ping,
    /// The merged capability advertisement this revision added.
    ServerDiscover,
    /// Set the upstream's log verbosity.
    LoggingSetLevel {
        level: String,
    },
    /// The upstream's tool list. The refresh path's request — see `crate::mcp::connect`.
    ToolsList,
    /// Invoke one tool. `name` is the UN-namespaced tool: the upstream has never heard of busbar's
    /// `{server}_{tool}` namespacing and would answer `-32602` to it.
    ToolsCall {
        name: String,
        arguments: serde_json::Value,
    },
    PromptsList,
    PromptsGet {
        name: String,
        arguments: serde_json::Value,
    },
    ResourcesList,
    ResourcesTemplatesList,
    ResourcesRead {
        uri: String,
    },
    ResourcesSubscribe {
        uri: String,
    },
    ResourcesUnsubscribe {
        uri: String,
    },
    /// SEP-2575's replacement for the removed GET stream. A METHOD in this revision.
    SubscriptionsListen {
        notifications: serde_json::Value,
    },
    CompletionComplete {
        reference: serde_json::Value,
        argument: serde_json::Value,
    },
    /// SEP-2663 tasks. `taskId` is the wire spelling — see `crate::mcp::tasks`.
    TasksGet {
        task_id: String,
    },
    TasksUpdate {
        task_id: String,
        input_responses: serde_json::Value,
    },
    TasksCancel {
        task_id: String,
    },
    /// A NOTIFICATION: the caller withdrew a request busbar had already forwarded.
    NotificationsCancelled {
        request_id: serde_json::Value,
        reason: String,
    },
    /// A NOTIFICATION: progress on a long-running call, relayed upstream.
    NotificationsProgress {
        progress_token: serde_json::Value,
        progress: f64,
        total: Option<f64>,
    },
    /// A NOTIFICATION: busbar's exposed root set changed.
    NotificationsRootsListChanged,
    /// A NOTIFICATION: the answer to an `elicitation/create` the upstream asked for.
    NotificationsElicitationResponse {
        request_id: serde_json::Value,
        content: serde_json::Value,
    },
}

impl UpstreamVerb {
    /// THE WIRE METHOD NAME. Exhaustive, with no wildcard arm, so a variant added without a name is
    /// a compile error rather than a method that silently sends the wrong word.
    pub(crate) fn method(&self) -> &'static str {
        match self {
            UpstreamVerb::Initialize => "initialize",
            UpstreamVerb::NotificationsInitialized => "notifications/initialized",
            UpstreamVerb::Ping => "ping",
            UpstreamVerb::ServerDiscover => "server/discover",
            UpstreamVerb::LoggingSetLevel { .. } => "logging/setLevel",
            UpstreamVerb::ToolsList => "tools/list",
            UpstreamVerb::ToolsCall { .. } => "tools/call",
            UpstreamVerb::PromptsList => "prompts/list",
            UpstreamVerb::PromptsGet { .. } => "prompts/get",
            UpstreamVerb::ResourcesList => "resources/list",
            UpstreamVerb::ResourcesTemplatesList => "resources/templates/list",
            UpstreamVerb::ResourcesRead { .. } => "resources/read",
            UpstreamVerb::ResourcesSubscribe { .. } => "resources/subscribe",
            UpstreamVerb::ResourcesUnsubscribe { .. } => "resources/unsubscribe",
            UpstreamVerb::SubscriptionsListen { .. } => "subscriptions/listen",
            UpstreamVerb::CompletionComplete { .. } => "completion/complete",
            UpstreamVerb::TasksGet { .. } => "tasks/get",
            UpstreamVerb::TasksUpdate { .. } => "tasks/update",
            UpstreamVerb::TasksCancel { .. } => "tasks/cancel",
            UpstreamVerb::NotificationsCancelled { .. } => "notifications/cancelled",
            UpstreamVerb::NotificationsProgress { .. } => "notifications/progress",
            UpstreamVerb::NotificationsRootsListChanged => "notifications/roots/list_changed",
            UpstreamVerb::NotificationsElicitationResponse { .. } => {
                "notifications/elicitation/response"
            }
        }
    }

    /// Whether this verb is a JSON-RPC NOTIFICATION — no `id`, and NO REPLY EVER.
    ///
    /// Decided on the VARIANT rather than by testing whether the method name starts with
    /// `notifications/`, because that string test is a rule about spelling that would silently
    /// reclassify any future method whose name happened to match. The distinction matters at the
    /// transport: [`super::wire::McpWire::notify`] does not read, and a request sent down that path
    /// would wait for an answer nobody would ever read — which on a stdio child means the answer
    /// stays in the pipe and desynchronises every subsequent call.
    pub(crate) fn is_notification(&self) -> bool {
        matches!(
            self,
            UpstreamVerb::NotificationsInitialized
                | UpstreamVerb::NotificationsCancelled { .. }
                | UpstreamVerb::NotificationsProgress { .. }
                | UpstreamVerb::NotificationsRootsListChanged
                | UpstreamVerb::NotificationsElicitationResponse { .. }
        )
    }

    /// The `params` object as the ARGUMENT GUARD sees it, before `_meta` is added.
    ///
    /// Exposed for exactly one caller, `super::issue::issue`, which walks it for URL and host
    /// fields. `_meta` is deliberately absent: it is BUSBAR's block, not the caller's, so judging it
    /// would be judging busbar's own protocol declaration as though a caller had chosen it.
    pub(super) fn params_for_guard(&self) -> serde_json::Value {
        self.params()
    }

    /// The `params` object, WITHOUT `_meta` — which [`Self::build`] adds, once, for every verb.
    ///
    /// Split that way so no variant can forget the revision's required `_meta`: a per-variant
    /// `params` that included it would be twenty-three chances to omit one key.
    fn params(&self) -> serde_json::Value {
        match self {
            UpstreamVerb::Initialize => serde_json::json!({
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                // THE EMPTY CAPABILITY SET, and it is the honest one. Sampling, elicitation and
                // roots are deny-by-default per server (`super::jsonrpc::ServerRequestGrants`), so
                // declaring a capability busbar then refuses to honour would invite a child to build
                // a call sequence around authority it will not be given.
                "capabilities": {},
                "clientInfo": { "name": CLIENT_NAME, "version": env!("CARGO_PKG_VERSION") },
            }),
            UpstreamVerb::NotificationsInitialized
            | UpstreamVerb::Ping
            | UpstreamVerb::ServerDiscover
            | UpstreamVerb::ToolsList
            | UpstreamVerb::PromptsList
            | UpstreamVerb::ResourcesList
            | UpstreamVerb::ResourcesTemplatesList
            | UpstreamVerb::NotificationsRootsListChanged => serde_json::json!({}),
            UpstreamVerb::LoggingSetLevel { level } => serde_json::json!({ "level": level }),
            UpstreamVerb::ToolsCall { name, arguments } => {
                serde_json::json!({ "name": name, "arguments": arguments })
            }
            UpstreamVerb::PromptsGet { name, arguments } => {
                serde_json::json!({ "name": name, "arguments": arguments })
            }
            UpstreamVerb::ResourcesRead { uri }
            | UpstreamVerb::ResourcesSubscribe { uri }
            | UpstreamVerb::ResourcesUnsubscribe { uri } => serde_json::json!({ "uri": uri }),
            UpstreamVerb::SubscriptionsListen { notifications } => {
                serde_json::json!({ "notifications": notifications })
            }
            UpstreamVerb::CompletionComplete {
                reference,
                argument,
            } => serde_json::json!({ "ref": reference, "argument": argument }),
            UpstreamVerb::TasksGet { task_id } | UpstreamVerb::TasksCancel { task_id } => {
                serde_json::json!({ "taskId": task_id })
            }
            UpstreamVerb::TasksUpdate {
                task_id,
                input_responses,
            } => serde_json::json!({ "taskId": task_id, "inputResponses": input_responses }),
            UpstreamVerb::NotificationsCancelled { request_id, reason } => {
                serde_json::json!({ "requestId": request_id, "reason": reason })
            }
            UpstreamVerb::NotificationsProgress {
                progress_token,
                progress,
                total,
            } => serde_json::json!({
                "progressToken": progress_token,
                "progress": progress,
                "total": total,
            }),
            UpstreamVerb::NotificationsElicitationResponse {
                request_id,
                content,
            } => serde_json::json!({ "requestId": request_id, "content": content }),
        }
    }

    /// The `Mcp-Name` header's value for this verb, when the revision requires one.
    ///
    /// `Some` only where the request NAMES a target the header can mirror. A header that mirrored a
    /// value the body does not carry would be a header busbar's own ingress answers `-32020` to.
    /// WHICH member of this verb's `params` the `Mcp-Name` header mirrors, and its value.
    ///
    /// The RULE is `crate::mcp::ingress::name_source_of`'s and is not restated here. This function
    /// once carried its own copy and the two disagreed about the three tasks methods, so a
    /// `tasks/get` issued over streamable HTTP went out with no `Mcp-Name` — the exact header
    /// busbar's own ingress answers `-32020` to. Reading the ingress's table means the requests
    /// busbar SENDS satisfy the MUSTs busbar ENFORCES, by construction rather than by two authors
    /// agreeing.
    ///
    /// It returns an owned `String` because the value is read back out of the serialised `params`
    /// rather than off the variant: the member the header mirrors is decided by the wire method, so
    /// looking it up by name is what keeps the two in step. A per-variant `match` would be the
    /// second copy again, wearing a different shape.
    fn target(&self) -> Option<String> {
        let source = crate::mcp::ingress::name_source_of(self.method())?;
        self.params()
            .get(source)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    /// BUILD the request. One envelope function, shared with `tools/call`, so the mirrored headers
    /// this revision REQUIRES cannot be got right on one verb and wrong on another.
    ///
    /// `request_id` is IGNORED for a notification, which carries no `id` member at all — a
    /// notification with an `id` is a request, and a peer would be right to answer it.
    pub(crate) fn build(
        &self,
        url: &str,
        request_id: u64,
        authorization: Option<&str>,
    ) -> OutboundRequest {
        let mut params = self.params();
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "_meta".to_string(),
                serde_json::json!({
                    META_PROTOCOL_VERSION: CLIENT_PROTOCOL_VERSION,
                    META_CLIENT_CAPABILITIES: {},
                }),
            );
        }
        let method = self.method();
        let body = if self.is_notification() {
            serde_json::json!({ "jsonrpc": "2.0", "method": method, "params": params })
        } else {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            })
        };
        envelope(url, method, self.target().as_deref(), body, authorization)
    }
}

#[cfg(test)]
impl UpstreamVerb {
    /// ONE INSTANCE OF EVERY VARIANT, for the tests that enumerate the surface.
    ///
    /// A `const` array rather than a derive, because the point is that a NEW VARIANT must be added
    /// here by hand — `every_issued_method_is_in_the_inventory` counts these against the generated
    /// matrix, so a variant missing from this list fails that test instead of quietly narrowing
    /// what the suite covers.
    pub(crate) fn all() -> Vec<UpstreamVerb> {
        vec![
            UpstreamVerb::Initialize,
            UpstreamVerb::NotificationsInitialized,
            UpstreamVerb::Ping,
            UpstreamVerb::ServerDiscover,
            UpstreamVerb::LoggingSetLevel {
                level: "info".to_string(),
            },
            UpstreamVerb::ToolsList,
            UpstreamVerb::ToolsCall {
                name: "read".to_string(),
                arguments: serde_json::json!({}),
            },
            UpstreamVerb::PromptsList,
            UpstreamVerb::PromptsGet {
                name: "greet".to_string(),
                arguments: serde_json::json!({}),
            },
            UpstreamVerb::ResourcesList,
            UpstreamVerb::ResourcesTemplatesList,
            UpstreamVerb::ResourcesRead {
                uri: "file:///a".to_string(),
            },
            UpstreamVerb::ResourcesSubscribe {
                uri: "file:///a".to_string(),
            },
            UpstreamVerb::ResourcesUnsubscribe {
                uri: "file:///a".to_string(),
            },
            UpstreamVerb::SubscriptionsListen {
                notifications: serde_json::json!({ "toolsListChanged": true }),
            },
            UpstreamVerb::CompletionComplete {
                reference: serde_json::json!({ "type": "ref/prompt", "name": "greet" }),
                argument: serde_json::json!({ "name": "who", "value": "b" }),
            },
            UpstreamVerb::TasksGet {
                task_id: "t1".to_string(),
            },
            UpstreamVerb::TasksUpdate {
                task_id: "t1".to_string(),
                input_responses: serde_json::json!([]),
            },
            UpstreamVerb::TasksCancel {
                task_id: "t1".to_string(),
            },
            UpstreamVerb::NotificationsCancelled {
                request_id: serde_json::json!(7),
                reason: "the caller withdrew".to_string(),
            },
            UpstreamVerb::NotificationsProgress {
                progress_token: serde_json::json!("busbar-7"),
                progress: 0.5,
                total: Some(1.0),
            },
            UpstreamVerb::NotificationsRootsListChanged,
            UpstreamVerb::NotificationsElicitationResponse {
                request_id: serde_json::json!(9),
                content: serde_json::json!({ "answer": "yes" }),
            },
        ]
    }
}

#[cfg(test)]
#[path = "tests/verb_tests.rs"]
mod verb_tests;
