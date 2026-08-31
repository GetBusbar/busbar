// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A CHILD SENDS BUSBAR — the `busbar-as-client / server-originated` half of the matrix.
//!
//! ## The defect this module exists to fix, stated first because it is the whole reason
//!
//! `StdioChild::call` used to write one line and read ONE line, and treat that line as the answer.
//! On streamable HTTP that is right: a POST has exactly one response and a notification arrives on
//! its own frame. On stdio it is WRONG, and wrong in the worst available way. A child's stdout is
//! ONE byte stream carrying everything the child ever says: its answers, its log records, its
//! progress, its list-changed notifications, and — under every revision an installed SDK server
//! actually speaks — its own REQUESTS. So a child that emitted a single `notifications/message`
//! before answering would have that log line adopted as the answer to `tools/call`, and every
//! subsequent call on that child would be answered by the PREVIOUS call's response. One
//! well-behaved, conformant, entirely ordinary child desynchronises the stream permanently and
//! silently.
//!
//! The fix is not "skip lines that are not responses". It is to CLASSIFY every line and give each
//! class an answer, because two of the classes are ones a peer is waiting on:
//!
//! | class | what busbar does |
//! |---|---|
//! | the correlated response | returned to the caller; the exchange ends |
//! | a notification busbar knows | the effect in [`NotificationEffect`], then keep reading |
//! | a notification busbar does not know | counted and dropped, then keep reading — never adopted |
//! | a request busbar knows | ANSWERED on the child's stdin, then keep reading |
//! | a request busbar does not know | answered `-32601`, then keep reading |
//!
//! A request left unanswered is a child blocked forever on a reply, which presents as a hang — the
//! same failure mode a piped-and-undrained stderr produces, and it is refused for the same reason.
//!
//! ## THE THREE AUTHORITY ASKS ARE DENY-BY-DEFAULT, AND THEY TERMINATE HERE
//!
//! `sampling/createMessage`, `elicitation/create` and `roots/list` are the three ways a peer asks
//! busbar to spend BUSBAR'S own authority: an LLM completion on busbar's pools and budget, a human's
//! attention, and the disclosure of filesystem structure. Arriving over a child's stdout does not
//! make them cheaper than arriving inline in an `InputRequiredResult`, so they get the same gate:
//! `crate::mcp::config::ServerRequestGrants`, all-false unless an operator set them.
//!
//! And they get the same TWO REFUSALS the server plane already distinguishes
//! (`crate::mcp::method`'s satisfier), because "it was refused" tells an operator nothing about
//! which thing refused it:
//!
//! - **[`AskOutcome::Ungranted`]** — the operator has not granted this server that authority. The
//!   remedy is `tools.<server>.grants.<kind>: true`.
//! - **[`AskOutcome::Unsatisfiable`]** — the grant IS held and busbar has no satisfier for that ask
//!   on this leg. The remedy is not a config key, and telling an operator to set one they have
//!   already set is worse than saying nothing.
//!
//! Both are refusals; neither is ever PROXIED OUTWARD to busbar's own caller. That is the rule
//! `super::jsonrpc`'s header states and it does not weaken because the peer is local: proxying it
//! would launder a child process's demand for authority through the party the caller actually
//! trusts.
//!
//! ## `ping` IS ANSWERED, and it is the one that is not a gate
//!
//! A ping carries no authority, discloses nothing, and its whole purpose is to let a peer tell a
//! live process from a wedged one. Refusing it would make busbar look dead to every child that
//! probes, which is the outcome the probe exists to detect. So it is answered with an empty result,
//! unconditionally, and it is the only server-originated request that is.
//!
//! ## Contents are NEVER read for a routing or trust decision
//!
//! The four "something changed" notifications can only bring a re-pull FORWARD, through
//! `super::catalogue::RefreshGate`, which is rate-limited. Their payloads are not parsed and not
//! believed. That is `super::catalogue`'s own rule — an attacker-controlled trigger may not choose
//! the moment freely and may not choose the content at all — and this module is the second place it
//! is now enforced rather than the first place it is bypassed.

use crate::mcp::config::ServerRequestGrants;

/// JSON-RPC standard: the method is not implemented.
///
/// A local re-statement rather than an import of `crate::mcp::envelope::code`, and it is the one
/// duplicated number in this module: that module's codes are `pub(super)`/`pub(in crate::mcp)` on
/// the SERVER plane's ingress, and widening their visibility so the client leg could borrow one
/// would make the ingress vocabulary reachable from the outbound half. The value is the JSON-RPC
/// specification's, not busbar's, so there is no busbar decision here for the two copies to drift on.
const METHOD_NOT_FOUND: i64 = -32601;

/// The code busbar answers an authority ask it will not satisfy with.
///
/// `-32001`, in the implementation-defined server-error range, and NOT `-32601`: the method is
/// recognised and implemented, and the answer is a policy decision. Telling a child "no such method"
/// when the truth is "you may not have that" would send its author looking for a version mismatch.
const ASK_REFUSED: i64 = -32001;

/// ONE MESSAGE A CHILD SENT, classified.
///
/// Note what is NOT an arm: a RESPONSE. [`classify`] returns `None` for anything carrying `result`
/// or `error`, so a response can only ever leave this module as "not a server message" and be
/// correlated by the caller. Making a response representable here would create a second place a
/// response could be consumed, which is the desynchronisation this module exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServerMessage {
    /// A notification busbar recognises. No reply, ever.
    Notification(ServerNotification),
    /// A notification busbar does not recognise. Still no reply — a notification is defined as
    /// unanswerable, and answering an unknown one would be busbar inventing a response to a message
    /// whose sender is not listening.
    UnknownNotification(String),
    /// A request busbar recognises. MUST be answered.
    Request {
        id: serde_json::Value,
        verb: ServerRequestVerb,
    },
    /// A request busbar does not recognise. MUST STILL BE ANSWERED, with `-32601`. Dropping it
    /// leaves the child blocked on a reply that never comes.
    UnknownRequest {
        id: serde_json::Value,
        method: String,
    },
}

/// THE NINE NOTIFICATIONS A SERVER MAY SEND, closed.
///
/// Closed so that a tenth cannot be handled by a default arm that treats it as one of these — which
/// on the four refresh triggers would mean an unknown method able to drive busbar's re-pull.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerNotification {
    /// The peer withdrew a request it had sent busbar.
    Cancelled,
    /// A log record. RFC 5424 severity in `params.level`.
    Message,
    /// Progress on a call busbar has in flight.
    Progress,
    PromptsListChanged,
    ResourcesListChanged,
    /// One resource's contents changed. Distinct from `ResourcesListChanged`: the LIST is the same
    /// and one member of it moved.
    ResourcesUpdated,
    /// The peer accepted a `subscriptions/listen` busbar sent.
    SubscriptionsAcknowledged,
    /// A task busbar created moved.
    Tasks,
    ToolsListChanged,
}

/// THE FOUR REQUESTS A SERVER MAY SEND, closed. Three of them are authority asks; one is a ping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerRequestVerb {
    /// Liveness. The only one that is not gated — see the module header.
    Ping,
    RootsList,
    SamplingCreateMessage,
    ElicitationCreate,
}

impl ServerRequestVerb {
    /// The grant this request asks to spend, or `None` for the one that spends nothing.
    ///
    /// Returns the same three key words `ServerRequestGrants::allows` reads, taken from
    /// [`super::jsonrpc::ServerAsk`] rather than spelled again — a second spelling of `"sampling"`
    /// is a second thing to get wrong, and the failure mode is a grant check that silently never
    /// matches and therefore always denies, which looks exactly like a correctly-configured denial.
    pub(crate) fn ask(self) -> Option<super::jsonrpc::ServerAsk> {
        match self {
            ServerRequestVerb::Ping => None,
            ServerRequestVerb::RootsList => Some(super::jsonrpc::ServerAsk::Roots),
            ServerRequestVerb::SamplingCreateMessage => Some(super::jsonrpc::ServerAsk::Sampling),
            ServerRequestVerb::ElicitationCreate => Some(super::jsonrpc::ServerAsk::Elicitation),
        }
    }
}

/// WHAT BUSBAR DOES about a notification it recognises. A closed set, so adding a notification
/// forces a decision about what it MEANS rather than letting it default to "nothing".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotificationEffect {
    /// Bring a `tools/list` re-pull forward, subject to [`super::catalogue::RefreshGate`]. The
    /// notification's CONTENTS are not read — see the module header.
    BringRefreshForward,
    /// `notifications/resources/updated` — everything [`NotificationEffect::BringRefreshForward`]
    /// does, PLUS record `(server, params.uri)` into [`super::pool::ResourceUpdates`] so the
    /// server leg can relay the update onto `subscriptions/listen`'s `resourceSubscriptions`
    /// category. The ONE effect that reads a field of a peer's notification, and the field is
    /// believed nowhere — see that type's header for the exact bounds on what the reading can do.
    RelayResourceUpdate,
    /// Relay to the caller's progress channel, if this dispatch has one.
    RelayProgress,
    /// Record it at the mapped log level and nothing else.
    Log,
}

impl ServerNotification {
    /// The effect, exhaustive and with no wildcard.
    pub(crate) fn effect(self) -> NotificationEffect {
        match self {
            // The three "the shape of what you can call has moved" triggers. A refresh re-pulls
            // the authoritative list and re-hashes it, which is the ONLY way an upstream can
            // influence busbar's catalogue — and it influences the TIMING, never the content.
            ServerNotification::ToolsListChanged
            | ServerNotification::PromptsListChanged
            | ServerNotification::ResourcesListChanged => NotificationEffect::BringRefreshForward,
            // The fourth trigger still brings the refresh forward AND is the one notification with
            // a second, named effect: the announced uri is recorded for the server-leg relay.
            ServerNotification::ResourcesUpdated => NotificationEffect::RelayResourceUpdate,
            ServerNotification::Progress => NotificationEffect::RelayProgress,
            // Cancelled, Message, SubscriptionsAcknowledged and Tasks are RECORDED and no more.
            // Acting on a peer's `cancelled` by aborting busbar's in-flight leg would hand a child
            // process the ability to cancel a call its own operator's caller paid for, on nothing
            // but an unauthenticated line of its own stdout.
            ServerNotification::Cancelled
            | ServerNotification::Message
            | ServerNotification::SubscriptionsAcknowledged
            | ServerNotification::Tasks => NotificationEffect::Log,
        }
    }
}

/// CLASSIFY one line a child wrote.
///
/// `None` means "this is not a server-originated message" — a response, or a line that is not a
/// JSON-RPC object at all. The caller correlates the former and refuses the latter; neither is this
/// module's decision.
///
/// The discriminator is the presence of `method`, and then of `id`, which is the JSON-RPC base
/// specification's own rule and not a heuristic. A `null` id on a request is treated as a
/// NOTIFICATION rather than as a request with a null id: answering it would produce a response
/// nothing can correlate, which the base protocol reserves for errors about un-parseable requests.
pub(crate) fn classify(value: &serde_json::Value) -> Option<ServerMessage> {
    let obj = value.as_object()?;
    // A response, not a message. Checked FIRST and by the presence of the members rather than by the
    // absence of `method`, so a malformed line carrying both is read as the response it claims to be
    // and fails correlation — rather than being executed as a request the peer never meant to send.
    if obj.contains_key("result") || obj.contains_key("error") {
        return None;
    }
    let method = obj.get("method").and_then(|m| m.as_str())?;
    let id = obj.get("id").filter(|v| !v.is_null()).cloned();
    match id {
        None => Some(match notification_of(method) {
            Some(n) => ServerMessage::Notification(n),
            None => ServerMessage::UnknownNotification(method.to_string()),
        }),
        Some(id) => Some(match request_of(method) {
            Some(verb) => ServerMessage::Request { id, verb },
            None => ServerMessage::UnknownRequest {
                id,
                method: method.to_string(),
            },
        }),
    }
}

/// The method-name table for notifications. One table, read in one direction, so a name cannot be
/// recognised here and spelled differently anywhere else.
fn notification_of(method: &str) -> Option<ServerNotification> {
    Some(match method {
        "notifications/cancelled" => ServerNotification::Cancelled,
        "notifications/message" => ServerNotification::Message,
        "notifications/progress" => ServerNotification::Progress,
        "notifications/prompts/list_changed" => ServerNotification::PromptsListChanged,
        "notifications/resources/list_changed" => ServerNotification::ResourcesListChanged,
        "notifications/resources/updated" => ServerNotification::ResourcesUpdated,
        "notifications/subscriptions/acknowledged" => ServerNotification::SubscriptionsAcknowledged,
        "notifications/tasks" => ServerNotification::Tasks,
        "notifications/tools/list_changed" => ServerNotification::ToolsListChanged,
        _ => return None,
    })
}

fn request_of(method: &str) -> Option<ServerRequestVerb> {
    Some(match method {
        "ping" => ServerRequestVerb::Ping,
        "roots/list" => ServerRequestVerb::RootsList,
        "sampling/createMessage" => ServerRequestVerb::SamplingCreateMessage,
        "elicitation/create" => ServerRequestVerb::ElicitationCreate,
        _ => return None,
    })
}

/// WHY an authority ask was answered the way it was. Two refusals, deliberately distinguishable —
/// see the module header for the two different operator remedies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AskOutcome {
    /// No grant. The remedy is `tools.<server>.grants.<kind>: true`.
    Ungranted,
    /// The grant is held and busbar has no satisfier for this ask on this leg.
    Unsatisfiable,
}

/// DECIDE an authority ask against the operator's per-server grants.
///
/// Takes the grants as a VALUE read at the moment of the decision rather than a captured one, for
/// the reason `super::jsonrpc::InputRequiredLoop::may_satisfy` takes them as a parameter: there is
/// no handshake to authorise once, so a revocation has to bite on the next message and not at the
/// end of a stream that has no end.
pub(crate) fn decide_ask(
    ask: super::jsonrpc::ServerAsk,
    grants: &ServerRequestGrants,
) -> AskOutcome {
    if grants.allows(ask.key()) {
        AskOutcome::Unsatisfiable
    } else {
        AskOutcome::Ungranted
    }
}

/// THE REPLY BUSBAR WRITES BACK on the child's stdin, as one JSON-RPC response value.
///
/// Total over [`ServerRequestVerb`] and over both [`AskOutcome`] arms, so every request a child can
/// send has an answer and none of them can be reached by forgetting to write one.
pub(crate) fn answer(
    id: &serde_json::Value,
    verb: ServerRequestVerb,
    grants: &ServerRequestGrants,
    server: &str,
) -> serde_json::Value {
    let Some(ask) = verb.ask() else {
        // `ping`. An empty result is the whole of the specified answer.
        return serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} });
    };
    let kind = ask.key();
    let message = match decide_ask(ask, grants) {
        AskOutcome::Ungranted => format!(
            "server `{server}` asked busbar to satisfy `{kind}` and its registry entry carries no \
             `{kind}` grant; the ask terminates at busbar and is not proxied to busbar's caller. \
             Set `tools.{server}.grants.{kind}: true` if the operator intends this server to spend \
             that authority."
        ),
        AskOutcome::Unsatisfiable => format!(
            "busbar holds the `{kind}` grant for server `{server}` but has no satisfier for that \
             ask on the stdio leg in this release; the ask terminates here and is not proxied to \
             busbar's caller."
        ),
    };
    error_reply(id, ASK_REFUSED, message)
}

/// The `-32601` a child gets for a request busbar does not implement.
///
/// ANSWERED rather than dropped, which is the point: a dropped request is a child blocked on a
/// reply forever, and a hang is a worse diagnosis than a refusal for exactly the reason
/// `super::stdio` inherits stderr.
pub(crate) fn method_not_found(id: &serde_json::Value, method: &str) -> serde_json::Value {
    error_reply(
        id,
        METHOD_NOT_FOUND,
        format!(
            "busbar's MCP client leg does not implement `{method}`; it answers `ping` and gates \
             `roots/list`, `sampling/createMessage` and `elicitation/create` on the operator's \
             per-server grants."
        ),
    )
}

fn error_reply(id: &serde_json::Value, code: i64, message: String) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/peer_tests.rs"]
mod peer_tests;
