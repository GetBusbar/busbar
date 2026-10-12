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
//! | `ping` | ANSWERED on the child's stdin, then keep reading |
//! | a granted authority ask | RELAYED to busbar's caller, who answers it (Law 11) |
//! | an ungranted authority ask | refused on the child's stdin, then keep reading |
//! | a request busbar does not know | answered `-32601`, then keep reading |
//!
//! A request left unanswered is a child blocked forever on a reply, which presents as a hang — the
//! same failure mode a piped-and-undrained stderr produces, and it is refused for the same reason.
//!
//! ## THE THREE AUTHORITY ASKS ARE THE CALLER'S, BEHIND A DENY-BY-DEFAULT GRANT
//!
//! `sampling/createMessage`, `elicitation/create` and `roots/list` are asks for something only the
//! caller has: an LLM completion, a human's attention, the disclosure of filesystem structure.
//! Busbar answers none of them on the caller's behalf (Law 11): a granted ask goes to the caller of
//! the call the child is serving as plane traffic (BUSBAR-1.6.0 Part 3 B.3 item 10), and the
//! caller's answer comes back to the child under its own request id. Arriving over a child's stdout
//! does not make an ask cheaper than arriving inline in an `InputRequiredResult`, so it gets the
//! same gate: `super::jsonrpc::ServerRequestGrants`, all-false unless an operator set them, read as
//! a RELAY PERMISSION.
//!
//! - **[`AskOutcome::Relay`]** — the operator lets this server put that ask to its callers.
//! - **[`AskOutcome::Ungranted`]** — it does not. The ask is refused on the child's input
//!   (`ask_ungranted`): busbar enforcing the operator's policy, not answering for the caller. The
//!   remedy is `tools.<server>.grants.<kind>: true`.
//!
//! ## `ping` IS ANSWERED, and it is the one that is not an ask
//!
//! A ping carries no authority, discloses nothing, and its whole purpose is to let a peer tell a
//! live process from a wedged one. Refusing it would make busbar look dead to every child that
//! probes, which is the outcome the probe exists to detect. So it is answered with an empty result,
//! unconditionally, and it is the only server-originated request that is.
//!
//! ## Contents are NEVER read for a routing or trust decision
//!
//! The four "something changed" notifications can only bring a re-pull FORWARD, through
//! the engine's `mcp::client::catalogue::RefreshGate`, which is rate-limited. Their payloads are not parsed and not
//! believed. That is the engine's `mcp::client::catalogue`'s own rule — an attacker-controlled trigger may not choose
//! the moment freely and may not choose the content at all — and this module is the second place it
//! is now enforced rather than the first place it is bypassed.

use super::jsonrpc::ServerRequestGrants;

/// JSON-RPC standard: the method is not implemented.
///
/// A local re-statement rather than an import of the engine's `mcp::envelope::code`, and it is the one
/// duplicated number in this module: that module's codes are `pub(super)`/`pub(in crate::mcp)` on
/// the SERVER plane's ingress, and widening their visibility so the client leg could borrow one
/// would make the ingress vocabulary reachable from the outbound half. The value is the JSON-RPC
/// specification's, not busbar's, so there is no busbar decision here for the two copies to drift on.
const METHOD_NOT_FOUND: i64 = -32601;

/// The code busbar refuses an authority ask it will not relay with.
///
/// `-32001`, in the implementation-defined server-error range, and NOT `-32601`: the method is
/// recognised and implemented, and the answer is a policy decision. Telling a child "no such method"
/// when the truth is "you may not have that" would send its author looking for a version mismatch.
pub const ASK_REFUSED: i64 = -32001;

/// ONE MESSAGE A CHILD SENT, classified.
///
/// Note what is NOT an arm: a RESPONSE. [`classify`] returns `None` for anything carrying `result`
/// or `error`, so a response can only ever leave this module as "not a server message" and be
/// correlated by the caller. Making a response representable here would create a second place a
/// response could be consumed, which is the desynchronisation this module exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMessage {
    /// A notification busbar recognises. No reply, ever.
    Notification(ServerNotification),
    /// A notification busbar does not recognise. Still no reply — a notification is defined as
    /// unanswerable, and answering an unknown one would be busbar inventing a response to a message
    /// whose sender is not listening.
    UnknownNotification(String),
    /// A request busbar recognises. MUST be answered.
    Request {
        /// The request's JSON-RPC id, echoed on the reply.
        id: serde_json::Value,
        /// Which of the four requests it is.
        verb: ServerRequestVerb,
    },
    /// A request busbar does not recognise. MUST STILL BE ANSWERED, with `-32601`. Dropping it
    /// leaves the child blocked on a reply that never comes.
    UnknownRequest {
        /// The request's JSON-RPC id, echoed on the `-32601` reply.
        id: serde_json::Value,
        /// The method name as the peer sent it.
        method: String,
    },
}

/// THE NINE NOTIFICATIONS A SERVER MAY SEND, closed.
///
/// Closed so that a tenth cannot be handled by a default arm that treats it as one of these — which
/// on the four refresh triggers would mean an unknown method able to drive busbar's re-pull.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerNotification {
    /// The peer withdrew a request it had sent busbar.
    Cancelled,
    /// A log record. RFC 5424 severity in `params.level`.
    Message,
    /// Progress on a call busbar has in flight.
    Progress,
    /// The peer's prompt list changed.
    PromptsListChanged,
    /// The peer's resource list changed.
    ResourcesListChanged,
    /// One resource's contents changed. Distinct from `ResourcesListChanged`: the LIST is the same
    /// and one member of it moved.
    ResourcesUpdated,
    /// The peer accepted a `subscriptions/listen` busbar sent.
    SubscriptionsAcknowledged,
    /// A task busbar created moved.
    Tasks,
    /// The peer's tool list changed.
    ToolsListChanged,
}

/// THE FOUR REQUESTS A SERVER MAY SEND, closed. Three of them are authority asks; one is a ping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerRequestVerb {
    /// Liveness. The only one that is not gated — see the module header.
    Ping,
    /// `roots/list`: disclose the caller's filesystem roots, if it answers.
    RootsList,
    /// `sampling/createMessage`: an LLM completion, which the caller runs if it answers.
    SamplingCreateMessage,
    /// `elicitation/create`: solicit user input.
    ElicitationCreate,
}

impl ServerRequestVerb {
    /// The grant this request asks to spend, or `None` for the one that spends nothing.
    ///
    /// Returns the same three key words `ServerRequestGrants::allows` reads, taken from
    /// [`super::jsonrpc::ServerAsk`] rather than spelled again — a second spelling of `"sampling"`
    /// is a second thing to get wrong, and the failure mode is a grant check that silently never
    /// matches and therefore always denies, which looks exactly like a correctly-configured denial.
    pub fn ask(self) -> Option<super::jsonrpc::ServerAsk> {
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
pub enum NotificationEffect {
    /// Bring a `tools/list` re-pull forward, subject to the engine's `mcp::client::catalogue::RefreshGate`. The
    /// notification's CONTENTS are not read — see the module header.
    BringRefreshForward,
    /// `notifications/resources/updated` — everything [`NotificationEffect::BringRefreshForward`]
    /// does, PLUS record `(server, params.uri)` into the engine's `mcp::client::pool::ResourceUpdates` so the
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
    pub fn effect(self) -> NotificationEffect {
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
/// ## THE HANG THIS FUNCTION USED TO PRODUCE
///
/// JSON-RPC 2.0 section 4 is explicit: a notification is a request whose `id` member is ABSENT — not one
/// whose `id` holds `null`. This function used to decide notification-ness by filtering `id` on
/// nullness (`.filter(|v| !v.is_null())`), which collapses a PRESENT-but-null id into "absent". Many
/// JSON-RPC encoders — serde's default among them, for any struct whose `id` field always serializes
/// — spell an absent id as an explicit `null` on the wire. Such a peer's `roots/list` was therefore
/// read as a notification, busbar never replied, and the child blocked forever on an answer that was
/// never coming: a well-behaved, conformant peer produced a permanent, silent hang.
///
/// The discriminator is now the METHOD FIRST, against the closed notification table
/// ([`notification_of`]): a known notification method is a notification regardless of what `id`
/// carries. Everything else is read by whether the `id` MEMBER IS PRESENT, never by its value — so a
/// request method with an explicit `null` id is still a request, and MUST be answered, echoing that
/// same `null` back as the JSON-RPC base specification allows. An `id`-absent line on an unrecognised
/// method still reads as a notification (see [`ServerMessage::UnknownNotification`]): the fix is
/// "read presence, not nullness", never "answer everything".
pub fn classify(value: &serde_json::Value) -> Option<ServerMessage> {
    let obj = value.as_object()?;
    // A response, not a message. Checked FIRST and by the presence of the members rather than by the
    // absence of `method`, so a malformed line carrying both is read as the response it claims to be
    // and fails correlation — rather than being executed as a request the peer never meant to send.
    if obj.contains_key("result") || obj.contains_key("error") {
        return None;
    }
    let method = obj.get("method").and_then(|m| m.as_str())?;
    // METHOD FIRST: a known notification method is a notification no matter what `id` holds — see
    // the header above for why reading `id`'s value at all, before this check, is the defect.
    if let Some(n) = notification_of(method) {
        return Some(ServerMessage::Notification(n));
    }
    // Now `id` is read by PRESENCE only. `unwrap_or(Value::Null)` cannot silently invent a value: the
    // `contains_key` guard above already proved the member is there, so this only ever unwraps a
    // `Some` — a defensive fallback, not a second decision.
    if !obj.contains_key("id") {
        return Some(ServerMessage::UnknownNotification(method.to_string()));
    }
    let id = obj.get("id").cloned().unwrap_or(serde_json::Value::Null);
    Some(match request_of(method) {
        Some(verb) => ServerMessage::Request { id, verb },
        None => ServerMessage::UnknownRequest {
            id,
            method: method.to_string(),
        },
    })
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

/// WHAT BECOMES OF an authority ask: relayed to the caller, or refused by the operator's grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskOutcome {
    /// The grant is held: the ask goes to busbar's caller, who answers it.
    Relay,
    /// No grant. The remedy is `tools.<server>.grants.<kind>: true`.
    Ungranted,
}

/// DECIDE an authority ask against the operator's per-server grants.
///
/// Takes the grants as a VALUE read at the moment of the decision rather than a captured one: there
/// is no handshake to authorise once, so a revocation has to bite on the next message and not at the
/// end of a stream that has no end.
pub fn decide_ask(ask: super::jsonrpc::ServerAsk, grants: &ServerRequestGrants) -> AskOutcome {
    if grants.allows(ask) {
        AskOutcome::Relay
    } else {
        AskOutcome::Ungranted
    }
}

/// THE REPLY BUSBAR WRITES BACK on the child's stdin, as one JSON-RPC response value: `ping`'s empty
/// result, or an ungranted ask's refusal. `None` for a granted ask: it is the caller's to answer,
/// and busbar writes nothing in its place (Law 11).
pub fn answer(
    id: &serde_json::Value,
    verb: ServerRequestVerb,
    grants: &ServerRequestGrants,
    server: &str,
) -> Option<serde_json::Value> {
    let Some(ask) = verb.ask() else {
        // `ping`. An empty result is the whole of the specified answer.
        return Some(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} }));
    };
    let kind = ask.key();
    match decide_ask(ask, grants) {
        AskOutcome::Relay => None,
        AskOutcome::Ungranted => Some(refused(
            id,
            "ask_ungranted",
            format!(
                "server `{server}` asked for `{kind}` and its registry entry carries no `{kind}` \
                 grant, so the ask is not relayed to busbar's caller. Set \
                 `tools.{server}.grants.{kind}: true` if the operator intends this server to put \
                 that ask to its callers."
            ),
        )),
    }
}

/// A REFUSAL of an ask of the child's own, written on its input: `-32001`, `message`, and the audit
/// reason word in `data` (the operator's grant, the round cap, or a relay the deployment cannot
/// carry).
pub fn refused(id: &serde_json::Value, reason: &str, message: String) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": ASK_REFUSED, "message": message, "data": { "reason": reason } },
    })
}

/// The `-32601` a child gets for a request busbar does not implement.
///
/// ANSWERED rather than dropped, which is the point: a dropped request is a child blocked on a
/// reply forever, and a hang is a worse diagnosis than a refusal for exactly the reason
/// the engine's `mcp::client::stdio` inherits stderr.
pub fn method_not_found(id: &serde_json::Value, method: &str) -> serde_json::Value {
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

#[cfg(test)]
#[path = "tests/peer_tests.rs"]
mod peer_tests;
