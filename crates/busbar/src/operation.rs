// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `Operation` axis — busbar's semantic operation vocabulary.
//!
//! A coarse TAG only: a metrics label and the `paths:` config key. It carries NO capability booleans
//! — whether a given (protocol, operation, model) streams or reports usage is an OperationHandler fact and lives on
//! the `OperationHandler`, not here. Variant names are 1:1 with `enum IrReq`/`IrResp` wherever an IR
//! subclass exists, so the egress-`write` dispatch is a trivial same-name match; the operations whose
//! IR subclass has not landed yet keep the name they will carry when it does.
//!
//! Semantic, endpoint-count-agnostic: `translation` is `Transcription` with a `target_language`;
//! image edit/variation are `Image` with an `op` discriminant — NOT separate operations.
//!
//! Foundation type; `dead_code` allowed until the Router/IR wiring lands.

/// The semantic operations busbar speaks. Closed set — adding one is a compile error at
/// every exhaustive match (the removability/symmetry gate).
///
/// **The first seven are the LLM surface. The last six are the protocol surface**, and they are
/// listed here rather than modelled as planes of their own because the gate above is exactly the
/// mechanism they need — every site that must decide something about them now refuses to compile
/// until it does, which is the opposite of how the MCP plane was built the first time (beside the
/// pipeline, where no compiler could ask it anything).
///
/// **GRANULARITY FOLLOWS IR SHAPE, NOT METHOD COUNT.** One variant per MCP/A2A method would be ~20
/// arms at every exhaustive match, for a tag this module documents as coarse. Every MCP and every
/// A2A method lands on one of the six below because they share six request/response shapes:
///
/// | operation | shape | MCP | A2A |
/// |---|---|---|---|
/// | [`Operation::Invoke`] | named target + args → content/artifacts or error | `tools/call`, `completion/complete`, `sampling/createMessage` | `message/send`, `message/stream` |
/// | [`Operation::Catalogue`] | query → list of named things with schemas | `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | agent card, `agent/getAuthenticatedExtendedCard` |
/// | [`Operation::Fetch`] | named thing → its content | `resources/read`, `prompts/get` | — |
/// | [`Operation::Task`] | id → state/artifacts, or a lifecycle command | `tasks/get`, `tasks/update`, `tasks/cancel` | `tasks/get`, `tasks/list`, `tasks/cancel`, `tasks/resubscribe` |
/// | [`Operation::Subscribe`] | register/deregister a callback or stream | `resources/subscribe`, `resources/unsubscribe` | `tasks/pushNotificationConfig/{set,get,list,delete}` |
/// | [`Operation::Control`] | handshake, liveness, knobs | `initialize`, `ping`, `logging/setLevel` | — |
///
/// **STREAMING IS NOT AN OPERATION.** `wants_stream()` is already an `OperationHandler` fact, which
/// is why A2A `message/stream` is [`Operation::Invoke`] and not a variant of its own — the same
/// request shape, answered incrementally.
///
/// **Both directions ride the same six.** busbar-as-client calling `tools/list` upstream is
/// `Catalogue` egress; busbar-as-server answering it is `Catalogue` ingress. That is what makes
/// bidirectional support cost nothing extra on this axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Operation {
    Chat,
    Embeddings,
    Moderation,
    Image,
    Transcription,
    Speech,
    Rerank,
    /// A caller names a target and hands it arguments, and gets content or an error back. Was
    /// `ToolCall` through 1.5: it now carries A2A `message/send` as well as MCP `tools/call`, so
    /// the MCP-flavoured name would have been a protocol branch waiting to happen. The engine
    /// must never learn which protocol it is serving, and a name that says `tool` invites it to.
    Invoke,
    // THE FIVE BELOW HAVE NO CONSTRUCTOR YET — no `resolve_operation` names them, because the cells
    // that read their wire land in their own units, each proven against the conformance suite. They
    // land here FIRST and deliberately: their arrival is what makes every exhaustive match in the
    // tree a compile error until it has an answer, which is the whole mechanism, and it is the
    // reverse of how the MCP plane was built the first time. `cfg_attr(not(test), allow(dead_code))`
    // is the same idiom `IrReq::Invoke` used for the same reason — it is scoped to the VARIANT's
    // never-constructed warning and to nothing else; no match site anywhere is suppressed. The
    // attribute comes off the moment a cell constructs the variant.
    //
    /// A query answered with a list of named things and their schemas. The discovery half of every
    /// protocol on this axis; it is one operation because a tool list, a resource list and an agent
    /// card differ in their CONTENT, not in their shape.
    #[cfg_attr(not(test), allow(dead_code))]
    Catalogue,
    /// A named thing resolved to its content. Distinct from [`Operation::Invoke`] because nothing
    /// runs: there are no arguments and no execution, so nothing to bill per call and nothing that
    /// can fail the way a tool can fail.
    #[cfg_attr(not(test), allow(dead_code))]
    Fetch,
    /// A task id resolved to its state and artifacts, or a lifecycle command applied to one.
    ///
    /// **THIS IS THE ROW THAT PAYS FOR THE WHOLE THESIS, AND IT MUST NOT BE SPLIT.** MCP tasks and
    /// A2A tasks are the SAME SHAPE, so they land on the SAME operation and share the one durable
    /// task store. Two variants here would make "one core, many protocols" an assertion again — a
    /// `McpTask`/`A2aTask` pair is an `if protocol ==` spelled as an enum, and every exhaustive
    /// match in the tree would then have to decide the same thing twice.
    #[cfg_attr(not(test), allow(dead_code))]
    Task,
    /// Registration and deregistration of a callback or a stream. The subject is the SUBSCRIPTION,
    /// not the events: delivering them is the transport's business, and an operation that tried to
    /// model the delivery would be modelling a channel rather than a request.
    #[cfg_attr(not(test), allow(dead_code))]
    Subscribe,
    /// Handshake, liveness and knobs — the operations that are ABOUT the connection rather than
    /// about a payload. They share a shape (small in, small out, no model, no billing subject) and
    /// they are the reason a protocol can be spoken at all, so they are an operation like any other
    /// rather than a special case wired beside the matrix.
    #[cfg_attr(not(test), allow(dead_code))]
    Control,
}

impl Operation {
    /// Stable identifier — the metrics label and the `paths:` config key.
    ///
    /// **OPERATOR-VISIBLE CONTRACT.** These strings appear in dashboards and in configuration files;
    /// changing one silently breaks a `paths:` key and re-bases a metric series. `snake_case`,
    /// singular, and named for the SHAPE rather than for any one protocol's method — `invoke`, not
    /// `tool_call`; `catalogue`, not `list_tools`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Operation::Chat => "chat",
            Operation::Embeddings => "embeddings",
            Operation::Moderation => "moderation",
            Operation::Image => "image",
            Operation::Transcription => "transcription",
            Operation::Speech => "speech",
            Operation::Rerank => "rerank",
            Operation::Invoke => "invoke",
            Operation::Catalogue => "catalogue",
            Operation::Fetch => "fetch",
            Operation::Task => "task",
            Operation::Subscribe => "subscribe",
            Operation::Control => "control",
        }
    }
}

#[cfg(test)]
#[path = "tests/operation_tests.rs"]
mod tests;
