// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `Operation` axis — busbar's semantic operation vocabulary, in TWO parts.
//!
//! ```text
//! Operation::Verb { op: OpShape, name: &'static str }
//!                   ^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^
//!                   THE SHAPE      THE WORD ON THE WIRE
//!                   core's         data a protocol supplies
//!                   closed tag     about itself
//! ```
//!
//! Read this file as a pair with `transport.rs`, exactly as that file's header says: both are
//! coarse, closed tags whose whole value is that adding a variant is a compile error at every site
//! that must now decide something. What changed here in 1.6.0 is WHICH tag carries that property.
//!
//! ## WHY THE SPLIT, AND WHAT WENT WRONG WITHOUT IT
//!
//! `Operation` was thirteen flat variants: seven named for LLM endpoints (`Chat`, `Embeddings`,
//! `Moderation`, `Image`, `Transcription`, `Speech`, `Rerank`) and six named for shapes (`Invoke`
//! … `Control`). The six were already the product of this same collapse — one variant per MCP/A2A
//! METHOD would have been ~20 arms at every exhaustive match — but the seven were never put
//! through it, because when they were written there was only one protocol family and its endpoint
//! names and its shapes were indistinguishable.
//!
//! They are distinguishable now, and the difference is the whole of the plugin seam. `Operation` is
//! the vocabulary the plugin ABI carries across a `dlopen` boundary. A verb named for one family's
//! endpoint, sitting in a core enum, means a plugin author adding a protocol must edit a CORE type
//! to name their own methods — which is precisely the coupling the seam exists to remove, and it
//! fails the deletion test on line one: "delete mcp should be 4 files or so, and the app never knew
//! it existed" is not true of a core enum that had to list mcp's verbs.
//!
//! So the core keeps the part that is genuinely core — the SHAPE of the exchange — and the wire
//! word rides as DATA.
//!
//! ## THE SHAPES ARE DERIVED FROM REQUEST/RESPONSE SHAPE, NOT FROM METHOD COUNT
//!
//! | shape | the exchange | LLM | MCP | A2A |
//! |---|---|---|---|---|
//! | [`OpShape::Invoke`] | named target + args → content/artifacts or error | every one of the seven: a model + arguments answered with a result | `tools/call`, `completion/complete`, `sampling/createMessage` | `message/send`, `message/stream` |
//! | [`OpShape::Catalogue`] | query (+cursor) → list of named things with schemas | — | `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | agent card, `agent/getAuthenticatedExtendedCard` |
//! | [`OpShape::Fetch`] | named thing → its content; nothing runs | — | `resources/read`, `prompts/get` | — |
//! | [`OpShape::Task`] | id → state/artifacts, or a lifecycle command | — | `tasks/get`, `tasks/update`, `tasks/cancel` | `tasks/get`, `tasks/list`, `tasks/cancel`, `tasks/resubscribe` |
//! | [`OpShape::Subscribe`] | target + intent → an acknowledgement | — | `resources/subscribe`, `resources/unsubscribe` | `tasks/pushNotificationConfig/{set,get,list,delete}` |
//! | [`OpShape::Control`] | handshake, liveness, knobs; no subject | — | `initialize`, `ping`, `logging/setLevel` | — |
//!
//! **THE SEVEN LLM VERBS ARE ALL ONE SHAPE, and that is a finding rather than a convenience.** A
//! chat completion, an embedding, a moderation, an image, a transcription, a speech synthesis and a
//! rerank are the SAME exchange: name a model, hand it arguments, get content or an error back.
//! Everything that differs between them — does it stream, does it report usage, is the body
//! multipart, is the response bytes rather than JSON — is ALREADY an `OperationHandler` fact and has
//! been since this module's first header said so ("it carries NO capability booleans"). What was
//! left on the tag after those facts moved to the vtable was the endpoint's NAME, which is what now
//! rides in `name`.
//!
//! **STREAMING IS NOT AN OPERATION**, for the same reason and unchanged: `wants_stream()` is an
//! `OperationHandler` fact, which is why A2A `message/stream` and `message/send` are one shape.
//!
//! **Both directions ride the same shapes.** busbar-as-client calling `tools/list` upstream is a
//! `Catalogue` egress; busbar-as-server answering it is a `Catalogue` ingress.
//!
//! ## WHAT IS LOAD-BEARING TODAY, STATED RATHER THAN CLAIMED
//!
//! Two of the six carry traffic: [`OpShape::Invoke`] (all seven LLM verbs plus MCP `tools/call`)
//! and [`OpShape::Subscribe`] (MCP `resources/{,un}subscribe`). Those two are the ones with an IR
//! subclass and a constructor. The other four are declared AHEAD of the cells that will construct
//! them, which is the same deliberate posture the previous header took and for the same reason:
//! their arrival is what makes every exhaustive match a compile error until it has an answer.
//!
//! ## `name` IS A METRIC LABEL, SO ITS VALUES ARE CLOSED
//!
//! [`Operation::name`] is the tracing/metrics `op` field and the `paths:` config key. An unbounded
//! caller-supplied string reaching it is a cardinality explosion. Nothing constructs an `Operation`
//! from the wire: the entire set of values that exist is [`Operation::ALL`] (the six shape verbs
//! the core owns) plus `proto::registry::declared_verbs()` (the verbs the registered protocols
//! declare, folded at boot from `ProtocolDecl::verbs` — the seven LLM words arrive this way).
//! Every one of them is an associated `const` — here for the shapes, in `operation.rs` still for
//! the seven LLM verbs that `ir::variant` constructs — and a protocol's `resolve_operation`
//! RETURNS one of these constants after matching the wire word; it never builds one out of the
//! wire word. `Verb`'s fields are `pub(crate)` to this module's readers by pattern only; the
//! constants are the constructors.

/// THE SHAPE OF AN EXCHANGE — the closed tag the agnostic core is allowed to know about, and the
/// half of [`Operation`] that survives a `dlopen` boundary as a discriminant rather than as a word.
///
/// Closed set — adding one is a compile error at every exhaustive match (the removability/symmetry
/// gate, now pointed at the thing that is genuinely core). There is no catch-all arm anywhere in the
/// tree on this type, deliberately: a `_ =>` here would mean a shape arrived and nothing had to
/// decide anything about it, which is the failure this tag exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OpShape {
    /// A caller names a target and hands it arguments, and gets content or an error back. The only
    /// shape with a BILLING SUBJECT and the only one that can be answered incrementally: something
    /// ran, it took a measurable amount of work, and the answer can arrive in pieces.
    Invoke,
    /// A query answered with a list of named things and their schemas. The discovery half of every
    /// protocol on this axis; one shape because a tool list, a resource list and an agent card
    /// differ in their CONTENT, not in their shape.
    Catalogue,
    /// A named thing resolved to its content. Distinct from [`OpShape::Invoke`] because nothing
    /// runs: there are no arguments and no execution, so nothing to bill per call and nothing that
    /// can fail the way a tool can fail.
    Fetch,
    /// A task id resolved to its state and artifacts, or a lifecycle command applied to one.
    ///
    /// **THIS IS THE ROW THAT PAYS FOR THE WHOLE THESIS, AND IT MUST NOT BE SPLIT.** MCP tasks and
    /// A2A tasks are the SAME SHAPE, so they land on the SAME shape. Two of these would make "one
    /// core, many protocols" an assertion again — an `McpTask`/`A2aTask` pair is an `if protocol ==`
    /// spelled as an enum, and every exhaustive match in the tree would decide the same thing twice.
    ///
    /// **ONE SHAPE IS NOT YET ONE STORE, and the gap is stated rather than glossed.** The two planes
    /// are backed by two substrates today: [`crate::a2a::taskstore`] writes every state change
    /// through to the configured governance store and rehydrates at boot, while [`crate::mcp::tasks`]
    /// is an IN-PROCESS registry that disclaims durability in its own header. That is a property of
    /// the SUBSTRATE, not of this axis.
    Task,
    /// Registration and deregistration of a callback or a stream. The subject is the SUBSCRIPTION,
    /// not the events: delivering them is the transport's business, and a shape that tried to model
    /// the delivery would be modelling a channel rather than a request.
    Subscribe,
    /// Handshake, liveness and knobs — the exchanges that are ABOUT the connection rather than about
    /// a payload. Small in, small out, no model, no billing subject.
    Control,
}

impl OpShape {
    /// Every shape, so a site that must cover all of them cannot silently cover some. The same role
    /// `Transport::ALL` and `Plane::ALL` play for their axes.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const ALL: &'static [OpShape] = &[
        OpShape::Invoke,
        OpShape::Catalogue,
        OpShape::Fetch,
        OpShape::Task,
        OpShape::Subscribe,
        OpShape::Control,
    ];

    /// MAY AN EXCHANGE OF THIS SHAPE BE ANSWERED INCREMENTALLY? The core's floor under
    /// [`crate::handlers::OpDispatch::wants_stream`] and
    /// [`crate::handlers::OpDispatch::streaming`], and the one place the shape is a decision rather
    /// than a label.
    ///
    /// It is a FLOOR, not a replacement: a cell that answers `false` still answers `false` (MCP's
    /// `tools/call` is `Invoke` and does not stream). What the floor buys is the direction no cell
    /// can be trusted to get right on its own — a shape that has nothing to stream must not be able
    /// to claim it does, because the engine would then hold a response open for a body that is
    /// never coming. That sentence was already written in prose on `IrReq::wants_stream` for
    /// `Subscribe`; this is the same rule with a compiler behind it.
    ///
    /// Enumerated, never `_`: a shape added without an answer here is a compile error, which is the
    /// whole mechanism.
    pub(crate) const fn may_stream(self) -> bool {
        match self {
            // Something ran and the answer can arrive in pieces.
            OpShape::Invoke => true,
            // A list, a document, a task record, an acknowledgement and a handshake are each ONE
            // answer. Registering is not the stream: the events that follow a subscription travel
            // on the channel the transport already provides, not as an incremental rendering of
            // the registration's own reply.
            OpShape::Catalogue
            | OpShape::Fetch
            | OpShape::Task
            | OpShape::Subscribe
            | OpShape::Control => false,
        }
    }

    /// The shape's own stable word, used as the `name` of the verb a protocol-surface shape carries
    /// when the protocol has not named it something else. Also the shape's label in a test failure.
    ///
    /// Enumerated, never `_`, for the same reason [`Self::may_stream`] is.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            OpShape::Invoke => "invoke",
            OpShape::Catalogue => "catalogue",
            OpShape::Fetch => "fetch",
            OpShape::Task => "task",
            OpShape::Subscribe => "subscribe",
            OpShape::Control => "control",
        }
    }
}

/// ONE SEMANTIC OPERATION — a [`OpShape`] plus the word the wire calls it.
///
/// The `Verb` variant is the only variant and that is the point: the core's decisions are taken on
/// `op`, which is closed, and the word is carried through untouched. A protocol that adds a method
/// adds a `const` in ITS OWN module; it does not touch this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Operation {
    Verb {
        /// The shape the pipeline decides on.
        op: OpShape,
        /// The operator-visible word. BOUNDED: see the module header — every value is one of the
        /// constants below, and none is built from a request.
        name: &'static str,
    },
}

impl Operation {
    // ── THE LLM FAMILY'S SEVEN VERBS. All one shape (`Invoke`): name a model, hand it arguments,
    //    get content or an error back. They keep their published names to the letter, because those
    //    names are the metrics label and the `paths:` config key and a rename is a broken dashboard.
    pub(crate) const CHAT: Operation = Operation::llm("chat");
    pub(crate) const EMBEDDINGS: Operation = Operation::llm("embeddings");
    pub(crate) const MODERATION: Operation = Operation::llm("moderation");
    pub(crate) const IMAGE: Operation = Operation::llm("image");
    pub(crate) const TRANSCRIPTION: Operation = Operation::llm("transcription");
    pub(crate) const SPEECH: Operation = Operation::llm("speech");
    pub(crate) const RERANK: Operation = Operation::llm("rerank");

    // ── THE PROTOCOL SURFACE'S SIX. One verb per shape today, carrying the shape's own word: MCP
    //    and A2A both address these through their own method names, which the protocol's
    //    `resolve_operation` maps onto these constants. When a cell needs to distinguish two verbs
    //    of one shape (`tools/list` from `prompts/list`), it adds a constant beside these with the
    //    SAME `op` and its own `name` — an addition in the protocol's vocabulary, not in the core's.
    pub(crate) const INVOKE: Operation = Operation::of(OpShape::Invoke);
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const CATALOGUE: Operation = Operation::of(OpShape::Catalogue);
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const FETCH: Operation = Operation::of(OpShape::Fetch);
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const TASK: Operation = Operation::of(OpShape::Task);
    pub(crate) const SUBSCRIBE: Operation = Operation::of(OpShape::Subscribe);
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const CONTROL: Operation = Operation::of(OpShape::Control);

    /// EVERY OPERATION THE CORE ITSELF OWNS — the six protocol-surface verbs, one per shape. This
    /// used to also list the seven LLM verbs, which made it a core table naming one family's
    /// endpoints — exactly the coupling the module header calls out, and the reason the deletion
    /// test passed "in the weakest sense": with every LLM protocol deleted, `ALL` still published
    /// `chat`…`rerank` as if something served them. The LLM rows now reach the vocabulary from the
    /// protocol DECLARATIONS instead (`proto::registry::declared_verbs()`, folded at boot from
    /// `ProtocolDecl::verbs`), so a protocol's verbs leave when the protocol does. The closed
    /// metric-label surface the header promises is `ALL ∪ declared_verbs()`: both halves are
    /// `&'static` consts fixed at load, and nothing constructs an `Operation` from the wire.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const ALL: &'static [Operation] = &[
        Operation::INVOKE,
        Operation::CATALOGUE,
        Operation::FETCH,
        Operation::TASK,
        Operation::SUBSCRIBE,
        Operation::CONTROL,
    ];

    /// An LLM-family verb: one shape, seven words. Private, `const`, and the only way the seven are
    /// spelled — so "are they really all one shape?" is answered by the constructor rather than by
    /// seven arms that could drift.
    const fn llm(name: &'static str) -> Operation {
        Operation::Verb {
            op: OpShape::Invoke,
            name,
        }
    }

    /// The verb a shape carries when the shape's own word is the name. Private for the same reason
    /// [`Self::llm`] is: constructing an `Operation` is this module's business.
    const fn of(op: OpShape) -> Operation {
        Operation::Verb {
            op,
            name: op.as_str(),
        }
    }

    /// The shape the core decides on.
    pub(crate) const fn shape(self) -> OpShape {
        match self {
            Operation::Verb { op, .. } => op,
        }
    }

    /// Stable identifier — the metrics label and the `paths:` config key.
    ///
    /// **OPERATOR-VISIBLE CONTRACT.** These strings appear in dashboards and in configuration files;
    /// changing one silently breaks a `paths:` key and re-bases a metric series. `snake_case`,
    /// singular, and named for the SHAPE rather than for any one protocol's method — `invoke`, not
    /// `tool_call`; `catalogue`, not `list_tools`. The seven LLM words are the exception the header
    /// explains: they are endpoint names that were already published, and republishing them under
    /// their shape's word would break every dashboard to prove a point about tidiness.
    ///
    /// BOUNDED BY CONSTRUCTION — see the module header. This returns a field, not a computation,
    /// and the field's only possible values are the constants above.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Operation::Verb { name, .. } => name,
        }
    }
}

#[cfg(test)]
#[path = "tests/operation_tests.rs"]
mod tests;
