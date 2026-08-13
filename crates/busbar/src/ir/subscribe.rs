// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUBSCRIBE IR — the `Operation::Subscribe` subclass of the parent
//! [`crate::ir::variant::IrReq`] / [`crate::ir::variant::IrResp`] enums.
//!
//! ## WHAT A SUBSCRIPTION REQUEST IS, REDUCED TO ITS INVARIANTS
//!
//! A caller names a thing and asks to start — or to stop — being told when it changes. That is the
//! whole operation, and it is two directions of ONE shape rather than two shapes: the name is the
//! same name, the answer is the same acknowledgement, and the only difference is which way the
//! registration moves. MCP spells the pair `resources/subscribe` and `resources/unsubscribe`; A2A
//! spells it as the push-notification-configuration verbs. They are the same request.
//!
//! ## THE SUBJECT IS THE REGISTRATION, NEVER THE EVENTS
//!
//! Nothing here models a notification. A subscription request is a request: it is made, it is
//! judged, it is answered, and it is over. The events that follow travel on whatever channel the
//! transport provides, and a request IR that tried to describe them would be describing a channel.
//! The notification vocabulary therefore lives with the protocol cell that frames it, not here.
//!
//! ## WHY REGISTER AND DEREGISTER ARE ONE VARIANT AND NOT TWO
//!
//! Two IR variants would mean every exhaustive match in the tree decides the same question twice,
//! and the second decision is the one that drifts. They differ in a single field, every guard that
//! applies to one applies to the other, and the pair is meaningless if the two ever disagree about
//! what a target name is. One variant with an explicit intent keeps that impossible.
//!
//! ## THE ANSWER CARRIES NOTHING, AND THAT IS A FACT ABOUT THE PROTOCOL
//!
//! MCP answers both verbs with an empty result: the acknowledgement IS the content. Other protocols
//! answer the same shape with the registration record they just stored. [`SubscribeResp`] therefore
//! carries an OPTIONAL record rather than pretending every peer returns one, so a cell never has to
//! invent a body its own wire does not have.

use serde_json::Value;

/// WHICH WAY THE REGISTRATION MOVES. Not a boolean: `subscribe: false` reads as "this is not a
/// subscription" at every call site, which is the opposite of what it would mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscribeIntent {
    /// Start being told about the named target.
    Register,
    /// Stop being told about it.
    Deregister,
}

/// A REQUEST TO START OR STOP FOLLOWING ONE NAMED TARGET. The request half of the `Subscribe`
/// operation.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SubscribeReq {
    /// Whether this registers or deregisters.
    pub(crate) intent: SubscribeIntent,
    /// THE THING BEING FOLLOWED, in the caller's vocabulary. A resource URI on MCP. Carried as an
    /// opaque string and never parsed here: deciding whether a caller may follow this target is an
    /// admission question answered against the catalogue, and a codec that started interpreting the
    /// name would be a second place that opinion lives.
    pub(crate) target: String,
    /// Unmodelled request members, kept keyed so a cross-protocol hop cannot leak a source-only key
    /// into a foreign dialect. Same discipline as every other operation's `extra`.
    pub(crate) extra: crate::lossless::SourceScopedExtra,
}

/// WHAT A SUBSCRIPTION REQUEST PRODUCED. The response half.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SubscribeResp {
    /// The registration record the peer returned, when its wire returns one. `None` is the honest
    /// answer for a protocol whose acknowledgement is empty, and it is deliberately distinct from
    /// `Some({})`: one says the peer returns no record, the other says it returned an empty one.
    pub(crate) registration: Option<Value>,
    /// Unmodelled response members, source-keyed for the same reason as the request's.
    pub(crate) extra: crate::lossless::SourceScopedExtra,
}
