// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUBSCRIBE IR data — the `Operation::SUBSCRIBE` request/response pair.
//!
//! A caller names a thing and asks to start — or to stop — being told when it changes. That is the
//! whole operation, and it is two directions of ONE shape: the name is the same name, the answer is
//! the same acknowledgement, and the only difference is which way the registration moves. MCP spells
//! the pair `resources/subscribe` and `resources/unsubscribe`; A2A spells it as the
//! push-notification-configuration verbs. They are the same request.
//!
//! `SubscribeResp` carries an OPTIONAL registration record rather than pretending every peer returns
//! one, so a cell never has to invent a body its own wire does not have.
//!
//! The family-blind `IrFacts` projection over `SubscribeReq` lives in `busbar-core`
//! (`crate::ir::subscribe`), beside the engine seam it feeds; core re-exports these types.

use super::SourceScopedExtra;
use serde_json::Value;

/// WHICH WAY THE REGISTRATION MOVES. Not a boolean: `subscribe: false` reads as "this is not a
/// subscription" at every call site, which is the opposite of what it would mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeIntent {
    /// Start being told about the named target.
    Register,
    /// Stop being told about it.
    Deregister,
}

/// A REQUEST TO START OR STOP FOLLOWING ONE NAMED TARGET. The request half of the `Subscribe`
/// operation.
#[derive(Debug, Clone, PartialEq)]
pub struct SubscribeReq {
    /// Whether this registers or deregisters.
    pub intent: SubscribeIntent,
    /// THE THING BEING FOLLOWED, in the caller's vocabulary. A resource URI on MCP. Carried as an
    /// opaque string and never parsed here: deciding whether a caller may follow this target is an
    /// admission question answered against the catalogue, and a codec that started interpreting the
    /// name would be a second place that opinion lives.
    pub target: String,
    /// Unmodelled request members, kept keyed so a cross-protocol hop cannot leak a source-only key
    /// into a foreign dialect. Same discipline as every other operation's `extra`.
    pub extra: SourceScopedExtra,
}

/// WHAT A SUBSCRIPTION REQUEST PRODUCED. The response half.
#[derive(Debug, Clone, PartialEq)]
pub struct SubscribeResp {
    /// The registration record the peer returned, when its wire returns one. `None` is the honest
    /// answer for a protocol whose acknowledgement is empty, and it is deliberately distinct from
    /// `Some({})`: one says the peer returns no record, the other says it returned an empty one.
    pub registration: Option<Value>,
    /// Unmodelled response members, source-keyed for the same reason as the request's.
    pub extra: SourceScopedExtra,
}
