// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO EVENT UNIONS — the four layers projected onto the two directions of travel. Design `plane4-duplex-session.md`.
//!
//! [`IrServerEvent`] is the SIBLING of `busbar-llm`'s `IrStreamEvent` (server→client, response-shaped),
//! NOT an extension of it. [`IrClientEvent`] is the genuine net-new IR work: a client→server event
//! vocabulary that has NO analog anywhere in the tree today (the LLM request path is whole-JSON
//! `IrRequest`, not a stream of events).

use crate::ir::control::IrDuplexControl;
use crate::ir::media::IrMediaFrame;
use crate::ir::tool::IrDuplexTool;
use crate::ir::usage::IrDuplexUsage;

/// CLIENT → SERVER events (`plane4-duplex-session.md`). The union of the client-originated cases across the four layers.
/// **This vocabulary has no analog anywhere in the tree today** — building it is the net-new IR work.
#[derive(Debug, Clone, PartialEq)]
pub enum IrClientEvent {
    /// An uplink media frame (`dir: Up`) — the client's own media, framed.
    MediaFrame(IrMediaFrame),
    /// A session-control / config event the client sent (reconciled against the locked config).
    Control(IrDuplexControl),
    /// A server-side tool RESULT the plane authored back toward the upstream (`CallResult`).
    Tool(IrDuplexTool),
}

/// SERVER → CLIENT events (`plane4-duplex-session.md`). The union of the server-originated cases across the four layers —
/// the sibling of `IrStreamEvent`, plane-owned.
#[derive(Debug, Clone, PartialEq)]
pub enum IrServerEvent {
    /// The upstream acknowledged the session OPEN and returned its resolved config. Carried VERBATIM
    /// as opaque JSON, because the resolved object holds server-assigned fields — an id, the model it
    /// settled on, an expiry — beyond the writable [`crate::ir::config::SessionConfig`] subset, and
    /// exactly which ones is the answering dialect's business, not the IR's.
    SessionOpened {
        /// The resolved session object, opaque.
        session: serde_json::Value,
    },
    /// A tool-call announcement / argument delta / close (`CallOpen` / `CallArgs` / `CallClose`).
    Tool(IrDuplexTool),
    /// The upstream detected the START of client activity on the uplink — the barge-in trigger. On a
    /// voice session that activity is speech; the IR states only that it began, because the modality is
    /// the session's, not this event's.
    ActivityStarted {
        /// Uplink-buffer offset (ms) where the activity began.
        at_ms: u64,
        /// The conversation item the buffered speech is being attributed to.
        item_id: String,
    },
    /// The upstream detected the END of that activity. `at_ms` is the carrier the truncate math reads
    /// to bound the turn just taken in.
    ActivityStopped {
        /// Uplink-buffer offset (ms) where the activity ended.
        at_ms: u64,
        /// The conversation item the buffered speech is being attributed to.
        item_id: String,
    },
    /// A downlink media frame (`dir: Down`) — the upstream's own media, framed.
    MediaFrame(IrMediaFrame),
    /// The downlink media for an item is complete.
    MediaDone {
        /// The item whose media just completed.
        item_id: String,
    },
    /// Extracted usage for a completed turn — a metering fact, read and never client-translated.
    Usage(IrDuplexUsage),
    /// A rate-limit update the upstream volunteered — extraction-only.
    RateLimits,
    /// An upstream error surfaced on the session.
    Error {
        /// A stable, dialect-normalized error code.
        code: String,
        /// A human-readable message.
        message: String,
    },
}
