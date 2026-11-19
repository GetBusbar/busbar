// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector` — THE CONNECTOR (THE DESIGN: connections). The chain is kernel →

#![deny(unsafe_code)]
#![deny(missing_docs)]
// Futures over the serving App's credential custody graph prove Send through more than the
// default 128 auto-trait steps (see busbar-kernel's lib.rs); the graph is acyclic.
#![recursion_limit = "256"]

// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
#[path = "conns.rs"]
mod conns;
pub use conns::*;

// The one cold module (LINT-RULES LR-167): refusal and diagnostic text the request-path tree beside
// it calls out of line.
mod cold;
// The request-path tree's code that runs off the request path: once per configuration, binding or
// process lifecycle, never per request.
mod off_path;

// The outbound parts (delivery record, sealing, credit, lending, redial, the proxy tunnel, the
// WebSocket upstream): each owns no socket and calls no plugin. They are bolted onto the native
// dial by the plumbing cards; the `dead_code` allowance goes with the last of those cards.
#[allow(dead_code)]
mod outbound;

// The Need handlers (IF 13): `HostNeeds` over the guard, the transport-security gate, the pool and
// the conn table. Core-side only; no plugin text crosses it.
pub mod need;
pub mod response_delivery;

/// The hold on an answer's last piece (`advanced.wait_for_commit`): the engine's own. When an answer must
/// wait for its record, the engine does not give the transport the piece that completes it until the
/// record is in; with the setting off nothing is withheld and nothing is paid.
pub mod hold {
    pub use crate::outbound::delivery::{Hold, Piece};
}

#[cfg(test)]
#[path = "tests/native_need_authority_tests.rs"]
mod native_need_authority_tests;
