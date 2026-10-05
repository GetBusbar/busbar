// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio transport: the CARRIER of a spawned program's pipes, one frame per line.
//!
//! No plugin opens a socket or a pipe (`BUSBAR-1.6.0.md` THE DESIGN, §5): the host spawns the program
//! (an absolute path, its arguments and its whole environment, no shell — what the deployment wrote
//! down and nothing it did not), owns its pipes and kills it when the connection closes. This crate
//! holds only the host's opaque handle ([`door`]) and owns the policy over it: the spawn it asks for,
//! one frame per line on the way in, one line per frame on the way out, and the close. It carries no
//! protocol meaning at all — no JSON-RPC, no ids, no correlation table: that belongs to whichever
//! plane rides this transport.
//!
//! One door, two ways in: a build that links this crate names [`linked::door`]; built with its
//! `dropped-in` feature, the crate's cdylib exports the same door as its image's one symbol.

#![deny(unsafe_code)]
#![deny(missing_docs)]

// THE KIND'S SKELETON (`BUSBAR-1.6.0.md` THE DESIGN, §2), the same files every transport twin
// carries: what it declares (`meta`), what it claims (`claims`), the entry (`transport`), and the
// door that states them.
mod claims;
pub mod door;
mod meta;
mod transport;

/// THE TRANSPORT AXIS ENTRY (#3, #30): what the composition root folds for this wire — its key, the
/// layers it declares and its door. The root names none of them.
pub mod linked {
    /// The row's registry key.
    pub const KEY: &str = crate::door::KEY;
    /// The layers this wire declares it can be built over: none, it is the bottom of its stack.
    pub const COMPOSES_OVER: &[&str] = &[];
    /// Whether this wire carries sessions.
    pub const SESSION: bool = true;
    /// THE MEMORY-ABI DOOR the host's connector carries a program's pipes through (the
    /// `transport-door` axis).
    pub use crate::door::door;
}

/// THE DROPPED-IN DOOR (`dropped-in`): the image's one door symbol, this crate's own door. The one
/// item this crate's `#![deny(unsafe_code)]` allows: exporting a symbol is the macro's.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exports {
    busbar_contract::export_door!(crate::door::door);
}
