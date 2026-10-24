// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport: a byte stream, and nothing else.
//!
//! The socket is the host's (`BUSBAR-1.6.0.md` THE DESIGN, §5): no plugin opens a socket. This
//! crate is the CARRIER of that stream ([`door`]): it listens, accepts, dials, reads, writes and
//! closes through the host's I/O (`io.*`), holding only the host's opaque handles, and owns the
//! policy over them — one attempt at the one judged address a dial is lent, the accept loop, the chunking
//! of what it reads, how a connection closes and what its far end is. Connection security and any
//! framing above the stream are the host's to stack on it. It spawns no thread and reads no clock.
//! It knows no protocol, no plane and no principal.
//!
//! One door, two ways in: a build that links this crate names [`linked::door`]; the sibling
//! `busbar-transport-tcp-plugin` cdylib exports the same door as its image's one symbol
//! (`export_door!`). This crate exports nothing, so linking it adds no door symbol.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// THE KIND'S SHAPE (`BUSBAR-1.6.0.md` THE DESIGN, §2), the same files every transport twin
// carries: what it declares (`meta`), what it claims (`claims`), the entry (`transport`), and the
// door that states them.
mod claims;
pub mod door;
mod meta;
mod transport;

/// THE TRANSPORT AXIS ENTRY: what the composition root folds for this transport: its key, the
/// layers it declares and its door. The root names none of them.
pub mod linked {
    /// The row's registry key.
    pub const KEY: &str = crate::door::KEY;
    /// The layers this transport declares it can be built over: none, it is the bottom of its stack.
    pub const COMPOSES_OVER: &[&str] = &[];
    /// Whether this transport carries sessions: the claim row's own bit, read off it (one home).
    pub const SESSION: bool = crate::claims::CLAIMS[0].session == 1;
    pub use crate::door::door;
}
