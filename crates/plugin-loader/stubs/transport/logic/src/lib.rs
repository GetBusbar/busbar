// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport: a byte stream, and nothing else.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod claims;
pub mod door;
mod meta;
mod transport;

/// THE TRANSPORT AXIS ENTRY: what the composition root folds for this transport: its key, the

pub mod linked {
    /// The row's registry key.
    pub const KEY: &str = crate::door::KEY;
    /// The layers this transport declares it can be built over: none, it is the bottom of its stack.
    pub const COMPOSES_OVER: &[&str] = &[];
    /// Whether this transport carries sessions: the claim row's own bit, read off it (one home).
    pub const SESSION: bool = crate::claims::CLAIMS[0].session == 1;
    pub use crate::door::door;
}
