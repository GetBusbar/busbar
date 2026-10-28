// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # trust — the network readers
//!
//! What remains of the folded trust unit is the network guard's pure readers and its
//! resolve-then-pin discipline, in [`net`]: the URL split, the userinfo strip and redaction, the
//! cloud-metadata and operator denylists, and the address judgement the connector and the kernel
//! call.
//!
//! The verify step's guards (the pool allow-list, the fallback walk and the unpriced-destination
//! gate, all run before anything is charged) are the kernel door's, in one home. This crate keeps no
//! second copy of them, and no second lane model, ordering or weighted selector beside the walk's
//! own ([`crate::select::WeightedFloor`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod net;

pub use net::{AddressRefusal, Denylist};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
