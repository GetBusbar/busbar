// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # trust — the network readers
//!
//! What remains of the folded trust unit is the network readers, in [`net`]: the strict `http(s)`
//! URL recogniser, the userinfo strip and redaction, the configuration-time cloud-metadata check,
//! and the name-resolution seam. None of them judges a dial: the one destination guard, with its
//! resolve-then-pin and its dial-time denylist, is the connector's (`busbar-core-connector`'s
//! `guard`), which reads the URL recogniser and the resolution seam from here.
//!
//! The verify step's guards (the pool allow-list, the fallback walk and the unpriced-destination
//! gate, all run before anything is charged) are the kernel door's, in one home. This crate keeps no
//! second copy of them, and no second lane model, ordering or weighted selector beside the walk's
//! own ([`crate::select::WeightedFloor`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod net;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
