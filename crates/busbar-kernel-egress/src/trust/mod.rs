// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # trust — the network readers

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod net;

pub use net::AddressRefusal;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
