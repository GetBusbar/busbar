// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-ledger — money as counts x the rate card
//!
//! Money is never stored. The store keeps the ledger COUNTS (the usage and metering rows) and the
//! dated rate-card history; every figure is derived at read time by pricing those counts against
//! the card in force when they were earned (owner ruling 2026-10-25: "money should just be a
//! function of cost x ledger").
//!
//! [`mod@cost`] — the money arithmetic: the dated rate-card history, the quantities a posting
//! stores and the one lookup over the two. [`mod@usage`] re-exports the closed usage sources and
//! the dated pricing beside it.
//!
//! It does not admit, and it does not write bytes to a disk or a store.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod cost;
pub mod usage;
