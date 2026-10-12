// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed set of places a quantity may come from.
//!
//! The set itself lives in `busbar-contract`, beside the usage report that carries it, because three
//! crates read a source: this unit writes it, the ledger settles against it, and the audit record
//! carries it into the journal. It was spelled three different ways before — seven arms here, four
//! in the audit crate, none in the capability crate — which meant the independent recompute and the
//! record it is checked against could disagree about what the same number was.
//!
//! This unit only re-exports it. It used to add a raw-to-quantity conversion beside the set (bytes
//! over a divisor, frames times a factor) that nothing in production called; the plane reports the
//! quantity it measured (THE DESIGN §7), so the conversion is gone rather than kept as a second
//! reading of a class declaration.

pub use busbar_contract::caps::{LocatorPtr, QuantitySource};
pub use busbar_contract::ClassDirection as Direction;
