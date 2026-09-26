// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `IrHandle` — the SEALED, NEUTRAL request/response handle. A SHAPE: defined in
//! `busbar_contract::ir::handle` (DECISIONS #83, SD-2b of the #83a split), where its byte carrier is
//! re-expressed over the contract's own `SlabBytes`; re-exported here under its historical path.

pub use busbar_contract::ir::handle::{handle_impl, sealed, IrHandle};
