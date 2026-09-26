// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NEUTRAL WIRE/EGRESS VALUE TYPES — the serialized-body carrier an `OperationHandler` yields, the
//! resolved-primitives egress context routing hands a `RequestHandler`, and the two wire outcomes a
//! handle writes itself out as. SHAPES: defined in `busbar_contract::codec` (DECISIONS #83, SD-1 and
//! SD-2b of the #83a split), where the byte carriers are re-expressed over the contract's own
//! `SlabBytes`; re-exported here under their historical paths.

/// The contract's shared byte slab the carriers above hold a body in, re-exported beside them so a
/// dialect crate that builds a body names it through the same path as the carrier.
pub use busbar_contract::bounded::SlabBytes;
pub use busbar_contract::codec::{EgressCtx, EgressWire, TranslatedResponse, WireBody};

#[cfg(test)]
#[path = "tests/egress_wire_tests.rs"]
mod egress_wire_tests;
