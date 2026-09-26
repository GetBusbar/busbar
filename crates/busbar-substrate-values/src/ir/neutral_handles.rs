// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral `IrHandle`s for the two protocol-surface operations. SHAPES: defined in
//! `busbar_contract::ir::neutral_handles` (DECISIONS #83, SD-2b of the #83a split) beside the handle
//! they implement; re-exported here under their historical path.

pub use busbar_contract::ir::neutral_handles::{
    InvokeReqHandle, InvokeRespHandle, SubscribeReqHandle, SubscribeRespHandle,
};
