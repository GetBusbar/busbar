// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral `IrHandle`s for the two protocol-surface operations, `Invoke` and `Subscribe` (G6 A4b
//! dissolve). RELOCATED to `busbar-substrate` (`busbar_substrate::ir::neutral_handles`) at Batch C-4
//! beside the trait and data they wrap; core re-exports the four handles from this historical path
//! (`crate::ir::neutral_handles::{InvokeReqHandle, …}`) so its own call sites are unchanged.

pub use busbar_substrate::ir::neutral_handles::{
    InvokeReqHandle, InvokeRespHandle, SubscribeReqHandle, SubscribeRespHandle,
};
