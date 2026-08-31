// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `IrHandle` — the SEALED, NEUTRAL request/response handle the operation-blind engine holds now that
//! `IrReq`/`IrResp` have dissolved (G6 A4b).
//!
//! The trait and its soft-seal RELOCATED to `busbar-substrate` (`busbar_substrate::ir::handle`) at
//! Batch C-4 so the dialect crates (`busbar-mcp`/`busbar-llm`/`busbar-a2a`) implement it without
//! reaching into `busbar-core`. Core re-exports `IrHandle` and the `#[doc(hidden)]` `sealed` module
//! from this historical path (`crate::ir::handle::IrHandle`, `crate::ir::handle::sealed::Sealed`) so
//! every in-core and plugin caller — and the four neutral `Invoke`/`Subscribe` handles that travelled
//! with it to `busbar_substrate::ir::neutral_handles` — is unchanged.

pub use busbar_substrate::ir::handle::{sealed, IrHandle};
