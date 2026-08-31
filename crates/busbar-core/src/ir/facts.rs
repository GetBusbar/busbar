// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `ir::facts` — THE ONE PROJECTION. What the shared pipeline is allowed to know about a request,
//! read from the IR and from nothing else.
//!
//! The projection surface (the `IrFacts` trait, the provenance `Slot`, the borrowed `ContentItem`,
//! the `Shape` counts, `NeutralFacts` and the label consts) RELOCATED to `busbar-substrate`
//! (`busbar_substrate::ir::facts`) at Batch C-2 so a second protocol family (`busbar-mcp`) implements
//! it without reaching into `busbar-core`. Core re-exports the whole surface from this historical
//! path (`crate::ir::facts::*`) so every in-core and plugin caller is unchanged. The concrete chat-IR
//! projection (`impl IrFacts for IrRequest` + `project`) lives in the `busbar-llm` plugin
//! (`ir::facts_impl`); the two in-core neutral-IR impls (`InvokeReq`/`SubscribeReq`) travelled to
//! substrate beside their data, keeping the orphan rule satisfied end-to-end.

pub use busbar_substrate::ir::facts::*;
