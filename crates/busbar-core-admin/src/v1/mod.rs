// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admin API **v1** — the frozen, additive-only surface, as a self-contained version unit.
//!
//! The whole v1 surface lives here (the contract and the envelope primitives moved in from the
//! kernel, 1.6.0-TODO.md D4):
//!
//! - [`contract`] — the typed views + the stable error taxonomy, the frozen surface in Rust.
//!
//! - [`service`] — the v1 application service: typed operations returning `contract` views/errors,
//!   over the shared engine (`busbar_kernel::state::App`).
//! - [`json`] — the JSON-REST wire adapter (`JsonV1`) mounting `/api/v1/admin/*`.

pub mod contract;
pub mod json;
mod named_def_views;
pub mod service;

#[cfg(test)]
#[path = "tests/hook_stage_projection.rs"]
mod hook_stage_projection;
