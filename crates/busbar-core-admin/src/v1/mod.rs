// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admin API **v1** — the frozen, additive-only surface, as a self-contained version unit.
//!
//! The typed views + stable error taxonomy (`contract`) and the JSON envelope PRIMITIVES
//! (`err_json`/`ok_json`/`err_json_cond`) STAYED in busbar-core (`busbar_kernel::admin::v1`); the rest
//! of the v1 surface lives here:
//!
//! - [`service`] — the v1 application service: typed operations returning `contract` views/errors,
//!   over the shared engine (`busbar_kernel::state::App`).
//! - [`json`] — the JSON-REST wire adapter (`JsonV1`) mounting `/api/v1/admin/*`.

pub mod json;
mod named_def_views;
pub mod service;

#[cfg(test)]
#[path = "tests/hook_stage_projection.rs"]
mod hook_stage_projection;
