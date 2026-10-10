// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admin API **v1** — the frozen, additive-only surface, as a self-contained version unit.
//!
//! The whole v1 surface lives here (the typed views, the stable error taxonomy and the JSON envelope
//! primitives moved from the kernel in P2 D4; the kernel keeps only its admin gate's half,
//! `busbar_kernel::admin::gate`):
//!
//! - [`contract`] — the typed views, the stable error taxonomy, the scope model.
//! - [`service`] — the v1 application service: typed operations returning `contract` views/errors,
//!   over the shared engine (`busbar_kernel::state::App`).
//! - [`json`] — the JSON-REST wire adapter (`JsonV1`) mounting `/api/v1/admin/*`.

/// THE v1 CONTRACT — the typed views, the stable error taxonomy and the scope model (moved here from
/// the kernel's `admin::v1::contract`, P2 D4).
pub mod contract;
pub mod json;
mod named_def_views;
pub mod service;

// SCHEMA-ONLY response views for the ad-hoc-`json!` endpoints (moved from the kernel's
// `admin::v1::contract::schema`); compiled only under the CI-only `openapi-schema` feature.
#[cfg(feature = "openapi-schema")]
pub mod schema;

#[cfg(test)]
#[path = "tests/hook_stage_projection.rs"]
mod hook_stage_projection;
