// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admin API **v1** — the CORE-RESIDENT half.
//!
//! The v1 SERVICE and JSON-REST wire adapter were extracted to `busbar-admin` (see
//! `busbar_admin::v1`). What STAYS here:
//!
//! - [`contract`] — v1 typed views + the stable error taxonomy (the frozen surface in Rust), the
//!   `PATH_*`/`ADMIN_PREFIX`/`required_scope` constants `auth`/`ratelimit`/`router` reference.
//! - [`json`] — the JSON envelope PRIMITIVES (`err_json`/`ok_json`/`err_json_cond`) only, which
//!   `router::fallback_error_response` and `admin::planeverbs::CorePlaneAdminEnvelope` render through.

pub mod contract;
pub mod json;
