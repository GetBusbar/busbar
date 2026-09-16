// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CORE-RESIDENT half of the admin API surface.
//!
//! ## 1.6.0: the admin API SERVICE was extracted to `busbar-admin`
//!
//! The `/api/v1/admin/*` JSON-REST service — the route table, every handler (keys, groups, hooks,
//! plugins, config, overlay, openapi), the committed `openapi.json`, the transport port and the
//! test-support recording layer — moved out to the `busbar-admin` sibling crate, which depends on
//! busbar-core ONE-WAY (Cargo hard-refuses the reverse edge). busbar-core mounts that service through
//! the fn-pointer seam in [`seam`] (registered once by the composition root, exactly like
//! `oauth_as::seam`), so `router.rs` names no `busbar_admin` type.
//!
//! What STAYS here is the CONTRACT + a little state the rest of busbar-core still reaches directly:
//!
//! * [`v1::contract`] — the frozen typed views + the stable [`v1::contract::AdminError`] taxonomy and
//!   the `PATH_*`/`ADMIN_PREFIX`/`required_scope` constants. `auth`, `ratelimit`, `router` and the
//!   config transaction all reference these, so they cannot move without the forbidden cycle (the
//!   remaining core↔admin contract coupling; the eventual target is `busbar-contract::SurfaceError`).
//! * [`v1::json`] — the ENVELOPE PRIMITIVES (`err_json`/`ok_json`/`err_json_cond`) only.
//!   `router::fallback_error_response` and [`planeverbs::CorePlaneAdminEnvelope`] render through them.
//! * [`planeverbs`] — [`planeverbs::CorePlaneAdminEnvelope`], the core backing for the self-enveloping
//!   plane-verb seam. `busbar-a2a`/`busbar-mcp` name it at
//!   `busbar_core::admin::planeverbs::CorePlaneAdminEnvelope`, so it stays in core.
//! * [`versions`] — the [`versions::VersionLog`] config-version store, a field of `state::App`.

pub mod seam;

/// THE PLANE TRUST VERB SURFACE, written once and parameterised by plane. Every plane that fronts a
/// registered upstream resolves it, looks at it and audits what it found in the same order; that
/// order lives here, and the plane supplies only the look.
// The surface is mounted only by the trust-fronting planes (MCP, A2A); with every such plane compiled
// out nothing mounts it, so its items read dead in that config alone. The allowance is UNCONDITIONAL
// rather than gated on the concrete plane features: a `feature = "plane-mcp"`/`"plane-a2a"` attribute
// names plane vocabulary, which this neutral crate must not — the same reason `planeverbs.rs`'s own
// ratchet test forbids `mcp`/`a2a` in its source. When a plane IS compiled in the module is used, so
// the allowance is a harmless no-op; only in the all-planes-off build does it silence the otherwise
// unavoidable dead-code warnings.
#[allow(dead_code)]
pub mod planeverbs;
pub mod v1;
pub mod versions;
