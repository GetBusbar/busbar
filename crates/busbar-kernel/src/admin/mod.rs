// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CORE-RESIDENT half of the admin API surface.
//!
//! ## 1.6.0: the admin API SERVICE and CONTRACT live in `busbar-core-admin`
//!
//! The `/api/v1/admin/*` JSON-REST service — the route table, every handler, the committed
//! `openapi.json`, the transport port, the test-support recording layer — and the v1 CONTRACT (the
//! typed views, the full `AdminError` taxonomy, the JSON envelope helpers and the plane-verb
//! envelope; P2 D4, ARCHITECT Q-D4-ADMIN (b) 2026-10-04) are `busbar-core-admin`'s, which depends on
//! the kernel ONE-WAY. The kernel mounts that service through the fn-pointer seam in [`seam`]
//! (registered once by the composition root, exactly like `oauth_as::seam`), so `router.rs` names no
//! core-admin type.
//!
//! What STAYS here is what the kernel answers itself, before any admin handler runs:
//!
//! * [`gate`] — the admin gate's scope matrix (`required_scope`) and the paths it and the
//!   mutation-rate classifier key off, and ONE small neutral `/api` error envelope for exactly the
//!   answers the kernel gives itself (the gate's 401/429/503, the router fallback's 404/405/500, the
//!   plane-driver serve's 405).

pub mod gate;
pub mod seam;
