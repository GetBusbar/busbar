// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL METRIC-NAME FACADE, in the substrate.
//!
//! These are the Prometheus metric NAMES a plane's engine emits into the process-global recorder via
//! the `metrics` facade macros (`counter!`/`histogram!`). They are pure `&'static str` — no `App`, no
//! registry handle, no state — so a plane names them (`busbar_substrate::metrics::…`) for its own
//! emission sites without reaching into `busbar-core`, and core's `crate::metrics` re-exports each so
//! its `describe_counter!` registrations and every existing `crate::metrics::…` call site resolve
//! unchanged.
//!
//! The RECORDER itself — install, `render()`, the scrape-time gauges, and the per-thread telemetry
//! bank drain — stays in `busbar-core::metrics`: `render()`/`drain_pending()` flush the core-resident
//! `crate::telemetry` bank and `refresh_scrape_gauges` reads the core `App`, so relocating the
//! singleton here would either drop the banked hot-path series from the scrape or drag `App` into the
//! substrate (a dependency cycle). Only the NAMES are neutral, so only the names move. The scrape
//! stays ONE registry, byte-for-byte: these are the same strings, described and emitted from the same
//! sites as before.

/// Routing-policy selections: incremented once per request whose pool resolved a non-default routing
/// policy that produced a ranked order (Prefer / on_error: first). `policy` is the native/transport
/// NAME (a fixed enumeration: cheapest/fastest/least_busy/usage/webhook/script) and `pool` is the
/// configured pool name (bounded at startup) — both safe, bounded labels (no request-derived data).
pub const ROUTE_POLICY_SELECTIONS_TOTAL: &str = "busbar_route_policy_selections_total"; // labels: policy, pool

/// Routing-policy REJECTIONS (the hook's reject verb — a guardrail said no; a 4xx to the caller,
/// no upstream dispatched). `status` is hook-influenced but BOUNDED: the forward seam that
/// constructs `RejectRequest` clamps it to 400..=499 for EVERY producer (wire-normalized or
/// direct-constructed), so the worst-case label fan-out is 100 per (policy, pool) — a safe label.
pub const ROUTE_POLICY_REJECTIONS_TOTAL: &str = "busbar_route_policy_rejections_total"; // labels: policy, pool, status

/// A hook content projection whose serialized size exceeded `limits.hook_content_max_bytes`, so the
/// content was OMITTED WHOLE (never truncated mid-value) and the hook was sent an empty content
/// projection. Unlabeled: the cap is a global ceiling, not a per-hook one. A steady non-zero rate
/// means a content-granted hook is being asked to screen requests it is not being shown; raise the
/// ceiling or narrow what reaches the hook.
pub const HOOK_CONTENT_TRUNCATED_TOTAL: &str = "busbar_hook_content_truncated_total";

/// Same-protocol non-stream responses whose billing-side buffer hit the translate-body cap before the
/// terminal `usage` block, so token usage could not be parsed and the request billed zero despite a
/// full 2xx reaching the client. Incremented once per truncated response. Unlabeled. An operator
/// alerts on a non-zero rate to detect an over-cap billing gap. (The client response is unaffected —
/// it streams verbatim; only the billing side-channel is capped.)
pub const BILLING_TRUNCATED_TOTAL: &str = "busbar_billing_truncated_total"; // no labels
