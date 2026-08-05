// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Built-in observability EXPORTERS (design §2/§7): the distribution half of the observability
//! streams, lifted OUT of core into compiled-in modules that CONSUME the `export` plugin kind + the
//! plugin HTTP endpoint registration. PRESENCE + settings (the `export:` config block,
//! [`crate::config::ExportCfg`]) is the on/off switch, exactly like the built-in `env`/`file` secret
//! modules — no config boolean, no dynamic tarball.
//!
//! The COLLECTION half stays core (design §9): the Prometheus recorder + the ~57 emit sites + the
//! scrape-time gauge derivation live in [`crate::metrics`]; the request-log projection is still built
//! in the request-finish path. These modules move only the DISTRIBUTION:
//!
//! - [`prometheus`] — PULL. Serves `/metrics` via the endpoint-registration `handle_http` path (the
//!   well-known-`/metrics` exception), rendering the recorder registry. When `export.prometheus` is
//!   present the recorder is installed (collection on) and a `GET /metrics` plugin route is
//!   registered; absent ⇒ no recorder, `/metrics` unmounted, every emit site a true no-op.
//! - [`webhook`] — PUSH per-request. The `request-log-webhook` + `generic-webhook` sinks POST the
//!   built request-log line behind the relocated SSRF guard + bounded `AdmissionGate` delivery.
//! - [`file`] — PUSH per-request. The `request-log-file` sink appends the line as JSONL.

pub(crate) mod file;
pub(crate) mod prometheus;
pub(crate) mod webhook;

use crate::config::ExportCfg;
use crate::plugin_routes::{RouteDecl, RouteKind};
use busbar_plugin_loader::Route;
use serde_json::Value;

/// The live plugin-route declarations the built-in exporters contribute (design §5) — today just the
/// `prometheus` exporter's `GET /metrics`. Built at App construction from the resolved `export:` block
/// and folded into the [`crate::plugin_routes::PluginRouteTable`] on the App snapshot, so a config
/// apply that adds/removes `export.prometheus` mounts/unmounts `/metrics` with no router rebuild.
pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    prometheus::route_decl(cfg).into_iter().collect()
}

/// The manifest-level `(owner, kind, route)` mirror of [`route_decls`] for the `--validate`/boot
/// collision preflight — WITHOUT the live dispatchers, so a loaded third-party export plugin claiming
/// a path a built-in exporter already owns (e.g. `GET /metrics`) fails loudly before boot.
pub(crate) fn route_owners(cfg: &ExportCfg) -> Vec<(String, RouteKind, Route)> {
    prometheus::route_owner(cfg).into_iter().collect()
}

/// Configure every PUSH request-log exporter from the resolved `export:` block. Called once at boot
/// after the pooled client exists; the process-global sinks are `OnceLock`-guarded (like the metrics
/// recorder), so a later config apply cannot re-point them (restart-to-apply, same posture the
/// request-log webhook always had). No-op for an absent block.
pub(crate) fn configure(cfg: &ExportCfg, client: reqwest::Client) {
    webhook::configure(cfg, client);
    file::configure(cfg);
}

/// True when ANY request-log PUSH sink (webhook / file / generic) is configured. Lets the
/// request-finish path skip BUILDING the JSON payload entirely when no sink is present — purely an
/// allocation guard (when configured the built payload + delivery are byte-identical to before).
#[inline]
pub(crate) fn request_log_configured() -> bool {
    webhook::request_log_configured() || file::configured()
}

/// Build the request-log JSON payload (relocated from `observability::build_request_log`). Pure (no
/// I/O) so it is unit-testable; the byte-identical 5-field shape today's request log produces.
pub(crate) fn build_request_log(
    ts: u64,
    ingress_protocol: &str,
    pool: &str,
    outcome: &str,
    latency_ms: u64,
) -> Value {
    serde_json::json!({
        "ts": ts,
        "ingress_protocol": ingress_protocol,
        "pool": pool,
        "outcome": outcome,
        "latency_ms": latency_ms,
    })
}

/// Fan one built request-log line out to every configured PUSH sink. Fire-and-forget; never blocks
/// the request path and never surfaces errors — telemetry must not affect serving. The file sink
/// borrows the payload (a synchronous append); the webhook sinks consume it last (each spawns its own
/// bounded delivery task).
pub(crate) fn deliver_request_log(payload: Value) {
    file::deliver(&payload);
    webhook::deliver_logs(payload);
}
