// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in **request-log-webhook** + **generic-webhook** exporters (PUSH) — design §2.3, §7.2.
//!
//! This is the relocated home of the request-log webhook DELIVERY that used to live in
//! `crate::observability`: the bounded fire-and-forget POST behind the SSRF guard
//! ([`crate::observability::validate_webhook_url`], reused not reinvented) and the in-flight
//! [`AdmissionGate`] backpressure. `export.request-log-webhook` is the direct replacement for the
//! retired `observability.request_log_webhook_url`; `export.generic-webhook` is the same machinery
//! plus a configurable auth header (design §2.3 — logs + audit).
//!
//! busbar core no longer POSTs telemetry anywhere itself — the request-finish path hands the built
//! request-log line to [`deliver_logs`], which fans it out to whichever webhook sinks the operator
//! configured.

use crate::config::ExportCfg;
use crate::limits::admission::AdmissionGate;
use crate::observability::{mask_userinfo, validate_webhook_url};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Client;
use serde_json::Value;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// One configured webhook sink: a validated `https://` target plus an optional `{name, value}` auth
/// header (the generic-webhook exporter's extra over the plain request-log webhook).
struct Target {
    url: Arc<String>,
    auth: Option<(String, String)>,
}

/// The configured webhook sinks (request-log-webhook + generic-webhook), sized ONCE at boot. An unset
/// lock IS the "no webhook configured" signal, so [`request_log_configured`] and [`deliver_logs`] skip
/// with a single pointer read.
static TARGETS: OnceLock<Vec<Target>> = OnceLock::new();
/// busbar's pooled reqwest client, reused for delivery (same client the old `configure_webhook` took).
static CLIENT: OnceLock<Client> = OnceLock::new();
/// The in-flight delivery limiter — relocated verbatim from `observability::webhook_inflight`. Sized
/// from `crate::limits::max_inflight_webhook_deliveries()` (which 1.5.3 sources from the
/// `export.request-log-webhook.settings.max_inflight_deliveries` config) on first delivery.
static WEBHOOK_INFLIGHT: OnceLock<AdmissionGate> = OnceLock::new();

fn webhook_inflight() -> &'static AdmissionGate {
    WEBHOOK_INFLIGHT.get_or_init(|| {
        AdmissionGate::new(crate::limits::max_inflight_webhook_deliveries(), "webhook")
    })
}

/// Per-delivery timeout — relocated from `observability::webhook_delivery_timeout`. Read fresh so a
/// live apply of the (export-sourced) timeout is honored, independent of the client's upstream timeout.
fn webhook_delivery_timeout() -> Duration {
    Duration::from_secs(crate::limits::webhook_delivery_timeout_secs())
}

/// Configure the webhook sinks once at startup from the `export:` block. Each URL is validated HERE
/// (SSRF guard + `https://`-only) so an invalid target is rejected loudly and left disabled, rather
/// than firing per-request POSTs at an unintended host. No-op when neither webhook exporter is present.
pub(crate) fn configure(cfg: &ExportCfg, client: Client) {
    let mut targets = Vec::new();
    if let Some(w) = &cfg.request_log_webhook {
        push_target(&mut targets, &w.settings.url, None);
    }
    if let Some(g) = &cfg.generic_webhook {
        let auth = g
            .settings
            .auth_header
            .as_ref()
            .map(|h| (h.name.clone(), h.value.clone()));
        push_target(&mut targets, &g.settings.url, auth);
    }
    if !targets.is_empty() {
        let _ = TARGETS.set(targets);
    }
    let _ = CLIENT.set(client);
}

/// Validate one URL and, if it survives, append a [`Target`]. A validation failure logs loudly and
/// disables THAT sink (the others still deliver) — the exact posture the old single-webhook config had.
fn push_target(targets: &mut Vec<Target>, url: &str, auth: Option<(String, String)>) {
    match validate_webhook_url(Some(url.to_string())) {
        Ok(Some(u)) => targets.push(Target {
            url: Arc::new(u),
            auth,
        }),
        Ok(None) => {}
        Err(msg) => tracing::error!("{msg}; disabling this webhook exporter"),
    }
}

/// True when at least one webhook sink is configured. Lets the request-finish path skip building the
/// payload when no webhook (or file) sink is present — purely an allocation guard.
#[inline]
pub(crate) fn request_log_configured() -> bool {
    TARGETS.get().is_some()
}

/// Fire-and-forget the built request-log line to every configured webhook sink. No-op when none are
/// configured. Never blocks the request path and never surfaces errors. Bounded: at most
/// `max_inflight_webhook_deliveries()` deliveries run concurrently (a slow sink drops logs rather than
/// piling up unbounded tasks), each with its own short timeout.
pub(crate) fn deliver_logs(payload: Value) {
    let Some(targets) = TARGETS.get() else {
        return;
    };
    let Some(client) = CLIENT.get().cloned() else {
        return;
    };
    // Serialize once; each delivery task owns a cheap `Arc` clone rather than re-walking the tree.
    let payload = Arc::new(payload);
    for target in targets {
        // Acquire a delivery slot WITHOUT awaiting; drop this log (counted) rather than block or
        // accumulate an unbounded backlog when the sink is saturated.
        let Some(permit) = webhook_inflight().try_enter() else {
            metrics::counter!(crate::metrics::WEBHOOK_LOGS_DROPPED_TOTAL).increment(1);
            continue;
        };
        let url = target.url.clone();
        let auth = target.auth.clone();
        let client = client.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            let _permit = permit; // slot releases on task end via the owned permit's Drop.
            let body = payload.to_string();
            let mut req = client
                .post(url.as_str())
                .header(
                    reqwest::header::CONTENT_TYPE,
                    crate::proxy::APPLICATION_JSON,
                )
                .body(body)
                .timeout(webhook_delivery_timeout());
            if let Some((name, value)) = &auth {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    req = req.header(n, v);
                }
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => warn_webhook_delivery_failed(url.as_str(), Ok(resp.status())),
                Err(e) => warn_webhook_delivery_failed(url.as_str(), Err(e)),
            }
        });
    }
}

/// The delivery-failure warn, factored into ONE place so the userinfo masking cannot be reintroduced
/// as a leak on only one of the two failure arms. Relocated from `observability` alongside the
/// delivery it guards.
pub(crate) fn warn_webhook_delivery_failed(
    url: &str,
    outcome: Result<reqwest::StatusCode, reqwest::Error>,
) {
    match outcome {
        Ok(status) => tracing::warn!(
            webhook_url = mask_userinfo(url),
            status = status.as_u16(),
            "request-log webhook delivery returned a non-2xx status; this log was dropped"
        ),
        Err(e) => tracing::warn!(
            webhook_url = mask_userinfo(url),
            error_kind = %e.without_url(),
            "request-log webhook delivery failed (transport error); this log was dropped"
        ),
    }
}

#[cfg(test)]
#[path = "tests/webhook_tests.rs"]
mod tests;
