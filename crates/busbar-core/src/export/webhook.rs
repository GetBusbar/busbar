// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in **request-log-webhook** + **generic-webhook** exporters (PUSH).
//!
//! This is the relocated home of the request-log webhook DELIVERY that used to live in
//! `crate::observability`: the bounded fire-and-forget POST behind the SSRF guard
//! ([`crate::observability::validate_webhook_url`], reused not reinvented) and the in-flight
//! [`AdmissionGate`] backpressure. `export.request-log-webhook` is the direct replacement for the
//! retired `observability.request_log_webhook_url`; `export.generic-webhook` is the same machinery
//! plus a configurable auth header (logs + audit).
//!
//! busbar core no longer POSTs telemetry anywhere itself — the request-finish path hands the built
//! request-log line to [`deliver_logs`], which fans it out to whichever webhook sinks the operator
//! configured.

use crate::config::ExportCfg;
use crate::export::projection::Projection;
use crate::export::PayloadCache;
use crate::limits::admission::AdmissionGate;
use crate::observability::{mask_userinfo, validate_webhook_url};
use http::header::{HeaderName, HeaderValue};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// One configured webhook sink: a validated `https://` target plus an optional `{name, value}` auth
/// header (the generic-webhook exporter's extra over the plain request-log webhook).
struct Target {
    url: Arc<String>,
    auth: Option<(String, String)>,
    /// This instance's OWN per-delivery deadline (`settings.delivery_timeout_secs`). 1.5.3: the
    /// `export:` map holds NAMED instances, so two webhook sinks can legitimately want different
    /// deadlines — the timeout is therefore per target here, not a process-global read.
    timeout: Duration,
    /// This instance's OWN in-flight delivery cap (`settings.max_inflight_deliveries`), for the same
    /// reason the timeout is per instance. Two named webhook sinks — the documented
    /// "app logs + SIEM" shape — are two INDEPENDENT budgets: one shared gate meant a stalled SIEM
    /// could hold every permit and starve the fast sink, and that a low cap an operator set on one
    /// instance was never actually enforced (the shared gate was sized to the MAX across instances).
    gate: AdmissionGate,
    /// This instance's PROJECTION — the streams + fields THIS sink was granted in config. The
    /// payload it receives is built to exactly this, so a field it was not granted is never
    /// serialized and never leaves the process.
    projection: Projection,
}

/// The configured webhook sinks (request-log-webhook + generic-webhook), sized ONCE at boot. An unset
/// lock IS the "no webhook configured" signal, so [`deliver_logs`] skips with a single pointer read.
/// (Whether the request-log payload is BUILT at all is decided earlier, by the union-of-projections
/// compute gate on the `App` — see `crate::export::projection::ProjectionUnion`.)
static TARGETS: OnceLock<Vec<Target>> = OnceLock::new();
/// The exporter's OWN delivery client — an ENGINE client on the cold open-web posture, built ONLY
/// when at least one webhook sink is actually configured (the default config pays nothing). Its
/// own client rather than the shared upstream pool because webhook delivery is a background,
/// seconds-cadence push with its own SSRF posture.
static CLIENT: OnceLock<crate::proxy::EgressClient> = OnceLock::new();

/// Configure the webhook sinks once at startup from the resolved `export:` block — one [`Target`] per
/// NAMED `module: request-log-webhook` instance, in config order. Each URL is validated HERE (SSRF
/// guard + `https://`-only) so an invalid target is rejected loudly and left disabled, rather than
/// firing per-request POSTs at an unintended host. No-op when no webhook instance is configured.
pub(crate) fn configure(cfg: &ExportCfg) {
    let mut targets = Vec::new();
    for w in &cfg.request_log_webhooks {
        let auth = w
            .auth_header
            .as_ref()
            .map(|h| (h.name.clone(), h.value.clone()));
        push_target(
            &mut targets,
            &w.url,
            auth,
            Duration::from_secs(w.delivery_timeout_secs),
            w.max_inflight_deliveries,
            w.projection,
        );
    }
    if !targets.is_empty() {
        // Delivery posture matches the retired reqwest client where it matters: 10s connect bound
        // (the engine's connect deadline, now spanning TLS too), reqwest-default pooling (unbounded
        // idle per host, 90s idle timeout — sinks are operator-configured hosts, exactly the shape
        // the LLM lanes pool for); the per-DELIVERY total timeout is each target's own
        // `delivery_timeout_secs` (applied per request below), so no client-level total is needed.
        let client = crate::proxy::build_egress_client(
            &crate::proxy::EgressClientSpec::pooled_webpki(usize::MAX, 90, false, false),
        );
        let _ = TARGETS.set(targets);
        let _ = CLIENT.set(client);
    }
}

/// Validate one URL and, if it survives, append a [`Target`]. A validation failure logs loudly and
/// disables THAT sink (the others still deliver) — the exact posture the old single-webhook config had.
fn push_target(
    targets: &mut Vec<Target>,
    url: &str,
    auth: Option<(String, String)>,
    timeout: Duration,
    max_inflight: usize,
    projection: Projection,
) {
    match validate_webhook_url(Some(url.to_string())) {
        Ok(Some(u)) => targets.push(Target {
            url: Arc::new(u),
            auth,
            timeout,
            // CLAMPED, not trusted: `config_validate` rejects a `max_inflight_deliveries` outside
            // `1..=Semaphore::MAX_PERMITS`, but this constructor must not be the thing that panics
            // (0 permits would also black-hole the sink silently) if it is ever reached unvalidated.
            gate: AdmissionGate::new(
                max_inflight.clamp(1, tokio::sync::Semaphore::MAX_PERMITS),
                "webhook",
            ),
            projection,
        }),
        Ok(None) => {}
        Err(msg) => crate::diagnostics::diag_error!(
            crate::diagnostics::WEBHOOK_EXPORTER_DISABLED,
            "{msg}; disabling this webhook exporter"
        ),
    }
}

/// Fire-and-forget the built request-log line to every configured webhook sink. No-op when none are
/// configured. Never blocks the request path and never surfaces errors. Bounded PER INSTANCE: at most
/// that sink's own `settings.max_inflight_deliveries` deliveries run concurrently (a slow sink drops
/// ITS logs rather than piling up unbounded tasks, and cannot consume a sibling sink's budget), each
/// with its own short timeout.
pub(crate) fn deliver_logs(cache: &mut PayloadCache<'_>) {
    let Some(targets) = TARGETS.get() else {
        return;
    };
    let Some(client) = CLIENT.get().cloned() else {
        return;
    };
    for target in targets {
        // Acquire a delivery slot WITHOUT awaiting; drop this log (counted) rather than block or
        // accumulate an unbounded backlog when the sink is saturated.
        let Some(permit) = target.gate.try_enter() else {
            metrics::counter!(crate::metrics::WEBHOOK_LOGS_DROPPED_TOTAL).increment(1);
            continue;
        };
        let url = target.url.clone();
        let auth = target.auth.clone();
        let timeout = target.timeout;
        let client = client.clone();
        // THIS sink's payload, built to THIS sink's projection (shared with any sibling holding the
        // identical projection). The build happens here, per sink — never once and broadcast.
        let payload = cache.get(target.projection);
        crate::state::spawn_detached(async move {
            let _permit = permit; // slot releases on task end via the owned permit's Drop.
            let Ok(uri) = url.as_str().parse::<http::Uri>() else {
                // Structurally unreachable: the target survived `validate_webhook_url` at boot.
                warn_webhook_delivery_failed(url.as_str(), Err("target URL does not parse".into()));
                return;
            };
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static(crate::proxy::APPLICATION_JSON),
            );
            if let Some((name, value)) = &auth {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    headers.insert(n, v);
                }
            }
            let req = busbar_substrate::egress::engine::request(
                http::Method::POST,
                uri,
                headers,
                bytes::Bytes::from(payload.to_string()),
            );
            // This target's own per-delivery deadline over the whole send — the same span the
            // retired per-request reqwest `.timeout()` covered.
            let deadline = tokio::time::Instant::now() + timeout;
            match busbar_substrate::egress::engine::send_bounded(&client, req, deadline).await {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => warn_webhook_delivery_failed(url.as_str(), Ok(resp.status())),
                Err(e) => warn_webhook_delivery_failed(url.as_str(), Err(e.into_cause())),
            }
        });
    }
}

/// The delivery-failure warn, factored into ONE place so the userinfo masking cannot be reintroduced
/// as a leak on only one of the two failure arms. Relocated from `observability` alongside the
/// delivery it guards.
pub(crate) fn warn_webhook_delivery_failed(url: &str, outcome: Result<http::StatusCode, String>) {
    match outcome {
        Ok(status) => crate::diagnostics::diag_debug!(
            crate::diagnostics::WEBHOOK_DELIVERY_NON_2XX,
            webhook_url = mask_userinfo(url),
            status = status.as_u16(),
            "request-log webhook delivery returned a non-2xx status; this log was dropped"
        ),
        // The cause string is URL-free by construction (hyper errors never carry the URL — the
        // `without_url()` this arm used to need was only ever stripping reqwest's addition).
        Err(e) => crate::diagnostics::diag_debug!(
            crate::diagnostics::WEBHOOK_DELIVERY_TRANSPORT_ERROR,
            webhook_url = mask_userinfo(url),
            error_kind = %e,
            "request-log webhook delivery failed (transport error); this log was dropped"
        ),
    }
}

#[cfg(test)]
#[path = "tests/webhook_tests.rs"]
mod tests;
