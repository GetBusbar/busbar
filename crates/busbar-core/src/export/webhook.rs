// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in **request-log-webhook** + **generic-webhook** exporters (PUSH).
//!
//! This is the relocated home of the request-log webhook DELIVERY that used to live in
//! `crate::observability`: the fire-and-forget POST behind the SSRF guard
//! ([`crate::observability::validate_webhook_url`], reused not reinvented).
//! `export.request-log-webhook` is the direct replacement for the retired
//! `observability.request_log_webhook_url`; `export.generic-webhook` is the same machinery plus a
//! configurable auth header (logs + audit).
//!
//! busbar core no longer POSTs telemetry anywhere itself, and it no longer decides WHO gets a line:
//! the request-finish path hands the facts to the composition root, which builds each sink's
//! payload, sheds against that sink's own capacity and calls [`deliver_one`] with the permit.

use crate::config::ExportCfg;
use crate::export::{BuiltinPushSink, Projection};
use busbar_plugin_loader::ExportStream;

/// The streams THIS SINK carries — its own declaration; see the sibling file sink's for why it is
/// here and not in a table keyed on the operator's `module:` token.
pub(crate) const STREAMS: &[ExportStream] = &[ExportStream::Logs];
use crate::observability::{mask_userinfo, validate_webhook_url};
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;

/// This sink's `busbar_admission_denied_total{gate="..."}` label, stated here and handed to the
/// root with the rest of the sink's declaration — never a string the fan-out invented.
const GATE: &str = "webhook";

/// One configured webhook sink: a validated `https://` target plus an optional `{name, value}` auth
/// header (the generic-webhook exporter's extra over the plain request-log webhook).
struct Target {
    url: Arc<String>,
    auth: Option<(String, String)>,
    /// This instance's OWN per-delivery deadline (`settings.delivery_timeout_secs`). 1.5.3: the
    /// `export:` map holds NAMED instances, so two webhook sinks can legitimately want different
    /// deadlines — the timeout is therefore per target here, not a process-global read.
    timeout: Duration,
}

/// Declare this module's configured instances to the composition root — one [`BuiltinPushSink`]
/// per NAMED `module: request-log-webhook` instance, in config order. Each URL is validated HERE
/// (SSRF guard + `https://`-only) so an invalid target is rejected loudly and left disabled, rather
/// than firing per-request POSTs at an unintended host. Empty when no webhook instance is
/// configured, and in that case NO delivery client is built at all (the default config pays
/// nothing).
///
/// Each instance is its OWN budget. Two named webhook sinks — the documented "app logs + SIEM"
/// shape — are two INDEPENDENT capacities: one shared gate meant a stalled SIEM could hold every
/// permit and starve the fast sink, and that a low cap an operator set on one instance was never
/// actually enforced (the shared gate was sized to the MAX across instances). The cap is stated
/// here per instance; the root enforces it per instance.
pub(crate) fn sinks(cfg: &ExportCfg) -> Vec<BuiltinPushSink> {
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
            // CLAMPED, not trusted: `config_validate` rejects a `max_inflight_deliveries` outside
            // `1..=Semaphore::MAX_PERMITS`, but the gate the root builds from this must not be the
            // thing that panics (0 permits would also black-hole the sink silently) if this is ever
            // reached unvalidated.
            w.max_inflight_deliveries
                .clamp(1, tokio::sync::Semaphore::MAX_PERMITS),
            w.projection,
        );
    }
    if targets.is_empty() {
        return Vec::new();
    }
    // The exporter's OWN delivery client — an ENGINE client on the cold open-web posture, built
    // ONLY when at least one webhook sink is actually configured. Its own client rather than the
    // shared upstream pool because webhook delivery is a background, seconds-cadence push with its
    // own SSRF posture. Delivery posture matches the retired reqwest client where it matters: 10s
    // connect bound (the engine's connect deadline, now spanning TLS too), reqwest-default pooling
    // (unbounded idle per host, 90s idle timeout — sinks are operator-configured hosts, exactly the
    // shape the LLM lanes pool for); the per-DELIVERY total timeout is each target's own
    // `delivery_timeout_secs` (applied per request below), so no client-level total is needed.
    let client = crate::proxy::build_egress_client(&crate::proxy::EgressClientSpec::pooled_webpki(
        usize::MAX,
        90,
        false,
        false,
    ));
    targets
        .into_iter()
        .map(|(target, max_inflight, projection)| {
            let client = client.clone();
            BuiltinPushSink {
                projection,
                max_inflight,
                gate: GATE,
                dropped_total: crate::metrics::WEBHOOK_LOGS_DROPPED_TOTAL,
                ship: Box::new(move |payload: &Value, permit| {
                    deliver_one(&target, &client, payload.to_string(), permit);
                }),
            }
        })
        .collect()
}

/// Validate one URL and, if it survives, append a [`Target`] plus the two per-instance policy
/// numbers the root needs. A validation failure logs loudly and disables THAT sink (the others
/// still deliver) — the exact posture the old single-webhook config had.
fn push_target(
    targets: &mut Vec<(Arc<Target>, usize, Projection)>,
    url: &str,
    auth: Option<(String, String)>,
    timeout: Duration,
    max_inflight: usize,
    projection: Projection,
) {
    match validate_webhook_url(Some(url.to_string())) {
        Ok(Some(u)) => targets.push((
            Arc::new(Target {
                url: Arc::new(u),
                auth,
                timeout,
            }),
            max_inflight,
            projection,
        )),
        Ok(None) => {}
        Err(msg) => crate::diagnostics::diag_error!(
            crate::diagnostics::WEBHOOK_EXPORTER_DISABLED,
            "{msg}; disabling this webhook exporter"
        ),
    }
}

/// Fire-and-forget ONE already-serialized request-log line at ONE configured webhook sink. Never
/// blocks the request path and never surfaces errors. BOUNDED PER INSTANCE by the root, which took
/// `permit` from that sink's own gate before calling here: at most that sink's own
/// `settings.max_inflight_deliveries` deliveries run concurrently (a slow sink drops ITS logs
/// rather than piling up unbounded tasks, and cannot consume a sibling sink's budget), each with
/// its own short timeout.
fn deliver_one(
    target: &Arc<Target>,
    client: &crate::proxy::EgressClient,
    payload: String,
    permit: OwnedSemaphorePermit,
) {
    let target = target.clone();
    let client = client.clone();
    busbar_substrate::detached::spawn_detached(async move {
        let _permit = permit; // slot releases on task end via the owned permit's Drop.
        let url = target.url.clone();
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
        if let Some((name, value)) = &target.auth {
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
            bytes::Bytes::from(payload),
        );
        // This target's own per-delivery deadline over the whole send — the same span the
        // retired per-request reqwest `.timeout()` covered.
        let deadline = tokio::time::Instant::now() + target.timeout;
        match busbar_substrate::egress::engine::send_bounded(&client, req, deadline).await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => warn_webhook_delivery_failed(url.as_str(), Ok(resp.status())),
            Err(e) => warn_webhook_delivery_failed(url.as_str(), Err(e.into_cause())),
        }
    });
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
