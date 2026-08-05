// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the built-in `request-log-webhook` / `generic-webhook` exporters — the request-log
//! delivery + SSRF guard + AdmissionGate relocated out of `observability` (design §7.2).

use super::*;

/// The SSRF guard + auth-header wiring is relocated INTO the exporter: [`push_target`] accepts a
/// valid external `https://` target, REJECTS an internal (cloud-metadata) one via the reused
/// [`crate::observability::validate_webhook_url`], and carries a generic-webhook auth header onto the
/// built target.
///
/// RED-BEFORE-GREEN: `crate::export::webhook` (and `push_target`/`Target`) did not exist before this
/// unit — the request-log webhook lived entirely in `observability`.
#[test]
fn push_target_validates_and_carries_auth_header() {
    let mut targets = Vec::new();

    push_target(&mut targets, "https://logs.example.com/busbar", None);
    assert_eq!(
        targets.len(),
        1,
        "a valid external https target is accepted"
    );
    assert_eq!(targets[0].url.as_str(), "https://logs.example.com/busbar");
    assert!(targets[0].auth.is_none());

    // The relocated SSRF guard drops a cloud-metadata target rather than adding it.
    push_target(
        &mut targets,
        "https://169.254.169.254/latest/meta-data/",
        None,
    );
    assert_eq!(
        targets.len(),
        1,
        "the SSRF guard rejects an internal target"
    );

    // A plaintext target is rejected by the https-only scheme check.
    push_target(&mut targets, "http://hook.example.com/log", None);
    assert_eq!(targets.len(), 1, "the https-only guard rejects plaintext");

    // The generic-webhook auth header is carried onto the target.
    push_target(
        &mut targets,
        "https://hook.example.com/events",
        Some(("Authorization".to_string(), "Bearer sekret".to_string())),
    );
    assert_eq!(targets.len(), 2);
    let (name, value) = targets[1].auth.as_ref().expect("auth header carried");
    assert_eq!(name, "Authorization");
    assert_eq!(value, "Bearer sekret");
}

/// A `tracing::Layer` capturing every structured field of every event, so a test can assert what a
/// `tracing::warn!` actually put on the wire (relocated from `observability` alongside the delivery
/// it guards).
#[derive(Clone, Default)]
struct FieldCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for FieldCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Vis(Vec<String>);
        impl tracing::field::Visit for Vis {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push(format!("{}={value:?}", field.name()));
            }
        }
        let mut vis = Vis(Vec::new());
        event.record(&mut vis);
        if let Ok(mut ev) = self.0.lock() {
            ev.push(vis.0.join(" "));
        }
    }
}

/// The request-log DELIVERY path lives in the webhook exporter now: its delivery-failure warn masks
/// any embedded userinfo in BOTH the `webhook_url` field AND the reqwest error Display, for BOTH the
/// transport-error and non-2xx arms. Drives a REAL POST to an unroutable TEST-NET host so the
/// exporter's own delivery code runs (not a hand-copy).
#[tokio::test]
async fn delivery_failure_masks_userinfo() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let cap = FieldCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let url = "https://user:hunter2@192.0.2.1/log";

    // Transport-error arm: a POST to an unroutable RFC 5737 TEST-NET-1 host fails fast.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(200))
        .build()
        .unwrap();
    let err = client
        .post(url)
        .body("{}")
        .send()
        .await
        .expect_err("post to an unroutable host must fail");
    warn_webhook_delivery_failed(url, Err(err));

    // Non-2xx arm.
    warn_webhook_delivery_failed(url, Ok(reqwest::StatusCode::INTERNAL_SERVER_ERROR));

    let events = cap.0.lock().unwrap().join("\n");
    assert!(
        !events.contains("hunter2") && !events.contains("user:hunter2"),
        "delivery-failure warn leaked webhook userinfo: {events}"
    );
    assert!(
        events.contains("***"),
        "the masked webhook_url field must show the redaction marker: {events}"
    );
}

/// The built request-log payload is the byte-identical 5-field shape (relocated to `crate::export`).
#[test]
fn build_request_log_shape() {
    let p = crate::export::build_request_log(1_700_000_000, "anthropic", "prod", "ok", 42);
    assert_eq!(p["ts"], 1_700_000_000_u64);
    assert_eq!(p["ingress_protocol"], "anthropic");
    assert_eq!(p["pool"], "prod");
    assert_eq!(p["outcome"], "ok");
    assert_eq!(p["latency_ms"], 42_u64);
}

/// Delivering with NO webhook configured is a harmless no-op (no panic, no spawn leak) — the
/// allocation-guarded default path.
#[tokio::test]
async fn deliver_logs_is_noop_when_unconfigured() {
    // TARGETS is an unset process-global here (no `configure` with a valid URL ran), so this returns
    // immediately.
    deliver_logs(crate::export::build_request_log(0, "openai", "p", "ok", 1));
}

/// The in-flight delivery limiter returns its slot on permit Drop (relocated `AdmissionGate` gate).
#[tokio::test]
async fn inflight_guard_releases_slot_on_drop() {
    let before = webhook_inflight().available_permits();
    {
        let _permit = webhook_inflight()
            .try_enter()
            .expect("a slot should be free");
    }
    assert_eq!(
        webhook_inflight().available_permits(),
        before,
        "dropping the owned permit must return the slot"
    );
}
