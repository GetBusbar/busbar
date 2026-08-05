// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the built-in `request-log-webhook` exporter — the request-log delivery + SSRF guard +
//! AdmissionGate relocated out of `observability` (design §7.2). 1.5.3: the separate
//! `generic-webhook` exporter FOLDED into this one (its only extra, `auth_header:`, is now a setting
//! here, and its other reason to exist — a SECOND target — is what the NAMED `export:` map provides).

use super::*;

/// A stand-in per-instance delivery deadline. 1.5.3: the timeout is carried on each named instance's
/// [`Target`] rather than read from a process-global, so it is an argument here.
const TEST_TIMEOUT: Duration = Duration::from_secs(2);

/// A stand-in per-instance in-flight delivery cap. 1.5.3 + audit MED-5: the cap is carried on each
/// named instance's [`Target`] (one `AdmissionGate` PER INSTANCE, sized to that instance's own
/// `settings.max_inflight_deliveries`), so it too is an argument here.
const TEST_MAX_INFLIGHT: usize = 4;

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

    push_target(
        &mut targets,
        "https://logs.example.com/busbar",
        None,
        TEST_TIMEOUT,
        TEST_MAX_INFLIGHT,
    );
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
        TEST_TIMEOUT,
        TEST_MAX_INFLIGHT,
    );
    assert_eq!(
        targets.len(),
        1,
        "the SSRF guard rejects an internal target"
    );

    // A plaintext target is rejected by the https-only scheme check.
    push_target(
        &mut targets,
        "http://hook.example.com/log",
        None,
        TEST_TIMEOUT,
        TEST_MAX_INFLIGHT,
    );
    assert_eq!(targets.len(), 1, "the https-only guard rejects plaintext");

    // The per-instance auth header is carried onto the target.
    push_target(
        &mut targets,
        "https://hook.example.com/events",
        Some(("Authorization".to_string(), "Bearer sekret".to_string())),
        TEST_TIMEOUT,
        TEST_MAX_INFLIGHT,
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

/// Delivering with NO webhook configured is a harmless no-op — the allocation-guarded default path
/// EVERY request-finish takes on an unconfigured deployment.
///
/// AUDIT MED-3: this test used to call `deliver_logs` and assert NOTHING, so the no-op it claims to
/// prove was unmeasured — deleting the `TARGETS` guard left it green. The no-op is now asserted on
/// what it OBSERVABLY means: no webhook is configured, and the call spawns NO delivery task. Neuter
/// the guard (make the unset `TARGETS` read fall through to a delivery, e.g. via `.expect`) and this
/// test fails instead of passing.
#[tokio::test]
async fn deliver_logs_is_noop_when_unconfigured() {
    // The precondition this test measures against: TARGETS is an unset process-global (no
    // `configure` with a valid URL runs anywhere in this binary).
    assert!(
        !request_log_configured(),
        "this test measures the UNCONFIGURED path; something configured a webhook sink"
    );
    let rt = tokio::runtime::Handle::current();
    let tasks_before = rt.metrics().num_alive_tasks();

    deliver_logs(crate::export::build_request_log(0, "openai", "p", "ok", 1));

    // Yield once so a spawned task would have been polled (and, if it completed, still counted at
    // spawn time — `num_alive_tasks` rises the moment `tokio::spawn` runs).
    tokio::task::yield_now().await;
    assert_eq!(
        rt.metrics().num_alive_tasks(),
        tasks_before,
        "an unconfigured deliver_logs must not spawn a delivery task"
    );
}

/// AUDIT MED-5 — ONE ADMISSION GATE PER NAMED INSTANCE, sized to THAT instance's own configured cap.
/// Two named webhook sinks (the documented "app logs + SIEM" shape) are two independent delivery
/// budgets: a stalled SIEM must not consume the permits an operator capped low on the fast sink, and
/// the low cap must actually be enforced on the instance that declares it.
///
/// RED-BEFORE-GREEN: pre-fix there was ONE process-global `webhook_inflight()` gate, sized (via
/// `LimitsResolved`) to the MAXIMUM `max_inflight_deliveries` across instances — so `Target` had no
/// `gate` for this test to reach at all, and the cap-1 sink below was in fact admitting 3.
#[tokio::test]
async fn each_webhook_instance_gets_its_own_admission_gate() {
    let mut targets = Vec::new();
    push_target(
        &mut targets,
        "https://fast.example.com/log",
        None,
        TEST_TIMEOUT,
        1,
    );
    push_target(
        &mut targets,
        "https://siem.example.com/log",
        None,
        TEST_TIMEOUT,
        3,
    );
    assert_eq!(targets.len(), 2);

    // Each gate is sized to ITS OWN instance's cap, not to the max across instances.
    assert_eq!(targets[0].gate.available_permits(), 1);
    assert_eq!(targets[1].gate.available_permits(), 3);

    // Saturating the slow sink leaves the fast sink's budget untouched (no cross-instance starving).
    let held: Vec<_> = (0..3)
        .map(|_| targets[1].gate.try_enter().expect("its own 3 slots"))
        .collect();
    assert!(
        targets[1].gate.try_enter().is_none(),
        "the slow sink is saturated at ITS cap"
    );
    assert_eq!(
        targets[0].gate.available_permits(),
        1,
        "a saturated sibling must not consume this instance's budget"
    );
    let permit = targets[0]
        .gate
        .try_enter()
        .expect("the fast sink still admits its own delivery");

    // And every permit returns its slot on Drop (the fire-and-forget task holds an owned permit).
    drop(held);
    drop(permit);
    assert_eq!(targets[1].gate.available_permits(), 3);
    assert_eq!(targets[0].gate.available_permits(), 1);
}
