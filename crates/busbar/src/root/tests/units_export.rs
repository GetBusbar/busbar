// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT FAN-OUT, measured at the root: the shed, and the per-projection payload build.
//!
//! These are the two things the root took over from the sinks, so this is where they are held in
//! place. Neither test names a sink body: they drive the fan-out over `ship` closures of their own,
//! which is the point — the fan-out is written over what a sink DECLARES, never over which one it
//! happens to be. The projections they use are minted through the REAL config path
//! (`resolve_export`), because resolution is the only way to obtain a `Projection` at all and a
//! test door that could widen one would be the hole in "the operator grants, nothing else does".

use super::*;
// The on-disk `export:` shape through the engine's own re-export of it: same reason the module
// above imports at module level — the root's reach into the retiring crates is a ratchet.
use config::ExportDefs;

/// A real resolved projection for the `request-log-file` module, minted through `resolve_export`
/// exactly as boot mints one — resolution is the only way to obtain one at all.
fn logs_projection() -> Projection {
    let mut defs = ExportDefs::new();
    defs.insert(
        "t".to_string(),
        // Deserialized from the operator's document rather than built as a struct literal: this is
        // the shape a config file actually carries, and the keys it omits are the ones the resolver
        // is supposed to fill in from what the sink itself declares.
        serde_json::from_value(serde_json::json!({
            "module": "request-log-file",
            "settings": { "path": "/dev/null" },
        }))
        .expect("a well-formed export instance"),
    );
    let mut errors = Vec::new();
    let cfg = config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:#?}");
    let mut instances = export::request_log_file_instances(&cfg);
    assert_eq!(
        instances.len(),
        1,
        "one configured instance, one declared sink"
    );
    instances.remove(0).projection
}

/// One composed sink whose `ship` only counts, so a test can measure what the fan-out DID without a
/// filesystem or a socket in the way.
fn counting_sink(
    projection: Projection,
    max_inflight: usize,
    shipped: &Arc<std::sync::atomic::AtomicUsize>,
    held: &Arc<std::sync::Mutex<Vec<tokio::sync::OwnedSemaphorePermit>>>,
) -> Sink {
    let shipped = shipped.clone();
    let held = held.clone();
    Sink {
        projection,
        gate: AdmissionGate::new(max_inflight, "test-fan-out"),
        dropped_total: "busbar_test_logs_dropped_total",
        ship: Box::new(move |_payload, permit| {
            shipped.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // HOLD the permit, exactly as a real delivery does for as long as it runs: the slot
            // comes back on Drop and not before, which is the property the cap depends on.
            held.lock().unwrap_or_else(|e| e.into_inner()).push(permit);
        }),
    }
}

/// The facts a request-finish hands over. The values are irrelevant here; what matters is that one
/// set of them reaches the fan-out.
fn facts() -> RequestLogFacts<'static> {
    RequestLogFacts {
        ts: 1_700_000_000,
        ingress_protocol: "anthropic",
        pool: "prod",
        outcome: "ok",
        latency_ms: 42,
    }
}

/// ONE GATE PER SINK, SIZED TO THAT SINK'S OWN DECLARED CAP — and a saturated sink sheds ITS OWN
/// line without touching a sibling's budget.
///
/// This is the half of "each named instance is its own budget" that used to live inside the sinks,
/// where each one both declared its cap and enforced it (and the file sink's copy of the mechanic
/// was a third of core's `limits::admission`). The declaration is still the sink's; the enforcement
/// is the root's, because capacity is a property of the composition and not of a sink that knows
/// nothing about what runs beside it. Before either, there was ONE process-global gate sized to the
/// MAXIMUM cap across instances — so a cap an operator set low was never enforced at all.
#[test]
fn fan_out_gates_each_sink_at_its_own_declared_cap() {
    let p = logs_projection();
    let shipped_fast = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let shipped_slow = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sinks = vec![
        counting_sink(p, 1, &shipped_fast, &held),
        counting_sink(p, 3, &shipped_slow, &held),
    ];

    // Five request-finishes against a cap-1 sink and a cap-3 sink, with every delivery still
    // holding its permit (nothing is released mid-run).
    let facts = facts();
    for _ in 0..5 {
        fan_out(&sinks, &facts);
    }

    assert_eq!(
        shipped_fast.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the cap-1 sink admits exactly ONE concurrent delivery and sheds the rest"
    );
    assert_eq!(
        shipped_slow.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "the cap-3 sink admits exactly THREE — its own budget, unaffected by its saturated sibling"
    );

    // Every permit returns its slot on Drop, so the next request-finish is admitted again.
    held.lock().unwrap_or_else(|e| e.into_inner()).clear();
    fan_out(&sinks, &facts);
    assert_eq!(
        (
            shipped_fast.load(std::sync::atomic::Ordering::SeqCst),
            shipped_slow.load(std::sync::atomic::Ordering::SeqCst)
        ),
        (2, 4),
        "a released permit re-opens the slot"
    );
}

/// SINKS HOLDING THE IDENTICAL PROJECTION SHARE ONE BUILD.
///
/// The build cost is per DISTINCT PROJECTION, not per sink — measured by pointer identity, because
/// equal-looking payloads would pass even with the cache deleted. (The other half of the cache's
/// contract — a DIFFERENT projection gets its own build — cannot be posed from config on this tip:
/// `logs` pins `correlation_id`, which this release does not yet produce, so `fields:` on the one
/// produced per-request stream is refused outright and every `logs` sink resolves to the same
/// projection. It comes back with the correlation-id producer.)
#[test]
fn payload_is_shared_across_sinks_holding_the_identical_projection() {
    let facts = facts();
    let mut cache = PayloadCache::new(&facts);
    let p = logs_projection();

    let a = cache.get(p);
    let b = cache.get(p);
    assert!(
        Arc::ptr_eq(&a, &b),
        "two sinks with the identical projection must share ONE build"
    );
    // And what they share is the request-log line, built to that projection.
    assert_eq!(a["pool"], "prod");
    assert_eq!(a["latency_ms"], 42_u64);
}

/// The `request-log-webhook` instances an operator's document resolves to, minted through the REAL
/// config path — the only way to obtain a `Projection` at all, and the path that runs the SSRF guard
/// that decides whether a target becomes an instance in the first place.
fn webhook_instances(url: &str) -> Vec<export::RequestLogWebhookInstance> {
    let mut defs = ExportDefs::new();
    defs.insert(
        "w".to_string(),
        serde_json::from_value(serde_json::json!({
            "module": "request-log-webhook",
            "settings": {
                "url": url,
                "auth_header": { "name": "Authorization", "value": "Bearer sekret" },
                "delivery_timeout_secs": 7,
                "max_inflight_deliveries": 2,
            },
        }))
        .expect("a well-formed export instance"),
    );
    let mut errors = Vec::new();
    let cfg = config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:#?}");
    export::request_log_webhook_instances(&cfg)
}

/// THE SERVED EXPORT PATH DELIVERS THROUGH THE PLUGIN, AND WHAT THE PLUGIN FRAMES IS THE LINE THE
/// ENGINE USED TO POST.
///
/// One request-finish goes into the root's fan-out; what comes out the far end is the
/// `busbar-export-webhook` sink's framed POST, handed to a send of this test's own instead of to a
/// socket. The assertion is on the BYTES: the body is the request-log line built to this instance's
/// projection — the same payload the in-engine `webhook.rs` serialized — at the operator's target,
/// under the operator's auth header, with that instance's own deadline.
///
/// The engine cannot answer this on its own any more: it holds no webhook sink to state the
/// delivery, and if the composition stopped naming the sink it mounts — or shipped it something
/// other than the payload it built — this is where it would show.
#[test]
fn the_served_webhook_path_frames_the_request_log_line_through_the_plugin() {
    let instances = webhook_instances("https://logs.example.com/busbar");
    assert_eq!(instances.len(), 1, "one configured instance, one sink");

    // The fake wire: it receives exactly what the socket would have, keeps it, and answers.
    type Sent = (String, Vec<(String, String)>, Vec<u8>, std::time::Duration);
    let sent: Arc<std::sync::Mutex<Vec<Sent>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = sent.clone();
    let send: export::ExportDeliverySend =
        Arc::new(move |url, headers, body, timeout, hold, outcome| {
            drop(hold);
            seen.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((url, headers, body, timeout));
            outcome(Ok(200));
        });

    let sinks = compose_webhook_sinks(instances, send);
    let facts = facts();
    fan_out(&sinks, &facts);

    let sent = sent.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(sent.len(), 1, "one request-finish, one delivery");
    let (url, headers, body, timeout) = &sent[0];
    assert_eq!(url, "https://logs.example.com/busbar");
    assert_eq!(
        headers,
        &vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer sekret".to_string()),
        ]
    );
    assert_eq!(*timeout, std::time::Duration::from_secs(7));

    // THE BYTES. What went out is the request-log line the root built to this sink's projection —
    // not a re-encoding of it and not some other sink's payload.
    let expected = export::build_request_log(sinks[0].projection, &facts).to_string();
    assert_eq!(
        String::from_utf8(body.clone()).expect("a utf-8 line"),
        expected
    );
    let line: serde_json::Value = serde_json::from_slice(body).expect("json");
    assert_eq!(line["pool"], "prod");
    assert_eq!(line["latency_ms"], 42_u64);
}

/// A TARGET THE GUARD REFUSES NEVER BECOMES A SINK, so nothing composes and nothing is ever POSTed
/// at it. The guard runs at resolution — once, on the operator's document — and the sink crate never
/// sees the target at all.
#[test]
fn an_ssrf_refused_target_composes_no_sink() {
    assert!(
        webhook_instances("https://169.254.169.254/latest/meta-data/").is_empty(),
        "a cloud-metadata target is refused before it can become a sink"
    );
    assert!(
        webhook_instances("gopher://hook.example.com/log").is_empty(),
        "a target whose scheme is not the secure one is refused, whatever it is instead"
    );
}

/// EACH NAMED INSTANCE IS ITS OWN BUDGET, and the number that reaches the gate is the one the
/// operator wrote on THAT instance — never a value reconciled across instances (the process-global
/// gate this replaced was sized to the MAX across them, so a low cap was never enforced at all).
#[test]
fn each_webhook_instance_carries_its_own_declared_cap() {
    let instances = webhook_instances("https://logs.example.com/busbar");
    assert_eq!(instances[0].max_inflight, 2);
    assert_eq!(instances[0].timeout, std::time::Duration::from_secs(7));
    assert_eq!(
        instances[0].display_url, "https://logs.example.com/busbar",
        "a credential-free target is carried unchanged into the loggable spelling"
    );
}

/// THE LOGGABLE SPELLING IS MASKED AT RESOLUTION, beside the masker, and it is the ONLY target
/// spelling the sink crate is given for its reports — while the delivery still goes to the real one.
#[test]
fn an_operators_credentials_reach_the_sink_only_in_the_address_never_in_the_label() {
    let instances = webhook_instances("https://alice:hunter2@logs.example.com/busbar");
    assert_eq!(instances.len(), 1);
    assert_eq!(
        instances[0].url,
        "https://alice:hunter2@logs.example.com/busbar"
    );
    assert_eq!(
        instances[0].display_url,
        "https://***@logs.example.com/busbar"
    );
}
