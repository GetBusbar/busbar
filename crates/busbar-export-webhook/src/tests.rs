// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The webhook sink tests itself (DECISIONS #2): its settings refusals, word for word as the
//! compiled-in sink's (1.5.5); what it asks the host to carry; and what it reports.

use super::*;
use busbar_plugin_sdk::{HttpResponse, Rotation};
use serde_json::json;

fn sink(settings: serde_json::Value) -> Box<dyn ExportHandler> {
    open(&settings.to_string()).expect("opens")
}

fn raised(s: &dyn ExportHandler) -> Vec<serde_json::Value> {
    s.drain_observations()
        .diagnostics
        .iter()
        .map(|d| serde_json::to_value(d).unwrap())
        .collect()
}

/// The shape refusals are serde's, under the `export.<name>.settings:` prefix — the same derive,
/// field order and `deny_unknown_fields` the compiled-in `WebhookSettings` had.
#[test]
fn a_settings_shape_refusal_is_the_compiled_in_sinks_line() {
    let s = sink(json!({}));
    assert_eq!(
        s.validate("req-log", &json!({"url": "https://a.example/", "bogus": 1})),
        vec![
            "export.req-log.settings: unknown field `bogus`, expected one of `url`, \
             `auth_header`, `max_inflight_deliveries`, `delivery_timeout_secs`"
        ]
    );
    assert_eq!(
        s.validate("w", &json!({})),
        vec!["export.w.settings: missing field `url`"]
    );
    assert_eq!(
        s.validate(
            "w",
            &json!({"url": "https://a/", "auth_header": {"name": "A"}})
        ),
        vec!["export.w.settings: missing field `value`"]
    );
    assert!(s
        .validate(
            "w",
            &json!({"url": "https://a/", "max_inflight_deliveries": 0})
        )
        .is_empty());
}

/// BOOT-083a / BOOT-083b / BOOT-089f: the validation-phase lines, one in-flight bound over the
/// instances (the largest), then each instance's deadline by its position.
#[test]
fn the_validation_phase_checks_are_the_compiled_in_sinks_lines() {
    let one = |v: serde_json::Value| {
        let instances = [("w".to_string(), v)];
        let mut lines = check(CheckPhase::Limits, &instances);
        lines.extend(check(CheckPhase::Instances, &instances));
        lines
    };
    assert_eq!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 0})),
        vec![
            "export.request-log-webhook.settings.max_inflight_deliveries must be >= 1 (a 0-permit \
             semaphore admits nothing, silently dropping every webhook delivery)"
        ]
    );
    assert_eq!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 2305843009213693952u64})),
        vec![
            "export.request-log-webhook.settings.max_inflight_deliveries must be <= \
             2305843009213693951 (tokio::sync::Semaphore's hard permit ceiling — a value above \
             it panics at build time instead of failing validation)"
        ]
    );
    assert!(
        one(json!({"url": "https://a/", "max_inflight_deliveries": 2305843009213693951u64}))
            .is_empty()
    );
    assert_eq!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": 0})),
        vec![
            "the `module: request-log-webhook` export instance targeting 'https://a/b' (#0) sets \
             settings.delivery_timeout_secs: 0, which would abort every delivery — it must be >= 1"
        ]
    );
    assert_eq!(
        one(json!({"url": "https://a/b", "delivery_timeout_secs": u64::MAX})),
        vec![format!(
            "the `module: request-log-webhook` export instance targeting 'https://a/b' (#0) sets \
             settings.delivery_timeout_secs: {}, above the 946080000-second (30-year) ceiling \
             every duration is bounded by — a delivery deadline that far out overflows the clock",
            u64::MAX
        )]
    );
    // A stingy sibling is not refused beside a generous one: the bound is the largest.
    let two_instances = [
        (
            "a".into(),
            json!({"url": "https://a/", "max_inflight_deliveries": 0}),
        ),
        (
            "b".into(),
            json!({"url": "https://b/", "max_inflight_deliveries": 8, "delivery_timeout_secs": 0}),
        ),
    ];
    let mut two = check(CheckPhase::Limits, &two_instances);
    two.extend(check(CheckPhase::Instances, &two_instances));
    assert_eq!(two.len(), 1, "{two:?}");
    assert!(two[0].contains("'https://b/' (#1)"), "{two:?}");
    assert!(check(CheckPhase::Limits, &[]).is_empty());
    // Each phase answers only its own lines: the deadline is not a limit, the bound not an
    // instance's own.
    let both = [(
        "w".to_string(),
        json!({"url": "https://a/", "max_inflight_deliveries": 0, "delivery_timeout_secs": 0}),
    )];
    assert_eq!(check(CheckPhase::Limits, &both).len(), 1);
    assert!(check(CheckPhase::Limits, &both)[0].contains("max_inflight_deliveries"));
    assert_eq!(check(CheckPhase::Instances, &both).len(), 1);
    assert!(check(CheckPhase::Instances, &both)[0].contains("delivery_timeout_secs"));
}

/// A delivery asks the host to POST the compact JSON line with `content-type: application/json`
/// then the auth header, under the instance's deadline — and nothing else.
#[test]
fn a_delivery_asks_the_host_to_post_the_line() {
    let s = sink(json!({
        "url": "https://siem.example/in",
        "auth_header": {"name": "Authorization", "value": "Bearer x"},
        "delivery_timeout_secs": 9
    }));
    let payload = json!({"ts": 7, "pool": "p", "outcome": "ok"});
    let HostStep::Host { token, ops } = s.deliver_via_host(ExportStream::Logs, &payload) else {
        panic!("a delivery asks the host")
    };
    assert_ne!(token, START);
    assert_eq!(
        ops,
        vec![HostOp::Http(HttpRequest {
            method: "POST".into(),
            url: "https://siem.example/in".into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("Authorization".into(), "Bearer x".into()),
            ],
            body: payload.to_string(),
            timeout_ms: 9000,
        })]
    );
    // Accepted: nothing to report, and never a second request (no retry).
    let ok = HostResult::Http(HttpResponse {
        status: 204,
        body: String::new(),
    });
    assert_eq!(s.resume(token, vec![ok]), HostStep::Done);
    assert!(raised(s.as_ref()).is_empty());
}

/// A non-2xx answer and a transport failure each drop the line and raise their code at debug,
/// with the fields in the compiled-in site's order, the target's userinfo masked.
#[test]
fn a_failed_delivery_raises_its_code_once_and_is_not_retried() {
    let s = sink(json!({"url": "https://user:pw@siem.example/in"}));
    let status = HostResult::Http(HttpResponse {
        status: 503,
        body: "busy".into(),
    });
    assert_eq!(s.resume(1, vec![status]), HostStep::Done);
    let failed = HostResult::Failed {
        step: "request".into(),
        error: "timed out".into(),
        rotation: None::<Rotation>,
    };
    assert_eq!(s.resume(2, vec![failed]), HostStep::Done);
    let got = raised(s.as_ref());
    assert_eq!(
        got,
        vec![
            json!({"code": "BUSBAR-7071", "level": "debug",
                   "message": "request-log webhook delivery returned a non-2xx status; this log was dropped",
                   "fields": {"status": "503", "webhook_url": "\"https://***@siem.example/in\""},
                   "order": ["webhook_url", "status"]}),
            json!({"code": "BUSBAR-7072", "level": "debug",
                   "message": "request-log webhook delivery failed (transport error); this log was dropped",
                   "fields": {"error_kind": "timed out", "webhook_url": "\"https://***@siem.example/in\""},
                   "order": ["webhook_url", "error_kind"]}),
        ]
    );
}

/// At start the sink asks the host's policy about its target: admitted, it is live under the
/// `webhook` gate at its own bound; refused, it raises BUSBAR-7070 in the policy's words and takes
/// nothing this run.
#[test]
fn start_admits_the_target_or_disables_the_instance() {
    let s = sink(json!({"url": "https://a.example/", "max_inflight_deliveries": 5}));
    assert_eq!(
        s.start(),
        HostStep::Host {
            token: START,
            ops: vec![HostOp::Admit {
                url: "https://a.example/".into()
            }]
        }
    );
    let done = HostResult::Done { rotation: None };
    assert_eq!(
        s.resume(START, vec![done]),
        HostStep::Started {
            live: true,
            inflight: 5,
            gate: "webhook".into()
        }
    );
    let refused = HostResult::Failed {
        step: "refused".into(),
        error: "observability.request_log_webhook_url must be an https:// URL (got 'http://a/')"
            .into(),
        rotation: None,
    };
    assert_eq!(
        s.resume(START, vec![refused]),
        HostStep::Started {
            live: false,
            inflight: 0,
            gate: "webhook".into()
        }
    );
    assert_eq!(
        raised(s.as_ref()),
        vec![json!({"code": "BUSBAR-7070", "level": "error",
            "message": "observability.request_log_webhook_url must be an https:// URL (got 'http://a/'); disabling this webhook exporter"})]
    );
}

#[test]
fn userinfo_is_masked_and_nothing_else_moves() {
    assert_eq!(
        mask_userinfo("https://u:p@h.example/x"),
        "https://***@h.example/x"
    );
    assert_eq!(mask_userinfo("https://h.example/x"), "https://h.example/x");
    assert_eq!(mask_userinfo("not a url"), "not a url");
}

/// The declaration both doors state: the shed counter and the three catalogue codes it raises.
#[test]
fn the_declaration_states_the_shed_counter_and_the_codes() {
    let d: serde_json::Value = serde_json::from_str(DECLARES).unwrap();
    assert_eq!(ALIAS, "request-log-webhook");
    assert_eq!(
        d["metrics"],
        json!([{"name": "busbar_webhook_logs_dropped_total", "type": "counter", "shed": true}])
    );
    let codes: Vec<u64> = d["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["code"].as_u64().unwrap())
        .collect();
    assert_eq!(codes, vec![7070, 7071, 7072]);
}
