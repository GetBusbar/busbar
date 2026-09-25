// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The file sink's own contract: what it asks the host to do, what it reports back, and the words
//! its settings errors carry. The both-doors equivalence is proven where both doors exist — the
//! composition root (`crates/busbar/src/root/tests/linked_exports.rs`).

use super::*;
use busbar_plugin_sdk::{RotationFault, Route};

fn sink(settings: serde_json::Value) -> Box<dyn ExportHandler> {
    open(&settings.to_string()).expect("the sink opens")
}

/// A delivery is ONE host append of the line plus `\n` to the declared destination, rotating at
/// `rotate_mb` MiB and keeping nine archives — the sink names the destination, never a path.
#[test]
fn a_delivery_is_one_host_append_of_the_line() {
    let s = sink(serde_json::json!({"path": "/var/log/x.jsonl", "rotate_mb": 2}));
    let line = serde_json::json!({"outcome": "ok", "ts": 1});
    assert_eq!(
        s.deliver_via_host(ExportStream::Logs, &line),
        HostStep::Host {
            token: 0,
            ops: vec![HostOp::Write {
                destination: "path".into(),
                data: "{\"outcome\":\"ok\",\"ts\":1}\n".into(),
                rotate_at: Some(2 * 1024 * 1024),
                keep: 9,
            }],
        }
    );
    let never = sink(serde_json::json!({"path": "/var/log/x.jsonl"}));
    assert!(matches!(
        never.deliver_via_host(ExportStream::Logs, &line),
        HostStep::Host { ops, .. } if matches!(&ops[0], HostOp::Write { rotate_at: None, .. })
    ));
}

/// The settings error is the configuration grammar's own serde line, prefixed as the host always
/// prefixed it; good settings report nothing.
#[test]
fn settings_are_validated_in_the_configurations_words() {
    let s = sink(serde_json::json!({}));
    assert!(s
        .validate("tail", &serde_json::json!({"path": "/x", "rotate_mb": 1}))
        .is_empty());
    assert_eq!(
        s.validate("tail", &serde_json::json!({})),
        vec!["export.tail.settings: missing field `path`".to_string()]
    );
    assert_eq!(
        s.validate("tail", &serde_json::json!({"path": "/x", "rotate": 1})),
        vec![
            "export.tail.settings: unknown field `rotate`, expected `path` or `rotate_mb`"
                .to_string()
        ]
    );
}

/// What the host reports is what the sink counts: a renamed rotation is one `rotated`, a failed
/// final rename one `rotate_failed`; a drain resets.
#[test]
fn the_hosts_rotations_are_counted_and_drained() {
    let s = sink(serde_json::json!({"path": "/x"}));
    let rotation = |renamed: bool| Rotation {
        archive: "/x.1".into(),
        renamed,
        faults: (!renamed)
            .then(|| RotationFault {
                step: "rename".into(),
                from: "/x".into(),
                to: Some("/x.1".into()),
                error: "denied".into(),
            })
            .into_iter()
            .collect(),
    };
    let results = vec![
        HostResult::Done {
            rotation: Some(rotation(true)),
        },
        HostResult::Failed {
            step: "append".into(),
            error: "full".into(),
            rotation: Some(rotation(false)),
        },
        HostResult::Done { rotation: None },
    ];
    assert_eq!(s.resume(0, results), HostStep::Done);
    let drained = s.drain_observations();
    let got: Vec<(String, f64)> = drained
        .metrics
        .iter()
        .map(|m| (m.name.clone(), m.value))
        .collect();
    assert_eq!(
        got,
        vec![
            (ROTATED_TOTAL.into(), 1.0),
            (ROTATE_FAILED_TOTAL.into(), 1.0)
        ]
    );
    assert!(s.drain_observations().is_empty());
}

/// Every code the sink raises and every series it reports is one its manifest DECLARES — the host
/// registers and grants exactly those — and the dropped counter is the declared SHED counter.
#[test]
fn every_code_and_series_the_sink_uses_is_declared() {
    let d: serde_json::Value = serde_json::from_str(DECLARES).expect("declares.json parses");
    let codes: Vec<String> = d["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| format!("BUSBAR-{}", x["code"]))
        .collect();
    for code in [
        APPEND_FAILED,
        OPEN_FAILED,
        RETENTION_FAILED,
        SHIFT_FAILED,
        ROTATE_RENAME_FAILED,
    ] {
        assert!(codes.contains(&code.to_string()), "{code} is not declared");
    }
    let series = |shed: bool| -> Vec<String> {
        d["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["shed"].as_bool().unwrap_or(false) == shed)
            .map(|m| m["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(series(false), vec![ROTATED_TOTAL, ROTATE_FAILED_TOTAL]);
    assert_eq!(series(true), vec![DROPPED_TOTAL]);
    assert_eq!(d["destinations"], serde_json::json!([DESTINATION]));
}

/// A push-only sink: it carries the `logs` stream and serves no route.
#[test]
fn the_sink_carries_logs_and_serves_no_route() {
    let s = sink(serde_json::json!({"path": "/x"}));
    assert_eq!(s.streams(), vec![ExportStream::Logs]);
    assert_eq!(s.routes(), Vec::<Route>::new());
}
