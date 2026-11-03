// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::export::{ExportStream, CHECK_PHASE_INSTANCES};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::export_calls::parse_families;

use super::*;
use crate::actual_exports;
use crate::both_ways;
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};
use crate::sign::Manifest;

#[test]
fn trace_diagnostics_mask_userinfo_even_when_the_endpoint_is_malformed() {
    let mask = busbar_contract::abi::sdk::mask::mask_url;
    assert_eq!(
        mask("https://user:secret@collector:bad/v1/traces"),
        "https://***@collector:bad/v1/traces"
    );
    assert_eq!(
        mask("https://user:secret@/v1/traces"),
        "https://***@/v1/traces"
    );
    assert_eq!(
        mask("https://collector/v1/traces"),
        "https://collector/v1/traces"
    );
    assert!(!mask("https://user:secret@collector/v1/traces").contains("secret"));
}

fn manifest(name: &str) -> Manifest {
    let v = busbar_contract::abi::export::ABI_VERSION;
    both_ways::statement("export", name, name, v)
}

fn both(name: &str, door: DoorFn, path: std::path::PathBuf) -> [PluginRegistry; 2] {
    let lib = std::fs::read(path).expect("read the actual exporter cdylib");
    let linked = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(name), door)])
        .expect("the linked door admits the sink");
    let mut stated = manifest(name);
    stated.statement = Some(hex::encode(
        rendering_of(door).expect("the door renders its Statement"),
    ));
    let dropped = both_ways::dropped(name, stated, &lib);
    [linked, dropped]
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

const EXPOSITION: &str = "\
# TYPE busbar_requests_total counter
busbar_requests_total{pool=\"a\\\"b\",outcome=\"ok\"} 3

# HELP busbar_lane_state lane health
# TYPE busbar_lane_state gauge
busbar_lane_state{lane=\"x\"} 2

# TYPE busbar_request_duration_seconds histogram
busbar_request_duration_seconds_bucket{le=\"+Inf\"} 2
busbar_request_duration_seconds_sum 0.75
busbar_request_duration_seconds_count 2

";

#[test]
fn the_scrape_sink_answers_the_same_through_either_door() {
    let row = actual_exports::prometheus::NAME;
    let doors = both(
        row,
        actual_exports::prometheus::door,
        actual_exports::prometheus::path(),
    );
    let transcripts = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher())
            .with_conns(Arc::new(crate::needs_restated::Inert));
        let module = row;
        let good = serde_json::json!({ "buffer_seconds": 60 });
        let (streams, clean) = rows.probe(module, "metrics", &good).expect("an export row");
        assert_eq!(streams, Some(vec![ExportStream::Metrics as u8]));
        assert!(clean.is_empty(), "{clean:?}");
        let bad = serde_json::json!({ "buffer_seconds": 60, "bogus": 1 });
        let (_, refused) = rows.probe(module, "metrics", &bad).expect("an export row");
        assert_eq!(
            refused,
            vec![
                "export.metrics.settings: unknown field `bogus`, expected `buffer_seconds` or \
                 `key_gauge_limit`"
                    .to_string()
            ]
        );
        let zero = serde_json::json!({ "buffer_seconds": 0 });
        let (_, zero) = rows.probe(module, "metrics", &zero).expect("an export row");
        assert!(
            zero.len() == 1 && zero[0].starts_with("the `module: prometheus` export instance"),
            "the whole sentence, unprefixed: {zero:?}"
        );
        let sink = rows
            .open(module, "export.metrics", &good)
            .expect("the sink opens");
        let families = parse_families(EXPOSITION).expect("the snapshot reads");
        let body = sink.scrape(&families).expect("the sink renders");
        assert_eq!(body, EXPOSITION.as_bytes(), "the recorder's bytes, back");
        assert!(rows
            .check(module, CHECK_PHASE_INSTANCES, &[("metrics".into(), &good)])
            .expect("an export row")
            .is_empty());
        format!("{refused:?} {zero:?} {}", String::from_utf8_lossy(&body))
    });
    assert_eq!(transcripts[0], transcripts[1], "both doors answer the same");
}

#[test]
fn the_trace_sink_answers_the_same_through_either_door() {
    let row = actual_exports::otlp::NAME;
    let doors = both(
        row,
        actual_exports::otlp::door,
        actual_exports::otlp::path(),
    );
    let transcripts = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher())
            .with_conns(Arc::new(crate::needs_restated::Inert));
        let module = row;
        let good = serde_json::json!({ "url": "http://127.0.0.1:4318/v1/traces" });
        let (streams, clean) = rows.probe(module, "trace", &good).expect("an export row");
        assert_eq!(streams, Some(vec![ExportStream::Traces as u8]));
        assert!(clean.is_empty(), "{clean:?}");
        let bad = serde_json::json!({ "url": "http://127.0.0.1:4318", "bogus": 1 });
        let (_, refused) = rows.probe(module, "trace", &bad).expect("an export row");
        assert_eq!(
            refused,
            vec!["export.trace.settings: unknown field `bogus`, expected `url`".to_string()]
        );
        let sink = rows
            .open(module, "export.trace", &good)
            .expect("the sink opens");
        format!("{refused:?} {:?}", sink.streams())
    });
    assert_eq!(transcripts[0], transcripts[1], "both doors answer the same");
}

#[test]
fn the_request_log_webhook_sink_answers_the_same_through_either_door() {
    let row = actual_exports::webhook::NAME;
    let doors = both(
        row,
        actual_exports::webhook::door,
        actual_exports::webhook::path(),
    );
    let transcripts = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher())
            .with_conns(Arc::new(crate::needs_restated::Inert));
        let module = row;
        let good = serde_json::json!({ "url": "https://collector.example.com/v1/logs" });
        let (streams, clean) = rows.probe(module, "audit", &good).expect("an export row");
        assert_eq!(streams, Some(vec![ExportStream::Logs as u8]));
        assert!(clean.is_empty(), "{clean:?}");
        let bad = serde_json::json!({ "url": "https://collector.example.com", "bogus": 1 });
        let (_, refused) = rows.probe(module, "audit", &bad).expect("an export row");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].starts_with("export.audit.settings: unknown field `bogus`"),
            "{refused:?}"
        );
        let sink = rows
            .open(module, "export.audit", &good)
            .expect("the sink opens");
        format!("{refused:?} {:?}", sink.streams())
    });
    assert_eq!(transcripts[0], transcripts[1], "both doors answer the same");
}

#[test]
fn a_refused_webhook_target_is_said_once_in_busbars_log_at_start() {
    use crate::dispatch::log_file::tests::{config, scratch, HostLog};
    use crate::dispatch::LogLevel;
    let host = HostLog::installed();
    let dir = scratch("webhook-refused");
    let logs = config(&dir, LogLevel::Info);
    let row = actual_exports::webhook::NAME;
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(
            manifest(row),
            actual_exports::webhook::door,
        )])
        .expect("the linked sink admits");
    let rows = ExportRows::new(&registry, dispatcher())
        .with_logs(&logs)
        .with_conns(Arc::new(crate::needs_restated::Refusing));

    let target = serde_json::json!({ "url": "http://127.0.0.1:1/said-once" });
    let said = || {
        host.lines()
            .into_iter()
            .filter(|(target, level, _, message)| {
                target == crate::dispatch::log_file::MIRROR_TARGET
                    && *level == tracing::Level::ERROR
                    && message.contains("disabling this webhook exporter")
                    && message.contains("said-once")
            })
            .count()
    };
    let sink = rows
        .open(row, "export.wh", &target)
        .expect("a refused target never refuses the open");
    let at_open = said();
    sink.start()
        .expect("a refused target never refuses the start");
    let at_start = said();
    let _ = sink.deliver(ExportStream::Logs as u8, b"{}".to_vec(), Box::new(()));
    std::thread::sleep(std::time::Duration::from_millis(200));
    let after = said();
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(at_open, 0, "opening the sink says nothing in busbar's log");
    assert_eq!(at_start, 1, "the start says the refusal exactly once");
    assert_eq!(after, 1, "a delivery after it never says it again");
}

#[test]
fn check_runs_when_the_first_instance_does_not_open() {
    let row = actual_exports::prometheus::NAME;
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(
            manifest(row),
            actual_exports::prometheus::door,
        )])
        .expect("the linked door admits the sink");
    let rows =
        ExportRows::new(&registry, dispatcher()).with_conns(Arc::new(crate::needs_restated::Inert));
    let findings = rows
        .check(
            row,
            busbar_contract::abi::export::CHECK_PHASE_LIMITS,
            &[
                ("metrics".into(), &serde_json::json!({ "bogus": 1 })),
                (
                    "second".into(),
                    &serde_json::json!({ "buffer_seconds": 60 }),
                ),
            ],
        )
        .expect("an export row");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].starts_with("export.second: a second `module: "),
        "{findings:?}"
    );
}

#[test]
fn a_module_no_row_answers_is_not_on_the_axis() {
    let registry = PluginRegistry::empty();
    let rows = ExportRows::new(&registry, dispatcher());
    assert!(rows.probe("nothing", "x", &serde_json::json!({})).is_none());
    assert!(rows.check("nothing", 0, &[]).is_none());
    let Err(refused) = rows.open("nothing", "export.x", &serde_json::json!({})) else {
        panic!("no row answers");
    };
    assert_eq!(refused, "no `kind: export` plugin answers to 'nothing'");
}

#[test]
fn an_export_door_stating_ready_is_awaited_when_it_starts() {
    use crate::dispatch::ready::ready_plugins::export::{door, NAME, READIES};
    use std::sync::atomic::Ordering;
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(NAME), door)])
        .expect("the linked witness admits");
    let rows =
        ExportRows::new(&registry, dispatcher()).with_conns(Arc::new(crate::needs_restated::Inert));
    let refused = serde_json::json!({ "ready": "err:the target is refused" });
    let before = READIES.load(Ordering::SeqCst);
    let _ = rows.check(NAME, CHECK_PHASE_INSTANCES, &[("audit".into(), &refused)]);
    assert_eq!(
        READIES.load(Ordering::SeqCst),
        before,
        "check's instance is never asked"
    );
    let sink = rows
        .open(NAME, "export.audit", &refused)
        .expect("the instance opens; it is not asked yet");
    assert_eq!(READIES.load(Ordering::SeqCst), before, "open does not ask");
    let failed = sink.start().expect_err("a refused ready refuses the start");
    assert!(failed.contains("the target is refused"), "{failed}");
    assert_eq!(READIES.load(Ordering::SeqCst), before + 1);
    rows.open(
        NAME,
        "export.audit",
        &serde_json::json!({ "ready": "fine" }),
    )
    .expect("the sink opens")
    .start()
    .expect("a READY ready starts the sink");
    assert_eq!(READIES.load(Ordering::SeqCst), before + 2);
}

#[test]
fn an_export_instance_is_bound_by_its_own_inflight_clamped_to_one() {
    use crate::dispatch::ready::ready_plugins::export::{door, NAME};
    const DECLARED: u32 = 4;
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(NAME), door)])
        .expect("the linked witness admits");
    let rows =
        ExportRows::new(&registry, dispatcher()).with_conns(Arc::new(crate::needs_restated::Inert));
    let row = rows.row(NAME).expect("an export row");
    let bound = |stated: Option<u64>| {
        let mut settings = serde_json::json!({ "ready": "fine" });
        if let Some(n) = stated {
            settings["max_inflight_deliveries"] = n.into();
        }
        rows.load(row, "export.audit", Some(&settings))
            .expect("the sink binds")
            .max_inflight()
    };
    assert_eq!(
        bound(Some(0)),
        1,
        "a stated 0 runs at one permit, as 1.5.5 clamped it"
    );
    assert_eq!(
        bound(Some(3)),
        3,
        "each instance is bound by its own figure"
    );
    assert_eq!(
        bound(None),
        busbar_contract::export_calls::DEFAULT_INFLIGHT.min(DECLARED),
        "none stated: the default, within the declared concurrency"
    );
}

#[test]
fn a_check_on_a_row_that_will_not_load_answers_why() {
    let row = "export-unloadable";
    let registry = both_ways::dropped(row, manifest(row), b"not a library");
    let rows = ExportRows::new(&registry, dispatcher());
    let findings = rows
        .check(
            row,
            CHECK_PHASE_INSTANCES,
            &[("audit".into(), &serde_json::json!({}))],
        )
        .expect("an export row");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].starts_with(&format!("export `module: {row}`: "))
            && findings[0].contains(NO_DOOR),
        "{findings:?}"
    );
}
