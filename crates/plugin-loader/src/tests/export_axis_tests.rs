// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export rows (`export_axis.rs`) through BOTH DOORS on the export kind's memory ABI: the real
//! sinks (owner FIXTURES ruling: "real plugins are the proofs") — the prometheus sink and the OTLP
//! trace sink — each LINKED by its logic crate's `door` and DROPPED IN as its `-plugin` crate's
//! `cdylib` (signed first-party, its Statement rendering in its manifest), probed, validated and
//! opened through ONE dispatcher, and required to answer the same. The validate refusal renders
//! under the instance as 1.5.5 printed it.

use std::sync::Arc;

use busbar_contract::abi::export::{ExportStream, CHECK_PHASE_INSTANCES};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::export_calls::parse_families;

use super::*;
use crate::both_ways;
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};
use crate::sign::Manifest;

/// A first-party export manifest named `name`, at this host's export ABI.
fn manifest(name: &str) -> Manifest {
    let v = busbar_contract::abi::export::ABI_VERSION;
    both_ways::statement("export", name, name, v)
}

/// The two registries a sink is reached through: its `door` LINKED, and its `-plugin` crate's
/// `cdylib` (`crate_snake`) DROPPED IN with its Statement rendering. `None` when the `cdylib` is not
/// built in this (scoped, non-CI) run.
fn both(name: &str, door: DoorFn, crate_snake: &str) -> Option<[PluginRegistry; 2]> {
    let lib = std::fs::read(both_ways::cdylib(crate_snake)?).expect("read the cdylib");
    let linked = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(name), door)])
        .expect("the linked door admits the sink");
    let mut stated = manifest(name);
    stated.statement = Some(hex::encode(
        rendering_of(door).expect("the door renders its Statement"),
    ));
    let dropped = both_ways::dropped(crate_snake, stated, &lib);
    Some([linked, dropped])
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

/// The recorder exposition both doors render back, in the sink's stable order (counters, then
/// gauges, then histograms/summaries, name-sorted within a kind).
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

/// THE PROMETHEUS SINK, BOTH DOORS: each probes as carrying `metrics`, validates good settings
/// clean, refuses a bad key under the instance in 1.5.5's words and its zero retention in its own
/// whole sentence, and renders the recorder snapshot back byte for byte — the same either way.
#[test]
fn the_scrape_sink_answers_the_same_through_either_door() {
    let Some(doors) = both(
        "busbar-export-prometheus",
        busbar_export_prometheus::door::door,
        "busbar_export_prometheus_plugin",
    ) else {
        eprintln!("skip: the prometheus sink's cdylib is not built");
        return;
    };
    let transcripts = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher());
        let module = "busbar-export-prometheus";
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
            .check(module, CHECK_PHASE_INSTANCES, &[("metrics".into(), good)])
            .expect("an export row")
            .is_empty());
        format!("{refused:?} {zero:?} {}", String::from_utf8_lossy(&body))
    });
    assert_eq!(transcripts[0], transcripts[1], "both doors answer the same");
}

/// THE OTLP SINK, BOTH DOORS: each probes as carrying `traces`, refuses a bad key under the
/// instance, and opens on good settings — the same either way. Its deliveries ride the host's
/// connector; the shipped binary's both-doors proof posts them (`traces_stream_both_doors`).
#[test]
fn the_trace_sink_answers_the_same_through_either_door() {
    let Some(doors) = both(
        "busbar-export-otlp",
        busbar_export_otlp::door::door,
        "busbar_export_otlp_plugin",
    ) else {
        eprintln!("skip: the OTLP sink's cdylib is not built");
        return;
    };
    let transcripts = doors.map(|registry| {
        // The OTLP sink declares an http need: opened to deliver, it binds over a table (one that
        // declares it and opens nothing; this row never delivers).
        let rows = ExportRows::new(&registry, dispatcher())
            .with_conns(Arc::new(crate::needs_restated::Inert));
        let module = "busbar-export-otlp";
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

/// A module no `kind: export` row answers is not the axis's (`None`), and opening it is refused
/// naming it.
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
