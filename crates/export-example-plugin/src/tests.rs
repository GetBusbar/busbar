// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for the trivial `kind: export` reference plugin: it declares exactly the `Metrics`
//! stream, takes the trait's default no-op `deliver`, and `open` accepts any config (including
//! malformed JSON) since this sink has no configurable shape.

use super::*;

#[test]
fn open_accepts_empty_config() {
    assert!(open("").is_ok());
}

#[test]
fn open_accepts_malformed_json_config_since_none_is_read() {
    // Unlike every other example plugin's `open`, this one reads NOTHING from `cfg` — a stray
    // trailing comma or outright garbage must not fail the load, since there is no shape to parse.
    assert!(open("{ not json at all").is_ok());
    assert!(open(r#"{"durable_path": "/x",}"#).is_ok());
}

#[test]
fn the_sink_declares_exactly_the_metrics_stream() {
    let sink = open("").unwrap();
    assert_eq!(sink.streams(), vec![ExportStream::Metrics]);
}

#[test]
fn deliver_is_the_trait_default_no_op_and_does_not_panic() {
    let sink = open("").unwrap();
    // The default `deliver` is a no-op: calling it for the declared stream (and for one it did NOT
    // declare) must not panic and produces no observable state to assert on beyond "it returned".
    sink.deliver(ExportStream::Metrics, &serde_json::json!({"n": 1}));
    sink.deliver(ExportStream::Logs, &serde_json::json!({}));
}

/// THE CATALOG IS WELL-FORMED: what the host reads at load and refuses if it does not check.
#[test]
fn the_catalog_is_a_catalog_document_that_checks() {
    let catalog = catalog();
    catalog.check().expect("the catalog checks");
    for e in catalog.entries.as_slice() {
        assert!(
            catalog.template(&e.code, "en").is_some(),
            "{} has an en template",
            e.code
        );
    }
}
