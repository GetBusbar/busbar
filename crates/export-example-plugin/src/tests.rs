// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for the trivial `kind: export` reference plugin: it declares exactly the `Metrics`
//! stream, DROPS every batch AND SAYS SO (answering `Retry`), and `open` accepts any config
//! (including malformed JSON) since this sink has no configurable shape.

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
fn deliver_drops_the_batch_and_honestly_says_retry() {
    let sink = open("").unwrap();
    // It is handed a record for the stream it declared and one for a stream it did not, drops BOTH,
    // and answers `Retry` to each — the only true word for a sink that took the record nowhere.
    // `Received` would claim the sink HAS it.
    assert_eq!(
        sink.deliver(ExportStream::Metrics, &serde_json::json!({"n": 1})),
        ExportAck::Retry
    );
    assert_eq!(
        sink.deliver(ExportStream::Logs, &serde_json::json!({})),
        ExportAck::Retry
    );
}
