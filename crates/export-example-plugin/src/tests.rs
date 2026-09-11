// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for the trivial `kind: export` reference plugin: it declares exactly the `metrics`
//! stream, takes every record and drops it, declares no route, and `open` accepts any config
//! (including malformed JSON) since this sink has no configurable shape.

use super::*;
use busbar_plugin_sdk::Delivery;

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

/// A host that lends nothing, which is what the six-symbol C ABI can carry.
struct NoLoan;

impl ExportHost for NoLoan {
    fn send(&self, _delivery: Delivery) -> bool {
        false
    }
    fn read(&self, _stream: &str) -> Option<String> {
        None
    }
}

#[test]
fn the_sink_declares_exactly_the_metrics_stream() {
    let sink = open("").unwrap();
    assert_eq!(sink.streams(), &["metrics"]);
}

/// THE WHOLE FACE, STATED BY THIS PLUGIN. It takes a record for the stream it declared and for one
/// it did not, drops both, and says [`Ack::Received`] — the honest word for "I have it and it is
/// nowhere durable". It declares no route and answers an unrouted request with a 404.
#[test]
fn the_sink_takes_every_record_drops_it_and_serves_nothing() {
    let sink = open("").unwrap();
    assert_eq!(
        sink.receive(
            ExportItem {
                stream: "metrics",
                bytes: br#"{"n":1}"#,
            },
            &NoLoan
        ),
        Ack::Received
    );
    assert_eq!(
        sink.receive(
            ExportItem {
                stream: "logs",
                bytes: b"{}",
            },
            &NoLoan
        ),
        Ack::Received
    );
    assert!(sink.routes().is_empty());
    assert_eq!(
        sink.serve(
            &ServeRequest {
                path: "/whatever",
                method: "GET",
                headers: &[],
                body: &[],
            },
            &NoLoan
        )
        .status,
        404
    );
}
