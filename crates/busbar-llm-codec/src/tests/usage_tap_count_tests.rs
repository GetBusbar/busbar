// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE USAGE-TAP COUNT PIN (#83a SD-3, architect ruling R-USAGE): every way a same-protocol usage
//! tap can fail to read a 2xx body counts ONCE on `busbar_billing_tap_decode_fail_total`, under the
//! reason that says which way, through the ONE host latch the host installs — whether the tap is
//! the chat cell's own (unknown protocol / bad JSON / a body its reader refuses), a leaf cell's
//! default (the host's decode reporter), or the signing dialect's direct shape-probed call
//! (`bedrock::handler::same_protocol_usage`, which calls both). The plane names no metrics crate:
//! the count is the host's, and this suite reads it through a local recorder.

use busbar_contract::codec::OperationHandler;
use busbar_contract::operation::OpVerb;
use metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const FAMILY: &str = "busbar_billing_tap_decode_fail_total";

type Counts = Arc<Mutex<BTreeMap<String, u64>>>;

struct Cell(Counts, String);
impl CounterFn for Cell {
    fn increment(&self, value: u64) {
        *self.0.lock().unwrap().entry(self.1.clone()).or_insert(0) += value;
    }
    fn absolute(&self, value: u64) {
        self.0.lock().unwrap().insert(self.1.clone(), value);
    }
}

/// Counts every counter series `name{k=v,...}` emitted while it is the thread's recorder.
struct Local(Counts);
impl Recorder for Local {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        let labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        let series = format!("{}{{{}}}", key.name(), labels.join(","));
        Counter::from_arc(Arc::new(Cell(Arc::clone(&self.0), series)))
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

fn counted(f: impl FnOnce()) -> BTreeMap<String, u64> {
    crate::ensure_test_protocols_registered();
    let counts = Counts::default();
    metrics::with_local_recorder(&Local(Arc::clone(&counts)), f);
    let out = counts.lock().unwrap().clone();
    out.into_iter()
        .filter(|(series, _)| series.starts_with(FAMILY))
        .collect()
}

fn series(protocol: &str, reason: &str) -> String {
    format!("{FAMILY}{{protocol={protocol},reason={reason}}}")
}

fn cell(op: OpVerb) -> &'static dyn OperationHandler {
    crate::bedrock::DECL
        .handler
        .and_then(|h| h.operation_handler(op))
        .expect("the signing dialect serves the operation")
}

/// A JSON body the signing dialect's chat reader refuses (it is not a Converse document).
const UNREADABLE: &[u8] = b"[1,2,3]";
const NOT_JSON: &[u8] = b"{not json";

#[test]
fn the_chat_cells_three_fault_paths_each_count_once_under_their_reason() {
    let chat = crate::chat_handle::ChatOperation("bedrock");
    let unknown = crate::chat_handle::ChatOperation("no-such-dialect");
    let counts = counted(|| {
        assert!(chat.extract_usage("bedrock", UNREADABLE).is_none());
        assert!(chat.extract_usage("bedrock", NOT_JSON).is_none());
        assert!(chat.extract_usage("bedrock", NOT_JSON).is_none());
        assert!(unknown.extract_usage("no-such-dialect", b"{}").is_none());
    });
    assert_eq!(
        counts,
        BTreeMap::from([
            (series("bedrock", "decode"), 1),
            (series("bedrock", "bad_json"), 2),
            (series("no-such-dialect", "unknown_protocol"), 1),
        ])
    );
}

#[test]
fn a_leaf_cells_default_tap_counts_a_refused_body_as_a_decode_failure() {
    let counts = counted(|| {
        assert!(cell(OpVerb::EMBEDDINGS)
            .extract_usage("bedrock", NOT_JSON)
            .is_none());
        assert!(cell(OpVerb::IMAGE)
            .extract_usage("bedrock", NOT_JSON)
            .is_none());
    });
    assert_eq!(counts, BTreeMap::from([(series("bedrock", "decode"), 2)]));
}

/// THE DIRECT CALL R-USAGE names: the signing dialect's shape-probed same-protocol tap reaches the
/// chat cell or a leaf cell by the body's shape, and each counts exactly as the cell counts when the
/// host dispatches it.
#[test]
fn the_shape_probed_same_protocol_tap_counts_exactly_as_the_cell_it_reaches() {
    // The probe reads the parsed SHAPE; the tap it picks reads the body — so a body the picked cell
    // refuses, under each shape, is what reaches each cell's fault path.
    let image_shaped: serde_json::Value = serde_json::json!({"images": []});
    let converse_shaped: serde_json::Value = serde_json::json!({"output": {}});
    let counts = counted(|| {
        let usage = crate::bedrock::handler::same_protocol_usage;
        assert!(usage(NOT_JSON, None).is_none());
        assert!(usage(NOT_JSON, Some(&image_shaped)).is_none());
        assert!(usage(UNREADABLE, Some(&converse_shaped)).is_none());
    });
    assert_eq!(
        counts,
        BTreeMap::from([
            (series("bedrock", "bad_json"), 1),
            (series("bedrock", "decode"), 2),
        ])
    );
}
