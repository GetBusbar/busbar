// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EXPORT-STREAMS (ABI-MIN3-INTERFACE §14): Export streams (round 28). (a)'s one-definition source check is
//! W1-X1's job.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_contract::export_stream::ExportStream;
use busbar_plugin_abi::kinds::export::export::{
    tag, FB_SPAN_RECORDS, M_DELIVER, STREAM_COMPLETIONS, STREAM_CONTENT, STREAM_COSTS,
    STREAM_COUNT, STREAM_DECISIONS, STREAM_EVENTS, STREAM_IDENTITY, STREAM_LOGS, STREAM_METRICS,
    STREAM_PROMPTS, STREAM_TRACES,
};
use busbar_plugin_abi::records::{Records, Reply, Writer};
use busbar_plugin_loader::adapters::export::decode_describe;

#[test]
fn the_const_block_matches_export_stream() {
    let pairs = [
        (STREAM_METRICS, ExportStream::Metrics),
        (STREAM_LOGS, ExportStream::Logs),
        (STREAM_TRACES, ExportStream::Traces),
        (STREAM_COSTS, ExportStream::Costs),
        (STREAM_DECISIONS, ExportStream::Decisions),
        (STREAM_EVENTS, ExportStream::Events),
        (STREAM_IDENTITY, ExportStream::Identity),
        (STREAM_PROMPTS, ExportStream::Prompts),
        (STREAM_COMPLETIONS, ExportStream::Completions),
        (STREAM_CONTENT, ExportStream::Content),
    ];
    for (id, stream) in pairs {
        assert_eq!(id, stream as u32);
        assert_eq!(ExportStream::ALL[id as usize], stream);
    }
    assert_eq!(ExportStream::ALL.len(), STREAM_COUNT as usize);
}

fn describe(bodies: &[&[u8]]) -> Reply {
    let mut w = Reply::new();
    for body in bodies {
        w.put(tag::D_STREAMS, body).unwrap();
    }
    w
}

#[test]
fn bad_d_streams_bodies_are_describe_invalid() {
    let run = |w: &Reply, facts: u64| decode_describe(Records::new(w.as_bytes()), M_DELIVER, facts);
    // The good one: {LOGS, EVENTS} is a mask of exactly those two bits.
    let ok = run(&describe(&[&[1, 5]]), 0).unwrap();
    assert_eq!(ok.streams, (1 << STREAM_LOGS) | (1 << STREAM_EVENTS));
    // No D_STREAMS at all declares none.
    assert_eq!(run(&Reply::new(), 0).unwrap().streams, 0);
    // Empty, a repeated id, a descending pair, an id >= 10, 11 bytes, two D_STREAMS records.
    let eleven: Vec<u8> = (0..=10).collect();
    for bad in [
        describe(&[&[]]),
        describe(&[&[1, 1]]),
        describe(&[&[5, 1]]),
        describe(&[&[10]]),
        describe(&[&eleven]),
        describe(&[&[1], &[5]]),
    ] {
        assert!(run(&bad, 0).is_err());
    }
    // FB_SPAN_RECORDS needs STREAM_TRACES (C-SPAN-RECORDS (a)).
    assert!(run(&describe(&[&[1]]), FB_SPAN_RECORDS).is_err());
    assert!(
        run(&describe(&[&[1, 2]]), FB_SPAN_RECORDS)
            .unwrap()
            .span_records
    );
}

#[test]
#[ignore = "owner: W1-K8C"]
fn stream_routing_and_refusals() {
    todo!("owner: W1-K8C (C-EXPORT-STREAMS)")
}
