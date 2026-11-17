// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export suite body (IF §14). Runs the generic admit/open/close cases and the export contract cases
//! (C-EXPORT-STREAMS, C-EXPORT-DELIVERY, C-SPAN-RECORDS as the plugin side can show them) through the registry's
//! `open_export`, driving the plugin with [`super::harness::Harness`]. The core-side arms (descriptor
//! rejection, pump retry schedule, breaker cells) belong to core's own tests, not to a plugin's suite.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::plugin::Plugin;
use busbar_ports::export::{Delivered, ExportPort, FamilyIn};
use busbar_ports::{CallCx, PortError};

use super::harness::Harness;
use crate::fake_needs::FakeNeeds;

/// STREAM_COUNT (§8.5, round 33): ids 0..=9.
const STREAM_COUNT: u32 = 10;
/// The metrics snapshot stream: pulled through `render`, never pushed through `deliver`.
const STREAM_METRICS: u32 = 0;
const STREAM_TRACES: u32 = 2;
/// `prompts` and `completions` have no producer and are never sent (C-EXPORT-STREAMS (d)).
const RESERVED: [u32; 2] = [7, 8];
const CUSTODY_INDEXED: u32 = 3;

fn cx(delivery: u64) -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(30),
        request_id: delivery,
        stack: CallStack::default(),
    }
}

fn deliver(
    h: &Harness,
    port: &dyn ExportPort,
    stream: u32,
    delivery: u64,
    attempt: u32,
    lines: &[&[u8]],
) -> Result<Delivered, PortError> {
    h.block_on(port.deliver(cx(delivery), stream, delivery, attempt, lines))
}

/// What a delivered answer must satisfy whatever the stream: the accepted prefix is within the batch, the
/// custody level is a defined one, and an APPEND names no more than the batch.
fn check_delivered(what: &str, got: &Delivered, lines: &[&[u8]], ceiling: Option<u32>) {
    match got {
        Delivered::Acked { accepted, custody } => {
            assert!(
                *accepted <= lines.len() as u64,
                "{what}: accepted {accepted} of {} lines",
                lines.len()
            );
            assert!(
                custody.level <= CUSTODY_INDEXED,
                "{what}: custody level {} is not defined",
                custody.level
            );
            if let Some(ceiling) = ceiling {
                assert!(
                    custody.level <= ceiling,
                    "{what}: custody {} above the stated ceiling {ceiling}",
                    custody.level
                );
            }
        }
        Delivered::Append {
            accepted, bytes, ..
        } => {
            assert!(
                *accepted <= lines.len() as u64,
                "{what}: APPEND accepted {accepted} of {} lines",
                lines.len()
            );
            if let Some(bytes) = bytes {
                assert!(
                    lines.is_empty() || !bytes.is_empty() || *accepted == 0,
                    "{what}: APPEND accepted lines but named no bytes"
                );
            }
        }
    }
}

pub(super) fn run(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    let h = match Harness::admit(plugin, needs) {
        Ok(h) => h,
        Err(refusal) => panic!("export suite: admission refused: {refusal:?}"),
    };

    // Generic: an export plugin's own config bytes that cannot be a config are refused, never a fault.
    let junk = h.check("suite-junk", b"\xff\xfe not a config");
    assert!(junk.is_err(), "export suite: a non-document config opened");

    // DRY_RUN of the suite's own config: the ENDPOINTs it declares are what every Need below must match.
    if let Err(e) = h.check("suite-check", config) {
        panic!("export suite: check refused the suite's own config: {e:?}");
    }

    // Open, and again under a second name (instances do not share state).
    let port = h
        .open_export("suite-a", config)
        .unwrap_or_else(|e| panic!("export suite: open refused: {e:?}"));

    // C-EXPORT-STREAMS (b)/(d): a non-empty, in-range mask with no reserved stream.
    let mask = port.streams();
    assert!(mask != 0, "export suite: no stream declared");
    assert!(
        mask >> STREAM_COUNT == 0,
        "export suite: stream mask {mask:#x} names an id >= {STREAM_COUNT}"
    );
    for id in RESERVED {
        assert!(
            mask & (1 << id) == 0,
            "export suite: declares reserved stream {id} (no producer)"
        );
    }
    let declared: Vec<u32> = (0..STREAM_COUNT)
        .filter(|id| mask & (1 << id) != 0)
        .collect();

    // C-SPAN-RECORDS: FB_SPAN_RECORDS requires STREAM_TRACES.
    if port.span_records() {
        assert!(
            mask & (1 << STREAM_TRACES) != 0,
            "export suite: span records without the traces stream"
        );
    }

    // C-EXPORT-DELIVERY (c): a stated ceiling is a real level (0 is refused by the kernel).
    let ceiling = port.custody_ceiling();
    if let Some(level) = ceiling {
        assert!(
            (1..=CUSTODY_INDEXED).contains(&level),
            "export suite: custody ceiling {level} is not a level"
        );
    }

    // D_SCOPE: each scope is a distinct, absolute path core can mount, and renders without a fault.
    let mut paths = HashSet::new();
    let mut scopes = Vec::new();
    for scope in port.scopes() {
        assert!(
            scope.path.starts_with('/'),
            "export suite: scope path {:?} is not absolute",
            scope.path
        );
        assert!(
            paths.insert(scope.path.clone()),
            "export suite: scope path {:?} declared twice",
            scope.path
        );
        scopes.push(scope.scope);
    }
    for scope in scopes {
        for snapshot in [
            &[][..],
            &[FamilyIn {
                kind: 0,
                name: "suite_total",
                help: "h",
                samples: &[],
            }][..],
        ] {
            let mut rendered: Option<(String, usize)> = None;
            let got = port.render(scope, snapshot, &mut |ct, body| {
                rendered = Some((ct.to_string(), body.len()));
            });
            match got {
                Ok(()) => {
                    let (ct, _) = rendered.expect("export suite: render answered no body");
                    assert!(!ct.is_empty(), "export suite: render gave no content type");
                }
                Err(PortError::Call(fault)) => {
                    panic!("export suite: render faulted: {fault:?}")
                }
                Err(_) => {}
            }
        }
    }

    // C-EXPORT-DELIVERY (d): deliveries. The first declared record stream (any but STREAM_METRICS: core never
    // pushes a metrics snapshot, and `deliver` is optional when every declared stream is metrics), one line, must
    // be taken; a metrics-only exporter owes no delivery. Every declared stream, an empty batch and a resend (same
    // id, attempt + 1) may be refused or failed by what the suite's `needs` script but must never fault, and an
    // answer must satisfy the invariants.
    let line: &[u8] = br#"{"suite":"line"}"#;
    let one: [&[u8]; 1] = [line];
    let record_stream = declared.iter().copied().find(|&s| s != STREAM_METRICS);
    if let Some(first) = record_stream {
        let got = deliver(&h, &*port, first, 1, 1, &one).unwrap_or_else(|e| {
            panic!("export suite: first delivery on stream {first} failed: {e:?}")
        });
        check_delivered("first delivery", &got, &one, ceiling);
    }
    let first = record_stream.unwrap_or(declared[0]);

    let mut id = 2u64;
    for &stream in &declared {
        for (attempt, lines) in [(1u32, &one[..]), (1, &[][..])] {
            let at = id;
            id += 1;
            match deliver(&h, &*port, stream, at, attempt, lines) {
                Ok(got) => check_delivered(&format!("stream {stream}"), &got, lines, ceiling),
                Err(PortError::Call(fault)) => {
                    panic!("export suite: stream {stream} delivery faulted: {fault:?}")
                }
                Err(_) => {}
            }
        }
        // The resend of a batch under its id: attempt 2 is the same call with one more attempt.
        let at = id;
        id += 1;
        let _ = deliver(&h, &*port, stream, at, 1, &one);
        match deliver(&h, &*port, stream, at, 2, &one) {
            Ok(got) => check_delivered(&format!("stream {stream} resend"), &got, &one, ceiling),
            Err(PortError::Call(fault)) => {
                panic!("export suite: stream {stream} resend faulted: {fault:?}")
            }
            Err(_) => {}
        }
    }

    // Generic: a second instance opens beside the first, and the first still answers after it closes.
    let second = h
        .open_export("suite-b", config)
        .unwrap_or_else(|e| panic!("export suite: second open refused: {e:?}"));
    assert_eq!(
        second.streams(),
        mask,
        "export suite: streams differ per instance"
    );
    drop(second);
    if let Err(PortError::Call(fault)) = deliver(&h, &*port, first, id, 1, &[]) {
        panic!("export suite: faulted after a sibling closed: {fault:?}")
    }

    // Generic: nothing the suite did may leave a core refusal besides the junk config it asked for.
    let refusals = h.refusals();
    assert!(
        refusals.len() == 1,
        "export suite: unexpected refusals: {refusals:?}"
    );
    h.assert_needs_declared("export");
}
