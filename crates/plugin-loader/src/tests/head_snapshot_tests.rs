// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn lifecycle_head_is_owned_before_its_ffi_worker_returns_and_restored_after_consumption() {
    let row = crate::dispatch::LinkedRow::of_raw(crate::dispatch_test_plugin::busbar_plugin_door)
        .unwrap();
    let plugin = crate::dispatch::load_linked::<crate::dispatch_tests::TestKind>(
        &row,
        Bind {
            instance: Arc::from("head-snapshot"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: crate::dispatch::Adopter::unwatched(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let mut out = crate::dispatch::out_head();
    let (snapshot, source) = crate::ffi_thread::on_plugin_thread(|| {
        let error = b"original error".to_vec();
        let label = b"original label".to_vec();
        let diagnostic = b"original log".to_vec();
        let labels = vec![AbiStr::over(&label)];
        let metrics = vec![MetricEntry {
            family_idx: 0,
            kind: METRIC_ADD,
            _reserved: [0; 3],
            value: 1.0,
            label_vals: labels.as_ptr(),
            label_vals_len: labels.len(),
        }];
        let diags = vec![Diag {
            id_idx: DIAG_LOG,
            severity: SEVERITY_ERROR,
            text: AbiStr::over(&diagnostic),
            ..Diag::ZERO
        }];
        out.outcome = RawOutcome::of(Outcome::Ready);
        out.error = AbiStr::over(&error);
        // SAFETY: the only named range is the live error owner above. READY does not consume
        // error text on this lifecycle path, so the snapshot must preserve that read order.
        let ready = unsafe {
            HeadSnapshot::capture(
                &plugin.inner,
                out.outcome,
                &mut out,
                size_of::<OutHead>() as u32,
                Ticket::NONE,
            )
        }
        .unwrap();
        assert_eq!(out.error.ptr, error.as_ptr());
        assert!(ready.bytes.is_empty());
        drop(ready);
        out.outcome = RawOutcome::of(Outcome::Failed);
        out.envelope.metrics = metrics.as_ptr();
        out.envelope.metrics_len = metrics.len();
        out.envelope.diags = diags.as_ptr();
        out.envelope.diags_len = diags.len();
        // SAFETY: every declared initialized source range is still owned here. This is the
        // same worker-local copy that cross_gated performs before its FFI lease is returned.
        let snapshot = unsafe {
            HeadSnapshot::capture(
                &plugin.inner,
                out.outcome,
                &mut out,
                size_of::<OutHead>() as u32,
                Ticket::NONE,
            )
        }
        .unwrap();
        (snapshot, (error, label, diagnostic, labels, metrics, diags))
    })
    .unwrap();
    let original_pointer = snapshot.original.error.ptr;
    // Free the old source owners. Every assertion below reads only snapshot-owned storage,
    // never an old raw pointer, so a failed retention witness does not itself invoke UB.
    drop(source);
    for expected in [
        b"original error".as_slice(),
        b"original label".as_slice(),
        b"original log".as_slice(),
    ] {
        assert!(snapshot
            .bytes
            .iter()
            .any(|bytes| bytes.as_ref() == expected));
    }
    assert_ne!(
        out.error.ptr, original_pointer,
        "the host consumes a distinct owned copy"
    );
    assert_eq!(out.envelope.metrics, snapshot.metrics.as_ptr());
    assert_eq!(out.envelope.diags, snapshot.diags.as_ptr());
    drop(snapshot);
    assert_eq!(
        out.error.ptr, original_pointer,
        "no short-lived host pointer escapes in the caller frame"
    );
}
