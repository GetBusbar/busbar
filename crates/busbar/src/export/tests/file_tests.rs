// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the built-in `request-log-file` exporter — the bounded JSONL append fan-out.

use super::*;
use crate::export::test_logs_projection;

/// AUDIT MED-4 — THE FILE SINK IS ADMISSION-BOUNDED. `deliver()` spawns one `spawn_blocking` append
/// per request per sink, each holding an owned `String`; on a slow or stalled filesystem those
/// accumulated with no cap, unlike every sibling fan-out in this delta. Each sink now takes a slot
/// from its OWN [`AdmissionGate`] and SHEDS (counted) when saturated.
///
/// The stall is simulated the way the code itself serializes appends: the test HOLDS the sink's
/// append `Mutex`, so every admitted blocking task parks on it exactly as it would on a hung mount.
/// With the cap, at most [`MAX_INFLIGHT_FILE_APPENDS`] of the offered lines can ever reach the file.
///
/// This drives a LOCALLY-BUILT sink through `append_one` rather than `configure()` + `deliver()`:
/// `SINKS` is a `OnceLock`, so configuring it here would set a file sink for the WHOLE test binary,
/// and every sibling SYNC test whose request-finish path then reached `deliver()` would panic in
/// `spawn_blocking` with "there is no reactor running". A test must not change global state its
/// neighbours can observe — that is the shared-process-global fixture trap, and it bit exactly this
/// way before this rewrite (5 `ingress::tests::*` failures).
///
/// RED-BEFORE-GREEN: without the gate, every offered line is spawned and — once the mutex is
/// released — written, so the count below is the full offered count instead of the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_sink_sheds_appends_beyond_its_inflight_cap() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-file-export-shed-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("req.jsonl");

    // A sink owned by THIS test. Leaked to obtain the `&'static` that `append_one` takes, without
    // touching the process-global `SINKS`.
    let sink: &'static FileSink = Box::leak(Box::new(FileSink {
        path: path.to_string_lossy().to_string(),
        rotate_bytes: None,
        lock: Mutex::new(()),
        gate: AdmissionGate::new(MAX_INFLIGHT_FILE_APPENDS, "request-log-file-test"),
        projection: test_logs_projection(),
    }));

    // Offered load: comfortably more than the cap, so an UNBOUNDED fan-out is visibly different.
    const OFFERED: usize = MAX_INFLIGHT_FILE_APPENDS * 3;

    // Hold the append mutex on a BLOCKING THREAD: a std `MutexGuard` held across an await is
    // `clippy::await_holding_lock` (denied here) and a hazard to copy into non-test code. The
    // channels make the hand-off deterministic — no load is offered until the lock is provably held.
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let stall = std::thread::spawn(move || {
        let _stall = sink.lock.lock().unwrap();
        held_tx.send(()).expect("test receiver alive");
        let _ = release_rx.recv();
    });
    held_rx
        .recv()
        .expect("the stall thread took the append mutex");

    for i in 0..OFFERED {
        append_one(sink, format!("{{\"correlation_id\":{i}}}"));
    }
    // Let every admitted task reach the blocking pool (and park on the mutex the stall thread holds).
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    release_tx.send(()).expect("stall thread alive");
    stall
        .join()
        .expect("stall thread released the append mutex");

    // Drain: the admitted tasks now take the mutex in turn and write their line.
    let mut lines = 0;
    for _ in 0..200 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        lines = std::fs::read_to_string(&path)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        if lines >= MAX_INFLIGHT_FILE_APPENDS {
            break;
        }
    }
    assert!(
        lines <= MAX_INFLIGHT_FILE_APPENDS,
        "the file sink must SHED beyond its in-flight cap ({MAX_INFLIGHT_FILE_APPENDS}); \
         {lines} of {OFFERED} offered lines were written, so the fan-out is still unbounded"
    );
    assert!(
        lines > 0,
        "the cap must admit up to its budget, not close the sink: {lines} lines"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
