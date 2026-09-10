// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the built-in `request-log-file` exporter — the JSONL append and its rename rotation.
//!
//! THE SHED IS NOT MEASURED HERE ANY MORE. The cap this sink DECLARES
//! ([`MAX_INFLIGHT_FILE_APPENDS`]) is enforced by the composition root, which owns the gate and the
//! permit; its test moved with it (`busbar/src/root/units_export`). What is left here is what the
//! sink itself does with a delivery it has already been given room for.

use super::*;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// One append slot, minted locally. In production the root hands this over from the gate it built
/// for this sink; a test that is not ABOUT capacity just needs a live permit to hold.
fn permit() -> OwnedSemaphorePermit {
    Arc::new(Semaphore::new(1))
        .try_acquire_owned()
        .expect("a fresh semaphore admits one")
}

/// THE AUDIT-INTEGRITY DEFECT: rotation used to reopen the sink's file with `.truncate(true)`,
/// discarding every previously written JSONL line with no rename and no archive. For a
/// security/audit product, a size-triggered rotation silently destroying recorded evidence is the
/// sharpest possible defect — an operator pointing this sink at a compliance mount would lose the
/// history on the very next rotation.
///
/// This test writes a line that pushes the file past a tiny `rotate_mb` threshold, then writes a
/// second line and asserts the FIRST line is still readable — in the renamed `.1` archive, not
/// vanished. Against the old `truncate(true)` rollover this assertion fails (the archive is never
/// created and the first line is gone, replaced by only the second). Against the rename-based
/// rollover it passes: the pre-rotation content survives in `<path>.1` and the fresh current file
/// holds only what was written after rotation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_sink_rotates_by_rename_preserving_prior_lines() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-file-export-rotate-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let path_str = path.to_string_lossy().to_string();
    let archive_str = format!("{path_str}.1");

    // A sink owned by THIS test. `sinks()` builds these from the resolved `export:` block and hands
    // them to the root; driving `append_one` directly is what keeps this test about ROTATION and
    // free of any process-global a sibling test could observe.
    let sink = Arc::new(FileSink {
        path: path_str.clone(),
        // Tiny threshold: the first line alone pushes the file past it.
        rotate_bytes: Some(16),
        lock: Mutex::new(()),
    });

    let first_line = r#"{"correlation_id":"pre-rotation-evidence"}"#.to_string();
    let second_line = r#"{"correlation_id":"post-rotation"}"#.to_string();

    // First append: file doesn't exist yet, so no rotation check can fire; it lands in the fresh
    // current file and pushes its size past the 16-byte threshold.
    append_one(sink.clone(), first_line.clone(), permit());
    wait_for_line(&path, &first_line).await;

    // Second append: the pre-write size check now sees the file over `rotate_bytes`, so this call
    // must rotate BEFORE writing — the current file becomes empty/fresh, the old one becomes `.1`.
    append_one(sink, second_line.clone(), permit());
    wait_for_line(&std::path::PathBuf::from(&archive_str), &first_line).await;
    // The post-rotation append to the fresh current file is also async (spawn_blocking behind the
    // sink Mutex), so wait for it too before the direct reads below — otherwise under load the read
    // can race ahead of the write and see an empty current file.
    wait_for_line(&path, &second_line).await;

    let archived = std::fs::read_to_string(&archive_str).unwrap_or_default();
    assert!(
        archived.contains(&first_line),
        "rotation must PRESERVE the pre-rotation line in the renamed archive `{archive_str}`; \
         got: {archived:?}"
    );

    let current = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        !current.contains(&first_line),
        "the fresh current file must not still hold the pre-rotation line: {current:?}"
    );
    assert!(
        current.contains(&second_line),
        "the fresh current file must hold what was written after rotation: {current:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Poll until `path` exists and contains `needle`, or panic after a bounded wait. Appends happen on
/// `spawn_blocking` behind the sink's `Mutex`, so the write is not synchronous with `append_one`
/// returning.
async fn wait_for_line(path: &std::path::Path, needle: &str) {
    for _ in 0..300 {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if contents.contains(needle) {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {path:?} to contain {needle:?}");
}
