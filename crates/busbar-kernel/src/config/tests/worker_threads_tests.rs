// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::sections::{effective_worker_threads, MAX_WORKER_THREADS};

#[test]
fn an_absent_or_in_range_worker_count_is_kept_without_a_log_line() {
    assert_eq!(effective_worker_threads(None), (None, None));
    assert_eq!(effective_worker_threads(Some(1)), (Some(1), None));
    assert_eq!(effective_worker_threads(Some(64)), (Some(64), None));
    assert_eq!(
        effective_worker_threads(Some(MAX_WORKER_THREADS)),
        (Some(MAX_WORKER_THREADS), None)
    );
}

#[test]
fn zero_is_converted_to_the_default_with_one_log_line() {
    let (workers, note) = effective_worker_threads(Some(0));
    assert_eq!(workers, None, "0 means the default count: one per core");
    let note = note.expect("a converted value says so");
    assert!(note.contains("advanced.worker_threads"), "{note}");
    assert!(note.contains("one per core"), "{note}");
    assert!(!note.contains('\n'), "one line: {note}");
}

#[test]
fn a_count_above_the_ceiling_is_converted_to_it_with_one_log_line() {
    for over in [MAX_WORKER_THREADS + 1, usize::MAX] {
        let (workers, note) = effective_worker_threads(Some(over));
        assert_eq!(workers, Some(MAX_WORKER_THREADS), "{over}");
        let note = note.expect("a converted value says so");
        assert!(note.contains("advanced.worker_threads"), "{note}");
        assert!(note.contains(&over.to_string()), "{note}");
        assert!(note.contains(&MAX_WORKER_THREADS.to_string()), "{note}");
        assert!(!note.contains('\n'), "one line: {note}");
    }
}
