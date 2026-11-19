// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::sections::{data_workers, MAX_WORKER_THREADS};

/// The worker count is what the operating system says this process may use (affinity and the
/// container's CPU quota), read through the one function, never a setting.
#[test]
fn the_data_worker_count_is_the_cores_this_process_may_use() {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    assert_eq!(data_workers(), available.min(MAX_WORKER_THREADS));
    assert!(data_workers() >= 1);
}

/// An old configuration's worker count changes nothing: the count is the same with or without it.
#[test]
fn a_configured_worker_count_changes_nothing() {
    let before = data_workers();
    let carried: super::AdvancedCfg =
        busbar_contract::yaml::from_str("worker_threads: 1\n").expect("an old key loads");
    assert_eq!(carried.removed().collect::<Vec<_>>(), ["worker_threads"]);
    assert_eq!(data_workers(), before);
}
