// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn failed_candidates_do_not_recycle_reserved_instance_ids() {
    let ids = Arc::new(InstanceIds::default());
    let first_registry = Arc::clone(&ids);
    assert_eq!(first_registry.next().unwrap(), 1);
    drop(first_registry);
    let next_registry = Arc::clone(&ids);
    assert_eq!(next_registry.next().unwrap(), 2);
    assert_eq!(ids.next().unwrap(), 3);
}

#[test]
fn exhausted_instance_ids_never_wrap_to_zero_or_reuse_an_id() {
    let ids = InstanceIds {
        next: AtomicU64::new(u64::MAX - 1),
    };
    assert_eq!(ids.next().unwrap(), u64::MAX);
    assert!(ids.next().is_err());
    assert!(ids.next().is_err());
}

#[test]
fn concurrent_candidates_reserve_distinct_ids() {
    let ids = Arc::new(InstanceIds::default());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let ids = Arc::clone(&ids);
            std::thread::spawn(move || (0..128).map(|_| ids.next().unwrap()).collect::<Vec<_>>())
        })
        .collect();
    let mut reserved: Vec<_> = threads
        .into_iter()
        .flat_map(|thread| thread.join().unwrap())
        .collect();
    reserved.sort();
    assert_eq!(reserved, (1..=1024).collect::<Vec<_>>());
}
