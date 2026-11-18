// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EXTRACT-IF-SWEEPS r4 S2 and S1: the scrape reaps only the banks whose threads exited (it does
//! not scan every live bank), and the metering tick takes whole shards.

use super::*;

fn key_of(bank: &std::sync::Weak<dyn std::any::Any + Send + Sync>) -> usize {
    bank.as_ptr() as *const () as usize
}

#[test]
fn an_exiting_thread_queues_its_bank_and_the_next_flush_folds_it_once() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let slot = counter_slot(
        crate::snapshot::REQUESTS_TOTAL,
        &[
            ("ingress_protocol", "acme"),
            ("pool", "tel-exited-queue-pool"),
            ("outcome", "ok"),
        ],
    );
    assert!(slot.is_valid(), "slot table must not be full in tests");
    // Held across the exit and the flush: no other test's scrape can reap the bank first.
    let _serial = drain_serial::lock();
    let bank = std::thread::spawn(move || {
        for _ in 0..40 {
            slot.incr();
        }
        this_threads_bank()
    })
    .join()
    .expect("the emitting thread exits cleanly");
    let key = key_of(&bank);

    let queued = registry()
        .exited
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter(|b| Arc::as_ptr(b) as *const () as usize == key)
        .count();
    assert_eq!(queued, 1, "the exit queues its bank once, for the flush");
    assert!(bank.upgrade().is_some(), "the bank is kept until a flush");

    flush_to_recorder();
    assert!(bank.upgrade().is_none(), "the flush releases the bank");
    let registered = registry()
        .threads
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(&key);
    assert!(!registered, "the flush removes the bank's registry key");
    assert!(registry()
        .exited
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .all(|b| Arc::as_ptr(b) as *const () as usize != key));
    let first = pool_sum("tel-exited-queue-pool");
    assert!(first >= 40.0, "the exited bank's adds are exposed");
    flush_to_recorder();
    assert_eq!(
        pool_sum("tel-exited-queue-pool"),
        first,
        "a second flush does not fold the bank again"
    );
}

fn pool_sum(pool: &str) -> f64 {
    crate::snapshot::snapshot()
        .expect("the recorder is installed")
        .iter()
        .flat_map(|family| &family.samples)
        .filter(|s| {
            s.name == crate::snapshot::REQUESTS_TOTAL
                && s.labels.iter().any(|(k, v)| k == "pool" && v == pool)
        })
        .map(|s| s.value.parse::<f64>().expect("a numeric sample"))
        .sum()
}

#[test]
fn the_metering_tick_takes_every_unretained_cell_and_keeps_the_retained_ones() {
    let shards: Vec<_> = (0..4)
        .map(|s| {
            let mut m: foldhash::HashMap<u32, u32> = foldhash::HashMap::default();
            for k in (0..32).filter(|k| k % 4 == s) {
                m.insert(k, k * 10);
            }
            std::sync::Mutex::new(m)
        })
        .collect();
    let retained: foldhash::HashSet<u32> = [1, 6, 11, 99].into_iter().collect();
    let mut flight = std::collections::VecDeque::new();
    crate::off_path::governance::state::metering_flush_take_unretained(
        &shards,
        &retained,
        &mut flight,
        |(k, v)| (v != 0).then_some((k, v)),
    );
    let mut taken: Vec<_> = flight.into_iter().map(|(k, _)| k).collect();
    taken.sort();
    let expected: Vec<u32> = (1..32).filter(|k| ![1, 6, 11].contains(k)).collect();
    assert_eq!(taken, expected, "key 0 has a zero count and is dropped");
    let mut left: Vec<u32> = shards
        .iter()
        .flat_map(|s| s.lock().unwrap().keys().copied().collect::<Vec<_>>())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec![1, 6, 11],
        "retained keys stay and keep coalescing"
    );
}
