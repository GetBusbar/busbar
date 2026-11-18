// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn labels(pool: &str) -> [(&str, &str); 5] {
    [
        ("plane", "synthetic"),
        ("phase", "MountedResponseReady"),
        ("pool", pool),
        ("ingress_protocol", "test-wire"),
        ("outcome", "ok"),
    ]
}

pub(crate) fn missing_nonce_capacity_and_invalid_samples() {
    let unavailable = RequestStore::with_nonce(false, None);
    unavailable.register(labels("missing-nonce")).record(1.0);
    let state = lock(&unavailable.core.state);
    assert!(!state.cells[0].observed);
    assert_eq!(state.dropped[3], 1);
    drop(state);
    assert!(unavailable.snapshot(32).is_none());
    drop(unavailable);

    let store = RequestStore::new(false);
    store.register(labels("0")).record(f64::NAN);
    assert_eq!(lock(&store.core.state).dropped[0], 1);
    for index in 1..CAPACITY {
        store.register(labels(&index.to_string())).record(0.0);
    }
    let overflow = store.register(labels("over-capacity"));
    overflow.record(0.0);
    let state = lock(&store.core.state);
    assert_eq!(state.index.len(), CAPACITY);
    assert_eq!(state.dropped[2], 1);
    assert_eq!(
        state.cells.iter().filter(|cell| cell.observed).count(),
        CAPACITY
    );
    drop(state);
    let snapshot = store.snapshot(32).unwrap();
    assert_eq!(snapshot.omitted_identities, (CAPACITY - 32) as u64);
    assert_eq!(snapshot.dropped[0], 1);
    assert_eq!(snapshot.dropped[2], 1);
}

#[test]
fn permutations_reuse_cells_and_refused_keys_reuse_targets() {
    let store = RequestStore::new(false);
    let original = labels("permuted");
    let mut reversed = original;
    reversed.reverse();
    let first = store.register(original);
    store.register(reversed).record(0.005);
    first.record(0.001);
    let before_refs = Arc::strong_count(&store.refusals[5]);
    for i in 0..1000 {
        store
            .register([("pool", i.to_string().as_str())])
            .record(0.0);
    }
    assert_eq!(Arc::strong_count(&store.refusals[5]), before_refs);
    assert_eq!(lock(&store.core.state).index.len(), 1);
    let snapshot = store.snapshot(32).unwrap();
    assert_eq!(snapshot.identities.len(), 1);
    assert_eq!(snapshot.identities[0].count, 2);
    assert_eq!(snapshot.identities[0].sum_us, 6000);
    assert_eq!(snapshot.dropped[5], 1000);
    assert_eq!(snapshot.omitted_identities, 0);
}

#[test]
fn retained_output_does_not_alias_the_reused_workspace() {
    let store = RequestStore::new(false);
    let target = store.register(labels("retained"));
    target.record(0.001);
    let first = store.snapshot(32).unwrap();
    target.record(0.005);
    let second = store.snapshot(32).unwrap();
    assert_eq!(first.identities[0].count, 1);
    assert_eq!(first.identities[0].sum_us, 1000);
    assert_eq!(second.identities[0].count, 2);
    assert_eq!(second.identities[0].sum_us, 6000);
}

#[test]
fn capture_contention_refuses_once_without_losing_observations() {
    let store = RequestStore::new(false);
    let target = store.register(labels("contended"));
    target.record(0.001);
    let workspace = lock(&store.core.workspace);
    assert!(store.snapshot(32).is_none());
    assert_eq!(store.core.busy[0].load(Ordering::Relaxed), 1);
    assert_eq!(store.core.busy[1].load(Ordering::Relaxed), 0);
    drop(workspace);
    let state = lock(&store.core.state);
    assert!(store.snapshot(32).is_none());
    assert_eq!(store.core.busy[1].load(Ordering::Relaxed), 1);
    assert_eq!(state.dropped, [0; 6]);
    drop(state);
    assert_eq!(store.snapshot(32).unwrap().identities[0].count, 1);
    let mut output = Building::new();
    store.put(&mut output).unwrap();
    let failures = output
        .iter()
        .find(|((_, name), _)| name.0 == "busbar_telemetry_request_capture_refusals_total")
        .unwrap()
        .1;
    let counts: Vec<_> = failures
        .values()
        .flat_map(|series| &series.samples)
        .map(|sample| sample.value.parse::<u64>().unwrap())
        .collect();
    assert_eq!(counts.iter().sum::<u64>(), 2);
}

#[test]
fn inactive_handles_preserve_cells_and_every_loss_counter() {
    let store = RequestStore::new(false);
    let valid = store.register(labels("inactive"));
    let invalid = store.register([("arbitrary", "invalid")]);
    store.core.active.store(false, Ordering::Relaxed);
    valid.record(f64::NAN);
    invalid.record(0.0);
    for reason in 0..6 {
        store.core.refused(reason);
    }
    let snapshot = store.snapshot(32).unwrap();
    assert!(snapshot.identities.is_empty());
    assert_eq!(snapshot.omitted_identities, 0);
    assert_eq!(snapshot.dropped, [0; 6]);
    store.core.active.store(true, Ordering::Relaxed);
    valid.record(0.001);
    assert_eq!(store.snapshot(32).unwrap().identities[0].count, 1);
}

#[test]
fn invalid_outcomes_mark_only_the_admitted_cohort_and_loss_saturates() {
    let store = RequestStore::new(false);
    let mut invalid = labels("invalid-outcome");
    invalid[4].1 = "not-an-outcome";
    let target = store.register(invalid);
    target.record(1.0);
    let snapshot = store.snapshot(32).unwrap();
    assert_eq!(snapshot.identities.len(), 1);
    assert_eq!(snapshot.identities[0].count, 0);
    assert_eq!(snapshot.dropped[0], 1);
    lock(&store.core.state).dropped[0] = u64::MAX;
    target.record(1.0);
    assert_eq!(store.snapshot(32).unwrap().dropped[0], u64::MAX);
}

#[test]
fn supported_layout_and_fixed_target_count_fit_the_adopted_compartments() {
    let store = RequestStore::new(false);
    assert_eq!(store.targets.len() * 5, CAPACITY * 5);
    assert_eq!(store.core.labels.len(), CAPACITY);
    assert!(store.reserved_bytes <= 32 * MIB);
    // Header is two usize reference counts in pinned std ArcInner; alignment is charged too.
    let payload = std::alloc::Layout::new::<PhaseTarget>();
    let header = std::alloc::Layout::new::<[usize; 2]>();
    let (allocation, _) = header.extend(payload).unwrap();
    assert!(allocation.pad_to_align().size() <= TARGET_CHARGE);
    #[cfg(not(target_env = "msvc"))]
    {
        let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
        let before = allocated.get();
        let target = Arc::new(PhaseTarget {
            core: Arc::clone(&store.core),
            cell: 0,
            outcome: 0,
        });
        assert!(allocated.get() - before <= TARGET_CHARGE as u64);
        drop(target);
        let rejected = [("unregistered", "not-retained")];
        let before = allocated.get();
        for _ in 0..1000 {
            drop(store.register(rejected));
        }
        assert_eq!(allocated.get(), before);
    }
}

#[test]
fn capture_unwind_releases_the_only_workspace() {
    let store = RequestStore::new(false);
    store.register(labels("unwind")).record(0.001);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.capture(|_, _, _, _, _| panic!("cancel output construction"));
    }));
    assert!(outcome.is_err());
    assert_eq!(store.snapshot(32).unwrap().identities[0].count, 1);
}

#[test]
fn failed_reservation_terminates_without_publishing_an_arena() {
    const CHILD: &str = "BUSBAR_TEST_PHASE_FATAL_RESERVATION";
    if std::env::var_os(CHILD).is_some() {
        // Deterministic reserve failure proves the fatal branch, not physical-OOM injection.
        let _impossible = reserved::<u8>(usize::MAX);
        return;
    }
    let full = concat!(
        module_path!(),
        "::failed_reservation_terminates_without_publishing_an_arena"
    );
    let (_, name) = full.split_once("::").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(output.status.signal(), Some(6)); // SIGABRT, not a caught Rust test panic.
    }
}
