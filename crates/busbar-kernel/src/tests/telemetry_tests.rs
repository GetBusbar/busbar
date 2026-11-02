// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::test_support::{metric_sum, LaneSpec, TestApp};

fn model_plane_key() -> &'static str {
    crate::test_support::register_neutral_test_plane();
    crate::plane_driver::dispatch::fallback_key()
}

fn shipped_protocols() -> (&'static str, &'static str) {
    let known = crate::ingress::protocols::known_protocols();
    assert!(
        known.len() >= 2,
        "the test binary's protocol registry must ship at least two codecs; got {known:?}"
    );
    (known[0], known[1])
}

fn lane_protocol() -> &'static str {
    shipped_protocols().0
}

#[test]
fn test_bank_multithread_adds_sum_exactly_under_concurrent_scrape() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let slot = counter_slot(
        crate::snapshot::REQUESTS_TOTAL,
        &[
            ("ingress_protocol", "acme"),
            ("pool", "tel-bank-mt-pool"),
            ("outcome", "ok"),
        ],
    );
    assert!(slot.is_valid(), "slot table must not be full in tests");
    let before = metric_sum(
        crate::snapshot::REQUESTS_TOTAL,
        &[("pool", "tel-bank-mt-pool")],
    );

    let writers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    slot.incr();
                }
            })
        })
        .collect();

    for _ in 0..50 {
        let _ = crate::snapshot::render();
    }
    for w in writers {
        w.join().unwrap();
    }

    let after = metric_sum(
        crate::snapshot::REQUESTS_TOTAL,
        &[("pool", "tel-bank-mt-pool")],
    );
    assert_eq!(
        (after - before).round() as u64,
        80_000,
        "8 threads x 10k adds must sum exactly across concurrent flushes"
    );
}

#[test]
fn test_reregistration_same_labels_resolves_same_slot() {
    let labels = [("pool", "tel-rereg-pool"), ("reason", "hard_down")];
    let a = counter_slot(crate::snapshot::FAILOVERS_TOTAL, &labels);
    let b = counter_slot(crate::snapshot::FAILOVERS_TOTAL, &labels);
    assert_eq!(a, b, "identical counter label sets must share a slot");

    let hlabels = [("ingress_protocol", "acme"), ("pool", "tel-rereg-pool")];
    let h1 = histogram_slot(crate::snapshot::REQUEST_DURATION_SECONDS, &hlabels);
    let h2 = histogram_slot(crate::snapshot::REQUEST_DURATION_SECONDS, &hlabels);
    assert_eq!(h1, h2, "identical histogram label sets must share a slot");

    let c = counter_slot(
        crate::snapshot::FAILOVERS_TOTAL,
        &[("pool", "tel-rereg-pool"), ("reason", "attempt_timeout")],
    );
    assert_ne!(a, c);
}

#[test]
fn test_config_reapply_accumulates_across_generations() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let build = || {
        TestApp::new()
            .lane(LaneSpec::new("tel-gen-model", lane_protocol(), "http://m"))
            .pool("tel-gen-pool", &[(0, 1)])
            .build()
    };
    let gen1 = build();
    let gen2 = build();

    let labels = [("pool", "tel-gen-pool"), ("outcome", "ok")];
    let before = metric_sum(crate::snapshot::REQUESTS_TOTAL, &labels);
    request_finished(
        &gen1,
        model_plane_key(),
        lane_protocol(),
        "tel-gen-pool",
        "ok",
        0.001,
    );
    request_finished(
        &gen2,
        model_plane_key(),
        lane_protocol(),
        "tel-gen-pool",
        "ok",
        0.002,
    );
    let after = metric_sum(crate::snapshot::REQUESTS_TOTAL, &labels);
    assert_eq!(
        (after - before).round() as u64,
        2,
        "both generations must land in the same series"
    );
}

#[test]
fn test_request_finished_renders_premigration_names_and_labels() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "tel-parity-model",
            lane_protocol(),
            "http://m",
        ))
        .pool("tel-parity-pool", &[(0, 1)])
        .build();
    let ingress = shipped_protocols().1;
    let ingress_label = format!("ingress_protocol=\"{ingress}\"");

    request_finished(
        &app,
        model_plane_key(),
        ingress,
        "tel-parity-pool",
        "ok",
        0.005,
    );
    let out = crate::snapshot::render();

    let counter_line = out.lines().find(|l| {
        !l.starts_with('#')
            && l.starts_with(crate::snapshot::REQUESTS_TOTAL)
            && l.contains(&ingress_label)
            && l.contains("pool=\"tel-parity-pool\"")
            && l.contains("outcome=\"ok\"")
    });
    assert!(
        counter_line.is_some(),
        "banked requests_total must render with the exact pre-migration labels; got:\n{out}"
    );

    assert!(
        !counter_line.unwrap().contains("plane=\""),
        "busbar_requests_total must NOT carry a `plane` label (v1.5.4 identity); got:\n{out}"
    );

    assert!(
        out.lines().any(|l| {
            !l.starts_with('#')
                && l.starts_with(crate::snapshot::REQUEST_DURATION_SECONDS)
                && l.contains("pool=\"tel-parity-pool\"")
                && l.contains("quantile=")
        }),
        "duration summary quantile lines must render for the banked pool; got:\n{out}"
    );
    let count = metric_sum(
        "busbar_request_duration_seconds_count",
        &[("ingress_protocol", ingress), ("pool", "tel-parity-pool")],
    );
    assert!(
        count >= 1.0,
        "duration _count must reflect the banked sample; got {count}"
    );
}

#[test]
fn test_engine_helpers_emit_premigration_series() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = TestApp::new()
        .lane(LaneSpec::new("tel-eng-model", lane_protocol(), "http://m"))
        .pool("tel-eng-pool", &[(0, 1)])
        .build();
    let pool = [("pool", "tel-eng-pool")];

    let attempts0 = metric_sum(crate::snapshot::UPSTREAM_ATTEMPTS_TOTAL, &pool);
    upstream_attempt(&app, "tel-eng-pool", 0);
    assert_eq!(
        (metric_sum(crate::snapshot::UPSTREAM_ATTEMPTS_TOTAL, &pool) - attempts0).round() as u64,
        1
    );

    let failures0 = metric_sum(
        crate::snapshot::UPSTREAM_FAILURES_TOTAL,
        &[
            ("pool", "tel-eng-pool"),
            ("lane", "tel-eng-model"),
            ("disposition", crate::telemetry::DISPOSITION_TRANSIENT),
        ],
    );
    upstream_failure(
        &app,
        "tel-eng-pool",
        0,
        crate::telemetry::DISPOSITION_TRANSIENT,
    );
    assert_eq!(
        (metric_sum(
            crate::snapshot::UPSTREAM_FAILURES_TOTAL,
            &[
                ("pool", "tel-eng-pool"),
                ("lane", "tel-eng-model"),
                ("disposition", crate::telemetry::DISPOSITION_TRANSIENT),
            ],
        ) - failures0)
            .round() as u64,
        1
    );

    let trips0 = metric_sum(crate::snapshot::BREAKER_TRIPS_TOTAL, &pool);
    breaker_trip(&app, "tel-eng-pool", 0);
    assert_eq!(
        (metric_sum(crate::snapshot::BREAKER_TRIPS_TOTAL, &pool) - trips0).round() as u64,
        1
    );

    let fo_labels = [
        ("pool", "tel-eng-pool"),
        ("reason", busbar_kernel_egress::upstream::ERR_NET_TIMEOUT),
    ];
    let failovers0 = metric_sum(crate::snapshot::FAILOVERS_TOTAL, &fo_labels);
    failover(
        &app,
        "tel-eng-pool",
        busbar_kernel_egress::upstream::ERR_NET_TIMEOUT,
    );
    assert_eq!(
        (metric_sum(crate::snapshot::FAILOVERS_TOTAL, &fo_labels) - failovers0).round() as u64,
        1
    );
}

#[test]
fn test_unregistered_pool_falls_back_to_macro_emission() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = TestApp::new()
        .lane(LaneSpec::new("tel-fb-model", lane_protocol(), "http://m"))
        .pool("tel-fb-pool", &[(0, 1)])
        .build();

    let labels = [("pool", "tel-fb-unregistered-pool"), ("outcome", "ok")];
    let before = metric_sum(crate::snapshot::REQUESTS_TOTAL, &labels);
    request_finished(
        &app,
        model_plane_key(),
        lane_protocol(),
        "tel-fb-unregistered-pool",
        "ok",
        0.001,
    );
    let after = metric_sum(crate::snapshot::REQUESTS_TOTAL, &labels);
    assert_eq!(
        (after - before).round() as u64,
        1,
        "unregistered labels must still be counted via the macro fallback"
    );
}

#[test]
fn test_histogram_bank_drains_all_thread_samples() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let slot = histogram_slot(
        crate::snapshot::REQUEST_DURATION_SECONDS,
        &[("ingress_protocol", "acme"), ("pool", "tel-hist-mt-pool")],
    );
    assert!(slot.is_valid());
    let labels = [("ingress_protocol", "acme"), ("pool", "tel-hist-mt-pool")];
    let before = metric_sum("busbar_request_duration_seconds_count", &labels);

    let writers: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..100 {
                    slot.record(0.003);
                }
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }

    let after = metric_sum("busbar_request_duration_seconds_count", &labels);
    assert_eq!(
        (after - before).round() as u64,
        400,
        "every thread's buffered samples must drain at flush"
    );
}

#[test]
fn test_translation_bank_counts_known_protocol_pair() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (from, to) = shipped_protocols();
    let labels = [("from", from), ("to", to)];
    let before = metric_sum(crate::snapshot::TRANSLATIONS_TOTAL, &labels);
    translation(from, to);
    let after = metric_sum(crate::snapshot::TRANSLATIONS_TOTAL, &labels);
    assert_eq!(
        (after - before).round() as u64,
        1,
        "known protocol pair must count via the bank"
    );

    let fb_labels = [("from", "tel-custom-proto"), ("to", to)];
    let fb_before = metric_sum(crate::snapshot::TRANSLATIONS_TOTAL, &fb_labels);
    translation("tel-custom-proto", to);
    let fb_after = metric_sum(crate::snapshot::TRANSLATIONS_TOTAL, &fb_labels);
    assert_eq!((fb_after - fb_before).round() as u64, 1);
}

/// THE CLASS INVARIANT: an observation costs BOUNDED memory whether or not anyone ever scrapes
/// `/metrics`, and the memory it does cost is RELEASED once the traffic stops.
///
/// Per-request observations must be drained into bounded aggregates even when no metrics scrape arrives. Both the bank's per-thread sample `Vec` and the exporter's `AtomicBucket` of raw `(value, timestamp)` pairs need an independent drain; retaining either raw-sample layer would let memory grow with total requests instead of reaching a plateau. The test exercises that unscripted-scrape case.
///
///
///
///
///
///
///
///
///
///
/// WHAT IT ASSERTS — the benchmark's own shape, not a ceiling. A ceiling assertion ("stayed under
/// N MiB") would pass on a build that plateaus high and never recovers, which is the reported bug.
/// So: measure a quiet BASELINE, drive a sustained burst with the maintenance drain running, then go
/// quiet and drain again, and require that the RECOVERED level lands near the baseline rather than
/// near the peak — the class-level statement of "RSS returns to idle after the load stops".
///
/// Per-THREAD jemalloc counters are used rather than process-wide ones so the measurement is immune
/// to the other tests running concurrently in this binary. That immunity has TWO holes:
///
/// 1. `telemetry::flush_to_recorder` `mem::take`s a thread's sample `Vec` and DROPS it on the
///    DRAINING thread, so a concurrent test's `render()`/`drain_pending()` frees THIS thread's
///    buffers on ITS thread and leaves `allocated - deallocated` here permanently inflated —
///    buffers on its own thread,
///    leaving this thread's `allocated -
///    deallocated` inflated. `drain_serial` keeps the
///    measured window on one drainer.
///    fresh thread per test — so even with drains serialized, an unrelated, already-finished test
///    that happened to allocate on the SAME reused thread before this one started can leave residual
///    `allocated - deallocated` bytes baked into the baseline this test reads. `drain_serial` cannot
///    close this hole: it only serializes telemetry's own drain path, not general allocator activity
///    from unrelated code. A fresh, dedicated
///    `std::thread::spawn` keeps the per-thread counters independent
///    of the reused test-harness threads.
///
/// A proof that only holds on an idle machine, or only on a freshly-started test binary, is no
/// proof, so both holes are closed explicitly. Nothing about WHAT is asserted changes — same
/// baseline, same burst, same tolerance, same failure on the pre-fix build.
///
/// Not on windows-msvc, which uses the system allocator (the jemalloc dep is target-gated; see
/// `main.rs`), so there are no jemalloc counters to read.
#[cfg(not(target_env = "msvc"))]
#[test]
fn test_observations_are_released_after_the_load_stops() {
    std::thread::Builder::new()
        .name("tel-recovery-dedicated".into())
        .spawn(measure_on_a_fresh_thread)
        .expect("spawn the dedicated measurement thread")
        .join()
        .expect("the dedicated measurement thread must not panic");
}

#[cfg(not(target_env = "msvc"))]
fn measure_on_a_fresh_thread() {
    use tikv_jemalloc_ctl::thread as jethread;

    let _drain_serial = crate::telemetry::drain_serial::lock();

    fn retained() -> u64 {
        let a = jethread::allocatedp::read()
            .map(|m| m.get())
            .unwrap_or_default();
        let d = jethread::deallocatedp::read()
            .map(|m| m.get())
            .unwrap_or_default();
        a.saturating_sub(d)
    }

    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let slot = histogram_slot(
        crate::snapshot::REQUEST_DURATION_SECONDS,
        &[
            ("ingress_protocol", "acme"),
            ("pool", "tel-unscraped-recovery-pool"),
        ],
    );
    assert!(slot.is_valid(), "slot table must not be full in tests");

    const BURST: usize = 2_000_000;

    const PER_INTERVAL: usize = 20_000;

    for _ in 0..PER_INTERVAL {
        slot.record(0.001);
    }
    crate::snapshot::drain_pending();

    let idle = retained();

    for i in 0..BURST {
        slot.record(0.001);
        if i % PER_INTERVAL == PER_INTERVAL - 1 {
            crate::snapshot::drain_pending();
        }
    }

    crate::snapshot::drain_pending();
    let recovered = retained().saturating_sub(idle);

    const TOLERANCE: u64 = 8 * 1024 * 1024;
    assert!(
        recovered < TOLERANCE,
        "after {BURST} observations and the traffic stopping, {recovered} bytes were still held \
         ({:.1} B/observation); a stopped load must fall back to the idle baseline, not stay parked \
         at the burst peak (tolerance {TOLERANCE} bytes)",
        recovered as f64 / BURST as f64,
    );
}

#[test]
fn test_retaining_from_truth_table() {
    use crate::snapshot::retaining_from;

    assert!(
        retaining_from(Some(true), || panic!(
            "opted_in must not be called when installed"
        )),
        "installed handle must retain"
    );

    assert!(
        !retaining_from(Some(false), || panic!(
            "opted_in must not be called after a failed install"
        )),
        "failed install must not retain"
    );

    assert!(
        retaining_from(None, || true),
        "opted-in pre-install boot window must retain"
    );
    assert!(
        !retaining_from(None, || false),
        "never configured / opted-out must not retain"
    );
}

#[test]
fn test_off_metrics_never_materializes_the_histogram_chunk() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let slot = histogram_slot(
        crate::snapshot::REQUEST_DURATION_SECONDS,
        &[
            ("ingress_protocol", "acme"),
            ("pool", "tel-off-no-materialize-pool"),
        ],
    );
    assert!(slot.is_valid(), "slot table must not be full in tests");

    let chunk_exists = std::thread::spawn(move || {
        for _ in 0..100_000 {
            slot.record_inner(0.001, false);
        }
        bank_internals::hist_chunk_materialized(slot)
    })
    .join()
    .unwrap();

    assert!(
        !chunk_exists,
        "record_inner(_, false) must never materialize the per-thread histogram chunk — nothing \
         will ever drain it, so allocating it at all would be pure waste"
    );
}

#[cfg(not(target_env = "msvc"))]
#[test]
fn test_off_metrics_retains_effectively_nothing_below_the_drain_threshold() {
    use tikv_jemalloc_ctl::thread as jethread;

    let _drain_serial = crate::telemetry::drain_serial::lock();

    fn retained() -> u64 {
        let a = jethread::allocatedp::read()
            .map(|m| m.get())
            .unwrap_or_default();
        let d = jethread::deallocatedp::read()
            .map(|m| m.get())
            .unwrap_or_default();
        a.saturating_sub(d)
    }

    let slot = histogram_slot(
        crate::snapshot::REQUEST_DURATION_SECONDS,
        &[
            ("ingress_protocol", "acme"),
            ("pool", "tel-off-retention-pool"),
        ],
    );
    assert!(slot.is_valid(), "slot table must not be full in tests");

    let warmup_slot = histogram_slot(
        crate::snapshot::REQUEST_DURATION_SECONDS,
        &[
            ("ingress_protocol", "acme"),
            ("pool", "tel-off-retention-warmup-pool"),
        ],
    );
    warmup_slot.record_inner(0.001, false);
    let idle = retained();

    const SAMPLES: usize = HIST_DRAIN_THRESHOLD - 1;
    for _ in 0..SAMPLES {
        slot.record_inner(0.001, false);
    }

    let after = retained().saturating_sub(idle);
    const TOLERANCE: u64 = 4 * 1024;
    assert!(
        after < TOLERANCE,
        "record_inner(_, false) retained {after} bytes after {SAMPLES} off-metrics samples \
         (tolerance {TOLERANCE} bytes, well under the drain-threshold backstop) — pre-fix, this \
         path buffered ~512 KiB (65,535 samples x 8 bytes) with metrics off and nothing to ever \
         drain it"
    );
}

#[test]
fn an_exited_threads_bank_is_released_and_its_counts_survive() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let slot = counter_slot(
        crate::snapshot::REQUESTS_TOTAL,
        &[
            ("ingress_protocol", "acme"),
            ("pool", "tel-bank-567-pool"),
            ("outcome", "ok"),
        ],
    );
    assert!(slot.is_valid(), "slot table must not be full in tests");
    let before = metric_sum(
        crate::snapshot::REQUESTS_TOTAL,
        &[("pool", "tel-bank-567-pool")],
    );
    let banks: Vec<_> = (0..6)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..100 {
                    slot.incr();
                }
                this_threads_bank()
            })
            .join()
            .expect("the emitting thread exits cleanly")
        })
        .collect();
    let first = metric_sum(
        crate::snapshot::REQUESTS_TOTAL,
        &[("pool", "tel-bank-567-pool")],
    );
    for bank in &banks {
        assert!(
            bank.upgrade().is_none(),
            "a bank whose thread has exited must be released by the flush, not kept"
        );
    }
    let second = metric_sum(
        crate::snapshot::REQUESTS_TOTAL,
        &[("pool", "tel-bank-567-pool")],
    );
    assert_eq!(
        (first - before).round() as u64,
        600,
        "the released banks' adds must all be exposed"
    );
    assert_eq!(
        second, first,
        "a later flush must not regress the total once the banks are gone"
    );
}

#[test]
fn off_metrics_releases_exited_banks_and_preserves_preinstall_counts() {
    const CHILD: &str = "BUSBAR_TEST_OFFLINE_BANK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = concat!(
            module_path!(),
            "::off_metrics_releases_exited_banks_and_preserves_preinstall_counts"
        );
        let (_, test_name) = name.split_once("::").expect("the crate prefix");
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .expect("run this test with a fresh process recorder");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert!(!crate::snapshot::retaining());
    let slot = counter_slot("offline_bank_custody_total", &[]);
    let bank = std::thread::spawn(move || {
        slot.add(17);
        this_threads_bank()
    })
    .join()
    .expect("the offline emitter exits");
    assert!(
        bank.upgrade().is_none(),
        "offline telemetry has no maintenance thread to reap this bank"
    );
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    assert_eq!(metric_sum("offline_bank_custody_total", &[]), 17.0);
    slot.add(3);
    assert_eq!(metric_sum("offline_bank_custody_total", &[]), 20.0);
    assert_eq!(metric_sum("offline_bank_custody_total", &[]), 20.0);
}

#[test]
fn test_finish_outcome_mapping_503_is_exhausted() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    model_plane_key();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "tel-f25-503-model",
            lane_protocol(),
            "http://m",
        ))
        .pool("tel-f25-503-pool", &[(0, 1)])
        .build();
    let ingress = shipped_protocols().1;
    let exhausted = [("pool", "tel-f25-503-pool"), ("outcome", "exhausted")];
    let error = [("pool", "tel-f25-503-pool"), ("outcome", "error")];
    let exhausted0 = metric_sum(crate::snapshot::REQUESTS_TOTAL, &exhausted);
    let error0 = metric_sum(crate::snapshot::REQUESTS_TOTAL, &error);

    model_request_finished(&app, ingress, "tel-f25-503-pool", 503, 0.001);

    assert_eq!(
        (metric_sum(crate::snapshot::REQUESTS_TOTAL, &exhausted) - exhausted0).round() as u64,
        1,
        "503 maps to outcome=exhausted"
    );
    assert_eq!(
        (metric_sum(crate::snapshot::REQUESTS_TOTAL, &error) - error0).round() as u64,
        0,
        "a 503 is never counted as a plain error"
    );
    assert_eq!(outcome_of(503), "exhausted");
    assert_eq!(outcome_of(502), "error");
    assert_eq!(outcome_of(429), "client_error");
    assert_eq!(outcome_of(200), "ok");
}
