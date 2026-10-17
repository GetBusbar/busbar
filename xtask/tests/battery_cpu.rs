//! A SELF-TEST BATTERY'S COST IS THE PROCESS'S CPU TIME (ARCHITECT 2026-10-12; Law 8: an instrument
//! must not report by noise). `xtask::gates::measure_battery` reads `getrusage(RUSAGE_SELF)` plus
//! `getrusage(RUSAGE_CHILDREN)` just before and just after the battery, over the ruler's CPU time
//! per pass. Four properties, each with its RED arm in the same assertion:
//!
//! 1. CPU spent on threads OTHER than the caller's is counted (a scan pool, a scoped thread) — a
//!    per-thread reading would have read nothing here;
//! 2. CPU spent by a reaped CHILD process is counted (every `git`);
//! 3. WAITING is not counted, which is the whole point: a busy box makes a battery wait;
//! 4. two windows open at once in one process REFUSE each other rather than guess.
//!
//! ONE TEST IN THIS FILE, ON PURPOSE. A window refuses to share its process with another, and
//! `cargo test` runs one file's tests on threads of one process; this file is its own binary.

#[cfg(target_os = "linux")]
#[test]
fn a_battery_costs_every_thread_and_reaped_child_never_its_waiting_and_never_an_overlap() {
    use std::time::Duration;
    use xtask::gates::{cpu, measure_battery, BatteryReading};

    /// Spend `want` of THIS thread's CPU time, whatever the wall clock does meanwhile.
    fn burn(want: Duration) {
        let start = cpu::thread().expect("Linux reads a thread's CPU time");
        let mut acc = 0u64;
        while cpu::thread().expect("Linux reads a thread's CPU time") - start < want {
            for i in 0..10_000u64 {
                acc = std::hint::black_box(acc.wrapping_mul(31).wrapping_add(i));
            }
        }
    }

    fn measured(reading: BatteryReading) -> Duration {
        match reading {
            BatteryReading::Measured { cpu, unit } => {
                assert!(unit > Duration::ZERO, "the ruler read a positive unit");
                cpu
            }
            other => panic!("alone in its process, the battery is measured: {other:?}"),
        }
    }

    // 1. FOUR HELPER THREADS each spend 100 ms of their own CPU; the caller spends none of it.
    let ((), threads) = measure_battery(|| {
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| burn(Duration::from_millis(100)));
            }
        })
    });
    let threads = measured(threads);
    assert!(
        threads >= Duration::from_millis(400),
        "every helper thread's CPU is the battery's: read {threads:?}, spent at least 400ms"
    );

    // 2. A CHILD that reports its own user+sys (bash's `time` over a busy loop, read by bash with
    //    getrusage itself), reaped inside the window.
    let (child, reaped) = measure_battery(|| {
        std::process::Command::new("bash")
            .args([
                "-c",
                "TIMEFORMAT='%3U %3S'; time { i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done; }",
            ])
            .output()
            .expect("bash runs")
    });
    let reaped = measured(reaped);
    let said = String::from_utf8_lossy(&child.stderr);
    let child_cpu: f64 = said
        .split_whitespace()
        .filter_map(|f| f.parse::<f64>().ok())
        .sum();
    assert!(
        child_cpu > 0.05,
        "the child spent measurable CPU: bash said {said:?}"
    );
    assert!(
        reaped.as_secs_f64() + 0.02 >= child_cpu,
        "the reaped child's CPU is the battery's: read {reaped:?}, the child said {child_cpu}s"
    );

    // 3. WAITING IS NOT COST: 300 ms asleep spends next to no CPU.
    let ((), waited) = measure_battery(|| std::thread::sleep(Duration::from_millis(300)));
    let waited = measured(waited);
    assert!(
        waited < Duration::from_millis(100),
        "a battery that only waited spent {waited:?} of CPU"
    );

    // 4. AN OVERLAP IS REFUSED, BOTH WAYS: the inner window opened while the outer was open, and
    //    the outer saw it happen.
    let ((), outer) = measure_battery(|| {
        let ((), inner) = measure_battery(|| burn(Duration::from_millis(10)));
        assert!(
            matches!(inner, BatteryReading::Refused(_)),
            "a window opened inside another is refused: {inner:?}"
        );
    });
    assert!(
        matches!(outer, BatteryReading::Refused(_)),
        "a window another opened inside is refused: {outer:?}"
    );

    // And once both are closed, a lone window measures again.
    let ((), after) = measure_battery(|| burn(Duration::from_millis(10)));
    assert!(measured(after) >= Duration::from_millis(10));
}

/// Where CPU time cannot be read, the reading says so and is never a stand-in figure.
#[cfg(not(target_os = "linux"))]
#[test]
fn off_linux_the_battery_is_unread_never_guessed() {
    let ((), reading) = xtask::gates::measure_battery(|| ());
    assert!(
        matches!(reading, xtask::gates::BatteryReading::Unread(_)),
        "{reading:?}"
    );
}
