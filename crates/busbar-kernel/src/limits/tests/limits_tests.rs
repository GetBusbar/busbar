// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{DEFAULT_PROBE_INTERVAL_SECS, DEFAULT_PROBE_TIMEOUT_SECS};

fn default_probe_interval_secs() -> u64 {
    get().map_or(DEFAULT_PROBE_INTERVAL_SECS, |l| {
        l.default_probe_interval_secs
    })
}

fn default_probe_timeout_secs() -> u64 {
    get().map_or(DEFAULT_PROBE_TIMEOUT_SECS, |l| l.default_probe_timeout_secs)
}

fn distinctive(
    key_gauge_limit: usize,
    body_max: usize,
    probe_interval_secs: u64,
) -> LimitsResolved {
    LimitsResolved {
        key_gauge_limit,
        request_body_max_bytes: body_max,
        default_probe_interval_secs: probe_interval_secs,
        ..LimitsResolved::default()
    }
}

#[test]
fn uninstalled_accessors_return_historical_defaults() {
    const CASE: &str = "limits::tests::uninstalled_accessors_return_historical_defaults";
    if std::env::var("BUSBAR_LIMITS_CASE_CHILD").ok().as_deref() != Some(CASE) {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", CASE, "--nocapture"])
            .env("BUSBAR_LIMITS_CASE_CHILD", CASE)
            .output()
            .expect("run this limits case in its own process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "the isolated process must actually run the exact limits case"
        );
        return;
    }
    assert_eq!(
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        DEFAULT_REQUEST_BODY_MAX_BYTES
    );
    assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(rate_sweep_interval(), DEFAULT_RATE_SWEEP_INTERVAL);
    assert_eq!(default_probe_interval_secs(), DEFAULT_PROBE_INTERVAL_SECS);
    assert_eq!(default_probe_timeout_secs(), DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(default_policy_timeout_ms(), DEFAULT_POLICY_TIMEOUT_MS);

    assert_eq!(
        request_body_read_timeout_secs(),
        crate::config::DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS
    );
}

#[test]
fn committed_guard_keeps_its_limits_live_after_the_guard_is_gone() {
    const CASE: &str =
        "limits::tests::committed_guard_keeps_its_limits_live_after_the_guard_is_gone";
    if std::env::var("BUSBAR_LIMITS_CASE_CHILD").ok().as_deref() != Some(CASE) {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", CASE, "--nocapture"])
            .env("BUSBAR_LIMITS_CASE_CHILD", CASE)
            .output()
            .expect("run this limits case in its own process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "the isolated process must actually run the exact limits case"
        );
        return;
    }

    let candidate = distinctive(4_242, 7 * 1024 * 1024, 37);
    busbar_kernel::config::limits::publish(&candidate);
    assert_eq!(
        key_gauge_limit(),
        4_242,
        "the guard installs its posture immediately"
    );

    // Publishing is the production commit boundary; leaving this scope cannot undo it.

    assert_eq!(
        key_gauge_limit(),
        4_242,
        "a COMMITTED guard must not roll back when it drops"
    );
    assert_eq!(
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        7 * 1024 * 1024
    );
    assert_eq!(default_probe_interval_secs(), 37);
}

#[test]
fn uncommitted_guard_restores_the_previous_limits_exactly_not_the_defaults() {
    const CASE: &str =
        "limits::tests::uncommitted_guard_restores_the_previous_limits_exactly_not_the_defaults";
    if std::env::var("BUSBAR_LIMITS_CASE_CHILD").ok().as_deref() != Some(CASE) {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", CASE, "--nocapture"])
            .env("BUSBAR_LIMITS_CASE_CHILD", CASE)
            .output()
            .expect("run this limits case in its own process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "the isolated process must actually run the exact limits case"
        );
        return;
    }

    let previous = distinctive(1_111, 5 * 1024 * 1024, 17);
    busbar_kernel::config::limits::publish(&previous);

    {
        busbar_kernel::config::limits::publish(&distinctive(2_222, 1024, 3));
        assert_eq!(key_gauge_limit(), 2_222);
        assert_eq!(
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
            1024
        );
    }

    busbar_kernel::config::limits::publish(&previous);
    assert_eq!(
        key_gauge_limit(),
        1_111,
        "rollback must restore the PREVIOUS value, not a default and not the candidate's"
    );
    assert_ne!(
        key_gauge_limit(),
        DEFAULT_KEY_GAUGE_LIMIT,
        "guards the assertion above: if this ever equals the default, the test can no longer tell \
         a real restore from a reset-to-defaults"
    );
    assert_eq!(
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        5 * 1024 * 1024
    );
    assert_eq!(default_probe_interval_secs(), 17);
}

#[test]
fn uncommitted_guard_restores_the_uninstalled_state_when_nothing_was_installed() {
    const CASE: &str = "limits::tests::uncommitted_guard_restores_the_uninstalled_state_when_nothing_was_installed";
    if std::env::var("BUSBAR_LIMITS_CASE_CHILD").ok().as_deref() != Some(CASE) {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", CASE, "--nocapture"])
            .env("BUSBAR_LIMITS_CASE_CHILD", CASE)
            .output()
            .expect("run this limits case in its own process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "the isolated process must actually run the exact limits case"
        );
        return;
    }

    assert!(
        get().is_none(),
        "the exact child starts without published limits"
    );
    {
        let _temporary =
            busbar_kernel::config::limits::BuildScope::enter(&distinctive(3_333, 2048, 51));
        assert_eq!(key_gauge_limit(), 3_333);
    }

    assert!(
        get().is_none(),
        "rollback from the uninstalled state must clear the slot, not leave the temporary posture \
         behind"
    );
    assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        DEFAULT_REQUEST_BODY_MAX_BYTES
    );
    assert_eq!(default_probe_interval_secs(), DEFAULT_PROBE_INTERVAL_SECS);
}

#[test]
fn rollback_is_visible_on_the_live_read_path_from_another_thread() {
    const CASE: &str =
        "limits::tests::rollback_is_visible_on_the_live_read_path_from_another_thread";
    if std::env::var("BUSBAR_LIMITS_CASE_CHILD").ok().as_deref() != Some(CASE) {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", CASE, "--nocapture"])
            .env("BUSBAR_LIMITS_CASE_CHILD", CASE)
            .output()
            .expect("run this limits case in its own process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "the isolated process must actually run the exact limits case"
        );
        return;
    }

    let previous = distinctive(1_234, 9 * 1024 * 1024, 23);
    busbar_kernel::config::limits::publish(&previous);

    busbar_kernel::config::limits::publish(&distinctive(5_678, 1024, 2));
    let during = std::thread::spawn(|| {
        (
            key_gauge_limit(),
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
        )
    })
    .join()
    .expect("reader thread must not panic");
    assert_eq!(
        during,
        (5_678, 1024),
        "the read path this test uses observes a process-wide install"
    );

    busbar_kernel::config::limits::publish(&previous);

    let after = std::thread::spawn(|| {
        (
            key_gauge_limit(),
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
            default_probe_interval_secs(),
        )
    })
    .join()
    .expect("reader thread must not panic");
    assert_eq!(
        after,
        (1_234, 9 * 1024 * 1024, 23),
        "a reader on another thread after the guard drops must see the previous limits: the \
         rollback has to land on the process-global slot, not just on the guard"
    );
}

#[test]
fn a_build_scope_is_seen_by_its_own_thread_only() {
    const CASE: &str = "limits::tests::a_build_scope_is_seen_by_its_own_thread_only";
    if std::env::var("BUSBAR_LIMITS_CASE_CHILD").ok().as_deref() != Some(CASE) {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", CASE, "--nocapture"])
            .env("BUSBAR_LIMITS_CASE_CHILD", CASE)
            .output()
            .expect("run this limits case in its own process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "the isolated process must actually run the exact limits case"
        );
        return;
    }
    busbar_kernel::config::limits::publish(&distinctive(1_111, 9 * 1024 * 1024, 23));

    {
        let _scope = busbar_kernel::config::limits::BuildScope::enter(&distinctive(2_222, 1024, 3));
        assert_eq!(
            key_gauge_limit(),
            2_222,
            "the build reads its own candidate"
        );
        assert_eq!(default_probe_interval_secs(), 3);
        let live = std::thread::spawn(|| {
            (
                key_gauge_limit(),
                busbar_kernel_egress::upstream::max_translate_body_bytes(),
                default_probe_interval_secs(),
            )
        })
        .join()
        .expect("reader thread must not panic");
        assert_eq!(
            live,
            (1_111, 9 * 1024 * 1024, 23),
            "live traffic on another thread must keep the published limits during a build"
        );
        assert_eq!(
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
            9 * 1024 * 1024,
            "a derived cap is never moved by a candidate"
        );
    }

    assert_eq!(
        key_gauge_limit(),
        1_111,
        "leaving the scope publishes nothing"
    );

    busbar_kernel::config::limits::publish(&distinctive(3_333, 2048, 51));
    let live = std::thread::spawn(|| {
        (
            key_gauge_limit(),
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
        )
    })
    .join()
    .expect("reader thread must not panic");
    assert_eq!(
        live,
        (3_333, 2048),
        "publication is what puts a generation's limits in force"
    );
}

#[test]
fn uncommitted_guard_restores_the_hook_content_ceiling() {
    const CASE: &str = "limits::tests::uncommitted_guard_restores_the_hook_content_ceiling";
    if std::env::var("BUSBAR_LIMITS_CASE_CHILD").ok().as_deref() != Some(CASE) {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", CASE, "--nocapture"])
            .env("BUSBAR_LIMITS_CASE_CHILD", CASE)
            .output()
            .expect("run this limits case in its own process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "the isolated process must actually run the exact limits case"
        );
        return;
    }

    let previous = LimitsResolved {
        hook_content_max_bytes: 4_096,
        ..distinctive(1_111, 5 * 1024 * 1024, 17)
    };
    busbar_kernel::config::limits::publish(&previous);
    assert_eq!(crate::hooks::hook_content_max_bytes(), 4_096);

    {
        busbar_kernel::config::limits::publish(&LimitsResolved {
            hook_content_max_bytes: 64,
            ..distinctive(2_222, 1024, 3)
        });
        assert_eq!(
            crate::hooks::hook_content_max_bytes(),
            64,
            "the temporary ceiling is in force while the guard is held"
        );
    }

    busbar_kernel::config::limits::publish(&previous);
    assert_eq!(
        crate::hooks::hook_content_max_bytes(),
        4_096,
        "a dropped guard left its hook content ceiling in force"
    );
}
