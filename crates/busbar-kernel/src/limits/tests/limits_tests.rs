// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{DEFAULT_PROBE_INTERVAL_SECS, DEFAULT_PROBE_TIMEOUT_SECS};

/// The installed active-probe interval fallback (seconds), read straight off the process-global slot
/// (the door plane's probe unit reads its own sections; no accessor reads this field).
fn default_probe_interval_secs() -> u64 {
    get().map_or(DEFAULT_PROBE_INTERVAL_SECS, |l| {
        l.default_probe_interval_secs
    })
}

/// The installed active-probe timeout fallback (seconds), read the same way.
fn default_probe_timeout_secs() -> u64 {
    get().map_or(DEFAULT_PROBE_TIMEOUT_SECS, |l| l.default_probe_timeout_secs)
}

/// Put the process-global slot back exactly as it was found, on the way out of a test — INCLUDING
/// the failure path, where an `assert!` panics before any hand-written restore line could run.
/// A leaked non-default install would otherwise turn one real failure into a cascade of unrelated
/// ones (that is precisely the bug `InstallGuard` exists to prevent, in miniature).
/// Deliberately NOT `InstallGuard`: the subject of these tests cannot also be their fixture, or a
/// broken `InstallGuard::drop` would silently repair the very state the assertions inspect.
struct RestoreOnDrop(Option<LimitsResolved>);

impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        busbar_kernel::config::limits::set_installed(self.0.take());
    }
}

/// A `LimitsResolved` whose every field asserted below differs from the historical default, so no
/// assertion can be satisfied by a fallback path.
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

/// UNINSTALLED accessors return the historical hardcoded defaults — an un-installed (or
/// default-config-installed) process is byte-for-byte today's behavior. `install` is
/// re-runnable (the config plane refreshes limits live), so another test in this binary MAY
/// have installed by the time this runs; every in-test installer uses a default-limits config,
/// making the assertions below hold in either order. A future test installing NON-default
/// limits would break this — give such a test its own values and this note is the pointer.
#[test]
fn uninstalled_accessors_return_historical_defaults() {
    // Under `LIMITS_TEST_LOCK` because the tests below DO install non-default limits: without it
    // this test can read the slot mid-swap and fail for a reason that has nothing to do with the
    // fallbacks it is asserting.
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    assert_eq!(
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        DEFAULT_REQUEST_BODY_MAX_BYTES
    );
    assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(rate_sweep_interval(), DEFAULT_RATE_SWEEP_INTERVAL);
    assert_eq!(default_probe_interval_secs(), DEFAULT_PROBE_INTERVAL_SECS);
    assert_eq!(default_probe_timeout_secs(), DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(default_policy_timeout_ms(), DEFAULT_POLICY_TIMEOUT_MS);
    // 1.5.3: no webhook-delivery-timeout accessor exists any more — the deadline is stated PER
    // named export instance (each sink carries its own delivery timeout), so there is no single
    // process-global value an accessor could honestly return.
    // Discharges the warning two paragraphs up: `tls.rs`'s body-read-timeout test now installs
    // its NON-default value through `InstallGuard` (restores on drop) instead of the bare
    // `install`, so this assertion is safe to add — if a future test regresses back to a bare
    // install that leaks its value, this fails hard instead of silently depending on run order.
    assert_eq!(
        request_body_read_timeout_secs(),
        crate::config::DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS
    );
}

/// THE TEST GUARD'S COMMIT PATH — a committed `InstallGuard` KEEPS the posture it installed. (The
/// guard is the test surface's process-wide installer; a configuration build never installs
/// through it — see `a_build_scope_is_seen_by_its_own_thread_only` below.) If `commit` failed to
/// suppress the rollback, a test that installs and commits a posture would silently run under the
/// previous one. Asserted AFTER `commit` has consumed and dropped the guard (`commit(mut self)` takes
/// it by value, so the `Drop` impl runs at the end of that call, not at the end of this test) — that
/// drop is the exact moment a mis-written commit flag would undo the install.
#[test]
fn committed_guard_keeps_its_limits_live_after_the_guard_is_gone() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());

    let candidate = distinctive(4_242, 7 * 1024 * 1024, 37);
    let guard = InstallGuard::install(&candidate);
    assert_eq!(
        key_gauge_limit(),
        4_242,
        "the guard installs its posture immediately"
    );

    guard.commit();

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

/// THE TEST GUARD'S ROLLBACK PATH — a guard dropped WITHOUT `commit` restores the PREVIOUS limits
/// exactly, so one test's posture never leaks into the next.
///
/// The previous limits here are deliberately NON-DEFAULT, which is the whole point of the test: a
/// rollback implemented as "reset to `LimitsResolved::default()`" or "clear the slot to `None`"
/// would look correct in a test whose starting state was already the default, and would wipe the
/// running operator's real, accepted configuration in production. Only a rollback that restores the
/// SNAPSHOT passes this.
#[test]
fn uncommitted_guard_restores_the_previous_limits_exactly_not_the_defaults() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());

    // The accepted config that is already serving traffic.
    let previous = distinctive(1_111, 5 * 1024 * 1024, 17);
    busbar_kernel::config::limits::install(&previous);

    {
        // A test's temporary posture, installed process-wide for the guard's scope.
        let _temporary = InstallGuard::install(&distinctive(2_222, 1024, 3));
        assert_eq!(key_gauge_limit(), 2_222);
        assert_eq!(
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
            1024
        );
        // …and the scope ends here, with no explicit unwind of any kind. Only `Drop` can restore.
    }

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

/// ROLLBACK FROM THE UNINSTALLED STATE — the `prior: None` arm. In a fresh test process nothing is
/// installed yet, so a dropped guard must restore the slot to EMPTY, which is what makes the
/// accessors fall back to the historical hardcoded defaults. A rollback that only knew how to write
/// `Some(_)` would leave the temporary posture as the process's permanent "defaults".
#[test]
fn uncommitted_guard_restores_the_uninstalled_state_when_nothing_was_installed() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());

    busbar_kernel::config::limits::set_installed(None);

    {
        let _temporary = InstallGuard::install(&distinctive(3_333, 2048, 51));
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

/// ROLLBACK REACHES THE LIVE READ PATH, not merely the guard's own fields: every read here goes
/// through the accessors the deep call-stack use sites call per request (`auth`'s body buffer and
/// `tls`'s total-deadline derivation call `busbar_kernel_egress::upstream::max_translate_body_bytes()`;
/// `metrics` calls `key_gauge_limit()`), FROM ANOTHER THREAD — the guard is not reachable from it,
/// so only the process-global slot can carry the restored value across.
#[test]
fn rollback_is_visible_on_the_live_read_path_from_another_thread() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());

    let previous = distinctive(1_234, 9 * 1024 * 1024, 23);
    busbar_kernel::config::limits::install(&previous);

    let guard = InstallGuard::install(&distinctive(5_678, 1024, 2));
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

    drop(guard);

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

/// A CONFIGURATION BUILD'S CANDIDATE LIMITS ARE SEEN BY ITS OWN THREAD ONLY (BUSBAR-1.6.0.md THE
/// DESIGN §6 item 8: a reload "is refused, leaving the running generation serving, if any check
/// fails"). While the build scope is held the building thread reads the candidate — the build reads
/// the values it builds with — and every other thread, the live traffic the running generation
/// serves, reads the published limits throughout, including the derived caps (the translate-body
/// cap) a refused candidate would otherwise shrink. Leaving the scope publishes nothing. The
/// end-to-end RED arm is `tests::a_built_generations_limits_are_in_force_only_once_it_is_live`.
#[test]
fn a_build_scope_is_seen_by_its_own_thread_only() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());
    busbar_kernel::config::limits::install(&distinctive(1_111, 9 * 1024 * 1024, 23));

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

/// THE HOOK CONTENT CEILING ROLLS BACK WITH THE REST (audit kernel-K1 #5): the ceiling is a process
/// global mirrored out of the installed limits, so a dropped guard puts it back with the rest.
#[test]
fn uncommitted_guard_restores_the_hook_content_ceiling() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());

    let previous = LimitsResolved {
        hook_content_max_bytes: 4_096,
        ..distinctive(1_111, 5 * 1024 * 1024, 17)
    };
    busbar_kernel::config::limits::install(&previous);
    assert_eq!(busbar_kernel::hooks::hook_content_max_bytes(), 4_096);

    {
        let _temporary = InstallGuard::install(&LimitsResolved {
            hook_content_max_bytes: 64,
            ..distinctive(2_222, 1024, 3)
        });
        assert_eq!(
            busbar_kernel::hooks::hook_content_max_bytes(),
            64,
            "the temporary ceiling is in force while the guard is held"
        );
    }

    assert_eq!(
        busbar_kernel::hooks::hook_content_max_bytes(),
        4_096,
        "a dropped guard left its hook content ceiling in force"
    );
}
