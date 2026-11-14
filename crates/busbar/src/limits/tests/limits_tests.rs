use super::*;

/// Put the process-global slot back exactly as it was found, on the way out of a test — INCLUDING
/// the failure path, where an `assert!` panics before any hand-written restore line could run.
/// A leaked non-default install would otherwise turn one real failure into a cascade of unrelated
/// ones (that is precisely the bug `InstallGuard` exists to prevent, in miniature).
/// Deliberately NOT `InstallGuard`: the subject of these tests cannot also be their fixture, or a
/// broken `InstallGuard::drop` would silently repair the very state the assertions inspect.
struct RestoreOnDrop(Option<LimitsResolved>);

impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = self.0.take();
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
    assert_eq!(translate_body_max_bytes(), DEFAULT_REQUEST_BODY_MAX_BYTES);
    assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(rate_sweep_interval(), DEFAULT_RATE_SWEEP_INTERVAL);
    assert_eq!(default_probe_interval_secs(), DEFAULT_PROBE_INTERVAL_SECS);
    assert_eq!(default_probe_timeout_secs(), DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(default_policy_timeout_ms(), DEFAULT_POLICY_TIMEOUT_MS);
    // 1.5.3: no `webhook_delivery_timeout_secs()` accessor exists any more — the deadline is PER
    // named `request-log-webhook` export instance (`export::webhook::Target::timeout`), so there is
    // no single process-global value an accessor could honestly return.
    // Discharges the warning two paragraphs up: `tls.rs`'s body-read-timeout test now installs
    // its NON-default value through `InstallGuard` (restores on drop) instead of the bare
    // `install`, so this assertion is safe to add — if a future test regresses back to a bare
    // install that leaks its value, this fails hard instead of silently depending on run order.
    assert_eq!(
        request_body_read_timeout_secs(),
        crate::config::DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS
    );
}

/// THE COMMIT PATH — a build that reaches its `Ok` KEEPS the limits it installed. The other half of
/// the guard's contract, and the half a rollback bug would break in the opposite (silent, far worse)
/// direction: if `commit` failed to suppress the rollback, every successful `POST /config/apply`
/// would quietly revert its own limits while reporting 200, and the operator's new caps would never
/// take effect. Asserted AFTER `commit` has consumed and dropped the guard (`commit(mut self)` takes
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
        "the guard must install its limits immediately: the build itself reads them"
    );

    guard.commit();

    assert_eq!(
        key_gauge_limit(),
        4_242,
        "a COMMITTED guard must not roll back when it drops: an accepted config's limits stay live"
    );
    assert_eq!(translate_body_max_bytes(), 7 * 1024 * 1024);
    assert_eq!(default_probe_interval_secs(), 37);
}

/// THE ROLLBACK PATH — a guard dropped WITHOUT `commit` (the rejected-apply case: semantic
/// validation failed, the plugin pre-flight failed, a secret-ref would not resolve, the store would
/// not open) restores the PREVIOUS limits exactly.
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
    install(&previous);

    {
        // The candidate config whose build is about to fail. Its limits ARE installed while the
        // build runs — that is required, not incidental: the build reads them.
        let _rejected = InstallGuard::install(&distinctive(2_222, 1024, 3));
        assert_eq!(key_gauge_limit(), 2_222);
        assert_eq!(
            translate_body_max_bytes(),
            1024,
            "the candidate's limits must be live DURING the build — including the dangerous ones \
             the later validation step exists to reject"
        );
        // …and the build fails here, with no explicit unwind of any kind. Only `Drop` can save us.
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
    assert_eq!(translate_body_max_bytes(), 5 * 1024 * 1024);
    assert_eq!(default_probe_interval_secs(), 17);
}

/// ROLLBACK FROM THE UNINSTALLED STATE — the `prior: None` arm. At boot (and in a fresh test
/// process) nothing is installed yet, so a failed first build must restore the slot to EMPTY, which
/// is what makes the accessors fall back to the historical hardcoded defaults. A rollback that only
/// knew how to write `Some(_)` would leave the rejected config's values as the process's permanent
/// "defaults".
#[test]
fn uncommitted_guard_restores_the_uninstalled_state_when_nothing_was_installed() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());

    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = None;

    {
        let _rejected = InstallGuard::install(&distinctive(3_333, 2048, 51));
        assert_eq!(key_gauge_limit(), 3_333);
    }

    assert!(
        get().is_none(),
        "rollback from the uninstalled state must clear the slot, not leave the rejected config's \
         struct behind"
    );
    assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(translate_body_max_bytes(), DEFAULT_REQUEST_BODY_MAX_BYTES);
    assert_eq!(default_probe_interval_secs(), DEFAULT_PROBE_INTERVAL_SECS);
}

/// ROLLBACK REACHES THE LIVE READ PATH, not merely the guard's own fields.
///
/// This is the assertion that makes the two tests above worth anything. A test that inspected
/// `guard.prior` would pass with `Drop` deleted entirely — it would report success while proving
/// nothing. So every read here goes through the module's accessors, which are the exact functions
/// the deep call-stack use sites call per request/per connection (`auth`'s SigV4 body buffer and
/// `tls`'s total-deadline derivation both call `translate_body_max_bytes()`; `metrics` calls
/// `key_gauge_limit()`), and they are read FROM ANOTHER THREAD — the guard is not on that thread's
/// stack and is not reachable from it, so the only thing that can carry the restored value across is
/// the process-global `INSTALLED` slot that a request would read.
/// `main::build_app_from_config`'s guard drops on a `POST /config/apply` worker while requests are
/// served on other threads; this is that shape.
#[test]
fn rollback_is_visible_on_the_live_read_path_from_another_thread() {
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    let _restore = RestoreOnDrop(get());

    let previous = distinctive(1_234, 9 * 1024 * 1024, 23);
    install(&previous);

    // A request-shaped read, off-thread, WHILE the candidate is installed: proves the read path this
    // test uses actually observes an install (so the post-drop read below is a real observation and
    // not a constant).
    let guard = InstallGuard::install(&distinctive(5_678, 1024, 2));
    let during = std::thread::spawn(|| (key_gauge_limit(), translate_body_max_bytes()))
        .join()
        .expect("reader thread must not panic");
    assert_eq!(
        during,
        (5_678, 1024),
        "another thread must see the candidate's limits while the build is in flight"
    );

    drop(guard);

    let after = std::thread::spawn(|| {
        (
            key_gauge_limit(),
            translate_body_max_bytes(),
            default_probe_interval_secs(),
        )
    })
    .join()
    .expect("reader thread must not panic");
    assert_eq!(
        after,
        (1_234, 9 * 1024 * 1024, 23),
        "a request served on another thread after a REJECTED apply must see the previous limits: \
         the rollback has to land on the process-global slot, not just on the guard"
    );
}
