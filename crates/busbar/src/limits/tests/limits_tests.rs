use super::*;

/// UNINSTALLED accessors return the historical hardcoded defaults — an un-installed (or
/// default-config-installed) process is byte-for-byte today's behavior. `install` is
/// re-runnable (the config plane refreshes limits live), so another test in this binary MAY
/// have installed by the time this runs; every in-test installer uses a default-limits config,
/// making the assertions below hold in either order. A future test installing NON-default
/// limits would break this — give such a test its own values and this note is the pointer.
#[test]
fn uninstalled_accessors_return_historical_defaults() {
    assert_eq!(translate_body_max_bytes(), DEFAULT_REQUEST_BODY_MAX_BYTES);
    assert_eq!(key_gauge_limit(), DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(rate_sweep_interval(), DEFAULT_RATE_SWEEP_INTERVAL);
    assert_eq!(default_probe_interval_secs(), DEFAULT_PROBE_INTERVAL_SECS);
    assert_eq!(default_probe_timeout_secs(), DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(default_policy_timeout_ms(), DEFAULT_POLICY_TIMEOUT_MS);
    assert_eq!(
        webhook_delivery_timeout_secs(),
        DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS
    );
    // Discharges the warning two paragraphs up: `tls.rs`'s body-read-timeout test now installs
    // its NON-default value through `InstallGuard` (restores on drop) instead of the bare
    // `install`, so this assertion is safe to add — if a future test regresses back to a bare
    // install that leaks its value, this fails hard instead of silently depending on run order.
    assert_eq!(
        request_body_read_timeout_secs(),
        crate::config::DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS
    );
}
