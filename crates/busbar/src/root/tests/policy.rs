use super::*;

#[test]
fn the_transport_client_reads_the_operators_limits_and_not_a_default() {
    let limits = LimitsResolved {
        request_body_max_bytes: 1024,
        pool_max_idle_per_host: 7,
        pool_idle_timeout_secs: 11,
        upstream_http1_only: true,
        upstream_h2_prior_knowledge: false,
        upstream_request_timeout_secs: 13,
        ..LimitsResolved::default()
    };
    let settings = client_settings(&limits);
    assert_eq!(settings.request_body_max_bytes, 1024);
    assert_eq!(settings.response_body_max_bytes, 1024);
    assert_eq!(settings.pool_max_idle_per_host, 7);
    assert_eq!(settings.pool_idle_timeout_secs, 11);
    assert!(settings.upstream_http1_only);
    assert!(!settings.upstream_h2_prior_knowledge);

    assert_ne!(
        LimitsResolved::default().upstream_request_timeout_secs,
        13,
        "the fixture's timeout must differ from the resolved default"
    );
    assert_ne!(TransportSettings::default().request_timeout_secs, 13);
    assert_eq!(settings.request_timeout_secs, 13);
}

#[test]
fn the_deprecated_upstream_env_pins_win_over_the_config() {
    let limits = LimitsResolved::default();
    assert!(!limits.upstream_h2_prior_knowledge && !limits.upstream_http1_only);
    let under = |pairs: &'static [(&'static str, &'static str)], limits: &LimitsResolved| {
        client_settings_under(limits, |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| std::ffi::OsString::from(v))
        })
    };
    let s = under(&[("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "1")], &limits);
    assert!(s.upstream_h2_prior_knowledge && !s.upstream_http1_only);
    let s = under(&[("BUSBAR_UPSTREAM_HTTP1_ONLY", "true")], &limits);
    assert!(s.upstream_http1_only && !s.upstream_h2_prior_knowledge);
    let configured = LimitsResolved {
        upstream_h2_prior_knowledge: true,
        upstream_http1_only: true,
        ..LimitsResolved::default()
    };
    let s = under(
        &[
            ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "0"),
            ("BUSBAR_UPSTREAM_HTTP1_ONLY", ""),
        ],
        &configured,
    );
    assert!(!s.upstream_h2_prior_knowledge && !s.upstream_http1_only);
    let s = under(&[], &configured);
    assert!(s.upstream_h2_prior_knowledge && s.upstream_http1_only);
}

#[test]
fn an_unset_body_cap_resolves_to_the_transport_default() {
    let settings = client_settings(&LimitsResolved::default());
    assert_eq!(
        settings.request_body_max_bytes,
        TransportSettings::default().request_body_max_bytes
    );
    assert_eq!(
        settings.request_body_max_bytes,
        32 * 1024 * 1024,
        "the transport's own default body cap is the 32 MiB this deployment has always had"
    );
}

#[test]
fn a_changed_upstream_timeout_changes_the_door_settings_an_unrelated_apply_does_not() {
    const DECLARED: [&str; 2] = [
        "limits.upstream_request_timeout_secs",
        "limits.request_body_max_bytes",
    ];
    let limits = LimitsResolved::default();

    let prior = client_settings(&limits);
    let unchanged = client_settings(&LimitsResolved::default());
    assert_eq!(
        crate::root::doors::settings_blob(&DECLARED, &prior),
        crate::root::doors::settings_blob(&DECLARED, &unchanged),
        "an apply that changes no client-affecting setting must REUSE the prior client's warm pool"
    );
    assert_eq!(
        crate::root::connector::pool_posture(&prior),
        crate::root::connector::pool_posture(&unchanged)
    );

    let changed = LimitsResolved {
        upstream_request_timeout_secs: limits.upstream_request_timeout_secs + 7,
        ..limits
    };
    let rebuilt = client_settings(&changed);
    assert_ne!(
        crate::root::doors::settings_blob(&DECLARED, &prior),
        crate::root::doors::settings_blob(&DECLARED, &rebuilt),
        "an apply that changes upstream_request_timeout_secs must REBUILD the client so the new \
         timeout takes effect"
    );
    assert_eq!(
        rebuilt.request_timeout_secs,
        prior.request_timeout_secs + 7,
        "the rebuilt client's carried settings snapshot must reflect the new timeout"
    );
    let blob: serde_json::Value =
        serde_json::from_slice(&crate::root::doors::settings_blob(&DECLARED, &rebuilt))
            .expect("the settings blob is JSON");
    assert_eq!(
        blob["limits.upstream_request_timeout_secs"],
        serde_json::json!(prior.request_timeout_secs + 7)
    );
}
