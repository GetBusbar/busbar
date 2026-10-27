//! Tests for `policy.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// **The hazard**, on the transport axis: a client built from the crate's own `Default` ignores
/// what the operator wrote. A deployment that caps request bodies at 1 KiB gets a transport that
/// buffers 32 MiB, and the door and the transport then disagree about which bodies exist. Every
/// field is checked, not just the cap, because the four beside it are operator knobs too and a
/// mapping that forgot one would be invisible until the deployment that set it.
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
    // The request timeout is the operator's too: a figure the transport hardcoded would
    // cut a slow upstream at a number nobody configured. 13 is neither the resolved default nor the
    // transport's own, so reading either instead of the operator's goes red here.
    assert_ne!(
        LimitsResolved::default().upstream_request_timeout_secs,
        13,
        "the fixture's timeout must differ from the resolved default"
    );
    assert_ne!(TransportSettings::default().request_timeout_secs, 13);
    assert_eq!(settings.request_timeout_secs, 13);
}

/// THE DEPRECATED ENV PINS STILL HOLD (1.5.5 honored them at its client build, over the config):
/// `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` set turns the http door's prior-knowledge key on whatever
/// `advanced.upstream_h2_prior_knowledge` says, `0` or empty turns it off, and unset leaves the
/// config's value; `BUSBAR_UPSTREAM_HTTP1_ONLY` the same for the http1-only key.
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

/// And a deployment that set nothing is left where it was: the resolved default body cap is the
/// same 32 MiB the transport's own `Default` carries, so wiring the knob through cannot move a
/// deployment that never touched it.
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

/// LEGACY the retiring engine crate's `src/engine/tests/runtime_carry_tests.rs::a_changed_upstream_timeout_rebuilds_the_client_an_unrelated_apply_reuses_it`
/// 1.5.5: a hot config apply that changes nothing client-relevant REUSES
/// the prior upstream client (its warm connection pool), and an apply that changes the upstream
/// request timeout REBUILDS it, so the new timeout (here the prior + 7 s) takes effect without a
/// restart.
///
/// This test pins only the SETTINGS half: what a transport door would be opened with
/// (`settings_blob`) and the connector's pool posture. An unchanged apply hands the doors
/// byte-identical settings and the same posture; a changed timeout hands them a different blob
/// carrying the new figure. It does not prove the doors are reopened on a hot apply: the served
/// connector is built once at boot (`root/connector.rs`), and that half (the row's rebuild) is the
/// egress lane's, with its own RED.
///
/// RED: an apply that changed nothing reads as a change, or a changed
/// `limits.upstream_request_timeout_secs` never reaches the settings a door is opened with.
#[test]
fn a_changed_upstream_timeout_changes_the_door_settings_an_unrelated_apply_does_not() {
    const DECLARED: [&str; 2] = [
        "limits.upstream_request_timeout_secs",
        "limits.request_body_max_bytes",
    ];
    let limits = LimitsResolved::default();
    // Reuse half: an apply with an identical client-affecting snapshot.
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
    // Rebuild half: bump the upstream request timeout and re-apply.
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
