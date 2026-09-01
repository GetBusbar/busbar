//! Regression tests for `App::pool_upstream_creds` after the p0-perfa-poolcreds fix: the accessor
//! grew a fast path (a `Copy` read of the all-pools default) gated on `any_pool_upstream_creds_
//! override`, which is resolved once at config apply. These pin the behavior the fast path must be
//! byte-identical to: same credential resolved as the pre-fix unconditional `pool_runtime` probe,
//! for every combination of {override present / absent} × {pool known / unknown}.

use crate::auth::UpstreamCreds;
use crate::state::PoolRuntime;
use crate::test_support::{LaneSpec, TestApp};

/// COMMON config (no pool sets `upstream_credentials:`): the flag is `false`, so the accessor takes
/// the fast path — every pool name (known, unknown, empty) resolves to the ALL-POOLS default.
#[test]
fn no_override_fast_path_returns_all_pools_default() {
    for default in [UpstreamCreds::Own, UpstreamCreds::Passthrough] {
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m0",
                crate::proto::PROTO_OPENAI,
                "http://localhost",
            ))
            .pool("p", &[(0, 1)])
            .upstream_creds(default)
            .build();

        assert!(
            !app.llm_runtime().any_pool_upstream_creds_override,
            "no pool overrides ⇒ fast path enabled"
        );
        // Known pool, unknown pool, and the empty (direct/ad-hoc) pool all resolve to the default.
        assert_eq!(app.engine_tables().pool_upstream_creds("p"), default);
        assert_eq!(
            app.engine_tables().pool_upstream_creds("does-not-exist"),
            default
        );
        assert_eq!(app.engine_tables().pool_upstream_creds(""), default);
    }
}

/// OVERRIDE present: one pool sets its own `upstream_credentials:`. The flag flips to `true`, so the
/// full `pool_runtime` probe runs — the overriding pool gets ITS value, every other name falls back
/// to the all-pools default (the SCALAR override rule, unchanged by the fast path).
#[test]
fn override_present_runs_full_lookup() {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::PROTO_OPENAI,
            "http://localhost",
        ))
        .lane(LaneSpec::new(
            "m1",
            crate::proto::PROTO_OPENAI,
            "http://localhost",
        ))
        .pool("base", &[(0, 1)])
        .pool("pt", &[(1, 1)])
        // All-pools default is Own; the `pt` pool overrides to Passthrough.
        .upstream_creds(UpstreamCreds::Own)
        .pool_runtime(
            "pt",
            PoolRuntime {
                upstream_credentials: Some(UpstreamCreds::Passthrough),
                ..PoolRuntime::default()
            },
        )
        .build();

    assert!(
        app.llm_runtime().any_pool_upstream_creds_override,
        "a pool sets an override ⇒ full lookup enabled"
    );
    // The overriding pool gets its own value.
    assert_eq!(
        app.engine_tables().pool_upstream_creds("pt"),
        UpstreamCreds::Passthrough
    );
    // A pool with no override inherits the all-pools default.
    assert_eq!(
        app.engine_tables().pool_upstream_creds("base"),
        UpstreamCreds::Own
    );
    // An unknown pool name falls back to the default too.
    assert_eq!(
        app.engine_tables().pool_upstream_creds("unknown"),
        UpstreamCreds::Own
    );
}
