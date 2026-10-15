//! Tests for `model_egress.rs`: what the served egress records and resolves, pinned at the root's
//! own seams (the breaker port the walk and the prober record through, and the pools the walk is
//! sealed over).

use super::*;
use busbar_kernel::test_support::{LaneSpec, TestApp};

/// The served breaker port over `app`'s lane store, each of `pools` a cell under the default ladder.
fn cells_over(app: Arc<busbar_kernel::state::App>, pools: &[&str]) -> DirectCells {
    let source: AppSource = Arc::new(move || Arc::clone(&app));
    let unit = Arc::clone(&source);
    let mut records: HashMap<String, busbar_kernel::store::BreakerCfg> = pools
        .iter()
        .map(|pool| {
            (
                (*pool).to_owned(),
                busbar_kernel::store::BreakerCfg::default(),
            )
        })
        .collect();
    records.insert(String::new(), busbar_kernel::store::BreakerCfg::default());
    DirectCells {
        inner: BreakerAdapter::over(
            Arc::new(move || unit().store.breaker_unit()),
            BreakerPolicy::new(),
        ),
        app: source,
        records,
        direct: HashSet::new(),
    }
}

fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

/// A SUCCESSFUL HEALTH PROBE COUNTS ONCE on the lane's `/stats` `ok`, whatever number of pools the
/// lane sits in (1.5.5 `engine/health.rs`: one bump per 2xx probe, mirroring the single `err` bump
/// of a failed one). The lane sits in three pools, each with a live cell of its own, and is probed
/// twice through the served breaker port: `ok` rises by exactly two. A per-cell count would read
/// eight (the default cell and three pool cells, per probe).
#[test]
fn a_successful_probe_counts_once_on_the_lanes_ok_whatever_its_pools() {
    let pools = ["first", "second", "third"];
    let app = TestApp::new()
        .lane(LaneSpec::new("m0", "wire-under-test", "http://127.0.0.1:9"))
        .pool(pools[0], &[(0, 1)])
        .pool(pools[1], &[(0, 1)])
        .pool(pools[2], &[(0, 1)])
        .build();
    let cells = cells_over(Arc::clone(&app), &pools);
    let dest = DestinationId::new(0);
    let token = busbar_kernel::test_support::tokens::pass();
    let now = wall_secs();

    // Every pool's cell exists before the probes, as a served request through each makes it.
    for pool in pools {
        assert!(!cells.observe(pool, dest, Outcome::Success, now, &token));
    }
    let before = app.store.snapshot(0, now).ok;

    for _ in 0..2 {
        cells.probed(dest, Outcome::Success, now, &token);
    }
    assert_eq!(
        app.store.snapshot(0, now).ok - before,
        2,
        "a successful probe bumps the lane's `ok` once, not once per cell"
    );
}

/// The pools `upstream_credentials` resolves to, for `section` (the `pools:` body).
fn pools_of(section: &str) -> ModelPools {
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&format!(
        "providers: {{}}\nmodels: {{}}\npools:\n{section}"
    ))
    .expect("the deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    ModelPools::of(&cfg)
}

/// THE ALL-POOLS `upstream_credentials:` DEFAULT IS INHERITED (1.5.5's scalar override rule): a
/// pool that sets none takes the all-pools default, a pool that sets its own keeps it, and a route
/// naming a model directly takes the default. Driven both ways round, so neither value is the one
/// that merely happens to be the built-in; and with no default at all, nothing is passed through.
#[test]
fn the_all_pools_credential_default_reaches_every_pool_without_its_own_and_every_direct_route() {
    for (default, other, passes) in [("passthrough", "own", true), ("own", "passthrough", false)] {
        let plan = pools_of(&format!(
            "  upstream_credentials: {default}\n  \
             inherits:\n    members: []\n  \
             overrides:\n    members: []\n    upstream_credentials: {other}\n"
        ));
        assert_eq!(
            plan.pools["inherits"].passthrough, passes,
            "a pool with no `upstream_credentials:` of its own inherits `{default}`"
        );
        assert_eq!(
            plan.pools["overrides"].passthrough, !passes,
            "a pool's own `{other}` replaces the all-pools `{default}`"
        );
        assert_eq!(
            plan.passthrough, passes,
            "a route naming a model directly takes the all-pools `{default}`"
        );
    }

    let plan = pools_of("  inherits:\n    members: []\n");
    assert!(
        !plan.pools["inherits"].passthrough && !plan.passthrough,
        "with no default set, every member is reached with its own credential"
    );
}
