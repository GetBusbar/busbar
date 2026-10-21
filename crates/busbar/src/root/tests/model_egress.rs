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
    // The deployment names `models:`/`pools:`, which config resolution hands a plane: the parse is
    // lent the kernel's neutral test table, whose one plane owns them, as the timeout cells' is.
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        &format!("providers: {{}}\nmodels: {{}}\npools:\n{section}"),
        busbar_kernel::test_support::neutral_test_doors(),
    )
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

/// LEGACY the retired engine crate's `src/engine/tests/ingress_integration_tests.rs::test_forward_resolved_by_model_uses_lane_default_breaker_cell`.
/// A ROUTE NAMING A MODEL DIRECTLY RECORDS ON THE LANE-DEFAULT CELL (`""`), the one cell 1.5.5's
/// `/<model>/v1/messages` and its by-model forward both selected: one transient on the direct
/// route's pool arms a cooldown on the lane's `""` cell and none under the model's own name, so a
/// model's breaker state is not split by the shape of the route that reached it.
/// RED: a direct route recorded under the model's name leaves the `""` cell's cooldown at 0.
#[test]
fn a_direct_routes_fault_is_recorded_on_the_lanes_default_cell() {
    let app = TestApp::new()
        .lane(LaneSpec::new("m0", "wire-under-test", "http://127.0.0.1:9"))
        .build();
    let mut cells = cells_over(Arc::clone(&app), &[]);
    cells.direct.insert("m0".to_owned());
    let token = busbar_kernel::test_support::tokens::pass();
    let now = wall_secs();

    cells.observe(
        "m0",
        DestinationId::new(0),
        Outcome::Transient { retry_after: None },
        now,
        &token,
    );
    assert!(
        app.store.cooldown_remaining_in("", 0, now) > 0,
        "the direct route's fault arms the lane-default cell"
    );
    // NO OUTCOME IS RECORDED UNDER THE MODEL'S OWN NAME. Read through the cell's outcome window,
    // not its cooldown: any read of a pool cell creates it on first touch, and a created cell
    // INHERITS the lane's current health (the store's `pool_cell`: state, cooldown and streak,
    // never the window), so its cooldown reads the lane's whatever the route recorded. The window
    // is the cell's own record: empty unless the fault was observed into that cell.
    assert_eq!(
        app.store.error_rate_in("", 0, now),
        Some(1.0),
        "the lane-default cell's window holds the direct route's one fault"
    );
    assert_eq!(
        app.store.error_rate_in("m0", 0, now),
        None,
        "no cell is kept under the model's own name"
    );
}
