//! Tests for `model_egress.rs`: what the served egress records and resolves, pinned at the root's
//! own seams (the breaker port the walk and the prober record through, and the pools the walk is
//! sealed over).

use super::*;
use busbar_kernel::test_support::{LaneSpec, TestApp};

/// The served breaker port over `app`'s lane store, each of `pools` a cell under the default ladder.
fn cells_over(app: Arc<busbar_kernel::state::App>, pools: &[&str]) -> WalkCells {
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
    WalkCells::over(
        app,
        Arc::new(CellPlan {
            records,
            direct: HashSet::new(),
        }),
    )
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

/// A SUCCESS JOINS THE ERROR-RATE WINDOW AT THE WALK'S `now`, as a failure does: six successes
/// and then five transient failures against the member of pool `p`, every one observed through the
/// served breaker port at the same instant of the walk's clock, leave a window of 5 errors in 11
/// outcomes (45%, under the default trip of 50% over at least five), so the cell stays Closed, as
/// 1.5.5's one clock kept it. The walk's clock reads an hour past the wall, as a test clock may.
/// RED: a success recorded on the store's own wall-clock read falls out of the window the walk's
/// failures are judged in, so those five read as 5 of 5 and trip the cell Open.
#[test]
fn a_success_is_recorded_on_the_walks_clock() {
    let app = TestApp::new()
        .lane(LaneSpec::new("m0", "wire-under-test", "http://127.0.0.1:9"))
        .pool("p", &[(0, 1)])
        .build();
    let cells = cells_over(Arc::clone(&app), &["p"]);
    let dest = DestinationId::new(0);
    let token = busbar_kernel::test_support::tokens::pass();
    let now = wall_secs() + 3_600;

    for _ in 0..6 {
        assert!(!cells.observe("p", dest, Outcome::Success, now, &token));
    }
    for _ in 0..5 {
        cells.observe(
            "p",
            dest,
            Outcome::Transient { retry_after: None },
            now,
            &token,
        );
    }
    assert_eq!(
        app.store.error_rate_in("p", 0, now),
        Some(5.0 / 11.0),
        "the window at the walk's clock holds every outcome the walk recorded"
    );
    assert!(
        matches!(
            app.store.breaker_state_in("p", 0),
            busbar_kernel::store::BreakerState::Closed
        ),
        "5 errors in 11 outcomes is under the trip"
    );
}

/// A HEALTH PROBE'S SUCCESS JOINS THE WALK'S WINDOW: one success the walk observes, five successful
/// probes and then five transient failures the walk observes, all at one instant of the walk's
/// clock (an hour past the wall, as a test clock may be), leave a window of 5 errors in 11 outcomes
/// in pool `p`'s cell (45%, under the default trip), so it stays Closed.
/// RED: probe successes recorded on the store's own wall-clock read fall out of the window the
/// walk's failures are judged in, so those read as 4 of 5 and trip the cell Open.
#[test]
fn a_probe_success_joins_the_walks_window() {
    let app = TestApp::new()
        .lane(LaneSpec::new("m0", "wire-under-test", "http://127.0.0.1:9"))
        .pool("p", &[(0, 1)])
        .build();
    let cells = cells_over(Arc::clone(&app), &["p"]);
    let dest = DestinationId::new(0);
    let token = busbar_kernel::test_support::tokens::pass();
    let now = wall_secs() + 3_600;

    // The pool's cell exists before the probes, as a served request through it makes it.
    assert!(!cells.observe("p", dest, Outcome::Success, now, &token));
    for _ in 0..5 {
        cells.probed(dest, Outcome::Success, now, &token);
    }
    for _ in 0..5 {
        cells.observe(
            "p",
            dest,
            Outcome::Transient { retry_after: None },
            now,
            &token,
        );
    }
    assert_eq!(
        app.store.error_rate_in("p", 0, now),
        Some(5.0 / 11.0),
        "the probes' successes sit in the window the walk's failures are judged in"
    );
    assert!(
        matches!(
            app.store.breaker_state_in("p", 0),
            busbar_kernel::store::BreakerState::Closed
        ),
        "5 errors in 11 outcomes is under the trip"
    );
}

/// A PROBE'S FAILURE AND EVERY HARD-DOWN ARM THEIR COOLDOWNS ON THE WALK'S CLOCK, the clock the
/// walk's admission and shed then read them on (an hour past the wall). One failed probe benches
/// pool `p`'s member for 1.5.5's 27..=33 s (the streak bumped to 1: 15 x 2, +-3), and a hard-down,
/// the walk's own or a probe's, parks every cell for the full sticky cooldown, read at the walk's
/// clock exactly.
/// RED: each was armed from the store's own wall-clock read, so at the walk's clock an hour on the
/// cooldown has already run out (it reads 0).
#[test]
fn probe_failures_and_hard_downs_cool_on_the_walks_clock() {
    let token = busbar_kernel::test_support::tokens::pass();
    let dest = DestinationId::new(0);
    let now = wall_secs() + 3_600;
    let fresh = || {
        let app = TestApp::new()
            .lane(LaneSpec::new("m0", "wire-under-test", "http://127.0.0.1:9"))
            .pool("p", &[(0, 1)])
            .build();
        let cells = cells_over(Arc::clone(&app), &["p"]);
        // The pool's cell exists before the record, as a served request through it makes it.
        assert!(!cells.observe("p", dest, Outcome::Success, now, &token));
        (app, cells)
    };

    let (app, cells) = fresh();
    cells.probed(dest, Outcome::Transient { retry_after: None }, now, &token);
    let cooling = app.store.cooldown_remaining_in("p", 0, now);
    assert!(
        (27..=33).contains(&cooling),
        "a failed probe benches the member for 1.5.5's cooldown, on the walk's clock: {cooling}"
    );

    for probe in [false, true] {
        let (app, cells) = fresh();
        let what = if probe {
            cells.probed(dest, Outcome::HardDown, now, &token);
            "a probe's hard-down"
        } else {
            cells.observe("p", dest, Outcome::HardDown, now, &token);
            "the walk's hard-down"
        };
        let sticky = app.store.breaker_unit().hard_down_cooldown_secs();
        for pool in ["", "p"] {
            assert_eq!(
                app.store.cooldown_remaining_in(pool, 0, now),
                sticky,
                "{what} parks cell {pool:?} for the sticky cooldown, read at the walk's clock"
            );
        }
    }
}

/// The pools `upstream_credentials` resolves to, for `section` (the `pools:` body).
fn pools_of(section: &str) -> ModelPools {
    // The deployment names `models:`/`pools:`, which config resolution hands a plane: register the
    // kernel's neutral test plane first, as the timeout cells do (nextest runs each test in its
    // own process, so no other test has registered one).
    busbar_kernel::test_support::register_neutral_test_plane();
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
