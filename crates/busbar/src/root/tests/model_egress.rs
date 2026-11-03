use super::*;

#[test]
fn queue_depth_counts_waiters_from_overlapping_egress_generations() {
    use busbar_kernel::plane_driver::route_tables::{ConfigTables, EngineTablesView};
    use busbar_kernel_egress::ports::Telemetry as _;
    let app = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let make = || ModelTelemetry {
        app: LiveApp::fixed(Arc::clone(&app)),
        names: Arc::default(),
        queued: crate::root::egress_ports::WalkTelemetry::default(),
        reservoirs: Arc::new(HashMap::new()),
    };
    let previous = make();
    let current = make();
    let tables = ConfigTables::default();
    let pool = "model-telemetry-overlapping-generations";
    previous.queued(pool, 1);
    current.queued(pool, 1);
    let both = tables.queued_depth(pool);
    previous.queued(pool, -1);
    let remaining = tables.queued_depth(pool);
    current.queued(pool, -1);
    let empty = tables.queued_depth(pool);
    drop(previous);
    drop(current);
    assert_eq!(both, 2, "the old and new egress each still have a waiter");
    assert_eq!(remaining, 1, "ending the old wait must retain the new one");
    assert_eq!(empty, 0, "balanced completion removes every waiter");
    assert_eq!(
        tables.queued_depth(pool),
        0,
        "dropping drained handles changes nothing"
    );
}

fn cells_over(app: Arc<busbar_kernel::state::App>, pools: &[&str]) -> WalkCells {
    cells_routing(LiveApp::fixed(app), pools, &[])
}

fn cells_routing(app: LiveApp, pools: &[&str], direct: &[&str]) -> WalkCells {
    let names = Arc::new(
        app.load()
            .engine_tables_view()
            .model_indices()
            .into_iter()
            .map(|(name, lane)| (DestinationId::new(lane as u64), name.to_string()))
            .collect(),
    );
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
            direct: direct.iter().map(|m| (*m).to_owned()).collect(),
            names,
        }),
    )
}

#[test]
fn retained_destinations_follow_the_model_name_across_reorder_and_removal() {
    use busbar_kernel::plane_driver::MemberSignals as _;
    use busbar_kernel_egress::ports::Telemetry as _;
    let first = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m-z: {provider: wire}}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let second = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m-a: {provider: wire}, m-z: {provider: wire}}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let removed = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m-a: {provider: wire}}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(&first)));
    let slot = Arc::new(std::sync::OnceLock::new());
    slot.set(Arc::downgrade(&handle)).unwrap();
    let cells = cells_routing(LiveApp::new(slot, Arc::clone(&first)), &["p"], &[]);
    let signals = ModelSignals {
        app: cells.live.clone(),
        names: Arc::clone(&cells.plan.names),
        permits: Arc::new(crate::root::egress_ports::MemberPermits::new(Vec::new())),
        reservoirs: Arc::default(),
    };
    let telemetry = ModelTelemetry {
        app: cells.live.clone(),
        names: Arc::clone(&cells.plan.names),
        queued: crate::root::egress_ports::WalkTelemetry::default(),
        reservoirs: Arc::default(),
    };
    let token = busbar_kernel::test_hooks::tokens::pass();
    let destination = DestinationId::new(0);
    let now = wall_secs();
    handle.swap(Arc::clone(&second));
    cells.observe("p", destination, Outcome::HardDown, now, &token);
    assert!(
        matches!(
            second.store.breaker_state_snapshot_in("", 0),
            busbar_kernel::store::BreakerState::Closed
        ),
        "new index0 is another model"
    );
    assert!(
        matches!(
            second.store.breaker_state_snapshot_in("", 1),
            busbar_kernel::store::BreakerState::Open { .. }
        ),
        "the original model moved to index1"
    );
    telemetry.upstream_latency(destination, 23.0);
    assert_eq!(second.store.lane_latency_ms(0), None);
    assert_eq!(signals.standing("p", destination).latency_ms, Some(23.0));
    handle.swap(Arc::clone(&removed));
    assert!(
        !cells.admissible(destination),
        "a removed model is unavailable"
    );
    assert!(matches!(
        cells.try_admit("p", destination, now),
        Err(Unavailable::Dead)
    ));
    cells.probed(destination, Outcome::HardDown, now, &token);
    cells.observe("p", destination, Outcome::Success, now, &token);
    telemetry.upstream_latency(destination, 91.0);
    assert_eq!(signals.standing("p", destination).budget_remaining, Some(0));
    assert_eq!(removed.store.lane_latency_ms(0), None);
    assert!(matches!(
        removed.store.breaker_state_snapshot_in("", 0),
        busbar_kernel::store::BreakerState::Closed
    ));
    assert_eq!(removed.store.snapshot(0, now).ok, 0);
    assert_eq!(removed.store.snapshot(0, now).err, 0);
}

#[test]
fn budget_refunds_and_probe_releases_keep_their_originating_unit() {
    let first = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m-z: {provider: wire, max_requests: 2}}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let second = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models =
            "{m-a: {provider: wire, max_requests: 11}, m-z: {provider: wire, max_requests: 7}}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(&first)));
    let slot = Arc::new(std::sync::OnceLock::new());
    slot.set(Arc::downgrade(&handle)).unwrap();
    let cells = cells_routing(LiveApp::new(slot, Arc::clone(&first)), &["p"], &[]);
    let destination = DestinationId::new(0);
    assert!(cells.spend_budget(destination));
    assert_eq!(first.store.lane_budget_remaining(0), Some(1));
    let token = busbar_kernel::test_hooks::tokens::pass();
    let now = wall_secs();
    cells.observe("p", destination, Outcome::HardDown, now, &token);
    let later = now + busbar_kernel_breaker::DEFAULT_HARD_DOWN_COOLDOWN_SECS + 1;
    let epoch = cells
        .try_admit("p", destination, later)
        .unwrap()
        .probe_epoch
        .expect("probe owned");
    handle.swap(Arc::clone(&second));
    cells.refund_budget(destination);
    cells.release_probe("p", destination, epoch, later);
    assert_eq!(first.store.lane_budget_remaining(0), Some(2));
    assert_eq!(second.store.lane_budget_remaining(0), Some(11));
    assert_eq!(second.store.lane_budget_remaining(1), Some(7));
    let unit = first.store.breaker_unit();
    let again = unit
        .try_admit("p", destination, later)
        .expect("the old unit's probe was released");
    unit.release_probe("p", destination, again.probe_epoch.unwrap());
}

fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

#[test]
fn a_successful_probe_counts_once_on_the_lanes_ok_whatever_its_pools() {
    let pools = ["first", "second", "third"];
    let app = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m0: {provider: wire}}";
        let pools = "{first: {members: [m0]}, second: {members: [m0]}, third: {members: [m0]}}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let cells = cells_over(Arc::clone(&app), &pools);
    let dest = DestinationId::new(0);
    let token = busbar_kernel::test_hooks::tokens::pass();
    let now = wall_secs();

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

#[test]
fn a_success_is_recorded_on_the_walks_clock() {
    let app = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m0: {provider: wire}}";
        let pools = "{p: {members: [m0]}}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let cells = cells_over(Arc::clone(&app), &["p"]);
    let dest = DestinationId::new(0);
    let token = busbar_kernel::test_hooks::tokens::pass();
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

#[test]
fn a_probe_success_joins_the_walks_window() {
    let app = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m0: {provider: wire}}";
        let pools = "{p: {members: [m0]}}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let cells = cells_over(Arc::clone(&app), &["p"]);
    let dest = DestinationId::new(0);
    let token = busbar_kernel::test_hooks::tokens::pass();
    let now = wall_secs() + 3_600;

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

#[test]
fn probe_failures_and_hard_downs_cool_on_the_walks_clock() {
    let token = busbar_kernel::test_hooks::tokens::pass();
    let dest = DestinationId::new(0);
    let now = wall_secs() + 3_600;
    let fresh = || {
        let app = {
            crate::dist_root_install::install();
            crate::root::test_plane_registry::register();
            let dialects: serde_json::Value =
                serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                    .expect("the actual linked dialects are recorded");
            let dialect = dialects["body_model"]
                .as_object()
                .and_then(|rows| rows.keys().next())
                .expect("the distribution links a model dialect");
            let models = "{m0: {provider: wire}}";
            let pools = "{p: {members: [m0]}}";
            let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
            let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
            let cfg =
                busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
            let store = crate::root::real_store::store();
            let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
                Arc::new(crate::root::door_steps::Rules::default());
            let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
                cfg,
                Default::default(),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
                Some(busbar_contract::store_calls::OpenedStore {
                    records: store.clone(),
                    calls: Some(store),
                }),
                false,
            )
            .expect("the product builds the configured model generation");
            limits
                .keep()
                .expect("the model generation commits its limits");
            if let Some(rotate) = rotate {
                rotate();
            }
            Arc::new(app)
        };
        let cells = cells_over(Arc::clone(&app), &["p"]);

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

fn pools_of(section: &str) -> ModelPools {
    crate::root::test_plane_registry::register();
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&format!(
        "providers: {{}}\nmodels: {{}}\npools:\n{section}"
    ))
    .expect("the deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    ModelPools::of(&cfg)
}

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

#[test]
fn a_direct_routes_fault_is_recorded_on_the_lanes_default_cell() {
    let app = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m0: {provider: wire}}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let cells = cells_routing(LiveApp::fixed(Arc::clone(&app)), &[], &["m0"]);
    let token = busbar_kernel::test_hooks::tokens::pass();
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

#[test]
fn a_walk_spanning_a_config_apply_records_into_the_new_store() {
    let generation = || {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{m0: {provider: wire}}";
        let pools = "{p: {members: [m0]}}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let (first, second) = (generation(), generation());
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(&first)));
    let live = Arc::new(std::sync::OnceLock::new());
    let _ = live.set(Arc::downgrade(&handle));
    let cells = cells_routing(LiveApp::new(live, Arc::clone(&first)), &["p"], &[]);
    let dest = DestinationId::new(0);
    let token = busbar_kernel::test_hooks::tokens::pass();
    let now = wall_secs();
    let fault = Outcome::Transient { retry_after: None };

    cells.observe("p", dest, Outcome::Success, now, &token);
    assert_eq!(first.store.error_rate_in("p", 0, now), Some(0.0));

    handle.swap(Arc::clone(&second));
    cells.observe("p", dest, fault, now, &token);
    assert_eq!(
        second.store.error_rate_in("p", 0, now),
        Some(1.0),
        "the record after the apply lands on the new generation's store"
    );
    assert_eq!(
        first.store.error_rate_in("p", 0, now),
        Some(0.0),
        "the retired store took nothing after the apply"
    );
}

#[test]
fn live_egress_borrows_its_owner_and_never_reverts_after_that_owner_retires() {
    let boot = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let retired_boot = Arc::downgrade(&boot);
    let slot = Arc::new(std::sync::OnceLock::new());
    let source = LiveApp::new(slot.clone(), boot.clone());
    assert!(
        Arc::ptr_eq(&source.load(), &boot),
        "boot remains usable before the handle exists"
    );
    let current = {
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let dialects: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked dialects are recorded");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the distribution links a model dialect");
        let models = "{}";
        let pools = "{}";
        let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        let store = crate::root::real_store::store();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
            Arc::new(crate::root::door_steps::Rules::default());
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(busbar_contract::store_calls::OpenedStore {
                records: store.clone(),
                calls: Some(store),
            }),
            false,
        )
        .expect("the product builds the configured model generation");
        limits
            .keep()
            .expect("the model generation commits its limits");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let owner = Arc::new(busbar_kernel::state::AppHandle::new(current.clone()));
    let _ = slot.set(Arc::downgrade(&owner));
    assert!(Arc::ptr_eq(&source.load(), &current));
    drop(boot);
    assert!(
        retired_boot.upgrade().is_none(),
        "the fallback is a backreference"
    );
    let owner_lifetime = Arc::downgrade(&owner);
    drop(owner);
    assert!(owner_lifetime.upgrade().is_none());
    assert!(
        source.try_load().is_none(),
        "a retired owner never selects its older fallback"
    );
}

#[test]
fn a_keyless_lane_is_not_probed() {
    crate::root::test_plane_registry::register();
    let mut defs = std::collections::HashMap::new();
    for name in ["keyed", "local"] {
        let def: busbar_kernel::config::ProviderDef =
            serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:9\n")
                .expect("a def");
        defs.insert(name.to_owned(), def);
    }
    let yaml = "providers:\n  \
                keyed:\n    api_key: { env: BUSBAR_TEST_KEY }\n    health: { mode: active }\n  \
                local:\n    api_key: none\n    health: { mode: active }\n\
                models:\n  m-keyed:\n    provider: keyed\n  m-local:\n    provider: local\n";
    let deploy = busbar_kernel::config::deploy_from_yaml_str(yaml).expect("parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    let serving = ModelServing {
        pools: ModelPools::of(&cfg),
        lanes: [("m-keyed".to_string(), 0), ("m-local".to_string(), 1)]
            .into_iter()
            .collect(),
        app: LiveApp::fixed({
            crate::dist_root_install::install();
            crate::root::test_plane_registry::register();
            let dialects: serde_json::Value =
                serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                    .expect("the actual linked dialects are recorded");
            let dialect = dialects["body_model"]
                .as_object()
                .and_then(|rows| rows.keys().next())
                .expect("the distribution links a model dialect");
            let models = "{}";
            let pools = "{}";
            let yaml = format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders:\n  wire:\n    protocol: {dialect}\n    base_url: http://127.0.0.1:9\n    api_key: none\nmodels: {models}\npools: {pools}\nadvanced:\n  allow_destinations: [127.0.0.1]\n"
    );
            let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
            let cfg =
                busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
            let store = crate::root::real_store::store();
            let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
                Arc::new(crate::root::door_steps::Rules::default());
            let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
                cfg,
                Default::default(),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
                Some(busbar_contract::store_calls::OpenedStore {
                    records: store.clone(),
                    calls: Some(store),
                }),
                false,
            )
            .expect("the product builds the configured model generation");
            limits
                .keep()
                .expect("the model generation commits its limits");
            if let Some(rotate) = rotate {
                rotate();
            }
            Arc::new(app)
        }),
    };
    let (_, members) = serving.probe_members();
    let probed: Vec<&str> = members.iter().map(|(_, m)| m.name.as_str()).collect();
    assert_eq!(
        probed,
        vec!["m-keyed"],
        "the keyed lane is probed and the keyless one is not"
    );
}
