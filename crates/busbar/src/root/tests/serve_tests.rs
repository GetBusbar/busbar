// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(any(linked_driver_proofs, linked_axis_plane_door))]
pub(crate) fn independent_cases(test: &str, cases: &[&str]) -> Option<String> {
    if std::env::var("BUSBAR_SERVE_INDEPENDENT_TEST").as_deref() == Ok(test) {
        let case = std::env::var("BUSBAR_SERVE_INDEPENDENT_CASE").unwrap();
        assert!(cases.contains(&case.as_str()));
        return Some(case);
    }
    let exact = test.split_once("::").unwrap().1;
    for case in cases {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", exact, "--nocapture"])
            .env("BUSBAR_SERVE_INDEPENDENT_TEST", test)
            .env("BUSBAR_SERVE_INDEPENDENT_CASE", case)
            .output()
            .expect("run the exact independent native deployment case");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{case}: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(&format!("SERVE-CASE-DONE {test} {case}")),
            "the independent case must execute its assertions: {stdout}"
        );
    }
    None
}
#[cfg(any(linked_driver_proofs, linked_axis_plane_door))]
pub(crate) fn independent_case_done(test: &str, case: &str) {
    println!("SERVE-CASE-DONE {test} {case}");
}

// A nextest process represents one deployment; sequential rigs are generations
// of it. Keep its native authority with the process-global price holder.
pub(crate) async fn process_store() -> std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>
{
    static STORE: tokio::sync::OnceCell<
        std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>,
    > = tokio::sync::OnceCell::const_new();
    STORE
        .get_or_init(crate::root::real_store::core)
        .await
        .clone()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_process_app(
    cfg: busbar_kernel::config::RootCfg,
    plugins: busbar_kernel::config::PluginsCfg,
    overlay: Option<std::sync::Arc<busbar_kernel::config::overlay::OverlayStore>>,
    base_hooks: std::collections::HashSet<String>,
    base_groups: std::collections::HashSet<String>,
    paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&busbar_kernel::state::App>,
    rules: &std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> Result<
    (
        busbar_kernel::state::App,
        Option<busbar_kernel::GovCredentialRotation>,
        busbar_kernel::InstalledLimits,
    ),
    String,
> {
    let core = process_store().await;
    if let Some(prior) = prior {
        assert!(std::sync::Arc::ptr_eq(
            &core,
            &prior
                .governance
                .as_ref()
                .unwrap()
                .core_store_handle()
                .unwrap()
        ));
    }
    busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        plugins,
        overlay,
        base_hooks,
        base_groups,
        paths,
        prior,
        rules,
        Some(core),
        false,
    )
    .await
}

pub(crate) async fn attach_process_prices(app: &busbar_kernel::state::App) -> Result<(), String> {
    let store = app
        .governance
        .as_ref()
        .ok_or("fixture governance is absent")?
        .core_store_handle()
        .map_err(|e| e.to_string())?;
    assert!(
        std::sync::Arc::ptr_eq(&store, &process_store().await),
        "every generation keeps this process's admitted Store"
    );
    if let Some(previous) = crate::root::kernel::ROOT_CARD.card_store() {
        assert!(
            previous.is_bound_to(&store),
            "a fixture cannot publish through another deployment's price Store"
        );
        return Ok(());
    }
    crate::root::kernel::ROOT_CARD.keep_in_store(store, busbar_kernel::door::op_id().counter())?;
    crate::root::kernel::ROOT_CARD.boot_in_store(None).await
}

pub(crate) async fn bind_process_amendments(
    book: &mut std::sync::Arc<std::sync::Mutex<crate::root::durability::Durability>>,
    amendments: &busbar_kernel_audit::amend::NodeAmendments,
) {
    let token = crate::root::kernel::new_kernel().durability_token();
    std::sync::Arc::get_mut(book)
        .expect("bootstrap owns the native book before sharing")
        .get_mut()
        .unwrap()
        .restore_amendments(amendments, &token)
        .await
        .expect("the fixture restores its actual native amendment history");
    crate::root::durability::bind_amendments(book, amendments)
        .await
        .expect("content handoffs use this same native journal");
}

pub(crate) fn metric_sum(name: &str, labels: &[(&str, &str)]) -> f64 {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    busbar_kernel::snapshot::snapshot()
        .expect("the real metrics recorder is installed")
        .iter()
        .flat_map(|family| &family.samples)
        .filter(|sample| {
            sample.name == name
                && labels
                    .iter()
                    .all(|&(key, value)| sample.labels.iter().any(|(k, v)| k == key && v == value))
        })
        .map(|sample| sample.value.parse::<f64>().expect("a numeric sample"))
        .sum()
}

#[tokio::test]
async fn an_empty_plane_set_still_stages_the_core_listener_lines() {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    let _publishing = crate::root::PUBLISHING.lock().await;
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = crate::root::test_plugins::scratch("serve-empty-plane-set");
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the empty-plane deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the empty-plane deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::serve::door_tests::build_process_app(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the empty-plane deployment");
    limits.stage_boot();
    crate::root::serve::door_tests::attach_process_prices(&app)
        .await
        .expect("native process price history");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = std::sync::Arc::new(app);
    crate::root::inbound::stage(busbar_kernel::guest::GuestList::default(), Vec::new());
    super::door_mounts(
        super::Served::default(),
        || None,
        &[],
        &[("/healthz".into(), RouteMethod::Get, RouteAuth::None)],
        &[],
        &[],
    )
    .unwrap();
    let generation =
        crate::root::inbound::publish(&app).expect("the no-plane listener is published");
    let specs = crate::root::inbound::host()
        .specs(crate::root::inbound::ROOT_OWNER, generation)
        .unwrap();
    assert_eq!(
        specs.len(),
        1,
        "a real core listener line survives without a plane claim"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn detached_session_caller_preserves_text_and_closes_its_pipe_on_worker_shutdown() {
    use busbar_kernel::plane_driver::{CallerEnd as _, SessionCaller as _};
    use std::future::Future as _;
    let tracker = busbar_kernel::detached::DetachedTasks::new();
    busbar_kernel::detached::set_worker_detached(tracker.clone());
    let (shutdown, stopped) = tokio::sync::watch::channel(false);
    busbar_kernel::detached::set_worker_shutdown(stopped);
    let (from, input) = tokio::sync::mpsc::channel(super::SESSION_QUEUE);
    let (output, mut to) = tokio::sync::mpsc::channel(super::SESSION_QUEUE);
    let caller = super::ClosingCaller::new(super::PipeCaller {
        from: tokio::sync::Mutex::new(input),
        to: output,
    });
    assert!(caller.write_text(b"session text").await);
    let text = to.recv().await.unwrap();
    assert!(
        text.text,
        "the shutdown wrapper preserves the caller's text framing"
    );
    assert_eq!(text.bytes, b"session text");
    let task = busbar_kernel::detached::spawn_detached(async move { caller.read().await });
    let mut drain = Box::pin(tracker.drained());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(drain.as_mut().poll(&mut context).is_pending());
    shutdown.send(true).unwrap();
    assert!(
        task.await.unwrap().is_none(),
        "shutdown ends the pending caller read"
    );
    drain.await;
    assert!(
        from.is_closed(),
        "the session releases its accepted input after closing"
    );
    assert!(
        to.recv().await.is_none(),
        "the session releases its output after closing"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_listener_subscribed_after_the_shutdown_broadcast_observes_the_level() {
    let (broadcast, _earlier) = tokio::sync::broadcast::channel(1);
    broadcast.send(()).unwrap();
    let (shutdown, stopped) = tokio::sync::watch::channel(false);
    busbar_kernel::detached::set_worker_shutdown(stopped);
    shutdown.send(true).unwrap();
    tokio::time::timeout(
        busbar_kernel::detached::DETACHED_DRAIN_GRACE,
        crate::recv_shutdown(broadcast.subscribe()),
    )
    .await
    .expect("a late listener cannot miss the process shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn a_dropped_session_future_closes_its_admitted_carrier() {
    let (started, running) = tokio::sync::oneshot::channel();
    let (ended, closed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _carrier = super::CarrierEnd {
            unit: busbar_contract::UnitKey::new(1).get(),
            ended: Some(Box::new(move |unit| {
                let _ = ended.send(unit);
            })),
        };
        let _ = started.send(());
        std::future::pending::<()>().await;
    });
    running.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        closed.await.unwrap(),
        busbar_contract::UnitKey::new(1).get()
    );
}

#[cfg(linked_axis_plane_door)]
#[test]
fn linked_plane_minimal_configuration_fixtures_parse() {
    crate::dist_root_install::install();
    let mut supplied = std::collections::BTreeMap::new();
    for (section, value) in super::door_cells_minimal_configs() {
        assert!(
            supplied.insert(section, value).is_none(),
            "duplicate owner configuration fixture for {section}"
        );
    }
    let declarations = busbar_kernel::plane_driver::registry::plane_decls();
    for declaration in declarations {
        let value = supplied
            .remove(declaration.config_section)
            .unwrap_or_else(|| panic!("missing owner fixture for {}", declaration.config_section));
        if declaration.fallback {
            continue;
        }
        let parse = declaration
            .parse_section
            .expect("nonfallback plane exposes its configuration parser");
        let yaml = serde_yaml::to_value(value).expect("owner configuration converts to YAML");
        parse(declaration, &yaml).unwrap_or_else(|error| {
            panic!(
                "{} owner fixture does not parse: {error}",
                declaration.config_section
            )
        });
    }
    assert!(
        supplied.is_empty(),
        "owner fixtures have no registered plane: {supplied:?}"
    );
}
