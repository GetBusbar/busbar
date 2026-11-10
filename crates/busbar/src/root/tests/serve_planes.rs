// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_kernel::governance::GovState;
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};

use crate::root::plane_node::NodeEndPost;
use crate::root::test_plugins::{missing, BUILD_BUSBAR_EXAMPLES};

use super::{compose_planes, LateServices};
use crate::root::loader::dispatch::{
    load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
};

pub(crate) async fn money() -> Arc<PlaneMoney> {
    let gov = Arc::new(
        GovState::new_with_core(crate::root::real_store::core().await, None, None)
            .await
            .expect("governance"),
    );
    Arc::new(PlaneMoney::new(gov, post() as Arc<dyn EndPost>))
}

pub(super) fn post() -> Arc<NodeEndPost> {
    Arc::new(NodeEndPost::new(crate::root::plane_node::node()))
}

pub(crate) use crate::root::PUBLISHING;

fn dropped_path() -> std::path::PathBuf {
    let name = "plane_driver_test_plane";
    let exe = std::env::current_exe().expect("the test binary's path");
    let path = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary sits in target/<profile>/deps")
        .join("examples")
        .join(format!(
            "{}{name}{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
    if !path.exists() {
        missing(name, BUILD_BUSBAR_EXAMPLES);
    }
    path
}

pub(super) fn bound(instance: &str, dispatcher: &Arc<Dispatcher>) -> crate::root::boot::DoorPlane {
    let path = dropped_path();
    let stated = rendering_of_library(&path)
        .expect("the test plane's library reads")
        .expect("the test plane states its Statement");
    Arc::new(
        load_dropped(
            &path,
            &stated,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),

                conns: crate::root::loader::dispatch::ConnTable::Probe,
            },
        )
        .expect("the dropped-in door binds"),
    )
}

pub(crate) fn composed_services() -> Arc<LateServices> {
    let late = LateServices::new();
    let kernel = Arc::new(KernelServices::new());
    late.install_kernel(Arc::clone(&kernel), kernel)
        .expect("installed once");
    late
}

async fn admin(
    tables: &busbar_kernel::plane_driver::serve::ServeTables,
    path: &str,
) -> Option<u16> {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}{path}", busbar_kernel::api::ADMIN_PREFIX))
        .body(axum::body::Body::from("go"))
        .expect("a request");
    tables
        .answer(req)
        .await
        .map(|response| response.status().as_u16())
}

#[tokio::test]
async fn a_configured_door_plane_is_opened_driven_and_its_admin_routes_published() {
    crate::dist_root_install::install();
    let module = busbar_kernel::preflight::root_rows()
        .stores
        .first()
        .expect("the distribution links its actual Store")
        .0;
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module},
    }))
    .expect("the configured plane's application deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the application deployment resolves");
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(crate::root::real_store::core().await),
        false,
    )
    .await
    .expect("the normal application admits its native Store");
    limits.stage_boot();
    crate::root::door_steps::tests::boot_fixture_prices(&app).await;
    limits.keep().await.expect("the application limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("normal startup registers the durable administrative audit stream");
    let native_money = Arc::new(PlaneMoney::new(
        app.governance
            .as_ref()
            .expect("the admitted application owns governance")
            .clone(),
        post() as Arc<dyn EndPost>,
    ));
    let money = || native_money.clone();
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let instance = "serve-compose-configured";
    let _one = PUBLISHING.lock().await;
    let plane = bound(instance, &dispatcher);
    let doors = vec![(instance.to_string(), plane)];
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", serde_yaml::Value::Mapping(Default::default()));
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &sections,
        None,
        &money,
        None,
        None,
        &busbar_kernel::plane_driver::serve::ServeTables::default(),
    ).await
    .expect("the door plane composes (the plane_driver_test_plane example cdylib, current: run `cargo build --workspace --examples`)");
    assert_eq!(served.planes.len(), 1, "one plane composed");
    let p = &served.planes[0];
    assert_eq!(p.instance, instance);
    let claims: Vec<(&str, &str)> = p
        .snapshot
        .claims
        .iter()
        .map(|c| (c.verb.as_str(), c.target.as_str()))
        .collect();
    assert_eq!(
        claims,
        [("POST", "/call"), ("POST", "/open"), ("POST", "/framed")],
        "its open published its claims"
    );
    assert_eq!(
        admin(&served.tables, "/items/composed/act").await,
        Some(200),
        "its audited admin route is served by its `serve` op"
    );
    assert_eq!(
        admin(&served.tables, "/items/composed/hook").await,
        None,
        "a public route is never on the admin table"
    );
}

#[tokio::test]
async fn a_door_plane_whose_section_is_absent_stays_unopened() {
    let native_money = money().await;
    let money = || native_money.clone();
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let instance = "serve-compose-unconfigured";
    let plane = bound(instance, &dispatcher);
    let doors = vec![(instance.to_string(), plane)];
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &BTreeMap::new(),
        None,
        &money,
        None,
        None,
        &busbar_kernel::plane_driver::serve::ServeTables::default(),
    )
    .await
    .expect("nothing to compose is not a refusal");
    assert!(served.planes.is_empty(), "LAW 7: no section, no plane");
}

#[tokio::test]
async fn no_door_plane_composes_nothing_and_needs_no_services() {
    let native_money = money().await;
    let money = || native_money.clone();
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let served = compose_planes(
        &[],
        &dispatcher,
        &LateServices::new(),
        &BTreeMap::new(),
        None,
        &money,
        None,
        None,
        &busbar_kernel::plane_driver::serve::ServeTables::default(),
    )
    .await
    .expect("an empty composition");
    assert!(served.planes.is_empty());
}

#[test]
fn a_session_model_from_the_top_level_catalog_is_folded_into_the_route_table() {
    use crate::root::door_steps::DoorPools;
    use busbar_contract::abi::plane::ROUTE_DIRECT;
    let catalog: std::collections::HashMap<String, busbar_contract::config::ModelCfg> =
        serde_yaml::from_str(
            "gpt-rt: { provider: p, upstream_model: gpt-realtime, attempt_timeout_ms: 900 }\n",
        )
        .expect("the catalog");
    let section: serde_yaml::Value =
        serde_yaml::from_str("session: { model: gpt-rt }\nsession_max_secs: 60\n").expect("yaml");
    let routes = super::catalog_routes(&section, &catalog);
    assert_eq!(
        routes["models"]["gpt-rt"],
        serde_yaml::from_str::<serde_yaml::Value>(
            "{ provider: p, upstream_model: gpt-realtime, attempt_timeout_ms: 900 }"
        )
        .expect("yaml"),
        "the catalog entry's routing facts, folded"
    );
    assert_eq!(
        routes["session"], section["session"],
        "the section stays as written"
    );
    let pools =
        DoorPools::of(&routes, busbar_contract::section::RESERVED_POOLS_KEY).expect("the pools");
    assert_eq!(
        pools.resolve(ROUTE_DIRECT, Some(b"gpt-rt")),
        Some((String::new(), vec!["gpt-rt".to_string()])),
        "the door's DIRECT route resolves to the folded entry"
    );
    let unknown: serde_yaml::Value =
        serde_yaml::from_str("session: { model: nope }\n").expect("yaml");
    assert_eq!(super::catalog_routes(&unknown, &catalog), unknown);
    let own: serde_yaml::Value =
        serde_yaml::from_str("session: { model: gpt-rt }\nmodels: { mine: {} }\n").expect("yaml");
    assert_eq!(super::catalog_routes(&own, &catalog), own);
}

#[tokio::test]
async fn an_interpolated_credential_reaches_a_door_plane_as_its_reference_never_its_bytes() {
    crate::dist_root_install::install();
    let native_money = money().await;
    let money = || native_money.clone();
    const PLAIN: &str = "sk-plane-bound-PLAINTEXT-0001";
    const RESOLVED: &str = "sk-plane-bound-RESOLVED-0002";
    let pid = std::process::id();
    let plain_var = format!("BUSBAR_PLANE_BOUND_SECRET_{pid}");
    let ref_var = format!("BUSBAR_PLANE_BOUND_REF_{pid}");
    let host_var = format!("BUSBAR_PLANE_BOUND_HOST_{pid}");
    let sources = busbar_kernel::preflight::root_rows()
        .secret_axis
        .expect("the distribution admits its source declarations")
        .sugars();
    let seal = busbar_kernel::seal::acquire();
    let reference = |name: &str| {
        serde_json::to_value(
            sources
                .reference_for_role(busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL, name)
                .expect("the admitted source supplies the interpolation role")
                .authoring(&seal),
        )
        .expect("an authorized authored reference")
    };
    let whole = reference(&plain_var);
    let written_reference = reference(&ref_var);
    let part = serde_json::to_value(
        busbar_contract::secret_ref::SecretRef::template(
            format!("Bearer ${{{plain_var}}}"),
            &sources,
        )
        .expect("the template binds to the admitted source")
        .authoring(&seal),
    )
    .expect("an authorized template reference");
    std::env::set_var(&plain_var, PLAIN);
    std::env::set_var(&ref_var, RESOLVED);
    std::env::set_var(&host_var, "upstream.invalid");
    let dir = std::env::temp_dir().join(format!("busbar-plane-bound-{pid}"));
    let template = format!(
        r#"
test_plane:
  capture_to: "{dir}"
  reg1:
    url: "http://${{{host_var}}}/v1"
    api_key: {written_reference}
    token: "${{{plain_var}}}"
    args: ["--flag", "${{{host_var}}}"]
    env:
      WHOLE: "${{{plain_var}}}"
      PART: "Bearer ${{{plain_var}}}"
test_plane_owned:
  reg: {{api_key: "${{{plain_var}}}", ref: {written_reference}, url: "http://${{{host_var}}}/o"}}
"#,
        dir = dir.display()
    );
    let text = busbar_kernel::config::interpolate_env_with(
        &template,
        busbar_kernel::config::EnvSubst::Strict,
        &mut Vec::new(),
    )
    .expect("interpolates");
    let doc: serde_yaml::Mapping = serde_yaml::from_str(&text).expect("parses");
    let mut sections = BTreeMap::new();
    for key in ["test_plane", "test_plane_owned"] {
        sections.insert(key, doc.get(key).cloned().expect("written"));
    }
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let instance = "serve-compose-plane-bound";
    let _one = PUBLISHING.lock().await;
    let plane = bound(instance, &dispatcher);
    let doors = vec![(instance.to_string(), plane)];
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &sections,
        None,
        &money,
        None,
        None,
        &busbar_kernel::plane_driver::serve::ServeTables::default(),
    )
    .await
    .expect("the door plane composes");
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    served.planes[0]
        .live
        .refreshed(
            &sections["test_plane"],
            &sections["test_plane"],
            &serde_json::Map::new(),
            2,
            secrets,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .await
        .expect("the plane refreshes");

    let read = |name: &str| {
        String::from_utf8_lossy(&std::fs::read(dir.join(name)).unwrap_or_default()).into_owned()
    };
    for name in ["open.settings", "open.owned", "refresh.settings"] {
        let text = read(name);
        assert!(!text.is_empty(), "the plane recorded its {name}");
        assert!(
            !text.contains(PLAIN),
            "{name} carries the secret's bytes: {text}"
        );
        assert!(
            !text.contains(RESOLVED),
            "{name} carries a resolved reference: {text}"
        );
    }
    for name in ["open.settings", "refresh.settings"] {
        let text = read(name);
        let settings: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(settings["reg1"]["token"], whole, "{name}: {text}");
        let env = &settings["reg1"][busbar_contract::conn::PROGRAM_ENV_KEY];
        assert_eq!(env["WHOLE"], whole, "{name}: {text}");
        assert_eq!(env["PART"], part, "{name}: {text}");
        assert_eq!(
            settings["reg1"]["api_key"], written_reference,
            "{name}: {text}"
        );

        assert_eq!(
            settings["reg1"]["url"], "http://upstream.invalid/v1",
            "{name}: {text}"
        );
        assert_eq!(
            settings["reg1"]["args"],
            serde_json::json!(["--flag", "upstream.invalid"]),
            "{name}: {text}"
        );
    }
    let text = read("open.owned");
    let owned: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(owned["test_plane_owned"]["reg"]["api_key"], whole, "{text}");
    assert_eq!(
        owned["test_plane_owned"]["reg"]["ref"], written_reference,
        "{text}"
    );
    assert_eq!(
        owned["test_plane_owned"]["reg"]["url"], "http://upstream.invalid/o",
        "{text}"
    );
}

#[test]
fn a_door_plane_is_handed_its_referenced_providers_dialect_facts_at_open() {
    use crate::root::door_steps::{dialect_facts, ProviderRoute, StyleParams};
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let plane = bound("serve-open-dialect-facts", &dispatcher);

    let _late = composed_services();
    let route = |protocol: &str, error_map: &[(&str, &str)]| ProviderRoute {
        base_url: "http://127.0.0.1:9".to_string(),
        userinfo: None,
        protocol: protocol.to_string(),
        error_map: error_map
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        credential: busbar_contract::secret_ref::SecretRef::none(),
        style: None,
        params: StyleParams::default(),
        metadata: busbar_kernel::config_validate::MetadataPosture::default(),
    };
    let providers: BTreeMap<String, ProviderRoute> = [
        ("eng-b".to_string(), route("dial-two", &[])),
        (
            "eng-a".to_string(),
            route("dial-one", &[("429", "rate_limited")]),
        ),
        ("unused".to_string(), route("dial-one", &[])),
    ]
    .into_iter()
    .collect();
    let section: serde_yaml::Value = serde_yaml::from_str(
        "models:\n  m1: {provider: eng-a}\n  m2: {provider: eng-b}\n  m3: {provider: eng-a}\n",
    )
    .expect("a section");
    let facts = dialect_facts(&section, &providers);
    let names: Vec<&str> = facts.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["eng-a", "eng-b"], "referenced, once each, in order");
    let snapshot = super::open(
        &plane,
        &["test_plane"],
        &section,
        None,
        &Default::default(),
        &facts,
    )
    .expect("the door opens");
    let handed: serde_json::Value = serde_json::from_slice(
        snapshot
            .resource_facts
            .as_deref()
            .expect("the plane was handed its providers' facts"),
    )
    .expect("JSON");
    assert_eq!(
        handed,
        serde_json::json!([
            ["eng-a", "dial-one", {"429": "rate_limited"}],
            ["eng-b", "dial-two", null]
        ])
    );
    let none = dialect_facts(&serde_yaml::Value::Null, &providers);
    assert!(none.is_empty(), "a section that references none hands none");

    let plane = bound("serve-open-dialect-none", &dispatcher);
    let snapshot = super::open(
        &plane,
        &["test_plane"],
        &serde_yaml::Value::Null,
        None,
        &Default::default(),
        &none,
    )
    .expect("the door opens");
    assert_eq!(snapshot.resource_facts, None);
}

pub(crate) type ChainedRecords = (String, Vec<(Vec<u8>, u64)>);

pub(crate) async fn chained_records(
    store: &Arc<busbar_kernel::persistence::facade::CoreStore>,
    instance: &str,
    kind: &'static str,
    framing: busbar_contract::abi::plane::RecordChain,
    want: usize,
) -> ChainedRecords {
    use busbar_contract::services::chain_key_parts;
    let schema = busbar_contract::ids::RecordSchemaId::new(kind);
    let store = busbar_kernel::persistence::scoped::ScopedStore::authorized(
        store.clone(),
        instance,
        [kind.to_string()],
    )
    .expect("authorized instance records");
    let framing =
        busbar_kernel::host_chains::ChainFraming::of(&framing).expect("host chain framing");
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let rows = loop {
        let mut rows = Vec::new();
        let mut after = None;
        loop {
            let page = store
                .page(kind, b"", after.as_ref())
                .await
                .expect("native chain page");
            rows.extend(
                page.rows
                    .into_iter()
                    .map(|(key, value)| (key, value.expose(&busbar_kernel::seal::lend()).clone())),
            );
            after = page.next;
            if after.is_none() {
                break;
            }
        }
        if rows.len() >= want || tokio::time::Instant::now() >= until {
            break rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    let read = busbar_kernel::host_chains::verified(instance, schema, rows, framing);
    let records = read
        .iter()
        .map(|(key, value)| {
            let (scope, seq) = chain_key_parts(key).unwrap_or_else(|| {
                panic!(
                    "a chain that does not verify: {}",
                    String::from_utf8_lossy(value)
                )
            });
            (scope.to_vec(), seq)
        })
        .collect();
    (instance.to_string(), records)
}

#[test]
#[should_panic(expected = "is not built: run")]
fn a_missing_fixture_cdylib_fails_the_test_and_names_its_build() {
    missing("no_such_fixture", BUILD_BUSBAR_EXAMPLES);
}

#[tokio::test]
async fn a_pools_refresh_whose_snapshot_the_host_refuses_is_retired() {
    let native_money = money().await;
    let money = || native_money.clone();
    use crate::root::loader::dispatch::kinds::plane::ServedFacts;
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("busbar-pools-refresh-refused-{pid}"));
    let _ = std::fs::remove_dir_all(&dir);
    let section: serde_yaml::Value = serde_yaml::from_str(&format!(
        "capture_to: \"{}\"\nunchecked_refresh: true\n",
        dir.display()
    ))
    .expect("yaml");
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", section);
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let instance = "serve-pools-refresh-refused";
    let _one = PUBLISHING.lock().await;
    let plane = bound(instance, &dispatcher);
    let late = composed_services();
    let served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &late,
        &sections,
        None,
        &money,
        None,
        None,
        &busbar_kernel::plane_driver::serve::ServeTables::default(),
    )
    .await
    .expect("the door plane composes");
    let composed = &served.planes[0].live;
    let pools = Arc::new(super::DoorApply {
        observations_supported: composed.observations_supported,
        plugin: Arc::clone(&composed.plugin),
        dispatcher: Arc::clone(&composed.dispatcher),
        served_facts: ServedFacts {
            section: busbar_contract::section::RESERVED_POOLS_KEY,
            ..composed.served_facts.clone()
        },
        facts: composed.facts.clone(),
        reach: None,
        live: std::sync::RwLock::new(composed.current()),
        driver: Arc::clone(&composed.driver),
        probe_schedule: Arc::clone(&composed.probe_schedule),
        scope_kinds: composed.scope_kinds.clone(),
        clock: Arc::clone(&composed.clock),
        units: Arc::clone(&composed.units),
    });
    let kept = pools.current().generation;
    let providers = BTreeMap::new();
    let reach = crate::root::door_steps::DoorReach {
        providers: &providers,
        secrets: Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
        auths: Arc::new(crate::root::door_steps::OutboundAuths::new(
            Arc::clone(&dispatcher),
            crate::LINKED.auths,
            None,
            crate::root::loader::dispatch::ConnTable::NoNeeds,
            busbar_kernel::diagnostics::Catalogue::NEUTRAL,
        )),
        conns: Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let mut applied = BTreeMap::new();
    applied.insert(
        busbar_contract::section::RESERVED_POOLS_KEY,
        serde_yaml::Value::Mapping(Default::default()),
    );
    super::DoorAppliers(vec![Arc::clone(&pools)]).refresh_models(
        &applied,
        &super::DoorEgress {
            reach: &reach,
            journal: post() as Arc<dyn busbar_kernel_egress::ports::Journal>,
        },
    );
    assert_eq!(
        pools.current().generation,
        kept,
        "the host keeps serving its generation"
    );
    assert!(
        dir.join(format!("retired.{}", kept + 1)).exists(),
        "the generation the host refused was retired at the plane"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn door_refresh_failure_classification_preserves_typed_bootstrap_refusal() {
    use super::DoorRefreshError;
    use busbar_kernel::host_services::AdmitRefused;
    use busbar_kernel::state::activation::RefreshFailure;
    let held = DoorRefreshError::Admission(AdmitRefused::BootstrapHeld {
        instance: "private-label".into(),
    });
    assert_eq!(held.classification(), RefreshFailure::BootstrapHeld);
    // Display-like text alone must never invent a restart remedy.
    let generic = DoorRefreshError::from(held.to_string());
    assert_eq!(generic.classification(), RefreshFailure::RefreshFailed);
}
