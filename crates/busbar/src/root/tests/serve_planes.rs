// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' COMPOSITION, over the test plane
//! dropped in (its `plane_driver_test_plane` example `cdylib`, admitted against the Statement its
//! own library states; the binary forbids unsafe code, so the fixture's source is never compiled
//! into it): a bound plane whose section the deployment writes is opened, driven and its admin
//! routes published; one whose section is absent stays unopened (LAW 7).

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_kernel::governance::{GovState, MemoryStore};
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};

use crate::root::plane_node::NodeEndPost;
use crate::root::test_plugins::{missing, BUILD_BUSBAR_EXAMPLES};

use super::{compose_planes, LateServices};
use crate::root::loader::dispatch::{
    load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
};

/// The money steps of a composition: an ungoverned book (a unit that runs here admits nothing that
/// bills), posting abandoned ends onto the process's one node.
pub(crate) fn money() -> Arc<PlaneMoney> {
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("governance"));
    Arc::new(PlaneMoney::new(gov, post() as Arc<dyn EndPost>))
}

/// The process's one posting site, over its one node.
pub(super) fn post() -> Arc<NodeEndPost> {
    Arc::new(NodeEndPost::new(crate::root::plane_node::node()))
}

/// THE OPERATOR AUDIT RING IS THE PROCESS'S ONE: a test that counts the audit rows its door's
/// admin routes sealed holds this while it does ([`crate::root::PUBLISHING`]). Each composition
/// publishes its admin routes into its own generation's table (`App::serve_tables`), so no test
/// withdraws another's.
pub(crate) use crate::root::PUBLISHING;

/// The test plane's example `cdylib` beside this test binary. Not built is a failure in every run,
/// never a skip: a composition proof without its plane proves nothing.
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

/// The test plane, dropped in and bound on `dispatcher` as `instance`.
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
                // These rows never dial (the plane's far end is not reached): its need is not
                // declared, bound as a probe.
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

/// An admin request on `tables`, the admin router's plane table: its status, or `None` (the
/// router's 404).
fn admin(tables: &busbar_kernel::plane_driver::serve::ServeTables, path: &str) -> Option<u16> {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}{path}", busbar_kernel::api::ADMIN_PREFIX))
        .body(axum::body::Body::from("go"))
        .expect("a request");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async { tables.answer(req).await.map(|r| r.status().as_u16()) })
}

#[test]
fn a_configured_door_plane_is_opened_driven_and_its_admin_routes_published() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-configured";
    let _one = PUBLISHING.blocking_lock();
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
    )
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
        admin(&served.tables, "/items/composed/act"),
        Some(200),
        "its audited admin route is served by its `serve` op"
    );
    assert_eq!(
        admin(&served.tables, "/items/composed/hook"),
        None,
        "a public route is never on the admin table"
    );
}

#[test]
fn a_door_plane_whose_section_is_absent_stays_unopened() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
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
    .expect("nothing to compose is not a refusal");
    assert!(served.planes.is_empty(), "LAW 7: no section, no plane");
}

#[test]
fn no_door_plane_composes_nothing_and_needs_no_services() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
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
    .expect("an empty composition");
    assert!(served.planes.is_empty());
}

/// THE CATALOG ROUTE (ARCHITECT Q-L5B-ROUTE, 2026-10-03): a section whose `session.model` names a
/// top-level catalog model has that entry folded into its route table, so the door steps resolve the
/// door's DIRECT route to it (unchanged); a section with its own `models:`, or naming a model the
/// catalog lacks, keeps its table as written. The settings the door opens with are never folded.
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
    let pools = DoorPools::of(&routes).expect("the pools");
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

/// A PLANE NEVER RECEIVES SECRET BYTES (THE DESIGN §6; SECURITY ruling 2026-10-07). `${VAR}` is
/// spliced into the config text before it is parsed, so its plaintext used to reach a door plane's
/// `open` settings, its owned sections and its `refresh` settings. The test plane records the bytes
/// it is handed at the ABI. At every CREDENTIAL position (`token`, `api_key`, a program's `env`) the
/// blobs carry the reference: `{ env: VAR }` for a whole value, a template reference for a part.
/// An operator-written reference crosses as written, unresolved. Every other position (`url`,
/// `args`, `command`) keeps the load-time interpolation, as 1.5.5 handed it on.
#[test]
fn an_interpolated_credential_reaches_a_door_plane_as_its_reference_never_its_bytes() {
    const PLAIN: &str = "sk-plane-bound-PLAINTEXT-0001";
    const RESOLVED: &str = "sk-plane-bound-RESOLVED-0002";
    let pid = std::process::id();
    let plain_var = format!("BUSBAR_PLANE_BOUND_SECRET_{pid}");
    let ref_var = format!("BUSBAR_PLANE_BOUND_REF_{pid}");
    let host_var = format!("BUSBAR_PLANE_BOUND_HOST_{pid}");
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
    api_key: {{env: {ref_var}}}
    token: "${{{plain_var}}}"
    args: ["--flag", "${{{host_var}}}"]
    env:
      WHOLE: "${{{plain_var}}}"
      PART: "Bearer ${{{plain_var}}}"
test_plane_owned:
  reg: {{api_key: "${{{plain_var}}}", ref: {{env: {ref_var}}}, url: "http://${{{host_var}}}/o"}}
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
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-plane-bound";
    let _one = PUBLISHING.blocking_lock();
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
    .expect("the door plane composes");
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    served.planes[0]
        .live
        .refreshed(
            &sections["test_plane"],
            // A plane that reads no section beside its own is handed its section bare.
            &sections["test_plane"],
            &serde_json::Map::new(),
            2,
            secrets,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("the plane refreshes");

    let read = |name: &str| {
        String::from_utf8_lossy(&std::fs::read(dir.join(name)).unwrap_or_default()).into_owned()
    };
    let whole = serde_json::json!({ (busbar_contract::secret_ref::SECRET_MODULE_ENV): plain_var });
    let part = serde_json::to_value(busbar_contract::secret_ref::SecretRef::template(format!(
        "Bearer ${{{plain_var}}}"
    )))
    .expect("a reference");
    let written_reference =
        serde_json::json!({ (busbar_contract::secret_ref::SECRET_MODULE_ENV): ref_var });
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
        // Not a credential field: the load-time interpolation, as 1.5.5 handed it on.
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

/// RED, THE DIALECT FACTS AT OPEN (THE DESIGN §4: a plane receives, at open, the dialect fields of
/// the providers it references): the providers its section's `models.<m>.provider` entries name,
/// once each in the order first referenced, cross `PlaneOpenIn::providers` with their resolved
/// `protocol` and `error_map` (absent when none). An unreferenced provider is not handed, and a
/// section that references none hands none. The test plane echoes what it was handed.
#[test]
fn a_door_plane_is_handed_its_referenced_providers_dialect_facts_at_open() {
    use crate::root::door_steps::{dialect_facts, ProviderRoute, StyleParams};
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plane = bound("serve-open-dialect-facts", &dispatcher);
    // The kernel's host services the plane's open is handed, as a composition installs them.
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
    // A second instance (an instance opens once): a section that references none is handed none.
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

/// THE CHAINED RECORDS of record kind `kind` in `store`, read back as the host's verified read
/// answers them (`busbar_kernel::host_chains::verified`, the one chain mechanism, over the kind's
/// declared `framing`): the one instance that wrote them, and each record's `(scope, sequence)` in
/// key order. A chain that does not verify is announced by a span keyed by its bare scope, which
/// this refuses, so a broken link fails the read. The flush is write-behind: the read waits up to
/// five seconds for at least `want` records to land.
/// One instance's chained records: its label, and each record's `(scope, sequence)`.
pub(crate) type ChainedRecords = (String, Vec<(Vec<u8>, u64)>);

pub(crate) fn chained_records(
    store: &MemoryStore,
    kind: &'static str,
    framing: busbar_contract::abi::plane::RecordChain,
    want: usize,
) -> ChainedRecords {
    use busbar_contract::services::chain_key_parts;
    let schema = busbar_contract::ids::RecordSchemaId::new(kind);
    let framing =
        busbar_kernel::host_chains::ChainFraming::of(&framing).expect("a framing this host keeps");
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let rows = loop {
        let rows = store.record_scan(schema, b"", u32::MAX).expect("a read");
        if rows.len() >= want || std::time::Instant::now() >= until {
            break rows;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    type Rows = Vec<(Vec<u8>, Vec<u8>)>;
    let mut by_instance: BTreeMap<String, Rows> = BTreeMap::new();
    for (key, value) in rows {
        let len = usize::from(u16::from_be_bytes([key[0], key[1]]));
        let label = String::from_utf8(key[2..2 + len].to_vec()).expect("a label");
        by_instance
            .entry(label)
            .or_default()
            .push((key[2 + len..].to_vec(), value.as_slice().to_vec()));
    }
    assert!(
        by_instance.len() <= 1,
        "one instance's records: {:?}",
        by_instance.keys().collect::<Vec<_>>()
    );
    let Some((instance, rows)) = by_instance.into_iter().next() else {
        return (String::new(), Vec::new());
    };
    let read = busbar_kernel::host_chains::verified(&instance, schema, rows, framing);
    let records: Vec<(Vec<u8>, u64)> = read
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
    (instance, records)
}

/// THE RED ARM OF "NEVER SKIPS": a fixture that is not built fails the test, naming what builds it.
#[test]
#[should_panic(expected = "is not built: run")]
fn a_missing_fixture_cdylib_fails_the_test_and_names_its_build() {
    missing("no_such_fixture", BUILD_BUSBAR_EXAMPLES);
}

/// RED (row 159): a config apply onto the door serving the `pools` map
/// ([`super::DoorAppliers::refresh_models`]) whose plane answers its `refresh` READY with a
/// snapshot the host's checks refuse retires that generation, so the plane never keeps the
/// generation the host refused as its newest: it answers from the one the host keeps serving.
/// The test plane is composed, then applied as the door serving `pools` (the same instance, its
/// served section that map's); opened `unchecked_refresh`, its refreshed snapshot states an
/// arrival span the host's copy refuses, and it records each generation it retires.
///
/// RED before: `refresh_models` kept its generation and left the refused one unretired (no
/// `retired.<next>` recorded); it retired only a generation whose seal failed.
#[test]
fn a_pools_refresh_whose_snapshot_the_host_refuses_is_retired() {
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
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-pools-refresh-refused";
    let _one = PUBLISHING.blocking_lock();
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
    .expect("the door plane composes");
    let composed = &served.planes[0].live;
    let pools = Arc::new(super::DoorApply {
        plugin: Arc::clone(&composed.plugin),
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
