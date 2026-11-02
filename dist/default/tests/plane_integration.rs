// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked {
    use busbar_kernel::plane_driver::registry::PlaneDecl;
    pub(super) fn install() {
        crate::dist_root_install::install();
    }
    pub(super) fn planes() -> &'static [&'static PlaneDecl] {
        install();
        busbar_kernel::plane_driver::registry::plane_decls()
    }
    pub(super) fn owning(section: &str) -> &'static PlaneDecl {
        planes()
            .iter()
            .copied()
            .find(|decl| {
                decl.config_section == section || decl.owned_config_sections.contains(&section)
            })
            .expect("the actual distribution declares the configured section")
    }
    pub(super) fn fallback() -> &'static PlaneDecl {
        planes()
            .iter()
            .copied()
            .find(|decl| decl.fallback)
            .expect("the actual distribution declares its fallback")
    }
    pub(super) fn door_section(decl: &PlaneDecl) -> &'static str {
        decl.owned_config_sections
            .first()
            .copied()
            .unwrap_or(decl.config_section)
    }
}

use busbar_kernel::config::RootCfg;
use busbar_kernel::plane_driver::registry::{BuildCtx, PlaneDecl};
#[path = "../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;
use std::sync::Arc;

fn door_plane() -> &'static PlaneDecl {
    linked::owning("tools")
}

fn agents_plane() -> &'static PlaneDecl {
    linked::owning("agents")
}

fn door_section_yaml(host: &str) -> String {
    let door = door_plane();
    format!(
        "{section}:\n  canonical_uri: \"https://{host}/{key}\"\n  \
         authorization_servers: [\"https://login.example.com\"]\n",
        section = linked::door_section(door),
        key = door.key,
    )
}

fn agents_yaml(peer: &crate::root::door_steps::tests::tool_door::TlsToolServer) -> String {
    format!("agents:\n  planner: {{ url: \"https://127.0.0.1:{}/rpc\", pin: {{ mechanism: cert_spki, key: \"{}\" }} }}\n", peer.port, peer.pin)
}

fn resolved(sections: &str) -> RootCfg {
    linked::install();
    let yaml = format!(
        "store: {{module: memory}}\n\
         providers:\n  acme: {{ api_key: none }}\n\
         models:\n  m: {{ provider: acme }}\n{sections}"
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("the document parses");
    let mut defs = std::collections::HashMap::new();
    defs.insert(
        "acme".to_string(),
        serde_yaml::from_str(&format!(
            "protocol: {}\nbase_url: https://api.example.com\n",
            (linked::fallback().provider_dialects)(linked::fallback())
                .first()
                .expect("the actual fallback declares provider dialects")
        ))
        .expect("provider def"),
    );
    busbar_kernel::config::resolve(&deploy, &defs)
        .unwrap_or_else(|e| panic!("the document resolves: {e:?}"))
}

fn bootable(sections: &str) -> RootCfg {
    let mut cfg = resolved(sections);
    cfg.public_url = Some("https://busbar.example".to_string());
    cfg.auth = Some(busbar_kernel::config::AuthCfg::default_none());
    cfg
}

fn built_planes(cfg: &RootCfg) -> Vec<(&'static PlaneDecl, Arc<dyn std::any::Any + Send + Sync>)> {
    linked::planes()
        .iter()
        .copied()
        .filter(|d| cfg.plane_sections.contains(d.config_section))
        .filter_map(|decl| {
            let ctx = BuildCtx {
                endpoint_slot: cfg.endpoint_resources.get(decl.config_section).cloned(),
                plane_defs: &cfg.plane_defs,
                public_url: cfg.public_url.as_deref(),
                prior: None,
                providers: None,
            };
            (decl.build)(decl, &ctx).map(|obj| (decl, obj))
        })
        .collect()
}

fn jsonrpc_mount(decl: &'static PlaneDecl, sections: &str) -> String {
    let mut cfg = resolved(sections);
    cfg.public_url = Some("https://busbar.example".to_string());
    let (_, obj) = built_planes(&cfg)
        .into_iter()
        .find(|(d, _)| d.key == decl.key)
        .unwrap_or_else(|| panic!("the `{}` plane builds from its section", decl.key));
    let audience_path = (decl.admission)(&*obj)
        .and_then(|a| url::Url::parse(&a.audience).ok())
        .map(|u| u.path().trim_end_matches('/').to_string());
    let jsonrpc: Vec<String> = (decl.claims)(&*obj)
        .into_iter()
        .filter(|(_, wire)| *wire == busbar_kernel::plane_driver::dispatch::WIRE_JSONRPC)
        .map(|(path, _)| path)
        .collect();
    jsonrpc
        .iter()
        .find(|path| Some(path.as_str()) == audience_path.as_deref())
        .or_else(|| jsonrpc.first())
        .cloned()
        .unwrap_or_else(|| panic!("the `{}` plane claims a JSON-RPC front door", decl.key))
}

fn served_by_root(slot: &Arc<dyn std::any::Any + Send + Sync>) -> bool {
    slot.downcast_ref::<busbar_kernel::plane_driver::door::DoorSlot>()
        .is_some()
}

fn door_served_by_root(decl: &'static PlaneDecl, sections: &str) -> bool {
    let mut cfg = resolved(sections);
    cfg.public_url = Some("https://busbar.example".to_string());
    built_planes(&cfg)
        .into_iter()
        .find(|(d, _)| d.key == decl.key)
        .is_some_and(|(_, obj)| served_by_root(&obj))
}

#[tokio::test]
async fn oversized_post_to_a_mounted_door_plane_is_refused_in_the_planes_own_dialect() {
    const CHILD: &str = "BUSBAR_PLANE_INTEGRATION_CHILD";
    if std::env::var(CHILD).ok().as_deref()
        != Some("oversized_post_to_a_mounted_door_plane_is_refused_in_the_planes_own_dialect")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!(
            "{module}::oversized_post_to_a_mounted_door_plane_is_refused_in_the_planes_own_dialect"
        );
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(
                CHILD,
                "oversized_post_to_a_mounted_door_plane_is_refused_in_the_planes_own_dialect",
            )
            .output()
            .expect("run the original behavior in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "the original behavior failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let sections = door_section_yaml("gateway.example.com");
    let mount = jsonrpc_mount(door_plane(), &sections);
    let mut cfg = resolved(&sections);
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "plane_integration-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    cfg.store = Some(busbar_kernel::config::StoreCfg {
        module,
        settings: settings
            .as_object()
            .expect("product settings object")
            .clone(),
    });
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let v = oversized_413_body(app, &sections, &mount).await;

    assert_eq!(
        v.get("jsonrpc").and_then(|j| j.as_str()),
        Some("2.0"),
        "a mounted door plane must refuse in JSON-RPC 2.0, the only wire format it speaks; got {v}"
    );
    assert!(
        v.pointer("/error/code").and_then(|c| c.as_i64()).is_some(),
        "a JSON-RPC refusal carries a numeric `error.code`; got {v}"
    );
    assert!(
        v.pointer("/error/type").is_none(),
        "`error.type` is the fallback dialect's envelope member — the vendor shape must not survive \
         on a mounted plane; got {v}"
    );
}

#[tokio::test]
async fn a_mount_claims_its_own_segment_and_not_its_sibling() {
    const CHILD: &str = "BUSBAR_PLANE_INTEGRATION_CHILD";
    if std::env::var(CHILD).ok().as_deref()
        != Some("a_mount_claims_its_own_segment_and_not_its_sibling")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!("{module}::a_mount_claims_its_own_segment_and_not_its_sibling");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "a_mount_claims_its_own_segment_and_not_its_sibling")
            .output()
            .expect("run the original behavior in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "the original behavior failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let sections = door_section_yaml("gateway.example.com");
    let mount = jsonrpc_mount(door_plane(), &sections);
    let mut cfg = resolved(&sections);
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "plane_integration-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    cfg.store = Some(busbar_kernel::config::StoreCfg {
        module,
        settings: settings
            .as_object()
            .expect("product settings object")
            .clone(),
    });
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let under = oversized_413_body(app.clone(), &sections, &format!("{mount}/anything")).await;
    assert_eq!(
        under.get("jsonrpc").and_then(|j| j.as_str()),
        Some("2.0"),
        "`{mount}/anything` lies beneath the `{mount}` mount at a segment boundary; got {under}"
    );

    let sibling = oversized_413_body(app, &sections, &format!("{mount}x")).await;
    assert!(
        sibling.get("jsonrpc").is_none(),
        "`{mount}x` is NOT under the `{mount}` mount — it must not inherit the plane's refusal \
         shape; got {sibling}"
    );
    assert!(
        sibling.pointer("/error/message").is_some(),
        "the residual plane still answers a legible native envelope; got {sibling}"
    );
}

#[tokio::test]
async fn plane_slot_holds_the_one_built_object_of_each_configured_plane() {
    const CHILD: &str = "BUSBAR_PLANE_INTEGRATION_CHILD";
    if std::env::var(CHILD).ok().as_deref()
        != Some("plane_slot_holds_the_one_built_object_of_each_configured_plane")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test =
            format!("{module}::plane_slot_holds_the_one_built_object_of_each_configured_plane");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(
                CHILD,
                "plane_slot_holds_the_one_built_object_of_each_configured_plane",
            )
            .output()
            .expect("run the original behavior in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "the original behavior failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let peer = crate::root::door_steps::tests::tool_door::TlsToolServer::new().await;
    let sections = format!(
        "{}{}",
        door_section_yaml("gw.example.com"),
        agents_yaml(&peer)
    );
    let cfg = bootable(&sections);
    let configured: Vec<&'static PlaneDecl> = linked::planes()
        .iter()
        .copied()
        .filter(|d| cfg.plane_sections.contains(d.config_section))
        .collect();
    assert_eq!(
        configured.len(),
        2,
        "the door and the agents: section configure two planes: {:?}",
        configured.iter().map(|d| d.key).collect::<Vec<_>>()
    );

    let mut cfg = cfg;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "plane_integration-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    cfg.store = Some(busbar_kernel::config::StoreCfg {
        module,
        settings: settings
            .as_object()
            .expect("product settings object")
            .clone(),
    });
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let routes = busbar_kernel::base_data_core_lines(&app)
        .into_iter()
        .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
        .collect::<Vec<_>>();

    for decl in configured {
        let key = decl.key;
        let slot = app
            .plane_slot(key)
            .unwrap_or_else(|| panic!("`{key}` configured => plane_slot(\"{key}\") is Some"))
            .clone();
        let again = app.plane_slot(key).expect("a second read").clone();
        assert!(
            Arc::ptr_eq(&slot, &again),
            "plane_slot(\"{key}\") must hand back the SAME object on every read, not a second \
             construction"
        );
        assert!(
            (decl.admission)(&*slot).is_some(),
            "the `{key}` slot must be the plane's own object: its declared admission reads it"
        );
        let claims: Vec<String> = (decl.claims)(&*slot)
            .into_iter()
            .filter(|(_, wire)| *wire == busbar_kernel::plane_driver::dispatch::WIRE_JSONRPC)
            .map(|(path, _)| path)
            .collect();
        assert!(
            !claims.is_empty(),
            "the `{key}` plane claims its JSON-RPC door"
        );

        if served_by_root(&slot) {
            continue;
        }
        for path in claims {
            assert_eq!(
                app.planes.mounted_plane_of(&path),
                Some(key),
                "`{path}`, claimed off the `{key}` slot object, must be mounted for `{key}` in the \
                 App's dispatch table"
            );
            if decl.routes.is_some() {
                assert!(
                    routes.iter().any(|(p, _, _)| *p == path),
                    "`{path}`, claimed off the `{key}` slot object, must be a route the router \
                     mounted"
                );
            }
        }
    }
}

#[test]
fn plane_slot_is_none_when_the_plane_is_not_configured() {
    const CHILD: &str = "BUSBAR_PLANE_INTEGRATION_CHILD";
    if std::env::var(CHILD).ok().as_deref()
        != Some("plane_slot_is_none_when_the_plane_is_not_configured")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!("{module}::plane_slot_is_none_when_the_plane_is_not_configured");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "plane_slot_is_none_when_the_plane_is_not_configured")
            .output()
            .expect("run the original behavior in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "the original behavior failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let cfg = resolved("");
    assert!(
        cfg.endpoint_resources.is_empty(),
        "fixture control: no endpoint door configured"
    );
    assert!(
        cfg.plane_defs.values().all(|d| d.def_names().is_empty()),
        "fixture control: no plane entries"
    );
    assert!(
        cfg.plane_sections.is_empty(),
        "fixture control: no plane section configured"
    );

    let mut cfg = cfg;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "plane_integration-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    cfg.store = Some(busbar_kernel::config::StoreCfg {
        module,
        settings: settings
            .as_object()
            .expect("product settings object")
            .clone(),
    });
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let mounting: Vec<&'static PlaneDecl> = linked::planes()
        .iter()
        .copied()
        .filter(|d| !d.fallback)
        .collect();
    assert!(
        mounting.len() >= 2,
        "the roster carries the planes this negative is about"
    );
    for decl in mounting {
        assert!(
            app.plane_slot(decl.key).is_none(),
            "no `{}:` section => no `{}` slot",
            decl.config_section,
            decl.key
        );
    }
}

#[cfg(test)]
mod metrics_scrape {
    use super::*;

    fn series_for<'a>(exposition: &'a str, family: &str, plane: &str) -> Vec<&'a str> {
        let want = format!("plane=\"{plane}\"");
        exposition
            .lines()
            .filter(|l| !l.starts_with('#') && l.starts_with(family) && l.contains(&want))
            .collect()
    }

    fn lines_for<'a>(exposition: &'a str, family: &str) -> Vec<&'a str> {
        exposition
            .lines()
            .filter(|l| !l.starts_with('#') && l.starts_with(family))
            .collect()
    }

    fn keys_of(line: &str) -> Vec<String> {
        line.split_once('{')
            .and_then(|(_, rest)| rest.rsplit_once('}'))
            .map(|(inner, _)| {
                let mut ks: Vec<String> = inner
                    .split(',')
                    .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_string()))
                    .collect();
                ks.sort();
                ks
            })
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn mounted_plane_traffic_appears_on_a_real_metrics_scrape() {
        const CHILD: &str = "BUSBAR_PLANE_INTEGRATION_CHILD";
        if std::env::var(CHILD).ok().as_deref()
            != Some("mounted_plane_traffic_appears_on_a_real_metrics_scrape")
        {
            let module = module_path!()
                .split_once("::")
                .expect("a mounted test module")
                .1;
            let test = format!("{module}::mounted_plane_traffic_appears_on_a_real_metrics_scrape");
            let output =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
                    .env(
                        CHILD,
                        "mounted_plane_traffic_appears_on_a_real_metrics_scrape",
                    )
                    .output()
                    .expect("run the original behavior in a fresh product process");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success()
                    && stdout.contains("running 1 test")
                    && stdout.contains(&format!("test {test} ..."))
                    && stdout.contains("1 passed; 0 failed; 0 ignored"),
                "the original behavior failed or did not run exactly once:\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        linked::install();
        let peer = crate::root::door_steps::tests::tool_door::TlsToolServer::new().await;
        let sections = format!(
            "{}{}export:\n  metrics: {{module: prometheus, settings: {{buffer_seconds: 60}}}}\n",
            door_section_yaml("gateway.example.com"),
            agents_yaml(&peer)
        );
        let door_mount = jsonrpc_mount(door_plane(), &sections);
        let agents_mount = jsonrpc_mount(agents_plane(), &sections);
        let mut cfg = resolved(&sections);
        cfg.public_url = Some("https://busbar.example".into());
        crate::dist_root_install::install();
        let library_path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch(&format!(
            "plane_integration-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        cfg.store = Some(busbar_kernel::config::StoreCfg {
            module,
            settings: settings
                .as_object()
                .expect("product settings object")
                .clone(),
        });
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        busbar_kernel::export::plugin::open(&cfg.export).expect("the configured exporter opens");
        let (app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the actual product builds the door deployment");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let app = Arc::new(app);

        let router = plane_router(app, &sections, usize::MAX, &[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        let door_status = client
            .post(format!("{base}{door_mount}"))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();

        let agents_status = client
            .post(format!("{base}{agents_mount}/agents/planner"))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": { "message": { "role": "user", "parts": [{ "kind": "text", "text": "go" }] } },
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();

        let scrape = client.get(format!("{base}/metrics")).send().await.unwrap();
        assert_eq!(
            scrape.status().as_u16(),
            200,
            "the built-in prometheus exporter must serve /metrics on this router"
        );
        let exposition = scrape.text().await.unwrap();
        server.abort();

        for plane in [door_plane().key, agents_plane().key] {
            let counters = series_for(
                &exposition,
                busbar_kernel::snapshot::PLANE_REQUESTS_TOTAL,
                plane,
            );
            assert!(
                !counters.is_empty(),
                "no `{}` series for plane=\"{plane}\" after driving real traffic \
                 (door {door_status}, agents {agents_status}). \
                 Exposition:\n{exposition}",
                busbar_kernel::snapshot::PLANE_REQUESTS_TOTAL,
            );
            let durations = series_for(
                &exposition,
                busbar_kernel::snapshot::PLANE_REQUEST_DURATION_SECONDS,
                plane,
            );
            assert!(
                !durations.is_empty(),
                "no `{}` series for plane=\"{plane}\" after driving real traffic. Exposition:\n{exposition}",
                busbar_kernel::snapshot::PLANE_REQUEST_DURATION_SECONDS,
            );

            for line in &counters {
                assert_eq!(
                    keys_of(line),
                    vec![
                        "ingress_protocol".to_string(),
                        "outcome".to_string(),
                        "plane".to_string(),
                        "pool".to_string()
                    ],
                    "plane=\"{plane}\" invented a differently-shaped series: {line}"
                );
            }
        }

        for family in [
            busbar_kernel::snapshot::REQUESTS_TOTAL,
            busbar_kernel::snapshot::REQUEST_DURATION_SECONDS,
        ] {
            for line in lines_for(&exposition, family) {
                assert!(
                    !line.contains("plane=\""),
                    "a `plane` label leaked onto the v1.5.4 model family `{family}`: {line}"
                );
            }
        }
    }
}

const BODY_INGRESS_ROUTES: [&str; 2] = ["/{name}/v1/messages", "/{provider}/{model}/v1/messages"];

#[tokio::test]
async fn an_audience_bound_token_is_confined_to_its_door_plane() {
    const CHILD: &str = "BUSBAR_PLANE_INTEGRATION_CHILD";
    if std::env::var(CHILD).ok().as_deref()
        != Some("an_audience_bound_token_is_confined_to_its_door_plane")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!("{module}::an_audience_bound_token_is_confined_to_its_door_plane");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(
                CHILD,
                "an_audience_bound_token_is_confined_to_its_door_plane",
            )
            .output()
            .expect("run the original behavior in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "the original behavior failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_kernel::governance::GovState;

    let door = door_plane();

    const HOST: &str = "busbar.example.com";
    let canonical = format!("https://{HOST}/{}", door.key);
    let sections = door_section_yaml(HOST);

    let admissible: Vec<String> = vec![jsonrpc_mount(door, &sections)];

    let by_root = door_served_by_root(door, &sections);

    let mut declared_public: Vec<String> = vec!["/healthz".to_string(), "/auth/token".to_string()];

    if !by_root {
        declared_public.push(format!(
            "/.well-known/oauth-protected-resource{}",
            admissible[0]
        ));
    }

    let store = crate::root::real_store::records();
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );

    let (key, plain_token) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "door-agent".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
    let generation = verifier
        .verify(
            plain_token.expose(&busbar_kernel::seal::lend()).as_str(),
            1_000_000_000,
            None,
        )
        .expect("plain claims")
        .generation;
    let bound_token = signer.mint_for_audience(
        &key.id,
        2_000_000_000,
        generation.as_deref(),
        &canonical,
        Some("client-1"),
    );

    let mut cfg = resolved(&sections);
    let mut auth = busbar_kernel::config::AuthCfg::default_none();
    auth.chain = vec![busbar_kernel::config::AuthChainEntry::bare("keys")];
    auth.signing_key = Some(busbar_kernel::config::SecretRef::template(hex::encode(
        [9u8; 32],
    )));
    cfg.auth = Some(auth);
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "plane_integration-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    cfg.store = Some(busbar_kernel::config::StoreCfg {
        module,
        settings: settings
            .as_object()
            .expect("product settings object")
            .clone(),
    });
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    let mut app = app;
    Arc::make_mut(&mut app).governance = Some(gov);

    let core_routes = busbar_kernel::base_data_core_lines(&app)
        .into_iter()
        .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
        .collect::<Vec<_>>();

    for path in &admissible {
        if by_root {
            assert!(
                !core_routes.iter().any(|(p, _, _)| p == path),
                "{path} is claimed by the `{}` door plane, whose claims the composition root \
                 mounts; the kernel's router must not mount it as well",
                door.key
            );
            continue;
        }
        assert!(
            core_routes.iter().any(|(p, _, _)| p == path),
            "{path} is claimed by the `{}` plane but no core route mounts it — the walk would \
             assert nothing about the plane it is named for",
            door.key
        );
    }

    for public in &declared_public {
        assert!(
            core_routes.iter().any(|(path, _, auth)| path == public
                && *auth == busbar_contract::abi::mechanism::route::RouteAuth::None),
            "{public} is declared unauthenticated-by-design but no core route mounts it with \
             RouteAuth::None — the bypass set this names is not the one the router built"
        );
    }

    for pattern in BODY_INGRESS_ROUTES {
        assert!(
            !core_routes.iter().any(|(path, _, _)| path == pattern),
            "{pattern} is the pools door's (its `/` claim), never a kernel route: {core_routes:?}"
        );
    }
    let boot_plugin_paths: Vec<String> = busbar_kernel::boot_route_paths_of(&app);
    assert!(
        !core_routes.is_empty(),
        "an empty table would make every assertion below vacuous"
    );

    let router = plane_router(app, &sections, usize::MAX, &["keys"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    fn concrete(pattern: &str) -> String {
        let mut out = String::new();
        for seg in pattern.split('/').skip(1) {
            out.push('/');
            if seg.starts_with('{') && seg.ends_with('}') {
                out.push_str(match seg {
                    "{name}" => "pa",
                    "{provider}" => "anthropic",
                    "{model}" => "test-model",
                    other => panic!(
                        "route pattern segment {other} has no fixture value: give it one, never \
                         skip the route"
                    ),
                });
            } else {
                out.push_str(seg);
            }
        }
        if out.is_empty() {
            "/".to_string()
        } else {
            out
        }
    }

    let body = serde_json::json!({
        "model": "pa",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16
    })
    .to_string();

    let mut checked = 0usize;
    let mut door_checked = 0usize;
    for route in &core_routes {
        let path = concrete(&route.0);
        if route.2 == busbar_contract::abi::mechanism::route::RouteAuth::None {
            assert!(
                declared_public.contains(&route.0),
                "{} is mounted RouteAuth::None but is not in declared_public — an unauthenticated \
                 core route must be a deliberate, reviewed act",
                route.0
            );
            continue;
        }
        let method = reqwest::Method::from_bytes(route.1.as_bytes()).unwrap();

        if admissible.contains(&route.0) {
            let url = format!("http://{addr}{path}");
            let anon = client
                .request(method.clone(), &url)
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                anon.status(),
                401,
                "an unauthenticated caller on the door plane must get 401, not a vendor-shaped \
                 envelope, on {} {}",
                route.1,
                path
            );
            assert!(
                anon.headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("Bearer ") && v.contains("resource_metadata=")),
                "a 401 on an OAuth protected resource must carry a Bearer challenge naming its \
                 resource_metadata — without it the client has no way to find the authorization \
                 server, on {} {}",
                route.1,
                path
            );
            let bound = client
                .request(method.clone(), &url)
                .header("authorization", format!("Bearer {bound_token}"))
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_ne!(
                bound.status(),
                401,
                "the audience-bound token is minted for exactly this resource and must be admitted \
                 on {} {}",
                route.1,
                path
            );
            let plain = client
                .request(method.clone(), &url)
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        plain_token.expose(&busbar_kernel::seal::lend())
                    ),
                )
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                plain.status(),
                401,
                "a plain data-plane key carries no audience and must be inadmissible on the door \
                 plane, on {} {}",
                route.1,
                path
            );
            door_checked += 1;
            continue;
        }
        let url = format!("http://{addr}{path}");

        let anon = client
            .request(method.clone(), &url)
            .body(body.clone())
            .send()
            .await
            .unwrap()
            .status();
        let bound = client
            .request(method.clone(), &url)
            .header("authorization", format!("Bearer {bound_token}"))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            bound.status(),
            anon,
            "an audience-bound door-plane token must be treated as no credential on {} {}",
            route.1,
            path
        );

        let plain = client
            .request(method, &url)
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    plain_token.expose(&busbar_kernel::seal::lend())
                ),
            )
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_ne!(
            plain.status(),
            anon,
            "the plain data-plane sibling must still be admitted on {} {}",
            route.1,
            path
        );
        checked += 1;
    }
    assert_eq!(
        door_checked,
        core_routes
            .iter()
            .filter(|(path, _, _)| admissible.contains(path))
            .count(),
        "every admissible mounted route must have been walked; a mismatch means a claimed route \
         was mounted with an auth level that skipped the arm"
    );
    assert!(
        by_root || door_checked > 0,
        "no door-plane route was walked, so the reciprocal half of the boundary was never asserted"
    );

    let guarded_core = core_routes
        .iter()
        .filter(|(path, _, auth)| {
            *auth != busbar_contract::abi::mechanism::route::RouteAuth::None
                && !admissible.contains(path)
        })
        .count();
    assert!(
        checked == guarded_core
            && checked >= 1
            && core_routes.iter().any(|(path, _, auth)| path == "/stats"
                && *auth != busbar_contract::abi::mechanism::route::RouteAuth::None),
        "the walk covered {checked} of {guarded_core} guarded core routes, and must cover the \
         kernel's guarded `/stats` — the enumeration is not seeing the router: {core_routes:?}"
    );

    for path in &boot_plugin_paths {
        let url = format!("http://{addr}{path}");
        let anon = client.get(&url).send().await.unwrap().status();
        let bound = client
            .get(&url)
            .header("authorization", format!("Bearer {bound_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            bound.status(),
            anon,
            "an audience-bound door-plane token must be treated as no credential on plugin route \
             {path}"
        );
    }

    handle.abort();
}

async fn oversized_413_body(
    app: Arc<busbar_kernel::state::App>,
    sections: &str,
    path: &str,
) -> serde_json::Value {
    let router = plane_router(app, sections, 64, &[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let task = tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
    let response = reqwest::Client::new()
        .post(format!("http://{address}{path}"))
        .header("content-type", "application/json")
        .body(vec![b'x'; 128])
        .send()
        .await
        .expect("oversized request");
    let status = response.status();
    let bytes = response.bytes().await.expect("response body");
    task.abort();
    assert_eq!(
        status.as_u16(),
        413,
        "{path}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).expect("the refusal is JSON")
}

fn plane_router(
    app: Arc<busbar_kernel::state::App>,
    sections: &str,
    body_limit: usize,
    chain: &[&str],
) -> axum::Router {
    use busbar_plugin_loader::dispatch::{load_linked, Bind, ConnTable, LinkedRow, NoSink};
    let cfg = resolved(sections);
    let late = crate::root::serve::LateServices::new();
    let dispatcher = Arc::new(crate::root::dispatch::build(1, &late));
    let (credentials, live) = crate::root::credentials::AppCredentials::late();
    crate::root::serve::compose(crate::root::connector::dest_judge(&cfg), &late, credentials);
    let declarations: Vec<_> = linked::planes()
        .iter()
        .map(|decl| &decl.declaration)
        .collect();
    crate::root::serve::attach(
        &late,
        app.governance.as_deref(),
        app.governance
            .clone()
            .map(|gov| gov as Arc<dyn busbar_kernel::host_services::SignKey>),
        &app.demotion_record,
        &declarations,
    );
    let doors: Vec<_> = crate::LINKED
        .plane_door_declares
        .iter()
        .map(|&(name, door, _)| {
            let row = LinkedRow::of(door).expect("the actual linked plane states itself");
            let plugin = load_linked::<busbar_plugin_loader::dispatch::kinds::plane::Plane>(
                &row,
                Bind {
                    instance: name.into(),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns: ConnTable::Host(crate::root::connector::the().clone()),
                },
            )
            .expect("the actual linked plane crosses its memory ABI");
            (name.to_string(), Arc::new(plugin))
        })
        .collect();
    let written: serde_yaml::Value =
        serde_yaml::from_str(sections).expect("the plane configuration");
    let mut configured = std::collections::BTreeMap::new();
    for decl in linked::planes() {
        for section in
            std::iter::once(decl.config_section).chain(decl.owned_config_sections.iter().copied())
        {
            if let Some(value) = written.get(section) {
                configured.insert(section, value.clone());
            }
        }
    }
    let gov = app.governance.clone().expect("actual governance book");
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(
        crate::root::plane_node::node(),
    ));
    let served = crate::root::serve::compose_planes(
        &doors,
        &dispatcher,
        &late,
        &configured,
        Some("https://busbar.example"),
        &|| {
            Arc::new(busbar_kernel::plane_driver::PlaneMoney::new(
                gov.clone(),
                post.clone(),
            ))
        },
        None,
        None,
        &app.serve_tables,
    )
    .expect("the actual plane generations open through the production composition");
    let data_chain: Vec<_> = chain
        .iter()
        .map(|name| {
            (
                (*name).to_string(),
                busbar_contract::abi::auth::AuthPoints(busbar_contract::abi::auth::POINT_HEAD),
            )
        })
        .collect();
    let mounts = crate::root::serve::door_mounts(
        served,
        || crate::root::kernel::ROOT_CARD.pin(),
        &data_chain,
        &busbar_kernel::base_data_core_lines(&app),
        &[],
        &crate::root::serve::transport_offers(crate::LINKED.transports, &[]),
    )
    .expect("the actual root mounts the planes' own declared doors");
    let (router, _, handle) = busbar_kernel::build_split_routers_serving_doors(
        app,
        mounts.routes,
        mounts.sessions,
        mounts.refusals,
        body_limit,
        16,
        false,
    );
    if let Some(refuser) = mounts.refuse_by_path {
        handle.bind_door_refuser(refuser);
    }
    live.set(handle);
    router
}
