// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn test_admin_v1_openapi_paths_all_resolve() {
    const CHILD: &str = "BUSBAR_ADMIN_OPENAPI_F1310C32";
    const WITNESS: &str = "actual hook case test_admin_v1_openapi_paths_all_resolve completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch("test_admin_v1_openapi_paths_all_resolve-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    for declaration in busbar_kernel::plane_driver::registry::plane_decls() {
        document
            .as_object_mut()
            .unwrap()
            .entry(declaration.config_section.to_string())
            .or_insert_with(|| serde_json::json!({}));
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let spawn = || {
        let router = busbar_kernel::build_router(app.clone());
        async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            (addr, handle)
        }
    };
    use std::collections::{BTreeMap, BTreeSet};
    const PREFIX: &str = busbar_core_admin::v1::contract::ADMIN_PREFIX;
    const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    const OAS_OPERATION_STATUSES: &str = include_str!(
        "../../../../busbar-core-admin/tests/fixtures/openapi_operation_statuses_key.txt"
    )
    .trim_ascii();
    const JSON_ROUTER: &str = include_str!("../../../../busbar-core-admin/src/v1/json/mod.rs");
    // Read the same literal route mounts used by the production JSON transport.
    let literal = literal_admin_routes(JSON_ROUTER);
    let literal_get_paths: Vec<&str> = literal
        .iter()
        .filter(|(method, _)| method == "GET")
        .map(|(_, path)| path.as_str())
        .collect();
    let client = reqwest::Client::new();
    let ask = |addr: std::net::SocketAddr, method: &str, path: &str| {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let req = client
            .request(method.clone(), format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok");

        let req = if method == reqwest::Method::GET {
            req
        } else {
            req.header("content-type", "application/json").body("{")
        };
        async move {
            let resp = req.send().await.unwrap();
            (resp.status().as_u16(), resp.text().await.unwrap())
        }
    };

    let (addr, handle) = spawn().await;
    let doc: serde_json::Value =
        serde_json::from_str(&ask(addr, "GET", &format!("{PREFIX}/openapi.json")).await.1)
            .expect("the served openapi.json parses");
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["title"], "Busbar Admin API");
    let codes = doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]
        ["enum"]
        .as_array()
        .unwrap();
    assert!(codes.iter().any(|c| c == "not_found"));

    let mut documented: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (key, op) in item.as_object().expect("path item") {
            if key.starts_with("x-") {
                continue;
            }
            let method = key.to_ascii_uppercase();
            assert!(
                METHODS.contains(&method.as_str()),
                "{path} documents `{key}`, which is no admin operation method"
            );
            let statuses = op[OAS_OPERATION_STATUSES]
                .as_object()
                .unwrap_or_else(|| panic!("{method} {path} documents no status"))
                .keys()
                .cloned()
                .collect();
            documented.insert((method, path.clone()), statuses);
        }
    }

    for rel in &literal_get_paths {
        assert!(
            documented.contains_key(&("GET".to_string(), format!("{PREFIX}{rel}"))),
            "GET {PREFIX}{rel} is missing from the served document"
        );
    }
    for m in METHODS {
        assert!(
            documented.keys().any(|(dm, _)| dm == m),
            "the served document documents no {m} operation at all"
        );
    }

    let loop_verbs: BTreeSet<&'static str> = busbar_core_admin::verb::NEW_VERBS
        .iter()
        .chain(busbar_core_admin::verb::LEDGER_VERBS)
        .chain(busbar_core_admin::verb::AUDIT_VERBS)
        .filter_map(|v| busbar_core_admin::verb::verb_name(*v))
        .collect();
    let kernel_loop: BTreeSet<(String, String)> = busbar_core_admin::admin_codec::verbs::table()
        .into_iter()
        .filter(|row| loop_verbs.contains(row.verb))
        .map(|row| (row.method.to_string(), row.template.to_string()))
        .collect();
    let concrete = |path: &str| {
        path.split('/')
            .map(|seg| {
                if seg.starts_with('{') {
                    "resolve-probe"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    let mut fallback: BTreeMap<&str, (u16, String)> = BTreeMap::new();
    for m in METHODS {
        fallback.insert(
            m,
            ask(addr, m, &format!("{PREFIX}/no-such-admin-route/resolve")).await,
        );
    }
    assert_eq!(
        fallback["GET"].0, 404,
        "the unmatched-path control is the router's 404"
    );

    let mut failures: Vec<String> = Vec::new();

    handle.abort();

    let mut probed = 0usize;
    let paths: BTreeSet<&String> = documented.keys().map(|(_, p)| p).collect();
    for path in paths {
        let (addr, handle) = spawn().await;
        for m in METHODS {
            let op = (m.to_string(), path.clone());
            let answer = match documented.get(&op) {
                Some(_) if kernel_loop.contains(&op) => continue,
                _ => ask(addr, m, &concrete(path)).await,
            };
            let Some(statuses) = documented.get(&op) else {
                if answer.0 != 405 && answer != fallback[m] {
                    failures.push(format!(
                        "{m} {path} is NOT documented but the router serves it ({}): {}",
                        answer.0, answer.1
                    ));
                }
                continue;
            };

            probed += 1;
            if answer == fallback[m] {
                failures.push(format!(
                    "{m} {path} is documented but the router answers its unmatched-path \
                     fallback: nothing serves it (phantom endpoint)"
                ));
            } else if answer.0 == 405 {
                failures.push(format!(
                    "{m} {path} is documented but the router mounts the path without this method"
                ));
            } else if !statuses.contains(&answer.0.to_string()) {
                failures.push(format!(
                    "{m} {path} answered {} which its documented statuses {statuses:?} do not \
                     list: {}",
                    answer.0, answer.1
                ));
            }
        }
        handle.abort();
    }
    assert!(
        probed > literal_get_paths.len() * 4,
        "only {probed} documented operations were probed on the router"
    );

    assert!(
        literal.len() >= 50,
        "only {} literal admin routes were read out of v1/json/mod.rs — the scanner lost the \
         router",
        literal.len()
    );
    for (method, rel) in &literal {
        let path = format!("{PREFIX}{rel}");
        if !documented.contains_key(&(method.clone(), path.clone())) {
            failures.push(format!(
                "{method} {path} is mounted by v1/json/mod.rs but is in NO served document"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "admin router / OpenAPI document disagree:\n  {}",
        failures.join("\n  ")
    );
    println!("{WITNESS}");
}

fn literal_admin_routes(src: &str) -> Vec<(String, String)> {
    use busbar_core_admin::v1::contract as c;
    let consts: [(&str, &str); 5] = [
        ("PATH_HOOKS", c::PATH_HOOKS),
        ("PATH_GROUPS", c::PATH_GROUPS),
        ("PATH_PLUGINS_INSPECT", c::PATH_PLUGINS_INSPECT),
        ("PATH_ADMIN_AUTH", c::PATH_ADMIN_AUTH),
        ("PATH_CONFIG_VALIDATE", c::PATH_CONFIG_VALIDATE),
    ];
    let start = src
        .find("impl AdminTransport for JsonV1")
        .expect("v1/json/mod.rs implements the JSON transport");
    let body = &src[start..];
    let body = &body[..body
        .find(".fallback(")
        .expect("the router ends in its fallback")];
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find(".route(") {
        let after = &rest[at + ".route(".len()..];

        let mut depth = 1usize;
        let mut end = 0usize;
        for (i, ch) in after.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let args = &after[..end];
        rest = &after[end..];
        let (first, second) = args.split_once(',').expect(".route(path, method_router)");
        let first = first.trim();
        let rel = if let Some(lit) = first.strip_prefix('"') {
            lit.trim_end_matches('"').to_string()
        } else {
            consts
                .iter()
                .find(|(name, _)| *name == first)
                .unwrap_or_else(|| {
                    panic!("v1/json/mod.rs mounts a route at `{first}`, a path this scanner cannot resolve — name its value here")
                })
                .1
                .to_string()
        };

        let mut depth = 0usize;
        let mut ident = String::new();
        let mut methods = Vec::new();
        for ch in second.chars() {
            match ch {
                '(' => {
                    if depth == 0
                        && ["get", "post", "put", "patch", "delete"].contains(&ident.as_str())
                    {
                        methods.push(ident.to_ascii_uppercase());
                    }
                    depth += 1;
                    ident.clear();
                }
                ')' => {
                    depth = depth.saturating_sub(1);
                    ident.clear();
                }
                c if c.is_ascii_alphanumeric() || c == '_' => ident.push(c),
                _ => ident.clear(),
            }
        }
        assert!(
            !methods.is_empty(),
            "the route at {rel} mounts no method this scanner recognises: {second}"
        );
        for m in methods {
            out.push((m, rel.clone()));
        }
    }
    out
}
