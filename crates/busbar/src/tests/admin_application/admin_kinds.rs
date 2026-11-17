// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 5 over the real root: the kind-generic discovery surface (`/kinds`, a
//! kind's instances, describe, views), the `/kinds` ETag, and the removal of the 1.5.5
//! per-kind paths and `/plane-facts` (section 0.2, CON-6).

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{json, JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value};

const CHILD: &str = "BUSBAR_ADMIN_KINDS_CHILD";
const WITNESS: &str = "actual root kinds assertions completed";

/// The operator credential (the `x-admin-token` file's content): a canary no read may serve.
const ADMIN_TOKEN: &str = "kinds-canary-admin-5b0e17d4c9a2";
/// The key-signing input (its file holds the hex of these 32 bytes).
const SIGNING_KEY: &[u8; 32] = b"kinds-canary-signing-key-1c8f3e0";

struct Served {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
    client: reqwest::Client,
    /// The store module the operator configured.
    store_module: String,
    operator: String,
    operator_token: std::path::PathBuf,
}

struct Read {
    status: u16,
    etag: Option<String>,
    text: String,
    body: Value,
}

impl Served {
    fn url(&self, path: &str) -> String {
        format!("http://{}/api/v1/admin{path}", self.addr)
    }

    async fn get(&self, path: &str) -> Read {
        self.send(reqwest::Method::GET, path, None).await
    }

    async fn send(&self, method: reqwest::Method, path: &str, body: Option<&Value>) -> Read {
        let mut request = self
            .client
            .request(method, self.url(path))
            .header("x-admin-token", ADMIN_TOKEN);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(busbar_contract::json::to_vec(body).unwrap());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = response.bytes().await.unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let body = busbar_contract::json::parse_value(&bytes).unwrap_or_default();
        Read {
            status,
            etag,
            text,
            body,
        }
    }

    fn finish(self) {
        self.handle.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn shown(path: &std::path::Path) -> String {
    path.display().to_string()
}

/// Compose the real root from an operator file on disk over the actual Store, and serve it.
async fn serve(name: &str) -> Served {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(name);
    let plugins = crate::root::test_plugins::trusted_config_document(&directory);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode(SIGNING_KEY)).unwrap();
    std::fs::write(&operator_token, ADMIN_TOKEN).unwrap();
    let operator = busbar_kernel::config::operator_provider().to_string();
    let mut document = json!({
        "providers": {}, "models": {},
        "auth": { "chain": [], "admin_auth": [operator.as_str()],
                  "signing_key": { "file": shown(&signing_key) } },
        "store": { "module": module.as_str(), "settings": settings },
        "advanced": {  },
        "groups": { "team": { "limits": [{ "budget": 20000, "per": "month" }] } },
        "identity-providers": {},
    });
    document["plugins"] = plugins;
    document["identity-providers"][operator.as_str()] = json!({
        "module": operator.as_str(), "token": { "file": shown(&operator_token) },
    });
    let config_path = directory.join("config.json");
    let providers_path = directory.join("providers.json");
    let text = busbar_contract::json::to_string(&document).unwrap();
    std::fs::write(&config_path, &text).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy =
        busbar_kernel::config::deploy_from_yaml_str(&text, &crate::root::boot::axis_test_grammar())
            .expect("the operator file parses as boot reads it");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .unwrap();
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone()).unwrap();
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path), Some(providers_path)),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .unwrap();
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module).await.unwrap();
    limits.keep().await.unwrap();
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Served {
        addr,
        handle,
        dir: directory,
        client: reqwest::Client::new(),
        store_module: module,
        operator,
        operator_token,
    }
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .map(|o| o.iter().map(|(k, _)| k.to_owned()).collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

fn items(read: &Read) -> Vec<Value> {
    read.body["items"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default()
}

fn kind_ids(read: &Read) -> Vec<String> {
    items(read)
        .iter()
        .filter_map(|row| row["kind"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn kinds_list_every_category_and_core() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-list").await;
    let kinds = s.get("/kinds").await;
    assert_eq!(kinds.status, 200, "{}", kinds.text);
    let ids = kind_ids(&kinds);
    for kind in [
        "auth",
        "store",
        "secret",
        "export",
        "hook",
        "transport",
        "core",
    ] {
        assert!(
            ids.contains(&kind.to_owned()),
            "/kinds lists `{kind}`: {ids:?}"
        );
    }
    for row in items(&kinds) {
        assert_eq!(
            keys(&row),
            [
                "category",
                "descriptors_uniform",
                "display",
                "etag",
                "instance_count",
                "kind",
                "record_attributes",
                "views",
            ],
            "a /kinds row is closed: {row}"
        );
    }
    let core = items(&kinds)
        .into_iter()
        .find(|row| row["kind"] == "core")
        .expect("core is a kind");
    assert_eq!(core["category"], "core");
    assert_eq!(
        core["instance_count"].as_u64(),
        Some(9),
        "the nine core instances"
    );

    let planes_only = s.get("/kinds?category=core").await;
    assert_eq!(planes_only.status, 200, "{}", planes_only.text);
    assert_eq!(kind_ids(&planes_only), vec!["core".to_owned()]);
    assert_eq!(s.get("/kinds?category=widgets").await.status, 400);
    assert_eq!(s.get("/kinds?colour=blue").await.status, 400);

    let core_instances = s.get("/kinds/core/instances").await;
    assert_eq!(core_instances.status, 200, "{}", core_instances.text);
    let mut ids: Vec<String> = items(&core_instances)
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_owned))
        .collect();
    ids.sort();
    let mut want: Vec<String> = busbar_kernel::config_validate::CORE_INSTANCES
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    want.sort();
    assert_eq!(ids, want);
    for row in items(&core_instances) {
        assert!(
            row["plugin"].is_null(),
            "a core instance runs no plugin: {row}"
        );
        assert_eq!(
            keys(&row),
            ["etag", "id", "labels", "name", "plugin", "state"],
            "an instance row is closed: {row}"
        );
    }
    assert_eq!(s.get("/kinds/widgets/instances").await.status, 404);
    assert_eq!(s.get("/kinds/core/instances/nowhere").await.status, 404);

    let auth = s.get("/kinds/auth/instances").await;
    assert_eq!(auth.status, 200, "{}", auth.text);
    assert!(
        items(&auth)
            .iter()
            .any(|row| row["id"] == s.operator.as_str()),
        "the operator's identity provider is an auth instance: {}",
        auth.text
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn describe_is_closed() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-describe").await;
    let closed = [
        "actions",
        "config",
        "config_schema",
        "etag",
        "health",
        "id",
        "labels",
        "links",
        "management",
        "name",
        "plugin",
        "runtime",
        "state",
        "state_schema",
        "views",
    ];
    for path in [
        format!("/kinds/auth/instances/{}", s.operator),
        "/kinds/store/instances/store".to_owned(),
        "/kinds/core/instances/routing".to_owned(),
        "/kinds/core/instances/limits".to_owned(),
    ] {
        let describe = s.get(&path).await;
        assert_eq!(describe.status, 200, "{path}: {}", describe.text);
        assert_eq!(
            keys(&describe.body),
            closed,
            "{path} is exactly §5.3 plus the adopted instance-settings management member"
        );
        assert!(
            describe.body["actions"]
                .as_array()
                .is_some_and(|a| a.is_empty()),
            "{path}: this fixture has no captured authoring-source binding or generic core settings wrapper"
        );
        assert_eq!(describe.body["management"]["available"], false);
        assert_eq!(
            describe.body["management"]["reason"],
            if path.contains("/kinds/core/") {
                "source_mapping_unavailable"
            } else {
                "source_binding_unavailable"
            }
        );
        assert!(
            describe.body["state"].is_null() && describe.body["state_schema"].is_null(),
            "{path}: core writes nothing into an instance's own state"
        );
    }
    let store = s.get("/kinds/store/instances/store").await;
    assert_eq!(
        keys(&store.body["runtime"]),
        [
            "crossings",
            "dispatch",
            "open",
            "plane",
            "records",
            "scrub",
            "settings",
            "watchdog"
        ],
        "runtime is closed and core-written for a plugin instance: {}",
        store.text
    );
    assert!(
        store.body["runtime"]["plane"].is_null(),
        "a store is not a plane"
    );
    assert!(
        store.body["health"]
            .as_array()
            .is_some_and(|h| h.iter().any(|c| c["check"] == "store")),
        "a store carries core's store check: {}",
        store.text
    );
    let routing = s.get("/kinds/core/instances/routing").await;
    assert!(
        routing.body["runtime"].is_null(),
        "a core instance's facts are its state"
    );
    assert!(routing.body["plugin"].is_null());
    for section in ["models", "providers", "pools"] {
        assert!(
            routing.body["config"].get(section).is_some(),
            "core/routing holds `{section}`, where GET /{section} moved: {}",
            routing.text
        );
    }
    let limits = s.get("/kinds/core/instances/limits").await;
    assert!(
        limits.body["config"]["groups"].get("team").is_some(),
        "core/limits holds the group tree: {}",
        limits.text
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn kinds_revision_moves_on_instance_change() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-revision").await;
    let kinds = s.get("/kinds").await;
    assert_eq!(kinds.status, 200, "{}", kinds.text);
    let before = kinds
        .etag
        .clone()
        .expect("/kinds carries its ETag, the discovery revision");
    assert_eq!(
        s.get("/kinds").await.etag.as_deref(),
        Some(before.as_str()),
        "a read moves nothing"
    );
    let limits_before = s.get("/kinds/core/instances").await;

    // Reconfigure an instance: a group is core/limits configuration.
    let wrote = s
        .send(
            reqwest::Method::POST,
            "/groups",
            Some(&json!({"name": "kinds-ann", "config": {"parent": "team"}})),
        )
        .await;
    assert!(wrote.status < 300, "{}: {}", wrote.status, wrote.text);
    let after = s.get("/kinds").await.etag.expect("/kinds carries its ETag");
    assert_ne!(
        before, after,
        "reconfiguring an instance moves the /kinds ETag"
    );
    let etag_of = |read: &Read, id: &str| {
        items(read)
            .into_iter()
            .find(|row| row["id"] == id)
            .and_then(|row| row["etag"].as_str().map(str::to_owned))
    };
    let limits_after = s.get("/kinds/core/instances").await;
    assert_ne!(
        etag_of(&limits_before, "limits"),
        etag_of(&limits_after, "limits"),
        "the reconfigured instance's ETag moves"
    );
    assert_eq!(
        etag_of(&limits_before, "ledger"),
        etag_of(&limits_after, "ledger"),
        "an untouched instance's ETag does not"
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn secret_positions_never_values() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-secrets").await;
    let provider = s
        .get(&format!("/kinds/auth/instances/{}", s.operator))
        .await;
    assert_eq!(provider.status, 200, "{}", provider.text);
    let token = &provider.body["config"]["token"];
    assert_eq!(
        keys(token),
        ["secret_ref", "set"],
        "the operator token is a secret position: {}",
        provider.text
    );
    assert_eq!(token["set"].as_bool(), Some(true));
    // No read of the discovery surface carries a secret value, in any instance.
    let mut bodies = vec![s.get("/kinds").await.text];
    for kind in kind_ids(&s.get("/kinds").await) {
        let listed = s.get(&format!("/kinds/{kind}/instances")).await;
        assert_eq!(listed.status, 200, "{kind}: {}", listed.text);
        for row in items(&listed) {
            let id = row["id"].as_str().unwrap().to_owned();
            bodies.push(s.get(&format!("/kinds/{kind}/instances/{id}")).await.text);
        }
        bodies.push(listed.text);
    }
    let signing_hex = hex::encode(SIGNING_KEY);
    for body in &bodies {
        for canary in [ADMIN_TOKEN, signing_hex.as_str()] {
            assert!(
                !body.contains(canary),
                "a discovery read served a secret value: {body}"
            );
        }
    }
    assert!(s.operator_token.exists());
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn core_never_names_plugin_in_kinds() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-blind").await;
    let kinds = s.get("/kinds").await;
    assert_eq!(kinds.status, 200, "{}", kinds.text);
    assert!(
        !kinds.text.contains(&format!("\"{}\"", s.store_module)),
        "/kinds names kinds, never the plugin a store runs: {}",
        kinds.text
    );
    let stores = s.get("/kinds/store/instances").await;
    assert_eq!(stores.status, 200, "{}", stores.text);
    let rows = items(&stores);
    assert_eq!(rows.len(), 1, "one store instance: {}", stores.text);
    let mut row = rows[0].clone();
    assert!(
        row["plugin"].is_object(),
        "the image is described in plugin{{}}: {}",
        stores.text
    );
    if let Some(object) = row.as_object_mut() {
        object.remove(&"plugin");
    }
    let rest = busbar_contract::json::to_string(&row).unwrap();
    assert!(
        !rest.contains(&format!("\"{}\"", s.store_module)),
        "outside plugin{{}} the row names no plugin: {rest}"
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn view_rows_positional_over_the_root() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-view").await;
    let routing = s.get("/kinds/core/instances/routing").await;
    let views = routing.body["views"]
        .as_array()
        .map(|v| v.to_vec())
        .unwrap_or_default();
    assert!(
        views.iter().any(|v| v["view"] == "pools"),
        "core/routing offers its pools view: {}",
        routing.text
    );
    let view = s.get("/kinds/core/instances/routing/views/pools").await;
    assert_eq!(view.status, 200, "{}", view.text);
    assert_eq!(
        keys(&view.body),
        ["as_of", "fields", "next_cursor", "rows"],
        "{}",
        view.text
    );
    let width = view.body["fields"].as_array().map(|f| f.len()).unwrap_or(0);
    assert!(width > 0, "{}", view.text);
    for row in view.body["rows"]
        .as_array()
        .map(|r| r.to_vec())
        .unwrap_or_default()
    {
        assert_eq!(
            row.as_array().map(|r| r.len()),
            Some(width),
            "each row is positional, one cell per field"
        );
    }
    assert_eq!(
        s.get("/kinds/core/instances/routing/views/pools?filter=inflight:1")
            .await
            .status,
        400,
        "a filter names a dimension or id field"
    );
    assert_eq!(
        s.get("/kinds/core/instances/routing/views/nope")
            .await
            .status,
        404
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn per_kind_paths_removed() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-removed").await;
    let named = format!("/identity-providers/{}", s.operator);
    let removed: Vec<(reqwest::Method, String)> = vec![
        (reqwest::Method::GET, "/models".into()),
        (reqwest::Method::GET, "/providers".into()),
        (reqwest::Method::GET, "/pools".into()),
        (reqwest::Method::GET, "/pools/main".into()),
        (reqwest::Method::GET, "/export".into()),
        (reqwest::Method::GET, "/export/metrics".into()),
        (reqwest::Method::PUT, "/export/metrics".into()),
        (reqwest::Method::DELETE, "/export/metrics".into()),
        (reqwest::Method::PATCH, "/export/metrics/settings".into()),
        (reqwest::Method::GET, "/identity-providers".into()),
        (reqwest::Method::GET, named.clone()),
        (reqwest::Method::PUT, named.clone()),
        (reqwest::Method::DELETE, named.clone()),
        (reqwest::Method::PATCH, format!("{named}/settings")),
    ];
    for (method, path) in removed {
        let body = (method != reqwest::Method::GET && method != reqwest::Method::DELETE)
            .then(|| json!({"module": "x", "settings": {}}));
        let read = s.send(method.clone(), &path, body.as_ref()).await;
        assert_eq!(
            read.status, 404,
            "{method} {path} is removed: {}",
            read.text
        );
        assert_eq!(
            read.body["error"]["code"], "not_found",
            "{method} {path}: {}",
            read.text
        );
    }
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn plane_facts_path_gone() {
    isolated!(CHILD, WITNESS, witness = "kinds");
    let s = serve("kinds-plane-facts").await;
    for path in ["/plane-facts", "/plane-facts?plane=llm"] {
        let read = s.get(path).await;
        assert_eq!(read.status, 404, "{path} is deleted in MR5: {}", read.text);
    }
    s.finish();
    println!("{WITNESS}");
}
