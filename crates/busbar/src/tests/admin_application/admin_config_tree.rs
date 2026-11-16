// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 14 over the real root: `GET /config/tree`, declared and effective, and
//! the secret rule on every admin read. The admin token, the signing key and a minted key's token
//! are canaries: none may reach any admin body, in raw, hex, base64 or base64url form.

use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine as _;
use busbar_contract::json::{json, JsonContainerTrait, JsonValueTrait, Value};

const CHILD: &str = "BUSBAR_ADMIN_CONFIG_TREE_CHILD";
const WITNESS: &str = "actual root config tree assertions completed";

/// The operator credential (the `x-admin-token` file's content).
const ADMIN_TOKEN: &str = "tree-canary-admin-0f3c9a71e2b8";
/// The key-signing input (its file holds the hex of these 32 bytes).
const SIGNING_KEY: &[u8; 32] = b"tree-canary-signing-key-7d41e9ab";

struct Served {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
    client: reqwest::Client,
    /// The document written to the operator's file.
    document: Value,
    signing_key: std::path::PathBuf,
    operator_token: std::path::PathBuf,
    operator: String,
    record_user_key: [u8; 32],
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
        self.read(
            self.client
                .get(self.url(path))
                .header("x-admin-token", ADMIN_TOKEN),
        )
        .await
    }

    async fn send(&self, method: reqwest::Method, path: &str, body: &Value) -> Read {
        self.read(
            self.client
                .request(method, self.url(path))
                .header("x-admin-token", ADMIN_TOKEN)
                .header("content-type", "application/json")
                .body(busbar_contract::json::to_vec(body).unwrap()),
        )
        .await
    }

    async fn read(&self, request: reqwest::RequestBuilder) -> Read {
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

/// Compose the real root from an operator file on disk (read as boot reads it, YAML), over the
/// actual Store, and serve it.
async fn serve(name: &str) -> Served {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(name);
    let settings = busbar_contract::json::parse_value(settings.to_string().as_bytes()).unwrap();
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode(SIGNING_KEY)).unwrap();
    std::fs::write(&operator_token, ADMIN_TOKEN).unwrap();
    let operator = busbar_kernel::config::operator_provider().to_string();
    let plugins = busbar_contract::json::parse_value(
        crate::root::test_plugins::trusted_config_document(&directory)
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let mut document = json!({
        "providers": {}, "models": {},
        "auth": { "chain": [], "admin_auth": [operator.as_str()],
                  "signing_key": { "file": shown(&signing_key) } },
        "store": { "module": module.as_str(), "settings": settings },
        "advanced": {  },
        "groups": { "team": { "limits": [{ "budget": 20000, "per": "month" }] } },
        "identity-providers": {},
        "records": { "user": "pseudonymous" },
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
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(
        &config,
        &plugin_config,
        &busbar_kernel::preflight::Unopened,
    )
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
        Some(anchor.clone()),
        true,
    )
    .await
    .unwrap();
    crate::root::records_capture::configure(&deploy.records);
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module).await.unwrap();
    let identity = busbar_kernel::persistence::boot_identity::BootIdentity::new(anchor).unwrap();
    let deployment = identity.keep_deployment_id().await.unwrap();
    let seed = identity.stored_keyset().await.unwrap().unwrap();
    let signer = busbar_kernel_audit::AuditSigningKey::from_hex_seed(&seed).unwrap();
    let record_user_key = signer.derived_key(
        deployment.as_bytes(),
        crate::root::records_capture::USER_KEY_INFO,
    );
    let mac = busbar_contract::crypto::hmac_sha256(&record_user_key, b"canary-user").unwrap();
    assert_eq!(
        crate::root::records_capture::user("canary-user").unwrap(),
        format!("u_{}", hex::encode(&mac[..16])),
        "the derived canary is the process's bound K_user"
    );
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
        document,
        signing_key,
        operator_token,
        operator,
        record_user_key,
    }
}

fn text_of(value: &Value) -> String {
    busbar_contract::json::to_string(value).unwrap()
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .map(|o| o.iter().map(|(k, _)| k.to_owned()).collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

/// Every form a canary could be served in.
fn forms(canary: &[u8]) -> Vec<String> {
    let mut forms = vec![
        hex::encode(canary),
        hex::encode_upper(canary),
        base64::engine::general_purpose::STANDARD.encode(canary),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(canary),
        base64::engine::general_purpose::URL_SAFE.encode(canary),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canary),
    ];
    if let Ok(raw) = std::str::from_utf8(canary) {
        forms.push(raw.to_owned());
    }
    forms
}

#[tokio::test]
async fn config_tree_effective_has_every_section() {
    isolated!(CHILD, WITNESS, witness = "config tree");
    let s = serve("config-tree-effective").await;
    let tree = s.get("/config/tree").await;
    assert_eq!(tree.status, 200, "{}", tree.text);
    assert_eq!(tree.body["view"], "effective");
    assert_eq!(tree.body["layer"], "merged");
    assert!(tree.body["config_generation"].is_number(), "{}", tree.text);
    let etag = tree.etag.clone().expect("the tree carries the config ETag");
    assert!(etag.starts_with("\"dep_"), "config ETag: {etag}");
    let again = s
        .read(
            s.client
                .get(s.url("/config/tree"))
                .header("x-admin-token", ADMIN_TOKEN)
                .header("if-none-match", &etag),
        )
        .await;
    assert_eq!(again.status, 304, "the tree answers If-None-Match");

    // Every section the kernel reads back is served, and `process` beside them.
    let settings = s.get("/config/settings").await;
    assert_eq!(settings.status, 200, "{}", settings.text);
    let read_back = &settings.body["configuration"]["values"]["sections"];
    assert!(read_back.is_object(), "{}", settings.text);
    let served = keys(&tree.body["sections"]);
    for section in keys(read_back) {
        assert!(
            served.contains(&section),
            "/config/tree omits section `{section}`: {served:?}"
        );
    }
    assert!(served.contains(&"process".to_owned()), "{served:?}");
    assert!(
        tree.body["sections"]["process"]["inputs"]
            .as_array()
            .is_some_and(|inputs| inputs.iter().any(|i| i["name"] == "--config"
                && i["set"].as_bool() == Some(true)
                && i["value"].is_null())),
        "the config path is an input shown by presence: {}",
        tree.text
    );
    assert_eq!(
        keys(&tree.body["digest"]["sections"]),
        served,
        "a digest per served section"
    );
    assert!(tree.body["digest"]["document"]
        .as_str()
        .is_some_and(|d| d.starts_with("sha256:")));

    // `section=` narrows to one dotted key, nested as it sits.
    let narrowed = s
        .get("/config/tree?section=limits.request_body_max_bytes")
        .await;
    assert_eq!(narrowed.status, 200, "{}", narrowed.text);
    assert_eq!(keys(&narrowed.body["sections"]), vec!["limits".to_owned()]);
    assert_eq!(
        text_of(&narrowed.body["sections"]["limits"]["request_body_max_bytes"]),
        text_of(&tree.body["sections"]["limits"]["request_body_max_bytes"]),
    );
    let missing = s.get("/config/tree?section=limits.no_such_key").await;
    assert_eq!(missing.status, 404, "{}", missing.text);
    for refused in [
        "/config/tree?view=effective&layer=base",
        "/config/tree?view=sideways",
        "/config/tree?layer=everything",
        "/config/tree?colour=blue",
    ] {
        assert_eq!(s.get(refused).await.status, 400, "{refused}");
    }
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn config_tree_declared_round_trips() {
    isolated!(CHILD, WITNESS, witness = "config tree");
    let s = serve("config-tree-declared").await;
    let tree = s.get("/config/tree?view=declared&layer=base").await;
    assert_eq!(tree.status, 200, "{}", tree.text);
    assert_eq!(tree.body["view"], "declared");
    let layers = &tree.body["layers"];
    assert_eq!(keys(layers), vec!["base".to_owned()], "{}", tree.text);
    let base = &layers["base"];
    assert_eq!(base["state"], "available", "{}", tree.text);
    // Every section the operator wrote is served, and a section that holds no secret position
    // is served exactly as written.
    assert_eq!(keys(&base["sections"]), keys(&s.document), "{}", tree.text);
    for section in ["providers", "models", "groups", "advanced"] {
        assert_eq!(
            text_of(&base["sections"][section]),
            text_of(&s.document[section]),
            "declared `{section}` round-trips"
        );
    }
    assert_eq!(
        base["sections"]["auth"]["admin_auth"][0],
        s.operator.as_str()
    );
    assert_eq!(
        keys(&base["digest"]["sections"]),
        keys(&s.document),
        "a digest per declared section"
    );
    let narrowed = s
        .get("/config/tree?view=declared&layer=base&section=groups.team")
        .await;
    assert_eq!(narrowed.status, 200, "{}", narrowed.text);
    let team = s.document["groups"]["team"].clone();
    assert_eq!(
        text_of(&narrowed.body["layers"]["base"]["sections"]),
        text_of(&json!({"groups": {"team": team}})),
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn config_tree_overlay_layer() {
    isolated!(CHILD, WITNESS, witness = "config tree");
    let s = serve("config-tree-overlay").await;
    let wrote = s
        .send(
            reqwest::Method::POST,
            "/groups",
            &json!({"name": "user:ann", "config": {"parent": "team"}}),
        )
        .await;
    assert!(wrote.status < 300, "{}: {}", wrote.status, wrote.text);
    let tree = s.get("/config/tree?view=declared&layer=overlay").await;
    assert_eq!(tree.status, 200, "{}", tree.text);
    assert_eq!(keys(&tree.body["layers"]), vec!["overlay".to_owned()]);
    let overlay = &tree.body["layers"]["overlay"];
    assert_eq!(overlay["state"], "available", "{}", tree.text);
    assert!(overlay["version"].is_number(), "{}", tree.text);
    assert_eq!(
        overlay["sections"]["groups"]["user:ann"]["parent"], "team",
        "the API-applied group is in the overlay layer: {}",
        tree.text
    );
    for tombstones in ["deleted", "deleted_groups"] {
        assert!(
            overlay["sections"][tombstones].is_array(),
            "the overlay serves its `{tombstones}` tombstones: {}",
            tree.text
        );
    }
    assert!(
        overlay["sections"]["groups"]["team"].is_null(),
        "a base group is not an overlay document"
    );
    let merged = s.get("/config/tree?view=declared").await;
    assert_eq!(merged.status, 200, "{}", merged.text);
    assert_eq!(merged.body["layer"], "merged");
    assert_eq!(
        keys(&merged.body["layers"]),
        vec!["base".to_owned(), "overlay".to_owned()]
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn secret_ref_shown_for_references() {
    isolated!(CHILD, WITNESS, witness = "config tree");
    let s = serve("config-tree-references").await;
    let tree = s.get("/config/tree?view=declared&layer=base").await;
    assert_eq!(tree.status, 200, "{}", tree.text);
    let sections = &tree.body["layers"]["base"]["sections"];
    for (at, position, path) in [
        (
            "auth.signing_key",
            &sections["auth"]["signing_key"],
            &s.signing_key,
        ),
        (
            "identity-providers.<operator>.token",
            &sections["identity-providers"][s.operator.as_str()]["token"],
            &s.operator_token,
        ),
    ] {
        assert_eq!(
            keys(position),
            vec!["secret_ref".to_owned(), "set".to_owned()],
            "{at} is a secret position: {position}"
        );
        assert_eq!(position["set"].as_bool(), Some(true), "{at}");
        assert_eq!(
            position["secret_ref"].as_str(),
            Some(format!("file:{}", shown(path)).as_str()),
            "{at} shows the reference text"
        );
    }
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn no_secret_in_any_admin_body() {
    isolated!(CHILD, WITNESS, witness = "config tree");
    let s = serve("config-tree-canary").await;
    // A runtime-minted secret: the key token, shown once by the mint and by no read.
    let minted = s
        .send(
            reqwest::Method::POST,
            "/keys",
            &json!({"name": "tree-canary"}),
        )
        .await;
    assert!(minted.status < 300, "{}: {}", minted.status, minted.text);
    let token = minted.body["token"]
        .as_str()
        .expect("the mint shows its token once")
        .to_owned();
    let id = minted.body["id"].as_str().expect("minted id").to_owned();

    let signing_hex = hex::encode(SIGNING_KEY);
    let canaries: Vec<(&str, Vec<String>)> = vec![
        ("admin token", forms(ADMIN_TOKEN.as_bytes())),
        ("signing key", forms(SIGNING_KEY)),
        ("records user key", forms(&s.record_user_key)),
        ("signing key file", forms(signing_hex.as_bytes())),
        ("minted key token", forms(token.as_bytes())),
    ];

    let document = busbar_contract::json::parse_value(
        busbar_core_admin::v1::json::openapi_document().as_bytes(),
    )
    .expect("the embedded admin document parses");
    let mut reads: Vec<String> = document["paths"]
        .as_object()
        .expect("documented paths")
        .iter()
        .filter(|(path, operations)| {
            !path.contains('{')
                && operations["get"].is_object()
                && operations["get"]["x-busbar-plane"].is_null()
        })
        .filter_map(|(path, _)| path.strip_prefix("/api/v1/admin").map(str::to_owned))
        .collect();
    for tree in [
        "/config/tree",
        "/config/tree?view=effective",
        "/config/tree?view=declared",
        "/config/tree?view=declared&layer=base",
        "/config/tree?view=declared&layer=overlay",
        "/config/tree?view=declared&layer=merged",
    ] {
        reads.push(tree.to_owned());
    }
    reads.push(format!("/keys/{id}"));
    reads.push("/keys".to_owned());
    reads.push("/audit".to_owned());
    assert!(reads.len() >= 20, "too few admin reads: {reads:?}");

    for path in &reads {
        let read = s.get(path).await;
        if path.starts_with("/config/tree") {
            assert_eq!(read.status, 200, "{path}: {}", read.text);
        }
        for (canary, forms) in &canaries {
            for form in forms {
                assert!(
                    !read.text.contains(form.as_str()),
                    "GET {path} served the {canary} (as `{form}`)"
                );
            }
        }
    }
    s.finish();
    println!("{WITNESS}");
}
