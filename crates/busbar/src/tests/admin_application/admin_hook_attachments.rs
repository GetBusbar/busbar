// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 8 over the real root: `PUT|DELETE /hooks/{name}/attachments/{target}`
//! edit the attach lists as durable document edits, and `HookView.attachments` reads them back.

use std::collections::HashSet;
use std::sync::Arc;

const CHILD: &str = "BUSBAR_ADMIN_HOOK_ATTACH_CHILD";
const WITNESS: &str = "actual root hook attachment assertions completed";

struct Served {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
    client: reqwest::Client,
}

impl Served {
    fn url(&self, path: &str) -> String {
        format!("http://{}/api/v1/admin{path}", self.addr)
    }
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(self.url(path))
            .header("x-admin-token", "admintok")
    }
    fn send(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.url(path))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    }
    async fn register(&self, name: &str) {
        let made = self
            .send(reqwest::Method::POST, "/hooks")
            .body(
                serde_json::json!({"name": name, "config": {"kind": "tap", "module": "test-hook"}})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert!(
            made.status().is_success(),
            "register {name}: {}",
            made.status()
        );
    }
    async fn attach(
        &self,
        name: &str,
        target: &str,
        position: serde_json::Value,
    ) -> reqwest::Response {
        self.send(
            reqwest::Method::PUT,
            &format!("/hooks/{name}/attachments/{target}"),
        )
        .body(serde_json::json!({ "position": position }).to_string())
        .send()
        .await
        .unwrap()
    }
    async fn attachments(&self, name: &str) -> serde_json::Value {
        let view: serde_json::Value = self
            .get(&format!("/hooks/{name}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        view["attachments"].clone()
    }
    fn finish(self) {
        self.handle.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn serve(name: &str, require_if_match: bool) -> Served {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(name);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([5u8; 32])).unwrap();
    std::fs::write(&operator_token, "admintok").unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {}, "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key },
                  "policy": { "require_if_match": require_if_match } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
        "hooks": { "base": { "kind": "tap", "module": "test-hook" } },
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let config_path = directory.join("config.json");
    let providers_path = directory.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .unwrap();
    let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let base_hook_names: HashSet<String> = config.hooks.keys().cloned().collect();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .unwrap();
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone()).unwrap();
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        base_hook_names,
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
    }
}

#[tokio::test]
async fn attach_is_idempotent() {
    isolated!(CHILD, WITNESS, witness = "hook attachment");
    let s = serve("hook-attach-idempotent", false).await;
    s.register("h1").await;
    let first = s.attach("h1", "pools", serde_json::json!("last")).await;
    assert_eq!(first.status().as_u16(), 200, "{:?}", first.text().await);
    let attached = s.attachments("h1").await;
    assert_eq!(
        attached,
        serde_json::json!([{"target": "pools", "instance": null, "position": 0}])
    );
    let before = s.get("/hooks").send().await.unwrap().headers()["etag"]
        .to_str()
        .unwrap()
        .to_string();
    let again = s.attach("h1", "pools", serde_json::json!("last")).await;
    assert_eq!(again.status().as_u16(), 200);
    assert_eq!(
        s.attachments("h1").await,
        attached,
        "a repeat is not a second entry"
    );
    let after = s.get("/hooks").send().await.unwrap().headers()["etag"]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        before, after,
        "an attach that changes nothing publishes nothing"
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn detach_observable() {
    isolated!(CHILD, WITNESS, witness = "hook attachment");
    let s = serve("hook-attach-detach", false).await;
    s.register("h1").await;
    s.register("h2").await;
    assert!(s
        .attach("h1", "pools", serde_json::json!("last"))
        .await
        .status()
        .is_success());
    assert!(s
        .attach("h2", "pools", serde_json::json!(0))
        .await
        .status()
        .is_success());
    assert_eq!(
        s.attachments("h1").await,
        serde_json::json!([{"target": "pools", "instance": null, "position": 1}])
    );
    let gone = s
        .send(reqwest::Method::DELETE, "/hooks/h1/attachments/pools")
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status().as_u16(), 200);
    assert_eq!(s.attachments("h1").await, serde_json::json!([]));
    assert_eq!(
        s.attachments("h2").await,
        serde_json::json!([{"target": "pools", "instance": null, "position": 0}])
    );
    let missing = s
        .send(reqwest::Method::DELETE, "/hooks/h1/attachments/pools")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn attach_base_defined_409() {
    isolated!(CHILD, WITNESS, witness = "hook attachment");
    let s = serve("hook-attach-base", false).await;
    let refused = s.attach("base", "pools", serde_json::json!("last")).await;
    assert_eq!(refused.status().as_u16(), 409);
    let body: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(body["error"]["reason"], "base_defined");
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn attach_unconfigured_instance_409() {
    isolated!(CHILD, WITNESS, witness = "hook attachment");
    let s = serve("hook-attach-unconfigured", false).await;
    s.register("h1").await;
    let refused = s
        .attach("h1", "tools.nowhere", serde_json::json!("last"))
        .await;
    assert_eq!(refused.status().as_u16(), 409);
    let body: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(body["error"]["reason"], "invalid_config");
    let no_pool = s
        .attach("h1", "pools.nowhere", serde_json::json!("last"))
        .await;
    assert_eq!(no_pool.status().as_u16(), 404);
    assert_eq!(s.attachments("h1").await, serde_json::json!([]));
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn attach_requires_if_match_when_required() {
    isolated!(CHILD, WITNESS, witness = "hook attachment");
    let s = serve("hook-attach-if-match", true).await;
    let made = s
        .send(reqwest::Method::POST, "/hooks")
        .body(
            serde_json::json!({"name": "h1", "config": {"kind": "tap", "module": "test-hook"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert!(made.status().is_success(), "{}", made.status());
    let refused = s.attach("h1", "pools", serde_json::json!("last")).await;
    assert_eq!(refused.status().as_u16(), 428);
    let body: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(body["error"]["reason"], "if_match_required");
    let etag = s.get("/hooks").send().await.unwrap().headers()["etag"]
        .to_str()
        .unwrap()
        .to_string();
    let allowed = s
        .send(reqwest::Method::PUT, "/hooks/h1/attachments/pools")
        .header("if-match", etag)
        .body(serde_json::json!({"position": "last"}).to_string())
        .send()
        .await
        .unwrap();
    assert!(allowed.status().is_success(), "{}", allowed.status());
    s.finish();
    println!("{WITNESS}");
}
