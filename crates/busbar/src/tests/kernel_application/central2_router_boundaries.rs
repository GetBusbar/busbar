// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[tokio::test]
async fn oversized_request_413_is_reshaped_on_the_live_stack() {
    const CHILD: &str = "BUSBAR_CENTRAL2_BODY_LIMIT_CHILD";
    const WITNESS: &str = "actual root live body limit completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("central2-live-body-limit");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD.keep_in_store(
        app.governance
            .as_ref()
            .unwrap()
            .store_calls()
            .expect("actual Store calls"),
        113,
    );
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    limits.keep().expect("actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let (mut router, _handle) =
        busbar_kernel::build_router_with_limits(Arc::new(app), 64, 1024, false);
    let oversized = "x".repeat(4096);
    let payload = serde_json::json!({"pad": oversized}).to_string();
    let req = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("content-length", payload.len().to_string())
        .body(axum::body::Body::from(payload))
        .unwrap();
    type Req = axum::http::Request<axum::body::Body>;
    std::future::poll_fn(|cx| <axum::Router as tower::Service<Req>>::poll_ready(&mut router, cx))
        .await
        .unwrap();
    let r = <axum::Router as tower::Service<Req>>::call(&mut router, req)
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 413, "the body cap must reject");
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = {
        use http_body_util::BodyExt as _;
        let bytes = r.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    };
    assert!(
        ct.starts_with("application/json"),
        "an oversized-body 413 must speak JSON, not the bare `{body}` router tell (content-type \
         was `{ct}`) — the reshape layer's sentinel no longer matches what axum emits"
    );
    let v: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("the 413 body must be JSON ({e}): {body}"));
    assert!(
        v.get("error").is_some(),
        "the 413 must carry the error envelope; got {v}"
    );
    println!("{WITNESS}");
}
