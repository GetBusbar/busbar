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
}

use crate::root::test_plugins as plugins;
use std::sync::Arc;

#[tokio::test]
async fn an_unmounted_plane_claims_no_path_by_url_shape() {
    busbar_kernel::snapshot::init_with(std::time::Duration::from_secs(60));
    let mounting: Vec<_> = linked::planes()
        .iter()
        .copied()
        .filter(|d| !d.fallback)
        .collect();
    assert!(
        !mounting.is_empty(),
        "the test-linked roster carries at least one plane that mounts a path"
    );
    for decl in mounting {
        let path = format!("/{}", decl.key);

        let yaml = "providers: {}\nmodels: {}\n";
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = plugins::manifest("store", &module, plugins::FIXTURE_PUBLISHER);
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch(&format!(
            "residual_envelope_cross_plane-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let mut document: serde_json::Value =
            serde_yaml::from_str(yaml).expect("the concrete product deployment is valid YAML");
        document["store"] = serde_json::json!({"module": module, "settings": settings});
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": []});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(
            &deploy,
            &std::collections::HashMap::from([(
                "fixture".to_string(),
                serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:9\n")
                    .expect("provider definition"),
            )]),
        )
        .expect("the product deployment resolves");
        let plugin_config = plugins::trusted_config(&directory);
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
        .expect("the actual product builds the door deployment");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let app = Arc::new(app);

        let v = oversized_413_body(app, &path).await;

        assert!(
            v.get("jsonrpc").is_none(),
            "nothing mounted the `{}` plane, so `{path}` is a residual path and must not be \
             answered as a plane; got {v}",
            decl.key
        );
        assert!(
            v.pointer("/error/message").is_some(),
            "the residual plane answers the widely-understood envelope on `{path}`; got {v}"
        );
    }
}

async fn oversized_413_body(app: Arc<busbar_kernel::state::App>, path: &str) -> serde_json::Value {
    let (router, _) = busbar_kernel::router::build_router_with_limits(app, 64, 16, false);
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
