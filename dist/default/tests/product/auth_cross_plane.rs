// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonValueTrait as _;
use busbar_kernel::auth::UpstreamCreds;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn test_open_door_regardless_of_upstream_creds() {
    crate::dist_root_install::install();
    for upstream_creds in [UpstreamCreds::Own, UpstreamCreds::Passthrough] {
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let module = crate::root::test_plugins::native_image(&library_path).name;
        let manifest = crate::root::test_plugins::native_manifest(
            "store",
            &library_path,
            plugins::FIXTURE_PUBLISHER,
        );
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch(&format!(
            "open-door-auth-{}",
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            serde_json::json!({
                "providers": {},
                "models": {},
                "auth": { "chain": [], "admin_auth": [] },
                "store": { "module": module, "settings": settings },
                "advanced": {  },
            }),
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the product deployment parses");
        let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        config.upstream_credentials = upstream_creds;
        let plugin_config = plugins::trusted_config(&directory);
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = crate::root::real_store::build_app(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the actual product builds the door deployment");

        assert!(app.auth.validate_token(None));
        assert!(app.auth.validate_token(Some("anything")));
        assert_eq!(app.upstream_creds(), upstream_creds);
        drop(limits);
        drop(rotate);
    }
}
