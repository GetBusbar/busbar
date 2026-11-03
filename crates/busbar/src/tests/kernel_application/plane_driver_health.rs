// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_kernel as kernel;
use busbar_kernel::plane_driver::door::DoorSection;
use busbar_kernel::plane_driver::registry::BuildCtx;

use crate::root::test_plugins as plugins;

// The control is section DATA handed to the actual installed door's FACING call.
// No test implementation decides whether OPEN succeeded.
fn lane_less_healthz(opening: Option<bool>) -> (u16, Vec<u8>) {
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
    let directory = plugins::scratch(&format!("plane-health-{}", kernel::door::op_id().counter()));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the readiness deployment");
    if !crate::root::kernel::ROOT_CARD.keeps_store() {
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD.keep_in_store(
            app.governance
                .as_ref()
                .expect("the actual deployment configured governance")
                .store_calls()
                .expect("the configured Store exposes its rate-history slots"),
            146,
        );
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the configured Store boots its initial rate history");
    }
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert_eq!(
        app.engine_tables_view().lane_count(),
        0,
        "no model lane may mask the plane's readiness"
    );
    if let Some(should_open) = opening {
        let decl = kernel::plane_driver::registry::plane_decl_for_config_section("decisions")
            .expect("the actual decisions plane is installed");
        let section = DoorSection::new(
            decl.door,
            decl.config_section,
            serde_yaml::from_str(if should_open {
                "models: {}"
            } else {
                "models: []"
            })
            .expect("the section data is YAML"),
        );
        let section_defs = section.as_defs();
        let slot = (decl.build)(
            decl,
            &BuildCtx {
                endpoint_slot: None,
                plane_defs: &section_defs,
                public_url: None,
                prior: None,
                providers: None,
            },
        )
        .expect("the configured actual door produces its generation slot");
        assert_eq!(
            kernel::plane_driver::door::opened(slot.as_ref()),
            should_open,
            "the real door must judge the control before healthz is queried"
        );
        app.plane_sections = Some([decl.config_section].into_iter().collect());
        app.plane_slots.insert(decl.key, slot);
    }
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let resp = kernel::endpoints::healthz(kernel::state::CurrentApp(Arc::new(app))).await;
            let status = resp.status().as_u16();
            let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
            (status, body.to_vec())
        })
}

#[test]
fn healthz_with_no_model_lane_is_ready_when_a_configured_plane_opened() {
    assert_eq!(
        lane_less_healthz(Some(true)),
        (200, b"ok".to_vec()),
        "a lane-less deployment whose configured plane opened this generation is ready"
    );
}

#[test]
fn healthz_with_no_model_lane_is_unready_when_the_planes_open_refused() {
    assert_eq!(
        lane_less_healthz(Some(false)),
        (503, b"no usable lanes".to_vec()),
        "a plane that is configured but did not open makes nothing ready"
    );
}

#[test]
fn healthz_with_no_plane_configured_stays_unready() {
    assert_eq!(
        lane_less_healthz(None),
        (503, b"no usable lanes".to_vec()),
        "with nothing configured /healthz answers 1.5.5's 503"
    );
}
