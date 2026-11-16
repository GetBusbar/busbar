// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_kernel as kernel;
use busbar_kernel::plane_driver::door::DoorSection;
use busbar_kernel::plane_driver::registry::BuildCtx;

use crate::root::test_plugins as plugins;

async fn lane_less_app(opening: Option<bool>) -> Arc<kernel::state::App> {
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
    let deploy = kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = crate::root::real_store::build_app(
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
    .expect("the actual product builds the readiness deployment");
    if !crate::root::kernel::ROOT_CARD.keeps_store() {
        limits.stage_boot();
        if !crate::root::kernel::ROOT_CARD.keeps_store() {
            crate::root::kernel::ROOT_CARD
                .keep_in_store(
                    app.governance
                        .as_ref()
                        .expect("the actual deployment configured governance")
                        .core_store_handle()
                        .expect("the configured Store exposes its rate-history slots"),
                    146,
                )
                .expect("the native rate-card Store binds");
        };
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the configured Store boots its initial rate history");
    }
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
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
            busbar_contract::yaml::from_str(if should_open {
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
    Arc::new(app)
}

async fn lane_less_healthz(opening: Option<bool>) -> (u16, Vec<u8>) {
    let resp =
        kernel::endpoints::healthz(kernel::state::CurrentApp(lane_less_app(opening).await)).await;
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    (status, body.to_vec())
}

#[tokio::test]
async fn healthz_with_no_model_lane_is_ready_when_a_configured_plane_opened() {
    assert_eq!(
        lane_less_healthz(Some(true)).await,
        (200, b"ok".to_vec()),
        "a lane-less deployment whose configured plane opened this generation is ready"
    );
}

#[tokio::test]
async fn healthz_with_no_model_lane_is_unready_when_the_planes_open_refused() {
    let key = kernel::plane_driver::registry::plane_decl_for_config_section("decisions")
        .expect("the actual decisions plane is installed")
        .key;
    assert_eq!(
        lane_less_healthz(Some(false)).await,
        (
            503,
            format!("plane '{key}' configured but not open").into_bytes()
        ),
        "a plane that is configured but did not open makes health 503 and names the plane"
    );
}

#[tokio::test]
async fn healthz_of_an_admin_only_engine_is_ready() {
    assert_eq!(
        lane_less_healthz(None).await,
        (200, b"ok".to_vec()),
        "no LLM plane, no providers and no other plane configured: lanes do not count against health"
    );
}

#[tokio::test]
async fn readiness_requires_its_root_state_and_present_configured_plane() {
    let mut app = lane_less_app(Some(true)).await;
    let missing = kernel::endpoints::readyz(kernel::state::CurrentApp(app.clone()), None).await;
    assert_eq!(missing.status(), 503);
    let core = app
        .governance
        .as_ref()
        .unwrap()
        .core_store_handle()
        .unwrap();
    let journal = kernel::persistence::journal::runtime::RuntimeJournal::open(
        core,
        899,
        kernel::persistence::journal::runtime::BufferBudget {
            records: 1,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let probes = Arc::new(kernel::endpoints::ProbeState::new(Some(journal)));
    let response = kernel::endpoints::readyz(
        kernel::state::CurrentApp(app.clone()),
        Some(axum::Extension(probes.clone())),
    )
    .await;
    assert_eq!(response.status(), 200);
    let decl = kernel::plane_driver::registry::plane_decl_for_config_section("decisions").unwrap();
    Arc::get_mut(&mut app).unwrap().plane_slots.remove(decl.key);
    let response = kernel::endpoints::readyz(
        kernel::state::CurrentApp(app),
        Some(axum::Extension(probes)),
    )
    .await;
    assert_eq!(
        response.status(),
        503,
        "a configured plane without a slot cannot be ready"
    );
}

#[tokio::test]
async fn readiness_observes_journal_custody_without_affecting_liveness_or_admission() {
    let app = lane_less_app(None).await;
    let gov = app.governance.as_ref().unwrap();
    let core = gov.core_store_handle().unwrap();
    let journal = kernel::persistence::journal::runtime::RuntimeJournal::open(
        core,
        900,
        kernel::persistence::journal::runtime::BufferBudget {
            records: 1,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let probes = Arc::new(kernel::endpoints::ProbeState::new(Some(journal.clone())));
    let before = gov.admissions().live();
    for blocked in [false, true] {
        if blocked {
            journal
                .stage_run(&[busbar_kernel_wal::Entry::new(
                    busbar_kernel_wal::RecordClass::Load,
                    Vec::new(),
                )])
                .unwrap();
        }
        let response = kernel::endpoints::readyz(
            kernel::state::CurrentApp(app.clone()),
            Some(axum::Extension(probes.clone())),
        )
        .await;
        assert_eq!(response.status().as_u16(), if blocked { 503 } else { 200 });
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
        assert_eq!(kernel::endpoints::livez().await.status(), 200);
        assert_eq!(gov.admissions().live(), before);
    }
    probes.begin_stopping();
    journal.stop_staging().unwrap();
    let response = kernel::endpoints::readyz(
        kernel::state::CurrentApp(app),
        Some(axum::Extension(probes)),
    )
    .await;
    assert_eq!(response.status(), 503);
    assert_eq!(kernel::endpoints::livez().await.status(), 200);
}

#[tokio::test]
async fn probe_routes_are_public_and_head_has_no_body() {
    use tower::ServiceExt;
    let mut app = lane_less_app(None).await;
    Arc::get_mut(&mut app).unwrap().governance = None;
    let handle = Arc::new(kernel::state::AppHandle::new(app));
    let probes = Arc::new(kernel::endpoints::ProbeState::new(None));
    let router = kernel::router::build_admin_router_on_with_dispatch_layer(
        &handle,
        1024,
        false,
        crate::root::listener::deferred_dispatch_layer,
    )
    .layer(axum::Extension(probes));
    for path in ["/livez", "/readyz"] {
        for method in ["GET", "HEAD"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                200,
                "{method} {path} without credentials"
            );
            assert_eq!(
                response.headers()["content-type"],
                "text/plain; charset=utf-8"
            );
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                body.as_ref(),
                if method == "HEAD" {
                    b"".as_slice()
                } else {
                    b"ok".as_slice()
                }
            );
        }
    }
}

#[tokio::test]
async fn readiness_refuses_missing_durability_and_closed_governed_admission() {
    let app = lane_less_app(None).await;
    let gov = app.governance.as_ref().unwrap();
    let without_journal = Arc::new(kernel::endpoints::ProbeState::new(None));
    assert_eq!(
        kernel::endpoints::readyz(
            kernel::state::CurrentApp(app.clone()),
            Some(axum::Extension(without_journal))
        )
        .await
        .status(),
        503
    );
    let journal = kernel::persistence::journal::runtime::RuntimeJournal::open(
        gov.core_store_handle().unwrap(),
        901,
        kernel::persistence::journal::runtime::BufferBudget {
            records: 1,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let probes = Arc::new(kernel::endpoints::ProbeState::new(Some(journal)));
    assert_eq!(
        kernel::endpoints::readyz(
            kernel::state::CurrentApp(app.clone()),
            Some(axum::Extension(probes.clone()))
        )
        .await
        .status(),
        200
    );
    gov.admissions().close();
    assert_eq!(
        kernel::endpoints::readyz(
            kernel::state::CurrentApp(app),
            Some(axum::Extension(probes))
        )
        .await
        .status(),
        503
    );
    assert_eq!(kernel::endpoints::livez().await.status(), 200);
}
