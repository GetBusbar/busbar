use crate::root::test_plugins as plugins;

use busbar_kernel::admin_verbs::{
    connect_reply, AdminReply, AdminReqCtx, PlaneTrust, PlaneVerbError,
};
use busbar_kernel::plane_driver::EngineHost;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A view `serde_json` cannot render: JSON object keys are strings, so a map keyed by a pair is
/// a serialization error rather than a type error -- exactly the shape of mistake a plane's own
/// view struct can acquire without the compiler saying a word.
#[derive(serde::Serialize)]
struct UnrenderableView {
    per_endpoint: BTreeMap<(String, String), u64>,
}

struct NanPlane;

impl PlaneTrust for NanPlane {
    const PLANE: &'static str = "fixture";
    type Subject = ();
    type View = UnrenderableView;

    fn resolve(_host: &Arc<dyn EngineHost>, _name: &str) -> Result<(), PlaneVerbError> {
        Ok(())
    }

    async fn look(
        _subject: (),
        _host: Arc<dyn EngineHost>,
        _name: String,
    ) -> Result<UnrenderableView, PlaneVerbError> {
        Ok(UnrenderableView {
            per_endpoint: BTreeMap::from([(("a".to_string(), "b".to_string()), 1)]),
        })
    }
}

#[tokio::test]
async fn a_view_that_will_not_serialize_is_not_answered_as_applied() {
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
    let directory = plugins::scratch("admin-view-serialization");
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
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let host: Arc<dyn EngineHost> = busbar_kernel::plane_driver::engine_host(&app);
    let ctx = AdminReqCtx {
        host,
        name: "anything".to_string(),
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        principal: None,
        consumed: None,
        query: None,
        serve: busbar_kernel::plane_driver::serve::ServeTables::default(),
    };
    let reply = connect_reply::<NanPlane>(ctx).await;
    assert!(
        matches!(reply, AdminReply::Rejected(PlaneVerbError::Internal(_))),
        "a view that will not serialize is an internal rejection, never an empty success"
    );
}
