//! THE ADMIN REQUEST CHAIN, END TO END, WITH NO PLANE ENTRY FACE ANYWHERE ON IT.
//!
//! The administrative surface serves operators on its own listener. It is a compiled-in core-admin surface, not a plugin or traffic `Plane`, and there is no `control` kind.
//!
//!
//!
//!
//!
//! Nothing ever dispatched through that face. The chain an administrative request actually takes,
//! which is what this file drives:
//!
//! 1. the connection arrives on `admin_listen`, a listener of its own, bound in `main.rs` and
//!    ABSENT from the data router;
//! 2. [`super::mount`] wraps the admin router. It asks two questions of the closed table before it
//!    will take a request into the loop at all — is the path under `ADMIN_PREFIX`, and does
//!    `busbar_core_admin::admin_codec::verbs::resolve` name a row for this method and path — and
//!    hands anything else straight to the surface that already answers it;
//! 3. the body is read to the operator's own cap, an `AdminRequest` is built, and
//!    `AdminNode::answer` runs its steps directly ([`super::decide`]);
//! 4. the steps are the ADMIN UNITS', not a `Plane`'s: decode resolves the verb off the same closed
//!    table, authenticate/verify resolve and keep the principal, approve compares the 1.5.5 matrix
//!    against the grant, admit takes no concurrency lease, ROUTE hands the operation to the mounted
//!    surface, and AUDIT seals the operation class and finish — the mutation's row on the ONE
//!    administrative ring is the kernel's, written by the core-admin handler at Route (item 237);
//! 5. the answer the surface produced comes back, byte for byte.
//!
//! So these cells assert two things the removal must not have cost: that a real verb still travels
//! that whole chain and comes back with the surface's own bytes, and that the metering and audit the
//! chain performs are still performed — by the admin units, explicitly, where they always were,
//! rather than inherited by pretending an operator's request is somebody's traffic.

use super::*;

#[cfg(feature = "root-admin")]
const THE_OPERATORS_CREDENTIAL: &str = "admin-token";

#[cfg(feature = "root-admin")]
struct ADirectoryThatMintedIt;

#[cfg(feature = "root-admin")]
impl crate::root::auth_bindings::VirtualKeyDirectory for ADirectoryThatMintedIt {
    fn verify(
        &self,
        credential: &str,
        _now: u64,
        _expected_aud: Option<&str>,
    ) -> Option<crate::root::auth_bindings::KeyFacts> {
        (credential == THE_OPERATORS_CREDENTIAL).then(|| crate::root::auth_bindings::KeyFacts {
            id: "key-admin-1".to_string(),
            name: "the operator credential these cells present".to_string(),
        })
    }

    fn revoked(&self, _credential: &str) -> bool {
        false
    }
}

#[cfg(feature = "root-admin")]
struct IdentifiesTheOperator;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesTheOperator {
    fn name(&self) -> &'static str {
        "identifies-the-operator"
    }

    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some(THE_OPERATORS_CREDENTIAL) => {
                busbar_kernel_identity::module::AuthOutcome::Identify(
                    busbar_kernel_identity::principal::Principal::from_id(
                        crate::root::auth_bindings::ADMIN_PRINCIPAL_ID,
                    ),
                )
            }
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

#[cfg(feature = "root-admin")]
fn a_door_that_identifies_the_operator() -> busbar_kernel_identity::AuthChain {
    busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-the-operator".to_string(),
            module: Box::new(IdentifiesTheOperator),
        }],
        false,
    )
}

/// What the mounted surface below the wrap saw, and what it answered.
///
/// A RECORDING surface, not a silent one: a walk that never reached the operation and a walk that
/// reached it and came back look identical from the response alone if the wrap is willing to
/// manufacture an answer of its own. Reading what the surface received is what tells them apart.
#[cfg(feature = "root-admin")]
#[derive(Default)]
struct SurfaceLog {
    seen: std::sync::Mutex<Vec<(String, String, Vec<u8>)>>,
}

#[cfg(feature = "root-admin")]
impl SurfaceLog {
    fn seen(&self) -> Vec<(String, String, Vec<u8>)> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[cfg(feature = "root-admin")]
const THE_SURFACES_OWN_BYTES: &[u8] =
    br#"{"answered_by":"the surface below the wrap","entries":[]}"#;

#[cfg(feature = "root-admin")]
fn a_recording_surface(log: Arc<SurfaceLog>) -> axum::Router {
    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let log = Arc::clone(&log);
            async move {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .expect("a test body is always readable");
                log.seen.lock().unwrap_or_else(|p| p.into_inner()).push((
                    parts.method.as_str().to_string(),
                    parts
                        .uri
                        .path_and_query()
                        .map_or_else(|| parts.uri.path().to_string(), ToString::to_string),
                    bytes.to_vec(),
                ));
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(THE_SURFACES_OWN_BYTES.to_vec()))
                    .expect("the response builds")
            }
        },
    ))
}

#[cfg(feature = "root-admin")]
struct ANodeWhoseChainThisCellReads {
    router: axum::Router,
    surface: Arc<SurfaceLog>,
}

#[cfg(feature = "root-admin")]
fn mounted_over(
    inner: axum::Router,
    request_body_max_bytes: usize,
    door: busbar_kernel_identity::AuthChain,
    tweak: impl FnOnce(&mut crate::root::kernel::ProductionUnits),
) -> axum::Router {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let held = Arc::new(std::sync::Mutex::new(durability));
    mount(
        inner,
        crate::root::kernel::new_kernel(),
        request_body_max_bytes,
        move |dispatch| {
            let mut units = crate::root::kernel::ProductionUnits::admin_only_sharing(
                dispatch,
                crate::root::units_admin::door_of_chain(door),
                held,
                None,
            )
            .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                ADirectoryThatMintedIt,
            )));
            tweak(&mut units);
            units
        },
    )
}

#[cfg(feature = "root-admin")]
fn a_node() -> ANodeWhoseChainThisCellReads {
    let surface = Arc::new(SurfaceLog::default());

    let router = mounted_over(
        a_recording_surface(Arc::clone(&surface)),
        64 * 1024,
        a_door_that_identifies_the_operator(),
        |_| {},
    );
    ANodeWhoseChainThisCellReads { router, surface }
}

#[cfg(feature = "root-admin")]
fn the_real_surface_bare_and_mounted() -> (axum::Router, axum::Router) {
    crate::dist_root_install::install();
    busbar_core_admin::install();

    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &[0x5a; 32],
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(
            crate::root::real_store::records(),
            None,
            Some(signer),
        )
        .expect("governance"),
    );
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        },
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    built.governance = Some(gov);
    let app = std::sync::Arc::new(built);
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let mounted = mounted_over(
        bare.clone(),
        1 << 20,
        a_door_that_identifies_the_operator(),
        |_| {},
    );
    (bare, mounted)
}

#[cfg(feature = "root-admin")]
async fn over_the_listener(
    node: &ANodeWhoseChainThisCellReads,
    method: &str,
    path: &str,
    body: &'static [u8],
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    over(&node.router, method, path, body.to_vec()).await
}

#[cfg(feature = "root-admin")]
async fn over(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    send(
        router,
        method,
        path,
        body,
        Some(THE_OPERATORS_CREDENTIAL),
        None,
    )
    .await
}

#[cfg(feature = "root-admin")]
async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Vec<u8>,
    credential: Option<&str>,
    idempotency_key: Option<&str>,
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    use tower::ServiceExt;

    let mut request = axum::http::Request::builder().method(method).uri(path);
    if let Some(credential) = credential {
        request = request.header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {credential}"),
        );
    }
    if let Some(key) = idempotency_key {
        request = request.header("idempotency-key", key);
    }
    let request = request
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("the request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the mounted router answers");
    let status = response.status().as_u16();
    let headers = header_pairs(response.headers());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the answer's body is readable");
    (status, bytes.to_vec(), headers)
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_mounted_live_admin_door_keeps_no_verdict_apart_from_bad_credentials() {
    use busbar_contract::auth_calls::{
        AuthCalls, Verified, VerifyAnswer, VerifyRequest, Verifying,
    };

    struct ProbeDoor(Option<Verified>);
    impl AuthCalls for ProbeDoor {
        fn name(&self) -> &str {
            "root-admin-probe"
        }
        fn facts(&self) -> u32 {
            0
        }
        fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
            self.0.clone().map(Into::into)
        }
        fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
            panic!("the root refusal must precede the inner awaited middleware")
        }
        fn refresh(&self) -> Result<u64, String> {
            Ok(0)
        }
    }

    crate::dist_root_install::install();
    busbar_core_admin::install();
    for (verified, expected_status, expected_code, expected_retry) in [
        (Some(Verified::Failed), 503, "unavailable", Some("1")),
        (None, 503, "unavailable", Some("1")),
        (Some(Verified::Reject), 401, "unauthorized", None),
        (Some(Verified::Overloaded), 401, "unauthorized", None),
    ] {
        crate::dist_root_install::install();
        let library_path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
        );
        let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "store",
            &module,
            crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual Store library reads");
        let directory = crate::root::test_plugins::scratch(&format!(
            "admin-unit-{}",
            busbar_kernel::door::op_id().counter(),
        ));
        let archive = crate::root::test_plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &library,
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {},
            "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
            "advanced": {"allow_destinations": ["127.0.0.1"]},
        }))
        .expect("the real admin deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the real admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut built, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            busbar_kernel::config::PluginsCfg {
                enabled: true,
                dir: directory.to_string_lossy().into_owned(),
                ..Default::default()
            },
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product builds the actual admin application");
        limits.keep().expect("the real application limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        built.admin_chain = vec!["external".to_string()];
        std::sync::Arc::get_mut(&mut built.admin_modules)
            .expect("the newly built admin chain has one owner")
            .modules
            .insert(
                "external".to_string(),
                busbar_kernel::auth::AdminModule {
                    calls: std::sync::Arc::new(ProbeDoor(verified)),
                },
            );
        let snapshot = std::sync::Arc::new(built);
        let app = Arc::new(busbar_kernel::state::AppHandle::new(snapshot));
        let surface = Arc::new(SurfaceLog::default());
        let book = crate::root::durability::node_book();
        let late = crate::root::serve::LateServices::new();
        let router = mount_node(
            a_recording_surface(surface.clone()),
            64 * 1024,
            &app,
            &book,
            None,
            &late,
            crate::root::adapters::BreakerPolicy::new(),
        );
        let (status, body, headers) = send(
            &router,
            "POST",
            "/api/v1/admin/keys",
            br#"{"name":"must-not-run"}"#.to_vec(),
            Some("presented"),
            None,
        )
        .await;
        assert_eq!(status, expected_status);
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("admin envelope");
        assert_eq!(answer["error"]["code"], expected_code);
        let retry = headers
            .iter()
            .find(|(name, _)| name == "retry-after")
            .map(|(_, value)| value.as_str());
        assert_eq!(retry, expected_retry);
        assert!(
            surface.seen().is_empty(),
            "a refused request executes no mutation"
        );
    }
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_real_verb_still_answers_end_to_end_over_the_admin_listener() {
    let node = a_node();
    let (status, body, headers) =
        over_the_listener(&node, "GET", "/api/v1/admin/audit?limit=4", b"").await;

    assert_eq!(status, 200, "the walk reached the operation and came back");
    assert_eq!(
        body, THE_SURFACES_OWN_BYTES,
        "the answer is the surface's own bytes, not something the wrap composed"
    );
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json"),
        "the surface's own headers travel back too: {headers:?}"
    );
    assert_eq!(
        node.surface.seen(),
        vec![(
            "GET".to_string(),
            "/api/v1/admin/audit?limit=4".to_string(),
            Vec::new()
        )],
        "the operation was reached exactly once, with the request the caller sent"
    );
}

#[cfg(feature = "root-admin")]
async fn audit_rows_for(router: &axum::Router, resource: &str) -> (u16, Vec<u8>) {
    let (status, body, _headers) = over(
        router,
        "GET",
        &format!("/api/v1/admin/audit?resource={resource}&limit=50"),
        Vec::new(),
    )
    .await;
    (status, body)
}

#[cfg(feature = "root-admin")]
fn actions_and_outcomes(body: &[u8]) -> Vec<(String, String)> {
    let page: serde_json::Value = serde_json::from_slice(body).expect("the audit page is JSON");
    page["items"]
        .as_array()
        .expect("the page carries items")
        .iter()
        .map(|row| {
            (
                row["action"].as_str().unwrap_or_default().to_string(),
                row["outcome"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[cfg(feature = "root-admin")]
async fn a_key_minted_over(router: &axum::Router, name: &str) -> String {
    let (status, body, _headers) = over(
        router,
        "POST",
        "/api/v1/admin/keys",
        format!(r#"{{"name":"{name}"}}"#).into_bytes(),
    )
    .await;
    assert_eq!(status, 201, "the mint reached the operation");
    let minted: serde_json::Value = serde_json::from_slice(&body).expect("the mint answers JSON");
    let id = minted["id"].as_str().expect("the minted key has an id");
    format!("key:{id}")
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_mutating_verb_still_seals_exactly_one_entry_onto_the_audit_chain() {
    let (_bare, mounted) = the_real_surface_bare_and_mounted();
    let resource = a_key_minted_over(&mounted, "p2-rootcleanup-one-entry").await;

    let (status, body) = audit_rows_for(&mounted, &resource).await;
    assert_eq!(status, 200);
    assert_eq!(
        actions_and_outcomes(&body),
        vec![("key.create".to_string(), "applied".to_string())],
        "one mutation, one row, on the ring the operator reads"
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_read_verb_still_seals_nothing_onto_the_audit_chain() {
    let (_bare, mounted) = the_real_surface_bare_and_mounted();
    let resource = a_key_minted_over(&mounted, "p2-rootcleanup-read-seals-nothing").await;
    let (_status, after_the_mutation) = audit_rows_for(&mounted, &resource).await;

    let (status, _body, _headers) = over(
        &mounted,
        "GET",
        &format!("/api/v1/admin/{}", resource.replacen("key:", "keys/", 1)),
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200, "the read reached the operation");
    let (_status, after_the_read) = audit_rows_for(&mounted, &resource).await;

    assert_eq!(
        after_the_read, after_the_mutation,
        "a read is not a mutation and the ring does not record it"
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_served_audit_body_is_byte_identical_with_and_without_the_root() {
    let (bare, mounted) = the_real_surface_bare_and_mounted();
    let resource = a_key_minted_over(&mounted, "p2-rootcleanup-byte-identity").await;
    let path = format!("/api/v1/admin/{}", resource.replacen("key:", "keys/", 1));

    let (status, _, _) = over(&mounted, "PATCH", &path, br#"{"enabled":false}"#.to_vec()).await;
    assert_eq!(status, 200, "the disable applied");
    let (status, _, _) = over(&mounted, "POST", &format!("{path}/revoke"), b"{}".to_vec()).await;
    assert!((200..300).contains(&status), "the revoke applied: {status}");
    let (status, _, _) = over(&mounted, "DELETE", &path, Vec::new()).await;
    assert!((200..300).contains(&status), "the delete applied: {status}");

    let (status, through_the_root) = audit_rows_for(&mounted, &resource).await;
    assert_eq!(status, 200);
    let (status, without_the_root) = audit_rows_for(&bare, &resource).await;
    assert_eq!(status, 200);

    assert_eq!(
        through_the_root, without_the_root,
        "the served audit body differs through the root"
    );
    assert_eq!(
        actions_and_outcomes(&through_the_root),
        vec![
            ("key.delete".to_string(), "applied".to_string()),
            ("key.revoke".to_string(), "applied".to_string()),
            ("key.patch".to_string(), "applied".to_string()),
            ("key.create".to_string(), "applied".to_string()),
        ],
        "one row per mutation, newest first, and no second copy"
    );
}

#[cfg(feature = "root-admin")]
struct AnApplyingStore;

#[cfg(feature = "root-admin")]
impl busbar_kernel_seams::verb_store::Store for AnApplyingStore {
    fn chain_break(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    ) -> Result<(), busbar_kernel_seams::verb_store::StoreError> {
        Ok(())
    }

    fn store_restore(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _backup_ref: &str,
    ) -> Result<(), busbar_kernel_seams::verb_store::StoreError> {
        Ok(())
    }
}

#[cfg(feature = "root-admin")]
async fn the_operators_rows_for(router: &axum::Router, resource: &str) -> Vec<(String, String)> {
    let (status, body) = audit_rows_for(router, resource).await;
    assert_eq!(status, 200, "the audit page answers");
    let page: serde_json::Value = serde_json::from_slice(&body).expect("the audit page is JSON");
    page["items"]
        .as_array()
        .expect("the page carries items")
        .iter()
        .filter(|row| row["principal"] == crate::root::auth_bindings::ADMIN_PRINCIPAL_ID)
        .map(|row| {
            (
                row["action"].as_str().unwrap_or_default().to_string(),
                row["outcome"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn every_root_only_mutating_verb_seals_one_durable_row_and_a_read_seals_none() {
    crate::dist_root_install::install();
    busbar_core_admin::install();
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        },
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = std::sync::Arc::new(built);
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let mounted = mounted_over(
        bare,
        1 << 20,
        a_door_that_identifies_the_operator(),
        |units| units.store = Some(Arc::new(AnApplyingStore)),
    );

    let applied = [
        ("/api/v1/admin/chain-break", "{}", "chain_break"),
        (
            "/api/v1/admin/store-restore",
            r#"{"backup_ref":"nightly"}"#,
            "store_restore",
        ),
    ];
    for (path, body, verb) in applied {
        let (status, _, _) = over(&mounted, "POST", path, body.as_bytes().to_vec()).await;
        assert_eq!(status, 204, "{verb} applied");
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            vec![(verb.to_string(), "applied".to_string())],
            "{verb}: one applied row on the durable ring"
        );
    }

    let rejected = [
        ("/api/v1/admin/adjust", "adjust"),
        (
            "/api/v1/admin/ledger/amend-rate-history",
            "amend_rate_history",
        ),
    ];
    for (path, verb) in rejected {
        let (status, _, _) = over(&mounted, "POST", path, b"{}".to_vec()).await;
        assert!(
            !(200..300).contains(&status),
            "{verb} did not apply: {status}"
        );
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            vec![(verb.to_string(), "rejected".to_string())],
            "{verb}: one rejected row on the durable ring"
        );
    }

    for path in ["/api/v1/admin/ledger/totals"] {
        let _ = over(&mounted, "GET", path, Vec::new()).await;
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            Vec::<(String, String)>::new(),
            "{path}: a read seals nothing"
        );
    }
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_booted_nodes_recovery_verbs_reach_its_configured_store_through_the_book() {
    crate::dist_root_install::install();
    busbar_core_admin::install();

    let configured_store = crate::root::real_store::store();
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(configured_store.clone(), None)
            .expect("governance over the actual configured Store"),
    );
    gov.attach_store_calls(configured_store);
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        },
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    built.governance = Some(gov);
    let booted = std::sync::Arc::new(built);
    let book = crate::root::boot::book(&booted, "test-store").expect("the boot book opens");
    assert!(
        book.verb_store.is_some(),
        "a node with a configured store carries it on its book"
    );

    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        },
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = std::sync::Arc::new(built);
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let mounted = mount(
        bare,
        crate::root::kernel::new_kernel(),
        1 << 20,
        move |dispatch| {
            let door: crate::root::units_admin::AdminDoorFn =
                Arc::new(|_: &crate::root::units_admin::AdminRequest| {
                    busbar_kernel::auth::AdminVerdict::from(
                        busbar_kernel::auth::AdminDoor::Identified(
                            busbar_contract::auth::Principal::from_id("row-113-recovery-operator"),
                            busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full),
                        ),
                    )
                });
            crate::root::kernel::ProductionUnits::admin_over_book(dispatch, door, &book)
                .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    ADirectoryThatMintedIt,
                )))
        },
    );

    for (path, body, verb, answered) in [
        ("/api/v1/admin/chain-break", "{}", "chain_break", 204),
        (
            "/api/v1/admin/store-restore",
            r#"{"backup_ref":"nightly"}"#,
            "store_restore",
            503,
        ),
    ] {
        let (status, _, _) = over(&mounted, "POST", path, body.as_bytes().to_vec()).await;
        assert_eq!(
            status, answered,
            "{verb} reached the configured store: applied, or refused where the store has no such \
             operation"
        );
    }
}

#[cfg(feature = "root-admin")]
const THE_REMOVED_VERBS: [(&str, &str); 9] = [
    ("POST", "/api/v1/admin/operator-key"),
    ("POST", "/api/v1/admin/escrow"),
    ("POST", "/api/v1/admin/dual-control"),
    ("POST", "/api/v1/admin/export-keyset"),
    ("POST", "/api/v1/admin/approve"),
    ("POST", "/api/v1/admin/overdraft-ceiling"),
    ("POST", "/api/v1/admin/dispute-max-age"),
    ("POST", "/api/v1/admin/disputes/resolve"),
    ("POST", "/api/v1/admin/slices/resolve"),
];

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn an_unbound_verb_is_not_served_it_answers_the_unmounted_404_and_seals_nothing() {
    crate::dist_root_install::install();
    busbar_core_admin::install();
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        },
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = std::sync::Arc::new(built);
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let mounted = mounted_over(bare, 1 << 20, a_door_that_identifies_the_operator(), |_| {});
    let (unmounted_status, unmounted, _) = over(
        &mounted,
        "POST",
        "/api/v1/admin/no-such-operation",
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(unmounted_status, 404, "the control is the unmounted path");
    assert_eq!(
        unmounted,
        br#"{"error":{"code":"not_found","message":"resource not found"}}"#.to_vec(),
        "the control is the router's generic miss"
    );
    for (method, path) in THE_REMOVED_VERBS {
        let body = if method == "GET" {
            Vec::new()
        } else {
            b"{}".to_vec()
        };
        let (status, answer, _) = over(&mounted, method, path, body).await;
        assert_eq!(
            (status, answer.as_slice()),
            (unmounted_status, unmounted.as_slice()),
            "{method} {path}: a removed verb answers exactly what an unmounted path answers"
        );
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            Vec::<(String, String)>::new(),
            "{method} {path}: an unserved verb seals no audit row"
        );
    }

    let unbound: Vec<(&str, &str)> = busbar_core_admin::NEW_VERBS
        .iter()
        .filter(|verb| !busbar_core_admin::verb::effect_bound(**verb))
        .filter_map(|verb| {
            let name = busbar_core_admin::verb_name(*verb)?;
            busbar_core_admin::admin_codec::verbs::table()
                .into_iter()
                .find(|row| row.verb == name)
                .map(|row| (row.method, row.template))
        })
        .collect();
    assert!(
        unbound.is_empty(),
        "the one generic check leaves no 1.6.0 verb unbound: {unbound:?}"
    );
    let table = busbar_core_admin::admin_codec::verbs::table();
    for (method, path) in THE_REMOVED_VERBS {
        assert!(
            !table
                .iter()
                .any(|row| row.method == method && row.template == path),
            "{method} {path}: a verb the owner removed from 1.6.0 still has a row in the table"
        );
    }
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn an_admin_verb_still_meters_to_nothing_and_posts_nothing() {
    let node = a_node();

    let (status, body, _headers) =
        over_the_listener(&node, "GET", "/api/v1/admin/audit", b"").await;
    assert_eq!(status, 200, "the unit completed, so it passed Meter");
    assert_eq!(
        body, THE_SURFACES_OWN_BYTES,
        "and the body is the operation's, not a refusal the meter step raised"
    );

    let (status, _body, _headers) = over_the_listener(
        &node,
        "POST",
        "/api/v1/admin/keys",
        br#"{"name":"a-key-this-cell-asked-for"}"#,
    )
    .await;
    assert_eq!(status, 200, "and so did the mutation");
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_path_the_table_does_not_declare_reaches_the_surface_without_the_loop() {
    let node = a_node();

    let (status, body, _headers) = over_the_listener(&node, "GET", "/healthz", b"").await;
    assert_eq!(status, 200);
    assert_eq!(body, THE_SURFACES_OWN_BYTES);
    assert_eq!(
        node.surface.seen().len(),
        1,
        "the surface answered it, once"
    );
}

#[cfg(feature = "root-admin")]
const A_SERVED_PLANE: busbar_contract::plane::PlaneDeclaration =
    busbar_contract::plane::PlaneDeclaration {
        key: "example",
        fallback: false,
        config_section: "examples",
        scope_kinds: &["example"],
        subject_noun: "example",
        admin_noun: "example",
        audit_kind: "example",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &["examples"],
        billable_classes: &[busbar_contract::plane::BillableClass {
            class: "calls",
            family: "count",
        }],
        fee_units: &[busbar_contract::plane::PER_REQUEST],
        metric_families: &[],
        record_kinds: &["note"],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    };

#[cfg(feature = "root-admin")]
struct IdentifiesATenant;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesATenant {
    fn name(&self) -> &'static str {
        "identifies-a-tenant"
    }

    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some(THE_OPERATORS_CREDENTIAL) => {
                busbar_kernel_identity::module::AuthOutcome::Identify(
                    busbar_kernel_identity::principal::Principal::from_id("a-tenant"),
                )
            }
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

#[cfg(feature = "root-admin")]
fn a_q71_node(
    door: busbar_kernel_identity::AuthChain,
) -> (
    axum::Router,
    Arc<std::sync::Mutex<Vec<busbar_contract::records::PlaneRecord>>>,
) {
    a_q71_node_trusting(door, crate::root::units_admin::no_trust())
}

#[cfg(feature = "root-admin")]
fn a_q71_node_trusting(
    door: busbar_kernel_identity::AuthChain,
    trust: crate::root::units_admin::TrustDesk,
) -> (
    axum::Router,
    Arc<std::sync::Mutex<Vec<busbar_contract::records::PlaneRecord>>>,
) {
    crate::dist_root_install::install();
    busbar_core_admin::install();
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        },
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = std::sync::Arc::new(built);
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let kept = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&kept);
    let mounted = mounted_over(bare, 1 << 20, door, move |units| {
        units.admin.planes =
            Arc::new(|key: &str| (key == A_SERVED_PLANE.key).then_some(A_SERVED_PLANE));
        units.admin.records = Some(Arc::new(
            move |record: &busbar_contract::records::PlaneRecord| {
                sink.lock().expect("the sink").push(record.clone());
                Ok(())
            },
        ));
        units.admin.trust = trust;
    });
    (mounted, kept)
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_trust_verbs_decide_over_the_kernels_trust_book() {
    let _one = crate::root::PUBLISHING.lock().await;
    use busbar_contract::services::{Caller, HostServices, Later};
    use busbar_kernel::host_services::{InstanceFacts, KernelServices};
    use busbar_kernel::trust::book::{Distrust, TrustFacts};
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;

    let kernel = Arc::new(KernelServices::new());
    kernel
        .admit(
            "inst",
            InstanceFacts {
                trust: vec![(
                    "peer".to_string(),
                    TrustEntry {
                        pin: None,
                        policy: Policy {
                            ttl_ms: 0,
                            recovery_backoff_ms: 0,
                        },
                        approved: Default::default(),
                    },
                )],
                ..InstanceFacts::default()
            },
        )
        .expect("admitted");
    let desk = Arc::clone(&kernel);
    let (node, _) = a_q71_node_trusting(
        a_door_that_identifies_the_operator(),
        Arc::new(move || Some(Arc::clone(&desk))),
    );
    let op = Some(THE_OPERATORS_CREDENTIAL);

    let approvals_before = the_operators_rows_for(&node, "/api/v1/admin/trust/approve")
        .await
        .len();
    let reads_before = the_operators_rows_for(&node, "/api/v1/admin/trust").await;
    let caller = Caller {
        instance: Arc::from("inst"),
        plugin: Arc::from("the-plane"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    };
    let sight = |hash: &str| {
        let later: Later = Box::new(|_| {});
        let _ = kernel.trust_sight(&caller, "peer", hash, later);
    };
    let served = || {
        kernel.trust_judge(
            "inst",
            &TrustFacts {
                counterparty: "peer",
                item: None,
                digest: None,
            },
        )
    };
    let approve = |key: &'static str| {
        let node = node.clone();
        async move {
            over_as(
                &node,
                "POST",
                "/api/v1/admin/trust/approve",
                &format!(r#"{{"key":"{key}"}}"#),
                op,
            )
            .await
        }
    };
    let row = |state: &str, approved: &str, seen: &str| {
        format!(
            r#"{{"approved":{approved},"counterparty":"peer","instance":"inst","item":null,"key":"inst/peer","seen":{seen},"state":"{state}"}}"#
        )
    };

    assert_eq!(
        over_as(&node, "GET", "/api/v1/admin/trust", "", op).await,
        (
            200,
            format!(r#"{{"keys":[{}]}}"#, row("new", "null", "null"))
        )
    );
    assert_eq!(
        approve("inst/peer").await,
        (
            409,
            r#"{"error":{"code":"conflict","message":"trust key `inst/peer` was never sighted"}}"#
                .to_string()
        )
    );

    sight("h1");
    assert_eq!(served(), Err(Distrust::NotApproved));

    let first = approve("inst/peer").await;
    assert_eq!(first, (200, row("approved", r#""h1""#, r#""h1""#)));
    assert_eq!(approve("inst/peer").await, first, "idempotent");
    assert_eq!(served(), Ok(()));

    sight("h2");
    assert_eq!(served(), Err(Distrust::Quarantined));
    assert_eq!(
        over_as(&node, "GET", "/api/v1/admin/trust", "", op).await,
        (
            200,
            format!(r#"{{"keys":[{}]}}"#, row("drifted", r#""h1""#, r#""h2""#))
        )
    );
    assert_eq!(
        approve("inst/peer").await,
        (200, row("approved", r#""h2""#, r#""h2""#))
    );
    assert_eq!(served(), Ok(()));

    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/trust/revoke",
            r#"{"key":"inst/peer"}"#,
            op
        )
        .await,
        (200, row("new", r#""h2""#, r#""h2""#))
    );
    assert_eq!(served(), Err(Distrust::NotApproved));

    assert_eq!(
        approve("inst/stranger").await,
        (
            404,
            r#"{"error":{"code":"not_found","message":"trust key `inst/stranger` not found"}}"#
                .to_string()
        )
    );
    assert_eq!(
        over_as(&node, "POST", "/api/v1/admin/trust/revoke", "{}", op).await,
        (
            400,
            r#"{"error":{"code":"invalid_request","message":"key is required"}}"#.to_string()
        )
    );

    let approvals = the_operators_rows_for(&node, "/api/v1/admin/trust/approve").await;
    assert_eq!(
        approvals.len() - approvals_before,
        5,
        "every approval call sealed one row: {approvals:?}"
    );

    assert!(approvals[..5]
        .iter()
        .all(|(verb, _)| verb == "trust_approve"));
    assert_eq!(
        the_operators_rows_for(&node, "/api/v1/admin/trust").await,
        reads_before,
        "the read seals nothing"
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_rejected_approval_is_audited() {
    let _one = crate::root::PUBLISHING.lock().await;
    use busbar_contract::services::{Caller, HostServices, Later};
    use busbar_kernel::host_services::{InstanceFacts, KernelServices};
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;

    let kernel = Arc::new(KernelServices::new());
    kernel
        .admit(
            "inst",
            InstanceFacts {
                trust: vec![(
                    "peer".to_string(),
                    TrustEntry {
                        pin: None,
                        policy: Policy {
                            ttl_ms: 0,
                            recovery_backoff_ms: 0,
                        },
                        approved: Default::default(),
                    },
                )],
                ..InstanceFacts::default()
            },
        )
        .expect("admitted");
    let desk = Arc::clone(&kernel);
    let (node, _) = a_q71_node_trusting(
        a_door_that_identifies_the_operator(),
        Arc::new(move || Some(Arc::clone(&desk))),
    );
    let op = Some(THE_OPERATORS_CREDENTIAL);
    let before = the_operators_rows_for(&node, "/api/v1/admin/trust/approve")
        .await
        .len();
    let approve = |body: &'static str| {
        let node = node.clone();
        async move { over_as(&node, "POST", "/api/v1/admin/trust/approve", body, op).await }
    };
    let caller = Caller {
        instance: Arc::from("inst"),
        plugin: Arc::from("the-plane"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    };
    let later: Later = Box::new(|_| {});
    let _ = kernel.trust_sight(&caller, "peer", "unverified", later);

    assert_eq!(approve("not json").await.0, 400, "malformed");
    assert_eq!(
        approve(r#"{"key":"inst/stranger"}"#).await.0,
        404,
        "unknown"
    );

    assert_eq!(
        approve(r#"{"key":"inst/peer"}"#).await,
        (
            409,
            r#"{"error":{"code":"conflict","message":"trust key `inst/peer` was last sighted unverified: its document failed verification, so there is nothing to approve"}}"#
                .to_string()
        ),
        "an unverified sighting is never approved"
    );
    assert!(
        kernel.trust_rows().iter().all(|r| r.approved.is_none()),
        "nothing was pinned"
    );

    let rows = the_operators_rows_for(&node, "/api/v1/admin/trust/approve").await;
    assert_eq!(rows.len() - before, 3, "one row per refusal: {rows:?}");

    assert!(
        rows[..3]
            .iter()
            .all(|(verb, outcome)| verb == "trust_approve" && outcome == "rejected"),
        "every refused approval is audited as rejected: {rows:?}"
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_new_verb_past_the_nodes_mutation_budget_is_refused() {
    let (node, _) = a_q71_node(a_door_that_identifies_the_operator());
    let op = Some(THE_OPERATORS_CREDENTIAL);
    let revoke = || {
        over_as(
            &node,
            "POST",
            "/api/v1/admin/trust/revoke",
            r#"{"key":"inst/stranger"}"#,
            op,
        )
    };
    let budget = busbar_core_admin::rate::MutationClass::Crud.limit();
    for i in 0..budget {
        let (status, body) = revoke().await;
        assert_ne!(status, 429, "call {i} is inside the budget: {body}");
    }
    let mut refused = None;
    for _ in 0..=budget {
        let answer = revoke().await;
        if answer.0 == 429 {
            refused = Some(answer);
            break;
        }
    }
    assert_eq!(
        refused,
        Some((
            429,
            r#"{"error":{"code":"rate_limited","message":"admin mutation rate limit exceeded; retry next minute"}}"#
                .to_string()
        )),
        "a call past the node's budget was admitted: the limiter forgot the window"
    );
}

#[cfg(feature = "root-admin")]
async fn over_as(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: &str,
    credential: Option<&str>,
) -> (u16, String) {
    let (status, bytes, _) = send(router, method, path, body.into(), credential, None).await;
    (
        status,
        String::from_utf8(bytes).expect("the answer is text"),
    )
}

#[cfg(feature = "root-admin")]
fn the_q71_verbs() -> [(&'static str, &'static str, String); 4] {
    [
        ("GET", "/api/v1/admin/verify", String::new()),
        (
            "GET",
            "/api/v1/admin/plane-facts?plane=example",
            String::new(),
        ),
        (
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"example","kind":"note","id":"n-1","body":{"text":"hello"}}"#.to_string(),
        ),
        (
            "POST",
            "/api/v1/admin/commit-upgrade",
            format!(r#"{{"version":"{}"}}"#, super::bound::RUNNING_RELEASE),
        ),
    ]
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_four_q71_verbs_are_served_and_refuse_by_name() {
    let (node, kept) = a_q71_node(a_door_that_identifies_the_operator());
    let op = Some(THE_OPERATORS_CREDENTIAL);

    let (status, body) = over_as(&node, "GET", "/api/v1/admin/verify", "", op).await;
    assert_eq!(status, 200, "verify is served: {body}");
    assert_eq!(
        body,
        r#"{"book_verified":false,"checkpoints":0,"discrepancies":0,"findings":[],"identity_holds":true,"ok":true,"since":null}"#
    );

    let (status, body) = over_as(
        &node,
        "GET",
        "/api/v1/admin/plane-facts?plane=example",
        "",
        op,
    )
    .await;
    assert_eq!(status, 200, "plane_facts is served: {body}");
    let facts: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(facts["plane"], "example");
    assert_eq!(facts["config_section"], "examples");
    assert_eq!(
        facts["billable_classes"],
        serde_json::json!([{"class": "calls", "family": "count"}])
    );
    assert_eq!(facts["fee_units"], serde_json::json!(["per_request"]));
    assert_eq!(facts["record_kinds"], serde_json::json!(["note"]));
    assert_eq!(
        over_as(&node, "GET", "/api/v1/admin/plane-facts?plane=nope", "", op).await,
        (
            404,
            r#"{"error":{"code":"not_found","message":"plane `nope` not found"}}"#.to_string()
        )
    );
    assert_eq!(
        over_as(&node, "GET", "/api/v1/admin/plane-facts", "", op).await,
        (
            400,
            r#"{"error":{"code":"invalid_request","message":"plane is required"}}"#.to_string()
        )
    );

    let (_, _, write) = the_q71_verbs()[2].clone();
    let (status, body) = over_as(
        &node,
        "POST",
        "/api/v1/admin/plane-record-write",
        &write,
        op,
    )
    .await;
    assert_eq!(status, 200, "plane_record_write is served: {body}");
    let at = serde_json::from_str::<serde_json::Value>(&body).expect("JSON")["written_at"]
        .as_u64()
        .expect("written_at");
    assert_eq!(
        body,
        format!(
            r#"{{"id":"n-1","kind":"note","parent":null,"plane":"example","terminal":false,"written_at":{at}}}"#
        )
    );
    {
        let kept = kept.lock().expect("the sink");
        assert_eq!(kept.len(), 1, "exactly one record written");

        assert_eq!(
            (kept[0].kind.as_str(), kept[0].id.as_str(), kept[0].ts),
            ("\u{1}plane\u{1}example\u{1}note", "n-1", at)
        );
        assert_eq!(kept[0].body, br#"{"text":"hello"}"#.to_vec());
        assert_eq!(
            kept[0].disposition,
            busbar_contract::records::PlaneDisposition::Active
        );
    }
    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"example","id":"n-1","body":{}}"#,
            op
        )
        .await,
        (
            400,
            r#"{"error":{"code":"invalid_request","message":"kind is required"}}"#.to_string()
        )
    );
    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"nope","kind":"note","id":"n-1","body":{}}"#,
            op
        )
        .await,
        (
            404,
            r#"{"error":{"code":"not_found","message":"plane `nope` not found"}}"#.to_string()
        )
    );

    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"example","kind":"task","id":"t-1","body":{}}"#,
            op
        )
        .await,
        (
            403,
            r#"{"error":{"code":"forbidden","message":"plane `example` may not write record kind `task`"}}"#
                .to_string()
        )
    );
    assert_eq!(
        kept.lock().expect("the sink").len(),
        1,
        "a refusal writes nothing"
    );

    let (_, _, commit) = the_q71_verbs()[3].clone();
    let (status, body) = over_as(&node, "POST", "/api/v1/admin/commit-upgrade", &commit, op).await;
    assert_eq!(status, 200, "commit_upgrade is served: {body}");
    let committed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(committed["committed"], super::bound::RUNNING_RELEASE);
    assert_eq!(committed["hash"].as_str().map(str::len), Some(64));
    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/commit-upgrade",
            r#"{"version":"0.0.1"}"#,
            op
        )
        .await,
        (
            409,
            format!(
                r#"{{"error":{{"code":"conflict","message":"this node runs `{}`; it cannot commit `0.0.1`"}}}}"#,
                super::bound::RUNNING_RELEASE
            )
        )
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_four_q71_verbs_refuse_an_unauthorized_caller_by_text() {
    const DOOR: &str = r#"{"error":{"code":"unauthorized","message":"missing or invalid admin credential (Bearer or x-admin-token)"}}"#;
    let scope = |needed: &str| {
        format!(
            r#"{{"error":{{"code":"forbidden","message":"insufficient scope: this endpoint requires `{needed}`"}}}}"#
        )
    };

    let (node, kept) = a_q71_node(a_door_that_identifies_the_operator());
    for (method, path, body) in the_q71_verbs() {
        assert_eq!(
            over_as(&node, method, path, &body, None).await,
            (401, DOOR.to_string()),
            "{method} {path}: no credential is the door"
        );
    }

    let tenant = busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-a-tenant".to_string(),
            module: Box::new(IdentifiesATenant),
        }],
        false,
    );
    let (tenants_node, tenants_kept) = a_q71_node(tenant);
    for (method, path, body) in the_q71_verbs() {
        let needed = if method == "GET" { "read-only" } else { "full" };
        assert_eq!(
            over_as(
                &tenants_node,
                method,
                path,
                &body,
                Some(THE_OPERATORS_CREDENTIAL)
            )
            .await,
            (403, scope(needed)),
            "{method} {path}: an identified caller with no grant is told the scope"
        );
    }

    let (plain, _) = a_q71_node(a_door_that_identifies_the_operator());
    let (_, _, commit) = the_q71_verbs()[3].clone();
    assert_ne!(
        over_as(
            &plain,
            "POST",
            "/api/v1/admin/commit-upgrade",
            &commit,
            Some(THE_OPERATORS_CREDENTIAL)
        )
        .await,
        (403, scope("full")),
        "commit_upgrade under a full grant was refused with no operator key configured"
    );

    for sink in [kept, tenants_kept] {
        assert!(
            sink.lock().expect("the sink").is_empty(),
            "no refusal wrote a record"
        );
    }
}

#[cfg(feature = "root-admin")]
async fn over_with_key(router: &axum::Router, path: &str, body: &str, key: &str) -> (u16, String) {
    let (status, bytes, _) = send(
        router,
        "POST",
        path,
        body.into(),
        Some(THE_OPERATORS_CREDENTIAL),
        Some(key),
    )
    .await;
    (
        status,
        String::from_utf8(bytes).expect("the answer is text"),
    )
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_q71_writes_replay_under_an_idempotency_key() {
    const MISMATCH: &str = r#"{"error":{"code":"conflict","message":"this Idempotency-Key was already used with a different request body"}}"#;
    let (node, kept) = a_q71_node(a_door_that_identifies_the_operator());

    let (_, _, write) = the_q71_verbs()[2].clone();
    let path = "/api/v1/admin/plane-record-write";
    let first = over_with_key(&node, path, &write, "k-write").await;
    assert_eq!(first.0, 200, "the first call writes: {}", first.1);
    assert_eq!(
        over_with_key(&node, path, &write, "k-write").await,
        first,
        "the retry answers the first answer, byte for byte"
    );
    assert_eq!(
        kept.lock().expect("the sink").len(),
        1,
        "and writes nothing again"
    );
    let other = r#"{"plane":"example","kind":"note","id":"n-2","body":{}}"#;
    assert_eq!(
        over_with_key(&node, path, other, "k-write").await,
        (409, MISMATCH.to_string()),
        "the same key with a different body is refused by name"
    );
    assert_eq!(
        kept.lock().expect("the sink").len(),
        1,
        "and writes nothing"
    );
    assert_eq!(over_with_key(&node, path, other, "k-other").await.0, 200);
    assert_eq!(
        kept.lock().expect("the sink").len(),
        2,
        "a different key runs"
    );

    let (_, _, commit) = the_q71_verbs()[3].clone();
    let path = "/api/v1/admin/commit-upgrade";
    let first = over_with_key(&node, path, &commit, "k-commit").await;
    assert_eq!(first.0, 200, "the first commit seals: {}", first.1);
    assert_eq!(
        over_with_key(&node, path, &commit, "k-commit").await,
        first,
        "the retry answers the first commit's seq and hash, sealing nothing again"
    );
    assert_eq!(
        over_with_key(&node, path, r#"{"version":"0.0.1"}"#, "k-commit").await,
        (409, MISMATCH.to_string())
    );
}
