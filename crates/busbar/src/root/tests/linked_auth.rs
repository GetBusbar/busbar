// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Arc;

use busbar_contract::auth::{AuthModule, AuthVerdict, Principal};
use busbar_kernel::auth::{AdminAuthChain, Operator};
use busbar_kernel::config::{self, AuthCfg, AuthChainEntry, RoleBindingCfg, SecretRef};
use busbar_kernel::governance::GovState;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;

const TOKEN: &str = "admintok";

fn link() {
    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    busbar_kernel_testkit::test_support::install_root_auth_axis(crate::root::dispatch::auth_axis);
    for decls in crate::LINKED.protocols {
        busbar_kernel_testkit::test_support::protocols::register_test_protocols(decls);
    }

    busbar_kernel_testkit::test_support::register_neutral_test_plane();
}

fn op() -> &'static str {
    link();
    config::operator_provider()
}

fn app(chain: &[&str], extra: Vec<(&str, Box<dyn AuthModule>)>) -> Arc<busbar_kernel::state::App> {
    link();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some(TOKEN.to_string())).expect("governance"));
    let mut app = busbar_kernel_testkit::test_support::TestApp::new()
        .governance(gov)
        .admin_chain(chain.iter().map(|s| s.to_string()).collect());
    for (name, module) in extra {
        app = app.admin_module(name, module);
    }
    app.build()
}

async fn probe(
    app: Arc<busbar_kernel::state::App>,
    bearer: Option<&str>,
    header: Option<&str>,
) -> (u16, String) {
    let router = busbar_core_admin::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = reqwest::Client::new().get(format!("http://{addr}/api/v1/admin/info"));
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    if let Some(h) = header {
        req = req.header("x-admin-token", h);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let head = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let (content_type, content_length) = (head("content-type"), head("content-length"));
    let body = resp.text().await.unwrap();
    server.abort();
    match status {
        200 => (status, body),
        _ => (status, refusal(&content_type, &content_length, &body)),
    }
}

fn refusal(content_type: &str, content_length: &str, body: &str) -> String {
    let body: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    format!("{content_type} {content_length} {body}")
}

fn golden_cell(cell: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("BUSBAR_CORE_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
        .join(cell);
    let text = std::fs::read_to_string(&path).expect("the 1.5.5 golden cell");
    serde_json::from_str(&text).expect("golden json")
}

fn unauthorized() -> String {
    let cell = golden_cell("admin.ops__GetInfo__unauth.json");
    assert_eq!(cell["status"], 401);
    refusal(
        cell["headers"]["content-type"].as_str().unwrap(),
        cell["headers"]["content-length"].as_str().unwrap(),
        &cell["body"]["json"].to_string(),
    )
}

struct AnyCredential;

impl AuthModule for AnyCredential {
    fn name(&self) -> &'static str {
        "any-credential"
    }
    fn authenticate(&self, candidate: Option<&str>) -> AuthVerdict {
        match candidate {
            Some(_) => AuthVerdict::Identify(Principal::from_id("idp:someone")),
            None => AuthVerdict::Pass,
        }
    }
}

#[test]
fn the_operator_credentials_row_is_linked_under_its_config_key() {
    link();
    assert!(
        busbar_kernel::preflight::linked_auth_names().contains(&config::operator_provider()),
        "the root links the operator credential's row: {:?}",
        busbar_kernel::preflight::linked_auth_names()
    );
}

#[test]
fn the_linked_default_inbound_style_is_the_1_5_5_client_token_lines_in_order() {
    link();
    let linked = busbar_kernel::preflight::linked().expect("the linked registry");
    let axis = crate::root::dispatch::auth_axis(linked);
    assert_eq!(
        axis.default_inbound_style(),
        Ok(vec![
            "authorization".to_string(),
            "x-api-key".to_string(),
            "x-goog-api-key".to_string()
        ])
    );
    assert_eq!(
        axis.carriers(config::operator_provider()),
        vec!["authorization".to_string(), "x-admin-token".to_string()]
    );
}

#[cfg(linked_every_auth)]
#[test]
fn the_info_auth_modules_are_the_inbound_rows_only() {
    link();
    let linked = busbar_kernel::preflight::linked_auth_names();
    assert!(
        linked.len() > 1,
        "the default build links an outbound-only auth row beside the operator credential's: {linked:?}"
    );
    assert_eq!(
        busbar_core_admin::v1::service::auth_modules_compiled_in(),
        vec![
            "keys",
            config::operator_provider(),
            "busbar-auth-webhook-signature"
        ],
        "only inbound auth-chain modules are listed, 1.5.5's two first and the default build's \
         webhook-signature row after them (ARCHITECT 2026-10-14; linked rows: {linked:?})"
    );
}

#[tokio::test]
async fn the_admin_door_answers_both_carriers_through_the_linked_row() {
    busbar_kernel_testkit::test_support::metrics::init();
    let op = op();
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    let cases: [(Option<&str>, Option<&str>, u16); 9] = [
        (None, None, 401),
        (Some(TOKEN), None, 200),
        (None, Some(TOKEN), 200),
        (Some("wrong"), None, 401),
        (None, Some("wrong"), 401),
        (Some("wrong"), Some(TOKEN), 200),
        (Some(TOKEN), Some("wrong"), 200),
        (Some(jws), Some(TOKEN), 200),
        (Some(jws), None, 401),
    ];
    for (bearer, header, want) in cases {
        let (status, body) = probe(app(&[op], Vec::new()), bearer, header).await;
        assert_eq!(status, want, "bearer={bearer:?} header={header:?}: {body}");
        if want == 401 {
            assert_eq!(body, unauthorized(), "bearer={bearer:?} header={header:?}");
        }
    }
}

#[tokio::test]
async fn the_chain_ends_at_the_operator_credential_on_any_wrong_token() {
    busbar_kernel_testkit::test_support::metrics::init();
    let op = op();
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    let chain = [op, "any-credential"];
    let with_idp = || app(&chain, vec![("any-credential", Box::new(AnyCredential))]);

    let (status, body) = probe(with_idp(), Some(jws), None).await;
    assert_eq!(
        (status, body),
        (401, unauthorized()),
        "a wrong JWS-shaped token is refused terminally at the first arm, as in 1.5.5"
    );
    let (status, body) = probe(with_idp(), Some(TOKEN), None).await;
    assert_eq!(
        status, 200,
        "the operator token still identifies at the first arm: {body}"
    );
    let (status, body) = probe(with_idp(), Some("wrong-opaque-token"), None).await;
    assert_eq!(
        (status, body),
        (401, unauthorized()),
        "a wrong opaque token is refused terminally — the arm behind never identifies it"
    );
}

#[tokio::test]
async fn without_the_root_row_the_operator_token_is_refused() {
    busbar_kernel_testkit::test_support::metrics::init();
    let op = op();
    let with_row = app(&[op], Vec::new());

    let mut without_row = (*with_row).clone();
    without_row.admin_modules = Arc::new(AdminAuthChain {
        modules: HashMap::new(),
        operator: Operator::new(config::operator_provider()),
    });
    let without_row = Arc::new(without_row);

    assert_eq!(
        probe(with_row, Some(TOKEN), None).await.0,
        200,
        "the row admits"
    );
    for (bearer, header) in [(Some(TOKEN), None), (None, Some(TOKEN))] {
        let (status, body) = probe(without_row.clone(), bearer, header).await;
        assert_eq!(
            (status, body),
            (401, unauthorized()),
            "no row answers the operator credential: bearer={bearer:?} header={header:?}"
        );
    }
}

fn golden_refusal(cell: &str) -> String {
    let cell = golden_cell(cell);
    let stderr = cell["effects"]["stderr"]
        .as_str()
        .expect("stderr")
        .to_string();
    let line = stderr
        .lines()
        .find_map(|l| l.strip_prefix("[error] "))
        .expect("an [error] line");
    line.to_string()
}

#[test]
fn an_unregistered_auth_module_is_refused_with_the_1_5_5_bytes() {
    link();
    let mut providers = config::IdentityProviders::new();
    let def: config::IdentityProviderCfg =
        serde_yaml::from_str("module: oidc").expect("a provider definition");
    providers.insert("oracle-oidc".to_string(), def);
    let err = busbar_kernel::preflight::plugins_preflight(
        None,
        None,
        &providers,
        &HashMap::new(),
        &config::PluginsCfg::default(),
        &config::ExportCfg::default(),
    )
    .expect_err("an unregistered auth module is refused");
    assert_eq!(err, golden_refusal("boot.refusal__BOOT-133__boot.json"));
}

#[test]
fn a_role_shadowing_the_operator_principal_is_refused() {
    link();
    let mut cfg = busbar_kernel_testkit::test_support::cfg_with_provider_api_key(SecretRef::none());
    let mut auth = AuthCfg::default_none();
    auth.chain = vec![AuthChainEntry::bare(config::KEYS_MODULE)];
    let mut roles = HashMap::new();
    roles.insert(
        config::operator_principal_id().to_string(),
        RoleBindingCfg::default(),
    );
    auth.role_bindings
        .insert(config::KEYS_MODULE.to_string(), roles.into_iter().collect());
    cfg.auth = Some(auth);
    let errs = busbar_kernel::config_validate::validate(&cfg).expect_err("a reserved role");
    assert!(
        errs.iter().any(|e| e.contains("role_bindings.keys")
            && e.contains(&format!("'{}'", config::operator_principal_id()))
            && e.contains("reserved")),
        "expected the reserved-role-name error; got: {errs:?}"
    );
}

#[test]
fn the_operator_token_ref_is_checked_by_shape_only() {
    link();
    let build = |token: SecretRef| -> Result<(), Vec<String>> {
        let mut cfg =
            busbar_kernel_testkit::test_support::cfg_with_provider_api_key(SecretRef::none());
        let mut auth = AuthCfg::default_none();
        let mut entry = AuthChainEntry::bare(config::operator_provider());
        entry.token = Some(token);
        auth.admin_auth = vec![entry];
        cfg.auth = Some(auth);
        busbar_kernel::config_validate::validate(&cfg)
    };
    assert!(
        build(SecretRef {
            module: "planted-plugin-secret-module".to_string(),
            settings: serde_json::Map::new(),
        })
        .is_ok(),
        "a plugin-backed secret module is checked at plugin pre-flight, not here"
    );
    let mut keyless = SecretRef::env("BUSBAR_ADMIN_TOKEN");
    keyless.settings.clear();
    let errs = build(keyless).expect_err("an env ref without settings.key");
    let path = format!("auth.admin_auth.{}.token", config::operator_provider());
    assert!(
        errs.iter()
            .any(|e| e.contains(&path) && e.contains("requires settings.key")),
        "expected the env-shape error; got: {errs:?}"
    );
    assert!(
        build(SecretRef::env("BUSBAR_ADMIN_TOKEN")).is_ok(),
        "a well-formed env admin-token ref must validate"
    );
}

fn cfg_with_credentials(
    token_path: &std::path::Path,
    key_path: &std::path::Path,
) -> busbar_kernel::config::RootCfg {
    let mut cfg = busbar_kernel_testkit::test_support::cfg_with_provider_api_key(
        busbar_kernel::config::SecretRef::none(),
    );
    let mut admin_entry =
        busbar_kernel::config::AuthChainEntry::bare(busbar_kernel::config::operator_provider());
    admin_entry.token = Some(busbar_kernel::config::SecretRef::file(
        token_path.to_string_lossy().to_string(),
    ));
    cfg.auth = Some(busbar_kernel::config::AuthCfg {
        signing_key: Some(busbar_kernel::config::SecretRef::file(
            key_path.to_string_lossy().to_string(),
        )),
        chain: vec![],
        admin_auth: vec![admin_entry],
        role_bindings: busbar_kernel::config::RoleBindings::new(),
        methods: Default::default(),
        key_ttl: None,
        policy: Default::default(),
    });
    cfg
}

#[test]
fn admin_token_secret_ref_re_resolves_on_apply() {
    link();
    busbar_kernel_testkit::test_support::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-high7-token-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("admin.token");
    let key_path = dir.join("signing.key");
    std::fs::write(&token_path, "tok-v1").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    let prior =
        busbar_kernel_testkit::app::build_once(cfg_with_credentials(&token_path, &key_path), None)
            .expect("boot");
    let gov = prior.governance.clone().expect("governance");
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"tok-v1").as_str()),
        "boot accepts the resolved token"
    );

    std::fs::write(&token_path, "tok-v2").unwrap();
    let next = busbar_kernel_testkit::app::build_once(
        cfg_with_credentials(&token_path, &key_path),
        Some(&prior),
    )
    .expect("apply");

    assert!(
        std::sync::Arc::ptr_eq(next.governance.as_ref().unwrap(), &gov),
        "the apply REUSES the same GovState (keys/ledgers survive) — the credential is swapped in place"
    );
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"tok-v2").as_str()),
        "the rotated admin token is the one now accepted"
    );
    assert_ne!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"tok-v1").as_str()),
        "the pre-rotation admin token is no longer accepted"
    );

    use busbar_contract::authz::Scope;
    assert!(
        busbar_kernel::auth::dry_run_admin_scope(&next, &bearer("tok-v2")).allows(Scope::Full),
        "the applied admin chain admits the rotated token"
    );
    assert!(
        !busbar_kernel::auth::dry_run_admin_scope(&next, &bearer("tok-v1")).allows(Scope::Full),
        "the applied admin chain refuses the pre-rotation token"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn signing_key_secret_ref_re_resolves_on_apply_and_fails_closed() {
    link();
    busbar_kernel_testkit::test_support::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-high7-signing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("admin.token");
    let key_path = dir.join("signing.key");
    std::fs::write(&token_path, "tok").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    let prior =
        busbar_kernel_testkit::app::build_once(cfg_with_credentials(&token_path, &key_path), None)
            .expect("boot");
    let gov = prior.governance.clone().expect("governance");
    let spec = busbar_kernel::governance::NewKeySpec {
        name: "k".into(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let now = busbar_kernel::store::now();
    let (_binding, old_token) = gov.mint_signed(spec, now + 10_000, now).expect("mint");
    assert!(
        gov.verify_token(old_token.expose(&busbar_kernel::seal::lend()), now, None)
            .is_some(),
        "valid pre-rotation"
    );

    std::fs::write(&key_path, hex::encode([9u8; 32])).unwrap();
    busbar_kernel_testkit::app::build_once(
        cfg_with_credentials(&token_path, &key_path),
        Some(&prior),
    )
    .expect("apply");

    assert!(
        gov.verify_token(old_token.expose(&busbar_kernel::seal::lend()), now, None)
            .is_none(),
        "a token minted under the PRE-rotation signing key must stop verifying after the reload"
    );
    let spec2 = busbar_kernel::governance::NewKeySpec {
        name: "k2".into(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let (_b2, fresh) = gov
        .mint_signed(spec2, now + 10_000, now)
        .expect("mint under the new key");
    assert!(
        gov.verify_token(fresh.expose(&busbar_kernel::seal::lend()), now, None).is_some(),
        "the engine mints AND verifies under the rotated key (signer and verifier swap as one unit)"
    );

    std::fs::remove_file(&key_path).unwrap();
    let err = match busbar_kernel_testkit::app::build_once(
        cfg_with_credentials(&token_path, &key_path),
        Some(&prior),
    ) {
        Err(e) => e,
        Ok(_) => panic!("an unresolvable signing-key ref must refuse the apply"),
    };
    assert!(
        err.contains("signing_key"),
        "the refusal names the ref: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn blank_admin_token_refuses_to_start() {
    link();
    busbar_kernel_testkit::test_support::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-blank-admin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("signing.key");
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    for blank in ["", "   ", "\n\t "] {
        let token_path = dir.join("admin.token");
        std::fs::write(&token_path, blank).unwrap();
        let err = match busbar_kernel_testkit::app::build_once(
            cfg_with_credentials(&token_path, &key_path),
            None,
        ) {
            Err(e) => e,
            Ok(_) => panic!("a blank admin token ({blank:?}) must refuse to start"),
        };
        assert!(
            err.contains(config::operator_provider()),
            "the refusal names the admin credential: {err}"
        );
        if !blank.is_empty() {
            assert!(
                err.contains("whitespace"),
                "a whitespace-only token must be refused as whitespace-only: {err}"
            );
        }
    }

    let token_path = dir.join("admin.token");
    std::fs::write(&token_path, "real-token").unwrap();
    let app =
        busbar_kernel_testkit::app::build_once(cfg_with_credentials(&token_path, &key_path), None)
            .expect("boot");
    let gov = app.governance.clone().expect("governance");
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"real-token").as_str())
    );
    assert_ne!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"").as_str()),
        "the blank-string digest must never be a live admin credential"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_renamed_provider_backed_by_the_operator_module_is_the_operator_credential() {
    renamed_provider_is_the_operator_credential(op()).await;
}

#[tokio::test]
async fn the_operator_module_named_by_its_canonical_name_is_the_operator_credential() {
    let op = op();
    let &(_, canonical, _) = crate::LINKED
        .auths
        .iter()
        .find(|row| row.0 == op)
        .expect("the root links the operator credential's row");
    assert_ne!(canonical, op, "the row's canonical name is not its key");
    assert!(config::names_operator(canonical) && config::names_operator(op));
    renamed_provider_is_the_operator_credential(canonical).await;
}

async fn renamed_provider_is_the_operator_credential(module: &str) {
    link();
    busbar_kernel_testkit::test_support::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-op-by-module-{module}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (token_path, key_path) = (dir.join("admin.token"), dir.join("signing.key"));
    std::fs::write(&token_path, TOKEN).unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();
    let mut cfg = cfg_with_credentials(&token_path, &key_path);
    let auth = cfg.auth.as_mut().expect("the fixture configures auth");
    auth.admin_auth[0].name = "ops".to_string();
    auth.admin_auth[0].module = module.to_string();
    cfg.admin_auth = vec!["ops".to_string()];

    let ops: config::IdentityProviderCfg =
        serde_yaml::from_str(&format!("module: {module}")).expect("ops");
    cfg.identity_providers.insert("ops".to_string(), ops);
    let app = Arc::new(busbar_kernel_testkit::app::build_once(cfg, None).expect("boot"));
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        app.admin_modules.operator.is("ops"),
        "{module}: the provider is the operator credential"
    );
    use busbar_contract::authz::Scope;
    assert!(
        busbar_kernel::auth::dry_run_admin_scope(&app, &bearer(TOKEN)).allows(Scope::Full),
        "{module}: the operator token earns full scope through the renamed provider"
    );
    for (bearer, header) in [(Some(TOKEN), None), (None, Some(TOKEN))] {
        let (status, body) = probe(app.clone(), bearer, header).await;
        assert_eq!(
            status, 200,
            "{module}: bearer={bearer:?} header={header:?}: {body}"
        );
    }
    let (status, body) = probe(app, Some("wrong"), None).await;
    assert_eq!(
        (status, body),
        (401, unauthorized()),
        "{module}: a wrong token is refused"
    );
}

#[tokio::test]
async fn a_provider_named_like_the_operator_but_backed_by_another_module_is_that_module() {
    busbar_kernel_testkit::test_support::metrics::init();
    let op = op();

    let named_op = || {
        let base = app(&[op], Vec::new());
        let defs = [(op, AnyCredential.name())].into_iter();
        let is_op = |m: &str| config::names_operator(m);

        let operator = Operator::open(op, defs, &is_op, false, None, |_| unreachable!())
            .expect("opens")
            .with_carriers(base.admin_modules.operator.carriers().to_vec());
        assert!(
            !operator.is(op),
            "a definition under the name, backed elsewhere"
        );
        let mut named = (*base).clone();
        named.admin_modules = Arc::new(AdminAuthChain {
            modules: HashMap::from([(
                op.to_string(),
                busbar_kernel_testkit::test_support::auth_helpers::in_process(Box::new(
                    AnyCredential,
                )),
            )]),
            operator,
        });
        Arc::new(named)
    };
    let (status, body) = probe(named_op(), Some("an-idp-credential"), None).await;
    assert_eq!(
        status, 403,
        "the configured module is consulted and identifies the caller: {body}"
    );
    let (status, body) = probe(named_op(), Some(TOKEN), None).await;
    assert_eq!(
        status, 403,
        "the operator token is not judged by the operator credential here: {body}"
    );
}

#[cfg(feature = "root-admin")]
struct Answers200;

#[cfg(feature = "root-admin")]
impl crate::root::units_admin::AdminDispatch for Answers200 {
    fn execute(
        &self,
        _verb: busbar_core_admin::KernelVerb,
        _request: &crate::root::units_admin::AdminRequest,
    ) -> crate::root::units_admin::AdminAnswer {
        crate::root::units_admin::AdminAnswer {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        }
    }
}

#[cfg(feature = "root-admin")]
const DOOR_401: &str = r#"{"error":{"code":"unauthorized","message":"missing or invalid admin credential (Bearer or x-admin-token)"}}"#;

#[cfg(feature = "root-admin")]
fn through_the_loop(
    handle: &Arc<busbar_kernel::state::AppHandle>,
    (method, path): (&str, &str),
    bearer: Option<&str>,
    header: Option<&str>,
) -> (u16, String) {
    busbar_kernel_testkit::test_support::metrics::init();
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(Answers200),
        crate::root::units_admin::live_admin_door(Arc::clone(handle)),
    );
    let node = crate::root::units_admin::AdminNode::new(crate::root::kernel::new_kernel(), units);
    let mut headers = Vec::new();
    if let Some(b) = bearer {
        headers.push(("authorization".to_string(), format!("Bearer {b}")));
    }
    if let Some(h) = header {
        headers.push(("x-admin-token".to_string(), h.to_string()));
    }
    let map: axum::http::HeaderMap = (headers.iter())
        .map(|(n, v)| (n.parse().unwrap(), v.parse().unwrap()))
        .collect();
    let answer = node.answer(crate::root::units_admin::AdminRequest {
        method: method.to_string(),
        path: path.to_string(),
        credential: crate::root::units_admin::presented_credential(&map),
        headers,
        body: Vec::new(),
        at: 1_700_000_000,
        unit: node.next_unit(),
    });
    (answer.status, String::from_utf8(answer.body).unwrap())
}

#[cfg(feature = "root-admin")]
const INFO: (&str, &str) = ("GET", "/api/v1/admin/info");

#[cfg(feature = "root-admin")]
#[test]
fn an_empty_admin_chain_is_the_open_posture_on_the_loop() {
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app(&[], Vec::new())));
    assert_eq!(through_the_loop(&handle, INFO, None, None).0, 200);
    let write = ("POST", "/api/v1/admin/keys");
    assert_eq!(through_the_loop(&handle, write, None, None).0, 200);
}

#[cfg(feature = "root-admin")]
#[test]
fn the_loop_judges_the_operator_token_on_both_carriers_as_1_5_5_did() {
    let op = op();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app(&[op], Vec::new())));
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    let cases: [(Option<&str>, Option<&str>, u16); 9] = [
        (None, None, 401),
        (Some(TOKEN), None, 200),
        (None, Some(TOKEN), 200),
        (Some("wrong"), None, 401),
        (None, Some("wrong"), 401),
        (Some("wrong"), Some(TOKEN), 200),
        (Some(TOKEN), Some("wrong"), 200),
        (Some(jws), Some(TOKEN), 200),
        (Some(jws), None, 401),
    ];
    for (bearer, header, want) in cases {
        let (status, body) = through_the_loop(&handle, INFO, bearer, header);
        assert_eq!(status, want, "bearer={bearer:?} header={header:?}: {body}");
        if want == 401 {
            assert_eq!(body, DOOR_401, "bearer={bearer:?} header={header:?}");
        }
    }
}

#[cfg(feature = "root-admin")]
#[test]
fn an_external_admin_module_is_consulted_by_the_loop() {
    let op = op();
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    let first = Arc::new(busbar_kernel::state::AppHandle::new(app(
        &["any-credential", op],
        vec![("any-credential", Box::new(AnyCredential))],
    )));
    assert_eq!(through_the_loop(&first, INFO, Some(jws), None).0, 403);
    assert_eq!(
        through_the_loop(&first, INFO, None, None),
        (401, DOOR_401.to_string())
    );
    let behind = Arc::new(busbar_kernel::state::AppHandle::new(app(
        &[op, "any-credential"],
        vec![("any-credential", Box::new(AnyCredential))],
    )));
    assert_eq!(through_the_loop(&behind, INFO, Some(TOKEN), None).0, 200);
    for wrong in [jws, "wrong-opaque-token"] {
        assert_eq!(
            through_the_loop(&behind, INFO, Some(wrong), None),
            (401, DOOR_401.to_string())
        );
    }
}

#[cfg(feature = "root-admin")]
#[test]
fn a_swapped_admin_chain_is_the_loops_next_door() {
    link();
    busbar_kernel_testkit::test_support::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-live-door-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (token_path, key_path) = (dir.join("admin.token"), dir.join("signing.key"));
    std::fs::write(&token_path, "tok-live").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();
    let closed = Arc::new(
        busbar_kernel_testkit::app::build_once(cfg_with_credentials(&token_path, &key_path), None)
            .expect("boot"),
    );
    let mut open = (*closed).clone();
    open.admin_chain = Vec::new();
    let open = Arc::new(open);

    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(&closed)));
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(Answers200),
        crate::root::units_admin::live_admin_door(Arc::clone(&handle)),
    );
    let node = crate::root::units_admin::AdminNode::new(crate::root::kernel::new_kernel(), units);
    let ask = |node: &crate::root::units_admin::AdminNode| {
        node.answer(crate::root::units_admin::AdminRequest {
            method: INFO.0.to_string(),
            path: INFO.1.to_string(),
            credential: None,
            headers: Vec::new(),
            body: Vec::new(),
            at: 1_700_000_000,
            unit: node.next_unit(),
        })
        .status
    };
    assert_eq!(ask(&node), 401, "the operator chain, no credential");
    handle.swap(Arc::clone(&open));
    assert_eq!(
        ask(&node),
        200,
        "the swapped-in empty chain opens the SAME node's door"
    );
    handle.swap(closed);
    assert_eq!(ask(&node), 401, "and swapping it back closes it");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_door_on_the_data_plane_chain_judges_the_request_it_is_lent() {
    use busbar_kernel::auth::{AuthMiddleware, ChainHead, ChainVerdict};
    let op = op();
    let registry = busbar_kernel::preflight::plugins_preflight(
        None,
        None,
        &config::IdentityProviders::new(),
        &HashMap::new(),
        &config::PluginsCfg::default(),
        &config::ExportCfg::default(),
    )
    .expect("the linked rows");
    let digest = busbar_contract::redacted::sha256_hex(TOKEN.as_bytes());
    let door = crate::root::dispatch::auth_axis(registry)
        .open(op, "data-door", &serde_json::Value::String(digest))
        .expect("the linked door opens through the root's auth axis");
    let auth = Arc::new(
        busbar_kernel_testkit::test_support::auth_helpers::from_doors_for_test(vec![(
            "data-door".to_string(),
            door,
        )]),
    );
    let judged = |token: Option<&str>, head: bool| {
        let headers = token.map(bearer).unwrap_or_default();
        let head = match head {
            true => ChainHead::of_parts("POST", "/v1/chat/completions", &headers),
            false => ChainHead::default(),
        };
        let auth = auth.clone();
        let token = token.map(str::to_string);
        async move { AuthMiddleware::run_chain_on_request_path(&auth, token, head, None, None).await }
    };
    match judged(Some(TOKEN), true).await {
        ChainVerdict::Identified { module, .. } => assert_eq!(module, "data-door"),
        other => panic!("the operator token identifies through the door: {other:?}"),
    }
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    for wrong in [Some("not-the-token"), Some(jws), None] {
        assert_eq!(
            judged(wrong, true).await,
            ChainVerdict::Denied,
            "{wrong:?} is refused or passed, and the chain denies"
        );
    }
    assert_eq!(
        judged(Some(TOKEN), false).await,
        ChainVerdict::Denied,
        "with no head lent the door sees no Bearer line"
    );
}

fn bearer(token: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("a header value"),
    );
    headers
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_bound_principal_governed_like_a_virtual_key() {
    use busbar_contract::abi::plane::ROUTE_POOL;
    use busbar_kernel::auth::{
        resolve_data_plane_identity, AuthMiddleware, ChainHead, IdentityRefusal,
    };
    link();
    let module = "test-groups-module";
    let mut table = std::collections::BTreeMap::new();
    table.insert(
        "pool-users".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["gpool-a".to_string()]),
            ..Default::default()
        },
    );

    table.insert("batch".to_string(), RoleBindingCfg::default());

    table.insert(
        "locked".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec![]),
            ..Default::default()
        },
    );
    let mut role_bindings = config::RoleBindings::new();
    role_bindings.insert(module.to_string(), table);
    let auth = Arc::new(
        busbar_kernel_testkit::test_support::auth_helpers::new_builtin(&AuthCfg::with_chain(vec![
            AuthChainEntry::bare(module),
        ])),
    );
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .auth(Arc::clone(&auth))
        .role_bindings(role_bindings)
        .build();
    let pools = crate::root::door_steps::DoorPools::of(
        &serde_yaml::from_str(
            "models:\n  rekey-model: {provider: p}\npools:\n  gpool-a:\n    members: \
             [rekey-model]\n  gpool-b:\n    members: [rekey-model]",
        )
        .expect("the section"),
        busbar_contract::section::RESERVED_POOLS_KEY,
    )
    .expect("the pools");

    let answer = |credential: &'static str, pool: &'static str| {
        let (auth, app, pools) = (Arc::clone(&auth), Arc::clone(&app), pools.clone());
        async move {
            let headers = axum::http::HeaderMap::new();
            let head = ChainHead::of_parts("POST", "/v1/chat/completions", &headers);
            let verdict = AuthMiddleware::run_chain_on_request_path(
                &auth,
                Some(credential.to_string()),
                head,
                None,
                None,
            )
            .await;
            match resolve_data_plane_identity(&app, verdict) {
                Err(IdentityRefusal::NoGrant | IdentityRefusal::Denied) => 401,
                Ok((_, gov)) => {
                    if pools.granted(
                        Some("pool"),
                        gov.key.as_deref(),
                        ROUTE_POOL,
                        Some(pool.as_bytes()),
                    ) {
                        200
                    } else {
                        busbar_kernel::plane_driver::refusal_status(
                            busbar_contract::caps::ReasonCode::ScopeDenied,
                        )
                    }
                }
            }
        }
    };

    assert_eq!(
        answer("grp:pool-users", "gpool-a").await,
        200,
        "granted pool serves"
    );
    assert_eq!(
        answer("grp:pool-users", "gpool-b").await,
        403,
        "ungranted pool is denied"
    );

    assert_eq!(
        answer("grp:batch", "gpool-a").await,
        200,
        "omitted allowed_pools grants all"
    );
    assert_eq!(
        answer("grp:batch", "gpool-b").await,
        200,
        "omitted allowed_pools grants all"
    );

    assert_eq!(
        answer("grp:locked", "gpool-a").await,
        401,
        "allowed_pools [] grants nothing"
    );

    assert_eq!(
        answer("grp:strangers", "gpool-a").await,
        401,
        "unbound roles grant nothing"
    );
}

#[tokio::test]
async fn the_data_listener_reads_the_three_1_5_5_lines_in_1_5_5_order() {
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::NewKeySpec;
    link();
    let store = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store, Some(TOKEN.to_string()), Some(signer)).expect("gov"),
    );
    let now = busbar_kernel::store::now();
    let (_, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "carriers".into(),
                ..Default::default()
            },
            now + 3_600,
            now,
        )
        .expect("mint");
    let token = token.expose(&busbar_kernel::seal::lend()).clone();
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .keys_chain()
        .governance(gov)
        .build();
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let status = |lines: Vec<(&'static str, String)>| {
        let mut req = client.get(format!("http://{addr}/stats"));
        for (name, value) in lines {
            req = req.header(name, value);
        }
        async move { req.send().await.unwrap().status().as_u16() }
    };
    let bearer = |t: &str| format!("Bearer {t}");
    let sigv4 = "AWS4-HMAC-SHA256 Credential=AKIA0000000000000000/20240101/us-east-1/svc/\
                 aws4_request, SignedHeaders=host, Signature=00"
        .to_string();
    let cases: Vec<CarrierCase> = vec![
        ("bearer alone", vec![("authorization", bearer(&token))], 200),
        ("x-api-key alone", vec![("x-api-key", token.clone())], 200),
        (
            "x-goog-api-key alone",
            vec![("x-goog-api-key", token.clone())],
            200,
        ),
        (
            "bearer wins over a bad x-api-key",
            vec![
                ("authorization", bearer(&token)),
                ("x-api-key", "not-a-key".into()),
            ],
            200,
        ),
        (
            "a bad bearer wins over a good x-api-key",
            vec![
                ("authorization", bearer("not-a-key")),
                ("x-api-key", token.clone()),
            ],
            401,
        ),
        (
            "x-api-key wins over a bad x-goog-api-key",
            vec![
                ("x-api-key", token.clone()),
                ("x-goog-api-key", "not-a-key".into()),
            ],
            200,
        ),
        (
            "a signature authorization falls through to x-api-key",
            vec![("authorization", sigv4), ("x-api-key", token.clone())],
            200,
        ),
        (
            "a bad x-goog-api-key",
            vec![("x-goog-api-key", "nope".into())],
            401,
        ),
        ("no line", vec![], 401),
    ];
    for (case, lines, want) in cases {
        assert_eq!(status(lines).await, want, "{case}");
    }
    server.abort();
}

type CarrierCase = (&'static str, Vec<(&'static str, String)>, u16);
