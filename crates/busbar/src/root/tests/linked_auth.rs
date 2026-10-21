// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH AXIS'S LINKED ROW (ARCHITECT 2026-09-27 AUTH-ROW; DECISIONS #2 rule (1), #40): the
//! operator credential resolves through the auth kind's registry by the key configuration names,
//! and the row that answers it is the one this composition root links (`auths` in the manifest).
//! The kernel names no auth module and links none, so every test here that needs the operator
//! credential to answer lives beside the row: the admin door judged on BOTH carriers, the chain
//! composing past it, the rotation of its token on apply, and the refusals when the row is gone.

use std::collections::HashMap;
use std::sync::Arc;

use busbar_contract::auth::{AuthModule, AuthVerdict, Principal};
use busbar_kernel::auth::{AdminAuthChain, Operator};
use busbar_kernel::config::{self, AuthCfg, AuthChainEntry, RoleBindingCfg, SecretRef};
use busbar_kernel::governance::{GovState, MemoryStore};
use busbar_kernel::preflight::RootInstall;

/// The operator's token in every fixture here.
const TOKEN: &str = "admintok";

/// THE RECORD EVERY FIXTURE HERE LENDS: the kernel's test stand-in lending this build's linked auth
/// rows and the root's operator words, as `root::linked::register_stores` builds the record `main`
/// lends, its auth rows opened through the root's own auth axis (`crate::root::dispatch::auth_axis`),
/// the opener the shipped root's install record lends.
fn root() -> RootInstall {
    RootInstall {
        auth_axis: Some(crate::root::dispatch::auth_axis),
        ..busbar_kernel::test_support::lending_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        )
    }
}

/// Register the linked protocol declarations and the neutral test plane every fixture here builds
/// over: a config fixture's provider names the registry's residual-default dialect, and which test
/// installed it first must not decide a verdict.
fn link() {
    for decls in crate::LINKED.protocols {
        busbar_kernel::proto::register_test_protocols(decls);
    }
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    busbar_kernel::test_support::register_neutral_test_plane();
}

/// The operator credential's provider key: the one the record every fixture here lends carries.
fn op() -> &'static str {
    link();
    root().operator.provider
}

/// An app whose governance holds the operator token, with `chain` as its admin chain, and `extra`
/// external admin modules beside it.
fn app(chain: &[&str], extra: Vec<(&str, Box<dyn AuthModule>)>) -> Arc<busbar_kernel::state::App> {
    link();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some(TOKEN.to_string())).expect("governance"));
    let mut app = busbar_kernel::test_support::TestApp::new()
        .root(root())
        .governance(gov)
        .admin_chain(chain.iter().map(|s| s.to_string()).collect());
    for (name, module) in extra {
        app = app.admin_module(name, module);
    }
    app.build()
}

/// `GET /api/v1/admin/info` over the real router with the given carriers: (status, body), the body
/// prefixed by its `content-type` and `content-length` when the answer is a refusal.
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

/// A refusal's comparable bytes: its content type, its length and its body, the body normalised to
/// JSON value form so the golden's recorded JSON compares to it.
fn refusal(content_type: &str, content_length: &str, body: &str) -> String {
    let body: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    format!("{content_type} {content_length} {body}")
}

/// A 1.5.5 golden cell (`testing/shadow-oracle/golden/1.5.5`, recorded from the published binary).
fn golden_cell(cell: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
        .join(cell);
    let text = std::fs::read_to_string(&path).expect("the 1.5.5 golden cell");
    serde_json::from_str(&text).expect("golden json")
}

/// The admin 401 exactly as 1.5.5 served `GET /api/v1/admin/info` with no credential.
fn unauthorized() -> String {
    let cell = golden_cell("admin.ops__GetInfo__unauth.json");
    assert_eq!(cell["status"], 401);
    refusal(
        cell["headers"]["content-type"].as_str().unwrap(),
        cell["headers"]["content-length"].as_str().unwrap(),
        &cell["body"]["json"].to_string(),
    )
}

/// An external admin module that identifies ANY presented credential as a roleless principal — the
/// shape an IdP arm behind the operator credential takes. It earns no grant (no binding), so a
/// request it identifies is a 403, which is how a test tells "the chain reached this arm" from "the
/// chain denied" (a 401).
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

/// The operator credential's row is on the auth axis under the configuration's key.
#[test]
fn the_operator_credentials_row_is_linked_under_its_config_key() {
    link();
    assert!(
        busbar_kernel::preflight::linked_auth_names(&root()).contains(&root().operator.provider),
        "the root links the operator credential's row: {:?}",
        busbar_kernel::preflight::linked_auth_names(&root())
    );
}

/// THE SHIPPED DEFAULT INBOUND STYLE (row 159, K3#1): the linked rows state exactly one, and its
/// carrier marks are 1.5.5's client-token lines in 1.5.5's precedence order (the Bearer on
/// `authorization`, then `x-api-key`, then `x-goog-api-key`). The kernel names none of them; RED
/// before the header auth states them (no row states the style, so the walk reads nothing). And the
/// operator credential's row states 1.5.5's two admin lines, Bearer first.
#[test]
fn the_linked_default_inbound_style_is_the_1_5_5_client_token_lines_in_order() {
    link();
    let linked = Arc::new(
        busbar_kernel::preflight::linked(&root(), crate::root::legacy::table())
            .expect("the linked registry"),
    );
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
        axis.carriers(root().operator.provider),
        vec!["authorization".to_string(), "x-admin-token".to_string()]
    );
}

/// `GET /api/v1/admin/info` `build.auth_modules` in the shipped build is 1.5.5's answer, `keys` and
/// the operator credential's word (oracle cell `admin.ops|GetInfo|ok`): the build also links
/// OUTBOUND-ONLY auth plugins on the auth axis (ARCHITECT Q-L1-AUTH (A)), and a row that declares no
/// inbound capability is not an auth-chain module an operator can name, so it is not listed. RED
/// before the fix: the outbound-only header row's name was listed third. The default build also
/// links the INBOUND webhook-signature row (ARCHITECT 2026-10-14, accepted difference `#64-class
/// build.auth_modules lists the webhook-signature module`), an auth-chain module an operator names,
/// so it is listed after 1.5.5's two. The case rides every linked auth row (`linked_every_auth`,
/// build.rs): every outbound-only row is then linked, and none of them is listed.
#[cfg(linked_every_auth)]
#[test]
fn the_info_auth_modules_are_the_inbound_rows_only() {
    link();
    let linked = busbar_kernel::preflight::linked_auth_names(&root());
    assert!(
        linked.len() > 1,
        "the default build links an outbound-only auth row beside the operator credential's: {linked:?}"
    );
    assert_eq!(
        busbar_core_admin::v1::service::auth_modules_compiled_in(&root()),
        vec![
            "keys",
            root().operator.provider,
            "busbar-auth-webhook-signature"
        ],
        "only inbound auth-chain modules are listed, 1.5.5's two first and the default build's \
         webhook-signature row after them (ARCHITECT 2026-10-14; linked rows: {linked:?})"
    );
}

/// THE PROBE EXT-AUTHADMIN ran, over the row the root links: every carrier combination answers as
/// 1.5.5 did — the operator token on EITHER carrier admits, a wrong one on either refuses with the
/// frozen 401 body, and a request carrying both is judged on both (the right header admits past a
/// wrong Bearer, and past a Bearer in another scheme's grammar).
#[tokio::test]
async fn the_admin_door_answers_both_carriers_through_the_linked_row() {
    busbar_kernel::snapshot::init();
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

/// THE ADMIN CHAIN ENDS AT THE OPERATOR CREDENTIAL ON ANY WRONG TOKEN, as 1.5.5's did. `Reject` is
/// TERMINAL in the admin chain, and the operator credential's module rejects every presented
/// mismatch whatever its shape: a JWS-shaped wrong token is refused there with the frozen 401 and
/// never reaches an IdP arm configured behind it.
#[tokio::test]
async fn the_chain_ends_at_the_operator_credential_on_any_wrong_token() {
    busbar_kernel::snapshot::init();
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

/// RED ARM — REMOVE THE ROOT ROW AND THE ADMIN DOOR REFUSES. The same app, with its operator
/// credential opened from a registry that does not hold the root's row: the operator token that
/// admits above is now refused with the frozen 401, on both carriers. The kernel had no other way
/// to answer it.
#[tokio::test]
async fn without_the_root_row_the_operator_token_is_refused() {
    busbar_kernel::snapshot::init();
    let op = op();
    let with_row = app(&[op], Vec::new());
    // What `busbar_kernel::auth::open_operator` answers when the registry holds no row under the operator
    // credential's key (the kernel's own tests pin that `open` over an empty registry yields it).
    let mut without_row = (*with_row).clone();
    without_row.admin_modules = Arc::new(AdminAuthChain {
        modules: HashMap::new(),
        operator: Operator::new(root().operator.provider),
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

/// The 1.5.5 golden cell's refusal line (`[error] …`), as the published binary printed it.
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

/// A CONFIG NAMING AN UNREGISTERED AUTH MODULE IS REFUSED WITH 1.5.5'S BYTES. With plugins off, a
/// provider whose `module:` no row answers is refused, and the refusal lists the built-ins exactly
/// as 1.5.5 did (`keys | admin-tokens`) — the operator credential is still a built-in to the
/// configuration, although the kernel links no module for it. Compared to the golden cell the
/// published 1.5.5 binary recorded (BOOT-133), byte for byte.
#[test]
fn an_unregistered_auth_module_is_refused_with_the_1_5_5_bytes() {
    link();
    let mut providers = config::IdentityProviders::new();
    let def: config::IdentityProviderCfg =
        serde_yaml::from_str("module: oidc").expect("a provider definition");
    providers.insert("oracle-oidc".to_string(), def);
    let err = busbar_kernel::preflight::plugins_preflight(
        &root(),
        None,
        None,
        &providers,
        &HashMap::new(),
        &config::PluginsCfg::default(),
        &config::ExportCfg::default(),
        crate::root::legacy::table(),
    )
    .expect_err("an unregistered auth module is refused");
    assert_eq!(err, golden_refusal("boot.refusal__BOOT-133__boot.json"));
}

/// A role name shadowing the operator principal id is refused while the operator credential's row is
/// linked (it is the principal that row mints), exactly as 1.5.5's default build refused it.
#[test]
fn a_role_shadowing_the_operator_principal_is_refused() {
    link();
    let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(SecretRef::none());
    cfg.root = root();
    // The fixture's default admin chain, under the words the record lends.
    cfg.admin_auth = config::default_admin_auth_names(&cfg.root);
    let mut auth = AuthCfg::default_none();
    auth.chain = vec![AuthChainEntry::bare(config::KEYS_MODULE)];
    let mut roles = HashMap::new();
    roles.insert(
        root().operator.principal_id.to_string(),
        RoleBindingCfg::default(),
    );
    auth.role_bindings
        .insert(config::KEYS_MODULE.to_string(), roles.into_iter().collect());
    cfg.auth = Some(auth);
    let errs = busbar_kernel::config_validate::validate(&cfg).expect_err("a reserved role");
    assert!(
        errs.iter().any(|e| e.contains("role_bindings.keys")
            && e.contains(&format!("'{}'", root().operator.principal_id))
            && e.contains("reserved")),
        "expected the reserved-role-name error; got: {errs:?}"
    );
}

/// The operator credential is a SECRET REFERENCE; `validate()` checks its MODULE resolves (env |
/// file) without resolving the value (moved from the kernel with the row it needs: without one, the
/// configured token is itself refused).
#[test]
fn the_operator_token_ref_is_checked_by_shape_only() {
    link();
    let build = |token: SecretRef| -> Result<(), Vec<String>> {
        let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(SecretRef::none());
        cfg.root = root();
        // The fixture's default admin chain, under the words the record lends.
        cfg.admin_auth = config::default_admin_auth_names(&cfg.root);
        let mut auth = AuthCfg::default_none();
        let mut entry = AuthChainEntry::bare(root().operator.provider);
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
    let path = format!("auth.admin_auth.{}.token", root().operator.provider);
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

/// Build a minimal, valid RootCfg whose admin token and signing key are `file:` secret refs, so a
/// rotation is "write different bytes to the same path". Used by the 3 tests below (moved from the
/// kernel with the row they need: without one, the configured token is itself refused at validate).
fn cfg_with_credentials(
    token_path: &std::path::Path,
    key_path: &std::path::Path,
) -> busbar_kernel::config::RootCfg {
    // `api_key: none` — this fixture's provider is never contacted, so it declares no credential
    // rather than naming a variable it knows is unset (which now refuses boot).
    let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(
        busbar_kernel::config::SecretRef::none(),
    );
    cfg.root = root();
    // The fixture's default admin chain, under the words the record lends.
    cfg.admin_auth = config::default_admin_auth_names(&cfg.root);
    let mut admin_entry = busbar_kernel::config::AuthChainEntry::bare(root().operator.provider);
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

/// Rotating the admin-token secret on disk and RE-APPLYING changes the credential the process
/// accepts. RED without the re-resolution: the digest stays on `tok-v1` forever.
#[test]
fn admin_token_secret_ref_re_resolves_on_apply() {
    link();
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!("busbar-high7-token-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("admin.token");
    let key_path = dir.join("signing.key");
    std::fs::write(&token_path, "tok-v1").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    let prior =
        busbar_kernel::test_support::build_once(cfg_with_credentials(&token_path, &key_path), None)
            .expect("boot");
    let gov = prior.governance.clone().expect("governance");
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"tok-v1").as_str()),
        "boot accepts the resolved token"
    );

    // THE ROTATION: the operator replaces the secret behind the ref, then reloads.
    std::fs::write(&token_path, "tok-v2").unwrap();
    let next = busbar_kernel::test_support::build_once(
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
    // The applied generation's admin chain judges the ROTATED token: its operator credential was
    // opened over the digest this apply resolved.
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

/// The same for `auth.signing_key`: after rotating the key material and re-applying, a token minted
/// under the OLD key no longer verifies and a freshly-minted one does. A resolution FAILURE on
/// apply is fail-closed — the apply is refused rather than silently keeping the old key.
#[test]
fn signing_key_secret_ref_re_resolves_on_apply_and_fails_closed() {
    link();
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!("busbar-high7-signing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("admin.token");
    let key_path = dir.join("signing.key");
    std::fs::write(&token_path, "tok").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    let prior =
        busbar_kernel::test_support::build_once(cfg_with_credentials(&token_path, &key_path), None)
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

    // THE ROTATION: new key material behind the same ref, then reload.
    std::fs::write(&key_path, hex::encode([9u8; 32])).unwrap();
    busbar_kernel::test_support::build_once(
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

    // FAIL-CLOSED: an unresolvable ref refuses the apply outright.
    std::fs::remove_file(&key_path).unwrap();
    let err = match busbar_kernel::test_support::build_once(
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

/// #37: a `token:` secret ref that resolves to EMPTY or WHITESPACE must refuse to start. The
/// documented boot guard for this was lost when the admin token became a SecretRef, and the
/// consequence is worse than "the admin API is silently locked": the digest is taken over the blank
/// string, so `admin_token_hash` becomes `Some(sha256(""))` — a real credential that an empty
/// presented token satisfies. An env var expanding to nothing would hand over the admin surface.
#[test]
fn blank_admin_token_refuses_to_start() {
    link();
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!("busbar-blank-admin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("signing.key");
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();

    for blank in ["", "   ", "\n\t "] {
        let token_path = dir.join("admin.token");
        std::fs::write(&token_path, blank).unwrap();
        let err = match busbar_kernel::test_support::build_once(
            cfg_with_credentials(&token_path, &key_path),
            None,
        ) {
            Err(e) => e,
            Ok(_) => panic!("a blank admin token ({blank:?}) must refuse to start"),
        };
        assert!(
            err.contains(root().operator.provider),
            "the refusal names the admin credential: {err}"
        );
        if !blank.is_empty() {
            // A WHITESPACE-only value must be refused AS whitespace-only, not merely refused. The
            // `file:` source resolves it untouched, as 1.5.5 did, and the admin credential's own
            // trim guard ("EMPTY/whitespace-only", 1.5.5's) is the refusal this case owes.
            assert!(
                err.contains("whitespace"),
                "a whitespace-only token must be refused as whitespace-only: {err}"
            );
        }
    }

    // A real token still boots, and the digest is of the real value (not of the blank string).
    let token_path = dir.join("admin.token");
    std::fs::write(&token_path, "real-token").unwrap();
    let app =
        busbar_kernel::test_support::build_once(cfg_with_credentials(&token_path, &key_path), None)
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

/// The operator credential chosen BY MODULE: an `admin_auth:` provider under another name whose
/// `module:` is the operator credential's (`ops: { module: admin-tokens, token: ... }`) is the
/// operator credential. Built from configuration through the real build, it admits the operator
/// token on either carrier with full scope and refuses a wrong one with the frozen 401. Dispatching
/// on the provider NAME skipped it and refused every admin request.
#[tokio::test]
async fn a_renamed_provider_backed_by_the_operator_module_is_the_operator_credential() {
    renamed_provider_is_the_operator_credential(op()).await;
}

/// ONE PLUGIN, ONE IDENTITY (ARCHITECT C'): the operator credential's module named by its CANONICAL
/// name (the manifest name its release tarball carries, its row's `linked-canonical` value) is the
/// operator credential exactly as its key is — the same provider, the same full scope, the same
/// carriers, the same refusal — because the kernel compares the plugin the module resolves to, not
/// the spelling. RED before: the token on that provider was refused as misplaced, and nothing
/// opened the operator credential behind it.
#[tokio::test]
async fn the_operator_module_named_by_its_canonical_name_is_the_operator_credential() {
    let op = op();
    let &(_, canonical, _) = crate::LINKED
        .auths
        .iter()
        .find(|row| row.0 == op)
        .expect("the root links the operator credential's row");
    assert_ne!(canonical, op, "the row's canonical name is not its key");
    assert!(
        config::names_operator(canonical, &root(), crate::root::legacy::table())
            && config::names_operator(op, &root(), crate::root::legacy::table())
    );
    renamed_provider_is_the_operator_credential(canonical).await;
}

/// `admin_auth: [ops]`, `ops: { module: <module>, token: <file> }`, built from configuration: the
/// operator credential, on both carriers, at full scope; a wrong token refused with the frozen 401.
async fn renamed_provider_is_the_operator_credential(module: &str) {
    link();
    busbar_kernel::snapshot::init();
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
    // The definition the resolved entry came from, as config.yaml would carry it.
    let ops: config::IdentityProviderCfg =
        serde_yaml::from_str(&format!("module: {module}")).expect("ops");
    cfg.identity_providers.insert("ops".to_string(), ops);
    let app = Arc::new(busbar_kernel::test_support::build_once(cfg, None).expect("boot"));
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

/// The other half: a provider NAMED like the operator credential but backed by another module is
/// that module, consulted under its own ceiling. It identifies what it identifies (a roleless
/// principal with no grant: 403) and the operator token confers nothing through it. Dispatching on
/// the name ran the operator credential instead and never asked the configured module.
#[tokio::test]
async fn a_provider_named_like_the_operator_but_backed_by_another_module_is_that_module() {
    busbar_kernel::snapshot::init();
    let op = op();
    // `admin_auth: [<op>]` with `<op>: { module: any-credential }`, as the build resolves it: the
    // provider is recorded as backed by that module, and the module is opened under its name.
    let named_op = || {
        let base = app(&[op], Vec::new());
        let defs = [(op, AnyCredential.name())].into_iter();
        let is_op = |m: &str| config::names_operator(m, &root(), crate::root::legacy::table());
        // The operator row's carriers, as the build opened them: the admin lines the candidate
        // the configured module is lent is read from.
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
                busbar_kernel::auth::AdminModule::in_process(Box::new(AnyCredential)),
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

// ── THE ROOT-ADMIN LOOP'S DOOR IS THE SAME LIVE ADMIN CHAIN (DONE-BUILD, ARCHITECT 2026-09-30) ──────
// The loop's authenticate step used to run a hardcoded `[admin-tokens]` chain built once at boot,
// whatever `admin_auth` said: `admin_auth: []` answered 401 where 1.5.5 answered 200 (1.5.5
// `auth/mod.rs:847-848`, scope Full at `:1067-1068`), an external admin module was never asked, and
// `PUT /api/v1/admin/admin-auth` never reached it. Each cell below walks the WHOLE loop over the
// production door (`live_admin_door`) on a live `AppHandle`.

/// The answer the mounted surface gives once the loop admits: a 200 the door could not have written.
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

/// 1.5.5's admin 401 body, the frozen envelope the loop writes at its door.
#[cfg(feature = "root-admin")]
const DOOR_401: &str = r#"{"error":{"code":"unauthorized","message":"missing or invalid admin credential (Bearer or x-admin-token)"}}"#;

/// Walk `method path` with the given carriers through the root-admin loop whose door is the live
/// chain on `handle`: (status, body).
#[cfg(feature = "root-admin")]
fn through_the_loop(
    handle: &Arc<busbar_kernel::state::AppHandle>,
    (method, path): (&str, &str),
    bearer: Option<&str>,
    header: Option<&str>,
) -> (u16, String) {
    busbar_kernel::snapshot::init();
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

/// (a) `admin_auth: []` IS OPEN on the loop, as in 1.5.5: a read and a write answer, with no
/// credential, even on a node whose governance holds an operator token.
#[cfg(feature = "root-admin")]
#[test]
fn an_empty_admin_chain_is_the_open_posture_on_the_loop() {
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app(&[], Vec::new())));
    assert_eq!(through_the_loop(&handle, INFO, None, None).0, 200);
    let write = ("POST", "/api/v1/admin/keys");
    assert_eq!(through_the_loop(&handle, write, None, None).0, 200);
}

/// (b) + (3) THE OPERATOR TOKEN ON THE LOOP, BOTH CARRIERS, AS 1.5.5 JUDGED THEM: no credential is
/// the door's 401 in 1.5.5's bytes; either carrier admits; a request carrying both is judged on
/// both (the right header admits past a wrong Bearer and past a Bearer in another grammar).
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

/// (c) AN EXTERNAL ADMIN MODULE ON THE CHAIN IS CONSULTED BY THE LOOP, and its verdict decides: a
/// credential it identifies (roleless, so no grant) is the authorization ending, 403 — not the
/// door's 401 the hardcoded chain answered — and one the chain refuses is still the door's 401.
/// The external module stands first: behind the operator credential it would never see a token,
/// since the operator credential rejects every presented mismatch (1.5.5's chain rule).
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

/// (d) THE CHAIN IS READ LIVE: swapping the snapshot's admin chain (what `PUT
/// /api/v1/admin/admin-auth` applies) changes the loop's next answer, with no new node. The
/// generations are real builds (`build_once`), so every plane's swap hook sees the runtime it owns.
#[cfg(feature = "root-admin")]
#[test]
fn a_swapped_admin_chain_is_the_loops_next_door() {
    link();
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!("busbar-live-door-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (token_path, key_path) = (dir.join("admin.token"), dir.join("signing.key"));
    std::fs::write(&token_path, "tok-live").unwrap();
    std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();
    let closed = Arc::new(
        busbar_kernel::test_support::build_once(cfg_with_credentials(&token_path, &key_path), None)
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

/// THE DATA-PLANE CHAIN ON THE AUTH AXIS (AUTH-CHAIN-SWITCH, ARCHITECT lane L2-AUTH; THE DESIGN
/// 11.6): a provider backed by the linked operator door — a REAL plugin on the auth kind's memory
/// ABI — opened through the root's auth axis is ONE chain position the request path submits and
/// awaits, lent the request's head and its candidate credential: the right token identifies under
/// the provider's name, a wrong one is REFUSED, another scheme's grammar and none pass (and the
/// all-pass chain denies).
///
/// Not vacuous: the same door lent NO head (the candidate alone) cannot see the Bearer this plugin
/// reads off its `authorization` line, and the right token is denied — the head reaches the door.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_door_on_the_data_plane_chain_judges_the_request_it_is_lent() {
    use busbar_kernel::auth::{AuthMiddleware, ChainHead, ChainVerdict};
    let op = op();
    let registry = Arc::new(
        busbar_kernel::preflight::plugins_preflight(
            &root(),
            None,
            None,
            &config::IdentityProviders::new(),
            &HashMap::new(),
            &config::PluginsCfg::default(),
            &config::ExportCfg::default(),
            crate::root::legacy::table(),
        )
        .expect("the linked rows"),
    );
    let digest = busbar_contract::redacted::sha256_hex(TOKEN.as_bytes());
    let door = crate::root::dispatch::auth_axis(registry)
        .open(op, "data-door", &serde_json::Value::String(digest))
        .expect("the linked door opens through the root's auth axis");
    let auth = Arc::new(AuthMiddleware::from_doors_for_test(vec![(
        "data-door".to_string(),
        door,
    )]));
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

/// A request's head presenting `token` as its Bearer: what the admin chain's dry run judges.
fn bearer(token: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("a header value"),
    );
    headers
}

/// LEGACY the retiring engine crate's `src/engine/tests/ingress_integration_tests.rs::test_role_bound_principal_governed_like_a_virtual_key`
/// (coverage map v2 row 402). 1.5.5: with governance on and an external data-plane module on the
/// chain, a role-bound principal is governed through a SYNTHESIZED key exactly like a virtual key:
/// its binding's pool ACL admits the granted pool (200) and refuses another (403); a binding that
/// omits `allowed_pools` grants every pool; an explicit `allowed_pools: []` grants nothing (401);
/// and an identified principal whose roles earn no binding is refused outright (401, fail closed).
///
/// Walked here through the served steps: the data-plane chain judges the request's credential
/// (the test chain's `grp:<role>` module), the verdict resolves to a governance key through the
/// module's `role_bindings` (`resolve_data_plane_identity`), and the door's grant judges the pool
/// the unit names with that key.
///
/// RED: a role binding's pool ACL stops gating (an ungranted pool served), an omitted grant stops
/// meaning every pool, or an empty or absent binding admits the principal.
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
    // OMITTED allowed_pools = ALL pools.
    table.insert("batch".to_string(), RoleBindingCfg::default());
    // Explicit [] = NO pools (the empty set, fail closed).
    table.insert(
        "locked".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec![]),
            ..Default::default()
        },
    );
    let mut role_bindings = config::RoleBindings::new();
    role_bindings.insert(module.to_string(), table);
    let auth = Arc::new(AuthMiddleware::new_builtin(&AuthCfg::with_chain(vec![
        AuthChainEntry::bare(module),
    ])));
    let app = busbar_kernel::test_support::TestApp::new()
        .root(root())
        .auth(Arc::clone(&auth))
        .role_bindings(role_bindings)
        .build();
    let pools = crate::root::door_steps::DoorPools::of(
        &serde_yaml::from_str(
            "models:\n  rekey-model: {provider: p}\npools:\n  gpool-a:\n    members: \
             [rekey-model]\n  gpool-b:\n    members: [rekey-model]",
        )
        .expect("the section"),
    )
    .expect("the pools");
    // What the caller reads: the identity refusal's 401, the grant's 403, else served.
    let answer = |credential: &'static str, pool: &'static str| {
        let (auth, app, pools) = (Arc::clone(&auth), Arc::clone(&app), pools.clone());
        async move {
            // The test module judges the credential handed beside the head, never the head's own line.
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

    // Pool ACL from the role binding: gpool-a serves, gpool-b is denied.
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
    // OMITTED allowed_pools grants every pool.
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
    // Explicit [] grants the EMPTY SET: no data-plane access at all.
    assert_eq!(
        answer("grp:locked", "gpool-a").await,
        401,
        "allowed_pools [] grants nothing"
    );
    // Fail closed: an identified principal whose roles earn no binding is rejected.
    assert_eq!(
        answer("grp:strangers", "gpool-a").await,
        401,
        "unbound roles grant nothing"
    );
}

/// THE CLIENT-TOKEN LINES ON THE DATA LISTENER, end to end through the linked default inbound style
/// (row 159, K3#1): a key minted by `keys` is admitted on each of 1.5.5's three lines alone (the
/// Bearer on `authorization`, raw on `x-api-key` and on `x-goog-api-key`), the Bearer wins when it
/// and `x-api-key` are both present (oracle cell `http.crosscut|bearer-and-x-api-key`), and a bad
/// credential on any line is 1.5.5's 401. A present non-Bearer `authorization` (a SigV4 signature
/// header) falls through to `x-api-key`, as a signed-request SDK's key-carrying shape needs. RED before
/// the header auth states its lines: no line yields a credential, so every request is 401.
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
    let app = busbar_kernel::test_support::TestApp::new()
        .root(root())
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

/// One carrier case: what it shows, the request lines it carries, and the status it is answered.
type CarrierCase = (&'static str, Vec<(&'static str, String)>, u16);
