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

/// The operator's token in every fixture here.
const TOKEN: &str = "admintok";

/// Link this build's auth rows onto the kernel's auth axis, as `register_planes` does at boot (the
/// first install stands, and every install in this binary is this one table). The linked protocol declarations go in too: a config fixture's provider names the registry's
/// residual-default dialect, and which test installed it first must not decide a verdict.
fn link() {
    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    busbar_kernel::preflight::install_auth_axis(crate::root::dispatch::auth_axis);
    for decls in crate::LINKED.protocols {
        busbar_kernel::proto::register_test_protocols(decls);
    }
}

/// The operator credential's provider key, read AFTER the root's words are handed in. Before the
/// first [`link`] the kernel answers with its test-build stand-in words, so a key read first and
/// linked second names a provider no row answers, and every verdict below would judge the wrong
/// chain.
fn op() -> &'static str {
    link();
    config::operator_provider()
}

/// An app whose governance holds the operator token, with `chain` as its admin chain, and `extra`
/// external admin modules beside it.
fn app(chain: &[&str], extra: Vec<(&str, Box<dyn AuthModule>)>) -> Arc<busbar_kernel::state::App> {
    link();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some(TOKEN.to_string())).expect("governance"));
    let mut app = busbar_kernel::test_support::TestApp::new()
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
        busbar_kernel::preflight::linked_auth_names().contains(&config::operator_provider()),
        "the root links the operator credential's row: {:?}",
        busbar_kernel::preflight::linked_auth_names()
    );
}

/// `GET /api/v1/admin/info` `build.auth_modules` in the shipped build is 1.5.5's answer,
/// `["keys", "admin-tokens"]` (oracle cell `admin.ops|GetInfo|ok`): the build also links the
/// OUTBOUND-ONLY header auth plugin on the auth axis (ARCHITECT Q-L1-AUTH (A)), and a row that
/// declares no inbound capability is not an auth-chain module an operator can name, so it is not
/// listed. RED before the fix: `["keys", "admin-tokens", "busbar-auth-header"]`.
#[cfg(feature = "auth-header")]
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
        vec!["keys", config::operator_provider()],
        "only inbound auth-chain modules are listed (linked rows: {linked:?})"
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

/// THE ADMIN CHAIN COMPOSES (moved from the kernel with the module it needs). `Reject` is TERMINAL
/// in the admin chain; the operator credential's module DEFERS on a candidate in another scheme's
/// grammar (a JWS), so an IdP arm configured behind it is reached — and it still refuses, terminally,
/// an opaque candidate that IS addressed to it and wrong, so the arm behind it never admits that.
#[tokio::test]
async fn the_chain_reaches_the_arm_behind_the_operator_credential_only_on_a_foreign_grammar() {
    busbar_kernel::snapshot::init();
    let op = op();
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    let chain = [op, "any-credential"];
    let with_idp = || app(&chain, vec![("any-credential", Box::new(AnyCredential))]);

    let (status, body) = probe(with_idp(), Some(jws), None).await;
    assert_eq!(
        status, 403,
        "a JWS reaches the arm behind and is identified there: {body}"
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

/// A role name shadowing the operator principal id is refused while the operator credential's row is
/// linked (it is the principal that row mints), exactly as 1.5.5's default build refused it.
#[test]
fn a_role_shadowing_the_operator_principal_is_refused() {
    link();
    let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(SecretRef::none());
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

/// The operator credential is a SECRET REFERENCE; `validate()` checks its MODULE resolves (env |
/// file) without resolving the value (moved from the kernel with the row it needs: without one, the
/// configured token is itself refused).
#[test]
fn the_operator_token_ref_is_checked_by_shape_only() {
    link();
    let build = |token: SecretRef| -> Result<(), Vec<String>> {
        let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(SecretRef::none());
        let mut auth = AuthCfg::default_none();
        let mut entry = AuthChainEntry::bare(config::operator_provider());
        entry.token = Some(token);
        auth.admin_auth = vec![entry];
        cfg.auth = Some(auth);
        busbar_kernel::config_validate::validate(&cfg)
    };
    assert!(
        build(SecretRef {
            module: "vault".to_string(),
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
    let mut admin_entry =
        busbar_kernel::config::AuthChainEntry::bare(busbar_kernel::config::operator_provider());
    admin_entry.token = Some(busbar_kernel::config::SecretRef::file(
        token_path.to_string_lossy().to_string(),
    ));
    cfg.auth = Some(busbar_kernel::config::AuthCfg {
        signing_key: Some(busbar_kernel::config::SecretRef::file(
            key_path.to_string_lossy().to_string(),
        )),
        operator_pub: None,
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
        gov.verify_token(old_token.expose_secret(), now, None)
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
        gov.verify_token(old_token.expose_secret(), now, None)
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
        gov.verify_token(fresh.expose_secret(), now, None).is_some(),
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
            err.contains(config::operator_provider()),
            "the refusal names the admin credential: {err}"
        );
        if !blank.is_empty() {
            // A WHITESPACE-only value must be refused AS whitespace-only, not merely refused.
            // The secret resolver now catches it first ("resolved to a BLANK file (whitespace
            // only)"), ahead of the admin trim guard ("EMPTY/whitespace-only"); either guard is
            // the refusal this case owes, and both name the whitespace, so the assertion holds
            // the reason rather than one guard's exact wording.
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
    assert!(config::names_operator(canonical) && config::names_operator(op));
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
        let is_op = |m: &str| config::names_operator(m);
        let operator =
            Operator::open(op, defs, &is_op, false, None, |_| unreachable!()).expect("opens");
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
#[cfg(feature = "root-admin")]
#[test]
fn an_external_admin_module_is_consulted_by_the_loop() {
    let op = op();
    let chain = [op, "any-credential"];
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app(
        &chain,
        vec![("any-credential", Box::new(AnyCredential))],
    )));
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    assert_eq!(through_the_loop(&handle, INFO, Some(jws), None).0, 403);
    assert_eq!(through_the_loop(&handle, INFO, Some(TOKEN), None).0, 200);
    assert_eq!(
        through_the_loop(&handle, INFO, Some("wrong-opaque-token"), None),
        (401, DOOR_401.to_string())
    );
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
            None,
            None,
            &config::IdentityProviders::new(),
            &HashMap::new(),
            &config::PluginsCfg::default(),
            &config::ExportCfg::default(),
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
