// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use busbar_kernel::admission::{Judged, PluginAdmission as _, Refusal};
use busbar_kernel::governance::GovState;

use crate::root::admission::ADMISSION;
use crate::root::loader::sign::{sign, Manifest, SigningKey};

fn tmp_plugins_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);

    static PROC_TOKEN: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    let token = PROC_TOKEN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    });
    let d = std::env::temp_dir().join(format!(
        "busbar-root-plugin-admin-{}-{token:x}-{n}-{tag}",
        std::process::id(),
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn test_manifest(name: &str, alias: &str, publisher: &str, version: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: version.into(),
        publisher: publisher.into(),
        abi_version: *crate::root::loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    }
}

fn unsigned_tarball(mut m: Manifest, lib: &[u8]) -> Vec<u8> {
    m.sha256 = crate::root::loader::sign::sha256_hex(lib);
    crate::root::loader::tarball::package(&m, "lib.so", lib).unwrap()
}

fn signed_tarball(key: &SigningKey, m: Manifest, lib: &[u8]) -> Vec<u8> {
    let m = sign(key, m, lib);
    crate::root::loader::tarball::package(&m, "lib.so", lib).unwrap()
}

fn admin_test_tarball(name: &str, alias: &str) -> Vec<u8> {
    admin_test_tarball_versioned(name, alias, "1.0.0")
}

fn admin_test_tarball_versioned(name: &str, alias: &str, version: &str) -> Vec<u8> {
    let lib = format!("junk library bytes for {name} {version} (never dlopened)").into_bytes();
    unsigned_tarball(test_manifest(name, alias, "acme", version), &lib)
}

fn admin_test_tarball_kind(name: &str, alias: &str, kind: &str) -> Vec<u8> {
    let lib = format!("junk library bytes for {name} (never dlopened)").into_bytes();
    let mut m = test_manifest(name, alias, "acme", "1.0.0");
    m.kind = kind.into();
    m.abi_version = *crate::root::loader::supported_abi(kind)
        .iter()
        .max()
        .unwrap_or(&1);
    unsigned_tarball(m, &lib)
}

fn strict_posture() -> busbar_kernel::config::PluginsCfg {
    busbar_kernel::config::PluginsCfg::default()
}

fn unsigned_ok_posture() -> busbar_kernel::config::PluginsCfg {
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.trust.allow_unsigned = true;
    cfg
}

fn publisher_posture(name: &str, key: &SigningKey) -> busbar_kernel::config::PluginsCfg {
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.trust.publishers = vec![busbar_kernel::config::PluginPublisher {
        name: name.into(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    }];
    cfg
}

fn gov_with_signer(admin_token: Option<String>) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            crate::root::real_store::records(),
            admin_token,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    )
}

async fn serve_admission(
    dir: PathBuf,
    cfg: busbar_kernel::config::PluginsCfg,
    hook_env: Option<busbar_kernel::hooks::HookEnv>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    serve_admission_with_inputs(dir, cfg, hook_env, None).await
}

async fn serve_admission_with_inputs(
    dir: PathBuf,
    cfg: busbar_kernel::config::PluginsCfg,
    hook_env: Option<busbar_kernel::hooks::HookEnv>,
    disk_paths: Option<(PathBuf, PathBuf)>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    busbar_core_admin::install();

    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    crate::dist_root_install::install();
    let module = busbar_kernel::preflight::root_rows()
        .stores
        .first()
        .expect("the distribution links its product store")
        .0;
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual store settings are JSON");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": [busbar_kernel::config::operator_provider()]},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]}
    }))
    .expect("the admission deployment parses");
    let mut resolved = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let admin_token_file = dir.with_extension("admin-token");
    std::fs::write(&admin_token_file, b"admintok").unwrap();
    resolved
        .auth
        .as_mut()
        .expect("configured authentication")
        .admin_auth[0]
        .token = Some(busbar_kernel::config::secret::SecretRef::file(
        admin_token_file.to_string_lossy(),
    ));
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotation, limits) = busbar_kernel::build_app_from_config(
        resolved,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the real product builds the admission deployment");
    std::fs::remove_file(admin_token_file).unwrap();
    limits.keep().unwrap();
    if let Some(rotate) = rotation {
        rotate();
    }
    app.governance = Some(gov_with_signer(Some("admintok".to_string())));
    app.plugins_dir = dir;
    app.plugins_cfg = cfg;
    app.plugin_admission = Some(&ADMISSION);
    if let Some(env) = hook_env {
        app.hook_env = env;
    }
    if let Some((config, providers)) = disk_paths {
        app.config_path = Some(config);
        app.providers_path = Some(providers);
    }
    let (router, _handle) = busbar_kernel::build_router_with_limits(
        Arc::new(app),
        256 * 1024 * 1024,
        0,
        busbar_kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

async fn serve_with_plugins_dir(
    dir: PathBuf,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    serve_admission(dir, unsigned_ok_posture(), None).await
}

async fn serve_with_plugins_dir_and_hook_env(
    dir: PathBuf,
    hook_env: busbar_kernel::hooks::HookEnv,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    serve_admission(dir, unsigned_ok_posture(), Some(hook_env)).await
}

fn scanned_hook_env(dir: &std::path::Path) -> busbar_kernel::hooks::HookEnv {
    let policy = crate::root::loader::sign::TrustPolicy {
        allow_unsigned: true,
        ..Default::default()
    };
    let registry = crate::root::loader::scan_and_validate(dir, &policy).unwrap();
    let rows: Arc<dyn busbar_contract::plugin_rows::PluginRows> = Arc::new(registry);
    let axis = crate::root::hooks::axis(&rows).expect("the registry's hook axis");
    busbar_kernel::hooks::HookEnv::with_axis(
        rows,
        axis,
        Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
    )
}

/// The upload body `POST /plugins` and `POST /plugins/inspect` take, by the admin contract's field
/// names (typed here so no field is spelled as a string).
#[derive(serde::Serialize)]
struct Upload<'a> {
    file: &'a str,
    tarball_b64: String,
}

impl<'a> Upload<'a> {
    fn of(file: &'a str, tarball: &[u8]) -> serde_json::Value {
        Self::raw(
            file,
            base64::engine::general_purpose::STANDARD.encode(tarball),
        )
    }

    fn raw(file: &'a str, tarball_b64: impl Into<String>) -> serde_json::Value {
        serde_json::to_value(Upload {
            file,
            tarball_b64: tarball_b64.into(),
        })
        .expect("an upload body serializes")
    }
}

/// The install view's fields, by the admin contract's names: what a successful `POST /plugins`
/// answers.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct InstallShape {
    file: String,
    interface_version: u64,
    name: String,
    note: String,
    publisher: String,
    trust: String,
    version: String,
}

fn file_of(row: &serde_json::Value) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Filed {
        file: Option<String>,
    }
    serde_json::from_value::<Filed>(row.clone()).ok()?.file
}

fn linked_store_key() -> &'static str {
    crate::dist_root_install::install();
    busbar_kernel::preflight::root_rows()
        .stores
        .first()
        .map(|s| s.0)
        .expect("the build links a store")
}

async fn install(
    addr: std::net::SocketAddr,
    file: &str,
    tarball: &[u8],
) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&Upload::of(file, tarball))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn inspect(addr: std::net::SocketAddr, tarball: &[u8]) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&Upload::of("candidate.tar.gz", tarball))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn store_catalog(addr: std::net::SocketAddr) -> Vec<serde_json::Value> {
    let list: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    list["items"].as_array().unwrap().clone()
}

fn message(body: &serde_json::Value) -> &str {
    body["error"]["message"].as_str().unwrap_or("")
}

#[tokio::test]
async fn inspect_previews_a_trusted_candidate_without_installing() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("inspect-ok");
    let mut m = test_manifest("acme-store-preview", "preview", "acme", "1.0.0");
    m.kind = "secret".into();
    m.abi_version = *crate::root::loader::supported_abi("secret")
        .iter()
        .max()
        .expect("secret abi");
    m.settings_schema = Some(
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"key": {"type": "string", "x-busbar-secret": true}},
        })
        .to_string(),
    );
    let tarball = unsigned_tarball(m, b"lib bytes");
    let (addr, handle) = serve_admission(dir.clone(), unsigned_ok_posture(), None).await;

    let (status, v) = inspect(addr, &tarball).await;
    assert_eq!(status, 200, "inspect succeeds: {v}");
    assert_eq!(v["name"], "acme-store-preview");
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["kind"], "secret");
    assert_eq!(v["trust"], "unverified");
    assert_eq!(v["source"], "manifest");
    assert_eq!(v["schema_error"], serde_json::Value::Null);
    assert!(
        v["schema"].is_object(),
        "schema round-trips as real JSON: {v}"
    );

    assert_eq!(v["restart_required_default"], true);

    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "inspect must not write anything to disk"
    );
    handle.abort();
}

#[tokio::test]
async fn inspect_reports_rejected_trust_rather_than_erroring() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("inspect-rejected");
    let tarball = unsigned_tarball(
        test_manifest("acme-store-untrusted", "untrusted", "acme", "1.0.0"),
        b"lib bytes",
    );

    let (addr, handle) = serve_admission(dir, strict_posture(), None).await;

    let (status, v) = inspect(addr, &tarball).await;
    assert_eq!(status, 200, "inspect still succeeds: {v}");
    assert_eq!(v["trust"], "rejected");
    assert_eq!(v["name"], "acme-store-untrusted");
    handle.abort();
}

#[tokio::test]
async fn inspect_rejects_invalid_tarball() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("inspect-garbage");
    let (addr, handle) = serve_admission(dir, unsigned_ok_posture(), None).await;
    let (status, b) = inspect(addr, b"not a tarball at all").await;
    assert_eq!(status, 400, "{b}");
    assert_eq!(b["error"]["code"], "invalid_request");
    handle.abort();
}

#[tokio::test]
async fn install_rejects_invalid_tarball() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("nontarball");
    let (addr, handle) = serve_admission(dir.clone(), unsigned_ok_posture(), None).await;
    let (status, b) = install(addr, "x.tar.gz", b"garbage, not a tarball").await;
    assert_eq!(
        status, 400,
        "non-tarball bytes must fail structural validation: {b}"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

#[tokio::test]
async fn install_rejects_signed_but_malformed_manifest() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("malformed");
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let mut m = test_manifest("acme-store-x", "x", "acme", "1.0.0");
    m.kind = "widget".into();
    let tarball = signed_tarball(&key, m, b"lib bytes");
    let (addr, handle) = serve_admission(dir.clone(), publisher_posture("acme", &key), None).await;
    let (status, b) = install(addr, "x.tar.gz", &tarball).await;
    assert!(
        status == 400 && message(&b).contains("kind"),
        "got {status} {b}"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

#[tokio::test]
async fn install_strict_posture_rejects_unsigned() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("strict");
    let lib = b"\x7fELF junk that would crash if ever dlopened";
    let tarball = unsigned_tarball(test_manifest("acme-store-x", "x", "acme", "1.0.0"), lib);
    let (addr, handle) = serve_admission(dir.clone(), strict_posture(), None).await;
    let (status, b) = install(addr, "x.tar.gz", &tarball).await;
    assert!(
        status == 409
            && (message(&b).contains("allow_third_party")
                || message(&b).contains("allow_unsigned")),
        "the rejection names the opt-in flag: {status} {b}"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

fn sealed_tarball_expiring(expires: u64) -> Vec<u8> {
    use crate::root::loader::release_trust::{
        wire, KeysDoc, ReleaseKey, Role, Target, TargetsDoc, PLUGINS_ROLE, PLUGIN_TARGET,
    };
    use crate::root::loader::sign::{canonical_manifest_bytes, sha256_hex, FIRST_PARTY_PUBLISHER};
    let (root, signer) = (
        SigningKey::from_bytes(&[0x31; 32]),
        SigningKey::from_bytes(&[0x32; 32]),
    );
    let envelope = |signed: serde_json::Value, by: &SigningKey| {
        use crate::root::loader::sign::Signer as _;
        let bytes = wire::canonical(&signed).unwrap();
        let id = wire::key_id(&ReleaseKey::Ed25519(by.verifying_key()));
        wire::write_envelope(&signed, &[(id, by.sign(&bytes).to_bytes().to_vec())]).unwrap()
    };
    let lib = b"\x7fELF sealed, never dlopened";
    let mut m = test_manifest(
        "busbar-store-sealed",
        "sealed",
        FIRST_PARTY_PUBLISHER,
        "1.6.0",
    );
    m.sha256 = sha256_hex(lib);
    let canonical = canonical_manifest_bytes(&m);
    let signer_key = ReleaseKey::Ed25519(signer.verifying_key());
    let signer_id = wire::key_id(&signer_key);
    let keys = wire::keys_signed(&KeysDoc {
        version: 1,
        expires,
        keys: [(signer_id.clone(), signer_key)].into(),
        roles: [(
            PLUGINS_ROLE.to_string(),
            Role {
                keyids: vec![signer_id],
                threshold: 1,
            },
        )]
        .into(),
        ..KeysDoc::default()
    });
    let targets = wire::targets_signed(&TargetsDoc {
        role: PLUGINS_ROLE.into(),
        version: 1,
        expires,
        targets: vec![Target {
            name: m.name.clone(),
            version: m.version.clone(),
            target: PLUGIN_TARGET.into(),
            sha256: sha256_hex(&canonical),
            length: canonical.len() as u64,
        }],
    });
    m.signature = wire::write_seal(&envelope(keys, &root), &envelope(targets, &signer)).unwrap();
    crate::root::loader::tarball::package(&m, "lib.so", lib).unwrap()
}

#[tokio::test]
async fn install_refuses_a_plugin_whose_release_seal_has_expired() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("expired-seal");
    let tarball = sealed_tarball_expiring(1_600_000_000);
    let (addr, handle) = serve_admission(dir.clone(), strict_posture(), None).await;
    let (status, b) = install(addr, "sealed.tar.gz", &tarball).await;
    assert!(
        status == 409
            && message(&b).contains("(keys-expired)")
            && message(&b).contains("expired at"),
        "an expired seal is refused, explained: {status} {b}"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

fn linked_store() -> (&'static str, &'static str, String, Vec<u8>) {
    crate::dist_root_install::install();
    let &(key, _, _, canonical) = busbar_kernel::preflight::root_rows()
        .stores
        .first()
        .expect("the build links a store");
    let linked: Vec<_> = busbar_kernel::preflight::linked_rows()
        .iter()
        .map(crate::root::boot::linked_row)
        .collect();
    let reg = crate::root::loader::PluginRegistry::empty()
        .link(linked)
        .expect("the linked rows register");
    let row = reg
        .resolve(canonical)
        .expect("the linked store answers its canonical name");
    let version = row.plugin_version().expect("the store states its version");
    (
        canonical,
        key,
        version,
        row.statement().expect("the store states itself"),
    )
}

fn restated(rendering: &[u8], version: &str) -> Vec<u8> {
    let head = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 16;
    let len = |at: usize| u32::from_le_bytes(rendering[at..at + 4].try_into().unwrap()) as usize;
    let at = head + 4 + len(head);
    let mut out = rendering[..at].to_vec();
    out.extend_from_slice(&(version.len() as u32).to_le_bytes());
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(&rendering[at + 4 + len(at)..]);
    out
}

fn unsigned_copy(name: &str, alias: &str, version: &str) -> Vec<u8> {
    let (_, _, _, statement) = linked_store();
    let lib = b"junk lib bytes of a linked plugin";
    let mut m = test_manifest(name, alias, "acme", "1.0.0");
    m.statement = Some(hex::encode(restated(&statement, version)));
    unsigned_tarball(m, lib)
}

#[tokio::test]
async fn install_of_a_linked_plugin_at_its_version_is_an_accepted_no_op() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("linked-same");
    let (addr, handle) = serve_admission(dir.clone(), unsigned_ok_posture(), None).await;
    let (canonical, key, version, _) = linked_store();
    let (status, view) = install(
        addr,
        "copy.tar.gz",
        &unsigned_copy(canonical, key, &version),
    )
    .await;
    assert_eq!(
        status, 201,
        "the same plugin at the same version is accepted: {view}"
    );
    assert_eq!(view["name"], canonical);
    let note = view["note"].as_str().unwrap_or("");
    assert!(note.contains("nothing was written"), "{note}");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

#[tokio::test]
async fn install_of_a_linked_plugin_at_another_version_is_refused() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("linked-other");
    let (addr, handle) = serve_admission(dir.clone(), unsigned_ok_posture(), None).await;
    let (canonical, key, version, _) = linked_store();
    let (status, b) = install(
        addr,
        "copy.tar.gz",
        &unsigned_copy(canonical, key, "99.0.0"),
    )
    .await;
    let want = format!(
        "plugin '{canonical}' arrives by both doors at two versions: linked v{version}, dropped \
         in v99.0.0 (copy.tar.gz) - one version per plugin: remove one"
    );
    assert!(status == 409 && message(&b) == want, "got {status} {b}");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

#[tokio::test]
async fn install_of_a_linked_plugin_stating_no_version_is_refused() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("linked-unstated");
    let (addr, handle) = serve_admission(dir.clone(), unsigned_ok_posture(), None).await;
    let (canonical, key, version, _) = linked_store();
    let lib = b"junk lib bytes of a linked plugin";
    let tarball = unsigned_tarball(test_manifest(canonical, key, "acme", &version), lib);
    let (status, b) = install(addr, "copy.tar.gz", &tarball).await;
    let want = format!(
        "plugin '{canonical}' states no version in its Statement: the one-version rule cannot \
         compare it"
    );
    assert!(status == 409 && message(&b) == want, "got {status} {b}");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

#[tokio::test]
async fn install_judges_trust_before_the_one_version_rule() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("linked-untrusted");
    let (addr, handle) = serve_admission(dir.clone(), strict_posture(), None).await;
    let (canonical, key, _, _) = linked_store();
    let (status, b) = install(
        addr,
        "copy.tar.gz",
        &unsigned_copy(canonical, key, "99.0.0"),
    )
    .await;
    assert!(
        status == 409
            && message(&b).starts_with("plugin rejected by the trust policy")
            && !message(&b).contains("one version per plugin"),
        "got {status} {b}"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

#[test]
fn rollback_resolves_a_trusted_below_floor_target_and_merges_pins() {
    let dir = tmp_plugins_dir("rollback-ok");
    let acme = SigningKey::from_bytes(&[11u8; 32]);

    let mut cfg = publisher_posture("acme", &acme);
    cfg.min_versions
        .insert("acme-store-x".to_string(), "2.0.0".to_string());

    let lib = b"prior artifact bytes";
    let tarball = signed_tarball(
        &acme,
        test_manifest("acme-store-x", "x", "acme", "1.4.0"),
        lib,
    );
    std::fs::write(dir.join("old.tar.gz"), &tarball).unwrap();

    let install_err = ADMISSION
        .admit_upload(&dir, "old.tar.gz", &tarball, &cfg)
        .unwrap_err();
    assert!(
        matches!(install_err, Refusal::Conflict(_)),
        "automatic install of a below-floor artifact is a conflict, got {install_err:?}"
    );

    let manifest = ADMISSION
        .rollback_target("old.tar.gz", &tarball, &cfg)
        .expect("rollback resolves the trusted below-floor target");
    assert_eq!(manifest.name, "acme-store-x");
    assert_eq!(manifest.version, "1.4.0");
}

#[test]
fn rollback_is_fail_closed_on_absent_or_untrusted_target() {
    let lib = b"unsigned prior artifact";
    let tarball = unsigned_tarball(test_manifest("acme-store-x", "x", "acme", "1.4.0"), lib);
    let err = ADMISSION
        .rollback_target("unsigned.tar.gz", &tarball, &strict_posture())
        .unwrap_err();
    assert!(
        matches!(err, Refusal::Conflict(_)),
        "an untrusted rollback target is refused (a rollback never launders trust), got {err:?}"
    );
}

#[tokio::test]
async fn catalog_does_not_dlopen_an_untrusted_plugin() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("untrusted-catalog");
    let lib = b"\x7fELF definitely not a loadable library";
    let tarball = unsigned_tarball(
        test_manifest("acme-store-evil", "evil", "acme", "1.0.0"),
        lib,
    );
    std::fs::write(dir.join("evil.tar.gz"), &tarball).unwrap();
    let (addr, handle) = serve_admission(dir, strict_posture(), None).await;

    let cat = store_catalog(addr).await;
    let row = cat
        .iter()
        .find(|p| p["target"] == "evil.tar.gz")
        .expect("the untrusted plugin is listed in the catalog");
    assert_eq!(
        row["trust"], "rejected",
        "an unsigned plugin under the strict default posture is reported rejected"
    );
    assert_eq!(row["valid"], false, "and it is not loadable");
    assert!(
        row["error"].as_str().is_some_and(|e| e.contains("SKIPPED")),
        "the exact skip reason is surfaced: {:?}",
        row["error"]
    );
    handle.abort();
}

#[tokio::test]
async fn install_signed_is_trusted() {
    crate::dist_root_install::install();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let lib = b"signed lib bytes";
    let tarball = signed_tarball(
        &key,
        test_manifest("acme-store-disk", "acmedisk", "acme", "2.1.0"),
        lib,
    );
    let dir = tmp_plugins_dir("signed");
    let (addr, handle) = serve_admission(dir.clone(), publisher_posture("acme", &key), None).await;

    let (status, view) = install(addr, "acme.tar.gz", &tarball).await;
    assert_eq!(
        status, 201,
        "a signed, allowlisted upload installs under the strict posture: {view}"
    );
    assert_eq!(view["trust"], "trusted");
    assert_eq!(view["publisher"], "acme");
    assert_eq!(view["version"], "2.1.0");
    assert_eq!(view["name"], "acme-store-disk");

    let cat = store_catalog(addr).await;
    let row = cat
        .iter()
        .find(|p| p["loader"] == "dynamic-library")
        .expect("dynamic plugin");
    assert_eq!(row["trust"], "trusted");
    assert_eq!(row["publisher"], "acme");
    assert_eq!(row["version"], "2.1.0");
    assert_eq!(row["name"], "acme-store-disk");
    handle.abort();
}

#[tokio::test]
async fn install_downgraded_version_is_rejected_by_floor() {
    crate::dist_root_install::install();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let lib = b"lib bytes";
    let mut cfg = publisher_posture("acme", &key);
    cfg.min_versions
        .insert("acme-store-disk".to_string(), "2.0.0".to_string());
    let dir = tmp_plugins_dir("downgrade");
    let (addr, handle) = serve_admission(dir.clone(), cfg, None).await;

    let old = signed_tarball(
        &key,
        test_manifest("acme-store-disk", "acmedisk", "acme", "1.9.0"),
        lib,
    );
    let (status, b) = install(addr, "old.tar.gz", &old).await;
    assert!(
        status == 409 && message(&b).contains("anti-downgrade"),
        "got {status} {b}"
    );
    assert!(!dir.join("old.tar.gz").exists());

    let cur = signed_tarball(
        &key,
        test_manifest("acme-store-disk", "acmedisk", "acme", "2.1.0"),
        lib,
    );
    let (status, view) = install(addr, "cur.tar.gz", &cur).await;
    assert_eq!(
        status, 201,
        "a signed release at/above the floor installs: {view}"
    );
    assert_eq!(view["trust"], "trusted");
    assert_eq!(view["version"], "2.1.0");
    handle.abort();
}

#[tokio::test]
async fn install_unknown_publisher_rejected() {
    crate::dist_root_install::install();
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let tarball = signed_tarball(
        &key,
        test_manifest("stranger-store-x", "strangerx", "stranger", "1.0.0"),
        b"lib",
    );
    let dir = tmp_plugins_dir("unknownpub");
    let (addr, handle) = serve_admission(dir.clone(), strict_posture(), None).await;
    let (status, b) = install(addr, "x.tar.gz", &tarball).await;
    assert_eq!(status, 409, "{b}");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    handle.abort();
}

#[tokio::test]
async fn install_alias_conflict_is_rejected() {
    crate::dist_root_install::install();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let dir = tmp_plugins_dir("conflict");
    let (addr, handle) = serve_admission(dir.clone(), publisher_posture("acme", &key), None).await;

    let first = signed_tarball(
        &key,
        test_manifest("acme-store-kv", "kv", "acme", "1.0.0"),
        b"lib a",
    );
    let (status, b) = install(addr, "first.tar.gz", &first).await;
    assert_eq!(status, 201, "first install: {b}");

    let clash = signed_tarball(
        &key,
        test_manifest("other-store-kv", "kv", "acme", "1.0.0"),
        b"lib b",
    );
    let (status, b) = install(addr, "clash.tar.gz", &clash).await;
    assert!(
        status == 409
            && message(&b).contains("acme-store-kv")
            && message(&b).contains("other-store-kv"),
        "names both plugins: {status} {b}"
    );
    assert!(!dir.join("clash.tar.gz").exists());

    let upgrade = signed_tarball(
        &key,
        test_manifest("acme-store-kv", "kv", "acme", "1.1.0"),
        b"lib a v2",
    );
    let (status, b) = install(addr, "first.tar.gz", &upgrade).await;
    assert_eq!(status, 201, "same-name overwrite is a legal upgrade: {b}");
    handle.abort();
}

#[test]
fn the_root_admission_classes_an_upload_and_writes_nothing() {
    let dir = tmp_plugins_dir("admission-classes");
    let unsigned = unsigned_tarball(test_manifest("acme-store-u", "u", "acme", "1.0.0"), b"u");
    let admitted = ADMISSION
        .admit_upload(&dir, "u.tar.gz", &unsigned, &unsigned_ok_posture())
        .expect("an unsigned upload is admitted under allow_unsigned");
    assert_eq!(admitted.judged, Judged::Allowed);
    assert!(!admitted.linked_serves);
    let key = SigningKey::from_bytes(&[13u8; 32]);
    let signed = signed_tarball(
        &key,
        test_manifest("acme-store-s", "s", "acme", "1.0.0"),
        b"s",
    );
    let admitted = ADMISSION
        .admit_upload(&dir, "s.tar.gz", &signed, &publisher_posture("acme", &key))
        .expect("an allowlisted signature is admitted");
    assert_eq!(
        admitted.judged,
        Judged::Trusted {
            publisher: "acme".into()
        }
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

#[tokio::test]
async fn test_admin_v1_plugin_install_of_a_linked_copy_is_a_201_no_op() {
    crate::dist_root_install::install();
    let (canonical, key, version, _) = linked_store();
    let tarball = unsigned_copy(canonical, key, &version);
    let file = "linked-copy.tar.gz";
    let dir = tmp_plugins_dir("linked-copy");
    let (addr, _handle) = serve_with_plugins_dir(dir.clone()).await;

    let (status, v) = install(addr, file, &tarball).await;
    assert_eq!(status, 201, "the install view, as every success");
    let mut fields: Vec<&str> = v
        .as_object()
        .unwrap_or_else(|| panic!("the install view is an object: {v}"))
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    let shape = serde_json::to_value(InstallShape::default()).expect("the shape serializes");
    let mut want: Vec<&str> = shape
        .as_object()
        .expect("the shape is an object")
        .keys()
        .map(String::as_str)
        .collect();
    want.sort_unstable();
    assert_eq!(fields, want, "the install view's shape: {v}");
    let typed: InstallShape = serde_json::from_value(v.clone())
        .unwrap_or_else(|e| panic!("the install view's field types: {e}: {v}"));
    assert_eq!(
        (typed.file.as_str(), typed.name.as_str()),
        (file, canonical)
    );
    assert_eq!(
        v["note"],
        "this build links the plugin at this version and the linked build serves it: nothing \
         was written"
    );
    assert!(!dir.join(file).exists(), "nothing is written");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_plugin_install_list_reload_remove() {
    crate::dist_root_install::install();
    let tarball = admin_test_tarball("acme-store-junk", "junkstore");
    let file = "acme-store-junk.tar.gz";
    let dir = tmp_plugins_dir("http");
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let body = Upload::of(file, &tarball);
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "install returns 201 Created");
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(file_of(&v).as_deref(), Some(file));
    assert_eq!(v["trust"], "unverified");
    assert_eq!(
        v["name"], "acme-store-junk",
        "identity from the signed manifest"
    );
    assert!(dir.join(file).exists(), "tarball published to disk");

    let unauth = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items[0]["name"], linked_store_key());
    let dyn_row = items
        .iter()
        .find(|p| p["loader"] == "dynamic-library")
        .expect("dynamic-library row present");
    assert_eq!(dyn_row["valid"], true);
    assert_eq!(dyn_row["target"], file);
    assert_eq!(dyn_row["name"], "acme-store-junk");

    let reload: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reload["plugins"].as_array().unwrap().len(), 1);

    let del = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204);
    assert!(!dir.join(file).exists(), "tarball removed from disk");

    let del2 = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del2.status().as_u16(), 404);
    let b: serde_json::Value = del2.json().await.unwrap();
    assert_eq!(b["error"]["code"], "not_found");

    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"plugin.install"),
        "install audited: {actions:?}"
    );
    assert!(
        actions.contains(&"plugin.remove"),
        "remove audited: {actions:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugins_type_secret_lists_secret_kind_only() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("secret");
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let (status, _) = install(
        addr,
        "acme-secret-vault.tar.gz",
        &admin_test_tarball_kind("acme-secret-vault", "acmevault", "secret"),
    )
    .await;
    assert_eq!(status, 201, "install must succeed");
    let (status, _) = install(
        addr,
        "acme-store-junk.tar.gz",
        &admin_test_tarball_kind("acme-store-junk", "junkstore", "store"),
    )
    .await;
    assert_eq!(status, 201, "install must succeed");

    let secret_list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=secret"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let secret_names: Vec<&str> = secret_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        secret_names,
        vec!["acme-secret-vault"],
        "type=secret lists ONLY the secret-kind plugin: {secret_list}"
    );
    for row in secret_list["items"].as_array().unwrap() {
        assert_eq!(row["type"], "secret");
    }

    let store_list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let store_names: Vec<&str> = store_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(
        store_names.contains(&linked_store_key()) && store_names.contains(&"acme-store-junk"),
        "type=store still lists the compiled-in default + the store plugin: {store_list}"
    );
    assert!(
        !store_names.contains(&"acme-secret-vault"),
        "type=store must NOT leak the secret-kind plugin: {store_list}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugins_list_row_carries_schema_url() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("schemaurl");

    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"url": {"type": "string"}},
    });
    let lib = b"junk lib bytes for acme-store-schemaurl".to_vec();
    let mut m = test_manifest("acme-store-schemaurl", "schemaurl", "acme", "1.0.0");
    m.settings_schema = Some(schema.to_string());
    let tarball = unsigned_tarball(m, &lib);

    std::fs::write(dir.join("acme-store-schemaurl.tar.gz"), &tarball).unwrap();
    let hook_env = scanned_hook_env(&dir);
    let (addr, handle) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env).await;
    let client = reqwest::Client::new();

    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "acme-store-schemaurl")
        .expect("the schema-carrying row is present");
    let schema_url = row["schema_url"].as_str().expect("schema_url is non-null");
    assert_eq!(
        schema_url, "/api/v1/admin/plugins/acme-store-schemaurl/schema",
        "always the admin-prefixed relative path — never absolute, never a catalog URL"
    );
    assert_eq!(row["schema_error"], serde_json::Value::Null);

    let followed: serde_json::Value = client
        .get(format!("http://{addr}{schema_url}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(followed["schema"], schema);

    let memory_row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == linked_store_key())
        .expect("compiled-in memory row present");
    assert_eq!(memory_row["schema_url"], serde_json::Value::Null);

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugins_list_row_carries_file_and_has_schema() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("file-hasschema");

    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"url": {"type": "string"}},
    });
    let lib_with = b"junk lib bytes for acme-store-filecheck-with".to_vec();
    let mut m_with = test_manifest(
        "acme-store-filecheck-with",
        "filecheckwith",
        "acme",
        "1.0.0",
    );
    m_with.settings_schema = Some(schema.to_string());
    let tarball_with = unsigned_tarball(m_with, &lib_with);

    std::fs::write(
        dir.join("acme-store-filecheck-with-1.0.0.tar.gz"),
        &tarball_with,
    )
    .unwrap();

    let lib_without = b"junk lib bytes for acme-store-filecheck-without".to_vec();
    let tarball_without = unsigned_tarball(
        test_manifest(
            "acme-store-filecheck-without",
            "filecheckwithout",
            "acme",
            "1.0.0",
        ),
        &lib_without,
    );
    std::fs::write(
        dir.join("acme-store-filecheck-without-1.0.0.tar.gz"),
        &tarball_without,
    )
    .unwrap();

    let hook_env = scanned_hook_env(&dir);
    let (addr, handle) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env).await;
    let client = reqwest::Client::new();

    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();

    let with_row = items
        .iter()
        .find(|p| p["name"] == "acme-store-filecheck-with")
        .expect("the schema-carrying row is present");
    assert_eq!(
        file_of(with_row).as_deref(),
        Some("acme-store-filecheck-with-1.0.0.tar.gz"),
        "`file` is the on-disk artifact filename, not the manifest name"
    );
    assert_eq!(with_row["has_schema"], true);
    assert!(
        with_row["schema_url"].is_string(),
        "sanity: has_schema tracks schema_url"
    );

    let file = file_of(with_row).expect("the row names its file");
    let schema_resp: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/plugins/{}/schema",
            with_row["name"].as_str().unwrap()
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(schema_resp["schema"], schema);
    let delete_status = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        delete_status, 204,
        "`file` from the list row is a valid DELETE key"
    );

    let without_row = items
        .iter()
        .find(|p| p["name"] == "acme-store-filecheck-without")
        .expect("the schema-less row is present");
    assert_eq!(
        file_of(without_row).as_deref(),
        Some("acme-store-filecheck-without-1.0.0.tar.gz"),
        "`file` is populated even when the manifest has no schema"
    );
    assert_eq!(without_row["has_schema"], false);
    assert_eq!(without_row["schema_url"], serde_json::Value::Null);

    let memory_row = items
        .iter()
        .find(|p| p["name"] == linked_store_key())
        .expect("compiled-in memory row present");
    assert_eq!(
        file_of(memory_row),
        None,
        "no backing artifact for a compiled-in row"
    );
    assert_eq!(memory_row["has_schema"], false);

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugins_inspect_previews_without_installing() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("inspect");
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let tarball = admin_test_tarball("acme-store-candidate", "candidate");
    let body = Upload::of("candidate.tar.gz", &tarball);
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["name"], "acme-store-candidate");
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["kind"], "store");
    assert_eq!(v["source"], "manifest");
    assert_eq!(v["trust"], "unverified");

    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "inspect must never write to plugins.dir"
    );
    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "acme-store-candidate"),
        "an inspected candidate must not appear in the catalog: {list}"
    );

    let bad = Upload::raw("x.tar.gz", "not-base64!!");
    let bad_resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_resp.status().as_u16(), 400);
    let bad_body: serde_json::Value = bad_resp.json().await.unwrap();
    assert_eq!(bad_body["error"]["code"], "invalid_request");

    let malformed_resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed_resp.status().as_u16(), 400);

    let unauth = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugin_schema_round_trips_from_manifest() {
    crate::dist_root_install::install();
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "url": {"type": "string", "x-busbar-secret": true},
        },
        "required": ["url"],
    });
    let lib = b"junk library bytes for acme-store-withschema (never dlopened)".to_vec();
    let mut m = test_manifest("acme-store-withschema", "withschema", "acme", "1.0.0");
    m.settings_schema = Some(schema.to_string());
    let tarball = unsigned_tarball(m, &lib);
    let file = "acme-store-withschema.tar.gz";
    let dir = tmp_plugins_dir("schema");

    std::fs::write(dir.join(file), &tarball).unwrap();
    let hook_env = scanned_hook_env(&dir);
    let (addr, handle) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env).await;
    let client = reqwest::Client::new();

    let got_resp = client
        .get(format!(
            "http://{addr}/api/v1/admin/plugins/acme-store-withschema/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let got_status = got_resp.status();
    let got: serde_json::Value = got_resp.json().await.unwrap();
    assert_eq!(got_status.as_u16(), 200, "schema get body: {got}");
    assert_eq!(got["name"], "acme-store-withschema");
    assert_eq!(got["schema"], schema);
    assert_eq!(got["schema_error"], serde_json::Value::Null);
    assert_eq!(got["source"], "manifest");

    assert_eq!(got["trust"], "unverified");

    handle.abort();

    let no_schema_tarball = admin_test_tarball("acme-store-junk", "junkstore");
    std::fs::write(dir.join("acme-store-junk.tar.gz"), &no_schema_tarball).unwrap();
    let hook_env2 = scanned_hook_env(&dir);
    let (addr2, handle2) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env2).await;
    let got2: serde_json::Value = client
        .get(format!(
            "http://{addr2}/api/v1/admin/plugins/acme-store-junk/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got2["schema"], serde_json::Value::Null);

    let got1_again: serde_json::Value = client
        .get(format!(
            "http://{addr2}/api/v1/admin/plugins/acme-store-withschema/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got1_again["schema"], schema);

    let _ = std::fs::remove_dir_all(&dir);
    handle2.abort();

    let bad_lib = b"junk library bytes for acme-store-badschema (never dlopened)".to_vec();
    let mut bad_m = test_manifest("acme-store-badschema", "badschema", "acme", "1.0.0");
    bad_m.settings_schema = Some("{ not valid json".into());
    let bad_tarball = unsigned_tarball(bad_m, &bad_lib);
    let bad_dir = tmp_plugins_dir("badschema");
    std::fs::write(bad_dir.join("acme-store-badschema.tar.gz"), &bad_tarball).unwrap();
    let bad_hook_env = scanned_hook_env(&bad_dir);
    let (bad_addr, bad_handle) =
        serve_with_plugins_dir_and_hook_env(bad_dir.clone(), bad_hook_env).await;
    let got_bad: serde_json::Value = client
        .get(format!(
            "http://{bad_addr}/api/v1/admin/plugins/acme-store-badschema/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got_bad["schema"], serde_json::Value::Null);
    assert!(
        got_bad["schema_error"].as_str().is_some(),
        "corrupt settings_schema reports schema_error, not a bare null: {got_bad}"
    );

    let missing = client
        .get(format!(
            "http://{bad_addr}/api/v1/admin/plugins/nope/schema"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    let _ = std::fs::remove_dir_all(&bad_dir);
    bad_handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugin_install_same_name_different_file_is_409() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("h2");
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;

    let v1 = admin_test_tarball_versioned("busbar-store-x", "storex", "1.0.0");
    let (s1, _) = install(addr, "busbar-store-x-1.0.0.tar.gz", &v1).await;
    assert_eq!(s1, 201, "first install succeeds");

    let v2 = admin_test_tarball_versioned("busbar-store-x", "storex", "1.1.0");
    let (s2, b) = install(addr, "busbar-store-x-1.1.0.tar.gz", &v2).await;
    assert_eq!(
        s2, 409,
        "same-name under a different filename must conflict, not brick the next boot"
    );
    assert_eq!(b["error"]["code"], "conflict");
    assert!(
        !dir.join("busbar-store-x-1.1.0.tar.gz").exists(),
        "the conflicting second file must NOT be published"
    );

    let tars: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.gz"))
        .collect();
    assert_eq!(tars.len(), 1, "only the original v1.0.0 file remains");

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugin_install_corrupt_existing_tarball_blocks_publish() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("m7");

    std::fs::write(
        dir.join("busbar-store-corrupt.tar.gz"),
        b"not a real tarball",
    )
    .unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;

    let good = admin_test_tarball("busbar-store-good", "goodstore");
    let (status, _) = install(addr, "busbar-store-good.tar.gz", &good).await;
    assert_ne!(
        status, 201,
        "an unvalidatable installed set must NOT let a new install publish (fail-open closed)"
    );
    assert_eq!(status, 409, "surfaced as a conflict");
    assert!(
        !dir.join("busbar-store-good.tar.gz").exists(),
        "nothing published while the installed set is unvalidatable"
    );

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_plugin_install_rejections() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("rej");
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    let bad = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&Upload::raw("x.tar.gz", "!!!not base64!!!"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    let b: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(b["error"]["code"], "invalid_request");

    let (status, _) = install(addr, "nope.tar.gz", b"not a tarball").await;
    assert_eq!(status, 400);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "nothing published"
    );

    {
        let strict_dir = tmp_plugins_dir("strict");
        let (strict_addr, strict_handle) =
            serve_admission(strict_dir.clone(), strict_posture(), None).await;
        let tarball = admin_test_tarball("acme-store-x", "acmex");
        let (status, b) = install(strict_addr, "x.tar.gz", &tarball).await;
        assert_eq!(
            status, 409,
            "the strict default posture rejects an unsigned upload over the API"
        );
        assert_eq!(b["error"]["code"], "conflict");
        assert_eq!(
            std::fs::read_dir(&strict_dir).unwrap().count(),
            0,
            "nothing published on a trust rejection"
        );
        let _ = std::fs::remove_dir_all(&strict_dir);
        strict_handle.abort();
    }

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

#[test]
fn an_inspect_of_no_tarball_is_refused_as_an_invalid_plugin_tarball() {
    let Err(Refusal::Validation(why)) =
        ADMISSION.inspect(b"not a tarball at all", &strict_posture())
    else {
        panic!("a body that is no tarball is a validation refusal");
    };
    assert!(why.starts_with("invalid plugin tarball"), "{why}");
}

#[tokio::test]
async fn a_bootstrap_archive_upload_and_rollback_refuse_a_changed_base_pin_before_publication() {
    crate::dist_root_install::install();
    let dir = tmp_plugins_dir("bootstrap-archive-mutation");
    let key = SigningKey::from_bytes(&[0x38; 32]);
    let first = signed_tarball(
        &key,
        test_manifest("acme-store-anchor", "anchor", "acme", "1.0.0"),
        b"first native image",
    );
    let changed = signed_tarball(
        &key,
        test_manifest("acme-store-anchor", "anchor", "acme", "1.1.0"),
        b"changed native image",
    );
    let file = "anchor.tar.gz";
    std::fs::write(dir.join(file), &first).unwrap();
    let config = dir.with_extension("config.yaml");
    let providers = dir.with_extension("providers.yaml");
    std::fs::write(&providers, "{}\n").unwrap();
    let write_base = |hash: &str| {
        let document = serde_json::json!({"providers":{},"models":{},
            "store":{"module":"anchor","settings":{}},
            "plugins":{"enabled":true,"dir":dir,
                "trust":{"publishers":[{"name":"acme","public_key":hex::encode(key.verifying_key().to_bytes())}]},
                "fetch":[{"url":"https://plugins.invalid/anchor.tar.gz","sha256":hash}]}});
        std::fs::write(&config, serde_yaml::to_string(&document).unwrap()).unwrap();
    };
    write_base(&crate::root::loader::sign::sha256_hex(&first));
    let mut posture = publisher_posture("acme", &key);
    posture.enabled = true;
    posture.dir = dir.display().to_string();
    let (addr, handle) = serve_admission_with_inputs(
        dir.clone(),
        posture,
        None,
        Some((config.clone(), providers.clone())),
    )
    .await;
    let (status, body) = install(addr, file, &changed).await;
    assert_eq!(status, 409, "{body}");
    assert!(message(&body).contains("exact archive SHA-256"), "{body}");
    assert_eq!(std::fs::read(dir.join(file)).unwrap(), first);

    write_base(&crate::root::loader::sign::sha256_hex(&changed));
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":file}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(status.as_u16(), 409, "{body}");
    assert!(message(&body).contains("exact archive SHA-256"), "{body}");
    assert_eq!(std::fs::read(dir.join(file)).unwrap(), first);
    handle.abort();
    std::fs::remove_file(config).unwrap();
    std::fs::remove_file(providers).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
