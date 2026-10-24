// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR SURFACE'S PLUGIN VERBS UNDER THE ROOT'S REAL ADMISSION (`BUSBAR-1.6.0.md` THE
//! DESIGN l.322: the kernel never names the loader, and neither does the admin crate). The admin
//! crate judges an uploaded, inspected, listed or rolled-back tarball only through the kernel's
//! `PluginAdmission` seam; what a REAL tarball is judged — its structure, its signature, the trust
//! posture, the anti-downgrade floors, the conflict with the installed set and the one-version rule
//! against the linked rows — is the root's admission ([`crate::root::admission::ADMISSION`]) over
//! the loader. These tests pack real tarballs and drive the admin surface over the wire on a
//! snapshot carrying that admission, so they prove the admission the shipped binary installs. The
//! admin surface's own mechanics (the catalog cache, its gate, the filename gate, the schema
//! bounds) stay in the admin crate over a test-local admission.

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use busbar_kernel::admission::{Judged, PluginAdmission as _, Refusal};
use busbar_kernel::governance::{GovState, MemoryStore};

use crate::root::admission::ADMISSION;
use crate::root::loader::sign::{sign, Manifest, SigningKey};

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

/// A unique temp plugins directory for one test (isolated so parallel tests never collide).
fn tmp_plugins_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // pid + counter alone is NOT unique over time: these dirs are never cleaned up and the OS
    // reuses pids, so a once-per-process clock token makes the name unique across pid reuse.
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

/// A well-formed manifest for tests (sha256/signature completed by `sign`).
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

/// `lib` packed UNSIGNED under `m`, the manifest bound to the library's hash.
fn unsigned_tarball(mut m: Manifest, lib: &[u8]) -> Vec<u8> {
    m.sha256 = crate::root::loader::sign::sha256_hex(lib);
    crate::root::loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// Package a signed plugin tarball in memory.
fn signed_tarball(key: &SigningKey, m: Manifest, lib: &[u8]) -> Vec<u8> {
    let m = sign(key, m, lib);
    crate::root::loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// Build an UNSIGNED (structurally valid) plugin tarball in memory for the HTTP lifecycle tests.
fn admin_test_tarball(name: &str, alias: &str) -> Vec<u8> {
    admin_test_tarball_versioned(name, alias, "1.0.0")
}

/// As `admin_test_tarball`, with an explicit version so a test can build two SAME-NAME tarballs that
/// differ only in version (and thus filename) - the same-name-different-file case.
fn admin_test_tarball_versioned(name: &str, alias: &str, version: &str) -> Vec<u8> {
    let lib = format!("junk library bytes for {name} {version} (never dlopened)").into_bytes();
    unsigned_tarball(test_manifest(name, alias, "acme", version), &lib)
}

/// As `admin_test_tarball_versioned`, but for an arbitrary plugin `kind` (the `type=secret`
/// support / richer `auth` rows need a non-`store` fixture to test against).
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

/// The STRICT default posture: no publishers, no opt-ins.
fn strict_posture() -> busbar_kernel::config::PluginsCfg {
    busbar_kernel::config::PluginsCfg::default()
}

/// A permissive posture (allow_unsigned): an unsigned upload installs "unverified".
fn unsigned_ok_posture() -> busbar_kernel::config::PluginsCfg {
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.trust.allow_unsigned = true;
    cfg
}

/// A posture that allowlists one third-party publisher key.
fn publisher_posture(name: &str, key: &SigningKey) -> busbar_kernel::config::PluginsCfg {
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.trust.publishers = vec![busbar_kernel::config::PluginPublisher {
        name: name.into(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    }];
    cfg
}

/// Governance holding the operator token `admin_token`, with a token signer.
fn gov_with_signer(admin_token: Option<String>) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            Arc::new(MemoryStore::new()),
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

/// Serve the admin router over an App whose plugin surface is `dir` under `cfg`, judged by THE
/// ROOT'S ADMISSION, with `hook_env` when given, and the known admin token `admintok`.
async fn serve_admission(
    dir: PathBuf,
    cfg: busbar_kernel::config::PluginsCfg,
    hook_env: Option<busbar_kernel::hooks::HookEnv>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    busbar_core_admin::install();
    // The operator credential's row on the auth axis, as boot links it (`register_planes`): the
    // admin chain authenticates `x-admin-token` through the root's REAL operator door (a test build
    // of the kernel answers no operator row of its own; the first install stands).
    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    busbar_kernel::test_support::install_root_auth_axis(crate::root::dispatch::auth_axis);
    let mut app = busbar_kernel::test_support::TestApp::new()
        .governance(gov_with_signer(Some("admintok".to_string())))
        .admin_chain(vec![busbar_kernel::config::operator_provider().to_string()])
        .plugins_dir(dir)
        .plugins_cfg(cfg)
        .plugin_admission(&ADMISSION);
    if let Some(env) = hook_env {
        app = app.hook_env(env);
    }
    let (router, _handle) = busbar_kernel::build_router_with_limits(
        app.build(),
        256 * 1024 * 1024,
        0,
        busbar_kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// Serve a router whose App points its plugin surface at `dir` (allow_unsigned posture, no
/// publishers), with a known admin token — for the install/list/remove/reload plugin endpoints.
async fn serve_with_plugins_dir(
    dir: PathBuf,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    // The lifecycle test installs an UNSIGNED plugin tarball, so opt in to unsigned plugins (the
    // trust DEFAULT rejects unsigned artifacts). The trust-default behavior itself is covered by
    // the dedicated trust tests; this test is about the install/list/reload/remove lifecycle.
    serve_admission(dir, unsigned_ok_posture(), None).await
}

/// As `serve_with_plugins_dir`, but with a caller-supplied `hook_env` — for tests that need the
/// live `hook_env.registry` (e.g. `GET /plugins/{name}/schema`) populated from the dir's actual
/// contents, since the plain `TestApp` builder defaults it to an empty registry regardless of
/// `plugins_dir` (that field only feeds the filesystem-scanning install/list/remove/reload paths).
async fn serve_with_plugins_dir_and_hook_env(
    dir: PathBuf,
    hook_env: busbar_kernel::hooks::HookEnv,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    serve_admission(dir, unsigned_ok_posture(), Some(hook_env)).await
}

/// The hook environment over what the boot's scan admits from `dir` under an `allow_unsigned`
/// policy: the REAL registry (the same `scan_and_validate` production boot uses) and the root's
/// hook axis over it.
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
    /// `tarball` under `file`, base64-encoded as the contract carries it.
    fn of(file: &'a str, tarball: &[u8]) -> serde_json::Value {
        Self::raw(
            file,
            base64::engine::general_purpose::STANDARD.encode(tarball),
        )
    }

    /// `file` with `tarball_b64` as given (a malformed body's).
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

/// A catalog or install row's artifact file (`None` for a compiled-in row), read by its field.
fn file_of(row: &serde_json::Value) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Filed {
        file: Option<String>,
    }
    serde_json::from_value::<Filed>(row.clone()).ok()?.file
}

/// The key of the first store this build links: the store catalog's compiled-in head, read off the
/// installed root rows (the root's table, or a test build's stand-in), never spelled here.
fn linked_store_key() -> &'static str {
    busbar_kernel::preflight::root_rows()
        .stores
        .first()
        .map(|s| s.0)
        .expect("the build links a store")
}

/// `POST /api/v1/admin/plugins` of `tarball` as `file`: (status, body).
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

/// `POST /api/v1/admin/plugins/inspect` of `tarball`: (status, body).
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

/// `GET /api/v1/admin/plugins?type=store`'s rows.
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

/// A refusal body's message.
fn message(body: &serde_json::Value) -> &str {
    body["error"]["message"].as_str().unwrap_or("")
}

// ── POST /plugins/inspect ──────────────────────────────────────────────────────────────────

/// A trusted, unsigned-under-`allow_unsigned` candidate previews cleanly: the SAME response
/// shape `GET /plugins/{name}/schema` carries, PLUS `name`/`version`/`kind` — and NOTHING is
/// written to disk (an inspect is stateless: no install, no conflict check).
#[tokio::test]
async fn inspect_previews_a_trusted_candidate_without_installing() {
    busbar_kernel::snapshot::init();
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
    // `secret` kind defaults to restart-required.
    assert_eq!(v["restart_required_default"], true);

    // NOTHING was written — inspect never installs, never touches `plugins.dir`.
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "inspect must not write anything to disk"
    );
    handle.abort();
}

/// An UNTRUSTED (unsigned, strict posture) candidate is REPORTED as `trust: "rejected"`, not
/// refused with an error — the whole point of inspect is previewing what a not-yet-trusted
/// plugin would need without ever installing or executing it.
#[tokio::test]
async fn inspect_reports_rejected_trust_rather_than_erroring() {
    busbar_kernel::snapshot::init();
    let dir = tmp_plugins_dir("inspect-rejected");
    let tarball = unsigned_tarball(
        test_manifest("acme-store-untrusted", "untrusted", "acme", "1.0.0"),
        b"lib bytes",
    );
    // STRICT posture: no publishers allowlisted, no allow_unsigned opt-in.
    let (addr, handle) = serve_admission(dir, strict_posture(), None).await;

    let (status, v) = inspect(addr, &tarball).await;
    assert_eq!(status, 200, "inspect still succeeds: {v}");
    assert_eq!(v["trust"], "rejected");
    assert_eq!(v["name"], "acme-store-untrusted");
    handle.abort();
}

/// Structurally invalid bytes (not a tarball at all) are a `Validation` error, same as install's
/// structural gate — inspect shares the exact same in-memory unpack path.
#[tokio::test]
async fn inspect_rejects_invalid_tarball() {
    busbar_kernel::snapshot::init();
    let dir = tmp_plugins_dir("inspect-garbage");
    let (addr, handle) = serve_admission(dir, unsigned_ok_posture(), None).await;
    let (status, b) = inspect(addr, b"not a tarball at all").await;
    assert_eq!(status, 400, "{b}");
    assert_eq!(b["error"]["code"], "invalid_request");
    handle.abort();
}

// ── POST /plugins ──────────────────────────────────────────────────────────────────────────

/// Install rejects an upload that is not a valid plugin tarball, and leaves NOTHING behind.
#[tokio::test]
async fn install_rejects_invalid_tarball() {
    busbar_kernel::snapshot::init();
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

/// A VALIDLY-SIGNED but structurally malformed manifest (bad `kind`) is a 400 — structural
/// validation is independent of trust.
#[tokio::test]
async fn install_rejects_signed_but_malformed_manifest() {
    busbar_kernel::snapshot::init();
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

/// Under the STRICT default posture, an UNSIGNED upload is rejected as a conflict naming the
/// opt-in flag, and nothing is written. The endpoint is MANIFEST-ONLY: the (junk) library
/// bytes are never executed, so pushing over the API cannot bypass the trust model.
#[tokio::test]
async fn install_strict_posture_rejects_unsigned() {
    busbar_kernel::snapshot::init();
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

/// The build's linked store, as `(canonical name, key, the version it states, its Statement)`: what
/// a copy of it dropped in must carry to be the same plugin at the same version.
fn linked_store() -> (&'static str, &'static str, String, Vec<u8>) {
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

/// `rendering` with its Statement's version restated as `version` (the rendering's head is the
/// magic, four `u32`s, then the name and the version, each a `u32` length and its bytes).
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

/// A copy of the linked store, `name` aliased `alias`, unsigned over junk library bytes, stating
/// the store's Statement restated at `version`.
fn unsigned_copy(name: &str, alias: &str, version: &str) -> Vec<u8> {
    let (_, _, _, statement) = linked_store();
    let lib = b"junk lib bytes of a linked plugin";
    let mut m = test_manifest(name, alias, "acme", "1.0.0");
    m.statement = Some(hex::encode(restated(&statement, version)));
    unsigned_tarball(m, lib)
}

/// THE ONE-VERSION RULE AT THE ADMIN INSTALL (ARCHITECT C'), SAME VERSION: uploading a copy of a
/// plugin this build LINKS, at the version the linked plugin states, is an accepted no-op — the
/// linked build already serves it, and nothing is written. RED before: it was published, and the
/// next boot met the same plugin by both doors.
#[tokio::test]
async fn install_of_a_linked_plugin_at_its_version_is_an_accepted_no_op() {
    busbar_kernel::snapshot::init();
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

/// THE ONE-VERSION RULE AT THE ADMIN INSTALL, ANOTHER VERSION: refused before anything is written,
/// in the words boot refuses the pair with. RED before: published, bricking the next boot.
#[tokio::test]
async fn install_of_a_linked_plugin_at_another_version_is_refused() {
    busbar_kernel::snapshot::init();
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

/// THE ONE-VERSION RULE COMPARES STATEMENT VERSIONS ONLY at the admin install: a copy of a linked
/// plugin stating no Statement is refused, naming it, whatever its manifest `version` says; nothing
/// is written.
#[tokio::test]
async fn install_of_a_linked_plugin_stating_no_version_is_refused() {
    busbar_kernel::snapshot::init();
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

/// TRUST BEFORE IDENTITY at the admin install: under the strict posture an UNSIGNED copy of a
/// linked plugin at another version is refused by the trust policy, never compared.
#[tokio::test]
async fn install_judges_trust_before_the_one_version_rule() {
    busbar_kernel::snapshot::init();
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

/// ROLLBACK RESOLUTION (1.5.0), the EXPLICIT-downgrade core: a TRUSTED third-party artifact whose
/// version is BELOW its configured base floor — which the AUTOMATIC path (`install`) rejects as an
/// anti-downgrade — is ACCEPTED as a rollback target, because the rollback lowers the floor to the
/// target's own version. The admin surface's own half (the target read off the plugins directory,
/// the not-found answer and the merged pin map) is the admin crate's to prove
/// (`rollback_reads_the_target_and_merges_pins`).
#[test]
fn rollback_resolves_a_trusted_below_floor_target_and_merges_pins() {
    let dir = tmp_plugins_dir("rollback-ok");
    let acme = SigningKey::from_bytes(&[11u8; 32]);
    // Base posture: allowlist acme AND floor this plugin at 2.0.0.
    let mut cfg = publisher_posture("acme", &acme);
    cfg.min_versions
        .insert("acme-store-x".to_string(), "2.0.0".to_string());

    // The PRIOR artifact at 1.4.0 (the rollback target) sits in the plugins dir.
    let lib = b"prior artifact bytes";
    let tarball = signed_tarball(
        &acme,
        test_manifest("acme-store-x", "x", "acme", "1.4.0"),
        lib,
    );
    std::fs::write(dir.join("old.tar.gz"), &tarball).unwrap();

    // The automatic install path REJECTS the below-floor artifact (anti-downgrade).
    let install_err = ADMISSION
        .admit_upload(&dir, "old.tar.gz", &tarball, &cfg)
        .unwrap_err();
    assert!(
        matches!(install_err, Refusal::Conflict(_)),
        "automatic install of a below-floor artifact is a conflict, got {install_err:?}"
    );

    // The EXPLICIT rollback resolves it, lowering the floor to 1.4.0.
    let manifest = ADMISSION
        .rollback_target("old.tar.gz", &tarball, &cfg)
        .expect("rollback resolves the trusted below-floor target");
    assert_eq!(manifest.name, "acme-store-x");
    assert_eq!(manifest.version, "1.4.0");
}

/// ROLLBACK is FAIL-CLOSED: an UNTRUSTED target (unsigned under a strict posture) is refused even
/// with the floor lowered — a rollback authenticates the OPERATOR, never the ARTIFACT. (An ABSENT
/// target's 404 is the admin surface's, proven in the admin crate.)
#[test]
fn rollback_is_fail_closed_on_absent_or_untrusted_target() {
    // An UNSIGNED artifact, under the STRICT posture: trust refuses it even for a rollback (the
    // floor was lowered, but the signature/opt-in gate still fails).
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

/// SECURITY: under the DEFAULT (strict) posture, an unsigned tarball present in the plugins dir
/// is reported present + `rejected` by the catalog WITHOUT ever being `dlopen`ed — the catalog
/// path is manifest-only (pure data), so the junk library bytes here can never execute.
#[tokio::test]
async fn catalog_does_not_dlopen_an_untrusted_plugin() {
    busbar_kernel::snapshot::init();
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

/// A SIGNED upload from an allowlisted third-party publisher installs as `trusted`, and the
/// catalog reports the signed metadata + trusted verdict.
#[tokio::test]
async fn install_signed_is_trusted() {
    busbar_kernel::snapshot::init();
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

/// ANTI-DOWNGRADE at the ADMIN INSTALL boundary: a `plugins.min_versions` floor rejects a
/// VALIDLY-SIGNED but older release of the same plugin (keyed on the manifest NAME) — a
/// rollback/replay is a `409`, nothing is written. The release at/above the floor installs.
#[tokio::test]
async fn install_downgraded_version_is_rejected_by_floor() {
    busbar_kernel::snapshot::init();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let lib = b"lib bytes";
    let mut cfg = publisher_posture("acme", &key);
    cfg.min_versions
        .insert("acme-store-disk".to_string(), "2.0.0".to_string());
    let dir = tmp_plugins_dir("downgrade");
    let (addr, handle) = serve_admission(dir.clone(), cfg, None).await;

    // A validly-signed 1.9.0 is below the 2.0.0 floor -> rejected, nothing published.
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

    // The current 2.1.0 clears the floor and installs as trusted.
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

/// A signed upload whose publisher is NOT allowlisted is untrusted; under the strict default it
/// is a conflict (rejected), and nothing is written.
#[tokio::test]
async fn install_unknown_publisher_rejected() {
    busbar_kernel::snapshot::init();
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

/// CONFLICT at the ADMIN INSTALL boundary: an upload whose alias collides with a DIFFERENT
/// already-installed loadable plugin is a `409` naming both ("can't use valkey and a
/// third-party valkey"); overwriting the SAME plugin (same name, same file) is a legal upgrade.
#[tokio::test]
async fn install_alias_conflict_is_rejected() {
    busbar_kernel::snapshot::init();
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

    // A DIFFERENT plugin claiming the same alias -> conflict naming both.
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

    // Upgrading the SAME plugin in place (same name, same file) is allowed.
    let upgrade = signed_tarball(
        &key,
        test_manifest("acme-store-kv", "kv", "acme", "1.1.0"),
        b"lib a v2",
    );
    let (status, b) = install(addr, "first.tar.gz", &upgrade).await;
    assert_eq!(status, 201, "same-name overwrite is a legal upgrade: {b}");
    handle.abort();
}

/// THE ROOT'S ADMISSION REPORTS AN UPLOAD'S TRUST IN THE ADMIN SURFACE'S CLASSES: an unsigned
/// upload under `allow_unsigned` is `Allowed` and an allowlisted signature is `Trusted` naming its
/// publisher; nothing is written by the admission itself.
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

// ── over the wire ──────────────────────────────────────────────────────────────────────────────

/// THE ONE-VERSION RULE OVER THE WIRE (ARCHITECT C'): `POST /plugins` with a copy of a plugin this
/// build LINKS, at the version its Statement states, answers exactly as every successful install
/// has since 1.5.5 — `201 Created` with the install view (v1.5.5 had no "already installed" answer:
/// `crates/busbar/src/admin/v1/json/handlers.rs:211` is its one success, and
/// `crates/busbar/src/admin/v1/service.rs:1873` overwrote a same-file upload) — its note saying the
/// linked build serves it, and NOTHING is written to the plugins directory.
#[tokio::test]
async fn test_admin_v1_plugin_install_of_a_linked_copy_is_a_201_no_op() {
    busbar_kernel::snapshot::init();
    let (canonical, key, version, _) = linked_store();
    let tarball = unsigned_copy(canonical, key, &version);
    let file = "linked-copy.tar.gz";
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-linked-copy-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, _handle) = serve_with_plugins_dir(dir.clone()).await;
    // The install view's shape is every one of its fields (both optional ones present, each of
    // its type) and nothing else.
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

/// FULL LIFECYCLE over the wire: `POST /plugins` installs an (unsigned, allow_unsigned-posture)
/// plugin tarball → `GET /plugins?type=store` lists it as a dynamic-library row → `POST
/// /plugins/reload` reports it → `DELETE /plugins/{file}` removes it (204) → a second DELETE is
/// 404. Every mutation is admin-token guarded and audited; the uploaded code is never executed.
#[tokio::test]
async fn test_admin_v1_plugin_install_list_reload_remove() {
    busbar_kernel::snapshot::init();
    let tarball = admin_test_tarball("acme-store-junk", "junkstore");
    let file = "acme-store-junk.tar.gz";
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-http-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    // INSTALL — 201 with a trust verdict of "unverified" (unsigned under allow_unsigned).
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

    // A mutation WITHOUT the admin token is rejected (401) — the whole surface is guarded.
    let unauth = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    // LIST — the store catalog reports the memory head + our dynamic plugin (ready).
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

    // RELOAD — reports the reconciled dynamic set (no memory head).
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

    // REMOVE — 204, then a second remove is 404 in the frozen envelope.
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

    // The install + remove both left audit rows (every mutation is audited).
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

/// `GET /plugins?type=secret` lists `kind: secret` plugins ONLY — a `kind: store`
/// tarball dropped in the same directory does not leak into it, and vice versa (the pre-existing
/// scan used to be unfiltered by kind at all, so this also proves the fix rather than just the
/// addition). `type=secret` previously did not exist as an accepted value (400 `invalid_request`
/// before this change).
#[tokio::test]
async fn test_admin_v1_plugins_type_secret_lists_secret_kind_only() {
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-secret-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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

/// `GET /plugins` list rows carry `schema_url`: a non-null, admin-prefixed RELATIVE path
/// whenever the manifest declared `settings_schema` at all — and
/// following it returns the SAME schema `GET /plugins/{name}/schema` would. A plugin with no
/// `settings_schema` gets `schema_url: null` (absence, not an empty string or omitted field).
#[tokio::test]
async fn test_admin_v1_plugins_list_row_carries_schema_url() {
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-schemaurl-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"url": {"type": "string"}},
    });
    let lib = b"junk lib bytes for acme-store-schemaurl".to_vec();
    let mut m = test_manifest("acme-store-schemaurl", "schemaurl", "acme", "1.0.0");
    m.settings_schema = Some(schema.to_string());
    let tarball = unsigned_tarball(m, &lib);
    // Write directly to disk (not via `POST /plugins`) so `hook_env.registry` — which the
    // per-plugin `GET /plugins/{name}/schema` endpoint resolves against, a SEPARATE path from the
    // directory-scanning list endpoint below — can be built from the same directory's real
    // contents up front (mirrors `test_admin_v1_plugin_schema_round_trips_from_manifest`, since the
    // plain `TestApp`/`serve_with_plugins_dir` builder otherwise defaults `hook_env` to an empty
    // registry regardless of `plugins_dir`).
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

    // Following it returns the same schema.
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

    // The `memory` compiled-in row (no manifest at all) has `schema_url: null` — absence, not an
    // error, and distinct from "declared but unparseable".
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

/// `GET /plugins` list rows carry `file` (the artifact
/// filename — the exact string `DELETE /plugins/{file}` and `GET /plugins/{file}/schema` key off)
/// and `has_schema` (mirrors `schema_url.is_some()`, so a catalog can flag configurable rows
/// without a fetch per row). Covers a dynamic-library row WITH a schema, a dynamic-library row
/// WITHOUT one, and the compiled-in `memory` row (no backing artifact at all).
#[tokio::test]
async fn test_admin_v1_plugins_list_row_carries_file_and_has_schema() {
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-file-hasschema-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

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
    // Deliberately different FILENAME than the manifest NAME, so a test that only checked `name`
    // could not accidentally pass — `file` must be the on-disk artifact filename.
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

    // Round-trip: `file` is exactly what `DELETE /plugins/{file}` and `GET /plugins/{file}/schema`
    // take.
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

/// Over the wire: a candidate tarball previews cleanly, NEVER lands on disk, and never appears in
/// `GET /plugins?type=store` afterward — inspect is genuinely stateless, not "install with extra
/// steps".
#[tokio::test]
async fn test_admin_v1_plugins_inspect_previews_without_installing() {
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-inspect-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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

    // NOTHING was written — a subsequent list shows no such plugin, and the directory is empty.
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

    // A read-only-scoped token (no `full`/`mint`/`hooks-register`) can still call it — `read-only`
    // scope, not a mutation scope (docs/admin-api.md).
    // (This server's operator token already holds `full`, which trivially satisfies `read-only` —
    // the scope MATRIX assignment itself is asserted structurally in contract::mod.rs's own tests;
    // this test's job is the wire behavior, not re-deriving the scope lattice.)

    // Malformed body (bad base64) is a 400, never a panic/500.
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

    // Malformed JSON body entirely is also a 400.
    let malformed_resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed_resp.status().as_u16(), 400);

    // No admin token at all → 401, same as every other admin endpoint.
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

/// The manifest-embedded `settings_schema` round-trips over the
/// wire: install a tarball whose SIGNED manifest carries a JSON Schema document, then `GET
/// /plugins/{file}/schema` returns it as real parsed JSON (not a JSON string containing JSON). A
/// plugin installed WITHOUT a `settings_schema` reports `"schema": null` rather than 404/erroring —
/// absence is a valid, common state (most plugins today have none), not a fault.
#[tokio::test]
async fn test_admin_v1_plugin_schema_round_trips_from_manifest() {
    busbar_kernel::snapshot::init();
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
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-schema-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Drop the tarball into the plugins dir BEFORE boot (the same "file-drop-then-boot" mechanism a
    // real operator uses) and scan it into a REAL `PluginRegistry` (the same
    // `scan_and_validate` production boot uses) so `hook_env.registry` — what `GET .../schema`
    // reads — is populated exactly as it would be at a real boot.
    std::fs::write(dir.join(file), &tarball).unwrap();
    let hook_env = scanned_hook_env(&dir);
    let (addr, handle) = serve_with_plugins_dir_and_hook_env(dir.clone(), hook_env).await;
    let client = reqwest::Client::new();

    // GET .../schema returns the schema as real JSON, resolved by NAME (not filename).
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
    // Unsigned tarball under an `allow_unsigned` posture (no publisher allowlist) → "unverified",
    // the real catalog vocabulary (never "verified").
    assert_eq!(got["trust"], "unverified");

    handle.abort();

    // A schemaless plugin reports `"schema": null`, not an error — dropped in and
    // rebooted the same way, since (as above) ephemeral test apps only pick up the plugins dir at
    // initial load.
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
    // The schema-carrying plugin from the first boot is still resolvable (both files on disk now).
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

    // A manifest that SET settings_schema but to unparseable text reports `schema_error`,
    // distinct from a manifest that never set the field at all (both used to
    // collapse to `schema: null` via `.ok()`, silently hiding a real authoring bug).
    let bad_lib = b"junk library bytes for acme-store-badschema (never dlopened)".to_vec();
    let mut bad_m = test_manifest("acme-store-badschema", "badschema", "acme", "1.0.0");
    bad_m.settings_schema = Some("{ not valid json".into());
    let bad_tarball = unsigned_tarball(bad_m, &bad_lib);
    let bad_dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-badschema-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&bad_dir);
    std::fs::create_dir_all(&bad_dir).unwrap();
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
    // An unknown plugin name is 404, distinguishing "no schema" from "no such plugin".
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

/// Bricks next boot: installing a SAME-NAME plugin under a DIFFERENT filename (e.g. a version
/// bump `-1.1.0.tar.gz` over an installed `-1.0.0.tar.gz`) must be a 409, NOT admitted. Two files
/// claiming the same plugin name are a hard conflict at boot (registry::conflicts()) - admitting the
/// second bricks the next restart. A same-name upgrade must REUSE the existing filename. The old gate
/// exempted this case (`&& existing.manifest.name != manifest.name`).
#[tokio::test]
async fn test_admin_v1_plugin_install_same_name_different_file_is_409() {
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-h2-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;

    // v1.0.0 installs cleanly.
    let v1 = admin_test_tarball_versioned("busbar-store-x", "storex", "1.0.0");
    let (s1, _) = install(addr, "busbar-store-x-1.0.0.tar.gz", &v1).await;
    assert_eq!(s1, 201, "first install succeeds");

    // v1.1.0 - SAME manifest name, DIFFERENT filename - must be a 409 (boot would reject two files
    // claiming the same name), NOT a silent second publish.
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
    // The original is untouched (still exactly one plugin file on disk).
    let tars: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.gz"))
        .collect();
    assert_eq!(tars.len(), 1, "only the original v1.0.0 file remains");

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// Fail-open: a CORRUPT tarball already sitting in the plugins dir makes scan_and_validate Err.
/// The old `if let Ok(reg)` SILENTLY SKIPPED the conflict check and published anyway. Now a new
/// install returns an error (never 201) until the offending tarball is fixed/removed.
#[tokio::test]
async fn test_admin_v1_plugin_install_corrupt_existing_tarball_blocks_publish() {
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-m7-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Plant a corrupt (non-tarball) *.tar.gz that discover() picks up but examine() cannot parse.
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

/// A malformed install body (bad base64) is a `400 invalid_request` in the frozen envelope, a
/// non-tarball upload is a `400`, and an UNSIGNED upload under the STRICT default posture is a
/// `409 conflict` (the trust gate cannot be bypassed by pushing over the API) — nothing is
/// published in any case, and the rejects are audited.
#[tokio::test]
async fn test_admin_v1_plugin_install_rejections() {
    busbar_kernel::snapshot::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-admin-plugins-rej-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    // Bad base64.
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

    // Valid base64 but not a plugin tarball → structural validation fails (400).
    let (status, _) = install(addr, "nope.tar.gz", b"not a tarball").await;
    assert_eq!(status, 400);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "nothing published"
    );

    // TRUST NO-BYPASS: a STRICT-posture server rejects an unsigned upload as 409 conflict.
    {
        let strict_dir = std::env::temp_dir().join(format!(
            "busbar-root-admin-plugins-strict-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&strict_dir);
        std::fs::create_dir_all(&strict_dir).unwrap();
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

/// THE INSPECT OF A BODY THAT IS NO TARBALL is refused as the invalid tarball it is, in the
/// loader's words (`POST /plugins/inspect`'s 400 `invalid_request`; the admin crate proves the
/// envelope carries the admission's refusal through).
#[test]
fn an_inspect_of_no_tarball_is_refused_as_an_invalid_plugin_tarball() {
    let Err(Refusal::Validation(why)) =
        ADMISSION.inspect(b"not a tarball at all", &strict_posture())
    else {
        panic!("a body that is no tarball is a validation refusal");
    };
    assert!(why.starts_with("invalid plugin tarball"), "{why}");
}
