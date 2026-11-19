// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::export_stream::ExportStream;
use busbar_plugin_loader::{
    dispatch::{
        kinds::export::{Export, ExportFacts},
        kinds::transport::{Transport, TransportFacts},
        load_dropped, load_linked, rendering_of_library, Bind, DispatchConfig, Dispatcher,
        LinkedRow, NoSink, Plugin,
    },
    list_plugin_files, plugin_library_filename, scan_and_validate,
    sign::{sha256_hex, sign, Manifest, SigningKey, TrustPolicy},
    supported_abi, tarball, PluginRegistry,
};
use std::path::{Path, PathBuf};

#[path = "native_store_startup.rs"]
mod native_fixture;
pub(crate) use native_fixture::core_over;

/// Build a canonical fixture reference from the admitted source owner's grammar.
pub fn source_reference(
    axis: &dyn busbar_contract::secret::SecretAxis,
    role: &str,
    value: impl Into<String>,
) -> busbar_contract::secret_ref::SecretRef {
    axis.sugars()
        .reference_for_role(role, value)
        .expect("the admitted source declares the fixture's role")
}

/// The separately built durable Store used by normal application boot fixtures.
pub fn application_store_library() -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
            .expect("BUSBAR_TEST_SQLITE_CDYLIB names the actual application Store image"),
    );
    assert!(
        path.is_absolute() && path.is_file(),
        "the actual application Store image exists"
    );
    path
}

pub fn application_store_settings(directory: &Path) -> busbar_contract::json::Value {
    busbar_contract::json::json!({ "db_path": directory.join("application.sqlite") })
}

/// The explicit configuration document for the same fixture plugin policy used at boot.
pub fn config_document(config: &busbar_kernel::config::PluginsCfg) -> busbar_contract::json::Value {
    let publishers: Vec<_> = config
        .trust
        .publishers
        .iter()
        .map(|p| {
            busbar_contract::json::json!({
                "name": p.name, "plugins": p.plugins, "keys": p.keys.iter().map(|key| busbar_contract::json::json!({"public_key": key.public_key, "revoked": key.revoked})).collect::<Vec<_>>()
            })
        })
        .collect();
    let fetch: Vec<_> = config
        .fetch
        .iter()
        .map(|entry| match entry {
            busbar_kernel::config::PluginFetch::Url(value) => {
                busbar_contract::json::json!({"url": value.url, "sha256": value.sha256})
            }
            busbar_kernel::config::PluginFetch::Github(value) => {
                busbar_contract::json::json!({"github": value.github, "sha256": value.sha256})
            }
            busbar_kernel::config::PluginFetch::Env(value) => {
                busbar_contract::json::json!({"env": value.env})
            }
        })
        .collect();
    busbar_contract::json::json!({
        "enabled": config.enabled, "dir": config.dir, "min_versions": config.min_versions,
        "trust": {"publishers": publishers, "allow_untrusted": config.trust.allow_untrusted}, "fetch": fetch
    })
}

pub fn trusted_config_document(directory: &Path) -> busbar_contract::json::Value {
    config_document(&trusted_config(directory))
}

/// Publisher explicitly configured by normal distribution fixtures.
pub const FIXTURE_PUBLISHER: &str = "distribution-fixture";

/// Trust the exact staged fixture archives through ordinary configured-publisher admission.
pub fn trusted_config(directory: &Path) -> busbar_kernel::config::PluginsCfg {
    trusted_config_with_key(directory, &key(0x5a))
}

pub(crate) fn trusted_config_with_key(
    directory: &Path,
    signing_key: &SigningKey,
) -> busbar_kernel::config::PluginsCfg {
    let mut archives: Vec<_> = std::fs::read_dir(directory)
        .expect("the fixture plugin directory exists")
        .map(|entry| entry.expect("the fixture directory entry reads").path())
        .filter(|path| path.is_file() && path.to_string_lossy().ends_with(".tar.gz"))
        .collect();
    archives.sort();
    let fetch: Vec<serde_json::Value> = archives
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .unwrap()
                .to_str()
                .expect("fixture archive name is UTF-8");
            serde_json::json!({
                "url": format!("https://distribution-fixtures.example/{name}"),
                "sha256": sha256(&std::fs::read(path).expect("the exact fixture archive reads"))
            })
        })
        .collect();
    let mut config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: serde_json::from_value(serde_json::Value::Array(fetch))
            .expect("fixture archive pins"),
        ..Default::default()
    };
    config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: FIXTURE_PUBLISHER.into(),
            plugins: archives
                .iter()
                .map(|path| {
                    tarball::unpack(
                        &std::fs::read(path).expect("fixture archive reads"),
                    )
                    .expect("fixture archive unpacks")
                    .manifest
                    .name
                })
                .collect(),
            keys: vec![busbar_kernel::config::PluginPublisherKey {
                public_key: hex::encode(signing_key.verifying_key().as_bytes()),
                revoked: false,
            }],
        });
    config
}

/// A native MIN-3 image's stamped identity and its header's ordered `former_names`.
pub struct NativeImage {
    pub name: String,
    pub version: String,
    pub former: Vec<String>,
}

/// The identity of the native image at `path` (the application Store is a MIN-3 image: its stamp,
/// not a door Statement, names it).
pub fn native_image(path: &Path) -> NativeImage {
    let bytes =
        busbar_plugin_loader::pack_native::read_image(path).expect("the native image reads");
    let (name, version, former) = busbar_plugin_loader::pack_native::identity(&bytes)
        .expect("the image is a native MIN-3 image");
    NativeImage {
        name,
        version,
        former,
    }
}

/// A `kind` manifest for the native image at `path`, completed from its stamp and header as
/// `busbar pack` completes it: its alias is the header's first former name.
pub fn native_manifest(kind: &str, path: &Path, publisher: &str) -> Manifest {
    let bytes =
        busbar_plugin_loader::pack_native::read_image(path).expect("the native image reads");
    let image = native_image(path);
    let mut m = manifest(kind, &image.name, publisher);
    m.version = image.version;
    m.alias = image
        .former
        .first()
        .cloned()
        .expect("a native image states its alias among its former_names");
    busbar_plugin_loader::pack_native::complete(&bytes, m, None)
        .expect("the native manifest completes from its stamp and header")
}

pub fn manifest(kind: &str, name: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: name.into(),
        kind: kind.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: publisher.into(),
        abi_version: supported_abi(kind).unwrap_or(0),
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

pub fn pack(kind: &str, name: &str, lib: &[u8], publisher: &str) -> Vec<u8> {
    seal(manifest(kind, name, publisher), lib)
}

pub(crate) fn pack_stated(kind: &str, name: &str, lib: &[u8], publisher: &str) -> Vec<u8> {
    let mut m = manifest(kind, name, publisher);
    state(&mut m, lib);
    seal(m, lib)
}

pub fn state(m: &mut Manifest, lib: &[u8]) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "busbar-stated-{}-{n}-{}{}",
        std::process::id(),
        m.name,
        std::env::consts::DLL_SUFFIX
    ));
    std::fs::write(&path, lib).expect("stage the library");
    let rendering = rendering_of_library(&path).expect("the library states itself");
    let _ = std::fs::remove_file(&path);
    m.statement = rendering.map(hex::encode);
}

pub fn seal(mut m: Manifest, lib: &[u8]) -> Vec<u8> {
    m.sha256 = sha256(lib);
    package(&m, lib)
}

pub fn signed(key: &SigningKey, m: Manifest, lib: &[u8]) -> Vec<u8> {
    package(&sign(key, m, lib), lib)
}

pub fn package(m: &Manifest, lib: &[u8]) -> Vec<u8> {
    tarball::package(m, "lib.so", lib).expect("the plugin packs")
}

pub fn sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn release_policy(release: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    }
}

pub fn scratch(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "busbar-plugins-{tag}-{}-{next}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

pub(crate) fn boot_with(dir: &Path, policy: &TrustPolicy) -> PluginRegistry {
    scan_and_validate(dir, policy).expect("the plugins directory scans")
}

fn profile_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.parent()?.to_path_buf())
}

pub(crate) fn cdylib_path(snake: &str) -> Option<PathBuf> {
    let profile = profile_dir()?;
    let exact = plugin_library_filename(snake);
    let (stem, ext) = exact.rsplit_once('.')?;
    let (stem, ext) = (format!("{stem}-"), format!(".{ext}"));
    let is_lib = |p: &PathBuf| {
        let f = p.file_name().and_then(|f| f.to_str()).unwrap_or("");
        f == exact
            || f.strip_prefix(stem.as_str())
                .and_then(|rest| rest.strip_suffix(ext.as_str()))
                .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    [profile.clone(), profile.join("deps")]
        .iter()
        .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
        .map(|e| e.path())
        .filter(is_lib)
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
}

pub fn missing(name: &str, command: &str) -> ! {
    panic!("the {name} cdylib is not built: run `{command}` first (this test never skips)")
}

pub const BUILD_PINNED: &str = "cargo test -p busbar --no-run";

pub const BUILD_LOADER_EXAMPLES: &str = "cargo build -p busbar-plugin-loader --examples";

pub const BUILD_BUSBAR_EXAMPLES: &str = "cargo build -p busbar --examples";

pub fn cdylib(snake: &str) -> Option<Vec<u8>> {
    std::fs::read(cdylib_path(snake)?).ok()
}

#[cfg(all(test, not(oracle_lookup)))]
include!(concat!(env!("OUT_DIR"), "/common_test_sources.rs"));

/// `token_verifier` is the cdylib lookup alone (the token-verifying `kind: auth` cdylib in the test
/// profile directory): busbar-auth-oidc publishes no root test sources since its MIN-3 port (c882ae1), so
/// the default distribution and the oracle package look it up the same way.
#[cfg(test)]
pub(crate) mod token_verifier {
    pub fn token_verifier_cdylib_path() -> Option<std::path::PathBuf> {
        super::cdylib_path("busbar_auth_oidc_plugin")
    }

    /// One framed (HTTP/2) admission request on `stream` for `path`, with the connection preface when
    /// `preface`: carried over unchanged from busbar-auth-oidc 7877ca7's retired common source, which
    /// the transport root sources still mounted here read.
    pub fn framed_admission_request(stream: u32, path: &str, preface: bool) -> Vec<u8> {
        assert!(path.len() < 127);
        let mut bytes = Vec::new();
        if preface {
            bytes.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        }
        let mut fields = vec![0x83, 0x86, 0x04, path.len() as u8];
        fields.extend_from_slice(path.as_bytes());
        fields.extend_from_slice(&[0x01, 9]);
        fields.extend_from_slice(b"localhost");
        let len = fields.len() as u32;
        bytes.extend_from_slice(&len.to_be_bytes()[1..]);
        bytes.extend_from_slice(&[1, 4]);
        bytes.extend_from_slice(&stream.to_be_bytes());
        bytes.extend_from_slice(&fields);
        bytes
    }
}
#[cfg(test)]
pub use token_verifier::*;

fn libraries() -> Vec<PathBuf> {
    let Some(profile) = profile_dir() else {
        return Vec::new();
    };
    let dirs = [
        profile.clone(),
        profile.join("deps"),
        profile.join("examples"),
    ];
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = dirs
        .iter()
        .flat_map(|dir| list_plugin_files(dir).into_iter().map(move |f| dir.join(f)))
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .collect();
    found.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    found.into_iter().map(|(_, p)| p).collect()
}

fn transport_door(path: &Path) -> Option<(Plugin<Transport>, &'static str)> {
    static ONE: std::sync::OnceLock<Dispatcher> = std::sync::OnceLock::new();
    let d = ONE.get_or_init(|| {
        Dispatcher::new(
            DispatchConfig::default(),
            busbar_kernel::host_services::caller_binding(),
        )
    });

    let stated = rendering_of_library(path).ok()??;
    let bind = Bind {
        accept: Default::default(),
        instance: std::sync::Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: std::sync::Arc::new(NoSink),
        dispatcher: d.adopter(),

        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_dropped::<Transport>(path, &stated, bind).ok()?;
    let key = *plugin.context::<TransportFacts>()?.claims.first()?;
    Some((plugin, key))
}

pub fn linked_transport(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    bind: Bind,
) -> Plugin<Transport> {
    let row = LinkedRow::of(door).expect("the linked door states itself");
    load_linked::<Transport>(&row, bind).expect("the linked door loads")
}

pub fn transport_cdylib() -> Option<(Vec<u8>, &'static str)> {
    transport_cdylib_under(&[])
}

pub fn transport_cdylib_under(keys: &[&str]) -> Option<(Vec<u8>, &'static str)> {
    let neutral = plugin_library_filename("neutral_frame_door");
    libraries().into_iter().find_map(|p| {
        if p.file_name().is_some_and(|n| n == neutral.as_str()) {
            return None;
        }
        let (plugin, key) = transport_door(&p)?;
        let facts = plugin.context::<TransportFacts>()?;

        if !facts.composes_over.is_empty()
            || facts.role != busbar_contract::transport::codes::ROLE_CARRIER
            || !facts.ported
        {
            return None;
        }
        if !keys.is_empty() && !keys.contains(&key) {
            return None;
        }
        Some((std::fs::read(&p).ok()?, key))
    })
}

/// The loader's `native_schema_bomb` example: a MIN-3 store whose describe answers a recursion-bomb D_SCHEMA.
pub fn native_schema_bomb_path() -> Option<PathBuf> {
    let file = plugin_library_filename("native_schema_bomb");
    libraries()
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == file.as_str()))
}

pub fn neutral_frame_door_bytes() -> Option<Vec<u8>> {
    let file = plugin_library_filename("neutral_frame_door");
    libraries()
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .and_then(|p| std::fs::read(p).ok())
}

pub fn metrics_sink_cdylib() -> Option<Vec<u8>> {
    static ONE: std::sync::OnceLock<Dispatcher> = std::sync::OnceLock::new();
    let d = ONE.get_or_init(|| {
        Dispatcher::new(
            DispatchConfig::default(),
            busbar_kernel::host_services::caller_binding(),
        )
    });
    libraries().into_iter().find_map(|p| {
        let stated = rendering_of_library(&p).ok()??;
        let bind = Bind {
            accept: Default::default(),
            instance: std::sync::Arc::from("probe"),
            max_inflight_cap: 64,
            sink: std::sync::Arc::new(NoSink),
            dispatcher: d.adopter(),

            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
        };
        let plugin = load_dropped::<Export>(&p, &stated, bind).ok()?;
        let metrics = [ExportStream::Metrics as u8];
        (plugin.context::<ExportFacts>()?.streams == metrics)
            .then(|| std::fs::read(&p).ok())
            .flatten()
    })
}

pub fn neutral_frame_door() -> Option<(Plugin<Transport>, &'static str)> {
    let file = plugin_library_filename("neutral_frame_door");
    libraries()
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .find_map(|p| transport_door(&p))
}

#[path = "../../../../plugin-loader/tests/fixtures/neutral_export_routes_plugin.rs"]
pub(crate) mod neutral_export_routes;

/// The operator admin token an admin test presents, as `Authorization: Bearer`. 1.6 has no open
/// admin posture (`admin_auth: []` is refused at boot, ADMIN-API-1.6-ONE-MODEL §8.1.1), so an
/// admin test configures the operator credential and sends this token.
const OPERATOR_TOKEN: &str = "admintok";

/// The operator's 1.6 settings digest, `identity-providers.<operator>.settings.sha256`: the
/// SHA-256 of [`OPERATOR_TOKEN`] as 64 lower-case hex characters.
pub fn operator_sha256() -> String {
    sha256(OPERATOR_TOKEN.as_bytes())
}

/// An HTTP client that presents [`OPERATOR_TOKEN`] as `Authorization: Bearer` on every request
/// (a request that sets its own `authorization` keeps it).
pub fn operator_client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_static("Bearer admintok"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("the operator client builds")
}

/// A fixture deployment as the root listeners need it since #359 SEC-L1 (2f61a291e9): a listener with no TLS
/// boots only with its explicit plaintext acceptance, which the owner ruling has fixtures write ("kernel and root
/// make_root_cfg fixtures write the explicit plaintext acceptance for both root listeners"). A listener with TLS,
/// or one whose acceptance the document already wrote, is left as it is.
pub(crate) fn plaintext_listeners(
    mut cfg: busbar_kernel::config::RootCfg,
) -> busbar_kernel::config::RootCfg {
    use busbar_plugin_abi::host_side::caller::Accept;
    let plain = || busbar_kernel::config::min3::InsecureTransport {
        accept: Accept(Accept::PLAINTEXT),
        reason: "test fixture listener".into(),
    };
    if cfg.tls.is_none() && cfg.listener_acceptances.listen.is_none() {
        cfg.listener_acceptances.listen = Some(plain());
    }
    if cfg.admin_tls.is_none() && cfg.listener_acceptances.admin_listen.is_none() {
        cfg.listener_acceptances.admin_listen = Some(plain());
    }
    cfg
}

/// The operator's 1.6 settings digest for a token a fixture wrote to `path`: 1.6 takes the operator
/// credential as `identity-providers.<operator>.settings.sha256`, and refuses the 1.5 `token:` form with its
/// remedy (c1b9b9e234, OPERATOR-FROM-ADMITTED-AUTH r3.1). The SHA-256 of the file's bytes, 64 lower-case hex.
pub fn operator_sha256_of(path: impl AsRef<std::path::Path>) -> String {
    sha256(&std::fs::read(path).expect("the fixture's operator token file reads"))
}
