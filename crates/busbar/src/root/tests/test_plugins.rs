// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use busbar_contract::abi::export::ExportStream;
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

/// Publisher explicitly configured by normal distribution fixtures.
pub const FIXTURE_PUBLISHER: &str = "distribution-fixture";

/// Trust the exact staged fixture archives through ordinary configured-publisher admission.
pub fn trusted_config(directory: &Path) -> busbar_kernel::config::PluginsCfg {
    trusted_config_with_key(directory, &key(0x5a))
}

pub fn trusted_config_with_key(
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
            public_key: hex::encode(signing_key.verifying_key().as_bytes()),
        });
    config
}

pub fn manifest(kind: &str, name: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: name.into(),
        kind: kind.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: publisher.into(),
        abi_version: supported_abi(kind).iter().copied().max().unwrap_or(0),
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

pub fn pack_stated(kind: &str, name: &str, lib: &[u8], publisher: &str) -> Vec<u8> {
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

pub fn boot_with(dir: &Path, policy: &TrustPolicy) -> PluginRegistry {
    scan_and_validate(dir, policy).expect("the plugins directory scans")
}

fn profile_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.parent()?.to_path_buf())
}

pub fn cdylib_path(snake: &str) -> Option<PathBuf> {
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

pub fn token_verifier_cdylib_path() -> Option<PathBuf> {
    cdylib_path("busbar_auth_oidc_plugin")
}

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
    let d = ONE.get_or_init(|| Dispatcher::new(DispatchConfig::default()));

    let stated = rendering_of_library(path).ok()??;
    let bind = Bind {
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
            || facts.role != busbar_contract::abi::transport::ROLE_CARRIER
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

pub fn neutral_frame_door_bytes() -> Option<Vec<u8>> {
    let file = plugin_library_filename("neutral_frame_door");
    libraries()
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .and_then(|p| std::fs::read(p).ok())
}

pub fn metrics_sink_cdylib() -> Option<Vec<u8>> {
    static ONE: std::sync::OnceLock<Dispatcher> = std::sync::OnceLock::new();
    let d = ONE.get_or_init(|| Dispatcher::new(DispatchConfig::default()));
    libraries().into_iter().find_map(|p| {
        let stated = rendering_of_library(&p).ok()??;
        let bind = Bind {
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

pub fn render_snapshot(
    lib: &[u8],
    name: &str,
    settings: &str,
    exposition: &str,
) -> Result<Vec<u8>, String> {
    use busbar_contract::export_calls::ExportCalls as _;
    let families =
        busbar_contract::export_calls::parse_families(exposition).expect("the snapshot reads");
    let path = std::env::temp_dir().join(format!(
        "busbar-render-{}-{name}{}",
        std::process::id(),
        std::env::consts::DLL_SUFFIX
    ));
    std::fs::write(&path, lib).expect("stage the library");
    let stated = rendering_of_library(&path)
        .expect("the library loads")
        .expect("the library states itself");
    let d = std::sync::Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: std::sync::Arc::from(name),
        max_inflight_cap: 64,
        sink: std::sync::Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
    };
    let plugin = load_dropped::<Export>(&path, &stated, bind).expect("the sink loads");
    let _ = std::fs::remove_file(&path);
    let sink =
        busbar_plugin_loader::export_door::ExportInstance::open(plugin, d, settings.as_bytes())
            .expect("the sink opens");
    sink.scrape(&families)
}

pub fn neutral_frame_door() -> Option<(Plugin<Transport>, &'static str)> {
    let file = plugin_library_filename("neutral_frame_door");
    libraries()
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .find_map(|p| transport_door(&p))
}
