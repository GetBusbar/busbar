// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PLUGIN FIXTURE — how this crate's tests pack a plugin, drop it into a `plugins/`
//! directory, find the in-tree `cdylib` it carries and read what the boot's scan makes of it.
//!
//! Every test that hands busbar a dropped-in plugin needs the same few steps: a manifest stating the
//! plugin (its kind, name and publisher, the newest payload schema the loader speaks for the kind),
//! the library's hash bound into it, a signature when the test holds a release key, and the
//! tarball the loader unpacks. Those steps live here, once, so a change to how a plugin is packaged
//! is one edit and every test packs the same artifact a release would.
//!
//! Integration tests reach it through `mod common;` (`common::plugins`); the composition root's unit
//! tests and the benches include this file by path. Nothing here reads a variable only an
//! integration test has: the target directory is found from the running test binary, which lives
//! in `target/<profile>/deps` whichever kind of test it is.

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

/// The manifest a plugin of `kind` named `name` states when `publisher` ships it: its alias is its
/// name, its version this binary's, its payload schema the newest the loader speaks for the kind,
/// and every optional field empty. A test changes the fields its case is about.
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

/// `lib` packed UNSIGNED as a `kind` plugin named `name` from `publisher` — the tarball a
/// deployment that opts into unsigned plugins drops in.
pub fn pack(kind: &str, name: &str, lib: &[u8], publisher: &str) -> Vec<u8> {
    seal(manifest(kind, name, publisher), lib)
}

/// `lib` packed UNSIGNED as a `kind` plugin, its manifest stating the library's own Statement
/// rendering when it exports a door (the door is admitted against it), as the pack tool signs it.
pub fn pack_stated(kind: &str, name: &str, lib: &[u8], publisher: &str) -> Vec<u8> {
    let mut m = manifest(kind, name, publisher);
    state(&mut m, lib);
    seal(m, lib)
}

/// `m` states the Statement rendering `lib`'s door answers (what the packer signs into a
/// memory-ABI plugin's manifest).
pub fn state(m: &mut Manifest, lib: &[u8]) {
    // One staging file per call: two tests of one binary may state the same plugin name at once,
    // and one must not unlink or overwrite the library the other is mapping.
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

/// `lib` packed UNSIGNED under `m`, the manifest bound to the library's hash.
pub fn seal(mut m: Manifest, lib: &[u8]) -> Vec<u8> {
    m.sha256 = sha256(lib);
    package(&m, lib)
}

/// `lib` packed under `m` SIGNED by `key` (the hash bound, then signed over every field).
pub fn signed(key: &SigningKey, m: Manifest, lib: &[u8]) -> Vec<u8> {
    package(&sign(key, m, lib), lib)
}

/// `lib` packed under `m` exactly as stated — the hash and signature are whatever `m` says, which
/// is how a test builds a tarball whose manifest does not match its library.
pub fn package(m: &Manifest, lib: &[u8]) -> Vec<u8> {
    tarball::package(m, "lib.so", lib).expect("the plugin packs")
}

/// The lowercase hex SHA-256 a manifest binds its library with.
pub fn sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// A signing key made from one repeated byte — a test's release key or third-party publisher key.
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The DEFAULT trust posture a release build boots with, holding `release` as its first-party key:
/// no publisher allowlisted, nothing unsigned, nothing third-party.
pub fn release_policy(release: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    }
}

/// A fresh, empty directory for this process under `tag`.
pub fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-plugins-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// What the boot's scan admits from `dir` under `policy` — every tarball in it verified, trusted and
/// registered, exactly as the boot scans the configured `plugins.dir`.
pub fn boot_with(dir: &Path, policy: &TrustPolicy) -> PluginRegistry {
    scan_and_validate(dir, policy).expect("the plugins directory scans")
}

/// `target/<profile>`: the directory this test binary's `deps/` sits in, where cargo builds (and
/// uplifts) every `cdylib` this crate depends on.
fn profile_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.parent()?.to_path_buf())
}

/// The built `cdylib` of the crate `snake` (its snake-cased crate name): uplifted, or under `deps/`
/// with cargo's metadata hash (`lib<name>-<hash>.<ext>`, how a git dependency's library is left),
/// the newest wins. `None` when it is not built; whether that is a skip or a failure is the
/// caller's to say.
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

/// The bytes of [`cdylib_path`].
pub fn cdylib(snake: &str) -> Option<Vec<u8>> {
    std::fs::read(cdylib_path(snake)?).ok()
}

/// Every loadable plugin library in the target directory (uplifted, under `deps/`, or an example
/// `cdylib` under `examples/`), newest first.
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

/// A transport door `cdylib` at `path`, admitted through the one dispatcher's door validation, and
/// the key its tail states (its own claim); `None` for any other library.
fn transport_door(path: &Path) -> Option<(Plugin<Transport>, &'static str)> {
    static ONE: std::sync::OnceLock<Dispatcher> = std::sync::OnceLock::new();
    let d = ONE.get_or_init(|| Dispatcher::new(DispatchConfig::default()));
    // The library's own Statement rendering, as its signed manifest would state it.
    let stated = rendering_of_library(path).ok()??;
    let bind = Bind {
        instance: std::sync::Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: std::sync::Arc::new(NoSink),
        dispatcher: d.adopter(),
        // A transport door is a framer the connector drives: it declares no need.
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_dropped::<Transport>(path, &stated, bind).ok()?;
    let key = *plugin.context::<TransportFacts>()?.claims.first()?;
    Some((plugin, key))
}

/// A compiled-in transport door (a linked row's door function), admitted through the same door
/// validation as a dropped-in one and bound with `bind`.
pub fn linked_transport(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    bind: Bind,
) -> Plugin<Transport> {
    let row = LinkedRow::of(door).expect("the linked door states itself");
    load_linked::<Transport>(&row, bind).expect("the linked door loads")
}

/// An in-tree transport door `cdylib` that frames the host's socket (the wire at the floor of a
/// stack: its tail composes over nothing), found by its KIND, and the key its tail states — the
/// test names no transport. A door composing over a layer (the http door example, where a workspace
/// build emits it) is not a dropped-in wire.
pub fn transport_cdylib() -> Option<(Vec<u8>, &'static str)> {
    transport_cdylib_under(&[])
}

/// [`transport_cdylib`] PINNED TO THE WIRE A PROOF NEEDS: the floor CARRIER whose key is one of
/// `keys` (the keys the build's linked layers compose over, read off its linked table); every key
/// when `keys` is empty.
///
/// The target directory holds every transport door any build in it emitted (the pinned plugin
/// repos' cdylibs, the loader's examples, an in-tree carrier built with its door), and "the newest
/// floor door" was whichever of them a build happened to touch last: in the dropped-in-tcp row it
/// was one the layers do not compose over, and the node refused to boot (`transport http composes
/// over tcp, which no registered transport provides`). Filtered by the key the layers need, the
/// artifact is the one wire that can sit under them, whatever else was built since.
pub fn transport_cdylib_under(keys: &[&str]) -> Option<(Vec<u8>, &'static str)> {
    // The neutral frame door claims no linked key and no layer composes over it; the proofs that
    // need it name it ([`neutral_frame_door`]).
    let neutral = plugin_library_filename("neutral_frame_door");
    libraries().into_iter().find_map(|p| {
        if p.file_name().is_some_and(|n| n == neutral.as_str()) {
            return None;
        }
        let (plugin, key) = transport_door(&p)?;
        let facts = plugin.context::<TransportFacts>()?;
        // The floor wire is a CARRIER whose claim serves a port: the one that can listen under the
        // data door (a carrier reached by a program serves no port).
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

/// The neutral frame door's library bytes ([`neutral_frame_door`]), for a proof that drops it in.
pub fn neutral_frame_door_bytes() -> Option<Vec<u8>> {
    let file = plugin_library_filename("neutral_frame_door");
    libraries()
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .and_then(|p| std::fs::read(p).ok())
}

/// An in-tree export door `cdylib` that loads as a sink carrying exactly the `metrics` stream,
/// found by what it carries rather than by name.
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
            // A probe: the library is only read for what it states, never opened to serve.
            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
        };
        let plugin = load_dropped::<Export>(&p, &stated, bind).ok()?;
        let metrics = [ExportStream::Metrics as u8];
        (plugin.context::<ExportFacts>()?.streams == metrics)
            .then(|| std::fs::read(&p).ok())
            .flatten()
    })
}

/// The export sink `lib`, DROPPED IN on the export kind's memory ABI (its door's Statement stated)
/// and opened under `name` with `settings`, handed `exposition` read into the recorder snapshot, as
/// the host hands a sink serving `/metrics` its scrape: the body it renders.
pub fn render_snapshot(lib: &[u8], name: &str, settings: &str, exposition: &str) -> Vec<u8> {
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
    sink.scrape(&families).expect("the sink renders")
}

/// THE NEUTRAL FRAME DOOR (the plugin loader's `neutral_frame_door` example): a transport door that
/// frames the host's socket under a neutral claim and names no transport, admitted through the one
/// dispatcher's door validation, and the key its tail states. `None` when it is not built beside the
/// test binary.
pub fn neutral_frame_door() -> Option<(Plugin<Transport>, &'static str)> {
    let file = plugin_library_filename("neutral_frame_door");
    libraries()
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == file.as_str()))
        .find_map(|p| transport_door(&p))
}
