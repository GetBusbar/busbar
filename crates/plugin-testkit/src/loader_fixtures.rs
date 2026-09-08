// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TARBALL FIXTURE — a scratch plugins directory, a well-formed manifest, and an
//! unsigned-but-structurally-valid archive, for any crate whose battery drives the REAL loader.
//!
//! These three helpers used to live in `busbar_core::tests` as `pub(crate)` items, which is fine
//! while exactly one crate's tests load a plugin and wrong the moment a second one does. The hook
//! engine's battery is that second one: it packages a real `hook-test-plugin` cdylib, dlopens it
//! through the loader, and asserts on what the plugin answered — a claim no mock can make. Two
//! copies of "how a test builds a plugin archive" would be two answers to what the loader accepts,
//! and the first divergence between them would look like an ABI defect.
//!
//! Behind the off-by-default `loader-fixtures` feature so an ordinary plugin's dev tree, which
//! wants only the `open`-seam contract checks above, does not compile the loader and the signer.

/// A FRESH scratch plugins directory for one test.
///
/// The naming is defensive in two directions that both produced real, misdiagnosed failures:
///
/// A monotonic counter, NOT a timestamp. Several helpers call this with the same `tag` from
/// different tests running concurrently, and a clock read is not guaranteed to differ between two
/// threads. Colliding on the path made two tests share one directory: one wrote its tarball while
/// the other scanned it, or removed the directory out from under it — surfacing as an unrelated
/// hooks test failing on "corrupt tar.gz archive" roughly one run in three.
///
/// AND a once-per-process token, because the pid alone is not a process identity over time. These
/// dirs are deliberately never cleaned up, and under process churn (a full workspace build spawning
/// thousands of compiler processes while several copies of a test binary run) the OS reuses pids
/// within a session — at which point a fresh run's `create_dir_all` happily adopts a PREVIOUS run's
/// leftover dir, stale manifests, stale cdylib copies and all. A stale plugin dir reads exactly like
/// an ABI or staleness defect, which is the worst possible way for a fixture to fail. One clock read
/// per PROCESS (not per call — see the counter note above), so two calls in one process still cannot
/// collide and two processes with one pid cannot either.
pub fn tmp_plugin_dir(tag: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static PROC_TOKEN: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    let token = PROC_TOKEN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    });
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-plugins-{}-{token:x}-{tag}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A well-formed manifest for `name`/`alias`/`publisher`, at the HIGHEST abi version the loader
/// says it supports for the kind — read from the loader rather than written as a literal, so a test
/// fixture can never pin an abi the loader has moved past.
pub fn plugin_manifest(name: &str, alias: &str, publisher: &str) -> busbar_plugin_sign::Manifest {
    busbar_plugin_sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: publisher.into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
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
    }
}

/// An UNSIGNED (but structurally valid) tarball: sha256 set, signature empty.
pub fn unsigned_tarball(mut m: busbar_plugin_sign::Manifest, lib: &[u8]) -> Vec<u8> {
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}
