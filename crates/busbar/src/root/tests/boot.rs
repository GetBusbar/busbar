// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's boot stages: its `plugins.fetch` runs the loader's fetch, and only ever downloads
//! through the kernel's SSRF-guarded downloader.

use super::*;

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-root-fetch-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A PIN-CACHED entry skips the network: the file already on disk hashes to the pin, so the
/// root's fetch reports it cached and never calls the downloader (which would fail the test).
#[test]
fn a_pin_cached_fetch_never_downloads() {
    let dir = scratch("cached");
    let body = b"cached-blob-bytes";
    std::fs::write(dir.join("cached-blob.dat"), body).unwrap();
    let target = FetchTarget {
        url: "https://plugin.invalid/cached-blob.dat".into(),
        sha256: Some(super::super::loader::sign::sha256_hex(body)),
        filename: "cached-blob.dat".into(),
    };
    let never = |url: &str| -> Result<Vec<u8>, String> { panic!("downloaded {url}") };
    let got = plugins_fetch(&dir, &[target], true, &never).expect("the cached pin fetches");
    assert_eq!(
        got,
        vec![Fetched::Cached {
            filename: "cached-blob.dat".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE ROOT'S FETCH CANNOT BYPASS THE GUARD: a cloud-metadata URL fetched through the root, with
/// the kernel's SSRF-guarded downloader, is refused with the same message the loader's fetch gives
/// that downloader directly, and nothing is written.
#[test]
fn the_roots_fetch_refuses_a_metadata_host_through_the_kernels_guard() {
    let dir = scratch("ssrf");
    let target = FetchTarget {
        url: "https://169.254.169.254/latest/plugin.tar.gz".into(),
        sha256: None,
        filename: "plugin.tar.gz".into(),
    };
    let guard = busbar_kernel::preflight::plugin_fetch_downloader(&[]);
    let via_root = plugins_fetch(&dir, &[target.clone()], true, &guard).unwrap_err();
    let spec = super::super::loader::FetchSpec {
        url: target.url.clone(),
        sha256: None,
        filename: target.filename.clone(),
    };
    let direct = super::super::loader::fetch_plugins(&dir, &[spec], true, &guard).unwrap_err();
    assert_eq!(via_root, direct);
    assert!(
        via_root[0].contains("blocked cloud-metadata host"),
        "{via_root:?}"
    );
    assert!(!dir.join("plugin.tar.gz").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
