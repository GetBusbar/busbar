// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRANSITIONAL: deleted when the kernel's plane driver serves the door's request path. Until the flip, the plane's door answers REFUSED on every
//! request-path op, so no production path may load it: the engine serves every request. This test
//! holds that. No production source outside this crate names the door; only the root's both-ways
//! test (`crates/busbar/tests/a2a_plane_door.rs`) and its example reach it.

use std::path::{Path, PathBuf};

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits in crates/")
        .to_path_buf()
}

/// Every `.rs` file under `dir` that is production source (a comment naming the door loads nothing): not under a `tests` directory, not a
/// `*_tests.rs` file.
fn production_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable").flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "tests" && name != "target" {
                production_sources(&path, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_production_path_loads_the_door_before_the_flip() {
    let own = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(crates_dir())
        .expect("crates/ is readable")
        .flatten()
    {
        let src = entry.path().join("src");
        if entry.path() != own && src.is_dir() {
            production_sources(&src, &mut sources);
        }
    }
    let offenders: Vec<String> = sources
        .iter()
        .filter(|p| {
            std::fs::read_to_string(p).is_ok_and(|t| {
                t.lines().any(|l| {
                    let l = l.trim_start();
                    !l.starts_with("//") && l.contains("plane_door::door")
                })
            })
        })
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        offenders.is_empty(),
        "production source loads the a2a door before its request path is served: {offenders:?}"
    );
}

#[test]
fn the_statement_names_the_crates_version() {
    assert_eq!(
        busbar_plane_a2a::plane_door::VERSION,
        env!("CARGO_PKG_VERSION")
    );
}
