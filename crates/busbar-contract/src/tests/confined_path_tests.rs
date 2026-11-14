// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the path-confinement helper in `crates/busbar-contract/src/confined_path.rs`: every
//! escape form (`..`, absolute, NUL, symlink, zip-slip through a planted directory link) refuses
//! with its typed error, and a plain relative name opens under the root.

use crate::confined_path::{check_relative, ConfinedPathError, ConfinedRoot, TrustedPath};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-confined-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("root")).unwrap();
    std::fs::create_dir_all(dir.join("outside")).unwrap();
    std::fs::write(dir.join("outside/secret"), b"secret").unwrap();
    dir
}

#[test]
fn lexical_escapes_refuse_with_their_own_error() {
    assert!(matches!(
        check_relative(Path::new("../secret")),
        Err(ConfinedPathError::ParentTraversal)
    ));
    assert!(matches!(
        check_relative(Path::new("a/../../secret")),
        Err(ConfinedPathError::ParentTraversal)
    ));
    assert!(matches!(
        check_relative(Path::new("/etc/passwd")),
        Err(ConfinedPathError::Absolute)
    ));
    assert!(matches!(
        check_relative(Path::new("a\0b")),
        Err(ConfinedPathError::Nul)
    ));
    assert!(matches!(
        check_relative(Path::new("")),
        Err(ConfinedPathError::Empty)
    ));
    assert!(matches!(
        check_relative(Path::new(".")),
        Err(ConfinedPathError::Empty)
    ));
    assert!(check_relative(Path::new("plugin.tar.gz")).is_ok());
    assert!(check_relative(Path::new("bundles/a/b.json")).is_ok());
}

#[test]
fn a_plain_name_resolves_and_opens_under_the_root() {
    let dir = scratch("plain");
    std::fs::write(dir.join("root/plugin.tar.gz"), b"bytes").unwrap();
    let root = ConfinedRoot::new(dir.join("root")).unwrap();
    let path = root.resolve("plugin.tar.gz").unwrap();
    assert!(path.starts_with(root.as_path()));
    let mut text = String::new();
    std::io::Read::read_to_string(&mut root.open("plugin.tar.gz").unwrap(), &mut text).unwrap();
    assert_eq!(text, "bytes");
    // A missing name still resolves (callers create it), and opening it is a plain NotFound.
    assert!(root.resolve("missing.tar.gz").is_ok());
    let missing = root.open("missing.tar.gz").unwrap_err();
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn dot_dot_and_absolute_names_never_reach_the_filesystem() {
    let dir = scratch("lexical");
    let root = ConfinedRoot::new(dir.join("root")).unwrap();
    assert!(matches!(
        root.open("../outside/secret"),
        Err(ConfinedPathError::ParentTraversal)
    ));
    let absolute = dir.join("outside/secret");
    assert!(matches!(
        root.open(&absolute),
        Err(ConfinedPathError::Absolute)
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_symlinked_final_component_refuses_even_when_its_target_is_inside() {
    let dir = scratch("symlink-final");
    std::os::unix::fs::symlink(dir.join("outside/secret"), dir.join("root/evil.tar.gz")).unwrap();
    std::fs::write(dir.join("root/real"), b"inside").unwrap();
    std::os::unix::fs::symlink(dir.join("root/real"), dir.join("root/alias")).unwrap();
    let root = ConfinedRoot::new(dir.join("root")).unwrap();
    assert!(matches!(
        root.open("evil.tar.gz"),
        Err(ConfinedPathError::Symlink)
    ));
    assert!(matches!(
        root.open("alias"),
        Err(ConfinedPathError::Symlink)
    ));
    let error: std::io::Error = root.open("evil.tar.gz").unwrap_err().into();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Zip-slip through a planted directory link: `link/secret` is lexically clean, but `link` points
/// outside the root, so the resolved parent escapes and the name refuses before any open.
#[cfg(unix)]
#[test]
fn a_symlinked_parent_that_escapes_the_root_refuses() {
    let dir = scratch("symlink-parent");
    std::os::unix::fs::symlink(dir.join("outside"), dir.join("root/link")).unwrap();
    let root = ConfinedRoot::new(dir.join("root")).unwrap();
    assert!(matches!(
        root.resolve("link/secret"),
        Err(ConfinedPathError::Escapes)
    ));
    assert!(matches!(
        root.open("link/secret"),
        Err(ConfinedPathError::Escapes)
    ));
    assert!(matches!(
        root.resolve("link/new/deeper"),
        Err(ConfinedPathError::Escapes)
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_root_that_is_not_a_directory_refuses() {
    let dir = scratch("root-file");
    assert!(ConfinedRoot::new(dir.join("outside/secret")).is_err());
    assert!(ConfinedRoot::new(dir.join("absent")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_trusted_directory_opens_for_its_durability_barrier() {
    let dir = scratch("trusted");
    let trusted = TrustedPath::internal(&dir);
    assert_eq!(trusted.as_path(), dir.as_path());
    trusted.open_dir().unwrap();
    assert!(TrustedPath::internal(&dir.join("outside/secret"))
        .open_dir()
        .is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
