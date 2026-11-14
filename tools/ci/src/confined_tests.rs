//! Tests for the controller's path confinement (`confined.rs`): `..`, absolute, NUL,
//! symlink-escape and zip-slip names refuse with their typed error before any write.
use crate::confined::{Error, Root, Trusted, check_relative};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("busbar-ci-confined-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("root")).unwrap();
    fs::create_dir_all(dir.join("outside")).unwrap();
    fs::write(dir.join("outside/secret"), b"secret").unwrap();
    dir
}

#[test]
fn lexical_escapes_refuse_with_their_own_error() {
    assert_eq!(
        check_relative(Path::new("../x")),
        Err(Error::ParentTraversal)
    );
    assert_eq!(
        check_relative(Path::new("bundles/../../x")),
        Err(Error::ParentTraversal)
    );
    assert_eq!(
        check_relative(Path::new("/etc/passwd")),
        Err(Error::Absolute)
    );
    assert_eq!(check_relative(Path::new("a\0b")), Err(Error::Nul));
    assert_eq!(check_relative(Path::new("")), Err(Error::Empty));
    assert_eq!(check_relative(Path::new("./.")), Err(Error::Empty));
    assert_eq!(check_relative(Path::new("bundles/a/b.json")), Ok(()));
}

#[test]
fn names_resolve_open_and_create_only_under_the_root() {
    let dir = scratch("plain");
    let root = Root::new(&dir.join("root")).unwrap();
    root.create_new(Path::new("bundles/a/b.json"), 0o600)
        .unwrap()
        .write_all(b"inside")
        .unwrap();
    let mut text = String::new();
    root.open(Path::new("bundles/a/b.json"))
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "inside");
    assert!(
        root.resolve(Path::new("bundles/a/b.json"))
            .unwrap()
            .starts_with(root.as_path())
    );
    // Never adopts an existing name.
    assert!(
        root.create_new(Path::new("bundles/a/b.json"), 0o600)
            .is_err()
    );
    assert_eq!(
        root.open(Path::new("../outside/secret")).unwrap_err(),
        Error::ParentTraversal
    );
    assert_eq!(
        root.create_new(&dir.join("outside/new"), 0o600)
            .unwrap_err(),
        Error::Absolute
    );
    assert!(!dir.join("outside/new").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_symlinked_final_component_refuses() {
    let dir = scratch("symlink-final");
    std::os::unix::fs::symlink(dir.join("outside/secret"), dir.join("root/evil")).unwrap();
    let root = Root::new(&dir.join("root")).unwrap();
    assert_eq!(root.open(Path::new("evil")).unwrap_err(), Error::Symlink);
    assert_eq!(
        root.create_new(Path::new("evil"), 0o600).unwrap_err(),
        Error::Symlink
    );
    assert_eq!(fs::read(dir.join("outside/secret")).unwrap(), b"secret");
    fs::remove_dir_all(dir).unwrap();
}

/// Zip-slip through a planted directory link: `link/file` is lexically clean, but writing it
/// would land outside the destination.
#[test]
fn a_symlinked_parent_that_escapes_the_root_refuses() {
    let dir = scratch("symlink-parent");
    std::os::unix::fs::symlink(dir.join("outside"), dir.join("root/link")).unwrap();
    let root = Root::new(&dir.join("root")).unwrap();
    assert_eq!(
        root.create_new(Path::new("link/planted"), 0o600)
            .unwrap_err(),
        Error::Escapes
    );
    assert_eq!(
        root.create_new(Path::new("link/deeper/planted"), 0o600)
            .unwrap_err(),
        Error::Escapes
    );
    assert_eq!(
        root.open(Path::new("link/secret")).unwrap_err(),
        Error::Escapes
    );
    assert!(!dir.join("outside/planted").exists());
    assert!(!dir.join("outside/deeper").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn trusted_paths_are_named_not_validated() {
    let path = Path::new("/var/lib/busbar-ci/tool.tar");
    assert_eq!(Trusted::internal(path).as_path(), path);
}
