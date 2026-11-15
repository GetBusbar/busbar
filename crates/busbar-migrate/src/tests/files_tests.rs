// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 1's in-place probes and 5b's `create_like`.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::scratch::Scratch;

#[test]
fn siblings_sit_beside_config_yaml() {
    assert_eq!(
        sibling(Path::new("/etc/busbar/config.yaml"), ".1.5.5"),
        Path::new("/etc/busbar/config.yaml.1.5.5")
    );
    assert_eq!(
        sibling(Path::new("config.yaml"), ".busbar-lock"),
        Path::new("config.yaml.busbar-lock")
    );
}

#[test]
fn the_in_place_probe_passes_in_a_writable_directory_and_leaves_nothing() {
    let scratch = Scratch::new();
    let path = scratch.config("listen: x\n");
    probe_in_place(&path).expect("writable in place");
    assert_eq!(scratch.names(), ["config.yaml"]);
}

#[test]
fn create_like_takes_the_source_mode_and_is_exclusive_per_process() {
    let scratch = Scratch::new();
    let path = scratch.config("listen: x\n");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let fresh = create_like(&path, b"config_version: 1\nlisten: x\n").unwrap();
    assert_eq!(
        std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert_eq!(
        std::fs::read(&fresh).unwrap(),
        b"config_version: 1\nlisten: x\n"
    );
    assert!(fresh
        .to_string_lossy()
        .ends_with(&format!("config.yaml.busbar-new.{}", std::process::id())));
}

/// 5b (coordinator ruling on r41 5b): `config.yaml.1.5.5` is a byte copy, never a link. It has its
/// own inode and config.yaml's mode, holds the source bytes, and an in-place rewrite of config.yaml
/// (an editor that writes through the open file) leaves it unchanged.
#[test]
fn the_backup_is_a_byte_copy_with_its_own_inode() {
    use std::os::unix::fs::MetadataExt;
    let scratch = Scratch::new();
    let source = "listen: x\n";
    let path = scratch.config(source);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let backup = sibling(&path, crate::BACKUP_SUFFIX);
    keep_backup(&path, &backup, source.as_bytes()).unwrap();
    let (kept, live) = (
        std::fs::metadata(&backup).unwrap(),
        std::fs::metadata(&path).unwrap(),
    );
    assert_ne!(kept.ino(), live.ino(), "the backup has its own inode");
    assert_eq!(kept.nlink(), 1, "the backup is not a link");
    assert_eq!(kept.permissions().mode() & 0o7777, 0o640);
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"config_version: 1\n"))
        .unwrap();
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), source);
    assert_eq!(scratch.names(), ["config.yaml", "config.yaml.1.5.5"]);
}
