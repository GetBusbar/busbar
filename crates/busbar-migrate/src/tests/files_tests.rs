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
