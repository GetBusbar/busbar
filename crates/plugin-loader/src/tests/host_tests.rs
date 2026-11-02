// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-host-rotate-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_rotation_renames_the_live_file_and_keeps_its_archives() {
    let dir = scratch("keep");
    let log = dir.join("log");
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    let path = log.display().to_string();
    for line in ["a\n", "b\n", "c\n"] {
        std::fs::write(&log, line).unwrap();
        assert_eq!(rotate(std::path::Path::new(&path), 2), (true, Vec::new()));
    }
    assert_eq!(read(&dir.join("log.1")), "c\n");
    assert_eq!(read(&dir.join("log.2")), "b\n", "archives shift up");
    assert!(!dir.join("log.3").exists(), "keep 2 drops the oldest");
    assert!(!log.exists(), "the live file was renamed, not truncated");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_rename_is_a_recorded_fault() {
    let dir = scratch("missing");
    let path = dir.join("absent").display().to_string();
    assert_eq!(
        rotate(std::path::Path::new(&path), 2),
        (false, vec!["rename"])
    );
    let _ = std::fs::remove_dir_all(&dir);
}
