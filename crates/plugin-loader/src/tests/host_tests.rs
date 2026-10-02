// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's acts for a cold sink (K9a S4): what a destination binds to, and what each act does
//! to the files — the rotation is the request-log file sink's rename rotation, step for step.

use super::*;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-host-ops-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bound(path: &Path) -> Destinations {
    let settings = serde_json::json!({ "path": path.display().to_string(), "other": "/etc/x" });
    Destinations::bind(&["path".to_string()], &settings.to_string()).expect("binds")
}

fn write_op(data: &str, rotate_at: Option<u64>) -> HostOp {
    HostOp::Write {
        destination: "path".into(),
        data: data.into(),
        rotate_at,
        keep: 2,
    }
}

/// Only a DECLARED key the operator SET is a destination: an undeclared settings key naming a path
/// is not one, and a declared key set to a non-path refuses the bind naming it.
#[test]
fn a_destination_is_a_declared_key_the_operator_set() {
    let dir = scratch("bind");
    let d = bound(&dir.join("log"));
    let undeclared = HostOp::Flush {
        destination: "other".into(),
    };
    assert!(matches!(
        d.perform(&undeclared),
        HostResult::Failed { step, .. } if step == "destination"
    ));
    let unset =
        Destinations::bind(&["path".to_string()], "{}").expect("an unset key binds nothing");
    assert!(matches!(
        unset.perform(&write_op("x", None)),
        HostResult::Failed { .. }
    ));
    let refused =
        Destinations::bind(&["path".to_string()], r#"{"path": 7}"#).expect_err("not a path");
    assert_eq!(refused, "settings.path: a destination must be a path");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Writes APPEND; a write that finds the file at its `rotate_at` rotates FIRST (the line lands in
/// the fresh file), keeping `keep` archives and dropping the oldest.
#[test]
fn a_write_appends_and_rotates_first_at_its_limit_keeping_its_archives() {
    let dir = scratch("rotate");
    let log = dir.join("log");
    let d = bound(&log);
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    assert_eq!(
        d.perform(&write_op("a\n", Some(4))),
        HostResult::Done { rotation: None }
    );
    assert_eq!(
        d.perform(&write_op("b\n", Some(4))),
        HostResult::Done { rotation: None }
    );
    let HostResult::Done { rotation: Some(r) } = d.perform(&write_op("c\n", Some(4))) else {
        panic!("the third write rotates first");
    };
    assert!(r.renamed && r.faults.is_empty(), "{r:?}");
    assert_eq!(r.archive, format!("{}.1", log.display()));
    assert_eq!(
        (read(&log), read(&dir.join("log.1"))),
        ("c\n".into(), "a\nb\n".into())
    );
    d.perform(&write_op("d\n", Some(2)));
    d.perform(&write_op("e\n", Some(2)));
    assert_eq!(read(&dir.join("log.2")), "c\n", "archives shift up");
    assert_eq!(read(&dir.join("log.1")), "d\n");
    assert_eq!(read(&log), "e\n");
    assert!(!dir.join("log.3").exists(), "keep 2 drops the oldest");
    assert_eq!(
        d.perform(&HostOp::Flush {
            destination: "path".into()
        }),
        HostResult::Done { rotation: None }
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A write whose path cannot be opened is a reported failure naming the step, never a panic.
#[test]
fn an_unopenable_destination_is_a_reported_failure() {
    let dir = scratch("unopenable");
    let d = bound(&dir.join("missing-dir").join("log"));
    assert!(matches!(
        d.perform(&write_op("x", None)),
        HostResult::Failed { step, .. } if step == "open"
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
