// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn list_reports_unparseable_suites_yaml() {
    let d = std::env::temp_dir().join(format!("hammer-list-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("suites.yaml"), "default: [a, b\n").unwrap();
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_busbar-system-hammer"))
        .args(["--list", "--scenarios"])
        .arg(&d)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("suites.yaml"));
}
