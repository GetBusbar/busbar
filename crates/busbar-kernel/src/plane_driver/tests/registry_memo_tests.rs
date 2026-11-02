// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

static ONE: PlaneDecl =
    crate::plane_driver::dispatch::neutral_sibling_decl("memo-one", "memo-one-section", "one");
static TWO: PlaneDecl =
    crate::plane_driver::dispatch::neutral_sibling_decl("memo-two", "memo-two-section", "two");

fn keys() -> Vec<&'static str> {
    plane_decls().iter().map(|d| d.key).collect()
}

#[test]
fn two_distinct_registration_sets_of_equal_size_do_not_alias() {
    const TEST: &str =
        "plane_driver::registry::registry_memo_tests::two_distinct_registration_sets_of_equal_size_do_not_alias";
    const CHILD: &str = "BUSBAR_REGISTRY_MEMO_CHILD";
    if std::env::var(CHILD).as_deref() != Ok(TEST) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, TEST)
            .output()
            .expect("the real registry test process starts");
        assert!(
            output.status.success(),
            "registry child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
        return;
    }
    {
        publish_planes(&[&ONE]);
        let k = keys();
        assert!(k.contains(&"memo-one"), "set {{ONE}} folds ONE: {k:?}");
        assert!(
            !k.contains(&"memo-two"),
            "set {{ONE}} does not fold TWO: {k:?}"
        );
    }
    {
        publish_planes(&[&TWO]);
        let k = keys();
        assert!(
            k.contains(&"memo-two"),
            "set {{TWO}} folds TWO, not the equal-size {{ONE}} fold: {k:?}"
        );
        assert!(
            !k.contains(&"memo-one"),
            "set {{TWO}} does not fold ONE: {k:?}"
        );
    }
    {
        publish_planes(&[&ONE]);
        let k = keys();
        assert!(k.contains(&"memo-one") && !k.contains(&"memo-two"), "{k:?}");
    }
}

#[test]
fn a_re_read_of_one_set_returns_the_one_leaked_fold() {
    const TEST: &str =
        "plane_driver::registry::registry_memo_tests::a_re_read_of_one_set_returns_the_one_leaked_fold";
    const CHILD: &str = "BUSBAR_REGISTRY_MEMO_CHILD";
    if std::env::var(CHILD).as_deref() != Ok(TEST) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, TEST)
            .output()
            .expect("the real registry test process starts");
        assert!(
            output.status.success(),
            "registry child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
        return;
    }
    publish_planes(&[&ONE, &TWO]);
    let a = plane_decls();
    let b = plane_decls();
    assert!(std::ptr::eq(a, b), "one set folds and leaks once");
}
