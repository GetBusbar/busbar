// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::libtest_path::{module_tree, resolve_cell};
use std::collections::BTreeMap;

/// A manifest in the composition root's shape: a default row that reaches a door row through
/// another feature, a door row on two axes, a section row, a driver-proofs row, and a row whose
/// feature is off.
const MANIFEST: &str = "\
[package]
name = \"c\"

[features]
default = [\"plane-x\", \"export-file\"]
plane-x = [\"plane-x-door\", \"dep:other\", \"k/plane-x\"]
plane-x-door = [\"dep:busbar-plane-x\"]
export-file = []
plane-y = [\"dep:busbar-plane-y\"]
test-harness = []

[package.metadata.busbar.linked]
plane-x-door = \"busbar-plane-x\"
plane-y = \"busbar-plane-y\"

[package.metadata.busbar.linked-axes]
plane-x-door = \"plane-door protocols\"
plane-y = \"plane-door node\"

[package.metadata.busbar.linked-section]
plane-x-door = \"pools\"
plane-y = \"agents\"

[package.metadata.busbar.driver-proofs]
plane-x-door = \"busbar-plane-x\"
";

fn build() -> CiBuild {
    CiBuild::of_manifest(MANIFEST).expect("the fixture manifest has a default row")
}

/// The default row's closure, and the cfgs build.rs would emit for it: the enabled rows' axes and
/// sections, the driver proofs; NOT the off row's `node` axis or `agents` section.
#[test]
fn the_ci_build_is_the_default_rows_closure_and_the_cfgs_its_rows_emit() {
    let b = build();
    for on in ["plane-x", "plane-x-door", "export-file"] {
        assert!(b.features.contains(on), "{on}");
    }
    for off in ["plane-y", "test-harness", "dep:other", "k/plane-x"] {
        assert!(!b.features.contains(off), "{off}");
    }
    for on in [
        "test",
        "linked_axis_plane_door",
        "linked_axis_protocols",
        "linked_section_pools",
        "linked_driver_proofs",
    ] {
        assert_eq!(b.eval(on), Tri::Yes, "{on}");
    }
    // RED, the shape status row 178 was: an axis no ENABLED row carries is OFF, not unknown.
    assert_eq!(b.eval("linked_axis_node"), Tri::No);
    assert_eq!(b.eval("all(test,linked_axis_node)"), Tri::No);
    assert_eq!(b.eval("linked_section_agents"), Tri::No);
    assert_eq!(b.eval("linked_every_plane_door"), Tri::No, "plane-y is off");
    assert_eq!(b.eval("feature=\"plane-x\""), Tri::Yes);
    assert_eq!(b.eval("feature=\"test-harness\""), Tri::No);
    assert_eq!(b.eval("not(feature=\"test-harness\")"), Tri::Yes);
    assert_eq!(
        b.eval("any(linked_axis_node,linked_section_pools)"),
        Tri::Yes
    );
    // A cfg this module does not derive is UNKNOWN, and stays unknown under `not`.
    assert_eq!(b.eval("miri"), Tri::Unknown);
    assert_eq!(b.eval("not(miri)"), Tri::Unknown);
    assert_eq!(b.eval("all(test,unix)"), Tri::Unknown);
    assert_eq!(
        b.eval("all(linked_axis_node,unix)"),
        Tri::No,
        "one off arm decides"
    );
    assert_eq!(b.eval("all(test"), Tri::Unknown, "unbalanced");
}

/// `linked_every_auth` (build.rs `AUTH_AXIS`, `auths`): on only while every row on that axis is
/// enabled. A cell under it once read UNKNOWN, refusing a cited test CI's build does run.
#[test]
fn every_auth_is_on_only_while_every_auths_row_is_enabled() {
    let manifest = |default: &str| {
        format!(
            "[features]\ndefault = [{default}]\nauth-a = []\nauth-b = []\n\n\
             [package.metadata.busbar.linked-axes]\nauth-a = \"auths\"\nauth-b = \"auths\"\n"
        )
    };
    let all = CiBuild::of_manifest(&manifest("\"auth-a\", \"auth-b\"")).expect("a default row");
    assert_eq!(all.eval("all(test,linked_every_auth)"), Tri::Yes);
    let one = CiBuild::of_manifest(&manifest("\"auth-a\"")).expect("a default row");
    assert_eq!(one.eval("linked_every_auth"), Tri::No, "auth-b is off");
}

#[test]
fn a_manifest_with_no_default_row_is_refused() {
    assert!(CiBuild::of_manifest("[features]\nx = []\n").is_err());
}

fn tree(files: &[(&str, &str)]) -> crate::libtest_path::ModuleTree {
    let map: BTreeMap<String, String> = files
        .iter()
        .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
        .collect();
    module_tree(&|p: &str| map.get(p).cloned(), "c/src/main.rs")
}

/// THE VERDICT over a resolved cell: green for a test under cfgs the build enables; red, naming
/// what keeps it out, for a module under an axis no enabled row carries (the 14 root-llm cells),
/// a fn-level cfg the build does not set, a helper with no test attribute, an ignored test, and a
/// cfg this module cannot answer.
#[test]
fn a_cited_cell_runs_only_under_cfgs_ci_enables_with_a_test_attribute_and_no_ignore() {
    let b = build();
    let t = tree(&[
        ("c/src/main.rs", "mod root;\nfn main() {}\n"),
        ("c/src/root/mod.rs", "pub mod node;\npub mod serve;\n"),
        (
            "c/src/root/node.rs",
            "#[cfg(all(test, linked_axis_node))]\n#[path = \"tests/node.rs\"]\nmod tests;\n",
        ),
        ("c/src/root/tests/node.rs", "#[tokio::test]\nasync fn a_node_cell() {}\n"),
        (
            "c/src/root/serve.rs",
            "#[cfg(all(test, linked_section_pools))]\n#[path = \"tests/serve.rs\"]\nmod door_tests;\n",
        ),
        (
            "c/src/root/tests/serve.rs",
            "#[cfg(linked_driver_proofs)]\n#[tokio::test(flavor = \"multi_thread\", worker_threads = 2)]\n\
             async fn a_door_cell() {}\n\
             #[cfg(feature = \"plane-y\")]\n#[test]\nfn an_off_feature_cell() {}\n\
             fn a_helper() {}\n\
             #[test]\n#[ignore = \"slow\"]\nfn an_ignored_cell() {}\n\
             #[cfg_attr(miri, ignore)]\n#[test]\nfn a_maybe_ignored_cell() {}\n\
             #[cfg(unix)]\n#[test]\nfn a_unix_cell() {}\n\
             #[cfg(linked_axis_plane_door)]\nmod inner {\n    #[test]\n    fn an_inner_cell() {}\n}\n",
        ),
    ]);
    let verdict = |file: &str, func: &str| resolve_cell(&t, file, func).and_then(|c| b.runs(&c));

    assert_eq!(verdict("c/src/root/tests/serve.rs", "a_door_cell"), Ok(()));
    assert_eq!(
        verdict("c/src/root/tests/serve.rs", "an_inner_cell"),
        Ok(())
    );

    let node = verdict("c/src/root/tests/node.rs", "a_node_cell").expect_err("node axis is off");
    assert!(
        node.contains("all(test,linked_axis_node)") && node.contains("root::node::tests"),
        "{node}"
    );
    let off = verdict("c/src/root/tests/serve.rs", "an_off_feature_cell").expect_err("feature off");
    assert!(off.contains("feature=\"plane-y\""), "{off}");
    let helper = verdict("c/src/root/tests/serve.rs", "a_helper").expect_err("no test attribute");
    assert!(helper.contains("no test attribute"), "{helper}");
    let ignored = verdict("c/src/root/tests/serve.rs", "an_ignored_cell").expect_err("ignored");
    assert!(ignored.contains("ignore"), "{ignored}");
    let maybe = verdict("c/src/root/tests/serve.rs", "a_maybe_ignored_cell").expect_err("miri?");
    assert!(maybe.contains("cfg_attr(miri,ignore)"), "{maybe}");
    let unix = verdict("c/src/root/tests/serve.rs", "a_unix_cell").expect_err("unknown cfg");
    assert!(unix.contains("cannot show"), "{unix}");
}

/// ANOTHER WORKSPACE MEMBER'S BUILD (status row 178): `cfg(test)`, its `default` closure and its
/// self dev-dependency's features are ON; a feature outside them is UNKNOWN (cargo unifies a
/// member's features across the `--workspace` run), never OFF; no `linked_*` cfg is set.
#[test]
fn a_member_build_is_its_default_and_self_dev_closure_and_other_features_are_unknown() {
    let b = CiBuild::of_member_manifest(
        "[package]\nname = \"k\"\n\n[features]\ndefault = [\"a\"]\na = [\"b\", \"dep:x\"]\nb = []\n\
         ts = [\"c\"]\nc = []\nfar = []\n\n[dev-dependencies]\n\
         k = { path = \".\", default-features = false, features = [\"ts\"] }\n\
         other = { path = \"../other\", features = [\"far\"] }\n",
    );
    for on in ["a", "b", "ts", "c"] {
        assert_eq!(b.eval(&format!("feature=\"{on}\"")), Tri::Yes, "{on}");
    }
    assert_eq!(b.eval("feature=\"far\""), Tri::Unknown);
    assert_eq!(b.eval("not(feature=\"far\")"), Tri::Unknown);
    assert_eq!(b.eval("test"), Tri::Yes);
    assert_eq!(b.eval("linked_axis_node"), Tri::No);
    assert_eq!(b.eval("loom"), Tri::Unknown);
    let none = CiBuild::of_member_manifest("[package]\nname = \"n\"\n");
    assert_eq!(none.eval("feature=\"x\""), Tri::Unknown);
    assert_eq!(none.eval("all(test,not(linked_driver_proofs))"), Tri::Yes);
}
