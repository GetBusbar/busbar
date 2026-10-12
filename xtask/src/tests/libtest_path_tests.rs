// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// A crate held in memory: repo-relative path -> text.
fn tree_of(files: &[(&str, &str)]) -> ModuleTree {
    let map: BTreeMap<String, String> = files
        .iter()
        .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
        .collect();
    module_tree(&|p: &str| map.get(p).cloned(), "c/src/main.rs")
}

/// The door shape: `serve.rs` carries `tests/serve_tests.rs` under ANOTHER module name through
/// `#[path]`, and the cell sits in an inline module of that file, beside literals and comments that
/// spell `mod` and braces.
fn door_tree() -> ModuleTree {
    tree_of(&[
        ("c/src/main.rs", "mod root;\nfn main() {}\n"),
        ("c/src/root/mod.rs", "pub mod serve;\n"),
        (
            "c/src/root/serve.rs",
            "pub fn serve() {}\n\
             #[cfg(test)]\n#[path = \"tests/serve.rs\"]\nmod tests;\n\
             // mod not_a_module;\n\
             #[cfg(all(test, linked_axis_node))]\n#[path = \"tests/serve_tests.rs\"]\nmod door_tests;\n",
        ),
        ("c/src/root/tests/serve.rs", "#[test]\nfn plain_cell() {}\n"),
        (
            "c/src/root/tests/serve_tests.rs",
            "use super::*;\n\
             #[cfg(feature = \"plane-decisions\")]\n\
             mod decisions_door {\n    #[tokio::test]\n    async fn a_decisions_cell() {\n        \
             let s = \"mod fake { fn a_door_cell() }\";\n        let c = '}';\n        \
             let q = '\\'';\n        let _ = (s, c, q);\n    }\n}\n\
             #[cfg(linked_plane_sections)]\n\
             mod agent_door {\n    fn helper<'a>(x: &'a str) -> &'a str { x }\n    \
             #[tokio::test]\n    async fn a_door_cell() {\n        /* } mod x { */\n        \
             assert_eq!(helper(r#\"}\"#), \"}\");\n    }\n}\n",
        ),
    ])
}

/// RED, the derivation this replaces: the file's NAME gave `root::serve_tests::tests::<fn>`, a
/// module no build carries, so `--root-legs` reported every door cell as absent. The source says
/// `root::serve::door_tests::<inline module>::<fn>`.
#[test]
fn a_path_carried_file_resolves_under_its_declared_module_and_inline_nesting() {
    let tree = door_tree();
    let got = resolve(&tree, "c/src/root/tests/serve_tests.rs", "a_door_cell");
    assert_eq!(
        got.as_deref(),
        Ok("root::serve::door_tests::agent_door::a_door_cell")
    );
    assert_ne!(
        got.as_deref(),
        Ok("root::serve_tests::tests::a_door_cell"),
        "the file-stem derivation names a module no build carries"
    );
    assert_eq!(
        resolve(&tree, "c/src/root/tests/serve_tests.rs", "a_decisions_cell").as_deref(),
        Ok("root::serve::door_tests::decisions_door::a_decisions_cell")
    );
    assert_eq!(
        resolve(&tree, "c/src/root/tests/serve.rs", "plain_cell").as_deref(),
        Ok("root::serve::tests::plain_cell")
    );
}

/// The three shapes the old derivation did get right still resolve to the same names: a sibling
/// file's tests, a directory module's own tests, and an inline `mod tests`. And a default-path child
/// of a non-mod-rs file sits under its stem directory.
#[test]
fn the_sibling_directory_and_inline_shapes_resolve_as_before() {
    let tree = tree_of(&[
        ("c/src/main.rs", "mod root;\n"),
        (
            "c/src/root/mod.rs",
            "pub mod gauntlet_kernel;\npub mod units_admin;\npub mod plane_node;\n",
        ),
        (
            "c/src/root/gauntlet_kernel.rs",
            "mod lines;\n#[cfg(test)]\n#[path = \"tests/gauntlet_kernel.rs\"]\nmod tests;\n",
        ),
        (
            "c/src/root/gauntlet_kernel/lines.rs",
            "#[cfg(test)]\nmod tests { #[test] fn a_line_cell() {} }\n",
        ),
        (
            "c/src/root/tests/gauntlet_kernel.rs",
            "#[test]\nfn a_kernel_cell() {}\n",
        ),
        (
            "c/src/root/units_admin/mod.rs",
            "#[cfg(test)]\n#[path = \"tests/units_admin.rs\"]\nmod tests;\n",
        ),
        (
            "c/src/root/units_admin/tests/units_admin.rs",
            "#[test]\nfn an_admin_cell() {}\n",
        ),
        (
            "c/src/root/plane_node.rs",
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn a_node_cell() {}\n}\n",
        ),
    ]);
    for (file, func, want) in [
        (
            "c/src/root/tests/gauntlet_kernel.rs",
            "a_kernel_cell",
            "root::gauntlet_kernel::tests::a_kernel_cell",
        ),
        (
            "c/src/root/units_admin/tests/units_admin.rs",
            "an_admin_cell",
            "root::units_admin::tests::an_admin_cell",
        ),
        (
            "c/src/root/plane_node.rs",
            "a_node_cell",
            "root::plane_node::tests::a_node_cell",
        ),
        (
            "c/src/root/gauntlet_kernel/lines.rs",
            "a_line_cell",
            "root::gauntlet_kernel::lines::tests::a_line_cell",
        ),
    ] {
        assert_eq!(
            resolve(&tree, file, func).as_deref(),
            Ok(want),
            "{file}::{func}"
        );
    }
}

/// AMBIGUITY IS REFUSED, NEVER GUESSED: a file the crate reaches under two module names, and a fn a
/// file defines under two inline modules, each name both.
#[test]
fn a_file_or_fn_reached_two_ways_is_refused_naming_both() {
    let tree = tree_of(&[
        ("c/src/main.rs", "mod root;\n"),
        (
            "c/src/root/mod.rs",
            "#[path = \"tests/shared.rs\"]\nmod one;\n#[path = \"tests/shared.rs\"]\nmod two;\n\
             #[path = \"tests/twice.rs\"]\nmod twice;\n",
        ),
        ("c/src/root/tests/shared.rs", "#[test]\nfn a_cell() {}\n"),
        (
            "c/src/root/tests/twice.rs",
            "mod a { #[test] fn a_cell() {} }\nmod b { #[test] fn a_cell() {} }\n",
        ),
    ]);
    let file =
        resolve(&tree, "c/src/root/tests/shared.rs", "a_cell").expect_err("two module paths");
    assert!(
        file.contains("AMBIGUOUS") && file.contains("root::one") && file.contains("root::two"),
        "{file}"
    );
    let func = resolve(&tree, "c/src/root/tests/twice.rs", "a_cell").expect_err("two nestings");
    assert!(
        func.contains("AMBIGUOUS") && func.contains("`a`") && func.contains("`b`"),
        "{func}"
    );
}

/// A file no declaration reaches, and a fn its file does not define, are refusals naming them.
#[test]
fn an_unreached_file_or_an_absent_fn_is_refused() {
    let tree = door_tree();
    let lost = resolve(&tree, "c/src/root/tests/orphan.rs", "a_cell").expect_err("unreached");
    assert!(
        lost.contains("orphan.rs") && lost.contains("no `mod` declaration"),
        "{lost}"
    );
    let gone =
        resolve(&tree, "c/src/root/tests/serve_tests.rs", "no_such_cell").expect_err("absent");
    assert!(gone.contains("no_such_cell"), "{gone}");
    assert!(
        resolve(&tree, "c/src/root/serve.rs", "not_a_module").is_err(),
        "a commented-out declaration is no module and no fn"
    );
}
