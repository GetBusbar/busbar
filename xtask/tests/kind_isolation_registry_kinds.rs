//! KIND-ISOLATION READS THE REGISTRY'S KIND WORDS ONTO ITS OWN KIND TABLE (row 159, audit XC2#2).
//!
//! `plugins.yaml` files both hook plugins as `kind: hook`; the instance axis is `hooks`. The
//! instance census compared the two words as written, so every hook alias was dropped without a
//! word and a core crate dispatching on a hook plugin's name was invisible to `kind-isolation:law0`
//! (BUSBAR-1.6.0.md: "The instance census must read plugins.yaml aliases and manifest names, so it
//! can see external plugins"). A registry kind word the table maps onto nothing was skipped the
//! same way; it is refused.
//!
//! Both plants go over the real tree. The hook aliases are read off the committed `plugins.yaml`,
//! never typed here, and written as values by a neutral core crate that names no hook instance
//! today, so that cell's Law 0 figure is exactly the number of aliases. The unmapped entry is
//! planted into the registry's `plugins:` list, and the `* × unattributed` cell counts it.

use std::path::PathBuf;

use xtask::ctx::{Ctx, Overlay};
use xtask::gates::execute;
use xtask::gates::kind_isolation::KindIsolationGate;

const REGISTRY: &str = "plugins.yaml";
const CORE_PLANT: &str = "crates/busbar-core-connector/src/planted_hook_aliases.rs";
const HOOK_CELL: &str = "busbar-core-connector \u{d7} instance:hooks";
const UNATTRIBUTED_CELL: &str = "* \u{d7} unattributed";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

/// Every `alias:` of a `plugins.yaml` entry filed `kind: hook`, three characters or longer (the
/// gate's needle floor).
fn hook_aliases(registry: &str) -> Vec<String> {
    let (mut out, mut kind, mut alias) = (Vec::new(), None::<String>, None::<String>);
    let mut flush = |kind: &mut Option<String>, alias: &mut Option<String>| {
        if let (Some(k), Some(a)) = (kind.take(), alias.take()) {
            if k == "hook" && a.chars().count() >= 3 {
                out.push(a);
            }
        }
    };
    for raw in registry.lines() {
        let t = raw.trim();
        let entry = t.strip_prefix("- ");
        if entry.is_some() {
            flush(&mut kind, &mut alias);
        }
        let Some((key, val)) = entry.unwrap_or(t).split_once(':') else {
            continue;
        };
        let val = val.trim().trim_matches('"').to_string();
        match key.trim() {
            "kind" => kind = Some(val),
            "alias" => alias = Some(val),
            _ => {}
        }
    }
    flush(&mut kind, &mut alias);
    out
}

#[test]
fn the_registry_hook_aliases_reach_the_hooks_axis_and_an_unmapped_kind_is_refused() {
    let cx = Ctx::new(repo_root())
        .and_then(|cx| cx.with_pinned_planes())
        .expect("the real tree opens with a writable scratch dir and its pinned planes");
    let registry = cx.read(REGISTRY).expect("plugins.yaml reads");
    let aliases = hook_aliases(&registry);
    assert!(
        !aliases.is_empty(),
        "plugins.yaml files no `kind: hook` alias: this test has nothing to plant"
    );

    let mut ov = Overlay::new();
    let body: String = aliases
        .iter()
        .enumerate()
        .map(|(i, a)| format!("pub const PLANTED_HOOK_{i}: &str = \"{a}\";\n"))
        .collect();
    ov.set(CORE_PLANT, body);
    let at = registry
        .find("\nplugins:\n")
        .expect("plugins.yaml has a top-level `plugins:` list")
        + "\nplugins:\n".len();
    ov.set(
        REGISTRY,
        format!(
            "{}  - repo: busbar-plantedkind-zorblat\n    kind: plantedkind\n    alias: zorblat\n    \
             crate: busbar-plantedkind-zorblat-plugin\n{}",
            &registry[..at],
            &registry[at..]
        ),
    );

    let verdict = execute(&KindIsolationGate::check(), &cx.with_overlay(ov));
    let law0 = verdict
        .rows
        .iter()
        .find(|r| r.id == "kind-isolation:law0")
        .expect("kind-isolation:law0 was not emitted");
    let cell = |key: &str| law0.cells.iter().find(|c| c.key == key);

    let hooks = cell(HOOK_CELL).unwrap_or_else(|| {
        panic!(
            "the core crate writing the hook aliases {aliases:?} raised no `{HOOK_CELL}` cell: \
             the registry's `kind: hook` never reached the `hooks` axis. {}",
            law0.detail
        )
    });
    assert_eq!(
        hooks.figure,
        Some(aliases.len() as u64),
        "{HOOK_CELL}: {}",
        hooks.detail
    );

    let unattributed = cell(UNATTRIBUTED_CELL).unwrap_or_else(|| {
        panic!(
            "a registry entry filed `kind: plantedkind` raised no `{UNATTRIBUTED_CELL}` cell: a \
             kind word the table maps onto nothing was skipped, not refused. {}",
            law0.detail
        )
    });
    assert!(
        unattributed.figure.is_some_and(|n| n >= 1),
        "{UNATTRIBUTED_CELL}: {}",
        unattributed.detail
    );
}
