// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE SOURCE FILE NAMES THE LOADER** (`BUSBAR-1.6.0.md` THE DESIGN, §3 Boot:
//! "`crates/busbar/src/root/boot.rs` is the one source file that names the loader").
//!
//! Every spelling of the loader crate's path, `<loader>::<item>`, in the composition root's source (its unit tests
//! excluded) is a row of [`SITES`], by file and item, with its count and the TODO step that removes
//! it. DRAIN-ONLY (ARCHITECT ruling 2026-09-28, BOOT-CHAIN (2)): a spelling no row holds fails; a
//! row whose spellings are gone fails until it is struck; a count that rose fails. `root/boot.rs`
//! is the one file that needs no row.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `(file under crates/busbar/src, item, count, the TODO step that removes it)`.
const SITES: &[(&str, &str, usize, &str)] = &[
    // BOOT-LOOP 10 (money: the kernel hands over the store seams).
    ("main.rs", "store_adapter", 2, "BL10"),
    ("root/keyset.rs", "store_adapter", 1, "BL10"),
    ("root/migration.rs", "store_adapter", 1, "BL10"),
    // BOOT-LOOP 8 (this step's structural move into root/boot.rs, after CONNECTOR-19 lands).
    ("main.rs", "sweep_dead_staging", 1, "BL8"),
    ("root/cli.rs", "inventory_tarballs", 1, "BL8"),
    ("root/linked.rs", "DynTransport", 2, "BL8"),
    ("root/linked.rs", "EgressCarrier", 1, "BL8"),
    ("root/linked.rs", "EgressPolicy", 10, "BL8"),
    ("root/linked.rs", "HighWaterMarks", 1, "BL8"),
    ("root/linked.rs", "install_egress_carrier", 1, "BL8"),
    ("root/linked.rs", "LinkedPlugin", 2, "BL8"),
    ("root/linked.rs", "observe", 1, "BL8"),
    ("root/linked.rs", "PluginRegistry", 8, "BL8"),
    ("root/linked.rs", "scan_and_validate", 2, "BL8"),
    ("root/linked.rs", "sign", 3, "BL8"),
    ("root/linked.rs", "supported_abi", 1, "BL8"),
    // TODO step 10 (BOOT-LOOP 6, money: the HOT adapter moves to the kernel).
    ("root/linked.rs", "DynPlane", 1, "step 10"),
    ("root/linked.rs", "HotReply", 4, "step 10"),
    ("root/linked.rs", "link_plane", 1, "step 10"),
    ("root/linked.rs", "ReplyStream", 4, "step 10"),
    ("root/linked.rs", "RequestHead", 1, "step 10"),
    ("root/linked.rs", "ServedPlane", 1, "step 10"),
    // BOOT-LOOP 9 (TransportRow; registry.rs's Row collapses).
    ("root/registry.rs", "DynTransport", 1, "BL9"),
    ("root/registry.rs", "WireTransport", 2, "BL9"),
];

/// The loader crate's path, as the source spells it.
const NEEDLE: &str = "busbar_plugin_loader::";

/// The file that names the loader by design.
const BOOT: &str = "root/boot.rs";

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read src").flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n != "tests") {
                walk(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `(file, item) -> count` of every [`NEEDLE`]`<item>` spelling: the first path segment
/// after the crate, each name of a braced list counted once.
fn measure(files: &[(String, String)]) -> BTreeMap<(String, String), usize> {
    let mut out = BTreeMap::new();
    for (file, text) in files {
        let mut rest = text.as_str();
        while let Some(i) = rest.find(NEEDLE) {
            rest = &rest[i + NEEDLE.len()..];
            let items: Vec<&str> = if let Some(list) = rest.strip_prefix('{') {
                let end = list.find('}').unwrap_or(list.len());
                list[..end]
                    .split(',')
                    .map(|s| {
                        s.split(|c: char| c == ':' || c.is_whitespace())
                            .find(|t| !t.is_empty())
                            .unwrap_or("")
                    })
                    .collect()
            } else {
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                vec![&rest[..end]]
            };
            for item in items.into_iter().filter(|s| !s.is_empty()) {
                *out.entry((file.clone(), item.to_string())).or_insert(0) += 1;
            }
        }
    }
    out
}

fn verdict(files: &[(String, String)]) -> Vec<String> {
    let got = measure(files);
    let mut problems = Vec::new();
    for ((file, item), n) in &got {
        if file == BOOT {
            continue;
        }
        match SITES.iter().find(|(f, i, _, _)| f == file && i == item) {
            None => problems.push(format!(
                "{file} names the loader's {item} ({n}x) and no row holds it: the loader is named only by {BOOT}"
            )),
            Some((_, _, want, _)) if n > want => problems.push(format!(
                "{file} names the loader's {item} {n}x, above its row's {want}"
            )),
            Some((_, _, want, step)) if n < want => problems.push(format!(
                "{file} names the loader's {item} {n}x, below its row's {want}: lower the row ({step})"
            )),
            Some(_) => {}
        }
    }
    for (file, item, _, step) in SITES {
        if !got.contains_key(&(file.to_string(), item.to_string())) {
            problems.push(format!(
                "{file} no longer names the loader's {item}: strike its row ({step})"
            ));
        }
    }
    problems
}

#[test]
fn the_loader_is_named_only_by_boot_and_the_named_remainder() {
    let root = src();
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    let files: Vec<(String, String)> = paths
        .iter()
        .map(|p| {
            (
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                std::fs::read_to_string(p).unwrap(),
            )
        })
        .collect();
    assert!(
        files.iter().any(|(f, _)| f == "main.rs"),
        "the walk found the source"
    );
    let problems = verdict(&files);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The ledger's own RED arms: a new site, a risen count and a drained row each fail.
#[test]
fn red_a_new_site_a_rise_and_an_unstruck_row_each_fail() {
    let base: Vec<(String, String)> = SITES
        .iter()
        .map(|(f, i, n, _)| (f.to_string(), format!("{NEEDLE}{i}; ").repeat(*n)))
        .collect();
    assert!(verdict(&base).is_empty(), "{:?}", verdict(&base));
    let mut new_site = base.clone();
    new_site.push((
        "root/adapters.rs".into(),
        format!("use {NEEDLE}{{PluginRegistry, scan_and_validate}};"),
    ));
    assert_eq!(verdict(&new_site).len(), 2);
    let mut rise = base.clone();
    rise[0].1.push_str(&format!("{NEEDLE}store_adapter::X"));
    assert!(verdict(&rise)[0].contains("above its row"));
    let drained: Vec<_> = base[1..].to_vec();
    assert!(verdict(&drained)
        .iter()
        .any(|p| p.contains("strike its row")));
    let mut boot = base;
    boot.push((BOOT.into(), format!("{NEEDLE}load(")));
    assert!(verdict(&boot).is_empty(), "{BOOT} names the loader freely");
}
