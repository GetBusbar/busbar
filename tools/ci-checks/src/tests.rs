// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

use super::{
    backend_only_reached, crypto_graph, no_getrandom, reached, recorded_exceptions, repo_root,
    scan_source, SEAM_ONLY,
};

/// The seam-only crates in a `cargo tree --prefix depth` listing, through crypto_graph's own `reached`
/// call with no recorded exception.
fn seam_only_reached(tree: &str) -> Vec<String> {
    reached(
        tree,
        &SEAM_ONLY,
        "outside busbar-crypto*",
        &std::collections::BTreeMap::new(),
    )
    .0
}

#[test]
fn shipped_graph_cannot_hide_crypto_outside_the_root_workspace() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypto-graph");
    let findings = crypto_graph(&root).expect("local resolver fixture");
    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("ring v0.1.0")),
        "shipped crypto must be detected even when the root graph is clean: {findings:?}"
    );
}

/// The real tree: core's feature-resolved graph builds ring, sha2, ed25519-dalek and curve25519-dalek
/// only beneath the seam, and curve25519-dalek only beneath the backend.
#[test]
fn the_root_graph_builds_seam_only_crypto_beneath_busbar_crypto_alone() {
    let findings = crypto_graph(&repo_root()).expect("cargo tree resolves the root workspace");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// The real tree: no first-party production code outside the seam names getrandom.
#[test]
fn no_first_party_code_names_getrandom_outside_the_seam() {
    let findings = no_getrandom(&repo_root()).expect("the crates tree scans");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

#[test]
fn production_getrandom_sites_are_found_and_test_code_is_not() {
    let source = r#"
use getrandom::fill;
// getrandom::fill in a comment
const DOC: &str = "getrandom::fill";
fn production(buf: &mut [u8]) { getrandom::fill(buf).ok(); }
fn in_macro() { println!("{:?}", getrandom::u64()); }
#[cfg(test)]
mod tests { fn helper() { getrandom::fill(&mut [0; 4]).ok(); } }
#[test]
fn a_test() { getrandom::fill(&mut [0; 4]).ok(); }
#[cfg(all(test, unix))]
fn unix_test_helper() { getrandom::fill(&mut [0; 4]).ok(); }
#[cfg(any(test, feature = "test-support"))]
fn feature_helper() { getrandom::fill(&mut [0; 4]).ok(); }
fn other_crate() { my::getrandom::fill(); getrandom(); }
extern crate getrandom;
"#;
    let scan = scan_source(Path::new("/r/crates/x/src/lib.rs"), source);
    let lines: Vec<usize> = scan.hits.iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [2, 5, 6, 14, 16]);
}

#[test]
fn a_whole_file_under_cfg_test_is_test_code() {
    let scan = scan_source(
        Path::new("/r/crates/x/src/lib.rs"),
        "#![cfg(test)]\nfn helper() { getrandom::fill(&mut [0; 4]).ok(); }\n",
    );
    assert!(scan.hits.is_empty());
}

#[test]
fn a_file_syn_cannot_parse_is_scanned_by_line() {
    let scan = scan_source(
        Path::new("/r/crates/x/src/lib.rs"),
        "fn broken( {\n// getrandom::fill\n    getrandom::fill(buf);\n",
    );
    let lines: Vec<usize> = scan.hits.iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [3]);
}

#[test]
fn module_files_declared_under_cfg_test_are_test_code() {
    let scan = scan_source(
        Path::new("/r/crates/x/src/engine.rs"),
        "#[cfg(test)]\nmod tests;\nmod live;\n#[cfg(test)]\n#[path = \"engine_more.rs\"]\nmod more;\n\
         #[cfg(test)]\nmod inline { mod deep; }\n",
    );
    let covered = |file: &str| {
        scan.test_modules
            .iter()
            .any(|module| module.covers(Path::new(file)))
    };
    assert!(covered("/r/crates/x/src/engine/tests.rs"));
    assert!(covered("/r/crates/x/src/engine/tests/mod.rs"));
    assert!(covered("/r/crates/x/src/engine/tests/cases.rs"));
    assert!(covered("/r/crates/x/src/engine_more.rs"));
    assert!(covered("/r/crates/x/src/engine/inline/deep.rs"));
    assert!(!covered("/r/crates/x/src/engine/live.rs"));
    assert!(!covered("/r/crates/x/src/engine.rs"));
}

const TREE: &str = "0app v1.0.0 (/r/app)\n1reqwest v0.12.28\n2rustls v0.23.46\n3ring v0.17.14\n\
                    3aws-lc-rs v1.16.0\n1tokio v1.53.3\n2ring v0.17.14 (*)\n\n0other v1.0.0 (/r/other)\n\
                    1sha2-like v0.1.0\n";

#[test]
fn seam_only_crypto_built_outside_the_seam_is_named_with_its_path() {
    assert_eq!(
        seam_only_reached(TREE),
        ["ring v0.17.14 is built outside busbar-crypto*: app -> reqwest -> rustls -> ring"]
    );
}

#[test]
fn a_graph_without_seam_only_crypto_is_clean() {
    let clean = TREE
        .replace("3ring v0.17.14\n", "")
        .replace("2ring v0.17.14 (*)\n", "");
    assert!(seam_only_reached(&clean).is_empty());
}

/// The facade's graph with the backend pruned: curve25519-dalek reached from the facade itself is
/// named with its path (a FIPS build, which swaps only the backend, would link it); reached only
/// through the pruned backend, it is not listed at all.
#[test]
fn a_backend_only_crate_reached_from_the_facade_is_named_with_its_path() {
    const FACADE: &str = "0busbar-crypto v1.6.0 (/r/crates/busbar-crypto)\n\
                          1busbar-crypto-backend v1.6.0 (/r/crates/busbar-crypto-backend)\n\
                          1helper v0.1.0\n2curve25519-dalek v4.1.3\n1zeroize v1.8.2\n";
    assert_eq!(
        backend_only_reached(FACADE),
        ["curve25519-dalek v4.1.3 is built by busbar-crypto outside busbar-crypto-backend, so a \
          swapped-in (FIPS) backend would link it: busbar-crypto -> helper -> curve25519-dalek"]
    );
    let clean = FACADE.replace("2curve25519-dalek v4.1.3\n", "");
    assert!(backend_only_reached(&clean).is_empty());
}

/// Postgres SCRAM (#289): `postgres-protocol` builds `sha2`, `hmac` and `md-5` itself, so a graph
/// that reaches `hmac` or `md-5` outside the seam is a seam bypass exactly as `sha2` is. The
/// backend is pruned from the listing, so its own `md-5` (the Q9a legacy exception) never shows.
#[test]
fn rustcrypto_macs_and_md5_built_outside_the_seam_are_named_with_their_paths() {
    const SHIPPED: &str = "0busbar-default v1.6.0 (/r/dist/default)\n\
                           1busbar-store-postgres v0.1.0\n\
                           2postgres-protocol v0.6.12\n\
                           3hmac v0.12.1\n3md-5 v0.10.6\n3sha2 v0.10.9\n";
    assert_eq!(
        seam_only_reached(SHIPPED),
        [
            "hmac v0.12.1 is built outside busbar-crypto*: busbar-default -> busbar-store-postgres -> postgres-protocol -> hmac",
            "md-5 v0.10.6 is built outside busbar-crypto*: busbar-default -> busbar-store-postgres -> postgres-protocol -> md-5",
            "sha2 v0.10.9 is built outside busbar-crypto*: busbar-default -> busbar-store-postgres -> postgres-protocol -> sha2",
        ]
    );
}

const RECORDED_DENY: &str = r#"
[bans]
deny = [
    # { crate = "commented", wrappers = ["x"], reason = "tracked: a#1" },
    { crate = "hmac", wrappers = ["postgres-protocol"], reason = "SCRAM, tracked: busbar-store-postgres#11" },
    { crate = "aes", wrappers = ["busbar-transport-webrtc", "other"], reason = "tracked: busbar-transport-webrtc#13" },
    { crate = "sha2", wrappers = ["postgres-protocol"], reason = "a ban exception with no issue" },
    { crate = "ring@0.16", reason = "no wrappers" }, { crate = "boring" },
]
"#;

#[test]
fn recorded_exceptions_are_the_deny_rows_that_name_wrappers_and_an_issue() {
    let recorded = recorded_exceptions(RECORDED_DENY);
    assert_eq!(
        recorded.keys().map(String::as_str).collect::<Vec<_>>(),
        ["aes", "hmac"]
    );
    assert_eq!(recorded["hmac"].issue, "busbar-store-postgres#11");
    assert_eq!(recorded["hmac"].parents, ["postgres-protocol"]);
    assert_eq!(
        recorded["aes"].parents,
        ["busbar-transport-webrtc", "other"]
    );
}

/// A recorded crate under its recorded parent passes and is listed with its issue; an unrecorded
/// crate, a recorded crate under another parent, and a crate whose row has no issue all fail.
#[test]
fn an_unrecorded_crate_fails_and_a_recorded_one_passes_and_is_listed() {
    const SHIPPED: &str = "0busbar-default v1.6.0 (/r/dist/default)\n\
                           1busbar-store-postgres v0.1.0\n\
                           2postgres-protocol v0.6.12\n\
                           3hmac v0.12.1\n3sha2 v0.10.9\n\
                           1busbar-transport-webrtc v0.1.0\n2aes v0.8.4\n\
                           1other-plugin v0.1.0\n2hmac v0.12.1\n2ring v0.17.14\n";
    let recorded = recorded_exceptions(RECORDED_DENY);
    let (failures, tracked) = reached(SHIPPED, &SEAM_ONLY, "outside busbar-crypto*", &recorded);
    assert_eq!(
        failures,
        [
            "sha2 v0.10.9 is built outside busbar-crypto*: busbar-default -> busbar-store-postgres -> postgres-protocol -> sha2",
            "hmac v0.12.1 is built outside busbar-crypto*: busbar-default -> other-plugin -> hmac",
            "ring v0.17.14 is built outside busbar-crypto*: busbar-default -> other-plugin -> ring",
        ]
    );
    assert_eq!(
        tracked,
        [
            "hmac v0.12.1 is built outside busbar-crypto*: busbar-default -> busbar-store-postgres -> postgres-protocol -> hmac (tracked: busbar-store-postgres#11)",
            "aes v0.8.4 is built outside busbar-crypto*: busbar-default -> busbar-transport-webrtc -> aes (tracked: busbar-transport-webrtc#13)",
        ]
    );
}

/// One source: the real deny.toml records the postgres-protocol and WebRTC exceptions with their issues.
#[test]
fn the_real_deny_toml_records_the_postgres_and_webrtc_exceptions() {
    let deny = std::fs::read_to_string(repo_root().join("deny.toml")).expect("deny.toml");
    let recorded = recorded_exceptions(&deny);
    for name in ["hmac", "md-5", "sha2"] {
        assert!(
            recorded[name]
                .parents
                .contains(&"postgres-protocol".to_string())
                && recorded[name].issue == "busbar-store-postgres#11",
            "{name}: {:?}",
            recorded.get(name)
        );
    }
    for name in ["ring", "aes"] {
        assert!(
            recorded[name]
                .parents
                .contains(&"busbar-transport-webrtc".to_string())
                && recorded[name].issue == "busbar-transport-webrtc#13",
            "{name}: {:?}",
            recorded.get(name)
        );
    }
    assert_eq!(recorded["cipher"].parents, ["aes"]);
}

/// The packages that may list `busbar-seal`, the crate whose two free functions mint every capability
/// seal: the kernel, which mints, and the contract, which re-exports the two seal TYPES only.
const SEAL_HOLDERS: [&str; 2] = ["busbar-contract", "busbar-kernel"];

/// The packages that may list `busbar-kernel`. The kernel's `seal` module is public, so each of these can
/// obtain a seal; every other crate cannot name one.
const KERNEL_DEPENDENTS: [&str; 8] = [
    "busbar",
    "busbar-core-admin",
    "busbar-core-connector",
    "busbar-core-oauth2",
    "busbar-default",
    "busbar-migrate",
    "busbar-oracle-blackbox",
    "busbar-plugin-test",
];

/// Every `Cargo.toml` in the repository (separate workspaces included), skipping build output.
fn every_manifest(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !matches!(name.as_str(), "target" | ".git" | "vendor" | "node_modules") {
                every_manifest(&path, out);
            }
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// Whether a manifest's `text` names `krate` in any dependency table (normal, dev, build, target-gated),
/// by key (`krate = ..`, `krate.path = ..`), by table (`[dependencies.krate]`) or by rename
/// (`package = "krate"`).
fn names_dependency(text: &str, krate: &str) -> bool {
    let mut section = String::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            section = line.to_string();
            let inner = line.trim_matches(|c| c == '[' || c == ']');
            if inner.contains("dependencies") && inner.rsplit('.').next() == Some(krate) {
                return true;
            }
            continue;
        }
        if !section.contains("dependencies") {
            continue;
        }
        let key = line.split('=').next().unwrap_or_default().trim();
        if key == krate
            || key
                .strip_prefix(krate)
                .is_some_and(|rest| rest.starts_with('.'))
            || line.contains(&format!("package = \"{krate}\""))
        {
            return true;
        }
    }
    false
}

/// The `[package]` name of a manifest.
fn package_name(text: &str) -> Option<String> {
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(value) = line.strip_prefix("name") {
                let value = value.trim_start();
                if let Some(value) = value.strip_prefix('=') {
                    return Some(value.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

/// The `wrappers` of `deny.toml`'s `[bans] deny` row for `krate`.
fn deny_wrappers(deny: &str, krate: &str) -> Option<Vec<String>> {
    let needle = format!("crate = \"{krate}\"");
    let row = deny.lines().map(str::trim).find(|line| {
        !line.starts_with('#') && line.contains(&needle) && line.contains("wrappers")
    })?;
    let list = row.split("wrappers = [").nth(1)?.split(']').next()?;
    let mut wrappers: Vec<String> = list
        .split(',')
        .map(|name| name.trim().trim_matches('"').to_string())
        .filter(|name| !name.is_empty())
        .collect();
    wrappers.sort();
    Some(wrappers)
}

/// Who can mint a capability is decided by manifests, and these two lists say exactly who: a crate that
/// does not list `busbar-seal` cannot name its mint (the compiler refuses it), and a crate that lists
/// neither `busbar-seal` nor `busbar-kernel` cannot obtain a seal at all. `deny.toml` carries both rows
/// (cargo-deny's `wrappers`); this test holds the rows to the lists and walks every manifest in the
/// repository, so a new dependent fails here even where cargo-deny does not run.
#[test]
fn only_the_named_crates_may_depend_on_the_seal_and_the_kernel() {
    let root = repo_root();
    let deny = std::fs::read_to_string(root.join("deny.toml")).expect("deny.toml");
    let mut manifests = Vec::new();
    every_manifest(&root, &mut manifests);
    assert!(
        manifests.len() > 20,
        "the manifest walk found {} Cargo.toml files: it is broken, and a broken walk proves nothing",
        manifests.len()
    );
    for (krate, allowed) in [
        ("busbar-seal", &SEAL_HOLDERS[..]),
        ("busbar-kernel", &KERNEL_DEPENDENTS[..]),
    ] {
        let mut allowed: Vec<String> = allowed.iter().map(|name| name.to_string()).collect();
        allowed.sort();
        assert_eq!(
            deny_wrappers(&deny, krate),
            Some(allowed.clone()),
            "deny.toml must carry the row `{{ crate = \"{krate}\", wrappers = {allowed:?} }}`"
        );
        let mut found: Vec<String> = manifests
            .iter()
            .filter_map(|manifest| {
                let text = std::fs::read_to_string(manifest).ok()?;
                names_dependency(&text, krate)
                    .then(|| package_name(&text).unwrap_or_else(|| manifest.display().to_string()))
            })
            .collect();
        found.sort();
        found.dedup();
        assert_eq!(
            found, allowed,
            "the manifests that list {krate} are not the ones allowed to"
        );
    }
}

/// The walk's reader, on the forms a manifest can name a dependency in.
#[test]
fn a_dependency_is_found_by_key_table_and_rename_and_nowhere_else() {
    let k = "busbar-seal";
    assert!(names_dependency(
        "[dependencies]\nbusbar-seal = { path = \"x\" }\n",
        k
    ));
    assert!(names_dependency(
        "[dev-dependencies]\nbusbar-seal.path = \"x\"\n",
        k
    ));
    assert!(names_dependency(
        "[target.'cfg(unix)'.dependencies.busbar-seal]\npath = \"x\"\n",
        k
    ));
    assert!(names_dependency(
        "[dependencies]\nseal = { package = \"busbar-seal\", path = \"x\" }\n",
        k
    ));
    assert!(!names_dependency("[features]\nbusbar-seal = []\n", k));
    assert!(!names_dependency(
        "[dependencies]\nbusbar-seal-extra = \"1\"\n",
        k
    ));
    assert!(!names_dependency("[package]\nname = \"busbar-seal\"\n", k));
    assert_eq!(
        deny_wrappers(
            "deny = [\n    { crate = \"a\", wrappers = [\"y\", \"x\"], reason = \"r\" },\n]\n",
            "a"
        ),
        Some(vec!["x".to_string(), "y".to_string()])
    );
}
