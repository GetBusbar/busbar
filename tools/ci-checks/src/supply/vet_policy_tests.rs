// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DEP-5 permits the existing aws-lc-rs and fastrand attestations, not new local audits.
//! Compare the entire active file, so alternate TOML spelling, delta/wildcard records, and
//! additional versions cannot evade the policy. The historical files are inert evidence;
//! cargo-vet must never import them. Imports and existing exemptions stay in their own files.

const CORE_HISTORY: &str =
    include_str!("../../../../supply-chain/history/core-audits-before-dep5-390.txt");
const DEFAULT_HISTORY: &str =
    include_str!("../../../../supply-chain/history/default-audits-before-dep5-390.txt");

// This extracts only fixed, canonical historical records. It is deliberately not a parser of
// the live policy: that file must equal these exact records, including their versions and notes.
fn grandfathered(history: &str, allowed: &[(&str, &str)]) -> String {
    let mut expected = String::from("\n# cargo-vet audits file\n\n");
    for (name, version) in allowed {
        let prefix = format!("{name}]]\ncriteria = \"safe-to-deploy\"\nversion = \"{version}\"\n");
        let records: Vec<_> = history
            .split("[[audits.")
            .skip(1)
            .filter(|record| record.starts_with(&prefix))
            .collect();
        assert_eq!(records.len(), 1, "historical {name} {version} record");
        expected.push_str("[[audits.");
        expected.push_str(records[0].trim_end());
        expected.push_str("\n\n");
    }
    expected
}

fn assert_store(path: &str, history: &str, allowed: &[(&str, &str)]) {
    let actual =
        std::fs::read_to_string(crate::repo_root().join(path)).expect("active audit store");
    assert_eq!(
        actual.trim_end(),
        grandfathered(history, allowed).trim_end(),
        "{path}: DEP-5 allows only the exact grandfathered local audits; use imported coverage, \
         trusted publishers, or a separately justified exemption for uncovered dependencies"
    );
}

#[test]
fn core_vet_policy_retains_only_exact_grandfathered_audits() {
    assert_store(
        "supply-chain/audits.toml",
        CORE_HISTORY,
        &[("aws-lc-rs", "1.19.0"), ("fastrand", "2.5.0")],
    );
}

#[test]
fn default_vet_policy_retains_only_exact_grandfathered_audits() {
    assert_store(
        "dist/default/supply-chain/audits.toml",
        DEFAULT_HISTORY,
        &[("aws-lc-rs", "1.19.0")],
    );
}
