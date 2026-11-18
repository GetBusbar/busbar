// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-X1's checks: each one has a failing fixture (the check must find it) and a passing one (it must
//! not), and the two checks whose real tree is clean today run over it.

use std::collections::BTreeSet;
use std::path::Path;

use busbar_contract::json;

use super::core_scan::{identity_hits, module_values};
use super::core_src::{
    count_lines, export_stream_findings, licence_header, licence_rust, transport_findings,
};
use super::fleet::{alias_findings, fleet_findings, parse_registry, plugin_words};
use super::host_link::{banned_symbol, cdylib_packages, graph_findings, scan_object};
use super::plugin_rules::{
    banned_module_path, dep_findings, fs_findings, is_plugin_crate, loopback_findings,
};
use super::repo_root;
use super::supply::{
    core_patch_findings, manifest_findings, patch_drift, patch_entries, template_drift,
};

fn words(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|w| (*w).to_string()).collect()
}

// ---- fleet/deps.toml and plugins.yaml ------------------------------------------------------------------

const DEPS_OK: &str = r#"
[min3-closure]
plugin_busbar_dependency = "busbar-plugin-abi"
helper_busbar_dependency = "busbar-plugin-abi"
plugin_busbar_dev_dependency = "busbar-plugin-test"
forbidden_plugin_dependencies = ["busbar-contract", "plugin-loader", "busbar-kernel", "busbar-core-connector"]
"#;

fn yaml_with(ported: usize) -> String {
    let mut text = String::from("excluded_repos:\n  - hindsight-hook # docs\n  - busbar-hook-headroom\narchived_repos:\n  - busbar-transport-tcp\n  - busbar-transport-stdio\nplugins:\n");
    for index in 0..ported {
        text.push_str(&format!(
            "  - repo: busbar-store-p{index}\n    kind: store\n    alias: p{index}\n"
        ));
    }
    for repo in ["busbar-transport-tcp", "busbar-transport-stdio"] {
        text.push_str(&format!("  - repo: {repo}\n    kind: transport\n"));
    }
    text
}

#[test]
fn a_complete_fleet_manifest_is_clean() {
    assert_eq!(
        fleet_findings(DEPS_OK, &yaml_with(33)),
        Vec::<String>::new()
    );
}

#[test]
fn the_closure_table_is_required_and_exact() {
    let none = fleet_findings("schema = 1\n", &yaml_with(33));
    assert!(
        none.iter().any(|f| f.contains("no [min3-closure]")),
        "{none:?}"
    );
    let wrong = DEPS_OK.replace("busbar-plugin-test", "busbar-kernel");
    let found = fleet_findings(&wrong, &yaml_with(33));
    assert!(
        found
            .iter()
            .any(|f| f.contains("plugin_busbar_dev_dependency")),
        "{found:?}"
    );
    let open = DEPS_OK.replace("\"busbar-contract\", ", "");
    let found = fleet_findings(&open, &yaml_with(33));
    assert!(
        found.iter().any(|f| f.contains("lacks busbar-contract")),
        "{found:?}"
    );
}

#[test]
fn the_repo_list_counts_33_ported_two_archived_and_no_headroom_entry() {
    let found = fleet_findings(DEPS_OK, &yaml_with(32));
    assert!(
        found.iter().any(|f| f.contains("32 ported repos")),
        "{found:?}"
    );
    let no_archive = yaml_with(33).replace("archived_repos:", "other_repos:");
    let found = fleet_findings(DEPS_OK, &no_archive);
    assert!(
        found.iter().any(|f| f.contains("archived_repos")),
        "{found:?}"
    );
    let headroom = format!("{}  - repo: busbar-hook-headroom\n", yaml_with(33));
    let found = fleet_findings(DEPS_OK, &headroom);
    assert!(
        found
            .iter()
            .any(|f| f.contains("must have no manifest entry")),
        "{found:?}"
    );
    let unlisted = yaml_with(33).replace("  - busbar-hook-headroom\n", "");
    let found = fleet_findings(DEPS_OK, &unlisted);
    assert!(
        found
            .iter()
            .any(|f| f.contains("excluded_repos lacks busbar-hook-headroom")),
        "{found:?}"
    );
}

#[test]
fn the_registry_reads_aliases_and_former_names() {
    let yaml = "plugins:\n  - repo: busbar-secret-vault\n    alias: vault\n    former_names: [busbar-hashicorp-vault, vault2] # c\n    manifest_name: busbar-secret-vault-plugin\n";
    let registry = parse_registry(yaml);
    assert_eq!(registry.entries.len(), 1);
    assert_eq!(registry.entries[0].alias.as_deref(), Some("vault"));
    assert_eq!(
        registry.entries[0].former_names,
        ["busbar-hashicorp-vault", "vault2"]
    );
    let list = plugin_words(yaml, "# enterprise\nbusbar-ent-x\n");
    assert!(list.contains("busbar-secret-vault-plugin") && list.contains("busbar-ent-x"));
}

#[test]
fn c_alias_finds_a_header_missing_an_alias_or_a_former_name() {
    let yaml = "excluded_repos:\n  - busbar-hook-headroom\nplugins:\n  - repo: busbar-secret-vault\n    alias: vault\n    former_names: [busbar-hashicorp-vault]\n  - repo: busbar-hook-complexity\n    alias: complexity\n";
    let full = "busbar-secret-vault: vault, busbar-hashicorp-vault\n";
    assert!(alias_findings(yaml, full).is_empty());
    let missing = "busbar-secret-vault: vault\n";
    let found = alias_findings(yaml, missing);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("busbar-hashicorp-vault"));
    // No shipped image (busbar-hook-complexity): skipped, not a finding.
    let with_excluded = format!("{yaml}  - repo: busbar-hook-headroom\n");
    assert!(alias_findings(&with_excluded, full)
        .iter()
        .any(|f| f.contains("excluded repo must have no manifest entry")));
}

/// The real tree: fleet/deps.toml carries the closure and plugins.yaml the 33 + 2 + headroom shape.
#[test]
fn the_real_fleet_manifest_is_the_min3_closure() {
    let root = repo_root();
    let deps = std::fs::read_to_string(root.join("fleet/deps.toml")).expect("fleet/deps.toml");
    let yaml = std::fs::read_to_string(root.join("plugins.yaml")).expect("plugins.yaml");
    let found = fleet_findings(&deps, &yaml);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

// ---- template drift and patches ------------------------------------------------------------------------

const TEMPLATE: &str = r#"
[graph]
all-features = false
exclude-dev = true

[bans]
multiple-versions = "deny"
deny = [
    { crate = "openssl" },
]
skip = [
    { crate = "syn@2", reason = "x" },
]

[licenses]
allow = ["MIT"]
"#;

#[test]
fn a_deny_toml_equal_outside_skip_and_licenses_has_no_drift() {
    let plugin = TEMPLATE
        .replace("syn@2", "other@1")
        .replace("allow = [\"MIT\"]", "allow = [\"MIT\", \"ISC\"]");
    assert!(template_drift(TEMPLATE, &plugin, "p").is_empty());
}

#[test]
fn a_deny_toml_drifts_on_a_ban_a_graph_key_or_an_extra_table() {
    let ban = TEMPLATE.replace("{ crate = \"openssl\" },", "");
    assert!(template_drift(TEMPLATE, &ban, "p")
        .iter()
        .any(|f| f.contains("[bans]")));
    let dev = TEMPLATE.replace("exclude-dev = true", "exclude-dev = false");
    assert!(template_drift(TEMPLATE, &dev, "p")
        .iter()
        .any(|f| f.contains("exclude-dev")));
    let extra = format!("{TEMPLATE}\n[advisories]\nignore = []\n");
    assert!(template_drift(TEMPLATE, &extra, "p")
        .iter()
        .any(|f| f.contains("extra section")));
    let bad_template = TEMPLATE.replace("exclude-dev = true", "");
    assert!(template_drift(&bad_template, &bad_template, "t")
        .iter()
        .any(|f| f.contains("template deny.toml")));
}

#[test]
fn patch_entries_are_compared_per_port_crate() {
    let core = "[patch.crates-io]\nmysql_common = { git = \"https://github.com/g/mysql_common\", rev = \"abc\" }\n";
    let same = core.to_string();
    assert!(patch_drift(core, &same, "p").is_empty());
    let moved = core.replace("abc", "def");
    assert!(patch_drift(core, &moved, "p")
        .iter()
        .any(|f| f.contains("mysql_common")));
    assert!(patch_drift(core, "", "p")
        .iter()
        .any(|f| f.contains("core [patch]es mysql_common")));
    assert!(patch_drift("", core, "p")
        .iter()
        .any(|f| f.contains("core's root does not")));
    assert_eq!(patch_entries(core)["mysql_common"].1, "abc");
}

#[test]
fn a_port_crate_patched_in_core_must_be_a_gitlab_fork() {
    let github = "[patch.crates-io]\nmysql_common = { git = \"https://github.com/x/mysql_common\", rev = \"abc\" }\n";
    assert!(core_patch_findings(github)
        .iter()
        .any(|f| f.contains("GitLab")));
    let gitlab = github.replace("github.com/x", "github.com/GetBusbar");
    assert!(core_patch_findings(&gitlab).is_empty());
}

#[test]
fn a_patch_needs_an_upstream_pr_comment_and_a_path_stays_in_the_repo() {
    let root = Path::new("/r");
    let manifest = Path::new("/r/crates/x/Cargo.toml");
    let bare = "[patch.crates-io]\nfoo = { git = \"https://g/foo\", rev = \"1\" }\n";
    assert!(manifest_findings(root, manifest, bare)
        .iter()
        .any(|f| f.contains("upstream PR")));
    let commented = "[patch.crates-io]\n# upstream PR: https://github.com/o/foo/pull/9\nfoo = { git = \"https://g/foo\", rev = \"1\" }\n";
    assert!(manifest_findings(root, manifest, commented).is_empty());
    let outside = "[dependencies]\nfoo = { path = \"../../../vendor/foo\" }\n";
    assert!(manifest_findings(root, manifest, outside)
        .iter()
        .any(|f| f.contains("outside the repo")));
    let inside = "[dependencies]\nfoo = { path = \"../foo\" }\n";
    assert!(manifest_findings(root, manifest, inside).is_empty());
}

// ---- C-NO-HOST-LINK ---------------------------------------------------------------------------------------

#[test]
fn the_graph_check_finds_a_host_crypto_or_tls_package_and_the_host_feature() {
    let tree = "busbar-secret-env-plugin v1.0.0 (/r)|\nbusbar-plugin-abi v1.6.0 (/c)|memio\nzerocopy v0.8.0|simd\n";
    assert!(graph_findings("p", tree).is_empty());
    let host = "busbar-plugin-abi v1.6.0 (/c)|host,memio\n";
    assert!(graph_findings("p", host)
        .iter()
        .any(|f| f.contains("feature `host`")));
    for banned in [
        "busbar-crypto",
        "aws-lc-rs",
        "rustls",
        "busbar-contract",
        "plugin-loader",
        "busbar-plugin-test",
    ] {
        let tree = format!("{banned} v1.0.0 (/x)|\n");
        assert!(
            graph_findings("p", &tree)
                .iter()
                .any(|f| f.contains(banned)),
            "{banned}"
        );
    }
}

#[test]
fn the_symbol_patterns_catch_aws_lc_busbar_crypto_ring_and_rustls() {
    for name in [
        "aws_lc_0_1_ec_key_new",
        "AWS_LC_FIPS_x",
        "busbar_crypto_fill",
        "ring_core_0_17_8_p256",
        "_ZN7rustls4conn",
        "_ZN12busbar_crypto4fill",
    ] {
        assert!(banned_symbol(name), "{name}");
    }
    for name in ["busbar_plugin", "memcpy", "bb_host_random"] {
        assert!(!banned_symbol(name), "{name}");
    }
    assert!(scan_object(b"not an object file").is_err());
}

#[test]
fn the_cdylib_packages_are_the_ones_with_a_cdylib_target() {
    let meta: json::Value = json::parse_str(
        r#"{"packages":[{"name":"a-plugin","targets":[{"crate_types":["cdylib"]}]},{"name":"a","targets":[{"crate_types":["lib"]}]}]}"#,
    )
    .expect("json");
    assert_eq!(cdylib_packages(&meta), ["a-plugin"]);
}

// ---- plugin rules ----------------------------------------------------------------------------------------------

fn meta(deps: &str) -> json::Value {
    json::parse_str(&format!(
        r#"{{"packages":[
 {{"name":"busbar-store-x","dependencies":[{deps}]}},
 {{"name":"busbar-store-x-plugin","dependencies":[{{"name":"busbar-store-x","kind":null}},{{"name":"busbar-plugin-abi","kind":null,"features":[],"uses_default_features":true}}]}},
 {{"name":"busbar-helper","dependencies":[{{"name":"busbar-plugin-abi","kind":null,"features":[],"uses_default_features":true}}]}}
]}}"#
    ))
    .expect("json")
}

#[test]
fn plugin_crate_names_are_the_seven_kinds() {
    assert!(is_plugin_crate("busbar-store-memory") && is_plugin_crate("busbar-transport-ws"));
    assert!(
        !is_plugin_crate("busbar-plugin-abi")
            && !is_plugin_crate("busbar-helper")
            && !is_plugin_crate("storex")
    );
}

#[test]
fn rule_1a_allows_the_abi_the_repos_own_crates_and_a_kind_free_helper() {
    let ok = meta(
        r#"{"name":"busbar-plugin-abi","kind":null,"features":[],"uses_default_features":true},{"name":"busbar-helper","kind":null}"#,
    );
    assert!(
        dep_findings(&ok, true).is_empty(),
        "{:?}",
        dep_findings(&ok, true)
    );
}

#[test]
fn rule_1a_refuses_core_crates_other_plugins_and_a_helper_with_a_second_busbar_edge() {
    for (dep, needle) in [
        ("busbar-contract", "busbar-contract"),
        ("plugin-loader", "plugin-loader"),
        ("busbar-kernel-identity", "busbar-kernel-identity"),
        ("busbar-core-connector", "busbar-core-connector"),
        ("busbar-store-other", "another plugin crate"),
        ("busbar-something", "busbar-something"),
    ] {
        let bad = meta(&format!(
            r#"{{"name":"{dep}","kind":null,"features":[],"uses_default_features":true}}"#
        ));
        let found = dep_findings(&bad, true);
        assert!(found.iter().any(|f| f.contains(needle)), "{dep}: {found:?}");
    }
    let helper = json::parse_str::<json::Value>(
        r#"{"packages":[{"name":"busbar-store-x-plugin","dependencies":[{"name":"busbar-helper","kind":null}]},{"name":"busbar-helper","dependencies":[{"name":"busbar-contract","kind":null}]}]}"#,
    )
    .expect("json");
    assert!(dep_findings(&helper, true)
        .iter()
        .any(|f| f.contains("kind-free helper")));
}

#[test]
fn rule_3_refuses_the_host_feature_on_a_normal_edge() {
    let bad = meta(
        r#"{"name":"busbar-plugin-abi","kind":null,"features":["host"],"uses_default_features":true}"#,
    );
    assert!(dep_findings(&bad, false)
        .iter()
        .any(|f| f.contains("rule 3")));
}

#[test]
fn rule_1b_allows_only_plugin_test_as_a_direct_dev_edge_and_only_when_enabled() {
    let bad =
        meta(r#"{"name":"busbar-kernel","kind":"dev"},{"name":"plugin-loader","kind":"dev"}"#);
    let found = dep_findings(&bad, true);
    assert!(
        found.iter().any(|f| f.contains("busbar-kernel"))
            && found.iter().any(|f| f.contains("plugin-loader")),
        "{found:?}"
    );
    assert!(dep_findings(&bad, false).is_empty());
    // C-DEV-EDGES (IF §14): a dev edge on busbar-transport-http, busbar-kernel or busbar-core-connector each
    // fails the job on its own.
    for crate_name in [
        "busbar-transport-http",
        "busbar-kernel",
        "busbar-core-connector",
    ] {
        let one = meta(&format!(r#"{{"name":"{crate_name}","kind":"dev"}}"#));
        let found = dep_findings(&one, true);
        assert!(
            found.len() == 1 && found[0].contains(crate_name) && found[0].contains("rule 1b"),
            "{crate_name}: {found:?}"
        );
    }
    let ok = meta(r#"{"name":"busbar-plugin-test","kind":"dev"}"#);
    assert!(dep_findings(&ok, true).is_empty());
}

#[test]
fn rule_8_bans_four_module_names_under_src_only() {
    assert_eq!(
        banned_module_path("crates/x/src/legacy.rs").as_deref(),
        Some("legacy")
    );
    assert_eq!(
        banned_module_path("x/src/foo/historical/mod.rs").as_deref(),
        Some("historical")
    );
    assert_eq!(
        banned_module_path("x/src/migration.rs").as_deref(),
        Some("migration")
    );
    assert_eq!(
        banned_module_path("x/src/source_interpretation/a.rs").as_deref(),
        Some("source_interpretation")
    );
    assert_eq!(banned_module_path("x/src/legacy_wire.rs"), None);
    assert_eq!(banned_module_path("x/src/settings_migration.rs"), None);
    assert_eq!(banned_module_path("x/tests/migration.rs"), None);
    assert_eq!(banned_module_path("x/src/migrate.rs"), None);
}

#[test]
fn rule_9_finds_file_access_in_production_code_outside_the_two_repos() {
    let source = "use std::fs;\nfn a() { let _ = std::fs::read(\"x\"); }\nfn b(f: File) {}\nuse std::os::unix::fs::PermissionsExt;\nuse tokio::fs as tf;\n#[cfg(test)]\nmod tests { fn t() { std::fs::read(\"y\"); } }\n";
    let found = fs_findings(source, "src/lib.rs", false);
    let lines: Vec<&str> = found.iter().filter_map(|f| f.split(':').nth(1)).collect();
    assert_eq!(lines, ["1", "2", "3", "4", "5"], "{found:?}");
    assert!(fs_findings(source, "src/lib.rs", true).is_empty());
    assert!(fs_findings("mod fs { }\nfn f() { crate::fs::x(); }\n", "a.rs", false).is_empty());
}

#[test]
fn the_fleet_lint_finds_a_plugins_own_loopback_allowance() {
    let source = "fn is_loopback(h: &str) -> bool { true }\nconst U: &str = \"http://127.0.0.1:9\";\nfn reaches_loopback_only() {}\n#[test]\nfn t() { is_loopback(\"\"); }\n";
    let found = loopback_findings(source, "src/lib.rs");
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(loopback_findings("fn ok() { let u = \"https://example.com\"; }", "a.rs").is_empty());
}

// ---- the §15.8 core scan -----------------------------------------------------------------------------------------

fn hits(source: &str) -> Vec<(usize, String)> {
    identity_hits(
        source,
        &words(&["env", "busbar-secret-env", "sigv4", "memory"]),
    )
    .expect("parses")
}

#[test]
fn an_identity_comparison_with_a_plugin_word_is_a_hit() {
    let source = r#"
fn a(spec: &InstanceSpec) -> bool { spec.identity == "env" }
fn b(stamp: &Stamp) -> bool { "busbar-secret-env" != stamp.name }
fn c(caller: &Caller) -> bool { caller.name.eq_ignore_ascii_case("memory") }
fn d(x: &Admitted) -> bool { x.plugin.starts_with("sigv4") }
"#;
    let lines: Vec<usize> = hits(source).iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [2, 3, 4, 5], "{:?}", hits(source));
}

#[test]
fn a_match_arm_a_matches_macro_and_a_const_at_an_identity_site_are_hits() {
    let source = r#"
const WORD: &str = "env";
fn a(s: &Stamp) { match s.identity { "memory" | "other" => 1, _ => 2 }; }
fn b(s: &Stamp) -> bool { matches!(s.identity, "sigv4" | "x") }
fn c(s: &Stamp) -> bool { s.identity == WORD }
"#;
    let lines: Vec<usize> = hits(source).iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [3, 4, 5], "{:?}", hits(source));
}

#[test]
fn a_module_value_an_identity_field_and_outbound_owner_are_hits() {
    let source = r#"
fn a() -> &'static str { "store:\n  module: memory\n" }
fn b() -> Spec { Spec { identity: "env", n: 1 } }
fn c(styles: &S) { outbound_owner(styles, "sigv4"); }
fn d(v: &Value) -> bool { v.get("module") == Some("env") }
"#;
    let found = hits(source);
    let lines: Vec<usize> = found.iter().map(|(line, _)| *line).collect();
    assert!(
        lines.contains(&2) && lines.contains(&3) && lines.contains(&4),
        "{found:?}"
    );
    assert_eq!(module_values("module: env\n"), ["env"]);
    assert_eq!(module_values("{\"module\": \"vault\"}"), ["vault"]);
    assert_eq!(module_values("the module is"), Vec::<String>::new());
}

#[test]
fn a_module_key_in_config_text_is_a_hit_but_prose_naming_one_is_not() {
    // Real config uses: YAML block, list item, flow mapping, JSON key.
    assert_eq!(
        module_values("export:\n  metrics:\n    module: memory\n"),
        ["memory"]
    );
    assert_eq!(module_values("stores:\n  - module: env\n"), ["env"]);
    assert_eq!(module_values("store: {module: memory}"), ["memory"]);
    assert_eq!(module_values("[{\"module\": \"env\"}]"), ["env"]);
    // The verbatim 1.5.5 remedy prose (busbar-migrate legacy markers) names a config line; it is not one.
    assert_eq!(
        module_values("an `export:` instance with `module: memory` and `settings.url`"),
        Vec::<String>::new()
    );
    assert_eq!(
        module_values("a `module: env` / `module: memory` instance"),
        Vec::<String>::new()
    );
    assert_eq!(
        module_values("submodule: env\nfoo-module: env"),
        Vec::<String>::new()
    );
    let source = r#"
fn a() -> &'static str { "export:\n  m:\n    module: memory\n" }
const REMEDY: &str = "the `export:` map, a `module: memory` / `module: env` instance";
fn b() -> &'static str { "store:\n  - module: env\n" }
"#;
    let lines: Vec<usize> = hits(source).iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [2, 4], "{:?}", hits(source));
}

#[test]
fn a_word_elsewhere_and_test_code_are_not_hits() {
    let source = r#"
/// the env plugin, "memory" in a doc comment
fn a(x: &Other) -> bool { x.kind == "env" }
fn b() -> &'static str { "sigv4" }
fn c(spec: &InstanceSpec) -> bool { spec.identity == "unrelated" }
#[cfg(test)]
mod tests { fn t(s: &Stamp) -> bool { s.identity == "env" } }
#[test]
fn u(s: &Stamp) { assert!(s.identity == "env"); }
"#;
    assert!(hits(source).is_empty(), "{:?}", hits(source));
}

// ---- C-TRANSPORT test 11, C-EXPORT-STREAMS, C-NO-LICENCE ----------------------------------------------------

fn one(path: &str, source: &str) -> Vec<(String, String)> {
    vec![(path.to_string(), source.to_string())]
}

#[test]
fn transport_verdict_is_unique_kindless_and_the_only_admission_path() {
    let good = one(
        "crates/busbar-plugin-abi/src/host_side/caller.rs",
        "pub fn transport_verdict(accept: Accept, tls: u32, dest: &str) -> Verdict { v() }",
    );
    assert!(
        transport_findings(&good).is_empty(),
        "{:?}",
        transport_findings(&good)
    );
    let kind = one(
        "crates/a/src/x.rs",
        "pub fn transport_verdict(kind: u32, tls: u32) -> u32 { 0 }",
    );
    assert!(transport_findings(&kind)
        .iter()
        .any(|f| f.contains("kind or module parameter")));
    let twice = vec![
        good[0].clone(),
        (
            "crates/b/src/y.rs".to_string(),
            "fn transport_verdict() {}".to_string(),
        ),
    ];
    assert!(transport_findings(&twice)
        .iter()
        .any(|f| f.contains("defined 2 times")));
    assert!(transport_findings(&[])
        .iter()
        .any(|f| f.contains("defined 0 times")));
}

#[test]
fn plaintext_fields_loopback_calls_and_unix_kind_tests_are_findings() {
    let verdict = "fn transport_verdict(accept: Accept) {}\n";
    let field = format!(
        "{verdict}pub struct TlsDestinationCfg {{ pub matches: String, pub plaintext: bool }}"
    );
    assert!(transport_findings(&one("crates/k/src/tls.rs", &field))
        .iter()
        .any(|f| f.contains("TlsDestinationCfg")));
    let limits = format!("{verdict}fn f(c: &Cfg) -> bool {{ c.limits.plaintext }}");
    assert!(transport_findings(&one("crates/k/src/l.rs", &limits))
        .iter()
        .any(|f| f.contains("limits.plaintext")));
    let loopback = format!("{verdict}fn admit(h: &str) -> bool {{ names_loopback(h) }}");
    assert!(transport_findings(&one(
        "crates/busbar-plugin-abi/src/host_side/a.rs",
        &loopback
    ))
    .iter()
    .any(|f| f.contains("admission path")));
    assert!(
        transport_findings(&one("crates/busbar-core-connector/src/guard.rs", &loopback)).is_empty()
    );
    let unix = format!("{verdict}fn admit_unix(k: Kind) -> bool {{ k == Kind::Store }}");
    assert!(
        transport_findings(&one("crates/busbar-plugin-abi/src/host_side/u.rs", &unix))
            .iter()
            .any(|f| f.contains("unix admission"))
    );
}

#[test]
fn export_stream_is_defined_exactly_once() {
    let a = (
        "crates/c/src/export_stream.rs".to_string(),
        "pub enum ExportStream { Logs }".to_string(),
    );
    assert!(export_stream_findings(std::slice::from_ref(&a)).is_empty());
    let b = (
        "crates/abi/src/export.rs".to_string(),
        "pub enum ExportStream { Logs }".to_string(),
    );
    assert!(export_stream_findings(&[a.clone(), b])
        .iter()
        .any(|f| f.contains("2 times")));
    assert!(export_stream_findings(&[])
        .iter()
        .any(|f| f.contains("0 times")));
    let near = (
        "crates/c/src/n.rs".to_string(),
        "enum ExportStreams { A }\n// enum ExportStream".to_string(),
    );
    assert!(export_stream_findings(&[a, near]).is_empty());
}

/// The real tree: core defines the enum once.
#[test]
fn the_real_tree_defines_export_stream_once() {
    let found = super::core_src::export_streams(&repo_root()).expect("the tree reads");
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn licence_words_in_identifiers_literals_and_doc_comments_are_hits_but_plain_comments_are_not() {
    let source = "// a plain comment about licence\n/* entitlement */\nfn ok() {}\nfn licence_check() {}\nconst T: &str = \"licensed_to\";\n/// doc about a License\nfn documented() {}\n";
    let lines: Vec<usize> = licence_rust(source)
        .expect("lexes")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [4, 5, 6], "{lines:?}");
    assert!(licence_rust("fn clean() { let x = 1; } // licence")
        .expect("lexes")
        .is_empty());
}

#[test]
fn the_c_header_scan_skips_plain_comments_and_reads_doc_comments_and_code() {
    let source = "// SPDX-License-Identifier: Apache-2.0\n/* a licence note */\n#define OK 1\n/** documents the entitlement */\nint licence;\n/*\n multi licence\n*/\nint fine;\n";
    let lines: Vec<usize> = licence_header(source).iter().map(|(l, _)| *l).collect();
    assert_eq!(lines, [4, 5], "{lines:?}");
}

// ---- the LOC report ------------------------------------------------------------------------------------------------

#[test]
fn production_and_test_lines_are_counted_apart() {
    let source = "// comment\n\nfn a() {\n    1\n}\n#[cfg(test)]\nmod tests {\n    fn t() {\n        2\n    }\n}\nfn b() {}\n";
    assert_eq!(count_lines(source), (4, 6));
}
