// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{install, MIGRATION_ROWS};

fn golden(n: usize) -> serde_yaml::Value {
    let doc: serde_yaml::Value = serde_yaml::from_str(include_str!("fixtures/retired_1_5_5.yaml"))
        .expect("the golden parses");
    doc["retired"][n].clone()
}

fn field(v: &serde_yaml::Value, k: &str) -> String {
    v[k].as_str()
        .unwrap_or_else(|| panic!("golden `{k}` is a string"))
        .to_string()
}

fn retired_word_meets_its_1_5_5_bytes(n: usize) {
    install();
    let g = golden(n);
    let (word, module) = (field(&g, "word"), field(&g, "module"));
    assert!(
        MIGRATION_ROWS
            .iter()
            .any(|(k, v)| *k == format!("retired.store.{word}") && *v == module),
        "the root migration table carries no `retired.store.{word}` row answering to `{module}`"
    );
    let raw = format!(
        "store:\n  module: {word}\n  settings: {{ url: \"kv://127.0.0.1:6379/0\" }}\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n"
    );

    let out = busbar_kernel::config::migrate::migrate_config(&raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("the output parses");
    assert_eq!(doc["store"]["module"].as_str(), Some(module.as_str()));
    assert_eq!(
        doc["store"]["settings"]["url"].as_str(),
        Some("kv://127.0.0.1:6379/0"),
        "the settings ride through verbatim"
    );
    assert!(
        out.changes.contains(&field(&g, "change")),
        "the change line is not 1.5.5's:\n{:#?}",
        out.changes
    );

    let dir = std::env::temp_dir().join(format!(
        "busbar-migration-{n}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("config.yaml");
    std::fs::write(&path, &raw).expect("write config");
    let refused = busbar_kernel::load_config_from_disk(
        &path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
    )
    .err()
    .expect("a retired spelling refuses boot");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        refused.contains(&format!("  - {}\n", field(&g, "marker"))),
        "the boot refusal does not carry 1.5.5's marker:\n{refused}"
    );
}

#[test]
fn retired_word_1_meets_its_1_5_5_bytes() {
    retired_word_meets_its_1_5_5_bytes(0);
}

#[test]
fn retired_word_2_meets_its_1_5_5_bytes() {
    retired_word_meets_its_1_5_5_bytes(1);
}

#[test]
fn retired_word_3_meets_its_1_5_5_bytes() {
    retired_word_meets_its_1_5_5_bytes(2);
}

fn observability_golden() -> serde_yaml::Value {
    serde_yaml::from_str(include_str!(
        "../../../../../testing/shadow-oracle/fixtures/migrate-observability-1.5.5.yaml"
    ))
    .expect("the golden parses")
}

fn bullets(text: &str, head: &str, bullet: &str) -> Vec<String> {
    text.lines()
        .skip_while(|l| !l.starts_with(head))
        .skip(usize::from(!head.is_empty()))
        .take_while(|l| head.is_empty() || !l.trim().is_empty())
        .filter_map(|l| l.strip_prefix(bullet).map(str::to_string))
        .collect()
}

#[test]
fn the_observability_lift_out_meets_its_1_5_5_bytes() {
    install();
    let g = observability_golden();
    let text = |k: &str| field(&g, k);
    let raw = text("config");

    let out = busbar_kernel::config::migrate::migrate_config(&raw).expect("migrates");
    let changes = bullets(&text("migrate_stderr"), "CHANGES (", "  - ");
    assert!(
        !changes.is_empty(),
        "the golden carries 1.5.5's change lines"
    );
    for want in changes {
        assert!(
            out.changes.contains(&want),
            "no 1.5.5 change line `{want}`:\n{:#?}",
            out.changes
        );
    }
    let todos = bullets(&text("migrate_stderr"), "TODO (", "  * ");
    assert!(!todos.is_empty(), "the golden carries 1.5.5's TODO");
    for want in todos {
        assert!(
            out.todos.contains(&want),
            "no 1.5.5 TODO `{want}`:\n{:#?}",
            out.todos
        );
    }
    let was: serde_yaml::Value =
        serde_yaml::from_str(&text("migrate_stdout")).expect("1.5.5's document parses");
    let now: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("the output parses");
    for (key, value) in was.as_mapping().expect("1.5.5's document is a map") {
        assert_eq!(
            now.get(key),
            Some(value),
            "`{key:?}` of the migrated document is not 1.5.5's:\n{}",
            out.yaml
        );
    }

    let dir = std::env::temp_dir().join(format!(
        "busbar-migration-obs-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("config.yaml");
    std::fs::write(&path, &raw).expect("write config");
    let refused = busbar_kernel::load_config_from_disk(
        &path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
    )
    .err()
    .expect("a 1.x config refuses boot");
    let _ = std::fs::remove_dir_all(&dir);
    let markers = bullets(&text("validate_stderr"), "", "  - ");
    assert!(!markers.is_empty(), "the golden carries 1.5.5's markers");
    for marker in markers {
        assert!(
            refused.contains(&format!("  - {marker}\n")),
            "the boot refusal does not carry 1.5.5's marker `{marker}`:\n{refused}"
        );
    }

    let hints = g["hints"].as_sequence().expect("golden `hints`");
    assert!(!hints.is_empty(), "the golden carries 1.5.5's hints");
    for row in hints {
        let stderr = field(row, "stderr");
        let old = stderr
            .split_once("unknown field `")
            .and_then(|(_, rest)| rest.split_once('`'))
            .map(|(old, _)| old)
            .expect("1.5.5 refused an unknown field");
        let hint = stderr
            .find("\n  hint: ")
            .map(|at| stderr[at..].trim_end_matches('\n'))
            .expect("1.5.5 printed a hint");
        let msg = format!("unknown field `{old}`");
        assert_eq!(
            busbar_kernel::config::augment_config_error(&msg),
            format!("{msg}{hint}"),
            "the `{old}` hint is not 1.5.5's"
        );
    }
}

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const REGISTRY: &str = include_str!("../../../../../plugins.yaml");
const HEADER: &str = "[package.metadata.busbar.migration]";
const NOTE: &str = "# THE ROOT MIGRATION TABLE (BUSBAR-1.6.0.md §2), @generated from plugins.yaml (`migration:` and each\n\
# entry's `retired:` and `former_names:`); src/root/tests/migration_table.rs is red on an edit and prints the\n\
# render to paste.\n\
# build.rs emits it as `MIGRATION_ROWS`, which the root hands to the kernel before any config is read.\n";

fn text(v: &serde_yaml::Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_string)
}

fn rows(registry: &str) -> Vec<(String, String)> {
    let doc: serde_yaml::Value = serde_yaml::from_str(registry).expect("plugins.yaml parses");
    let mut out: Vec<(String, String)> = doc["migration"]
        .as_mapping()
        .map(|m| {
            m.iter()
                .map(|(k, v)| {
                    let k = k.as_str().expect("a `migration:` key is a string");
                    let v = v.as_str().unwrap_or_else(|| {
                        panic!("plugins.yaml migration: `{k}` must be a string")
                    });
                    (k.to_string(), v.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    for p in doc["plugins"].as_sequence().expect("`plugins:`") {
        let former: Vec<&str> = p["former_names"]
            .as_sequence()
            .map(|s| {
                s.iter()
                    .map(|w| w.as_str().expect("a `former_names:` word is a string"))
                    .collect()
            })
            .unwrap_or_default();
        if !former.is_empty() {
            let alias = text(p, "alias").expect("`alias`");
            out.push((format!("former.{alias}"), former.join(" ")));
        }
        let Some(retired) = p["retired"].as_sequence() else {
            continue;
        };
        let repo = text(p, "repo").expect("`repo`");
        let (kind, alias) = (
            text(p, "kind").expect("`kind`"),
            text(p, "alias").expect("`alias`"),
        );
        for word in retired {
            let word = word.as_str().expect("a `retired:` word is a string");
            out.push((format!("retired.{kind}.{word}"), alias.clone()));
        }
        out.push((
            format!("manifest.{alias}"),
            text(p, "manifest_name").unwrap_or_else(|| repo.clone()),
        ));
        out.push((
            format!("asset.{alias}"),
            text(p, "asset_prefix").unwrap_or(repo),
        ));
    }
    out
}

fn render(registry: &str) -> String {
    let mut s = format!("{HEADER}\n{NOTE}");
    for (k, v) in rows(registry) {
        let v = v.replace('\\', "\\\\").replace('"', "\\\"");
        s.push_str(&format!("\"{k}\" = \"{v}\"\n"));
    }
    s
}

fn table(manifest: &str) -> String {
    let lines: Vec<&str> = manifest.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim() == HEADER)
        .unwrap_or_else(|| panic!("dist/default/Cargo.toml carries no `{HEADER}`"));
    let mut end = lines[start + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map_or(lines.len(), |i| start + 1 + i);
    while end > start + 1 && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    lines[start..end].iter().map(|l| format!("{l}\n")).collect()
}

fn drift(manifest: &str, registry: &str) -> Option<String> {
    let want = render(registry);
    (table(manifest) != want).then(|| {
        format!(
            "dist/default/Cargo.toml: `{HEADER}` is not the render of plugins.yaml; replace it with:\n\n{want}"
        )
    })
}

#[test]
fn the_committed_migration_table_is_the_render() {
    if let Some(reason) = drift(MANIFEST, REGISTRY) {
        panic!("{reason}");
    }
}

#[test]
fn a_linked_plugin_reads_its_former_names_by_its_alias() {
    install();
    assert_eq!(
        busbar_kernel::config::migration_table::former_names("webrequest"),
        ["busbar-webrequest"]
    );
    assert!(
        busbar_kernel::config::migration_table::former_names("planted-never-renamed").is_empty()
    );
}
