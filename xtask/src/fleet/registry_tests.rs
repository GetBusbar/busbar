//! `plugins.yaml` read as the plugin registry: the pin policy is required, and the committed
//! registry parses with the aliases the drop-in loader resolves by.

use super::registry::parse;
use crate::ctx::Ctx;

#[test]
fn a_registry_without_the_pin_policy_or_with_a_short_pin_is_refused() {
    assert!(parse("plugins:\n  - repo: x\n")
        .unwrap_err()
        .contains("no `fleet:` block"));
    let short = "fleet:\n  busbar_ref: \"0123456 1.6.0\"\n  name_pattern: \"^x$\"\n  branches: [dev]\nplugins:\n  - repo: x\n";
    assert!(parse(short)
        .unwrap_err()
        .contains("not a full 40-hex commit"));
}

#[test]
fn an_export_sinks_registry_alias_is_its_module_name() {
    // The dropped-in tarball resolves under the operator's `module:` spelling, exactly like the
    // linked row, only if the packed alias IS that module name.
    let text = Ctx::workspace().unwrap().read("plugins.yaml").unwrap();
    let fleet = parse(&text).expect("the committed plugins.yaml parses as a fleet");
    for (repo, module) in [
        ("busbar-export-file", "request-log-file"),
        ("busbar-export-webhook", "request-log-webhook"),
    ] {
        assert_eq!(fleet.plugin(repo).unwrap().alias, module, "{repo}");
    }
}

/// RED: a second row for one repo (the duplicated busbar-secret-env/-file rows predev carried) is
/// refused by name; the committed registry has one row per repo, alias and crate.
#[test]
fn a_duplicate_repo_row_is_refused() {
    let text = Ctx::workspace().unwrap().read("plugins.yaml").unwrap();
    parse(&text).expect("the committed plugins.yaml has one row per repo");
    let start = text
        .find("  - repo: busbar-secret-env\n")
        .expect("the env row");
    let end = text[start + 1..]
        .find("\n  - repo: ")
        .map(|i| start + 1 + i + 1)
        .expect("a row after it");
    let row = &text[start..end];
    let doubled = format!("{text}{}", row.trim_end_matches('\n').to_string() + "\n");
    let err = parse(&doubled).unwrap_err();
    assert!(err.contains("duplicate repo `busbar-secret-env`"), "{err}");
}

/// The plugin pin table, on segregation.rs's ORACLE_DATA_ALLOW (a read of data).
const PLUGIN_DIGESTS: &str = "testing/shadow-oracle/plugin-digests.tsv";

/// Every fault in `testing/shadow-oracle/plugin-digests.tsv`, read the way busbar-release's
/// `recorder::plugin_build` reads it (one row per line, tab-separated): a published row is `name, tag,
/// asset, 64-hex sha256[, line]`; a source row is `name, src:<40-hex commit>, build:<repo>, -, line`.
/// A source row that does not parse is not an error there: it is silently no pin, and `fetch-plugin`
/// on its line answers NoPin.
fn digest_row_faults(tsv: &str) -> Vec<String> {
    let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    let mut out = Vec::new();
    for (i, row) in tsv.lines().enumerate() {
        if row.is_empty() || row.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = row.split('\t').collect();
        let at = format!("line {}", i + 1);
        if !(4..=5).contains(&f.len()) {
            out.push(format!("{at}: {} fields, not 4 or 5", f.len()));
            continue;
        }
        if f[1].starts_with("src:") || f[2].starts_with("build:") {
            let commit = f[1].strip_prefix("src:").unwrap_or("");
            let repo = f[2].strip_prefix("build:").unwrap_or("");
            let repo_ok = !repo.is_empty()
                && repo
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
            if !hex(commit, 40) || !repo_ok || f.len() != 5 || f[4].is_empty() {
                out.push(format!(
                    "{at}: {} is not a source row (src:<40 hex>, build:<repo>, -, line)",
                    f[0]
                ));
            }
        } else if !hex(f[3], 64) {
            out.push(format!("{at}: {} has no 64-hex digest", f[0]));
        }
    }
    out
}

#[test]
fn every_plugin_digest_row_parses_and_the_sans_io_plugins_are_pinned_on_the_1_6_line() {
    let tsv = Ctx::workspace().unwrap().read(PLUGIN_DIGESTS).unwrap();
    assert_eq!(digest_row_faults(&tsv), Vec::<String>::new());
    // /status row 129: the sans-IO postgres, valkey and ldap heads are each one 1.6 source pin.
    for name in ["store-postgres", "store-valkey", "auth-ldap"] {
        let pins = tsv
            .lines()
            .filter(|r| r.starts_with(&format!("{name}\tsrc:")) && r.ends_with("\t1.6"))
            .count();
        assert_eq!(pins, 1, "{name}");
    }

    // RED: the shape #716 committed (the tab between the commit and `build:` dropped) is refused.
    let is_pg = |r: &str| r.starts_with("store-postgres\tsrc:");
    let row = tsv.lines().position(is_pg).unwrap();
    let joined: Vec<String> = tsv
        .lines()
        .map(|r| {
            if is_pg(r) {
                r.replacen("\tbuild:", "build:", 1)
            } else {
                r.to_string()
            }
        })
        .collect();
    assert_eq!(
        digest_row_faults(&joined.join("\n")),
        [format!(
            "line {}: store-postgres is not a source row (src:<40 hex>, build:<repo>, -, line)",
            row + 1
        )]
    );
}
