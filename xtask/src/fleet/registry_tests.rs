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
