//! The shared ledger's writer: `--write` regenerates a ledger the verdict then reads, so a row it
//! writes must hold the number its key has in the tree.

use super::*;

/// `--write` CARRIES EACH ROW'S COUNT (Law 9). A regenerated row with no `count` holds no number,
/// so a ledger rewritten by `--write` used to forgive every later site of every key it named.
#[test]
fn write_carries_each_rows_count() {
    let spec = Spec {
        gate: "planted",
        ledger: "qa/planted.toml",
        rules: &[("planted:rule", "a planted rule")],
        header: "# planted\n",
    };
    let at = |line| Finding::new("planted:rule", "crates/x/src/a.rs", "item", line);
    let text = render_ledger(&spec, &BTreeMap::new(), &[at(1), at(2)]);
    assert!(
        text.contains("count = 2"),
        "--write must carry the key's count of 2:\n{text}"
    );
}

/// `[ package ]` IS `[package]`: a header spelled with spaces names its crate (the census gap
/// kind-isolation closed, here in this gate's own reader). RED before the shared header reading:
/// the crate had no name.
#[test]
fn a_spaced_package_header_names_its_crate() {
    assert_eq!(
        package_name("[ package ]\nname = \"busbar-plane-spaced\"\n").as_deref(),
        Some("busbar-plane-spaced")
    );
    assert_eq!(package_name("[[bin]]\nname = \"tool\"\n"), None);
}
