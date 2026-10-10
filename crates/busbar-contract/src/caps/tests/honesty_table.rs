// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! caps/mod.rs's honesty table names only types that exist (items 319, 327). It is that file's own ground
//! truth for what is enforced, so a type it names has to be a type a real signature takes.

/// The pre-#73 proof-type names, none of which survives as a type — read from the one list
/// that defines them, `seal-witness`'s `ZOO` (xtask/src/gates/seal_witness.rs), rather than
/// spelled here: that gate scans test code and string literals, so a second copy of the names
/// in this file would be the very survival it reports. Its scan strips comments, which is why
/// this test exists at all: the table in caps/mod.rs is a doc comment the gate never reads.
///
/// An empty or unparsable list fails loudly, because an empty list would pass vacuously.
fn zoo() -> Vec<&'static str> {
    const SOURCE: &str = include_str!("../../../../../xtask/src/gates/seal_witness.rs");
    const OPEN: &str = "pub const ZOO: &[&str] = &[";
    let start = SOURCE
        .find(OPEN)
        .expect("seal_witness.rs declares `pub const ZOO: &[&str] = &[` — the list moved")
        + OPEN.len();
    let len = SOURCE[start..]
        .find("];")
        .expect("seal_witness.rs's ZOO list is closed by `];`");
    let names: Vec<&str> = SOURCE[start..start + len]
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            let name = item
                .strip_prefix('"')
                .and_then(|i| i.strip_suffix('"'))
                .unwrap_or_else(|| panic!("ZOO entry is not a plain string literal: {item}"));
            assert!(
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "ZOO entry is not an identifier: {item}"
            );
            name
        })
        .collect();
    assert!(
        names.len() >= 2,
        "ZOO parsed to {names:?}; an empty list passes vacuously"
    );
    names
}

fn table_rows() -> Vec<&'static str> {
    include_str!("../mod.rs")
        .lines()
        .filter(|l| l.starts_with("//! |"))
        .collect()
}

#[test]
fn no_row_names_a_deleted_proof_type() {
    for row in table_rows() {
        for name in zoo() {
            assert!(!row.contains(name), "`{name}` does not exist: {row}");
        }
    }
}

#[test]
fn the_grants_the_table_names_are_the_ones_the_signatures_take() {
    let rows = table_rows().join("\n");
    let hold = include_str!("../hold.rs");
    for (row, signature) in [
        (
            "`Hold::open` demands a `Grant<Admittance>`",
            "pub fn open(_token: &Grant<Admittance>,",
        ),
        (
            "`Posted::settle` demands a `Grant<WriteMoney>`",
            "_token: &Grant<WriteMoney>,\n    ) -> Self {\n        // Read the figures out",
        ),
    ] {
        assert!(rows.contains(row), "the table states: {row}");
        assert!(
            hold.contains(signature),
            "the signature takes it: {signature}"
        );
    }
}
