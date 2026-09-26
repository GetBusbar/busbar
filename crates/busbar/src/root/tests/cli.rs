// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `cli.rs`: `busbar --help` is the root's own text plus the rows each linked plane
//! declares on the CLI-help axis, and nothing else.

use super::{is_plane_flag, render_help};
use crate::root::linked::CliHelpRow;

/// The default (every-plane) build prints the help byte for byte as it always has. The golden is
/// fixture data (`fixtures/cli_help.txt`, the version as `<VERSION>`); every plane-owned line in it
/// comes from a linked plane's rows, so a plane that stops declaring its rows fails this.
#[cfg(linked_every_plane)]
#[test]
fn the_help_reads_as_it_always_has_from_the_linked_rows() {
    assert_eq!(
        render_help("<VERSION>", crate::LINKED.cli_help),
        include_str!("fixtures/cli_help.txt")
    );
}

/// A plane compiled out takes its rows with it: a build whose linked planes declare no `Flags:` row
/// prints the root's `Flags:` block alone (`fixtures/cli_help_without_flag_rows.txt`), and nothing
/// else in the help moves.
#[test]
fn a_plane_compiled_out_takes_its_help_rows_with_it() {
    let rows: Vec<&[CliHelpRow]> = crate::LINKED
        .cli_help
        .iter()
        .copied()
        .filter(|rows| !rows.iter().any(|(slot, _)| *slot == "flag"))
        .collect();
    let tagline: Vec<&str> = rows
        .iter()
        .flat_map(|rows| rows.iter())
        .filter(|(slot, _)| *slot == "tagline")
        .map(|(_, text)| *text)
        .collect();
    let want = include_str!("fixtures/cli_help_without_flag_rows.txt");
    let got = render_help("<VERSION>", &rows);
    if tagline.is_empty() {
        // No tagline row linked either: the first line is the version alone.
        let (_, rest) = want.split_once('\n').expect("the golden has a first line");
        assert_eq!(got, format!("busbar <VERSION>\n{rest}"));
    } else {
        assert_eq!(got, want);
    }
}

/// Every flag a linked plane declares is accepted as that flag (the first word of its row) and
/// nothing else is: a word inside the row's prose is not a flag.
#[test]
fn a_declared_plane_flag_is_accepted_and_nothing_else_is() {
    let rows: &[&[CliHelpRow]] = &[&[(
        "flag",
        "    --planted-flag      a planted row\n                        its second line",
    )]];
    assert!(is_plane_flag(rows, "--planted-flag"));
    assert!(!is_plane_flag(rows, "a"));
    assert!(!is_plane_flag(rows, "--second"));
    assert!(!is_plane_flag(&[], "--planted-flag"));
    for rows in crate::LINKED.cli_help {
        for (slot, lines) in rows.iter() {
            if *slot == "flag" {
                let flag = lines
                    .split_whitespace()
                    .next()
                    .expect("a flag row names its flag");
                assert!(is_plane_flag(crate::LINKED.cli_help, flag), "{flag}");
            }
        }
    }
}
