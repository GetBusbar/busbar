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
    let endpoints = rows
        .iter()
        .flat_map(|rows| rows.iter())
        .any(|(slot, _)| *slot == "endpoint");
    let mut want = include_str!("fixtures/cli_help_without_flag_rows.txt").to_owned();
    if tagline.is_empty() {
        // No tagline row linked either: the first line is the version alone.
        let (_, rest) = want.split_once('\n').expect("the golden has a first line");
        want = format!("busbar <VERSION>\n{rest}");
    }
    if !endpoints {
        // No `ENDPOINTS` row linked either: the block holds the root's own row alone.
        want = without_plane_endpoint_rows(&want);
    }
    assert_eq!(render_help("<VERSION>", &rows), want);
}

/// The golden with every plane-declared `ENDPOINTS` row dropped: the lines between the block's
/// header and the root's own row, which closes the block.
fn without_plane_endpoint_rows(golden: &str) -> String {
    let (head, block) = golden
        .split_once("\nENDPOINTS (")
        .expect("the golden has an ENDPOINTS block");
    let (header, rows) = block.split_once('\n').expect("the header is one line");
    let (_, tail) = rows
        .split_once("    GET  /stats")
        .expect("the root's own row closes the block");
    format!("{head}\nENDPOINTS ({header}\n    GET  /stats{tail}")
}

/// A plane's `ENDPOINTS` rows land inside the `ENDPOINTS` block, after its header and before the
/// root's own row, in the order the planes declare them; a `Flags:` row never lands there.
#[test]
fn a_declared_endpoint_row_lands_inside_the_endpoints_block() {
    let rows: &[&[CliHelpRow]] = &[
        &[(
            "endpoint",
            "    POST /planted-a                        first",
        )],
        &[
            ("flag", "    --planted-flag      a planted row"),
            (
                "endpoint",
                "    POST /planted-b                        second",
            ),
        ],
    ];
    let help = render_help("<VERSION>", rows);
    let (_, block) = help
        .split_once("\nENDPOINTS (once running, listen address from config.yaml `listen`):\n")
        .expect("the help has its ENDPOINTS block");
    assert!(
        block.starts_with(
            "    POST /planted-a                        first\n    POST /planted-b                        second\n    GET  /stats  /healthz  /metrics\n"
        ),
        "{block}"
    );
    assert!(!block.contains("--planted-flag"), "{block}");
    let bare = render_help("<VERSION>", &[]);
    assert!(
        bare.contains(
            "\nENDPOINTS (once running, listen address from config.yaml `listen`):\n    GET  /stats  /healthz  /metrics\n"
        ),
        "{bare}"
    );
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
