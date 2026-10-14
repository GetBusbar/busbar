// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `cli.rs`: `busbar --help` is the root's own text plus the rows each linked plane
//! declares on the CLI-help axis, and nothing else.

use super::{help_rows, is_plane_flag, render_help};
use crate::root::linked::CliHelpRow;

/// The help's three plane-fed places, split out of a rendered help: its first line (the
/// tagline's), its `Flags:` block and its `ENDPOINTS` block.
fn blocks(help: &str) -> (&str, &str, &str) {
    let first = help.lines().next().expect("the help has a first line");
    let (_, rest) = help
        .split_once("\nFlags:\n")
        .expect("the help has its Flags: block");
    let (flags, endpoints) = rest
        .split_once("\nENDPOINTS (")
        .expect("the Flags: block is followed by the ENDPOINTS block");
    (first, flags, endpoints)
}

/// EVERY LINKED ROW REACHES THE HELP, IN ITS PLACE: the first tagline row closes the first line,
/// every `Flags:` row lands in the `Flags:` block and every `ENDPOINTS` row in the `ENDPOINTS`
/// block, each in the order the planes declare it; and the root's own text is all there around
/// them. Read off the linked rows (a linked row's `cli-help` axis or a linked door's tail
/// `cli_help`, as `--help` reads them), so a plane that stops declaring its rows fails this. The
/// help's 1.5.5 bytes are the oracle golden cells `cli|--help` and `cli|-h` (from the 1.5.5 binary).
#[test]
fn every_linked_row_reaches_the_help_in_its_place() {
    let linked = help_rows();
    let help = render_help("<VERSION>", &linked);
    let (first, flags, endpoints) = blocks(&help);
    let rows = || linked.iter().flat_map(|rows| rows.iter());
    if let Some((_, tagline)) = rows().find(|(slot, _)| *slot == "tagline") {
        assert_eq!(first, format!("busbar <VERSION> — {tagline}"));
    } else {
        assert_eq!(first, "busbar <VERSION>");
    }
    for (slot, block) in [("flag", flags), ("endpoint", endpoints)] {
        let mut from = 0;
        for (_, text) in rows().filter(|(s, _)| *s == slot) {
            let at = block[from..]
                .find(text)
                .unwrap_or_else(|| panic!("the `{slot}` row {text:?} is in its block, in order"));
            from += at + text.len();
        }
    }
    let bare = render_help("<VERSION>", &[]);
    let mut from = 0;
    for line in bare.lines().skip(1) {
        let at = help[from..]
            .find(line)
            .unwrap_or_else(|| panic!("the root's own line {line:?} is in the help, in order"));
        from += at + line.len();
    }
}

/// A plane compiled out takes its rows with it: a build whose linked planes declare no `Flags:` row
/// prints the root's `Flags:` block alone, and every row of the planes it keeps stays.
#[test]
fn a_plane_compiled_out_takes_its_help_rows_with_it() {
    let linked = help_rows();
    let has_flag = |rows: &[CliHelpRow]| rows.iter().any(|(slot, _)| *slot == "flag");
    let kept: Vec<&[CliHelpRow]> = linked.iter().copied().filter(|r| !has_flag(r)).collect();
    let help = render_help("<VERSION>", &kept);
    let bare = render_help("<VERSION>", &[]);
    assert_eq!(
        blocks(&help).1,
        blocks(&bare).1,
        "the root's own Flags: rows alone"
    );
    // The first line is the first kept tagline's, if any (`every_linked_row_reaches_the_help...`).
    for rows in &linked {
        for (slot, text) in rows.iter() {
            if *slot == "tagline" {
                continue;
            }
            assert_eq!(
                help.contains(text),
                !has_flag(rows),
                "a compiled-out plane's {slot} row leaves with it, a kept plane's stays: {text:?}"
            );
        }
    }
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
    let linked = help_rows();
    for rows in &linked {
        for (slot, lines) in rows.iter() {
            if *slot == "flag" {
                let flag = lines
                    .split_whitespace()
                    .next()
                    .expect("a flag row names its flag");
                assert!(is_plane_flag(&linked, flag), "{flag}");
            }
        }
    }
}
