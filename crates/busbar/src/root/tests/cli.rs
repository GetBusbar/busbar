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

/// THE `--list-plugins` HEADER IS THE ROW FORMAT'S: its six column names at the widths every row
/// prints at, then `STATUS`, so each name heads its own column.
#[test]
fn the_list_plugins_header_heads_the_row_formats_columns() {
    let names: Vec<&str> = super::LIST_PLUGINS_HEADER.split_whitespace().collect();
    assert_eq!(names.len(), 7, "six columns and STATUS");
    assert_eq!(
        super::LIST_PLUGINS_HEADER,
        format!(
            "{:<34} {:<24} {:<12} {:<6} {:<9} {:<24} {}",
            names[0], names[1], names[2], names[3], names[4], names[5], names[6]
        )
    );
}

/// THE DEFAULT DISTRIBUTION'S `busbar --help`, BYTE FOR BYTE: the root's own text with every row the
/// linked plane doors state on their tails (a tagline, `Flags:` rows, `ENDPOINTS` rows). The pin is
/// DATA in the oracle corpus (`testing/shadow-oracle/fixtures/law0/help-default-build-1.6.0.txt`):
/// the help this binary printed while a legacy linked row still supplied the fallback plane's rows,
/// so a door that stops stating its rows, or a reader that drops a slot, fails here. A build that
/// links fewer planes prints a different help, not a wrong one, so the pin holds only where every
/// plane and every plane door is linked.
#[cfg(all(linked_every_plane, linked_every_plane_door))]
#[test]
fn the_default_distributions_help_is_byte_identical() {
    assert_eq!(
        render_help("<VERSION>", &help_rows()),
        include_str!(
            "../../../../../testing/shadow-oracle/fixtures/law0/help-default-build-1.6.0.txt"
        )
    );
}

/// A DROPPED-IN PLANE'S `busbar --help` ROWS, ITS LINE-SERVE FLAG AMONG THEM, ARE THE SAME PLANE'S
/// COMPILED IN (audit busbar-src r4 S-2; BUSBAR-1.6.0.md l.2179, Part 2 #2: compiled in or dropped
/// in, one loading path). RED before the fix: the command line read only the linked planes' rows,
/// so with the plane dropped into `plugins.dir` its flag was refused as an unknown argument, and
/// after `-c <path>` the boot bound the network listeners and logged to stdout. A linked plane
/// door's Statement rendering (what its pack signs into the manifest) stands here as a dropped-in
/// candidate whose library is not a library: its rows are read off the rendering with no dlopen,
/// equal the linked door's, and its flag is a plane flag. A linked candidate adds no row of its
/// own: [`help_rows`] already reads it off the door.
#[cfg(linked_every_plane_door)]
#[test]
fn a_dropped_in_planes_help_rows_are_read_off_its_signed_rendering() {
    use crate::root::loader::boot::{Candidate, Origin};
    use crate::root::loader::dispatch::kinds::plane::linked_cli_help;
    use busbar_contract::abi::plane::cli_help;
    let (door, help) = crate::LINKED
        .plane_doors
        .iter()
        .find_map(|door| {
            let help = linked_cli_help(*door).ok()??;
            cli_help::rows(help)
                .any(|(slot, _)| slot == cli_help::FLAG)
                .then_some((*door, help))
        })
        .expect("the default build links a plane door stating a `Flags:` row");
    let stated = crate::root::loader::dispatch::rendering_of(door).expect("the door states itself");
    let dropped = Candidate::from_rendering(
        stated,
        None,
        Origin::Dropped {
            file: "dropped-plane.tar.gz".into(),
            bytes: std::sync::Arc::new(b"not a library: a help read never opens it".to_vec()),
        },
    )
    .expect("the rendering states a candidate");
    let texts = super::dropped_help(&[dropped]);
    assert_eq!(
        texts,
        vec![help.to_string()],
        "the linked door's rows, read off its rendering"
    );
    let text: &'static str = Box::leak(texts[0].clone().into_boxed_str());
    let rows: Vec<CliHelpRow> = cli_help::rows(text).collect();
    let flag = rows
        .iter()
        .find(|(slot, _)| *slot == cli_help::FLAG)
        .and_then(|(_, lines)| lines.split_whitespace().next())
        .expect("a flag row names its flag");
    assert!(is_plane_flag(&[&rows], flag), "{flag} is a plane flag");
    let linked = Candidate::linked(door).expect("the linked door is a candidate");
    assert_eq!(
        super::dropped_help(&[linked]),
        Vec::<String>::new(),
        "a linked door's rows are read once, off the door"
    );
}
