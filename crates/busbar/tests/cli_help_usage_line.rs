// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE USAGE LINE OF `busbar --help` IS PINNED TO THE PUBLISHED 1.5.5 BYTES.
//!
//! `--help` is the one CLI surface an operator reads before they have a deployment, and the shadow
//! oracle rates a `cli` cell's body as the contract itself: the bytes ARE the answer. Most of what
//! 1.6.0 added to this text is growth an operator gains (a `CONFIG INPUTS` section, `--build-info`,
//! `--mcp-stdio`), but the FIRST line under `USAGE:` is not growth — it is the one line that tells a
//! reader how busbar is invoked and configured, and rewriting it as a flag synopsis
//! (`busbar [-c <path>] [--providers <path>]`) replaced that sentence with a spelling of two
//! optional flags the section below already documents.
//!
//! So this test does not paraphrase the line, and it does not carry its own copy: it READS THE
//! GOLDEN CELL the oracle judges that surface by (`testing/shadow-oracle/golden/1.5.5/cells/
//! cli__--help.json`, recorded from the published 1.5.5 binary) and asserts the shipped binary
//! prints those exact bytes. A copy pasted into this file would drift from the golden the moment
//! either moved and the test would keep passing over the drift; reading the golden means the ONLY
//! way to make this test agree with a changed line is to change what 1.5.5 published, which nobody
//! can.
//!
//! `-h` is asserted to print the same text as `--help` for the same reason the oracle records both:
//! they are two names for one answer, and a fix applied to one of them is not a fix.

use std::path::PathBuf;
use std::process::Command;

/// The 1.5.5 golden recording of `cli|--help` — the published binary's own stdout, normalized by
/// the oracle's recorder (the version string is `<VERSION>`; nothing else in the text is rewritten).
fn golden_help_text() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells/cli__--help.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("golden cell {} is unreadable: {e}", path.display()));
    let cell: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("golden cell is not JSON: {e}"));
    cell["body"]["text"]
        .as_str()
        .expect("golden cli|--help cell has no body.text")
        .to_string()
}

/// The line the assertions below are about: the first line under `USAGE:`.
fn usage_line(text: &str) -> &str {
    let mut after_heading = text.lines().skip_while(|l| *l != "USAGE:");
    assert!(
        after_heading.next().is_some(),
        "help text has no USAGE: heading"
    );
    after_heading
        .next()
        .expect("help text has a USAGE: heading with nothing under it")
}

fn run_help(flag: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg(flag)
        .output()
        .unwrap_or_else(|e| panic!("could not run the binary with {flag}: {e}"));
    assert!(
        out.status.success(),
        "{flag} exited {:?}",
        out.status.code()
    );
    String::from_utf8(out.stdout).expect("help text is not UTF-8")
}

#[test]
fn help_usage_line_is_the_published_1_5_5_line_byte_for_byte() {
    let golden = golden_help_text();
    let expected = usage_line(&golden);
    // The golden's own line, not a copy of it: if 1.5.5 said something else, this test says so too.
    assert_eq!(
        expected,
        "    busbar              run the gateway (configured entirely via environment + YAML)",
        "the golden cell's USAGE line is not the line this test was written against — the golden \
         moved, and that is the thing to look at before touching the binary"
    );
    let printed = run_help("--help");
    assert_eq!(
        usage_line(&printed),
        expected,
        "busbar --help no longer prints the published 1.5.5 usage line"
    );
}

#[test]
fn dash_h_prints_the_same_text_as_help() {
    assert_eq!(
        run_help("-h"),
        run_help("--help"),
        "-h and --help are two names for one answer"
    );
}
