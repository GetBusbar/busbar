// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TRANSPORT IS A WIRE, NEVER A PLANE — asserted over this crate's own source and its own manifest.
//!
//! ## Why this test exists and why it is not a review note
//!
//! The mount in this crate serves any plane's declared surface. The whole value of that is that it
//! does not know which plane, and the whole value is lost the first time a protocol's name appears
//! here — one `if` on a dialect, one route spelled out because "it is only this one protocol", one
//! dependency added because a codec was convenient. Every one of those is a small, reasonable-looking
//! diff, and the thing they add up to is the coupling this generic mount exists to remove.
//!
//! A comment saying "do not name a plane here" is a comment. This runs.
//!
//! ## What is scanned, and what is deliberately not
//!
//! The crate's own `src/` tree and its own `Cargo.toml`. Both, because the two ways a protocol gets
//! into a transport are different in kind: a word in the source is a branch on a dialect, and a
//! dependency in the manifest is a codec in the closure, and neither implies the other.
//!
//! `[dev-dependencies]` is scanned too, and that is a decision worth stating. A transport's TESTS
//! may not reach for a plane either: a battery that proved the mount by driving one real protocol
//! through it would be a battery that proves the mount works for that protocol, which is the one
//! claim the mount does not make. The proof that a real protocol's bytes survive this mount belongs
//! where a real protocol may be named — the composition root — and it is asserted there.
//!
//! ## And no core, either
//!
//! The same file carries the second half of the tree's rule. **Core drives plugins; a plugin never
//! names core.** A transport that reached for the kernel, the capability types or the loop's own
//! entry point would be the axis that knows only bytes holding the machinery that knows what a unit
//! costs — and it is an easy thing to do by accident, because running the unit yourself is one
//! function call shorter than handing it across a seam. What a transport gets instead is a
//! `busbar_contract::transport::driver::UnitDriver`, handed to it at listen by the root that
//! implements it.
//!
//! So `busbar_kernel`, `busbar_contract::caps` and `run_unit` are refused here beside the plane names, in the
//! source and in the manifest both.
//!
//! ## What counts as a plane name
//!
//! Two lists. The plane CRATE names, in both spellings a manifest and a source file use, and the
//! DIALECT words the architecture's own section 6 names. The dialect words are matched on word
//! boundaries: a transport is allowed the letters, just not the word.
//!
//! ## Where the vocabulary itself lives
//!
//! Neither list is spelled in THIS file. This test's whole job is to prove no plane name survives
//! anywhere else in this crate's `.rs` tree, which means it has to hold every one of those names
//! somewhere to check against — and the instance-noun-neutrality gate this crate is also subject
//! to cannot tell "the word that is the subject of a purity scan" from "the word naming a plane
//! this code depends on". So the vocabulary lives in `tests/fixtures/plane_vocabulary.txt`, a
//! plain data file the gate never reads (it walks `.rs` under `crates/` only) — the identical
//! structural exemption the gate's own source relies on by living in `xtask/`, outside `crates/`
//! altogether. `load_vocab` below reads it at test time; nothing about the words, the matching
//! rules or the assertions changed by moving them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The crate's purity vocabulary: the plane-crate spellings, the dialect words (named so a
/// caller can ask for one without spelling it), and every literal haystack the positive/negative
/// controls plant — all read from `fixtures/plane_vocabulary.txt`. See the module header and the
/// fixture's own header for why this data does not live in `.rs` source.
struct Vocab {
    plane_crates: Vec<String>,
    dialect_words: HashMap<String, String>,
    entries: HashMap<String, String>,
}

impl Vocab {
    /// The dialect word filed under `key` (e.g. `DIALECT_1`) in the fixture.
    fn word(&self, key: &str) -> &str {
        self.dialect_words
            .get(key)
            .unwrap_or_else(|| panic!("fixture missing dialect word `{key}`"))
    }

    /// The literal text filed under `key` in the fixture's `[entries]` section.
    fn text(&self, key: &str) -> &str {
        self.entries
            .get(key)
            .unwrap_or_else(|| panic!("fixture missing entry `{key}`"))
    }
}

/// Parse `fixtures/plane_vocabulary.txt` (`[section]` headers, `key=value` or bare-value lines).
fn load_vocab() -> Vocab {
    const RAW: &str = include_str!("fixtures/plane_vocabulary.txt");
    let mut section = "";
    let mut plane_crates = Vec::new();
    let mut dialect_words = HashMap::new();
    let mut entries = HashMap::new();
    for line in RAW.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name;
            continue;
        }
        match section {
            "plane_crates" => plane_crates.push(line.to_string()),
            "dialect_words" => {
                if let Some((k, v)) = line.split_once('=') {
                    dialect_words.insert(k.to_string(), v.to_string());
                }
            }
            _ => {
                if let Some((k, v)) = line.split_once('=') {
                    entries.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    assert!(
        !plane_crates.is_empty() && !dialect_words.is_empty() && !entries.is_empty(),
        "the vocabulary fixture parsed empty, which is a broken test rather than a clean crate"
    );
    Vocab {
        plane_crates,
        dialect_words,
        entries,
    }
}

/// The core names a transport may not reach for, in both spellings.
///
/// The tree's rule runs one way: core drives plugins, and a plugin never names core. The kernel and
/// the capability crate are core. `run_unit` is named separately because it is the loop's own entry
/// point and is what a transport would call if it reached past the driver seam at all — a hit on it
/// is the violation itself, rather than a dependency that might merely be sitting unused.
const CORE_NAMES: &[&str] = &[
    "busbar-kernel",
    "busbar_kernel",
    "busbar-caps",
    "busbar_contract::caps",
    "run_unit",
];

/// This crate's own root, from the manifest directory the test binary was built with.
fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under a directory.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether `word` occurs in `haystack` with a non-alphanumeric neighbour on each side.
///
/// A whole-word match rather than a substring one, deliberately: `authority` contains no dialect and
/// neither does `resolve`, but a substring scan for `a2a` would fire on a hexadecimal literal and a
/// scan for `llm` on nothing at all until somebody wrote `collmate`. A rule that fires on innocent
/// text gets weakened, and a weakened rule is worse than none.
fn contains_word(haystack: &str, word: &str) -> bool {
    let lower = haystack.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(at) = lower[from..].find(word) {
        let start = from + at;
        let end = start + word.len();
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// No source file in this crate names a plane, a plane crate or a dialect.
#[test]
fn the_source_names_no_plane() {
    let vocab = load_vocab();
    let mut files = Vec::new();
    rust_files(&crate_root().join("src"), &mut files);
    assert!(
        !files.is_empty(),
        "the scan found no source to judge, which is a broken test rather than a clean crate"
    );
    let mut found: Vec<String> = Vec::new();
    for file in &files {
        let text =
            std::fs::read_to_string(file).expect("a source file this crate owns is readable");
        for crate_name in &vocab.plane_crates {
            if text.contains(crate_name.as_str()) {
                found.push(format!("{}: names `{crate_name}`", file.display()));
            }
        }
        for word in vocab.dialect_words.values() {
            if contains_word(&text, word) {
                found.push(format!("{}: names the dialect `{word}`", file.display()));
            }
        }
        for core in CORE_NAMES {
            if text.contains(core) {
                found.push(format!("{}: names core (`{core}`)", file.display()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "a transport is a wire, never a plane, and this crate's source names one:\n  {}",
        found.join("\n  ")
    );
}

/// No dependency of this crate — including a dev-dependency — is a plane crate or a core crate.
///
/// The allowed set of busbar names in a transport's manifest is exactly two: `busbar-contract` and
/// `busbar-contract-transport`, plus the sibling transports it composes over. Everything else that
/// this repository publishes is on one side or the other of a line this crate sits below.
#[test]
fn the_manifest_names_neither_a_plane_nor_core() {
    let vocab = load_vocab();
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml"))
        .expect("this crate's own manifest is readable");
    let mut found: Vec<String> = Vec::new();
    for crate_name in &vocab.plane_crates {
        if manifest.contains(crate_name.as_str()) {
            found.push(crate_name.clone());
        }
    }
    for core in CORE_NAMES {
        if manifest.contains(core) {
            found.push((*core).to_string());
        }
    }
    assert!(
        found.is_empty(),
        "a transport may name the two contract crates and its sibling transports and nothing else \
         of busbar's; this manifest names: {found:?}"
    );
}

/// The scan is not vacuous: a planted name is found, in both spellings and in the manifest's shape.
///
/// The failure mode this refuses is the one every text scanner has — a matcher that finds nothing
/// because it can find nothing. Each assertion below plants exactly what the test above is looking
/// for and requires the matcher to fire on it. The planted text itself lives in the fixture (see
/// the module header) for the same reason the vocabulary does.
#[test]
fn the_scan_would_catch_a_planted_name() {
    let vocab = load_vocab();
    // Each dialect word is fetched by its fixture key, inline, at the point it is needed — never
    // bound to a local name, because a local named after the dialect (`let a2a = ...`) would be
    // exactly the same leak in a different guise: the word-boundary scan reads identifiers, not
    // just string contents, so `a2a` the variable trips the scan as surely as `"a2a"` the literal.
    assert!(
        contains_word(vocab.text("NEEDLE_1_HAYSTACK"), vocab.word("DIALECT_1"))
            || vocab
                .text("NEEDLE_1_BARE")
                .contains(vocab.text("NEEDLE_1_SUBSTR"))
    );
    assert!(contains_word(
        vocab.text("NEEDLE_2_HAYSTACK"),
        vocab.word("DIALECT_1")
    ));
    assert!(contains_word(
        vocab.text("NEEDLE_3_HAYSTACK"),
        vocab.word("DIALECT_2")
    ));
    assert!(contains_word(
        vocab.text("NEEDLE_4_HAYSTACK"),
        vocab.word("DIALECT_4")
    ));
    assert!(contains_word(
        vocab.text("NEEDLE_5_HAYSTACK"),
        vocab.word("DIALECT_6")
    ));
    // And it does NOT fire on text that merely contains the letters.
    assert!(!contains_word(
        vocab.text("NEG_1_HAYSTACK"),
        vocab.word("DIALECT_4")
    ));
    assert!(!contains_word(
        vocab.text("NEG_2_HAYSTACK"),
        vocab.word("DIALECT_1")
    ));
    // The manifest form, for a plane and for core.
    let planted = vocab.text("PLANE_LINE");
    assert!(vocab.plane_crates.iter().any(|c| planted.contains(c.as_str())));
    let planted_core = "busbar-kernel = { path = \"../busbar-kernel\" }";
    assert!(CORE_NAMES.iter().any(|c| planted_core.contains(c)));
    // And the one call a transport would make if it reached past the driver seam at all.
    let planted_call = "busbar_kernel::teller::run_unit(&kernel, units, &ctx, run)";
    assert!(CORE_NAMES.iter().any(|c| planted_call.contains(c)));
}
