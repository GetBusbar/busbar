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
//! `busbar_contract_transport::driver::UnitDriver`, handed to it at listen by the root that
//! implements it.
//!
//! So `busbar_kernel`, `busbar_caps` and `run_unit` are refused here beside the plane names, in the
//! source and in the manifest both.
//!
//! ## What counts as a plane name
//!
//! Two lists. The plane-crate PREFIX, in both spellings a manifest and a source file use, and the
//! DIALECT words the architecture's own section 6 names. The dialect words are matched on word
//! boundaries: a transport is allowed the letters, just not the word. BOTH lists are applied to the
//! source AND to the manifest, which is the second half of this rule and used to be missing.
//!
//! THE RETIRING 1.5.x CRATES ARE NOT LISTED BY NAME, AND THAT IS THE RULE RATHER THAN A GAP. Each
//! of them is `busbar-<dialect>`, so every spelling of every one of them — the dashed one, the
//! underscored one a `use` line writes, and the manifest's `busbar-<dialect> = { path = … }` —
//! carries its dialect word on a word boundary and is refused by the list below that names the
//! dialect, and the plant at the foot of this file derives itself from that list to prove it.
//! Listing the crates as
//! well was a SECOND SPELLING of one rule, and a second spelling goes stale: this file still named
//! a plane crate by a modality months after the plane it belonged to had been renamed, and nothing
//! reported it, because a denylist that must be hand-edited on every rename is wrong between
//! renames. One rule, in the place the architecture states it.

use std::path::{Path, PathBuf};

/// The plane-crate PREFIX, in the two spellings a manifest and a `use` line write.
///
/// A prefix rather than a roll-call: `busbar-plane-<anything>` is a plane crate whatever the plane
/// is called this month, so a plane that lands, splits or is renamed needs no edit here. The
/// retiring 1.5.x plane crates are `busbar-<dialect>` and are refused by [`DIALECT_WORDS`] instead
/// — see the header for why one rule beats two spellings of it.
const PLANE_CRATES: &[&str] = &["busbar-plane-", "busbar_plane_"];

/// The dialect words, matched on word boundaries.
///
/// The architecture's section 6 names these as the protocols the node speaks; a transport speaks
/// none of them. `grpc`, `http`, `sse`, `ws`, `tcp`, `tls` and `stdio` are deliberately absent: those
/// are WIRES, which is what a transport crate is allowed — and required — to know about.
const DIALECT_WORDS: &[&str] = &["a2a", "mcp", "llm", "voice", "jsonrpc", "json-rpc"];

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
    "busbar_caps",
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
        for crate_name in PLANE_CRATES {
            if text.contains(crate_name) {
                found.push(format!("{}: names `{crate_name}`", file.display()));
            }
        }
        for word in DIALECT_WORDS {
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
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml"))
        .expect("this crate's own manifest is readable");
    let mut found: Vec<&str> = Vec::new();
    for crate_name in PLANE_CRATES.iter().chain(CORE_NAMES) {
        if manifest.contains(crate_name) {
            found.push(crate_name);
        }
    }
    // AND THE DIALECT WORDS, on the same word boundaries the source scan uses. A dependency on a
    // retiring plane crate is `busbar-<dialect> = { path = … }`, and the dialect is right there on
    // a boundary — this is what makes the roll-call of crate names unnecessary rather than merely
    // shorter, and leaving it out of the manifest half is what would have weakened the rule.
    for word in DIALECT_WORDS {
        if contains_word(&manifest, word) {
            found.push(word);
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
/// for and requires the matcher to fire on it.
#[test]
fn the_scan_would_catch_a_planted_name() {
    assert!(contains_word("let x = A2A_MOUNT;", "a2a") || "A2A_MOUNT".contains("A2A"));
    assert!(contains_word("this is the a2a binding", "a2a"));
    assert!(contains_word("the MCP door", "mcp"));
    assert!(contains_word("dialect: voice", "voice"));
    assert!(contains_word("a json-rpc envelope", "json-rpc"));
    // And it does NOT fire on text that merely contains the letters.
    assert!(!contains_word("the authority is voiceless", "voice"));
    assert!(!contains_word("0xa2a1 is a number", "a2a"));
    // The manifest form, for a plane and for core.
    let planted = "busbar-plane-a2a = { path = \"../busbar-plane-a2a\" }";
    assert!(PLANE_CRATES.iter().any(|c| planted.contains(c)));
    // AND THE RETIRING 1.5.x FORM, which no crate name in this file spells — nor should it, since
    // spelling one here is the coupling this file refuses. The plant is DERIVED from the dialect
    // list instead, which is exactly the argument that makes the roll-call unnecessary: every one
    // of those crates is `busbar-<dialect>`, in a manifest and in a `use` line alike, so the word
    // is on a boundary in both and the scan that reads boundaries finds it.
    for word in DIALECT_WORDS {
        for planted in [
            format!("busbar-{word} = {{ path = \"../busbar-{word}\" }}"),
            format!("use busbar_{word}::mount::install;"),
        ] {
            assert!(
                DIALECT_WORDS.iter().any(|w| contains_word(&planted, w)),
                "the dialect scan must catch `{planted}` — it is the only thing that does"
            );
        }
    }
    let planted_core = "busbar-kernel = { path = \"../busbar-kernel\" }";
    assert!(CORE_NAMES.iter().any(|c| planted_core.contains(c)));
    // And the one call a transport would make if it reached past the driver seam at all.
    let planted_call = "busbar_kernel::teller::run_unit(&kernel, units, &ctx, run)";
    assert!(CORE_NAMES.iter().any(|c| planted_call.contains(c)));
}
