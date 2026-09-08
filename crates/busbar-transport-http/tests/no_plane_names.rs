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
//! Four lists, and they are four because the ways this axis leaks are four different things. The
//! plane CRATE names, in both spellings a manifest and a source file use. The PLANE words — the
//! surfaces the node speaks. The DIALECT words the architecture's own section 6 names, which are
//! the vendors the planes speak to and which for a long time were missing from a list named after
//! them: a gate that cannot fail on its own class is not a gate. And the MONEY words, because the
//! blindness this file defends runs in that direction too — a wire that named a denomination or a
//! rate would be pricing its own traffic.
//!
//! The three word lists are matched on word boundaries: a transport is allowed the letters, just
//! not the word. Each list states which near-misses it deliberately leaves out and why, and the
//! plant-proof cell below requires the matcher to fire on every word in all three.

use std::path::{Path, PathBuf};

/// The plane crate names, in the two spellings a manifest and a `use` line write.
const PLANE_CRATES: &[&str] = &[
    "busbar-plane-",
    "busbar_plane_",
    "busbar-llm",
    "busbar_llm",
    "busbar-mcp",
    "busbar_mcp",
    "busbar-a2a",
    "busbar_a2a",
    "busbar-voice",
    "busbar_voice",
];

/// The plane and protocol-family words, matched on word boundaries.
///
/// The architecture's section 6 names these as the surfaces the node speaks; a transport speaks
/// none of them. `grpc`, `http`, `sse`, `ws`, `tcp`, `tls` and `stdio` are deliberately absent: those
/// are WIRES, which is what a transport crate is allowed — and required — to know about.
const PLANE_WORDS: &[&str] = &["a2a", "mcp", "llm", "voice", "jsonrpc", "json-rpc"];

/// The DIALECT words, matched on word boundaries.
///
/// A plane is one list and a dialect is another, and for a long time only the first was here — a
/// list named for dialects that held no dialect, which is a gate that cannot fail on the class it
/// is named for. The architecture's section 6 enumerates these as the vendor dialects the planes
/// speak (plus `twilio` on the streams plane), and a transport speaks none of them either: a wire
/// that branched on which vendor was on the far side of it would have stopped being a wire.
///
/// `responses` is one of the six and is deliberately NOT here. It is also an ordinary English word
/// this kind uses constantly — a transport reads requests and writes responses — and a rule that
/// fires on innocent text gets weakened, which is worse than a rule with a named hole. The hole is
/// named here instead: a dialect reached for by that spelling alone is not caught by this scan.
const DIALECT_WORDS: &[&str] = &[
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "cohere",
    "twilio",
];

/// The MONEY words, matched on word boundaries.
///
/// A transport never names money. It reports how many bytes crossed, and what that is worth is
/// decided a long way above it by something this axis may not know exists — the whole point of the
/// three blind axes is that the wire cannot price its own traffic. A denomination or a rate
/// appearing in a transport is the axis leaking, and the leak is cheap to make by accident: one
/// comment explaining what a byte count is FOR is a sentence, and one field carrying it is a defect.
///
/// Chosen for words that cannot be innocent here. `cost`, `budget`, `meter`, `metering` and
/// `ledger` are all absent on purpose: this kind uses every one of them about ITSELF — a read
/// budget, the resource cost of a discarded body, the metering path that reads the byte count this
/// transport reports, the ledger it deliberately does not write to — and firing on those would
/// train a reader to delete the rule. Naming the meter is not naming money; the transport is
/// allowed to know its byte count is read, and not allowed to know what the reader does with it.
const MONEY_WORDS: &[&str] = &[
    "cents", "usd", "price", "pricing", "invoice", "billable", "tariff", "currency",
];

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
        for word in PLANE_WORDS {
            if contains_word(&text, word) {
                found.push(format!("{}: names the plane `{word}`", file.display()));
            }
        }
        for word in DIALECT_WORDS {
            if contains_word(&text, word) {
                found.push(format!("{}: names the dialect `{word}`", file.display()));
            }
        }
        for word in MONEY_WORDS {
            if contains_word(&text, word) {
                found.push(format!("{}: names money (`{word}`)", file.display()));
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
    // EVERY word in every list, planted in the shape a real leak has, and the matcher required to
    // fire on each. A list is only a gate for the words that are proven findable: the old cell
    // planted four of them, and the two lists that carry the classes this file is named for were
    // not covered at all — one of them did not exist and the other held no dialect.
    for word in PLANE_WORDS.iter().chain(DIALECT_WORDS).chain(MONEY_WORDS) {
        let planted = format!("// the {word} case is handled here");
        assert!(
            contains_word(&planted, word),
            "the scan must fire on `{word}` where it is planted"
        );
        let uppercased = format!("const {}_ROUTE: &str = \"/x\";", word.to_ascii_uppercase());
        assert!(
            contains_word(&uppercased, word),
            "and on `{word}` shouted, which is how a constant spells it"
        );
    }
    assert!(contains_word("let x = A2A_MOUNT;", "a2a"));
    assert!(contains_word("this is the a2a binding", "a2a"));
    assert!(contains_word("the MCP door", "mcp"));
    assert!(contains_word(
        "match dialect { Anthropic => {} }",
        "anthropic"
    ));
    assert!(contains_word(
        "headers.insert(\"x-openai-beta\", v)",
        "openai"
    ));
    assert!(contains_word(
        "let cents = frame.meta.bytes * rate;",
        "cents"
    ));
    assert!(contains_word("a json-rpc envelope", "json-rpc"));
    // And it does NOT fire on text that merely contains the letters.
    assert!(!contains_word("the authority is voiceless", "voice"));
    assert!(!contains_word("0xa2a1 is a number", "a2a"));
    // The words this kind is allowed about ITSELF, which is why they are not on any list above: a
    // read budget, the cost of discarding a body, the meter class the frame's byte count feeds, and
    // the ledger this transport deliberately does not write to.
    for innocent in ["budget", "cost", "meter", "metering", "ledger"] {
        assert!(
            !PLANE_WORDS.contains(&innocent)
                && !DIALECT_WORDS.contains(&innocent)
                && !MONEY_WORDS.contains(&innocent),
            "`{innocent}` is this kind's own vocabulary and must not be a refused word"
        );
    }
    // The manifest form, for a plane and for core.
    let planted = "busbar-plane-a2a = { path = \"../busbar-plane-a2a\" }";
    assert!(PLANE_CRATES.iter().any(|c| planted.contains(c)));
    let planted_core = "busbar-kernel = { path = \"../busbar-kernel\" }";
    assert!(CORE_NAMES.iter().any(|c| planted_core.contains(c)));
    // And the one call a transport would make if it reached past the driver seam at all.
    let planted_call = "busbar_kernel::teller::run_unit(&kernel, units, &ctx, run)";
    assert!(CORE_NAMES.iter().any(|c| planted_call.contains(c)));
}
