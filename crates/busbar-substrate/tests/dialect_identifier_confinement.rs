// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DIMENSION-1 LEAKAGE GATE (dialect axis) — the neutral ABI crate `busbar-substrate` must name NO
//! LLM dialect. The `plane-purity` DIALECT scanner matches WHOLE-WORD tokens (`openai`, `bedrock`, …),
//! so a dialect-PREFIXED snake_case identifier (`openai_context_length_prose_scan`) slips through it
//! uncaught — the exact blind spot the plane-extraction audit found. This gate closes it: it scans
//! `busbar-substrate`'s production source for any `<dialect>_<snake>` identifier and fails RED unless
//! it is in the ALLOWLIST of the currently-tracked residue.
//!
//! The allowlist is the LLM-ABI purity §3E tracked debt: a small bank of OpenAI-family error/prose
//! helpers that still live here and are slated to relocate into `busbar-llm` (the LLM-seal). Until that
//! money-path-adjacent relocation lands, this gate PINS the residue so it cannot GROW — a NEW
//! dialect-prefixed identifier in the neutral crate reds the build, named. When the seal lands, the
//! allowlist shrinks to empty and this gate proves the neutral crate is dialect-clean.

use std::path::{Path, PathBuf};

/// The LLM dialect prefixes a neutral-crate identifier must never carry (snake_case form).
const DIALECT_PREFIXES: &[&str] = &["openai_", "bedrock_", "gemini_", "cohere_", "anthropic_"];

/// The CURRENTLY-TRACKED residue (LLM-ABI §3E) — OpenAI-family helpers awaiting relocation into
/// `busbar-llm`. This allowlist may only SHRINK. A dialect-prefixed identifier NOT listed here is a
/// NEW leak and reds the gate.
const TRACKED_RESIDUE: &[&str] = &["openai_context_length_prose_scan", "openai_classify"];

/// BOTH HALVES OF THE NEUTRAL ABI CRATE. The substrate was split in two — `busbar-substrate-values`
/// carries the pure value families (including `proto`, where the tracked residue lives) and
/// `busbar-substrate` keeps the egress engine — but they are ONE neutral surface as far as this gate
/// is concerned, and a residue that merely changed crates has not been relocated into `busbar-llm`.
/// Scanning only one root would let the allowlist go stale on one side while a leak grew on the other.
fn substrate_srcs() -> Vec<PathBuf> {
    // CARGO_MANIFEST_DIR is crates/busbar-substrate.
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        here.join("src"),
        here.join("../busbar-substrate-values/src"),
    ]
}

/// Collect every production `.rs` file under `dir` (test files excluded — a plane's own tests may name
/// a dialect; the point is the SHIPPED neutral source), skipping `target/`.
fn production_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == "tests" {
                continue;
            }
            production_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let p = path.to_string_lossy().replace('\\', "/");
            let is_test =
                p.ends_with("_tests.rs") || p.ends_with("/tests.rs") || p.contains("/test_support");
            if !is_test {
                out.push(path);
            }
        }
    }
}

/// Extract dialect-prefixed snake_case identifiers on `line`, excluding line/doc comments. Returns each
/// full identifier (e.g. `openai_context_length_prose_scan`) so it can be checked against the allowlist.
fn dialect_identifiers(line: &str) -> Vec<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return Vec::new();
    }
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    let mut hits = Vec::new();
    // Walk identifier-like runs and keep those whose head is a dialect prefix.
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_alphanumeric() || c == '_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let ident = &code[start..i];
            if DIALECT_PREFIXES.iter().any(|p| ident.starts_with(p)) && ident.len() > 1 {
                hits.push(ident.to_string());
            }
        } else {
            i += 1;
        }
    }
    hits
}

#[test]
fn busbar_substrate_names_no_new_llm_dialect_identifier() {
    let mut files = Vec::new();
    for root in substrate_srcs() {
        production_rs_files(&root, &mut files);
    }
    assert!(
        !files.is_empty(),
        "the source scan found no .rs files under the substrate src roots — wrong tree"
    );

    let mut offenders: Vec<String> = Vec::new();
    let mut seen_tracked: Vec<String> = Vec::new();
    for path in &files {
        // This gate's own source names the residue in its allowlist — skip it.
        if path.file_name().and_then(|n| n.to_str()) == Some("dialect_identifier_confinement.rs") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        for (lineno, line) in src.lines().enumerate() {
            for ident in dialect_identifiers(line) {
                if TRACKED_RESIDUE.contains(&ident.as_str()) {
                    seen_tracked.push(ident);
                } else {
                    offenders.push(format!("{}:{}: {ident}", path.display(), lineno + 1));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "the neutral crate busbar-substrate names an LLM DIALECT identifier not in the tracked-residue \
         allowlist — a new dialect leak (the whole-word plane-purity scanner misses snake_case). Move \
         it into busbar-llm, or (if genuinely neutral) rename it without a dialect prefix:\n{}",
        offenders.join("\n")
    );
    // The allowlist may only SHRINK: if a tracked identifier is gone (relocated), drop it here so the
    // allowlist can never silently retain a stale entry that would mask a re-introduction.
    for tracked in TRACKED_RESIDUE {
        assert!(
            seen_tracked.iter().any(|s| s == tracked),
            "allowlisted residue `{tracked}` no longer appears in busbar-substrate — remove it from \
             TRACKED_RESIDUE (the allowlist only shrinks; a stale entry could mask a re-leak)"
        );
    }
}
