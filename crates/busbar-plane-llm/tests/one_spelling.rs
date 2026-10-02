//! ONE SPELLING PER WIRE WORD (OWNER 2026-10-01: "anything written more than once is a smell,
//! especially field names").
//!
//! Within each dialect's production source (`src/codec/<dialect>/`, tests and the generated
//! `map.gen.rs` excluded), every word-shaped string literal — a wire key, an event name, a tier or
//! role word — should be spelled once: as a named const, or as a row of the dialect's mapping file.
//! This counts, per dialect, the occurrences beyond the first of every such literal and holds the
//! count to `one_spelling.baseline`, a LOWER-ONLY ratchet: a rise is red (naming the repeated
//! literals), and a fall is red until the baseline is lowered to the new count, so the ledger never
//! drifts above what the tree carries.

use std::collections::BTreeMap;
use std::path::Path;

/// Every string literal of `text`, comments skipped (raw strings and escapes understood).
fn literals(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            i = text[i..].find('\n').map_or(b.len(), |n| i + n);
        } else if b[i..].starts_with(b"/*") {
            i = text[i..].find("*/").map_or(b.len(), |n| i + n + 2);
        } else if b[i] == b'\'' {
            // A char literal ('"' included) or a lifetime: skip the quoted char when there is one.
            let close = text[i + 1..].char_indices().nth(1).map(|(n, _)| i + 1 + n);
            i += match (b.get(i + 1), close.map(|c| b[c])) {
                (Some(b'\\'), _) => text[i + 3..].find('\'').map_or(1, |n| n + 4),
                (_, Some(b'\'')) => close.map_or(1, |c| c - i + 1),
                _ => 1,
            };
        } else if b[i] == b'r'
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
            && text[i + 1..].trim_start_matches('#').starts_with('"')
        {
            let hashes = text[i + 1..].len() - text[i + 1..].trim_start_matches('#').len();
            let start = i + 2 + hashes;
            let close = format!("\"{}", "#".repeat(hashes));
            let end = text[start..].find(&close).map_or(b.len(), |n| start + n);
            out.push(text[start..end].to_string());
            i = end + close.len();
        } else if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            out.push(text[i + 1..j.min(b.len())].to_string());
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// A word-shaped literal: an identifier, possibly dotted / dashed / slashed (`response.created`).
fn word_shaped(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || "_.-/".contains(c))
}

fn production_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("dialect dir").flatten() {
        let path = entry.path();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let name = name.unwrap_or_default();
        if path.is_dir() {
            if name != "tests" {
                production_files(&path, out);
            }
        } else if name.ends_with(".rs")
            && !name.ends_with(".gen.rs")
            && !name.ends_with("_tests.rs")
            && name != "tests.rs"
        {
            out.push(path);
        }
    }
}

/// Per dialect: each word-shaped literal spelled more than once, with its count.
fn repeated() -> BTreeMap<String, BTreeMap<String, usize>> {
    let codec = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec");
    let mut out = BTreeMap::new();
    for dialect in [
        "anthropic",
        "bedrock",
        "cohere",
        "gemini",
        "openai_chat",
        "openai_responses",
    ] {
        let mut files = Vec::new();
        production_files(&codec.join(dialect), &mut files);
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("source");
            for lit in literals(&text).into_iter().filter(|l| word_shaped(l)) {
                *counts.entry(lit).or_default() += 1;
            }
        }
        counts.retain(|_, n| *n > 1);
        out.insert(dialect.to_string(), counts);
    }
    out
}

#[test]
fn every_dialect_spells_each_wire_word_once_or_lowers_its_baseline() {
    let baseline_text = include_str!("one_spelling.baseline");
    let baseline: BTreeMap<&str, usize> = baseline_text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (d, n) = l.split_once('=')?;
            Some((d.trim(), n.trim().parse().ok()?))
        })
        .collect();
    let mut problems = Vec::new();
    for (dialect, counts) in repeated() {
        let extra: usize = counts.values().map(|n| n - 1).sum();
        let allowed = baseline.get(dialect.as_str()).copied().unwrap_or(0);
        if extra > allowed {
            let mut worst: Vec<_> = counts.iter().collect();
            worst.sort_by(|a, b| b.1.cmp(a.1));
            let names: Vec<String> = worst
                .iter()
                .take(40)
                .map(|(l, n)| format!("{l} x{n}"))
                .collect();
            problems.push(format!(
                "{dialect}: {extra} repeated spellings, baseline {allowed}; spell each once (a \
                 const or a mapping row): {}",
                names.join(", ")
            ));
        } else if extra < allowed {
            problems.push(format!(
                "{dialect}: {extra} repeated spellings, below the baseline {allowed}: lower \
                 tests/one_spelling.baseline to {extra}"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_literal_scanner_reads_strings_and_skips_comments_and_chars() {
    let text = "let a = \"x\"; // \"no\"\n/* \"no\" */ let c = '\"'; let r = r#\"y\"#; b\"z\"";
    assert_eq!(literals(text), ["x", "y", "z"]);
    assert!(word_shaped("response.output_text.delta") && !word_shaped("a b") && !word_shaped(""));
}
