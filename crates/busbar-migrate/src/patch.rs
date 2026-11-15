// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The patch writer (MIGRATE-ON-BOOT §A7 "Authored text"): config.yaml is rewritten by byte-range
//! edits of the operator's own text, never by re-serializing a tree, so comments, key order,
//! quoting, anchors and blank lines survive and only the changed spans differ. Every edit is
//! checked by its two proofs: re-parsing the written bytes gives the planned tree (one), and the
//! written bytes minus the changed spans equal the source bytes minus the same spans (two).

use busbar_contract::yaml::{self, ValueExt};

use crate::{Refusal, STAMP_KEY};

/// Insert `config_version: <format>` as the document's first key: after a leading block of blank
/// lines, comments, directives and the `---` marker, before the first key. Nothing else changes.
///
/// # Errors
/// CONFIG when the document's root is not a block mapping the line can open (proof one fails).
pub fn stamp(text: &str, format: u64) -> Result<String, Refusal> {
    let at = first_key_offset(text);
    let mut line = String::new();
    if at == text.len() && !text.is_empty() && !text.ends_with('\n') {
        line.push('\n');
    }
    line.push_str(STAMP_KEY);
    line.push_str(": ");
    line.push_str(&format.to_string());
    line.push('\n');
    let mut out = String::with_capacity(text.len() + line.len());
    out.push_str(&text[..at]);
    out.push_str(&line);
    out.push_str(&text[at..]);
    proof_one((at < text.len()).then_some(text), &out, format)?;
    debug_assert!(proof_two(text, &out, at, line.len()));
    Ok(out)
}

/// The byte offset of the first line that is not blank, a comment, a `%` directive or `---`.
fn first_key_offset(text: &str) -> usize {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let code = line.trim_start();
        let preamble = code.is_empty()
            || code.starts_with('#')
            || code.starts_with('%')
            || code.trim_end() == "---"
            || code.starts_with("--- #");
        if !preamble {
            break;
        }
        offset += line.len();
    }
    offset
}

/// Proof one: the written bytes parse to the stamp followed by exactly the source's tree (`None`:
/// the source holds no key).
fn proof_one(source: Option<&str>, written: &str, format: u64) -> Result<(), Refusal> {
    let refused = || {
        Refusal::Config(format!(
            "config.yaml's top level is not a block mapping that `{STAMP_KEY}: {format}` can \
             open; write its top-level keys one per line (`key: value`), then boot again"
        ))
    };
    let after: yaml::Value = yaml::from_str(written).map_err(|_| refused())?;
    let pairs = after.as_mapping().ok_or_else(refused)?;
    let (first, rest) = pairs.split_first().ok_or_else(refused)?;
    let stamped = first.0.as_str() == Some(STAMP_KEY) && first.1.as_u64() == Some(format);
    // A source with no key (blank, comments only) is the empty mapping.
    let original = match source {
        None => yaml::Value::Map(Vec::new()),
        Some(source) => yaml::from_str::<yaml::Value>(source).map_err(|_| refused())?,
    };
    if !original.is_mapping() {
        return Err(refused());
    }
    if stamped && yaml::same_tree(&yaml::Value::Map(rest.to_vec()), &original) {
        Ok(())
    } else {
        Err(refused())
    }
}

/// Proof two: the written bytes minus the inserted span equal the source.
fn proof_two(source: &str, written: &str, at: usize, inserted: usize) -> bool {
    written.len() == source.len() + inserted
        && written[..at] == source[..at]
        && written[at + inserted..] == source[at..]
}

#[cfg(test)]
#[path = "tests/patch_tests.rs"]
mod tests;
