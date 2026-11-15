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

// ---- The general edit: the operator's text rewritten to a planned tree --------------------------
//
// A pass computes the tree it wants (the overlay fold, 1c) and [`rewrite`] turns it into byte-range
// edits of the operator's own text: only the block-mapping entries whose value differs are touched
// (inserted, removed, or rewritten through the per-span emitter), recursing into an entry whose
// value is a block mapping on both sides, so every other byte (comments, quoting, `${VAR}` tokens,
// key order, blank lines) stays the operator's. Proof one re-parses the result and requires the
// planned tree; an edit the locator cannot place in the text refuses CONFIG instead of guessing.

/// The document's tree: a mapping (a blank or comments-only document is the empty mapping).
///
/// # Errors
/// CONFIG when the text is not YAML or its top level is not a mapping.
pub fn document(text: &str) -> Result<yaml::Value, Refusal> {
    if first_key_offset(text) == text.len() {
        return Ok(yaml::Value::Map(Vec::new()));
    }
    let value: yaml::Value = yaml::from_str(text)
        .map_err(|error| Refusal::Config(format!("config.yaml is not valid YAML: {error}")))?;
    match value {
        yaml::Value::Null => Ok(yaml::Value::Map(Vec::new())),
        value if value.is_mapping() => Ok(value),
        _ => Err(Refusal::Config(
            "config.yaml's top level is not a mapping; 1.5.5 did not boot it either".to_owned(),
        )),
    }
}

/// Rewrite `source` so that it reads as `planned` (a mapping), editing only the entries that
/// differ. `what` names the pass in a refusal.
///
/// # Errors
/// CONFIG when an edit cannot be placed in the operator's text (a flow mapping, a complex key, a
/// second document), or the written bytes do not read back as `planned` (proof one).
pub fn rewrite(source: &str, planned: &yaml::Value, what: &str) -> Result<String, Refusal> {
    let unplaced = || {
        Refusal::Config(format!(
            "the upgrade cannot place {what} in config.yaml's text (its layout is not plain block \
             YAML there: a flow mapping, a complex key or a second document); write that part \
             one key per line, then boot again; nothing was written"
        ))
    };
    let before = document(source)?;
    let (Some(old), Some(new)) = (before.as_mapping(), planned.as_mapping()) else {
        return Err(unplaced());
    };
    let start = first_key_offset(source);
    let root = Block {
        start,
        end: source.len(),
        indent: indent_of(source.get(start..).unwrap_or_default()),
    };
    let mut edits = Vec::new();
    if diff(source, root, old, new, &mut edits).is_none() {
        return Err(unplaced());
    }
    if edits.is_empty() {
        return Ok(source.to_owned());
    }
    edits.sort_by_key(|edit| (edit.start, edit.end));
    let written = apply(source, &edits);
    let after = document(&written).map_err(|_| unplaced())?;
    if !yaml::same_tree(&after, planned) {
        return Err(unplaced());
    }
    debug_assert!(kept_outside(source, &written, &edits));
    Ok(written)
}

/// One edit: `start..end` of the source becomes `text` (an insertion when `start == end`).
struct Edit {
    start: usize,
    end: usize,
    text: String,
}

/// A block mapping in the text: the lines `start..end`, its keys at column `indent`.
#[derive(Clone, Copy)]
struct Block {
    start: usize,
    end: usize,
    indent: usize,
}

/// One `key: value` entry of a block mapping.
struct Entry {
    key: yaml::Value,
    /// The key as the operator wrote it (quoting kept), for a rewritten entry.
    key_text: String,
    /// The key line's first byte.
    start: usize,
    /// One past the entry's last content line, its newline included.
    end: usize,
    /// Whether the key line carries the value (anything but a comment after the colon).
    inline: bool,
    /// The first content line after the key line: (offset, indent, whether it is a `- ` item).
    first: Option<(usize, usize, bool)>,
}

impl Entry {
    /// The value's block mapping on the following lines, when it is one.
    fn child(&self, parent: usize) -> Option<Block> {
        match (self.inline, self.first) {
            (false, Some((start, indent, false))) if indent > parent => Some(Block {
                start,
                end: self.end,
                indent,
            }),
            _ => None,
        }
    }
}

/// The edits that take `old` (the pairs `block` holds in `text`) to `new`. `None`: the block's
/// text could not be read entry by entry, so the caller rewrites the whole value instead.
fn diff(
    text: &str,
    block: Block,
    old: &[(yaml::Value, yaml::Value)],
    new: &[(yaml::Value, yaml::Value)],
    edits: &mut Vec<Edit>,
) -> Option<()> {
    let entries = entries(text, block)?;
    if entries.len() != old.len() {
        return None;
    }
    let mut located = Vec::with_capacity(old.len());
    for (key, value) in old {
        let entry = entries
            .iter()
            .find(|entry| yaml::same_tree(&entry.key, key))?;
        located.push((entry, key, value));
    }
    for (entry, key, before) in located {
        let after = new
            .iter()
            .find(|(other, _)| yaml::same_tree(other, key))
            .map(|(_, value)| value);
        let Some(after) = after else {
            edits.push(Edit {
                start: entry.start,
                end: entry.end,
                text: String::new(),
            });
            continue;
        };
        if yaml::same_tree(before, after) {
            continue;
        }
        if let (Some(old_inner), Some(new_inner), Some(child)) = (
            before.as_mapping(),
            after.as_mapping(),
            entry.child(block.indent),
        ) {
            if !new_inner.is_empty() {
                let mark = edits.len();
                if diff(text, child, old_inner, new_inner, edits).is_some() {
                    continue;
                }
                edits.truncate(mark);
            }
        }
        edits.push(Edit {
            start: entry.start,
            end: entry.end,
            text: emit_entry(&entry.key_text, after, block.indent)?,
        });
    }
    let at = entries.last().map_or(block.start, |entry| entry.end);
    for (key, value) in new {
        if old.iter().any(|(other, _)| yaml::same_tree(other, key)) {
            continue;
        }
        let key_text = emit_key(key)?;
        let mut line = String::new();
        if at > 0 && at == text.len() && !text.ends_with('\n') {
            line.push('\n');
        }
        line.push_str(&emit_entry(&key_text, value, block.indent)?);
        edits.push(Edit {
            start: at,
            end: at,
            text: line,
        });
    }
    Some(())
}

/// The entries of `block`, in text order. `None` for a layout the locator does not read: a tab
/// indent, a line indented less than the block, a sequence item or deeper line before any key, or
/// a key line that is not a plain or quoted scalar key.
fn entries(text: &str, block: Block) -> Option<Vec<Entry>> {
    let region = text.get(block.start..block.end)?;
    let mut found: Vec<Entry> = Vec::new();
    let mut offset = block.start;
    for line in region.split_inclusive('\n') {
        let at = offset;
        offset += line.len();
        let body = line.trim_end_matches(['\n', '\r']);
        let indent = indent_of(body);
        let rest = body.get(indent..).unwrap_or_default();
        if rest.trim().is_empty() || rest.starts_with('#') {
            continue;
        }
        if rest.starts_with('\t') || indent < block.indent {
            return None;
        }
        if indent == block.indent && !is_item(rest) {
            let (key, key_text, inline) = split_key(rest)?;
            found.push(Entry {
                key,
                key_text,
                start: at,
                end: offset,
                inline,
                first: None,
            });
        } else {
            let entry = found.last_mut()?;
            entry.end = offset;
            if entry.first.is_none() {
                entry.first = Some((at, indent, is_item(rest)));
            }
        }
    }
    Some(found)
}

/// Leading spaces.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// A block sequence item (`- x`, or a bare `-`).
fn is_item(rest: &str) -> bool {
    rest == "-" || rest.starts_with("- ") || rest.starts_with("-\t")
}

/// A key line's key (parsed as the document parses it), the key as written, and whether a value
/// follows the colon on the same line.
fn split_key(rest: &str) -> Option<(yaml::Value, String, bool)> {
    let bytes = rest.as_bytes();
    let first = *bytes.first()?;
    let key_end = match first {
        b'"' => {
            let mut at = 1;
            loop {
                match bytes.get(at).copied()? {
                    b'\\' => at += 2,
                    b'"' => break at + 1,
                    _ => at += 1,
                }
            }
        }
        b'\'' => {
            let mut at = 1;
            loop {
                match (bytes.get(at).copied()?, bytes.get(at + 1).copied()) {
                    (b'\'', Some(b'\'')) => at += 2,
                    (b'\'', _) => break at + 1,
                    _ => at += 1,
                }
            }
        }
        b'?' | b'[' | b'{' | b'&' | b'*' | b'!' | b'|' | b'>' | b'%' | b'@' | b'`' | b'#' => {
            return None
        }
        _ => {
            let mut at = 0;
            loop {
                match bytes.get(at).copied()? {
                    b':' if matches!(bytes.get(at + 1).copied(), None | Some(b' ' | b'\t')) => {
                        break at
                    }
                    b'#' if at > 0 && matches!(bytes.get(at - 1).copied(), Some(b' ' | b'\t')) => {
                        return None
                    }
                    _ => at += 1,
                }
            }
        }
    };
    let key_text = rest.get(..key_end)?.trim_end();
    let after_key = rest.get(key_end..)?.trim_start_matches([' ', '\t']);
    let after = after_key.strip_prefix(':')?;
    if !after.is_empty() && !after.starts_with([' ', '\t']) {
        return None;
    }
    let value = after.trim_start();
    let inline = !value.is_empty() && !value.starts_with('#');
    let key: yaml::Value = yaml::from_str(key_text).ok()?;
    if key.is_mapping() || key.is_sequence() {
        return None;
    }
    Some((key, key_text.to_owned(), inline))
}

/// A key for an inserted entry, as the emitter writes a scalar.
fn emit_key(key: &yaml::Value) -> Option<String> {
    let text = emitted(key)?;
    (!text.contains('\n')).then_some(text)
}

/// The emitter's text for one value: no document marker, no trailing newline.
fn emitted(value: &yaml::Value) -> Option<String> {
    let text = yaml::to_string(value).ok()?;
    let text = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("--- "))
        .unwrap_or(&text);
    Some(text.trim_end_matches('\n').to_owned())
}

/// `key: value` at `indent` (the per-span emitter): a non-empty mapping or sequence as a block
/// below the key, anything else after it on the key line (a multi-line scalar continues below).
fn emit_entry(key_text: &str, value: &yaml::Value, indent: usize) -> Option<String> {
    let pad = " ".repeat(indent);
    let body = emitted(value)?;
    let block = match value {
        yaml::Value::Map(pairs) => !pairs.is_empty(),
        yaml::Value::Array(items) => !items.is_empty(),
        _ => false,
    };
    let mut out = String::new();
    if block {
        out.push_str(&pad);
        out.push_str(key_text);
        out.push_str(":\n");
        for line in body.split('\n') {
            if !line.is_empty() {
                out.push_str(&pad);
                out.push_str("  ");
                out.push_str(line);
            }
            out.push('\n');
        }
        return Some(out);
    }
    let mut lines = body.split('\n');
    out.push_str(&pad);
    out.push_str(key_text);
    out.push_str(": ");
    out.push_str(lines.next().unwrap_or_default());
    out.push('\n');
    for line in lines {
        if !line.is_empty() {
            out.push_str(&pad);
            out.push_str(line);
        }
        out.push('\n');
    }
    Some(out)
}

/// The source with every edit applied; the edits are sorted and do not overlap.
fn apply(source: &str, edits: &[Edit]) -> String {
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    for edit in edits {
        out.push_str(source.get(at..edit.start).unwrap_or_default());
        out.push_str(&edit.text);
        at = edit.end;
    }
    out.push_str(source.get(at..).unwrap_or_default());
    out
}

/// Proof two for [`rewrite`]: outside the edited spans the written bytes are the source's.
fn kept_outside(source: &str, written: &str, edits: &[Edit]) -> bool {
    let mut from = 0;
    let mut to = 0;
    for edit in edits {
        let kept = edit.start - from;
        if source.get(from..edit.start) != written.get(to..to + kept) {
            return false;
        }
        to += kept + edit.text.len();
        from = edit.end;
    }
    source.get(from..) == written.get(to..)
}

#[cfg(test)]
#[path = "tests/patch_tests.rs"]
mod tests;
