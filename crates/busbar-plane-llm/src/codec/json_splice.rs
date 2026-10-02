// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BYTE-LEVEL MEMBER SPLICES on a JSON object: the one way this plane edits a body it relays.
//!
//! A same-dialect attempt sends the caller's bytes. The few members busbar governs (the mapped
//! `model`, the metering `stream_options.include_usage`, its own router keys) are edited IN PLACE
//! over the caller's bytes: a member's value is replaced where it stands, a member is removed with
//! exactly one adjacent comma, a missing member is inserted right after the opening brace. Every
//! other byte (key order, whitespace, number spelling, escapes) stays the caller's. Nothing is
//! parsed into a tree and nothing is re-serialized (LLM DIALECT FIDELITY, owner 2026-10-02;
//! DIALECT-FIDELITY-DESIGN F2).
//!
//! The scanner locates; it does not validate. A body it cannot read as an object is left alone and
//! the caller decides what that means.

use std::borrow::Cow;

use super::dialect::{scan_json_string_end, scan_json_value_end};

/// One member of an object, located in its buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The key, unescaped.
    pub key: String,
    /// The key's opening quote.
    pub key_start: usize,
    /// The value's first byte.
    pub value_start: usize,
    /// One past the value's last byte.
    pub value_end: usize,
    /// The comma that follows the member, when another member follows.
    pub comma: Option<usize>,
}

/// An object, located in its buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// The opening brace.
    pub open: usize,
    /// The closing brace.
    pub close: usize,
    /// Its members, in order.
    pub members: Vec<Member>,
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn unescape_key(raw: &[u8]) -> Option<String> {
    if raw.contains(&b'\\') {
        serde_json::from_slice::<String>(raw).ok()
    } else {
        std::str::from_utf8(&raw[1..raw.len() - 1])
            .ok()
            .map(str::to_string)
    }
}

/// The object whose opening brace is the first significant byte at or after `at`.
#[must_use]
pub fn object_at(b: &[u8], at: usize) -> Option<Object> {
    let open = skip_ws(b, at);
    if b.get(open) != Some(&b'{') {
        return None;
    }
    let mut members = Vec::new();
    let mut i = skip_ws(b, open + 1);
    if b.get(i) == Some(&b'}') {
        return Some(Object {
            open,
            close: i,
            members,
        });
    }
    loop {
        if b.get(i) != Some(&b'"') {
            return None;
        }
        let key_start = i;
        let key_end = scan_json_string_end(b, i)?;
        let key = unescape_key(&b[key_start..key_end])?;
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return None;
        }
        let value_start = skip_ws(b, i + 1);
        let value_end = scan_json_value_end(b, value_start)?;
        i = skip_ws(b, value_end);
        match b.get(i) {
            Some(b',') => {
                members.push(Member {
                    key,
                    key_start,
                    value_start,
                    value_end,
                    comma: Some(i),
                });
                i = skip_ws(b, i + 1);
            }
            Some(b'}') => {
                members.push(Member {
                    key,
                    key_start,
                    value_start,
                    value_end,
                    comma: None,
                });
                return Some(Object {
                    open,
                    close: i,
                    members,
                });
            }
            _ => return None,
        }
    }
}

impl Object {
    /// The last member named `key` (the one a last-wins reader honours).
    #[must_use]
    pub fn last(&self, key: &str) -> Option<&Member> {
        self.members.iter().rev().find(|m| m.key == key)
    }
}

/// One governed edit of an object's member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit<'a> {
    /// Remove every member named so.
    Remove(&'a str),
    /// Give every member named so this raw JSON value; insert it after the opening brace when the
    /// object has none. A member whose value already reads the same is left untouched.
    Set(&'a str, Cow<'a, [u8]>),
}

impl Edit<'_> {
    fn key(&self) -> &str {
        match self {
            Edit::Remove(k) | Edit::Set(k, _) => k,
        }
    }
}

/// The same JSON value, whatever its spelling.
fn same_value(a: &[u8], b: &[u8]) -> bool {
    a == b
        || matches!(
            (
                serde_json::from_slice::<serde_json::Value>(a),
                serde_json::from_slice::<serde_json::Value>(b),
            ),
            (Ok(x), Ok(y)) if x == y
        )
}

/// One replacement over a buffer: `[start, end)` becomes `with`.
type Cut<'a> = (usize, usize, Cow<'a, [u8]>);

/// APPLY `edits` to the object `obj` of `b` (a later edit of a key overrides an earlier one).
/// `None` when nothing changes.
#[must_use]
pub fn apply(b: &[u8], obj: &Object, edits: &[Edit<'_>]) -> Option<Vec<u8>> {
    let cuts = edit_cuts(b, obj, edits)?;
    render(b, cuts)
}

/// The cuts `edits` make to `obj`; `None` when the object's punctuation cannot be read.
fn edit_cuts<'a>(b: &'a [u8], obj: &Object, edits: &'a [Edit<'a>]) -> Option<Vec<Cut<'a>>> {
    // The winning edit per key, in first-mention order.
    let mut wins: Vec<&Edit<'_>> = Vec::new();
    for e in edits {
        match wins.iter_mut().find(|w| w.key() == e.key()) {
            Some(w) => *w = e,
            None => wins.push(e),
        }
    }
    let edit_of = |key: &str| wins.iter().copied().find(|w| w.key() == key);
    let n = obj.members.len();
    let removed: Vec<bool> = obj
        .members
        .iter()
        .map(|m| matches!(edit_of(&m.key), Some(Edit::Remove(_))))
        .collect();
    // (start, end, replacement) over `b`, in order, never overlapping.
    let mut cuts: Vec<(usize, usize, Cow<'_, [u8]>)> = Vec::new();
    let mut inserted: Vec<u8> = Vec::new();
    for w in &wins {
        if let Edit::Set(k, v) = w {
            if !obj.members.iter().any(|m| m.key == *k) {
                if !inserted.is_empty() {
                    inserted.push(b',');
                }
                inserted.extend_from_slice(&serde_json::to_vec(k).ok()?);
                inserted.push(b':');
                inserted.extend_from_slice(v);
            }
        }
    }
    let kept = removed.iter().filter(|r| !**r).count();
    if !inserted.is_empty() {
        if kept > 0 {
            inserted.push(b',');
        }
        cuts.push((obj.open + 1, obj.open + 1, Cow::Owned(inserted)));
    }
    let mut i = 0;
    while i < n {
        let m = &obj.members[i];
        if !removed[i] {
            if let Some(Edit::Set(_, v)) = edit_of(&m.key) {
                if !same_value(&b[m.value_start..m.value_end], v) {
                    cuts.push((m.value_start, m.value_end, Cow::Borrowed(v.as_ref())));
                }
            }
            i += 1;
            continue;
        }
        // A run of removed members [i, j].
        let mut j = i;
        while j + 1 < n && removed[j + 1] {
            j += 1;
        }
        let (start, end) = if j + 1 < n {
            // A kept member follows: the run goes with the comma after it.
            (obj.members[i].key_start, obj.members[j].comma? + 1)
        } else if i > 0 {
            // The run ends the object: it goes with the comma before it.
            (obj.members[i - 1].comma?, obj.members[j].value_end)
        } else {
            (obj.members[i].key_start, obj.members[j].value_end)
        };
        cuts.push((start, end, Cow::Borrowed(&[][..])));
        i = j + 1;
    }
    Some(cuts)
}

/// `b` with `cuts` made; `None` when there are none.
fn render(b: &[u8], mut cuts: Vec<Cut<'_>>) -> Option<Vec<u8>> {
    if cuts.is_empty() {
        return None;
    }
    cuts.sort_by_key(|c| (c.0, c.1));
    let mut out = Vec::with_capacity(b.len() + 64);
    let mut at = 0;
    for (start, end, with) in &cuts {
        out.extend_from_slice(&b[at..*start]);
        out.extend_from_slice(with);
        at = *end;
    }
    out.extend_from_slice(&b[at..]);
    Some(out)
}

/// APPLY `edits` to the top-level object of `b`. `None` when `b` is not an object or nothing
/// changes.
#[must_use]
pub fn apply_top(b: &[u8], edits: &[Edit<'_>]) -> Option<Vec<u8>> {
    let obj = object_at(b, 0)?;
    apply(b, &obj, edits)
}

/// The elements of the array whose opening bracket is the first significant byte at `at`: each
/// element's `[start, end)`.
fn array_at(b: &[u8], at: usize) -> Option<Vec<(usize, usize)>> {
    let open = skip_ws(b, at);
    if b.get(open) != Some(&b'[') {
        return None;
    }
    let mut elements = Vec::new();
    let mut i = skip_ws(b, open + 1);
    if b.get(i) == Some(&b']') {
        return Some(elements);
    }
    loop {
        let end = scan_json_value_end(b, i)?;
        elements.push((i, end));
        i = skip_ws(b, end);
        match b.get(i) {
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b']') => return Some(elements),
            _ => return None,
        }
    }
}

/// The cuts that turn the value at `[start, end)` of `b` (which reads as `old`) into `new`,
/// touching only what differs: an object's unchanged members and an equal-length array's
/// unchanged elements keep their bytes; anything else that differs is written whole.
fn diff_cuts(
    b: &[u8],
    (start, end): (usize, usize),
    old: &serde_json::Value,
    new: &serde_json::Value,
    cuts: &mut Vec<Cut<'static>>,
) -> Option<()> {
    use serde_json::Value;
    if old == new {
        return Some(());
    }
    let whole = |cuts: &mut Vec<Cut<'static>>| -> Option<()> {
        cuts.push((start, end, Cow::Owned(serde_json::to_vec(new).ok()?)));
        Some(())
    };
    match (old, new) {
        (Value::Object(o), Value::Object(n)) => {
            let Some(obj) = object_at(&b[..end], start) else {
                return whole(cuts);
            };
            let unique = obj
                .members
                .iter()
                .all(|m| obj.members.iter().filter(|x| x.key == m.key).count() == 1);
            if !unique {
                return whole(cuts);
            }
            let mut raw: Vec<(String, Option<Vec<u8>>)> = Vec::new();
            for k in o.keys().filter(|k| !n.contains_key(*k)) {
                raw.push((k.clone(), None));
            }
            for (k, v) in n.iter().filter(|(k, _)| !o.contains_key(*k)) {
                raw.push((k.clone(), Some(serde_json::to_vec(v).ok()?)));
            }
            let edits: Vec<Edit<'_>> = raw
                .iter()
                .map(|(k, v)| match v {
                    Some(v) => Edit::Set(k, Cow::Borrowed(v.as_slice())),
                    None => Edit::Remove(k),
                })
                .collect();
            for (s, e, with) in edit_cuts(&b[..end], &obj, &edits)? {
                cuts.push((s, e, Cow::Owned(with.into_owned())));
            }
            for m in &obj.members {
                if let (Some(ov), Some(nv)) = (o.get(&m.key), n.get(&m.key)) {
                    diff_cuts(b, (m.value_start, m.value_end), ov, nv, cuts)?;
                }
            }
            Some(())
        }
        (Value::Array(o), Value::Array(n)) if o.len() == n.len() => {
            let Some(elements) = array_at(&b[..end], start) else {
                return whole(cuts);
            };
            if elements.len() != o.len() {
                return whole(cuts);
            }
            for ((span, ov), nv) in elements.into_iter().zip(o).zip(n) {
                diff_cuts(b, span, ov, nv, cuts)?;
            }
            Some(())
        }
        _ => whole(cuts),
    }
}

/// THE WRITE-BACK SPLICE: `b` (which reads as `old`) edited to read as `new`, touching only the
/// members and elements that differ — every untouched block keeps its bytes. `None` when nothing
/// differs or `b` cannot be read as `old`'s shape (the caller then writes `new` whole).
#[must_use]
pub fn diff(b: &[u8], old: &serde_json::Value, new: &serde_json::Value) -> Option<Vec<u8>> {
    let start = skip_ws(b, 0);
    let end = scan_json_value_end(b, start)?;
    let mut cuts = Vec::new();
    diff_cuts(b, (start, end), old, new, &mut cuts)?;
    render(b, cuts)
}

#[cfg(test)]
#[path = "tests/json_splice_tests.rs"]
mod tests;
