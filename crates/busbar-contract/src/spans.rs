//! The closed JSON span grammar, on the plugin surface.

pub use crate::json_grammar::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

use crate::bounded::{PlaneAlloc, PlaneAllocBudget, MAX_KEYS};

/// Resolve a plane's declared pointers over a body, into a table the unit can hold.

pub fn resolve<'a>(
    body: &[u8],
    pointers: &[&'a str],
    arena: &'a dyn PlaneAlloc,
) -> Result<&'a [(&'a str, Span)], PlaneAllocBudget> {
    let mut found: [(&'a str, Span); MAX_KEYS] = [("", Span::new(0, 0)); MAX_KEYS];
    let mut len = 0usize;
    for pointer in pointers.iter().take(MAX_KEYS) {
        if let Resolved::Found(span) = resolve_pointer(body, pointer) {
            found[len] = (*pointer, span);
            len += 1;
        }
    }
    arena.alloc_spans(&found[..len])
}

/// THE JSON NESTING-DEPTH GUARD: does `bytes` nest `{`/`[` deeper than `max`?

#[must_use]
pub fn exceeds_max_depth(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

use std::borrow::Cow;

/// `i` moved past the JSON whitespace (space, tab, line feed, carriage return) at it.
fn past_ws(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// One past the closing quote of the JSON string whose opening quote is at `open_quote`, honouring

#[must_use]
pub fn string_end(b: &[u8], open_quote: usize) -> Option<usize> {
    if b.get(open_quote) != Some(&b'"') {
        return None;
    }
    let mut i = open_quote + 1;
    while let Some(c) = b.get(i) {
        match c {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// One past the JSON value that starts at `start` (whitespace before it allowed), respecting nested

#[must_use]
pub fn value_end(b: &[u8], start: usize) -> Option<usize> {
    let mut i = past_ws(b, start);
    match b.get(i)? {
        b'"' => string_end(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            while let Some(c) = b.get(i) {
                match c {
                    b'"' => i = string_end(b, i)?,
                    b'{' | b'[' => {
                        depth += 1;
                        i += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        i += 1;
                        if depth == 0 {
                            return Some(i);
                        }
                    }
                    _ => i += 1,
                }
            }
            None
        }
        _ => {
            let first = i;
            while !matches!(
                b.get(i),
                None | Some(b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            ) {
                i += 1;
            }
            (i > first).then_some(i)
        }
    }
}

/// A key as written (quotes included), unescaped.
fn unescape_key(raw: &[u8]) -> Option<String> {
    if raw.contains(&b'\\') {
        serde_json::from_slice::<String>(raw).ok()
    } else {
        std::str::from_utf8(raw.get(1..raw.len().saturating_sub(1))?)
            .ok()
            .map(str::to_string)
    }
}

/// One member as [`scan`] meets it: the raw key (quotes included, escapes as written) and the
/// member's positions.
#[derive(Clone, Copy, Debug)]
pub struct RawMember<'a> {
    /// The key as written, quotes included.
    pub raw_key: &'a [u8],
    /// The key's opening quote.
    pub key_start: usize,
    /// The value's first byte.
    pub value_start: usize,
    /// One past the value's last byte.
    pub value_end: usize,
    /// The comma that follows the member, when another member follows.
    pub comma: Option<usize>,
}

impl RawMember<'_> {
    /// Whether the key is `key`, without allocating when it is written without escapes.
    #[must_use]
    pub fn is(&self, key: &str) -> bool {
        let inner = self
            .raw_key
            .get(1..self.raw_key.len().saturating_sub(1))
            .unwrap_or_default();
        if inner.contains(&b'\\') {
            unescape_key(self.raw_key).is_some_and(|k| k == key)
        } else {
            inner == key.as_bytes()
        }
    }

    /// The value's span.
    #[must_use]
    pub const fn value(&self) -> Span {
        Span::new(self.value_start, self.value_end)
    }
}

/// SCAN the object whose opening brace is the first significant byte at or after `at`, meeting

pub fn scan<'a>(
    b: &'a [u8],
    at: usize,
    mut each: impl FnMut(RawMember<'a>),
) -> Option<(usize, usize)> {
    let open = past_ws(b, at);
    if b.get(open) != Some(&b'{') {
        return None;
    }
    let mut i = past_ws(b, open + 1);
    if b.get(i) == Some(&b'}') {
        return Some((open, i));
    }
    loop {
        let key_start = i;
        let key_end = string_end(b, i)?;
        i = past_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return None;
        }
        let value_start = past_ws(b, i + 1);
        let value_end = value_end(b, value_start)?;
        i = past_ws(b, value_end);
        let comma = match b.get(i) {
            Some(b',') => Some(i),
            Some(b'}') => None,
            _ => return None,
        };
        each(RawMember {
            raw_key: b.get(key_start..key_end)?,
            key_start,
            value_start,
            value_end,
            comma,
        });
        match comma {
            Some(c) => i = past_ws(b, c + 1),
            None => return Some((open, i)),
        }
    }
}

/// One member of an object, located in its buffer, its key unescaped.
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

impl Member {
    /// The value's span.
    #[must_use]
    pub const fn value(&self) -> Span {
        Span::new(self.value_start, self.value_end)
    }
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

impl Object {
    /// The last member named `key` (the one a last-wins reader honours).
    #[must_use]
    pub fn last(&self, key: &str) -> Option<&Member> {
        self.members.iter().rev().find(|m| m.key == key)
    }
}

/// The MEMBERS of the object whose opening brace is the first significant byte at or after `at`.

#[must_use]
pub fn members(b: &[u8], at: usize) -> Option<Object> {
    let mut members = Vec::new();
    let mut keys_ok = true;
    let (open, close) = scan(b, at, |m| match unescape_key(m.raw_key) {
        Some(key) => members.push(Member {
            key,
            key_start: m.key_start,
            value_start: m.value_start,
            value_end: m.value_end,
            comma: m.comma,
        }),
        None => keys_ok = false,
    })?;
    keys_ok.then_some(Object {
        open,
        close,
        members,
    })
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

#[must_use]
pub fn apply(b: &[u8], obj: &Object, edits: &[Edit<'_>]) -> Option<Vec<u8>> {
    render(b, edit_cuts(b, obj, edits)?)
}

/// APPLY `edits` to the top-level object of `b`. `None` when `b` is not an object or nothing

#[must_use]
pub fn apply_top(b: &[u8], edits: &[Edit<'_>]) -> Option<Vec<u8>> {
    apply(b, &members(b, 0)?, edits)
}

/// The cuts `edits` make to `obj`; `None` when the object's punctuation cannot be read.
fn edit_cuts<'a>(b: &'a [u8], obj: &Object, edits: &'a [Edit<'a>]) -> Option<Vec<Cut<'a>>> {
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

    let mut cuts: Vec<Cut<'_>> = Vec::new();
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
                if !same_value(b.get(m.value_start..m.value_end)?, v) {
                    cuts.push((m.value_start, m.value_end, Cow::Borrowed(v.as_ref())));
                }
            }
            i += 1;
            continue;
        }

        let mut j = i;
        while j + 1 < n && removed[j + 1] {
            j += 1;
        }
        let (start, end) = if i > 0 {
            (obj.members[i - 1].comma?, obj.members[j].value_end)
        } else if j + 1 < n {
            (obj.members[i].key_start, obj.members[j].comma? + 1)
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
        out.extend_from_slice(b.get(at..*start)?);
        out.extend_from_slice(with);
        at = *end;
    }
    out.extend_from_slice(b.get(at..)?);
    Some(out)
}

#[cfg(test)]
#[path = "tests/spans_object_tests.rs"]
mod object_tests;
