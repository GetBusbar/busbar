// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GOVERNED SPLICE: the one edit a same-dialect relay makes to a caller's bytes.
//!
//! Law 5: "A RELAY (same dialect) runs the reader only as that read-only tap and sends the client's
//! bytes with governed byte-level splices; a WRITER runs only when translating." The governance a
//! live session splices is Part 2 #45's browser trust boundary: the caller "never authors tools or
//! instructions, and cannot override the session's locked instructions". So a caller frame that
//! configures the session, or asks for one response under its own settings, has its instructions and
//! tool set cut out and the session's locked keys put in their place; every other member it wrote
//! passes as the caller wrote it, byte for byte, and so does every frame that configures nothing.
//!
//! The edit is made on the frame's own bytes: one object member is rebuilt from the members the
//! caller wrote (their bytes unchanged, in their order) and the locked members after them, and the
//! bytes around that object are copied as they arrived. Keys are compared as the far end reads them,
//! escapes decoded, and a key the caller wrote twice is cut every time it appears.

use serde_json::{Map, Value};

use crate::codec::ir::codec::gemini::{setup_locked, GeminiLiveCodec};
use crate::codec::ir::codec::OpenAiRealtimeCodec;
use crate::codec::ir::config::SessionConfig;

/// Where in a dialect's caller frame the governed object sits, and what is done to it.
#[derive(Debug)]
pub struct Rule {
    /// The top-level member holding the governed object.
    pub at: &'static str,
    /// The keys a caller never authors there.
    pub cut: &'static [&'static str],
    /// The locked members put in, each over the caller's own (an object over an object is merged
    /// member by member).
    pub set: Map<String, Value>,
}

/// THE DIALECT'S GOVERNED KEYS: which caller frames a session's lock splices, and how.
pub trait LockedKeys {
    /// The rule for a frame that configures the session (`session.update`, `setup`), locked to
    /// `locked`.
    fn configure_rule(&self, locked: &SessionConfig) -> Rule;
    /// The rule for a frame that asks for one response under its own settings; `None` for a
    /// dialect with no such frame.
    fn response_rule(&self) -> Option<Rule>;
}

/// OpenAI Realtime: `session.update`'s `session`, and `response.create`'s `response`.
const REALTIME_CUT: &[&str] = &["instructions", "tools"];
/// Gemini Live: `setup`'s system instruction and tools.
const LIVE_CUT: &[&str] = &["systemInstruction", "tools"];

impl LockedKeys for OpenAiRealtimeCodec {
    fn configure_rule(&self, locked: &SessionConfig) -> Rule {
        Rule {
            at: "session",
            cut: REALTIME_CUT,
            set: match serde_json::to_value(locked) {
                Ok(Value::Object(m)) => m,
                _ => Map::new(),
            },
        }
    }

    fn response_rule(&self) -> Option<Rule> {
        Some(Rule {
            at: "response",
            cut: REALTIME_CUT,
            set: Map::new(),
        })
    }
}

impl LockedKeys for GeminiLiveCodec {
    fn configure_rule(&self, locked: &SessionConfig) -> Rule {
        Rule {
            at: "setup",
            cut: LIVE_CUT,
            set: setup_locked(locked),
        }
    }

    fn response_rule(&self) -> Option<Rule> {
        None
    }
}

/// `frame` with `rule` applied to every top-level `rule.at` object; the frame unchanged when it
/// holds none. `None` when the frame is not one JSON object.
#[must_use]
pub fn splice(frame: &[u8], rule: &Rule) -> Option<Vec<u8>> {
    let open = ws(frame, 0);
    let (members, close) = members(frame, open)?;
    if ws(frame, close) != frame.len() {
        return None;
    }
    let mut out = Vec::with_capacity(frame.len() + 64);
    let mut at = 0;
    for m in members.iter().filter(|m| m.key == rule.at) {
        if frame.get(m.value.0) != Some(&b'{') {
            continue;
        }
        let edited = object(frame, m.value.0, rule.cut, &rule.set)?;
        out.extend_from_slice(&frame[at..m.value.0]);
        out.extend_from_slice(&edited);
        at = m.value.1;
    }
    out.extend_from_slice(&frame[at..]);
    Some(out)
}

/// One member of an object: its key as the far end reads it, where it starts and its value's span.
struct JsonMember {
    key: String,
    start: usize,
    value: (usize, usize),
}

/// The object at `b[open]`, rebuilt: the caller's members not cut and not set, in order and byte for
/// byte, then each `set` member (merged into the caller's when both are objects).
fn object(b: &[u8], open: usize, cut: &[&str], set: &Map<String, Value>) -> Option<Vec<u8>> {
    let (members, _) = members(b, open)?;
    let mut out = vec![b'{'];
    let mut first = true;
    let mut sep = |out: &mut Vec<u8>| {
        if !std::mem::take(&mut first) {
            out.push(b',');
        }
    };
    for m in &members {
        if cut.contains(&m.key.as_str()) || set.contains_key(&m.key) {
            continue;
        }
        sep(&mut out);
        out.extend_from_slice(&b[m.start..m.value.1]);
    }
    for (key, value) in set {
        sep(&mut out);
        out.extend_from_slice(&serde_json::to_vec(key).ok()?);
        out.push(b':');
        let theirs = members
            .iter()
            .rev()
            .find(|m| &m.key == key && b.get(m.value.0) == Some(&b'{'));
        match (value, theirs) {
            (Value::Object(locked), Some(m)) => {
                out.extend_from_slice(&object(b, m.value.0, &[], locked)?);
            }
            _ => out.extend_from_slice(&serde_json::to_vec(value).ok()?),
        }
    }
    out.push(b'}');
    Some(out)
}

/// The index of the first byte at or after `i` that is not JSON whitespace.
fn ws(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// The index past the JSON string starting at `b[i]`.
fn string_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// The index past the JSON value starting at `b[i]`.
fn value_end(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'"' => string_end(b, i),
        b'{' | b'[' => {
            let mut depth = 0_usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = string_end(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The members of the object at `b[open]`, and the index past its closing brace.
fn members(b: &[u8], open: usize) -> Option<(Vec<JsonMember>, usize)> {
    if b.get(open) != Some(&b'{') {
        return None;
    }
    let mut out = Vec::new();
    let mut i = ws(b, open + 1);
    if b.get(i) == Some(&b'}') {
        return Some((out, i + 1));
    }
    loop {
        if b.get(i) != Some(&b'"') {
            return None;
        }
        let key_end = string_end(b, i)?;
        let key: String = serde_json::from_slice(&b[i..key_end]).ok()?;
        let colon = ws(b, key_end);
        if b.get(colon) != Some(&b':') {
            return None;
        }
        let start = ws(b, colon + 1);
        let end = value_end(b, start)?;
        out.push(JsonMember {
            key,
            start: i,
            value: (start, end),
        });
        let next = ws(b, end);
        match b.get(next)? {
            b',' => i = ws(b, next + 1),
            b'}' => return Some((out, next + 1)),
            _ => return None,
        }
    }
}

#[cfg(test)]
#[path = "tests/splice_tests.rs"]
mod tests;
