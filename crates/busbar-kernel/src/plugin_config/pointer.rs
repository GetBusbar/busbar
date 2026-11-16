// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Declared config positions (D_SECRET_PATH, D_TRUST_PATH, D_DEST_PATH, D_REF_PATH): RFC 6901 JSON Pointers in
//! which a `*` token stands for any array index (IF §8 `secret_path`). Expanded against one config into the
//! concrete pointers present in it; an absent position binds nothing.

use serde_json::Value;

/// The unescaped reference tokens of `pattern` (`""` = the whole document). None = not a JSON Pointer.
pub(super) fn tokens(pattern: &str) -> Option<Vec<String>> {
    if pattern.is_empty() {
        return Some(Vec::new());
    }
    let rest = pattern.strip_prefix('/')?;
    let mut out = Vec::new();
    for raw in rest.split('/') {
        out.push(unescape(raw)?);
    }
    Some(out)
}

fn unescape(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// One token, escaped for a concrete pointer.
pub(super) fn escape_into(out: &mut String, token: &str) {
    for c in token.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            c => out.push(c),
        }
    }
}

/// Every concrete pointer in `doc` that `pattern` names, in document order (array indices ascending).
pub(super) fn expand(doc: &Value, pattern: &str, out: &mut Vec<String>) {
    let Some(tokens) = tokens(pattern) else {
        return;
    };
    let mut at = String::new();
    walk(doc, &tokens, &mut at, out);
}

fn walk(node: &Value, tokens: &[String], at: &mut String, out: &mut Vec<String>) {
    let Some((head, rest)) = tokens.split_first() else {
        out.push(at.clone());
        return;
    };
    let mark = at.len();
    match node {
        Value::Array(items) if head == "*" => {
            for (i, item) in items.iter().enumerate() {
                at.push('/');
                at.push_str(itoa(i).as_str());
                walk(item, rest, at, out);
                at.truncate(mark);
            }
        }
        Value::Array(items) => {
            if let Some(item) = head.parse::<usize>().ok().and_then(|i| items.get(i)) {
                at.push('/');
                at.push_str(head);
                walk(item, rest, at, out);
                at.truncate(mark);
            }
        }
        Value::Object(map) => {
            if let Some(child) = map.get(head.as_str()) {
                at.push('/');
                escape_into(at, head);
                walk(child, rest, at, out);
                at.truncate(mark);
            }
        }
        _ => {}
    }
}

fn itoa(i: usize) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = write!(s, "{i}");
    s
}

/// Whether the concrete pointer `at` is named by `pattern` (`*` matching any array index token).
pub(super) fn matches(pattern: &str, at: &str) -> bool {
    let (Some(p), Some(a)) = (tokens(pattern), tokens(at)) else {
        return false;
    };
    p.len() == a.len()
        && p.iter().zip(a.iter()).all(|(p, a)| {
            p == a || (p == "*" && !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Whether `at` is `prefix` or lies beneath it.
pub(super) fn within(prefix: &str, at: &str) -> bool {
    at == prefix
        || (at.len() > prefix.len()
            && at.starts_with(prefix)
            && at.as_bytes().get(prefix.len()) == Some(&b'/'))
}
