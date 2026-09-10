//! ORDER-PRESERVING JSON, and Python's `json.dump` byte-for-byte.
//!
//! Two of the gates converted in batch 2 read committed JSON whose KEY ORDER IS THE DATA.
//! `qa/teller-steps.json`'s `steps` object is the Teller step ORDER — `list(steps)` in the Python
//! is the sequence the matrix is rendered in, so a reader that sorts keys renders a different
//! matrix. `qa/audit-ledger.json` is written back by `sync`/`record`/`fixed` with
//! `json.dump(doc, fh, indent=1, ensure_ascii=False, sort_keys=False)`, so a reader that loses
//! order and a writer that emits `serde_json`'s two-space, sorted, ASCII-escaped shape rewrite
//! 147KB of committed register on the first `sync --write` and destroy the diff.
//!
//! `serde_json` can do neither: `preserve_order` is a workspace-wide feature flag on a dependency
//! eleven other crates share, and its `to_string_pretty` is two-space indent with no way to ask for
//! one. So this module carries the reader and the writer, sized to exactly what those two files
//! contain and refusing anything else rather than guessing.
//!
//! [`dump_python`] reproduces `json.dump(..., indent=1, ensure_ascii=False, sort_keys=False)`:
//!
//! * ONE space per nesting level, not two;
//! * insertion order, never sorted;
//! * `ensure_ascii=False` — non-ASCII passes through as UTF-8 rather than `\uXXXX`;
//! * Python's escape table: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t` as short forms, every other
//!   C0 control as `\u00xx` lowercase-hex, and `/` NOT escaped;
//! * empty containers inline as `{}` / `[]` with no interior newline — the one case where Python's
//!   pretty-printer does not break the line;
//! * no trailing whitespace on any line.
//!
//! The caller adds the trailing `"\n"` Python's writers add separately, so a file that must end in
//! exactly one newline says so at its own call site.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A JSON value whose objects remember the order their keys arrived in.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Integers are kept as `i64` because neither file this module reads contains a float, and a
    /// register that round-trips `3` as `3.0` is a register whose diff is noise.
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Obj),
}

/// An object: the entries in order, plus an index so lookup is not a linear scan over 144 scopes
/// times every query.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Obj {
    entries: Vec<(String, Json)>,
    index: BTreeMap<String, usize>,
}

impl Obj {
    pub fn new() -> Obj {
        Obj::default()
    }

    /// Insert, or REPLACE IN PLACE. Replacing in place is the load-bearing half: `sync --write`
    /// assigns the preserved keys over a freshly derived scope, and Python's `dict` keeps the
    /// original position when an existing key is reassigned. A writer that moved the key to the end
    /// would reorder every scope in the register.
    pub fn insert(&mut self, key: impl Into<String>, value: Json) {
        let key = key.into();
        match self.index.get(&key) {
            Some(&i) => self.entries[i].1 = value,
            None => {
                self.index.insert(key.clone(), self.entries.len());
                self.entries.push((key, value));
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.index.get(key).map(|&i| &self.entries[i].1)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        let i = *self.index.get(key)?;
        Some(&mut self.entries[i].1)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// Remove a key, keeping every remaining key in its position. Used only by the selftests, which
    /// plant a violation by taking a step or a leg OUT of the real committed matrix — a plant that
    /// also reordered the file would be proving the reader, not the rule.
    pub fn remove(&mut self, key: &str) -> Option<Json> {
        let i = self.index.remove(key)?;
        let (_, v) = self.entries.remove(i);
        for slot in self.index.values_mut() {
            if *slot > i {
                *slot -= 1;
            }
        }
        Some(v)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The keys IN ORDER. `qa/teller-steps.json`'s step order is exactly this.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Json)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl Json {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Obj> {
        match self {
            Json::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut Obj> {
        match self {
            Json::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Python truthiness, which is what every `sc.get("auditor")` guard in `audit-ledger.py`
    /// actually tests: `None`, `false`, `0`, `""`, `[]` and `{}` are all falsy.
    pub fn truthy(&self) -> bool {
        match self {
            Json::Null => false,
            Json::Bool(b) => *b,
            Json::Int(i) => *i != 0,
            Json::Float(f) => *f != 0.0,
            Json::Str(s) => !s.is_empty(),
            Json::Array(a) => !a.is_empty(),
            Json::Object(o) => !o.is_empty(),
        }
    }

    /// The key's value, or `Json::Null` — `dict.get(k)` with no default, so a caller never has to
    /// spell the absent case differently from the null case where Python does not either.
    pub fn get(&self, key: &str) -> &Json {
        const NULL: &Json = &Json::Null;
        self.as_object().and_then(|o| o.get(key)).unwrap_or(NULL)
    }

    pub fn str_or(&self, key: &str, default: &str) -> String {
        self.get(key).as_str().unwrap_or(default).to_string()
    }
}

/// `repr()` of a Python string — single-quoted unless the value contains a `'` and no `"`.
///
/// This is not decoration: `audit-ledger.py --check` prints `result %r` and
/// `teller-steps-check.py` prints `status {..!r}`, so the offender lines a reviewer greps for are
/// spelled `'passed'`, not `"passed"`.
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr()` of a JSON value as Python would print the object `json.load` produced: `None`, `True`,
/// integers bare, strings single-quoted.
pub fn py_repr_json(v: &Json) -> String {
    match v {
        Json::Null => "None".to_string(),
        Json::Bool(true) => "True".to_string(),
        Json::Bool(false) => "False".to_string(),
        Json::Int(i) => i.to_string(),
        Json::Float(f) => format!("{f}"),
        Json::Str(s) => py_repr(s),
        Json::Array(a) => format!(
            "[{}]",
            a.iter().map(py_repr_json).collect::<Vec<_>>().join(", ")
        ),
        Json::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr_json(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The name Python's `type(x).__name__` gives a decoded JSON value, for the register's
/// `counts is %s, want an object` refusal.
pub fn py_type_name(v: &Json) -> &'static str {
    match v {
        Json::Null => "NoneType",
        Json::Bool(_) => "bool",
        Json::Int(_) => "int",
        Json::Float(_) => "float",
        Json::Str(_) => "str",
        Json::Array(_) => "list",
        Json::Object(_) => "dict",
    }
}

// ---------------------------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------------------------

/// Parse a JSON document. TRAILING BYTES ARE AN ERROR: a register whose second half was never read
/// is not a register with fewer scopes.
pub fn parse(text: &str) -> Result<Json, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut p = Parser { chars, i: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != p.chars.len() {
        return Err(format!(
            "trailing bytes after the document at char {} — a document whose tail was never read \
             is not a shorter document",
            p.i
        ));
    }
    Ok(v)
}

struct Parser {
    chars: Vec<char>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!(
                "char {}: expected `{c}`, found {}",
                self.i,
                self.peek().map(String::from).unwrap_or("end".into())
            ))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('t') => self.literal("true", Json::Bool(true)),
            Some('f') => self.literal("false", Json::Bool(false)),
            Some('n') => self.literal("null", Json::Null),
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            other => Err(format!(
                "char {}: no JSON value starts with {}",
                self.i,
                other.map(String::from).unwrap_or("end".into())
            )),
        }
    }

    fn literal(&mut self, word: &str, v: Json) -> Result<Json, String> {
        for c in word.chars() {
            self.expect(c)?;
        }
        Ok(v)
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect('{')?;
        let mut obj = Obj::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.i += 1;
            return Ok(Json::Object(obj));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(':')?;
            self.skip_ws();
            let val = self.value()?;
            // LAST WINS, which is what `json.load` does with a duplicate key, and the position the
            // FIRST occurrence held is the position Python's dict keeps.
            obj.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(',') => self.i += 1,
                Some('}') => {
                    self.i += 1;
                    return Ok(Json::Object(obj));
                }
                _ => return Err(format!("char {}: expected `,` or `}}` in object", self.i)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect('[')?;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.i += 1;
            return Ok(Json::Array(out));
        }
        loop {
            self.skip_ws();
            out.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => self.i += 1,
                Some(']') => {
                    self.i += 1;
                    return Ok(Json::Array(out));
                }
                _ => return Err(format!("char {}: expected `,` or `]` in array", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err("unterminated string".to_string());
            };
            self.i += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let Some(e) = self.peek() else {
                        return Err("unterminated escape".to_string());
                    };
                    self.i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => out.push(self.unicode_escape()?),
                        other => return Err(format!("unknown escape `\\{other}`")),
                    }
                }
                c => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut n = 0u32;
        for _ in 0..4 {
            let Some(c) = self.peek() else {
                return Err("truncated \\u escape".to_string());
            };
            let d = c
                .to_digit(16)
                .ok_or_else(|| format!("`{c}` is not a hex digit in a \\u escape"))?;
            n = n * 16 + d;
            self.i += 1;
        }
        Ok(n)
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let hi = self.hex4()?;
        // A LONE SURROGATE IS AN ERROR, not a replacement character: a register key that decoded to
        // U+FFFD would compare unequal to itself on the next read.
        if (0xD800..0xDC00).contains(&hi) {
            if self.peek() == Some('\\') && self.chars.get(self.i + 1) == Some(&'u') {
                self.i += 2;
                let lo = self.hex4()?;
                if (0xDC00..0xE000).contains(&lo) {
                    let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    return char::from_u32(c).ok_or_else(|| format!("bad code point U+{c:X}"));
                }
                return Err(format!(
                    "\\u{hi:04X} is a high surrogate not followed by a low one"
                ));
            }
            return Err(format!("\\u{hi:04X} is an unpaired surrogate"));
        }
        char::from_u32(hi).ok_or_else(|| format!("bad code point U+{hi:X}"))
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek() == Some('-') {
            self.i += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        let mut is_float = false;
        if self.peek() == Some('.') {
            is_float = true;
            self.i += 1;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            is_float = true;
            self.i += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.i += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let text: String = self.chars[start..self.i].iter().collect();
        if is_float {
            text.parse::<f64>()
                .map(Json::Float)
                .map_err(|e| format!("`{text}`: {e}"))
        } else {
            text.parse::<i64>()
                .map(Json::Int)
                .map_err(|e| format!("`{text}`: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------------------------

/// `json.dump(value, fh, indent=1, ensure_ascii=False, sort_keys=False)`, byte for byte. The
/// caller appends the trailing newline Python's callers append separately.
pub fn dump_python(value: &Json) -> String {
    dump_python_indent(value, 1)
}

/// The same, with the indent WIDTH parameterized — `json.dump(..., indent=N, ...)` for an `N`
/// other than 1. `inventory-coverage.py` writes with `indent=2`; the shape (order, escaping, empty
/// containers inline) is otherwise identical, so only the per-level column count differs.
pub fn dump_python_indent(value: &Json, unit: usize) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0, unit);
    out
}

fn write_value(out: &mut String, v: &Json, level: usize, unit: usize) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Float(f) => out.push_str(&py_float(*f)),
        Json::Str(s) => write_string(out, s),
        Json::Array(a) => {
            // EMPTY CONTAINERS STAY INLINE. Python's pretty-printer emits `[]`, not `[\n ]`, and
            // the register is full of `"counts": {}`.
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(out, level + 1, unit);
                write_value(out, item, level + 1, unit);
            }
            out.push('\n');
            indent(out, level, unit);
            out.push(']');
        }
        Json::Object(o) => {
            if o.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(out, level + 1, unit);
                write_string(out, k);
                out.push_str(": ");
                write_value(out, val, level + 1, unit);
            }
            out.push('\n');
            indent(out, level, unit);
            out.push('}');
        }
    }
}

fn indent(out: &mut String, level: usize, unit: usize) {
    for _ in 0..(level * unit) {
        out.push(' ');
    }
}

/// Python's `repr`-free float formatting (`float.__repr__`, shortest round-trip). Neither file this
/// module writes contains a float today; the arm exists so a value that acquires one is written
/// rather than silently dropped.
fn py_float(f: f64) -> String {
    if f == f.trunc() && f.is_finite() && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

/// `ensure_ascii=False` string escaping: the seven short forms, `\u00xx` for the rest of C0, and
/// everything else — including every non-ASCII character — passed through as UTF-8.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
