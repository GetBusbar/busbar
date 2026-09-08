//! AN ORDER-PRESERVING JSON READER AND WRITER, byte-compatible with
//! `json.dumps(obj, indent=1, ensure_ascii=False)`.
//!
//! WHY NOT `serde_json`, WHICH THIS CRATE ALREADY DEPENDS ON. Its `Map` is a `BTreeMap` unless the
//! `preserve_order` feature is on, and that feature costs an `indexmap` dependency in the one crate
//! whose whole purpose is auditing dependencies. Key order is not cosmetic here: `qa/design-bindings.json`
//! is a COMMITTED artifact, and `scripts/design-bindings.sh --check --strict` refuses a ledger that
//! is not what a fresh derivation produces. A reader that sorted the keys of a hand-added check
//! would make every regeneration a diff, and the REGEN-CLEAN guard would fire on the conversion
//! rather than on a stale ledger — which is exactly the noise `xtask/src/parity.rs` exists to keep
//! out of a rewrite.
//!
//! So: objects keep the order they were read (or built) in, and the writer reproduces CPython's
//! `json` module exactly — `indent=1`, `", "` never appearing because `indent` switches the item
//! separator to a bare `,` with a newline, `": "` between key and value, `{}`/`[]` for the empty
//! containers, and `ensure_ascii=False`, which leaves every non-ASCII character as itself and
//! escapes only `"`, `\` and the control characters.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn obj() -> J {
        J::Obj(Vec::new())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[J]> {
        match self {
            J::Arr(v) => Some(v),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn str_of(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(J::as_str)
    }

    /// Set `key`, KEEPING its existing position when it is already present — CPython's dict
    /// assignment, which is what makes a hand-added check re-emit in the order it was written.
    pub fn set(&mut self, key: &str, value: J) {
        if let J::Obj(kv) = self {
            match kv.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value,
                None => kv.push((key.to_string(), value)),
            }
        }
    }

    /// `dict.setdefault`: only inserted when absent.
    pub fn set_default(&mut self, key: &str, value: J) {
        if self.get(key).is_none() {
            self.set(key, value);
        }
    }

    pub fn keys(&self) -> Vec<&str> {
        match self {
            J::Obj(kv) => kv.iter().map(|(k, _)| k.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

/// Build an object literal in a fixed order, which is the only order it will ever be written in.
#[macro_export]
macro_rules! jobj {
    ($($k:expr => $v:expr),* $(,)?) => {
        $crate::gates::design_bindings::json::J::Obj(vec![
            $(($k.to_string(), $v)),*
        ])
    };
}

pub fn s(v: impl Into<String>) -> J {
    J::Str(v.into())
}

// ── writing ──────────────────────────────────────────────────────────────────────────────────────

/// `json.dumps(obj, indent=1, ensure_ascii=False)`, with no trailing newline.
pub fn dumps(value: &J) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0);
    out
}

fn write_value(out: &mut String, value: &J, depth: usize) {
    match value {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Int(i) => {
            let _ = write!(out, "{i}");
        }
        J::Str(v) => write_string(out, v),
        J::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                indent(out, depth + 1);
                write_value(out, item, depth + 1);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, depth);
            out.push(']');
        }
        J::Obj(kv) => {
            if kv.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (k, v)) in kv.iter().enumerate() {
                indent(out, depth + 1);
                write_string(out, k);
                out.push_str(": ");
                write_value(out, v, depth + 1);
                if i + 1 < kv.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, depth);
            out.push('}');
        }
    }
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push(' ');
    }
}

fn write_string(out: &mut String, v: &str) {
    out.push('"');
    for ch in v.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ── reading ──────────────────────────────────────────────────────────────────────────────────────

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("json: expected {what} at byte {}", self.i))
    }

    fn value(&mut self) -> Result<J, String> {
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(J::Str(self.string()?)),
            Some(b't') => self.lit("true", J::Bool(true)),
            Some(b'f') => self.lit("false", J::Bool(false)),
            Some(b'n') => self.lit("null", J::Null),
            Some(_) => self.number(),
            None => self.err("a value"),
        }
    }

    fn lit(&mut self, word: &str, v: J) -> Result<J, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            self.err(word)
        }
    }

    fn number(&mut self) -> Result<J, String> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == start {
            return self.err("a number");
        }
        // A float here would be a value this ledger does not carry, and silently truncating one is
        // the kind of quiet lie the whole file exists to refuse.
        if matches!(self.b.get(self.i), Some(b'.' | b'e' | b'E')) {
            return self.err("an integer (this ledger carries no floats)");
        }
        String::from_utf8_lossy(&self.b[start..self.i])
            .parse()
            .map(J::Int)
            .map_err(|e| format!("json: {e}"))
    }

    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return self.err("a string");
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            match self.b.get(self.i) {
                None => return self.err("a closing quote"),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = *self.b.get(self.i).ok_or("json: trailing backslash")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'u' => {
                            let hex = self
                                .b
                                .get(self.i..self.i + 4)
                                .ok_or("json: truncated \\u escape")?;
                            self.i += 4;
                            let n = u32::from_str_radix(&String::from_utf8_lossy(hex), 16)
                                .map_err(|e| format!("json: bad \\u escape: {e}"))?;
                            out.push(char::from_u32(n).unwrap_or('\u{fffd}'));
                        }
                        other => return Err(format!("json: unknown escape \\{}", other as char)),
                    }
                }
                Some(&lead) => {
                    // Copy the whole UTF-8 sequence, not one byte: the ledger's prose carries `§`
                    // and `—`, and splitting them would produce a string that is not what was read.
                    //
                    // THE SEQUENCE IS SIZED FROM ITS LEAD BYTE, and that is the whole point. The
                    // obvious spelling — decode the REST of the buffer and take its first char —
                    // is quadratic: it rescans every remaining byte once per character, which on a
                    // quarter-megabyte ledger is six seconds of a gate that is supposed to run on
                    // every push. Here each character costs its own length and nothing more.
                    let width = match lead {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf7 => 4,
                        // A continuation or invalid lead byte: consume exactly one byte so the
                        // scan always advances, and report it the way a lossy decode would.
                        _ => 1,
                    };
                    let end = (self.i + width).min(self.b.len());
                    let c = std::str::from_utf8(&self.b[self.i..end])
                        .ok()
                        .and_then(|s| s.chars().next());
                    match c {
                        Some(c) => {
                            out.push(c);
                            self.i += c.len_utf8();
                        }
                        None => {
                            out.push('\u{fffd}');
                            self.i += 1;
                        }
                    }
                }
            }
        }
    }

    fn array(&mut self) -> Result<J, String> {
        self.i += 1;
        let mut items = Vec::new();
        loop {
            self.ws();
            if self.b.get(self.i) == Some(&b']') {
                self.i += 1;
                return Ok(J::Arr(items));
            }
            items.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {}
                _ => return self.err("`,` or `]`"),
            }
        }
    }

    fn object(&mut self) -> Result<J, String> {
        self.i += 1;
        let mut kv: Vec<(String, J)> = Vec::new();
        loop {
            self.ws();
            if self.b.get(self.i) == Some(&b'}') {
                self.i += 1;
                return Ok(J::Obj(kv));
            }
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return self.err("`:`");
            }
            self.i += 1;
            let v = self.value()?;
            kv.push((k, v));
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {}
                _ => return self.err("`,` or `}`"),
            }
        }
    }
}

pub fn parse(text: &str) -> Result<J, String> {
    let mut p = P {
        b: text.as_bytes(),
        i: 0,
    };
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return p.err("end of input");
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE PROPERTY THE COMMITTED LEDGER RESTS ON: read then write is the identity, byte for byte.
    /// If it is not, every `--write` is a diff and REGEN-CLEAN fires on the tool instead of on a
    /// stale ledger.
    #[test]
    fn the_committed_ledger_round_trips_byte_for_byte() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("qa/design-bindings.json");
        let text = std::fs::read_to_string(&path).expect("the ledger is committed");
        let parsed = parse(&text).expect("the ledger parses");
        assert_eq!(
            dumps(&parsed) + "\n",
            text,
            "read-then-write is not the identity on the committed ledger"
        );
    }

    #[test]
    fn empty_containers_and_escapes_match_cpython() {
        assert_eq!(dumps(&J::Obj(vec![])), "{}");
        assert_eq!(dumps(&J::Arr(vec![])), "[]");
        assert_eq!(dumps(&s("a\"b\\c\nd")), r#""a\"b\\c\nd""#);
        // ensure_ascii=False: a non-ASCII character is itself, never a \u escape.
        assert_eq!(dumps(&s("§ — ok")), "\"§ — ok\"");
    }

    #[test]
    fn indent_is_one_space_per_level() {
        let v = jobj! {
            "a" => J::Int(1),
            "b" => J::Arr(vec![J::Int(1), J::Int(2)]),
        };
        assert_eq!(dumps(&v), "{\n \"a\": 1,\n \"b\": [\n  1,\n  2\n ]\n}");
    }

    /// A key already present keeps its position, which is what CPython's dict assignment does and
    /// what makes a hand-added check re-emit in the order somebody wrote it.
    #[test]
    fn setting_an_existing_key_does_not_move_it() {
        let mut v = jobj! { "kind" => s("test"), "ref" => s("x"), "status" => s("unmapped") };
        v.set("status", s("mapped"));
        assert_eq!(v.keys(), vec!["kind", "ref", "status"]);
    }
}
