//! Minimal JSON with Python `json` semantics where the controller depends on them:
//! object order is preserved (a repeated key keeps its first position and last
//! value), equality is order-insensitive like `dict ==`, integers compare
//! numerically, and output matches `json.dumps` (ASCII-escaped).
use std::fmt::Write as _;

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    /// Source text of a JSON number. Integers are compared exactly.
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

pub static NULL: Value = Value::Null;

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => match (int(a), int(b)) {
                (Some(a), Some(b)) => a == b,
                _ => a.parse::<f64>().ok() == b.parse::<f64>().ok(),
            },
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .all(|(k, v)| b.iter().any(|(k2, v2)| k == k2 && v == v2))
            }
            _ => false,
        }
    }
}

fn int(text: &str) -> Option<i128> {
    if text.contains(['.', 'e', 'E']) {
        None
    } else {
        text.parse().ok()
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::String(value.to_owned())
    }
}
impl From<String> for Value {
    fn from(value: String) -> Self {
        Value::String(value)
    }
}
impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Value::Bool(value)
    }
}
impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Value::Number(value.to_string())
    }
}
impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Value::Number(value.to_string())
    }
}
impl From<Vec<Value>> for Value {
    fn from(value: Vec<Value>) -> Self {
        Value::Array(value)
    }
}

/// Build an object from ordered pairs.
pub fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(rows) => rows.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /// Python `dict.get(key)` returning `null` when absent.
    pub fn at(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
    pub fn index(&self, i: usize) -> &Value {
        match self {
            Value::Array(rows) => rows.get(i).unwrap_or(&NULL),
            _ => &NULL,
        }
    }
    pub fn set(&mut self, key: &str, value: Value) {
        if let Value::Object(rows) = self {
            match rows.iter_mut().find(|(k, _)| k == key) {
                Some(row) => row.1 = value,
                None => rows.push((key.to_owned(), value)),
            }
        }
    }
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self {
            Value::Object(rows) => rows.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    /// Non-negative JSON integer (`type(x) is int` and x >= 0).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => int(n).and_then(|v| u64::try_from(v).ok()),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(rows) => Some(rows),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Object(rows) => Some(rows),
            _ => None,
        }
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Value::Object(_))
    }
    /// The exact key set of an object.
    pub fn has_keys(&self, expected: &[&str]) -> bool {
        self.as_object().is_some_and(|rows| {
            rows.len() == expected.len()
                && expected.iter().all(|k| rows.iter().any(|(r, _)| r == k))
        })
    }
    pub fn keys(&self) -> Vec<&str> {
        self.as_object()
            .map(|rows| rows.iter().map(|(k, _)| k.as_str()).collect())
            .unwrap_or_default()
    }
}

pub fn parse(text: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(text).map_err(|_| "JSON is not UTF-8".to_owned())?;
    let mut parser = Parser {
        s: text.as_bytes(),
        i: 0,
        depth: 0,
    };
    parser.ws();
    let value = parser.value()?;
    parser.ws();
    if parser.i != parser.s.len() {
        return Err("trailing data after JSON value".into());
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("invalid JSON at byte {}", self.i))
        }
    }
    fn literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(value)
        } else {
            Err(format!("invalid JSON literal at byte {}", self.i))
        }
    }
    fn value(&mut self) -> Result<Value, String> {
        self.depth += 1;
        if self.depth > 512 {
            return Err("JSON nesting exceeds bound".into());
        }
        let result = match self.peek() {
            Some(b'{') => {
                self.i += 1;
                let mut rows: Vec<(String, Value)> = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        let key = self.string()?;
                        self.ws();
                        self.expect(b':')?;
                        self.ws();
                        let value = self.value()?;
                        match rows.iter_mut().find(|(k, _)| *k == key) {
                            Some(row) => row.1 = value,
                            None => rows.push((key, value)),
                        }
                        self.ws();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err(format!("invalid JSON object at byte {}", self.i)),
                        }
                    }
                }
                Ok(Value::Object(rows))
            }
            Some(b'[') => {
                self.i += 1;
                let mut rows = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        rows.push(self.value()?);
                        self.ws();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err(format!("invalid JSON array at byte {}", self.i)),
                        }
                    }
                }
                Ok(Value::Array(rows))
            }
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("invalid JSON value at byte {}", self.i)),
        };
        self.depth -= 1;
        result
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits = |p: &mut Self| {
            let begin = p.i;
            while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                p.i += 1;
            }
            p.i > begin
        };
        if self.peek() == Some(b'0') {
            self.i += 1;
        } else if !digits(self) {
            return Err("invalid JSON number".into());
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !digits(self) {
                return Err("invalid JSON number".into());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !digits(self) {
                return Err("invalid JSON number".into());
            }
        }
        Ok(Value::Number(
            std::str::from_utf8(&self.s[start..self.i])
                .unwrap()
                .to_owned(),
        ))
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .s
            .get(self.i..self.i + 4)
            .ok_or("truncated JSON escape")?;
        let text = std::str::from_utf8(digits).map_err(|_| "invalid JSON escape")?;
        let value = u32::from_str_radix(text, 16).map_err(|_| "invalid JSON escape")?;
        self.i += 4;
        Ok(value)
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self
                .peek()
                .is_some_and(|c| c != b'"' && c != b'\\' && c >= 0x20)
            {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).unwrap());
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let escape = self.peek().ok_or("truncated JSON string")?;
                    self.i += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xd800..0xdc00).contains(&code)
                                && self.s[self.i..].starts_with(b"\\u")
                            {
                                self.i += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    return Err("invalid JSON surrogate pair".into());
                                }
                            }
                            out.push(char::from_u32(code).ok_or("unpaired JSON surrogate")?);
                        }
                        _ => return Err("invalid JSON escape".into()),
                    }
                }
                _ => return Err("invalid or unterminated JSON string".into()),
            }
        }
    }
}

fn quote(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

fn sorted(rows: &[(String, Value)], sort: bool) -> Vec<&(String, Value)> {
    let mut rows: Vec<_> = rows.iter().collect();
    if sort {
        rows.sort_by(|a, b| a.0.cmp(&b.0));
    }
    rows
}

fn compact(out: &mut String, value: &Value, sort: bool) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => quote(out, s),
        Value::Array(rows) => {
            out.push('[');
            for (i, row) in rows.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                compact(out, row, sort);
            }
            out.push(']');
        }
        Value::Object(rows) => {
            out.push('{');
            for (i, (k, v)) in sorted(rows, sort).into_iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                quote(out, k);
                out.push_str(": ");
                compact(out, v, sort);
            }
            out.push('}');
        }
    }
}

fn indented(out: &mut String, value: &Value, level: usize) {
    let pad = |out: &mut String, n: usize| out.extend(std::iter::repeat_n(' ', n * 2));
    match value {
        Value::Array(rows) if !rows.is_empty() => {
            out.push('[');
            for (i, row) in rows.iter().enumerate() {
                out.push_str(if i > 0 { ",\n" } else { "\n" });
                pad(out, level + 1);
                indented(out, row, level + 1);
            }
            out.push('\n');
            pad(out, level);
            out.push(']');
        }
        Value::Object(rows) if !rows.is_empty() => {
            out.push('{');
            for (i, (k, v)) in rows.iter().enumerate() {
                out.push_str(if i > 0 { ",\n" } else { "\n" });
                pad(out, level + 1);
                quote(out, k);
                out.push_str(": ");
                indented(out, v, level + 1);
            }
            out.push('\n');
            pad(out, level);
            out.push('}');
        }
        _ => compact(out, value, false),
    }
}

/// `json.dumps(value)` / `json.dumps(value, sort_keys=True)`.
pub fn dumps(value: &Value, sort_keys: bool) -> String {
    let mut out = String::new();
    compact(&mut out, value, sort_keys);
    out
}

/// `json.dumps(value, indent=2)`.
pub fn dumps_indent(value: &Value) -> String {
    let mut out = String::new();
    indented(&mut out, value, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_python_formats() {
        let value =
            parse(br#"{"b": [1, {"x": null}], "a": "\u00e9\n", "c": {}, "d": []}"#).unwrap();
        assert_eq!(
            dumps(&value, false),
            r#"{"b": [1, {"x": null}], "a": "\u00e9\n", "c": {}, "d": []}"#
        );
        assert_eq!(
            dumps(&value, true),
            r#"{"a": "\u00e9\n", "b": [1, {"x": null}], "c": {}, "d": []}"#
        );
        assert_eq!(
            dumps_indent(&value),
            "{\n  \"b\": [\n    1,\n    {\n      \"x\": null\n    }\n  ],\n  \"a\": \"\\u00e9\\n\",\n  \"c\": {},\n  \"d\": []\n}"
        );
        assert_eq!(
            dumps(&parse("\"\u{1f600}\"".as_bytes()).unwrap(), false),
            r#""\ud83d\ude00""#
        );
    }

    #[test]
    fn equality_is_python_dict_equality() {
        assert_eq!(
            parse(br#"{"a":1,"b":[true]}"#).unwrap(),
            parse(br#"{"b":[true],"a":1.0}"#).unwrap()
        );
        assert_ne!(
            parse(br#"{"a":1}"#).unwrap(),
            parse(br#"{"a":1,"b":2}"#).unwrap()
        );
        assert_ne!(parse(b"[1,2]").unwrap(), parse(b"[2,1]").unwrap());
        let repeated = parse(br#"{"a":1,"b":2,"a":3}"#).unwrap();
        assert_eq!(repeated.keys(), ["a", "b"]);
        assert_eq!(repeated.at("a").as_u64(), Some(3));
    }

    #[test]
    fn rejects_invalid_documents() {
        for bad in [
            &b"{"[..],
            b"[1,]",
            b"01",
            b"\"\x01\"",
            b"{} x",
            b"nul",
            b"\"\\ud800\"",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        assert_eq!(parse(b"-1").unwrap().as_u64(), None);
        assert_eq!(parse(b"1.0").unwrap().as_u64(), None);
    }
}
