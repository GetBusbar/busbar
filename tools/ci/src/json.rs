//! The one JSON model shared by every busbar-ci command, with Python `json`
//! semantics where the controller depends on them:
//!
//! * objects keep insertion order; a repeated key keeps its first position and
//!   its last value (`dict` construction); equality is order-insensitive like
//!   `dict ==`, and integers compare exactly;
//! * integers keep arbitrary precision as canonical decimal text (`str(int)`:
//!   no `-0`); other numbers keep their source text;
//! * output matches `json.dumps` (ASCII-escaped) in the default, `sort_keys`,
//!   `indent=2` and canonical `sort_keys=True, separators=(',', ':')` forms.
//!
//! Two input dialects exist because the two former Python controllers read
//! different inputs. [`parse`] is the strict reader for protected policy,
//! Docker and controller documents. [`parse_cpython`] reproduces CPython's
//! `json.loads(bytes)` for untrusted scanner reports, including its quirks.
use std::fmt::Write as _;

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    /// Canonical decimal text for integers; source text for other numbers.
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

pub static NULL: Value = Value::Null;

/// Integer-shaped number text (`type(x) is int` after `json.loads`).
fn integer_text(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit())
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => {
                if integer_text(a) && integer_text(b) {
                    a == b
                } else {
                    a.parse::<f64>().ok() == b.parse::<f64>().ok()
                }
            }
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
    pub fn str(value: impl Into<String>) -> Value {
        Value::String(value.into())
    }
    pub fn int(value: impl Into<i128>) -> Value {
        Value::Number(value.into().to_string())
    }
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
    /// `dict[key] = value`: replaces in place or appends.
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
    /// `type(x) is int` (bool excluded).
    pub fn is_int(&self) -> bool {
        matches!(self, Value::Number(n) if integer_text(n))
    }
    /// A JSON integer as i128 when representable.
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Number(n) if integer_text(n) && n.len() <= 30 => n.parse().ok(),
            _ => None,
        }
    }
    /// Non-negative JSON integer (`type(x) is int` and x >= 0).
    pub fn as_u64(&self) -> Option<u64> {
        self.as_int().and_then(|v| u64::try_from(v).ok())
    }
    /// A JSON number that is not an integer, as `float(text)`.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Number(n) if !integer_text(n) => n.parse().ok(),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
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
    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) if integer_text(n) => n != "0",
            Value::Number(n) => n.parse::<f64>().is_ok_and(|f| f != 0.0),
            Value::String(s) => !s.is_empty(),
            Value::Array(rows) => !rows.is_empty(),
            Value::Object(rows) => !rows.is_empty(),
        }
    }
    /// Python `value == n` for a small integer n (bool compares as 0/1).
    pub fn equals_int(&self, n: i64) -> bool {
        match self {
            Value::Number(text) if integer_text(text) => *text == n.to_string(),
            Value::Number(text) => text.parse::<f64>().is_ok_and(|f| f == n as f64),
            Value::Bool(b) => i64::from(*b) == n,
            _ => false,
        }
    }
}

/// Parse failure. Excessive nesting is distinct: CPython raises
/// `RecursionError` there, which the former scanner did not treat as a refusal.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    Invalid(String),
    TooDeep,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Invalid(message) => f.write_str(message),
            ParseError::TooDeep => f.write_str("JSON nesting exceeds bound"),
        }
    }
}

impl From<ParseError> for String {
    fn from(error: ParseError) -> String {
        error.to_string()
    }
}

#[derive(Clone, Copy)]
struct Dialect {
    /// Containers deeper than this are refused (TooDeep for CPython).
    depth: usize,
    /// UTF-8 BOM, `NaN`, `Infinity`, `-Infinity`, lone surrogates (U+FFFD).
    cpython: bool,
}

/// Strict reader for protected controller inputs: no BOM, no non-finite
/// constants, no lone surrogates, at most 512 nested containers.
pub fn parse(data: &[u8]) -> Result<Value, String> {
    let dialect = Dialect {
        depth: 512,
        cpython: false,
    };
    parse_with(data, dialect).map_err(String::from)
}

/// CPython 3.12 `json.loads(bytes)`: UTF-8 BOM decoded as utf-8-sig, `NaN`
/// and `Infinity` accepted, lone surrogates kept (as U+FFFD here: they can never
/// satisfy a projection pattern or trusted policy value), 9997 nested containers
/// parse and 9998 raise RecursionError, and the 4300-digit int conversion limit.
/// UTF-16/32 detection is not reproduced: pinned scanners emit UTF-8.
pub fn parse_cpython(data: &[u8]) -> Result<Value, ParseError> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    parse_with(
        data,
        Dialect {
            depth: 9997,
            cpython: true,
        },
    )
}

fn parse_with(data: &[u8], dialect: Dialect) -> Result<Value, ParseError> {
    let text = std::str::from_utf8(data).map_err(|_| invalid("JSON is not UTF-8"))?;
    let mut parser = Parser {
        s: text.as_bytes(),
        text,
        i: 0,
        dialect,
    };
    parser.ws();
    let value = parser.value(0)?;
    parser.ws();
    if parser.i != parser.s.len() {
        return Err(invalid("trailing data after JSON value"));
    }
    Ok(value)
}

// CPython 3.11+ int/str conversion limit (sys.get_int_max_str_digits()).
const INT_DIGITS_LIMIT: usize = 4300;

fn invalid(message: &str) -> ParseError {
    ParseError::Invalid(message.to_owned())
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
    dialect: Dialect,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn eat(&mut self, literal: &str) -> bool {
        if self.s[self.i..].starts_with(literal.as_bytes()) {
            self.i += literal.len();
            true
        } else {
            false
        }
    }
    fn at_error(&self, what: &str) -> ParseError {
        ParseError::Invalid(format!("invalid JSON {what} at byte {}", self.i))
    }
    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        let Some(&c) = self.s.get(self.i) else {
            return Err(self.at_error("value"));
        };
        let cpython = self.dialect.cpython;
        match c {
            b'{' | b'[' if depth >= self.dialect.depth => Err(ParseError::TooDeep),
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => Ok(Value::String(self.string()?)),
            b'n' if self.eat("null") => Ok(Value::Null),
            b't' if self.eat("true") => Ok(Value::Bool(true)),
            b'f' if self.eat("false") => Ok(Value::Bool(false)),
            b'N' if cpython && self.eat("NaN") => Ok(Value::Number("NaN".into())),
            b'I' if cpython && self.eat("Infinity") => Ok(Value::Number("Infinity".into())),
            b'-' if cpython && self.eat("-Infinity") => Ok(Value::Number("-Infinity".into())),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(self.at_error("value")),
        }
    }
    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        self.i - start
    }
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        let negative = self.s[self.i] == b'-';
        if negative {
            self.i += 1;
        }
        let int_start = self.i;
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.at_error("number")),
        }
        let int_end = self.i;
        let mut float = false;
        // CPython's NUMBER_RE leaves an incomplete fraction or exponent
        // unconsumed; the following byte then fails the enclosing grammar.
        if self.s.get(self.i) == Some(&b'.')
            && self.s.get(self.i + 1).is_some_and(u8::is_ascii_digit)
        {
            self.i += 1;
            self.digits();
            float = true;
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                self.i = save;
            } else {
                float = true;
            }
        }
        if float {
            let text = &self.text[start..self.i];
            text.parse::<f64>().map_err(|_| self.at_error("number"))?;
            return Ok(Value::Number(text.to_owned()));
        }
        let digits = &self.text[int_start..int_end];
        if self.dialect.cpython && digits.len() > INT_DIGITS_LIMIT {
            return Err(invalid("integer exceeds the conversion digit limit"));
        }
        Ok(Value::Number(if negative && digits != "0" {
            format!("-{digits}")
        } else {
            digits.to_owned()
        }))
    }
    fn hex4(&mut self) -> Result<u32, ParseError> {
        let hex = self
            .s
            .get(self.i..self.i + 4)
            .ok_or_else(|| invalid("truncated JSON escape"))?;
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid("invalid JSON escape"));
        }
        self.i += 4;
        let text = std::str::from_utf8(hex).map_err(|_| invalid("invalid JSON escape"))?;
        u32::from_str_radix(text, 16).map_err(|_| invalid("invalid JSON escape"))
    }
    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.s.len() && !matches!(self.s[self.i], b'"' | b'\\' | 0..=0x1f) {
                self.i += 1;
            }
            out.push_str(&self.text[start..self.i]);
            match self.s.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let escape = *self
                        .s
                        .get(self.i)
                        .ok_or_else(|| invalid("truncated JSON string"))?;
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
                                let save = self.i;
                                self.i += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            match char::from_u32(code) {
                                Some(c) => out.push(c),
                                None if self.dialect.cpython => out.push('\u{fffd}'),
                                None => return Err(invalid("unpaired JSON surrogate")),
                            }
                        }
                        _ => return Err(invalid("invalid JSON escape")),
                    }
                }
                // End of input or an unescaped control character (strict=True).
                _ => return Err(invalid("invalid or unterminated JSON string")),
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut rows = Vec::new();
        self.ws();
        if self.eat("]") {
            return Ok(Value::Array(rows));
        }
        loop {
            self.ws();
            rows.push(self.value(depth)?);
            self.ws();
            if self.eat("]") {
                return Ok(Value::Array(rows));
            }
            if !self.eat(",") {
                return Err(self.at_error("array"));
            }
        }
    }
    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut rows: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.eat("}") {
            return Ok(Value::Object(rows));
        }
        loop {
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return Err(self.at_error("object"));
            }
            let key = self.string()?;
            self.ws();
            if !self.eat(":") {
                return Err(self.at_error("object"));
            }
            self.ws();
            let value = self.value(depth)?;
            match rows.iter_mut().find(|(k, _)| *k == key) {
                Some(row) => row.1 = value,
                None => rows.push((key, value)),
            }
            self.ws();
            if self.eat("}") {
                return Ok(Value::Object(rows));
            }
            if !self.eat(",") {
                return Err(self.at_error("object"));
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

#[derive(Clone, Copy)]
struct Form {
    sort: bool,
    item: &'static str,
    key: &'static str,
}

fn compact(out: &mut String, value: &Value, form: Form) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => quote(out, s),
        Value::Array(rows) => {
            out.push('[');
            for (i, row) in rows.iter().enumerate() {
                if i > 0 {
                    out.push_str(form.item);
                }
                compact(out, row, form);
            }
            out.push(']');
        }
        Value::Object(rows) => {
            let mut rows: Vec<_> = rows.iter().collect();
            if form.sort {
                rows.sort_by(|a, b| a.0.cmp(&b.0));
            }
            out.push('{');
            for (i, (k, v)) in rows.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(form.item);
                }
                quote(out, k);
                out.push_str(form.key);
                compact(out, v, form);
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
        _ => dumps_into(out, value, false),
    }
}

fn dumps_into(out: &mut String, value: &Value, sort: bool) {
    let form = Form {
        sort,
        item: ", ",
        key: ": ",
    };
    compact(out, value, form);
}

/// `json.dumps(value)` / `json.dumps(value, sort_keys=True)`.
pub fn dumps(value: &Value, sort_keys: bool) -> String {
    let mut out = String::new();
    dumps_into(&mut out, value, sort_keys);
    out
}

/// `json.dumps(value, indent=2)`.
pub fn dumps_indent(value: &Value) -> String {
    let mut out = String::new();
    indented(&mut out, value, 0);
    out
}

/// `(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()`.
pub fn encoded(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    let form = Form {
        sort: true,
        item: ",",
        key: ":",
    };
    compact(&mut out, value, form);
    out.push('\n');
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpython_parse_semantics() {
        let int = |n: i64| Value::int(n);
        assert_eq!(parse_cpython(b" -0 ").unwrap(), int(0));
        assert!(matches!(parse_cpython(b" -0 ").unwrap(), Value::Number(n) if n == "0"));
        assert_eq!(parse_cpython(b"\xef\xbb\xbf2").unwrap(), int(2));
        assert!(parse_cpython(b"1.0").unwrap().as_float().is_some());
        assert!(!parse_cpython(b"1.0").unwrap().is_int());
        assert!(parse_cpython(b"NaN").unwrap().as_float().unwrap().is_nan());
        assert_eq!(
            parse_cpython(b"-Infinity").unwrap().as_float(),
            Some(f64::NEG_INFINITY)
        );
        assert_eq!(
            parse_cpython(br#"{"a":1,"a":2}"#).unwrap().get("a"),
            Some(&int(2))
        );
        assert_eq!(
            parse_cpython(br#""\ud83d\ude00""#).unwrap(),
            Value::str("\u{1f600}")
        );
        assert_eq!(
            parse_cpython(br#""\ud800x""#).unwrap(),
            Value::str("\u{fffd}x")
        );
        for bad in [
            &b"01"[..],
            b"1e",
            b"1.",
            b"[1,]",
            b"{\"a\" 1}",
            b"\"\x01\"",
            b"\"\\x\"",
            b"\"\\u+abc\"",
            b"",
            b"tru",
            b"\xff",
        ] {
            assert!(
                matches!(parse_cpython(bad), Err(ParseError::Invalid(_))),
                "{bad:?}"
            );
        }
        // Production parses reports on the controller's dedicated large stack.
        std::thread::Builder::new()
            .stack_size(512 << 20)
            .spawn(|| {
                assert_eq!(parse_cpython(&b"[".repeat(9998)), Err(ParseError::TooDeep));
                let deep = [b"[".repeat(9997), b"]".repeat(9997)].concat();
                assert!(parse_cpython(&deep).is_ok());
            })
            .unwrap()
            .join()
            .unwrap();
        assert!(parse_cpython(&"9".repeat(4301).into_bytes()).is_err());
        assert!(parse_cpython(&"9".repeat(4300).into_bytes()).is_ok());
    }

    #[test]
    fn strict_dialect_refuses_cpython_extensions() {
        for bad in [
            &b"NaN"[..],
            b"Infinity",
            b"-Infinity",
            b"\xef\xbb\xbf1",
            b"\"\\ud800\"",
            b"\"\\u+abc\"",
            b"{",
            b"[1,]",
            b"01",
            b"\"\x01\"",
            b"{} x",
            b"nul",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let deep = |n: usize| [b"[".repeat(n), b"]".repeat(n)].concat();
        assert!(parse(&deep(512)).is_ok());
        assert_eq!(
            parse(&deep(513)),
            Err("JSON nesting exceeds bound".to_owned())
        );
        assert_eq!(parse(b"-1").unwrap().as_u64(), None);
        assert_eq!(parse(b"1.0").unwrap().as_u64(), None);
    }

    #[test]
    fn python_dump_forms() {
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
        let value = parse_cpython(
            "{\"b\":[1,true,null],\"a\":\"\u{e9}\u{1f600}\\u007f\\\"/\\n\\u0001\"}".as_bytes(),
        )
        .unwrap();
        assert_eq!(
            encoded(&value),
            b"{\"a\":\"\\u00e9\\ud83d\\ude00\\u007f\\\"/\\n\\u0001\",\"b\":[1,true,null]}\n"
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
        let huge = "9".repeat(60);
        assert_eq!(parse(huge.as_bytes()).unwrap(), Value::Number(huge.clone()));
        assert_ne!(
            parse(huge.as_bytes()).unwrap(),
            Value::Number(huge[1..].to_owned() + "8")
        );
    }

    #[test]
    fn python_truthiness_and_integer_comparison() {
        for (text, truthy) in [
            ("0", false),
            ("0.0", false),
            ("2", true),
            ("\"\"", false),
            ("[]", false),
            ("{}", false),
            ("null", false),
            ("[0]", true),
        ] {
            assert_eq!(parse(text.as_bytes()).unwrap().truthy(), truthy, "{text}");
        }
        assert!(parse(b"0.0").unwrap().equals_int(0));
        assert!(Value::Bool(true).equals_int(1));
        assert!(!Value::str("0").equals_int(0));
    }
}
