//! JSON with the semantics of CPython's `json.loads(bytes)` and
//! `json.dumps(value, sort_keys=True, separators=(',', ':'))`, as used by the
//! former scanner. Integers keep arbitrary precision as canonical decimal text.
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Canonical decimal text (no leading zeros, no `-0`), like Python `str(int)`.
    Int(String),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    /// Python dicts keep the last duplicate value; output is always key-sorted.
    Obj(BTreeMap<String, Json>),
}

/// Parse failures are Python `ValueError`s; excessive nesting is a
/// `RecursionError`, which the former scanner did not treat as a refusal.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    Invalid,
    TooDeep,
}

// CPython 3.12's C recursion bound as measured for json.loads: 9997 nested
// containers parse, 9998 raise RecursionError.
const DEPTH_LIMIT: usize = 9997;
// CPython 3.11+ int/str conversion limit (sys.get_int_max_str_digits()).
const INT_DIGITS_LIMIT: usize = 4300;

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(map) => map.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(values) => Some(values),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Obj(map) => Some(map),
            _ => None,
        }
    }
    /// Python `type(value) is int` (bool excluded), as i128 when representable.
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Json::Int(text) if text.len() <= 30 => text.parse().ok(),
            _ => None,
        }
    }
    pub fn is_int(&self) -> bool {
        matches!(self, Json::Int(_))
    }
    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Json::Null => false,
            Json::Bool(b) => *b,
            Json::Int(text) => text != "0",
            Json::Float(f) => *f != 0.0,
            Json::Str(s) => !s.is_empty(),
            Json::Arr(values) => !values.is_empty(),
            Json::Obj(map) => !map.is_empty(),
        }
    }
    /// Python `value == n` for a small integer n (bool compares as 0/1).
    pub fn equals_int(&self, n: i64) -> bool {
        match self {
            Json::Int(text) => *text == n.to_string(),
            Json::Float(f) => *f == n as f64,
            Json::Bool(b) => i64::from(*b) == n,
            _ => false,
        }
    }
    pub fn int(n: impl Into<i128>) -> Json {
        Json::Int(n.into().to_string())
    }
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    pub fn obj<const N: usize>(pairs: [(&str, Json); N]) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }
    pub fn insert(&mut self, key: &str, value: Json) {
        if let Json::Obj(map) = self {
            map.insert(key.to_owned(), value);
        }
    }
}

pub fn parse(data: &[u8]) -> Result<Json, ParseError> {
    // json.loads(bytes) decodes a UTF-8 BOM as utf-8-sig. UTF-16/32 detection
    // is not reproduced: pinned scanners emit UTF-8, so such input is refused.
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let text = std::str::from_utf8(data).map_err(|_| ParseError::Invalid)?;
    let mut parser = Parser {
        s: text.as_bytes(),
        text,
        i: 0,
    };
    parser.ws();
    let value = parser.value(0)?;
    parser.ws();
    if parser.i != parser.s.len() {
        return Err(ParseError::Invalid);
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
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
    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        let Some(&c) = self.s.get(self.i) else {
            return Err(ParseError::Invalid);
        };
        match c {
            b'{' | b'[' if depth >= DEPTH_LIMIT => Err(ParseError::TooDeep),
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => Ok(Json::Str(self.string()?)),
            b'n' if self.eat("null") => Ok(Json::Null),
            b't' if self.eat("true") => Ok(Json::Bool(true)),
            b'f' if self.eat("false") => Ok(Json::Bool(false)),
            b'N' if self.eat("NaN") => Ok(Json::Float(f64::NAN)),
            b'I' if self.eat("Infinity") => Ok(Json::Float(f64::INFINITY)),
            b'-' if self.s[self.i..].starts_with(b"-Infinity") => {
                self.i += 9;
                Ok(Json::Float(f64::NEG_INFINITY))
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(ParseError::Invalid),
        }
    }
    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        self.i - start
    }
    fn number(&mut self) -> Result<Json, ParseError> {
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
            _ => return Err(ParseError::Invalid),
        }
        let int_end = self.i;
        let mut float = false;
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
                // CPython's NUMBER_RE leaves an incomplete exponent unconsumed.
                self.i = save;
            } else {
                float = true;
            }
        }
        let text = &self.text[start..self.i];
        if float {
            return text
                .parse()
                .map(Json::Float)
                .map_err(|_| ParseError::Invalid);
        }
        let digits = &self.text[int_start..int_end];
        if digits.len() > INT_DIGITS_LIMIT {
            return Err(ParseError::Invalid);
        }
        Ok(Json::Int(if negative && digits != "0" {
            format!("-{digits}")
        } else {
            digits.to_owned()
        }))
    }
    fn hex4(&mut self) -> Result<u32, ParseError> {
        let hex = self.s.get(self.i..self.i + 4).ok_or(ParseError::Invalid)?;
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return Err(ParseError::Invalid);
        }
        self.i += 4;
        u32::from_str_radix(
            std::str::from_utf8(hex).map_err(|_| ParseError::Invalid)?,
            16,
        )
        .map_err(|_| ParseError::Invalid)
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
                    let escape = *self.s.get(self.i).ok_or(ParseError::Invalid)?;
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
                            // Lone surrogates cannot occur in a Rust string. They can
                            // never satisfy a projection pattern or trusted policy value.
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(ParseError::Invalid),
                    }
                }
                // End of input or an unescaped control character (strict=True).
                _ => return Err(ParseError::Invalid),
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.i += 1;
        let mut values = Vec::new();
        self.ws();
        if self.eat("]") {
            return Ok(Json::Arr(values));
        }
        loop {
            self.ws();
            values.push(self.value(depth)?);
            self.ws();
            if self.eat("]") {
                return Ok(Json::Arr(values));
            }
            if !self.eat(",") {
                return Err(ParseError::Invalid);
            }
        }
    }
    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.i += 1;
        let mut map = BTreeMap::new();
        self.ws();
        if self.eat("}") {
            return Ok(Json::Obj(map));
        }
        loop {
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return Err(ParseError::Invalid);
            }
            let key = self.string()?;
            self.ws();
            if !self.eat(":") {
                return Err(ParseError::Invalid);
            }
            self.ws();
            let value = self.value(depth)?;
            map.insert(key, value);
            self.ws();
            if self.eat("}") {
                return Ok(Json::Obj(map));
            }
            if !self.eat(",") {
                return Err(ParseError::Invalid);
            }
        }
    }
}

fn escape(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    out.push('"');
    for c in s.chars() {
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
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(out, "\\u{unit:04x}").expect("string write");
                }
            }
        }
    }
    out.push('"');
}

fn write(out: &mut String, value: &Json) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(text) => out.push_str(text),
        // Receipts carry no floats; this mirrors Python only for special values.
        Json::Float(f) if f.is_nan() => out.push_str("NaN"),
        Json::Float(f) if f.is_infinite() => {
            out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" })
        }
        Json::Float(f) => out.push_str(&format!("{f:?}")),
        Json::Str(s) => escape(out, s),
        Json::Arr(values) => {
            out.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write(out, item);
            }
            out.push(']');
        }
        Json::Obj(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                escape(out, key);
                out.push(':');
                write(out, item);
            }
            out.push('}');
        }
    }
}

/// `(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()`.
pub fn encoded(value: &Json) -> Vec<u8> {
    let mut out = String::new();
    write(&mut out, value);
    out.push('\n');
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_parse_semantics() {
        assert_eq!(parse(b" -0 ").unwrap(), Json::Int("0".into()));
        assert_eq!(parse(b"\xef\xbb\xbf2").unwrap(), Json::Int("2".into()));
        assert!(matches!(parse(b"1.0").unwrap(), Json::Float(_)));
        assert!(matches!(parse(b"NaN").unwrap(), Json::Float(f) if f.is_nan()));
        assert_eq!(
            parse(br#"{"a":1,"a":2}"#).unwrap().get("a"),
            Some(&Json::int(2))
        );
        assert_eq!(parse(br#""\ud83d\ude00""#).unwrap(), Json::str("\u{1f600}"));
        for bad in [
            &b"01"[..],
            b"1e",
            b"[1,]",
            b"{\"a\" 1}",
            b"\"\x01\"",
            b"\"\\x\"",
            b"",
            b"tru",
            b"\xff",
        ] {
            assert_eq!(parse(bad), Err(ParseError::Invalid), "{bad:?}");
        }
        assert_eq!(parse(&b"[".repeat(9998)), Err(ParseError::TooDeep));
        let deep = [b"[".repeat(9997), b"]".repeat(9997)].concat();
        assert!(parse(&deep).is_ok());
        assert!(parse(&"9".repeat(4301).into_bytes()).is_err());
    }

    #[test]
    fn python_dump_semantics() {
        let value = parse(
            "{\"b\":[1,true,null],\"a\":\"\u{e9}\u{1f600}\\u007f\\\"/\\n\\u0001\"}".as_bytes(),
        )
        .unwrap();
        assert_eq!(
            encoded(&value),
            b"{\"a\":\"\\u00e9\\ud83d\\ude00\\u007f\\\"/\\n\\u0001\",\"b\":[1,true,null]}\n"
        );
    }
}
