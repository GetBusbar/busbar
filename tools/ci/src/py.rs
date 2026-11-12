//! Python value semantics the retention decision depends on, over [`Value`]:
//! CPython 3 `json.loads(bytes)` (encoding detection, `surrogatepass`, the C
//! scanner's acceptance and its exact `JSONDecodeError` / `UnicodeDecodeError`
//! / int-digit-limit messages), `==` between JSON values (bool is an int,
//! int/float compare exactly), `str()`/`repr()`, `type(x).__name__` and float
//! `repr`. Lone surrogates become U+FFFD: they can never equal a trusted value.
use crate::json::Value;
use std::fmt::Write as _;

/// A Python exception: class name and `str(exception)`.
#[derive(Clone, Debug, PartialEq)]
pub struct PyErr {
    pub class: &'static str,
    pub message: String,
}

impl PyErr {
    pub fn new(class: &'static str, message: impl Into<String>) -> PyErr {
        PyErr {
            class,
            message: message.into(),
        }
    }

    /// `isinstance(error, ValueError)` for the classes raised here.
    pub fn is_value_error(&self) -> bool {
        matches!(
            self.class,
            "ValueError" | "JSONDecodeError" | "UnicodeDecodeError"
        )
    }
}

/// Recursion bound standing in for CPython's (stack-dependent) RecursionError.
pub const MAX_DEPTH: usize = 100_000;
const INT_DIGITS_LIMIT: usize = 4300;

fn is_surrogate_bytes(data: &[u8]) -> bool {
    data.len() >= 3
        && data[0] == 0xed
        && (0xa0..=0xbf).contains(&data[1])
        && (0x80..=0xbf).contains(&data[2])
}

/// `str(UnicodeDecodeError)` text for the utf-8 codec.
fn utf8_error(codec: &str, data: &[u8], start: usize, len: Option<usize>) -> PyErr {
    let (end, reason) = match len {
        None => (data.len(), "unexpected end of data"),
        Some(n) => {
            let first = data[start];
            let invalid_start = (0x80..=0xc1).contains(&first) || first >= 0xf5;
            (
                start + n,
                if n == 1 && invalid_start {
                    "invalid start byte"
                } else {
                    "invalid continuation byte"
                },
            )
        }
    };
    let message = if end - start == 1 {
        format!(
            "'{codec}' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            data[start]
        )
    } else {
        format!(
            "'{codec}' codec can't decode bytes in position {start}-{}: {reason}",
            end - 1
        )
    };
    PyErr::new("UnicodeDecodeError", message)
}

/// `bytes.decode('utf-8', 'strict' | 'surrogatepass')` as chars.
pub fn decode_utf8(data: &[u8], surrogatepass: bool) -> Result<Vec<char>, PyErr> {
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0;
    while at < data.len() {
        match std::str::from_utf8(&data[at..]) {
            Ok(text) => {
                out.extend(text.chars());
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                out.extend(
                    std::str::from_utf8(&data[at..at + valid])
                        .unwrap_or_default()
                        .chars(),
                );
                let bad = at + valid;
                if surrogatepass && is_surrogate_bytes(&data[bad..]) {
                    out.push('\u{fffd}');
                    at = bad + 3;
                    continue;
                }
                return Err(utf8_error("utf-8", data, bad, error.error_len()));
            }
        }
    }
    Ok(out)
}

fn decode_utf16(data: &[u8], big: bool, codec: &str, offset: usize) -> Result<Vec<char>, PyErr> {
    let mut out = Vec::with_capacity(data.len() / 2);
    let units = data.len() / 2;
    for i in 0..units {
        let pair = [data[2 * i], data[2 * i + 1]];
        let unit = if big {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        };
        out.push(unit);
    }
    let mut chars = Vec::with_capacity(out.len());
    let mut i = 0;
    while i < out.len() {
        let unit = out[i];
        if (0xd800..0xdc00).contains(&unit)
            && i + 1 < out.len()
            && (0xdc00..0xe000).contains(&out[i + 1])
        {
            let c = 0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(out[i + 1]) - 0xdc00);
            chars.push(char::from_u32(c).unwrap_or('\u{fffd}'));
            i += 2;
            continue;
        }
        chars.push(char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}'));
        i += 1;
    }
    if data.len() % 2 == 1 {
        let at = data.len() - 1;
        return Err(PyErr::new(
            "UnicodeDecodeError",
            format!(
                "'{codec}' codec can't decode byte 0x{:02x} in position {}: truncated data",
                data[at],
                at + offset
            ),
        ));
    }
    Ok(chars)
}

fn decode_utf32(data: &[u8], big: bool, codec: &str, offset: usize) -> Result<Vec<char>, PyErr> {
    let mut chars = Vec::with_capacity(data.len() / 4);
    let whole = data.len() / 4 * 4;
    for (i, quad) in data[..whole].chunks(4).enumerate() {
        let quad = [quad[0], quad[1], quad[2], quad[3]];
        let c = if big {
            u32::from_be_bytes(quad)
        } else {
            u32::from_le_bytes(quad)
        };
        if c > 0x10ffff {
            let at = 4 * i + offset;
            return Err(PyErr::new(
                "UnicodeDecodeError",
                format!(
                    "'{codec}' codec can't decode bytes in position {at}-{}: code point not in range(0x110000)",
                    at + 3
                ),
            ));
        }
        chars.push(char::from_u32(c).unwrap_or('\u{fffd}'));
    }
    if whole != data.len() {
        let message = if data.len() - whole == 1 {
            format!(
                "'{codec}' codec can't decode byte 0x{:02x} in position {}: truncated data",
                data[whole],
                whole + offset
            )
        } else {
            format!(
                "'{codec}' codec can't decode bytes in position {}-{}: truncated data",
                whole + offset,
                data.len() - 1 + offset
            )
        };
        return Err(PyErr::new("UnicodeDecodeError", message));
    }
    Ok(chars)
}

/// `bytes.decode(json.detect_encoding(b), 'surrogatepass')`.
fn decode_json_bytes(b: &[u8]) -> Result<Vec<char>, PyErr> {
    if b.starts_with(&[0, 0, 0xfe, 0xff]) {
        return decode_utf32(&b[4..], true, "utf-32-be", 4);
    }
    if b.starts_with(&[0xff, 0xfe, 0, 0]) {
        return decode_utf32(&b[4..], false, "utf-32-le", 4);
    }
    if b.starts_with(&[0xfe, 0xff]) {
        return decode_utf16(&b[2..], true, "utf-16-be", 2);
    }
    if b.starts_with(&[0xff, 0xfe]) {
        return decode_utf16(&b[2..], false, "utf-16-le", 2);
    }
    if let Some(rest) = b.strip_prefix(b"\xef\xbb\xbf") {
        return decode_utf8(rest, true);
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] != 0 {
                decode_utf16(b, true, "utf-16-be", 0)
            } else {
                decode_utf32(b, true, "utf-32-be", 0)
            };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 {
                decode_utf16(b, false, "utf-16-le", 0)
            } else {
                decode_utf32(b, false, "utf-32-le", 0)
            };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return decode_utf16(b, true, "utf-16-be", 0);
        }
        if b[1] == 0 {
            return decode_utf16(b, false, "utf-16-le", 0);
        }
    }
    decode_utf8(b, true)
}

enum Scan {
    /// StopIteration(idx): reported as "Expecting value".
    Stop(usize),
    Error(PyErr),
}

struct Scanner<'a> {
    s: &'a [char],
}

fn white(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn digit(c: char) -> bool {
    c.is_ascii_digit()
}

impl Scanner<'_> {
    fn error(&self, message: &str, pos: usize) -> Scan {
        Scan::Error(decode_error(self.s, message, pos))
    }

    fn skip(&self, mut idx: usize) -> usize {
        while idx < self.s.len() && white(self.s[idx]) {
            idx += 1;
        }
        idx
    }

    fn word(&self, idx: usize, word: &str) -> bool {
        let n = word.chars().count();
        idx + n - 1 < self.s.len() && self.s[idx..idx + n].iter().copied().eq(word.chars())
    }

    fn scan_once(&self, idx: usize, depth: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        if idx >= s.len() {
            return Err(Scan::Stop(idx));
        }
        match s[idx] {
            '"' => {
                let (text, end) = self.string(idx + 1)?;
                return Ok((Value::String(text), end));
            }
            '{' | '[' => {
                let what = if s[idx] == '{' { "object" } else { "array" };
                if depth >= MAX_DEPTH {
                    return Err(Scan::Error(PyErr::new(
                        "RecursionError",
                        format!(
                            "maximum recursion depth exceeded while decoding a JSON {what} from a unicode string"
                        ),
                    )));
                }
                return if s[idx] == '{' {
                    self.object(idx + 1, depth + 1)
                } else {
                    self.array(idx + 1, depth + 1)
                };
            }
            'n' if self.word(idx, "null") => return Ok((Value::Null, idx + 4)),
            't' if self.word(idx, "true") => return Ok((Value::Bool(true), idx + 4)),
            'f' if self.word(idx, "false") => return Ok((Value::Bool(false), idx + 5)),
            'N' if self.word(idx, "NaN") => return Ok((Value::Number("NaN".into()), idx + 3)),
            'I' if self.word(idx, "Infinity") => {
                return Ok((Value::Number("Infinity".into()), idx + 8));
            }
            '-' if self.word(idx, "-Infinity") => {
                return Ok((Value::Number("-Infinity".into()), idx + 9));
            }
            _ => {}
        }
        self.number(idx)
    }

    fn number(&self, start: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        let end_idx = s.len() as isize - 1;
        let mut idx = start;
        let at = |i: usize| s[i];
        if at(idx) == '-' {
            idx += 1;
            if idx as isize > end_idx {
                return Err(Scan::Stop(start));
            }
        }
        let c = at(idx);
        if ('1'..='9').contains(&c) {
            idx += 1;
            while (idx as isize) <= end_idx && digit(at(idx)) {
                idx += 1;
            }
        } else if c == '0' {
            idx += 1;
        } else {
            return Err(Scan::Stop(start));
        }
        let mut float = false;
        if (idx as isize) < end_idx && at(idx) == '.' && digit(at(idx + 1)) {
            float = true;
            idx += 2;
            while (idx as isize) <= end_idx && digit(at(idx)) {
                idx += 1;
            }
        }
        if (idx as isize) < end_idx && (at(idx) == 'e' || at(idx) == 'E') {
            let e_start = idx;
            idx += 1;
            if (idx as isize) < end_idx && (at(idx) == '-' || at(idx) == '+') {
                idx += 1;
            }
            while (idx as isize) <= end_idx && digit(at(idx)) {
                idx += 1;
            }
            if digit(at(idx - 1)) {
                float = true;
            } else {
                idx = e_start;
            }
        }
        let text: String = s[start..idx].iter().collect();
        if float {
            let value: f64 = text.parse().unwrap_or(f64::NAN);
            return Ok((Value::Number(float_json(value)), idx));
        }
        let digits = text.strip_prefix('-').unwrap_or(&text);
        if digits.len() > INT_DIGITS_LIMIT {
            return Err(Scan::Error(PyErr::new(
                "ValueError",
                format!(
                    "Exceeds the limit ({INT_DIGITS_LIMIT} digits) for integer string conversion: value has {} digits; use sys.set_int_max_str_digits() to increase the limit",
                    digits.len()
                ),
            )));
        }
        let canonical = if digits.bytes().all(|b| b == b'0') {
            "0".to_owned()
        } else {
            text
        };
        Ok((Value::Number(canonical), idx))
    }

    fn string(&self, mut end: usize) -> Result<(String, usize), Scan> {
        let s = self.s;
        let len = s.len();
        let begin = end - 1;
        let mut out = String::new();
        loop {
            let mut next = end;
            let mut c = '\0';
            while next < len {
                let d = s[next];
                if d == '"' || d == '\\' {
                    c = d;
                    break;
                }
                if (d as u32) <= 0x1f {
                    return Err(self.error("Invalid control character at", next));
                }
                next += 1;
            }
            if next >= len || !(c == '"' || c == '\\') {
                return Err(self.error("Unterminated string starting at", begin));
            }
            out.extend(&s[end..next]);
            next += 1;
            if c == '"' {
                return Ok((out, next));
            }
            if next == len {
                return Err(self.error("Unterminated string starting at", begin));
            }
            let c = s[next];
            if c != 'u' {
                end = next + 1;
                let mapped = match c {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => return Err(self.error("Invalid \\escape", end - 2)),
                };
                out.push(mapped);
                continue;
            }
            next += 1;
            end = next + 4;
            if end > len {
                return Err(self.error("Invalid \\uXXXX escape", next - 1));
            }
            let hex = |from: usize, to: usize| -> Option<u32> {
                let mut value = 0u32;
                for &h in &s[from..to] {
                    value = (value << 4) | h.to_digit(16)?;
                }
                Some(value)
            };
            let mut code =
                hex(next, end).ok_or_else(|| self.error("Invalid \\uXXXX escape", end - 5))?;
            if (0xd800..0xdc00).contains(&code)
                && end + 6 < len
                && s[end] == '\\'
                && s[end + 1] == 'u'
            {
                let low = hex(end + 2, end + 6)
                    .ok_or_else(|| self.error("Invalid \\uXXXX escape", end + 1))?;
                if (0xdc00..0xe000).contains(&low) {
                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                    end += 6;
                }
            }
            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
        }
    }

    fn object(&self, idx: usize, depth: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        let mut rows: Vec<(String, Value)> = Vec::new();
        let mut idx = self.skip(idx);
        if idx >= s.len() || s[idx] != '}' {
            loop {
                if idx >= s.len() || s[idx] != '"' {
                    return Err(
                        self.error("Expecting property name enclosed in double quotes", idx)
                    );
                }
                let (key, next) = self.string(idx + 1)?;
                idx = self.skip(next);
                if idx >= s.len() || s[idx] != ':' {
                    return Err(self.error("Expecting ':' delimiter", idx));
                }
                idx = self.skip(idx + 1);
                let (value, next) = self.scan_once(idx, depth)?;
                match rows.iter_mut().find(|(k, _)| *k == key) {
                    Some(row) => row.1 = value,
                    None => rows.push((key, value)),
                }
                idx = self.skip(next);
                if idx < s.len() && s[idx] == '}' {
                    break;
                }
                if idx >= s.len() || s[idx] != ',' {
                    return Err(self.error("Expecting ',' delimiter", idx));
                }
                let comma = idx;
                idx = self.skip(idx + 1);
                if idx < s.len() && s[idx] == '}' {
                    return Err(self.error("Illegal trailing comma before end of object", comma));
                }
            }
        }
        Ok((Value::Object(rows), idx + 1))
    }

    fn array(&self, idx: usize, depth: usize) -> Result<(Value, usize), Scan> {
        let s = self.s;
        let mut rows = Vec::new();
        let mut idx = self.skip(idx);
        if idx >= s.len() || s[idx] != ']' {
            loop {
                let (value, next) = self.scan_once(idx, depth)?;
                rows.push(value);
                idx = self.skip(next);
                if idx < s.len() && s[idx] == ']' {
                    break;
                }
                if idx >= s.len() || s[idx] != ',' {
                    return Err(self.error("Expecting ',' delimiter", idx));
                }
                let comma = idx;
                idx = self.skip(idx + 1);
                if idx < s.len() && s[idx] == ']' {
                    return Err(self.error("Illegal trailing comma before end of array", comma));
                }
            }
        }
        Ok((Value::Array(rows), idx + 1))
    }
}

fn decode_error(doc: &[char], message: &str, pos: usize) -> PyErr {
    let before = &doc[..pos.min(doc.len())];
    let line = before.iter().filter(|c| **c == '\n').count() + 1;
    let column = match before.iter().rposition(|c| *c == '\n') {
        Some(i) => pos - i,
        None => pos + 1,
    };
    PyErr::new(
        "JSONDecodeError",
        format!("{message}: line {line} column {column} (char {pos})"),
    )
}

/// `json.loads(data)` for bytes.
pub fn loads(data: &[u8]) -> Result<Value, PyErr> {
    let doc = decode_json_bytes(data)?;
    let scanner = Scanner { s: &doc };
    let idx = scanner.skip(0);
    let (value, end) = match scanner.scan_once(idx, 0) {
        Ok(found) => found,
        Err(Scan::Stop(at)) => return Err(decode_error(&doc, "Expecting value", at)),
        Err(Scan::Error(error)) => return Err(error),
    };
    let end = scanner.skip(end);
    if end != doc.len() {
        return Err(decode_error(&doc, "Extra data", end));
    }
    Ok(value)
}

/// `float.__repr__`, the text `json.dumps` writes for finite floats.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.into();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .into();
    }
    // Rust's `{:e}` is the shortest round-trip form, like repr's digits.
    let text = format!("{:e}", value.abs());
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let decpt = exponent + 1;
    let sign = if value < 0.0 { "-" } else { "" };
    if decpt <= -4 || decpt > 16 {
        let mut out = format!("{sign}{}", &digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let _ = write!(
            out,
            "e{}{:02}",
            if exponent < 0 { '-' } else { '+' },
            exponent.abs()
        );
        out
    } else if decpt <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-decpt) as usize))
    } else {
        let point = decpt as usize;
        if digits.len() <= point {
            format!("{sign}{digits}{}.0", "0".repeat(point - digits.len()))
        } else {
            format!("{sign}{}.{}", &digits[..point], &digits[point..])
        }
    }
}

/// The text `json.dumps` writes for a float.
pub fn float_json(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value.is_infinite() {
        if value > 0.0 { "Infinity" } else { "-Infinity" }.into()
    } else {
        float_repr(value)
    }
}

fn integer_text(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit())
}

fn float_of(text: &str) -> f64 {
    match text {
        "NaN" => f64::NAN,
        "Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        _ => text.parse().unwrap_or(f64::NAN),
    }
}

/// A number as Python sees it: exact integer text or a float.
enum Num {
    Int(String),
    Float(f64),
}

fn number(value: &Value) -> Option<Num> {
    match value {
        Value::Bool(b) => Some(Num::Int(if *b { "1" } else { "0" }.into())),
        Value::Number(n) if integer_text(n) => Some(Num::Int(n.clone())),
        Value::Number(n) => Some(Num::Float(float_of(n))),
        _ => None,
    }
}

fn int_equals_float(int: &str, float: f64) -> bool {
    if !float.is_finite() || float.fract() != 0.0 {
        return false;
    }
    let exact = format!("{float:.0}");
    let exact = if exact == "-0" { "0".to_owned() } else { exact };
    exact == int
}

/// Python `a == b` for JSON-derived values.
pub fn eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.iter().any(|(k2, v2)| k == k2 && eq(v, v2)))
        }
        _ => match (number(a), number(b)) {
            (Some(Num::Int(x)), Some(Num::Int(y))) => x == y,
            (Some(Num::Float(x)), Some(Num::Float(y))) => x == y,
            (Some(Num::Int(x)), Some(Num::Float(y))) | (Some(Num::Float(y)), Some(Num::Int(x))) => {
                int_equals_float(&x, y)
            }
            _ => false,
        },
    }
}

/// `type(value).__name__`.
pub fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if integer_text(n) => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `repr(text)` for a str.
pub fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (0x7f..0xa1).contains(&(c as u32)) || c == '\u{ad}' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if matches!(c as u32, 0x2028 | 0x2029 | 0xfeff | 0x200b..=0x200f | 0x2060..=0x2064) =>
            {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr(value)`.
pub fn repr(value: &Value) -> String {
    match value {
        Value::String(s) => repr_str(s),
        Value::Array(rows) => format!("[{}]", rows.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(rows) => format!(
            "{{{}}}",
            rows.iter()
                .map(|(k, v)| format!("{}: {}", repr_str(k), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => str(other),
    }
}

/// `str(value)`.
pub fn str(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) if integer_text(n) => n.clone(),
        Value::Number(n) => float_repr(float_of(n)),
        Value::String(s) => s.clone(),
        other => repr(other),
    }
}

/// Python truthiness.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Number(n) if !integer_text(n) => float_of(n) != 0.0,
        other => other.truthy(),
    }
}

/// `json.dumps(value, indent=2, sort_keys=True)`.
pub fn dumps_sorted_indent(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Array(rows) => Value::Array(rows.iter().map(sorted).collect()),
            Value::Object(rows) => {
                let mut rows: Vec<(String, Value)> =
                    rows.iter().map(|(k, v)| (k.clone(), sorted(v))).collect();
                rows.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(rows)
            }
            other => other.clone(),
        }
    }
    crate::json::dumps_indent(&sorted(value))
}

/// Characters of `text` up to `n` code points (`text[:n]`).
pub fn prefix(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(data: &[u8]) -> String {
        loads(data).unwrap_err().message
    }

    #[test]
    fn decode_errors_match_cpython() {
        for (input, expected) in [
            (
                &b"{\"a\": }"[..],
                "Expecting value: line 1 column 7 (char 6)",
            ),
            (
                b"[1,]",
                "Illegal trailing comma before end of array: line 1 column 3 (char 2)",
            ),
            (
                b"{\"a\":1,}",
                "Illegal trailing comma before end of object: line 1 column 7 (char 6)",
            ),
            (
                b"\"\\u12",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
            (
                b"\"abc",
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            (
                b"\"a\x01\"",
                "Invalid control character at: line 1 column 3 (char 2)",
            ),
            (
                b"[1 2]",
                "Expecting ',' delimiter: line 1 column 4 (char 3)",
            ),
            (
                b"{\"a\" 1}",
                "Expecting ':' delimiter: line 1 column 6 (char 5)",
            ),
            (
                b"{1:2}",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (b"tru", "Expecting value: line 1 column 1 (char 0)"),
            (b"1 2", "Extra data: line 1 column 3 (char 2)"),
            (b"-", "Expecting value: line 1 column 1 (char 0)"),
            (b"\"\\x\"", "Invalid \\escape: line 1 column 2 (char 1)"),
            (b"[", "Expecting value: line 1 column 2 (char 1)"),
            (b"1.e5", "Extra data: line 1 column 2 (char 1)"),
            (
                b"{not json",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (
                b"\xff",
                "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
            ),
        ] {
            assert_eq!(error(input), expected, "{}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn values_and_python_equality() {
        let v = loads(b"{\"a\": 1, \"a\": 2.50, \"b\": [true, null, -0, 1e400]}").unwrap();
        assert_eq!(
            crate::json::dumps(&v, true),
            "{\"a\": 2.5, \"b\": [true, null, 0, Infinity]}"
        );
        assert!(eq(&Value::Bool(false), &Value::int(0)));
        assert!(eq(&Value::Number("3.0".into()), &Value::int(3)));
        assert!(!eq(
            &Value::Number("NaN".into()),
            &Value::Number("NaN".into())
        ));
        assert!(!eq(&Value::str("3"), &Value::int(3)));
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1e15), "1000000000000000.0");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(0.00001), "1e-05");
        assert_eq!(float_repr(1.5e-7), "1.5e-07");
        assert_eq!(float_repr(123.456), "123.456");
        assert_eq!(str(&Value::Number("50.0".into())), "50.0");
        assert_eq!(
            repr(&loads(b"{\"a\": [1, \"x'\"]}").unwrap()),
            "{'a': [1, \"x'\"]}"
        );
    }
}
