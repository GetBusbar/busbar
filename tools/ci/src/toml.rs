//! TOML 1.0 reader for protected policy, producing `json::Value` like `tomllib`.
//! Offset date-times are refused: the policy has none and the bootstrap needs none.
use crate::json::Value;
use std::collections::BTreeSet;

pub fn parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    let mut root = Value::Object(Vec::new());
    let mut current: Vec<String> = Vec::new();
    let mut defined: BTreeSet<Vec<String>> = BTreeSet::new();
    loop {
        parser.blank_lines()?;
        if parser.i >= parser.s.len() {
            return Ok(root);
        }
        if parser.peek() == Some(b'[') {
            let array = parser.s[parser.i..].starts_with(b"[[");
            parser.i += if array { 2 } else { 1 };
            parser.spaces();
            let path = parser.key()?;
            parser.spaces();
            for _ in 0..if array { 2 } else { 1 } {
                parser.expect(b']')?;
            }
            parser.end_of_line()?;
            if array {
                let (parent, last) = path.split_at(path.len() - 1);
                let table = navigate(&mut root, parent)?;
                match table.get_mut(&last[0]) {
                    Some(Value::Array(rows)) => rows.push(Value::Object(Vec::new())),
                    Some(_) => {
                        return Err(format!("TOML key {} is not an array of tables", last[0]));
                    }
                    None => table.set(&last[0], Value::Array(vec![Value::Object(Vec::new())])),
                }
            } else {
                if !defined.insert(path.clone()) {
                    return Err(format!("TOML table [{}] is defined twice", path.join(".")));
                }
                navigate(&mut root, &path)?;
            }
            current = path;
        } else {
            let key = parser.key()?;
            parser.spaces();
            parser.expect(b'=')?;
            parser.spaces();
            let value = parser.value()?;
            parser.end_of_line()?;
            let mut full = current.clone();
            full.extend(key);
            let (parent, last) = full.split_at(full.len() - 1);
            let table = navigate(&mut root, parent)?;
            if table.get(&last[0]).is_some() {
                return Err(format!("duplicate TOML key {}", full.join(".")));
            }
            table.set(&last[0], value);
        }
    }
}

fn navigate<'a>(mut table: &'a mut Value, path: &[String]) -> Result<&'a mut Value, String> {
    for part in path {
        if table.get(part).is_none() {
            table.set(part, Value::Object(Vec::new()));
        }
        let next = table.get_mut(part).unwrap();
        table = match next {
            Value::Array(rows) => rows
                .last_mut()
                .filter(|row| row.is_object())
                .ok_or_else(|| format!("TOML key {part} is not a table"))?,
            Value::Object(_) => next,
            _ => return Err(format!("TOML key {part} is not a table")),
        };
    }
    Ok(table)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn error<T>(&self, message: &str) -> Result<T, String> {
        let line = self.s[..self.i.min(self.s.len())]
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            + 1;
        Err(format!("TOML {message} at line {line}"))
    }
    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.i += 1;
            Ok(())
        } else {
            self.error(&format!("expected '{}'", byte as char))
        }
    }
    fn spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }
    fn comment(&mut self) -> Result<(), String> {
        if self.peek() == Some(b'#') {
            while let Some(c) = self.peek() {
                if c == b'\n' {
                    break;
                }
                if c < 0x20 && c != b'\t' && !(c == b'\r' && self.s.get(self.i + 1) == Some(&b'\n'))
                {
                    return self.error("control character in comment");
                }
                self.i += 1;
            }
        }
        Ok(())
    }
    fn newline(&mut self) -> bool {
        if self.peek() == Some(b'\n') {
            self.i += 1;
            true
        } else if self.s[self.i..].starts_with(b"\r\n") {
            self.i += 2;
            true
        } else {
            false
        }
    }
    fn end_of_line(&mut self) -> Result<(), String> {
        self.spaces();
        self.comment()?;
        if self.i >= self.s.len() || self.newline() {
            Ok(())
        } else {
            self.error("expected end of line")
        }
    }
    fn blank_lines(&mut self) -> Result<(), String> {
        loop {
            self.spaces();
            self.comment()?;
            if !self.newline() {
                return Ok(());
            }
        }
    }
    /// Whitespace, newlines and comments inside arrays.
    fn array_space(&mut self) -> Result<(), String> {
        loop {
            self.spaces();
            self.comment()?;
            if !self.newline() {
                return Ok(());
            }
        }
    }
    fn key(&mut self) -> Result<Vec<String>, String> {
        let mut parts = Vec::new();
        loop {
            self.spaces();
            let part = match self.peek() {
                Some(b'"') if !self.s[self.i..].starts_with(b"\"\"\"") => self.basic()?,
                Some(b'\'') if !self.s[self.i..].starts_with(b"'''") => self.literal()?,
                _ => {
                    let start = self.i;
                    while self
                        .peek()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                    {
                        self.i += 1;
                    }
                    if self.i == start {
                        return self.error("invalid key");
                    }
                    String::from_utf8(self.s[start..self.i].to_vec()).unwrap()
                }
            };
            parts.push(part);
            self.spaces();
            if self.peek() == Some(b'.') {
                self.i += 1;
            } else {
                return Ok(parts);
            }
        }
    }
    fn escape(&mut self, out: &mut String) -> Result<(), String> {
        let c = self.peek().ok_or("truncated TOML escape")?;
        self.i += 1;
        let hex = |p: &mut Self, n: usize| -> Result<char, String> {
            let digits = p.s.get(p.i..p.i + n).ok_or("truncated TOML escape")?;
            let code = std::str::from_utf8(digits)
                .ok()
                .and_then(|t| u32::from_str_radix(t, 16).ok())
                .and_then(char::from_u32)
                .ok_or("invalid TOML unicode escape")?;
            p.i += n;
            Ok(code)
        };
        match c {
            b'b' => out.push('\u{8}'),
            b't' => out.push('\t'),
            b'n' => out.push('\n'),
            b'f' => out.push('\u{c}'),
            b'r' => out.push('\r'),
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'u' => out.push(hex(self, 4)?),
            b'U' => out.push(hex(self, 8)?),
            _ => return self.error("invalid escape"),
        }
        Ok(())
    }
    fn chunk(&mut self, start: usize, out: &mut String) -> Result<(), String> {
        out.push_str(std::str::from_utf8(&self.s[start..self.i]).map_err(|_| "TOML is not UTF-8")?);
        Ok(())
    }
    fn basic(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self
                .peek()
                .is_some_and(|c| c != b'"' && c != b'\\' && (c >= 0x20 || c == b'\t') && c != 0x7f)
            {
                self.i += 1;
            }
            self.chunk(start, &mut out)?;
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    self.escape(&mut out)?;
                }
                _ => return self.error("unterminated string"),
            }
        }
    }
    fn literal(&mut self) -> Result<String, String> {
        self.expect(b'\'')?;
        let start = self.i;
        while self
            .peek()
            .is_some_and(|c| c != b'\'' && (c >= 0x20 || c == b'\t') && c != 0x7f)
        {
            self.i += 1;
        }
        let mut out = String::new();
        self.chunk(start, &mut out)?;
        self.expect(b'\'')?;
        Ok(out)
    }
    fn multiline(&mut self, quote: u8) -> Result<String, String> {
        let delimiter = [quote; 3];
        self.i += 3;
        self.newline();
        let mut out = String::new();
        loop {
            if self.s[self.i..].starts_with(&delimiter) {
                // Up to two adjacent quotes may close the content.
                let mut extra = 0;
                while extra < 2 && self.s.get(self.i + 3 + extra) == Some(&quote) {
                    extra += 1;
                }
                out.extend(std::iter::repeat_n(quote as char, extra));
                self.i += 3 + extra;
                return Ok(out);
            }
            match self.peek() {
                None => return self.error("unterminated multi-line string"),
                Some(b'\\') if quote == b'"' => {
                    self.i += 1;
                    let save = self.i;
                    self.spaces();
                    if self.newline() {
                        loop {
                            self.spaces();
                            if !self.newline() {
                                break;
                            }
                        }
                    } else {
                        self.i = save;
                        self.escape(&mut out)?;
                    }
                }
                Some(c) if c == b'\n' || c == b'\t' || c >= 0x20 && c != 0x7f => {
                    let start = self.i;
                    self.i += 1;
                    while self.peek().is_some_and(|b| (0x80..0xc0).contains(&b)) {
                        self.i += 1;
                    }
                    self.chunk(start, &mut out)?;
                }
                Some(b'\r') if self.s.get(self.i + 1) == Some(&b'\n') => {
                    self.i += 2;
                    out.push('\n');
                }
                _ => return self.error("control character in string"),
            }
        }
    }
    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'"') if self.s[self.i..].starts_with(b"\"\"\"") => {
                self.multiline(b'"').map(Value::String)
            }
            Some(b'\'') if self.s[self.i..].starts_with(b"'''") => {
                self.multiline(b'\'').map(Value::String)
            }
            Some(b'"') => self.basic().map(Value::String),
            Some(b'\'') => self.literal().map(Value::String),
            Some(b'[') => {
                self.i += 1;
                let mut rows = Vec::new();
                loop {
                    self.array_space()?;
                    if self.peek() == Some(b']') {
                        self.i += 1;
                        return Ok(Value::Array(rows));
                    }
                    rows.push(self.value()?);
                    self.array_space()?;
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Array(rows));
                        }
                        _ => return self.error("invalid array"),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut table = Value::Object(Vec::new());
                self.spaces();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(table);
                }
                loop {
                    let key = self.key()?;
                    self.spaces();
                    self.expect(b'=')?;
                    self.spaces();
                    let value = self.value()?;
                    let (parent, last) = key.split_at(key.len() - 1);
                    let target = navigate(&mut table, parent)?;
                    if target.get(&last[0]).is_some() {
                        return self.error("duplicate inline table key");
                    }
                    target.set(&last[0], value);
                    self.spaces();
                    match self.peek() {
                        Some(b',') => {
                            self.i += 1;
                            self.spaces();
                        }
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(table);
                        }
                        _ => return self.error("invalid inline table"),
                    }
                }
            }
            _ => {
                let start = self.i;
                while self.peek().is_some_and(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'+' | b'.' | b':')
                }) {
                    self.i += 1;
                }
                let word = std::str::from_utf8(&self.s[start..self.i]).unwrap();
                scalar(word).or_else(|e| self.error(&e))
            }
        }
    }
}

fn scalar(word: &str) -> Result<Value, String> {
    match word {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        "" => return Err("missing value".into()),
        _ => {}
    }
    let valid_underscores =
        |digits: &str| !digits.starts_with('_') && !digits.ends_with('_') && !digits.contains("__");
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(digits) = word.strip_prefix(prefix) {
            if !valid_underscores(digits) {
                return Err("invalid integer".into());
            }
            let value = i64::from_str_radix(&digits.replace('_', ""), radix)
                .map_err(|_| "invalid integer".to_owned())?;
            return Ok(Value::Number(value.to_string()));
        }
    }
    let unsigned = word.strip_prefix(['+', '-']).unwrap_or(word);
    if !valid_underscores(unsigned) {
        return Err("invalid number".into());
    }
    let plain = word.replace('_', "");
    let body = plain.strip_prefix(['+', '-']).unwrap_or(&plain);
    if body.bytes().all(|c| c.is_ascii_digit()) {
        if body.len() > 1 && body.starts_with('0') {
            return Err("leading zero in integer".into());
        }
        let value: i64 = plain.parse().map_err(|_| "invalid integer".to_owned())?;
        return Ok(Value::Number(value.to_string()));
    }
    if body.contains([':']) || (body.len() >= 10 && body.as_bytes()[4] == b'-') {
        return Err("date-time values are not supported in protected policy".into());
    }
    let digits_ok = body.split(['.', 'e', 'E']).all(|part| {
        let part = part.strip_prefix(['+', '-']).unwrap_or(part);
        !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit())
    });
    if digits_ok && plain.parse::<f64>().is_ok() && !body.starts_with('.') {
        return Ok(Value::Number(plain));
    }
    Err(format!("invalid value {word}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_shapes() {
        let value = parse(
            r#"
# comment
title = "x" # trailing
[repositories."GetBusbar/a"]
native = { services = ["wiremock"], prepare_runtime = 'testing/native/prepare.sh' }
kind = "auth"
private = false

[[repositories."GetBusbar/a".packages]]
name = "one"
dev_allows = [
  "a", # note
  "b",
]

[[repositories."GetBusbar/a".packages]]
name = "two"
n = 1_000
f = -1.5e3
[assembly]
native.services = []
text = """
line\
   joined"""
"#,
        )
        .unwrap();
        let repo = value.at("repositories").at("GetBusbar/a");
        assert_eq!(
            repo.at("native").at("services").index(0).as_str(),
            Some("wiremock")
        );
        assert_eq!(repo.at("private").as_bool(), Some(false));
        let packages = repo.at("packages").as_array().unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].at("dev_allows").as_array().unwrap().len(), 2);
        assert_eq!(packages[1].at("n").as_u64(), Some(1000));
        assert_eq!(
            value
                .at("assembly")
                .at("native")
                .at("services")
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(value.at("assembly").at("text").as_str(), Some("linejoined"));
    }

    #[test]
    fn rejects_invalid_or_ambiguous_documents() {
        for bad in [
            "a = 1\na = 2",
            "[t]\n[t]",
            "a = ",
            "a = 1 b = 2",
            "a = 2026-11-11T00:00:00Z",
            "a = 012",
            "a = [1,,2]",
            "a = { b = 1, b = 2 }",
            "a = \"unterminated",
            "a = 1\n[a]",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn actual_protected_policy_parses() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/architecture.toml");
        let value = parse(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            value.at("assembly").at("repository").as_str(),
            Some("GetBusbar/busbar")
        );
    }
}
