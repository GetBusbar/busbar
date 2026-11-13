// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The TOML the conformance registry is written in: comments, `[table]` and `[[array]]` headers,
//! and `key = value` lines whose values are strings (basic or literal), integers, booleans or
//! one-line arrays of those. Anything else is refused as unreadable, never guessed at.

use crate::py::{Dict, Kind, PyErr, Value, R};

fn err(line: usize, what: &str) -> PyErr {
    PyErr::new(
        Kind::Value,
        format!("{what} (at line {line}) is not TOML this reader accepts"),
    )
}

struct Cur<'a> {
    c: &'a [char],
    i: usize,
    line: usize,
}

impl Cur<'_> {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.i += 1;
        }
    }
    fn key(&mut self) -> R<String> {
        match self.peek() {
            Some('"') => self.basic(),
            Some('\'') => self.literal(),
            _ => {
                let start = self.i;
                while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    self.i += 1;
                }
                if start == self.i {
                    return Err(err(self.line, "a key"));
                }
                Ok(self.c[start..self.i].iter().collect())
            }
        }
    }
    fn basic(&mut self) -> R<String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(err(self.line, "an unterminated string"));
            };
            self.i += 1;
            match c {
                '"' => return Ok(out),
                '\n' => return Err(err(self.line, "a string")),
                '\\' => {
                    let Some(e) = self.peek() else {
                        return Err(err(self.line, "an escape"));
                    };
                    self.i += 1;
                    match e {
                        'b' => out.push('\u{8}'),
                        't' => out.push('\t'),
                        'n' => out.push('\n'),
                        'f' => out.push('\u{c}'),
                        'r' => out.push('\r'),
                        'e' => out.push('\u{1b}'),
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'u' | 'U' => {
                            let n = if e == 'u' { 4 } else { 8 };
                            if self.i + n > self.c.len() {
                                return Err(err(self.line, "an escape"));
                            }
                            let h: String = self.c[self.i..self.i + n].iter().collect();
                            self.i += n;
                            let ch = u32::from_str_radix(&h, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or_else(|| err(self.line, "an escape"))?;
                            out.push(ch);
                        }
                        _ => return Err(err(self.line, "an escape")),
                    }
                }
                c if (c as u32) < 0x20 && c != '\t' || c == '\x7f' => {
                    return Err(err(self.line, "a control character"))
                }
                c => out.push(c),
            }
        }
    }
    fn literal(&mut self) -> R<String> {
        self.i += 1;
        let start = self.i;
        loop {
            match self.peek() {
                None | Some('\n') => return Err(err(self.line, "an unterminated string")),
                Some('\'') => {
                    let s: String = self.c[start..self.i].iter().collect();
                    self.i += 1;
                    return Ok(s);
                }
                Some(_) => self.i += 1,
            }
        }
    }
    fn value(&mut self) -> R<Value> {
        match self.peek() {
            Some('"') => {
                if self.c[self.i..].starts_with(&['"', '"', '"']) {
                    return Err(err(self.line, "a multi-line string"));
                }
                self.basic().map(Value::Str)
            }
            Some('\'') => {
                if self.c[self.i..].starts_with(&['\'', '\'', '\'']) {
                    return Err(err(self.line, "a multi-line string"));
                }
                self.literal().map(Value::Str)
            }
            Some('[') => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.ws();
                    if self.peek() == Some(']') {
                        self.i += 1;
                        return Ok(Value::List(items));
                    }
                    items.push(self.value()?);
                    self.ws();
                    match self.peek() {
                        Some(',') => self.i += 1,
                        Some(']') => {}
                        _ => return Err(err(self.line, "an array")),
                    }
                }
            }
            _ => {
                let start = self.i;
                while matches!(self.peek(), Some(c) if !matches!(c, ' ' | '\t' | '\n' | ',' | ']' | '#'))
                {
                    self.i += 1;
                }
                let w: String = self.c[start..self.i].iter().collect();
                match w.as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    _ => {
                        let digits = w.replace('_', "");
                        let body = digits.strip_prefix(['+', '-']).unwrap_or(&digits);
                        let ok = !body.is_empty()
                            && body.chars().all(|c| c.is_ascii_digit())
                            && !(body.len() > 1 && body.starts_with('0'))
                            && !w.starts_with('_')
                            && !w.ends_with('_')
                            && !w.contains("__");
                        if !ok {
                            return Err(err(self.line, "a value"));
                        }
                        let n: i128 = digits.parse().map_err(|_| err(self.line, "a value"))?;
                        Ok(Value::Int(n.to_string()))
                    }
                }
            }
        }
    }
    fn eol(&mut self) -> R<()> {
        self.ws();
        match self.peek() {
            Some('#') => {
                while !matches!(self.peek(), None | Some('\n')) {
                    self.i += 1;
                }
            }
            None | Some('\n') => {}
            _ => return Err(err(self.line, "trailing text")),
        }
        if self.peek() == Some('\n') {
            self.i += 1;
            self.line += 1;
        }
        Ok(())
    }
}

/// Where `key = value` lines currently land.
enum Target {
    Root,
    Table(String),
    ArrayItem(String),
}

fn slot<'a>(root: &'a mut Dict, t: &Target) -> R<&'a mut Dict> {
    match t {
        Target::Root => Ok(root),
        Target::Table(name) => match root.0.iter_mut().find(|(k, _)| k == name) {
            Some((_, Value::Dict(d))) => Ok(d),
            _ => Err(PyErr::value(format!("table {name} is not a table"))),
        },
        Target::ArrayItem(name) => match root.0.iter_mut().find(|(k, _)| k == name) {
            Some((_, Value::List(v))) => match v.last_mut() {
                Some(Value::Dict(d)) => Ok(d),
                _ => Err(PyErr::value(format!("array {name} has no table"))),
            },
            _ => Err(PyErr::value(format!("{name} is not an array of tables"))),
        },
    }
}

/// `tomllib.loads(text)`, for the subset above.
pub fn loads(text: &str) -> R<Dict> {
    let chars: Vec<char> = text.chars().collect();
    let mut c = Cur {
        c: &chars,
        i: 0,
        line: 1,
    };
    let mut root = Dict::new();
    let mut target = Target::Root;
    while c.peek().is_some() {
        c.ws();
        match c.peek() {
            None => break,
            Some('\n') | Some('#') => c.eol()?,
            Some('\r') => return Err(err(c.line, "a carriage return")),
            Some('[') => {
                let array = c.c[c.i..].starts_with(&['[', '[']);
                c.i += if array { 2 } else { 1 };
                c.ws();
                let name = c.key()?;
                c.ws();
                if c.peek() == Some('.') {
                    return Err(err(c.line, "a dotted table name"));
                }
                let close: &[char] = if array { &[']', ']'] } else { &[']'] };
                if !c.c[c.i..].starts_with(close) {
                    return Err(err(c.line, "a table header"));
                }
                c.i += close.len();
                c.eol()?;
                if array {
                    match root.0.iter_mut().find(|(k, _)| *k == name) {
                        Some((_, Value::List(v))) => v.push(Value::Dict(Dict::new())),
                        Some(_) => {
                            return Err(PyErr::value(format!(
                                "Cannot mutate immutable namespace {name:?}"
                            )))
                        }
                        None => {
                            root.insert(name.clone(), Value::List(vec![Value::Dict(Dict::new())]))
                        }
                    }
                    target = Target::ArrayItem(name);
                } else {
                    if root.contains(&name) {
                        return Err(PyErr::value(format!("Cannot declare {name:?} twice")));
                    }
                    root.insert(name.clone(), Value::Dict(Dict::new()));
                    target = Target::Table(name);
                }
            }
            Some(_) => {
                let key = c.key()?;
                c.ws();
                if c.peek() == Some('.') {
                    return Err(err(c.line, "a dotted key"));
                }
                if c.peek() != Some('=') {
                    return Err(err(c.line, "a key/value pair"));
                }
                c.i += 1;
                c.ws();
                let v = c.value()?;
                let line = c.line;
                c.eol()?;
                let d = slot(&mut root, &target)?;
                if d.contains(&key) {
                    return Err(PyErr::value(format!(
                        "Cannot overwrite a value (at line {line})"
                    )));
                }
                d.insert(key, v);
            }
        }
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_registry_shape() {
        let d = loads(
            "# c\n[[suite]]\nid = \"tls\" # x\npublic = \"true\"\nn = 3\n\n[[suite]]\nid = 'ws'\nflag = true\n",
        )
        .unwrap();
        let suites = d.get("suite").unwrap().as_list().unwrap();
        assert_eq!(suites.len(), 2);
        assert_eq!(
            suites[1].as_dict().unwrap().get("id").unwrap().as_str(),
            Some("ws")
        );
        assert!(loads("a = 1\na = 2\n").is_err());
        assert!(loads("a = \"\"\"x\"\"\"\n").is_err());
        assert!(loads("a = 1.5\n").is_err());
    }
}
