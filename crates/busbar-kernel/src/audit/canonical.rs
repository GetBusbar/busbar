// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The canonical form of an audit row's `data` (ADMIN-API-1.6 section 7.2, hash scheme 3).
//!
//! Compact JSON: no whitespace outside strings; object members in ascending order of their names'
//! UTF-8 bytes at every depth; strings escaped minimally (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`,
//! other U+0000..U+001F as `\u00xx` in lowercase hex, every other character as raw UTF-8); a number
//! is kept as the token the writer wrote, so no precision is lost.

/// Re-serialize the JSON object `text` in canonical form. `Err` for anything but one JSON object.
pub(crate) fn canonical_object(text: &str) -> Result<String, ()> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
        depth: 0,
    };
    parser.space();
    if parser.peek() != Some(b'{') {
        return Err(());
    }
    let mut out = String::with_capacity(text.len());
    parser.value(&mut out)?;
    parser.space();
    if parser.at != parser.bytes.len() {
        return Err(());
    }
    Ok(out)
}

const MAX_DEPTH: usize = 64;

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Result<(), ()> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    fn literal(&mut self, word: &str, out: &mut String) -> Result<(), ()> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            out.push_str(word);
            Ok(())
        } else {
            Err(())
        }
    }

    fn value(&mut self, out: &mut String) -> Result<(), ()> {
        self.space();
        match self.peek().ok_or(())? {
            b'{' => self.object(out),
            b'[' => self.array(out),
            b'"' => {
                let s = self.string()?;
                push_string(out, &s);
                Ok(())
            }
            b't' => self.literal("true", out),
            b'f' => self.literal("false", out),
            b'n' => self.literal("null", out),
            b'-' | b'0'..=b'9' => self.number(out),
            _ => Err(()),
        }
    }

    fn number(&mut self, out: &mut String) -> Result<(), ()> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let digits = |p: &mut Self| {
            let from = p.at;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.at += 1;
            }
            p.at - from
        };
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(()),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if digits(self) == 0 {
                return Err(());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if digits(self) == 0 {
                return Err(());
            }
        }
        out.push_str(std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| ())?);
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, ()> {
        let digits = self.bytes.get(self.at..self.at + 4).ok_or(())?;
        let mut n = 0u32;
        for &d in digits {
            n = n * 16 + char::from(d).to_digit(16).ok_or(())?;
        }
        self.at += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, ()> {
        self.eat(b'"')?;
        let mut raw: Vec<u8> = Vec::new();
        loop {
            let byte = self.peek().ok_or(())?;
            self.at += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let esc = self.peek().ok_or(())?;
                    self.at += 1;
                    let ch = match esc {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&first) {
                                self.eat(b'\\')?;
                                self.eat(b'u')?;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return Err(());
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else {
                                first
                            };
                            char::from_u32(code).ok_or(())?
                        }
                        _ => return Err(()),
                    };
                    let mut buf = [0u8; 4];
                    raw.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1f => return Err(()),
                other => raw.push(other),
            }
        }
        String::from_utf8(raw).map_err(|_| ())
    }

    fn array(&mut self, out: &mut String) -> Result<(), ()> {
        self.enter()?;
        self.eat(b'[')?;
        out.push('[');
        self.space();
        if self.peek() == Some(b']') {
            self.at += 1;
        } else {
            loop {
                self.value(out)?;
                self.space();
                match self.peek() {
                    Some(b',') => {
                        self.at += 1;
                        out.push(',');
                    }
                    Some(b']') => {
                        self.at += 1;
                        break;
                    }
                    _ => return Err(()),
                }
            }
        }
        out.push(']');
        self.depth -= 1;
        Ok(())
    }

    fn object(&mut self, out: &mut String) -> Result<(), ()> {
        self.enter()?;
        self.eat(b'{')?;
        let mut members: Vec<(String, String)> = Vec::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.at += 1;
        } else {
            loop {
                self.space();
                let name = self.string()?;
                self.space();
                self.eat(b':')?;
                let mut rendered = String::new();
                self.value(&mut rendered)?;
                members.push((name, rendered));
                self.space();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(b'}') => {
                        self.at += 1;
                        break;
                    }
                    _ => return Err(()),
                }
            }
        }
        members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if members.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(());
        }
        out.push('{');
        for (i, (name, rendered)) in members.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_string(out, name);
            out.push(':');
            out.push_str(rendered);
        }
        out.push('}');
        self.depth -= 1;
        Ok(())
    }

    fn enter(&mut self) -> Result<(), ()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(())
        } else {
            Ok(())
        }
    }
}

fn push_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let n = c as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX[n >> 4]));
                out.push(char::from(HEX[n & 15]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
