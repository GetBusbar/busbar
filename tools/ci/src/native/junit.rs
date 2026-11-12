//! Nextest JUnit validation (former `native.validate_test_report`): a minimal
//! well-formedness-checking XML reader with ElementTree's element model.
use super::sp::{self, R, violation};
use std::path::Path;

#[derive(Debug, Default)]
pub struct Element {
    pub tag: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Element>,
}

impl Element {
    /// `element.iter()`: pre-order, the element itself first.
    pub fn iter(&self) -> Vec<&Element> {
        let mut out = vec![self];
        for child in &self.children {
            out.extend(child.iter());
        }
        out
    }
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> String {
        let before = &self.s[..self.i.min(self.s.len())];
        let line = before.iter().filter(|b| **b == b'\n').count() + 1;
        let column = match before.iter().rposition(|b| *b == b'\n') {
            Some(p) => self.i - p - 1,
            None => self.i,
        };
        format!("{message}: line {line}, column {column}")
    }
    fn starts(&self, text: &str) -> bool {
        self.s[self.i..].starts_with(text.as_bytes())
    }
    fn skip_ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }
    fn until(&mut self, end: &str, message: &str) -> Result<(), String> {
        match self.s[self.i..]
            .windows(end.len())
            .position(|w| w == end.as_bytes())
        {
            Some(p) => {
                self.i += p + end.len();
                Ok(())
            }
            None => {
                self.i = self.s.len();
                Err(self.error(message))
            }
        }
    }
    fn misc(&mut self) -> Result<(), String> {
        loop {
            self.skip_ws();
            if self.starts("<?") {
                self.until("?>", "unclosed token")?;
            } else if self.starts("<!--") {
                self.until("-->", "unclosed token")?;
            } else if self.starts("<!DOCTYPE") {
                self.until(">", "unclosed token")?;
            } else {
                return Ok(());
            }
        }
    }
    fn name(&mut self) -> Result<String, String> {
        let start = self.i;
        while self.i < self.s.len()
            && !matches!(
                self.s[self.i],
                b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>' | b'=' | b'<'
            )
        {
            self.i += 1;
        }
        let name = &self.s[start..self.i];
        let first_ok = name
            .first()
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_' || *c == b':' || *c >= 0x80);
        if !first_ok
            || !name
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"_:.-".contains(c) || *c >= 0x80)
        {
            self.i = start;
            return Err(self.error("not well-formed (invalid token)"));
        }
        Ok(String::from_utf8_lossy(name).into_owned())
    }
    fn entities(&self, raw: &[u8]) -> Result<String, String> {
        let text = String::from_utf8_lossy(raw);
        let mut out = String::new();
        let mut rest = text.as_ref();
        while let Some(at) = rest.find('&') {
            out.push_str(&rest[..at]);
            let tail = &rest[at + 1..];
            let end = tail
                .find(';')
                .ok_or_else(|| self.error("not well-formed (invalid token)"))?;
            let entity = &tail[..end];
            let value = match entity {
                "lt" => '<',
                "gt" => '>',
                "amp" => '&',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let code = if let Some(hex) = entity.strip_prefix("#x") {
                        u32::from_str_radix(hex, 16).ok()
                    } else if let Some(decimal) = entity.strip_prefix('#') {
                        decimal.parse().ok()
                    } else {
                        return Err(self.error("undefined entity"));
                    };
                    code.and_then(char::from_u32)
                        .ok_or_else(|| self.error("reference to invalid character number"))?
                }
            };
            out.push(value);
            rest = &tail[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }
    fn element(&mut self, depth: usize) -> Result<Element, String> {
        if depth > 10_000 {
            return Err(self.error("excessive nesting"));
        }
        self.i += 1; // '<'
        let tag = self.name()?;
        let mut element = Element {
            tag: tag.clone(),
            ..Default::default()
        };
        loop {
            self.skip_ws();
            match self.s.get(self.i) {
                Some(b'/') => {
                    if self.s.get(self.i + 1) != Some(&b'>') {
                        return Err(self.error("not well-formed (invalid token)"));
                    }
                    self.i += 2;
                    return Ok(element);
                }
                Some(b'>') => {
                    self.i += 1;
                    break;
                }
                Some(_) => {
                    let attribute_at = self.i;
                    let name = self.name()?;
                    self.skip_ws();
                    if self.s.get(self.i) != Some(&b'=') {
                        return Err(self.error("not well-formed (invalid token)"));
                    }
                    self.i += 1;
                    self.skip_ws();
                    let quote = match self.s.get(self.i) {
                        Some(q @ (b'"' | b'\'')) => *q,
                        _ => return Err(self.error("not well-formed (invalid token)")),
                    };
                    self.i += 1;
                    let start = self.i;
                    while self.i < self.s.len() && self.s[self.i] != quote {
                        if self.s[self.i] == b'<' {
                            return Err(self.error("not well-formed (invalid token)"));
                        }
                        self.i += 1;
                    }
                    if self.i >= self.s.len() {
                        return Err(self.error("unclosed token"));
                    }
                    let value = self.entities(&self.s[start..self.i])?;
                    self.i += 1;
                    if element.attributes.iter().any(|(k, _)| *k == name) {
                        self.i = attribute_at;
                        return Err(self.error("duplicate attribute"));
                    }
                    element.attributes.push((name, value));
                }
                None => return Err(self.error("unclosed token")),
            }
        }
        loop {
            let start = self.i;
            while self.i < self.s.len() && self.s[self.i] != b'<' {
                self.i += 1;
            }
            self.entities(&self.s[start..self.i])?;
            if self.i >= self.s.len() {
                return Err(self.error("no element found"));
            }
            if self.starts("</") {
                self.i += 2;
                let at = self.i;
                let close = self.name()?;
                self.skip_ws();
                if close != tag || self.s.get(self.i) != Some(&b'>') {
                    self.i = at;
                    return Err(self.error("mismatched tag"));
                }
                self.i += 1;
                return Ok(element);
            } else if self.starts("<!--") {
                self.until("-->", "unclosed token")?;
            } else if self.starts("<![CDATA[") {
                self.until("]]>", "unclosed CDATA section")?;
            } else if self.starts("<?") {
                self.until("?>", "unclosed token")?;
            } else {
                element.children.push(self.element(depth + 1)?);
            }
        }
    }
}

pub fn parse(data: &[u8]) -> Result<Element, String> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    if std::str::from_utf8(data).is_err() {
        return Err("not well-formed (invalid token): line 1, column 0".into());
    }
    let mut parser = Parser { s: data, i: 0 };
    parser.misc()?;
    if parser.i >= data.len() {
        return Err(parser.error("no element found"));
    }
    if data[parser.i] != b'<' {
        return Err(parser.error("syntax error"));
    }
    let root = parser.element(0)?;
    parser.misc()?;
    if parser.i < data.len() {
        return Err(parser.error("junk after document element"));
    }
    Ok(root)
}

const FAILURES: [&str; 6] = [
    "failure",
    "error",
    "rerunFailure",
    "rerunError",
    "flakyFailure",
    "flakyError",
];

fn check(root: &Element) -> Result<(), String> {
    let all = root.iter();
    let cases: Vec<&&Element> = all.iter().filter(|e| e.tag == "testcase").collect();
    if !matches!(root.tag.as_str(), "testsuites" | "testsuite") || cases.is_empty() {
        return Err("empty or unrecognized JUnit report".into());
    }
    for element in &all {
        if FAILURES.contains(&element.tag.as_str()) {
            return Err("reported test failure".into());
        }
        for attribute in ["failures", "errors"] {
            if let Some(value) = element.attribute(attribute)
                && sp::py_int(value).map_err(|e| e.message)? != 0
            {
                return Err("nonzero failure/error count".into());
            }
        }
    }
    if cases
        .iter()
        .all(|case| case.children.iter().any(|c| c.tag == "skipped"))
    {
        return Err("no executed test cases".into());
    }
    Ok(())
}

/// `validate_test_report(path)`: a successful exit cannot contradict a failing report.
pub fn validate_test_report(path: &Path) -> R<()> {
    let outcome = std::fs::read(path)
        .map_err(|e| sp::os_error(&e, Some(path)).message)
        .and_then(|data| parse(&data))
        .and_then(|root| check(&root));
    outcome.map_err(|message| violation(format!("native test report is not passing: {message}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(xml: &str) -> Result<(), String> {
        parse(xml.as_bytes()).and_then(|root| check(&root))
    }

    #[test]
    fn report_must_execute_and_pass() {
        let pass = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="2" failures="0" errors="0"><testsuite name="a" tests="2" failures="0">
<testcase name="x &amp; y" classname="a"/><testcase name="z"><system-out><![CDATA[<ok>]]></system-out></testcase>
</testsuite></testsuites>"#;
        assert_eq!(verdict(pass), Ok(()));
        assert_eq!(
            verdict(&pass.replace(
                "<testcase name=\"z\">",
                "<testcase name=\"z\"><failure message=\"boom\"/>"
            )),
            Err("reported test failure".into())
        );
        assert_eq!(
            verdict(&pass.replace("failures=\"0\" errors", "failures=\"1\" errors")),
            Err("nonzero failure/error count".into())
        );
        assert_eq!(
            verdict(&pass.replace("failures=\"0\" errors", "failures=\"x\" errors")),
            Err("invalid literal for int() with base 10: 'x'".into())
        );
        assert_eq!(
            verdict("<testsuites><testsuite/></testsuites>"),
            Err("empty or unrecognized JUnit report".into())
        );
        assert_eq!(
            verdict("<testsuite><testcase><skipped/></testcase></testsuite>"),
            Err("no executed test cases".into())
        );
        assert_eq!(
            verdict(""),
            Err("no element found: line 1, column 0".into())
        );
        assert_eq!(
            verdict("<a><b></a>"),
            Err("mismatched tag: line 1, column 8".into())
        );
        assert_eq!(
            verdict("<testsuite/><x/>"),
            Err("junk after document element: line 1, column 12".into())
        );
        assert_eq!(
            verdict("<a b=\"1\" b=\"2\"/>"),
            Err("duplicate attribute: line 1, column 9".into())
        );
    }
}
