//! `toml_doc` — an ORDER-PRESERVING reader for `qa/construction.toml`.
//!
//! This is not a second copy of [`crate::toml_lite`]. That reader answers "what does this key say",
//! which is all `qa/denylist-allow.toml` and the plugin-kind globs ever needed, and it answers it
//! out of a `BTreeMap` — alphabetically. The construction ceilings file needs one thing more:
//! **the order the owner wrote the tables in is part of the rule.**
//!
//! Three of the ported rules join their sub-tables into one detail column —
//! `[rules.hold-escapes.symbols.*]`, `[rules.seal-sites.symbols.*]`,
//! `[rules.sealed-unit-traits.traits.*]` — and a reader that hands them back sorted produces a row
//! whose text differs from the Python's for no reason that is about the tree. That is precisely the
//! class of difference `xtask/src/parity.rs` exists to refuse, so it is refused here instead: a
//! table remembers its declaration order and its keys remember theirs.
//!
//! It is also a REAL value parser rather than a comma-split: `qa/construction.toml` carries literal
//! strings whose contents are regular expressions (`'\.client\(\)\.get\(\)\.request\('`), basic
//! strings with escapes (`"ARCHITECTURE\\.md §"`), quoted keys that are file paths, integers,
//! booleans, arrays spread over lines with trailing commas, and `"""` prose blocks. Reading a regex
//! through an unescaping parser, or an escaped string through a literal one, silently changes the
//! rule; so each string form is read as its own form.

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
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
            Value::Array(v) => Some(v),
            _ => None,
        }
    }
}

/// One `[table]`: its key/value pairs, and the ORDER they were written in.
#[derive(Debug, Clone, Default)]
pub struct Table {
    order: Vec<String>,
    values: BTreeMap<String, Value>,
}

impl Table {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.values.get(key)
    }

    /// Every key in declaration order.
    pub fn keys(&self) -> &[String] {
        &self.order
    }

    fn insert(&mut self, key: String, value: Value) {
        if !self.values.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.values.insert(key, value);
    }

    pub fn str_of(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }

    pub fn int_of(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(Value::as_int)
    }

    pub fn bool_of(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(Value::as_bool)
    }

    /// A `key = [ "a", "b" ]` list. A key that is absent is an empty list; a key that is present
    /// but is not an array of strings is a refusal, because a rule reading an empty list where the
    /// file wrote something else scans nothing and reports clean.
    pub fn list_of(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| panic!("toml_doc: `{key}` holds a non-string item"))
                        .to_string()
                })
                .collect(),
            Some(_) => panic!("toml_doc: `{key}` is not an array"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Document {
    order: Vec<String>,
    tables: BTreeMap<String, Table>,
    /// `[[name]]` -> how many were written. An entry is registered under `name.<i>`.
    arrays: BTreeMap<String, usize>,
}

impl Document {
    pub fn table(&self, path: &str) -> Option<&Table> {
        self.tables.get(path)
    }

    /// The table at `path`, or an empty one. Used where the ported Python does `cfg.get(k, {})`.
    pub fn table_or_empty(&self, path: &str) -> Table {
        self.tables.get(path).cloned().unwrap_or_default()
    }

    /// The DIRECT sub-tables of `path`, each with its last path segment, in declaration order —
    /// the whole reason this reader exists.
    pub fn children(&self, path: &str) -> Vec<(String, &Table)> {
        let prefix = format!("{path}.");
        self.order
            .iter()
            .filter_map(|p| {
                let rest = p.strip_prefix(&prefix)?;
                if rest.contains('.') {
                    return None;
                }
                Some((rest.to_string(), self.tables.get(p)?))
            })
            .collect()
    }

    /// EVERY table in the document, in declaration order, each under its full dotted path (the
    /// root table's path is the empty string). [`Document::descendants`] cannot answer this: its
    /// prefix is `"<path>."`, so an empty `path` asks for tables whose name starts with a dot and
    /// finds none. A rule about the SHAPE of a ceilings file — every integer in it, wherever it
    /// sits — needs the whole document rather than one subtree of it.
    pub fn tables(&self) -> Vec<(&str, &Table)> {
        self.order
            .iter()
            .filter_map(|p| Some((p.as_str(), self.tables.get(p)?)))
            .collect()
    }

    /// How many `[[path]]` entries the document carries.
    pub fn array_len(&self, path: &str) -> usize {
        self.arrays.get(path).copied().unwrap_or(0)
    }

    /// Every `[[path]]` entry, in the order they were written.
    ///
    /// A caller that reached for `children(path)` instead would get the same tables today and
    /// would silently start reading `[path.something]` sub-tables the day one was written, so the
    /// array accessor is separate from the sub-table one.
    pub fn array_of_tables(&self, path: &str) -> Vec<&Table> {
        (0..self.array_len(path))
            .filter_map(|i| self.tables.get(&format!("{path}.{i}")))
            .collect()
    }

    fn table_mut(&mut self, path: &str) -> &mut Table {
        if !self.tables.contains_key(path) {
            self.order.push(path.to_string());
            self.tables.insert(path.to_string(), Table::default());
        }
        self.tables.get_mut(path).expect("just inserted")
    }
}

struct Scanner<'a> {
    src: &'a [u8],
    i: usize,
}

impl<'a> Scanner<'a> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.i).copied()
    }

    fn starts_with(&self, s: &str) -> bool {
        self.src[self.i..].starts_with(s.as_bytes())
    }

    fn err<T>(&self, msg: &str) -> Result<T, String> {
        let line = self.src[..self.i].iter().filter(|b| **b == b'\n').count() + 1;
        Err(format!("toml_doc: {msg} (line {line})"))
    }

    /// Whitespace, newlines and comments — everything between two things that mean something.
    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') => self.i += 1,
                Some(b'#') => {
                    while self.peek().is_some_and(|b| b != b'\n') {
                        self.i += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn skip_inline_space(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t') | Some(b'\r')) {
            self.i += 1;
        }
    }

    /// A bare or quoted key, or a dotted run of them.
    fn key_path(&mut self) -> Result<Vec<String>, String> {
        let mut parts = Vec::new();
        loop {
            self.skip_inline_space();
            let part = match self.peek() {
                Some(b'"') | Some(b'\'') => self.string()?,
                _ => {
                    let start = self.i;
                    while self
                        .peek()
                        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    {
                        self.i += 1;
                    }
                    if self.i == start {
                        return self.err("expected a key");
                    }
                    String::from_utf8_lossy(&self.src[start..self.i]).into_owned()
                }
            };
            parts.push(part);
            self.skip_inline_space();
            if self.peek() == Some(b'.') {
                self.i += 1;
                continue;
            }
            return Ok(parts);
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.starts_with("\"\"\"") {
            self.i += 3;
            let start = self.i;
            while self.i < self.src.len() && !self.starts_with("\"\"\"") {
                self.i += 1;
            }
            if self.i >= self.src.len() {
                return self.err("unterminated multi-line basic string");
            }
            let body = String::from_utf8_lossy(&self.src[start..self.i]).into_owned();
            self.i += 3;
            return Ok(unescape_basic(&body));
        }
        if self.starts_with("'''") {
            self.i += 3;
            let start = self.i;
            while self.i < self.src.len() && !self.starts_with("'''") {
                self.i += 1;
            }
            if self.i >= self.src.len() {
                return self.err("unterminated multi-line literal string");
            }
            let body = String::from_utf8_lossy(&self.src[start..self.i]).into_owned();
            self.i += 3;
            return Ok(body);
        }
        match self.peek() {
            Some(b'\'') => {
                // A LITERAL string: no escape processing at all, which is the whole reason the
                // ceilings file spells its regular expressions this way.
                self.i += 1;
                let start = self.i;
                while self.peek().is_some_and(|b| b != b'\'') {
                    self.i += 1;
                }
                if self.peek().is_none() {
                    return self.err("unterminated literal string");
                }
                let body = String::from_utf8_lossy(&self.src[start..self.i]).into_owned();
                self.i += 1;
                Ok(body)
            }
            Some(b'"') => {
                self.i += 1;
                let start = self.i;
                while let Some(b) = self.peek() {
                    if b == b'\\' {
                        self.i += 2;
                        continue;
                    }
                    if b == b'"' {
                        break;
                    }
                    self.i += 1;
                }
                if self.peek().is_none() {
                    return self.err("unterminated basic string");
                }
                let body = String::from_utf8_lossy(&self.src[start..self.i]).into_owned();
                self.i += 1;
                Ok(unescape_basic(&body))
            }
            _ => self.err("expected a string"),
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        self.skip_inline_space();
        match self.peek() {
            Some(b'"') | Some(b'\'') => Ok(Value::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_trivia();
                    if self.peek() == Some(b']') {
                        self.i += 1;
                        return Ok(Value::Array(items));
                    }
                    if self.peek().is_none() {
                        return self.err("unterminated array");
                    }
                    items.push(self.value()?);
                    self.skip_trivia();
                    if self.peek() == Some(b',') {
                        self.i += 1;
                    }
                }
            }
            Some(b'{') => self.err("inline tables are not a shape this reader accepts"),
            _ => {
                let start = self.i;
                while self
                    .peek()
                    .is_some_and(|b| !matches!(b, b',' | b']' | b'\n' | b'#'))
                {
                    self.i += 1;
                }
                let tok = String::from_utf8_lossy(&self.src[start..self.i])
                    .trim()
                    .to_string();
                match tok.as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    _ => match tok.replace('_', "").parse::<i64>() {
                        Ok(n) => Ok(Value::Int(n)),
                        Err(_) => self.err(&format!("`{tok}` is not a value this reader accepts")),
                    },
                }
            }
        }
    }
}

fn unescape_basic(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut it = body.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Read a document, refusing anything the reader does not understand. A ceilings file this cannot
/// read must not be half-read: a rule whose threshold silently went missing scans against a
/// default nobody wrote down.
pub fn parse_str(text: &str) -> Result<Document, String> {
    let mut sc = Scanner {
        src: text.as_bytes(),
        i: 0,
    };
    let mut doc = Document::default();
    let mut cur = String::new();
    doc.table_mut("");

    loop {
        sc.skip_trivia();
        let Some(b) = sc.peek() else {
            return Ok(doc);
        };
        if b == b'[' {
            sc.i += 1;
            // AN ARRAY OF TABLES IS A REPEATED HEADER, and it is read as one: `[[registered]]`
            // written three times registers `registered.0`, `registered.1`, `registered.2`. The
            // reader refused the shape entirely until `qa/kind-isolation.toml` needed it —
            // `docs/design/PLUGIN-TREE.md` cites `[[registered]]` rows as the mechanism that names
            // a crate's kind ahead of its rename, and a document cannot be normative about a shape
            // the only reader of it will not parse.
            let array = sc.peek() == Some(b'[');
            if array {
                sc.i += 1;
            }
            let parts = sc.key_path()?;
            sc.skip_inline_space();
            if sc.peek() != Some(b']') {
                return sc.err("unterminated table header");
            }
            sc.i += 1;
            if array {
                if sc.peek() != Some(b']') {
                    return sc
                        .err("an array-of-tables header opened with `[[` and closed with `]`");
                }
                sc.i += 1;
                let base = parts.join(".");
                let n = doc.array_len(&base);
                doc.arrays.insert(base.clone(), n + 1);
                cur = format!("{base}.{n}");
            } else {
                cur = parts.join(".");
            }
            doc.table_mut(&cur);
            continue;
        }
        let parts = sc.key_path()?;
        sc.skip_inline_space();
        if sc.peek() != Some(b'=') {
            return sc.err("expected `=` after a key");
        }
        sc.i += 1;
        let value = sc.value()?;
        // A dotted key writes into a nested table, exactly as TOML says.
        let (leaf, prefix) = parts
            .split_last()
            .expect("key_path yields at least one part");
        let path = if prefix.is_empty() {
            cur.clone()
        } else if cur.is_empty() {
            prefix.join(".")
        } else {
            format!("{cur}.{}", prefix.join("."))
        };
        doc.table_mut(&path).insert(leaf.clone(), value);
    }
}

pub fn parse(path: &Path) -> Result<Document, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("toml_doc: {}: {e}", path.display()))?;
    parse_str(&text)
}

#[cfg(test)]
mod tests {
    /// `[[registered]]` is a repeated header, and it is read as one entry per repetition rather
    /// than as one table the last repetition wins. Reading it the other way would make a file with
    /// three registrations describe one.
    #[test]
    fn an_array_of_tables_is_one_entry_per_repetition() {
        let doc =
            super::parse_str("[[registered]]\ncrate = \"a\"\n\n[[registered]]\ncrate = \"b\"\n")
                .expect("the fixture parses");
        assert_eq!(doc.array_len("registered"), 2);
        let rows: Vec<&str> = doc
            .array_of_tables("registered")
            .iter()
            .filter_map(|t| t.str_of("crate"))
            .collect();
        assert_eq!(rows, vec!["a", "b"]);
    }

    #[test]
    fn a_header_that_opens_with_two_brackets_must_close_with_two() {
        assert!(super::parse_str("[[registered]\n").is_err());
    }

    use super::*;

    /// The property this reader exists for: sub-tables come back in the order the owner wrote
    /// them, because three rules join them into one sentence and a sorted reading rewrites it.
    #[test]
    fn sub_tables_keep_their_declaration_order() {
        let doc = parse_str(
            r#"
[rules.hold-escapes.symbols.forget]
symbol = "mem::forget"
[rules.hold-escapes.symbols.manually-drop]
symbol = "ManuallyDrop"
[rules.hold-escapes.symbols.box-leak]
symbol = "Box::leak"
"#,
        )
        .expect("parses");
        let names: Vec<String> = doc
            .children("rules.hold-escapes.symbols")
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(names, vec!["forget", "manually-drop", "box-leak"]);
    }

    /// A literal string is a regular expression; a basic string carries escapes. Reading either
    /// through the other's rules changes the rule the file states.
    #[test]
    fn literal_and_basic_strings_are_read_as_their_own_form() {
        let doc = parse_str(
            r#"
[rules.demo]
send_verb = '\.client\(\)\.get\(\)\.request\('
patterns = ["PB-[0-9]", "ARCHITECTURE\\.md §"]
"#,
        )
        .expect("parses");
        let t = doc.table("rules.demo").expect("table");
        assert_eq!(
            t.str_of("send_verb"),
            Some(r"\.client\(\)\.get\(\)\.request\(")
        );
        assert_eq!(
            t.list_of("patterns"),
            vec!["PB-[0-9]".to_string(), r"ARCHITECTURE\.md §".to_string()]
        );
    }

    /// A `"""` prose block is prose. A reader that falls out of it mid-paragraph obeys any
    /// sentence containing an `=` as configuration — the same fault `toml_lite`'s own tests pin.
    #[test]
    fn prose_blocks_are_consumed_whole() {
        let doc = parse_str(
            r#"
[rules.demo]
why = """A rule that reports max_hits = 0 over nothing
has proven nothing. severity = "advisory" is worse."""
max_hits = 21
informational = true
"#,
        )
        .expect("parses");
        let t = doc.table("rules.demo").expect("table");
        assert_eq!(t.int_of("max_hits"), Some(21));
        assert_eq!(t.bool_of("informational"), Some(true));
        assert_eq!(t.str_of("severity"), None);
    }

    #[test]
    fn quoted_keys_arrays_and_trailing_commas() {
        let doc = parse_str(
            r#"
[rules.plane-no-money.allowlist]
"crates/busbar-llm/src/unit/verify.rs" = ["CostHandle", "priced"]

[rules.demo]
forbidden = [
  "Pricer::flat(",
  "AuthChain::new(Vec::new()",   # a stand-in
  "NullShipper",
]
"#,
        )
        .expect("parses");
        assert_eq!(
            doc.table("rules.plane-no-money.allowlist")
                .expect("table")
                .list_of("crates/busbar-llm/src/unit/verify.rs"),
            vec!["CostHandle".to_string(), "priced".to_string()]
        );
        assert_eq!(
            doc.table("rules.demo").expect("table").list_of("forbidden"),
            vec![
                "Pricer::flat(".to_string(),
                "AuthChain::new(Vec::new()".to_string(),
                "NullShipper".to_string()
            ]
        );
    }

    /// The real file, read whole: a reader that cannot is a gate that cannot run.
    #[test]
    fn the_committed_ceilings_file_parses() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("qa/construction.toml");
        let doc = parse(&root).expect("qa/construction.toml parses");
        assert_eq!(
            doc.table("gate")
                .expect("gate table")
                .list_of("plane_crates"),
            vec!["busbar-llm", "busbar-mcp", "busbar-a2a", "busbar-voice"]
        );
        assert_eq!(
            doc.children("rules.loc-ceilings.kernel_files")
                .first()
                .map(|(k, _)| k.as_str()),
            Some("teller"),
            "the kernel file split is read in the owner's order, not alphabetically"
        );
    }
}
