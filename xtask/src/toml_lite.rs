//! toml_lite — a deliberately small TOML-SUBSET reader, in the same spirit as
//! `scripts/construction-gate/rules.py::_read_cargo_deps`: it reads exactly the shapes this tool
//! needs (`[section]` and `[[array-of-tables]]` headers, `key = "scalar"`, `key = [ "a", "b", .. ]`
//! possibly spread across lines, `#` comments) and nothing else. It is not a TOML parser; it is a
//! reader for `qa/construction.toml`'s `[gate.plugin_kinds]` / `[rules.source-denylist]` tables and
//! for `qa/denylist-allow.toml`'s `[[allow]]` entries, both of which use only these shapes.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// One `[[section]]` array-of-tables entry, or the single `[section]` table: a flat map of
/// `key -> values` (a scalar is a one-element vec).
#[derive(Debug, Default, Clone)]
pub struct Table {
    pub values: BTreeMap<String, Vec<String>>,
    /// Every single-line `key = value` in FILE ORDER: the key unquoted, the value's raw text. For
    /// a reader whose rows are ordered (the dialect mapping files), where `values` is a sorted map.
    pub entries: Vec<(String, String)>,
}

impl Table {
    pub fn get_one(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    pub fn get_list(&self, key: &str) -> Vec<String> {
        self.values.get(key).cloned().unwrap_or_default()
    }
}

/// The whole file: every `[section.path]` table by its dotted name (last one wins, TOML-style),
/// plus every `[[section.path]]` array-of-tables entry, in file order, keyed the same way.
#[derive(Debug, Default)]
pub struct Document {
    pub tables: BTreeMap<String, Table>,
    pub array_tables: BTreeMap<String, Vec<Table>>,
    /// Every non-blank line the reader could not place — neither a table header, nor a
    /// `key = value`, nor the body of an open array or `"""` string — as `(1-based line, text)`.
    /// X-1206: these used to vanish, so a document this reader misread was indistinguishable from
    /// one it read whole. [`parse_text_checked`] refuses a document that has any.
    pub unread: Vec<(usize, String)>,
}

impl Document {
    pub fn table(&self, path: &str) -> Table {
        self.tables.get(path).cloned().unwrap_or_default()
    }

    pub fn array_table(&self, path: &str) -> Vec<Table> {
        self.array_tables.get(path).cloned().unwrap_or_default()
    }
}

fn strip_comment(line: &str) -> &str {
    // No string literal in either file this reader targets contains a `#`, so a plain scan is
    // enough — the same "deliberately small" trade the ported Python parser makes.
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn unquote(tok: &str) -> String {
    let t = tok.trim();
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn split_array_items(body: &str) -> Vec<String> {
    body.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(unquote)
        .collect()
}

/// Parse the small subset described above. Panics are refusals: a document this tool cannot read
/// is a document it must not silently misread (same "an entry without both is a refusal" spirit
/// as the allow-list rule below).
pub fn parse(path: &Path) -> Document {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("toml_lite: cannot read {}: {e}", path.display()));
    parse_text(&raw)
}

/// [`parse_text`], refusing a document with any line it could not place (X-1206). The refusal
/// names the first lines, so the cause — a shape this subset does not read, or a stray line — is
/// visible where the old reader silently dropped it and every rule over the file read less than
/// the file said.
pub fn parse_text_checked(raw: &str) -> Result<Document, String> {
    let doc = parse_text(raw);
    if doc.unread.is_empty() {
        return Ok(doc);
    }
    let shown: Vec<String> = doc
        .unread
        .iter()
        .take(5)
        .map(|(n, l)| format!("line {n}: `{l}`"))
        .collect();
    Err(format!(
        "{} line(s) are neither a table header nor `key = value` nor inside an open array or \
         string, so this reader would drop them: {}",
        doc.unread.len(),
        shown.join("; ")
    ))
}

/// True when `line` closes an open multi-line array: a `]` OUTSIDE any quoted string. A `]` inside
/// a regex literal (`'[^<>]*'`) is the string's, not the array's — the bare `contains(']')` this
/// replaces closed `pattern_families` after its first item and dropped the rest of the array.
fn closes_array(line: &str) -> bool {
    let (mut quote, mut escaped) = (None::<char>, false);
    for c in line.chars() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == ']' => return true,
            None => {}
        }
    }
    false
}

/// The same parse over TEXT SOMEBODY ELSE READ. A gate reads its config through the `Ctx` so a
/// selftest can plant one with an overlay; [`parse`] reaches around that to `std::fs`, and a
/// document read from disk is the one document no plant can change.
pub fn parse_text(raw: &str) -> Document {
    let mut doc = Document::default();
    let mut cur_path: Option<String> = None;
    let mut cur_table = Table::default();
    let mut cur_is_array = false;

    // pending multi-line array collection: key name + accumulated raw body text
    let mut pending_key: Option<String> = None;
    let mut pending_buf = String::new();

    let flush_pending = |table: &mut Table, key: &Option<String>, buf: &str| {
        if let Some(k) = key {
            table.values.insert(k.clone(), split_array_items(buf));
        }
    };

    let commit_table = |doc: &mut Document, path: &Option<String>, is_array: bool, table: Table| {
        if let Some(p) = path {
            if is_array {
                doc.array_tables.entry(p.clone()).or_default().push(table);
            } else {
                doc.tables.insert(p.clone(), table);
            }
        }
    };

    // Inside the body of a `key = """ .. """` block whose closing delimiter has not been seen yet.
    let mut in_multiline_string = false;

    for (idx, raw_line) in raw.lines().enumerate() {
        if in_multiline_string {
            // Scanned on the RAW line, not the comment-stripped one: `#` inside prose is ordinary
            // text, and stripping from it would hide a closing delimiter that follows on the same
            // line and leave the parser swallowing the rest of the file.
            if raw_line.contains("\"\"\"") {
                in_multiline_string = false;
            }
            continue;
        }

        let line = strip_comment(raw_line);
        let trimmed = line.trim();

        if pending_key.is_some() {
            pending_buf.push(' ');
            pending_buf.push_str(trimmed);
            if closes_array(trimmed) {
                // `pending_buf` already excludes the opening `[` (sliced off when the array was
                // first opened), so only the closing `]` needs trimming here.
                let body = pending_buf
                    .rsplit_once(']')
                    .map_or("", |(before, _)| before);
                flush_pending(&mut cur_table, &pending_key, body);
                pending_key = None;
                pending_buf.clear();
            }
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("[[") && trimmed.ends_with("]]") {
            commit_table(
                &mut doc,
                &cur_path,
                cur_is_array,
                std::mem::take(&mut cur_table),
            );
            cur_path = Some(trimmed[2..trimmed.len() - 2].trim().to_string());
            cur_is_array = true;
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            commit_table(
                &mut doc,
                &cur_path,
                cur_is_array,
                std::mem::take(&mut cur_table),
            );
            cur_path = Some(trimmed[1..trimmed.len() - 1].trim().to_string());
            cur_is_array = false;
            continue;
        }

        // The key ends at the first `=` outside a quoted key: a dialect mapping row's quoted wire
        // path may itself hold `=` (a union arm, `messages[].content[].type=text.text`).
        let key_len = split_top(trimmed, '=').first().map_or(0, |k| k.len());
        if let Some((key, value)) =
            (key_len < trimmed.len()).then(|| (&trimmed[..key_len], &trimmed[key_len + 1..]))
        {
            let key = key.trim().to_string();
            let value = value.trim();
            if let Some(rest) = value.strip_prefix('[') {
                if let Some(body) = rest.strip_suffix(']') {
                    cur_table.values.insert(key, split_array_items(body));
                } else {
                    pending_key = Some(key);
                    pending_buf = rest.to_string();
                }
            } else if let Some(rest) = value.strip_prefix("\"\"\"") {
                // A triple-quoted `why =` prose field: this tool never reads the text, so it is
                // recorded as an opaque empty scalar. Its BODY still has to be consumed to the
                // closing delimiter, though — otherwise every prose line falls through to this
                // same `key = value` arm, and any sentence containing an `=` is recorded as a key
                // of the enclosing table. That silently invents settings the file never declared,
                // and a prose line reading `max_hits = 0` would be obeyed as configuration.
                cur_table.values.insert(key, vec![String::new()]);
                if !rest.contains("\"\"\"") {
                    in_multiline_string = true;
                }
            } else {
                cur_table.entries.push((unquote(&key), value.to_string()));
                cur_table.values.insert(key, vec![unquote(value)]);
            }
        } else {
            doc.unread.push((idx + 1, trimmed.to_string()));
        }
    }
    commit_table(&mut doc, &cur_path, cur_is_array, cur_table);
    doc
}

/// Split `body` on every `sep` that is outside a double-quoted string and outside `[..]` / `{..}`.
fn split_top(body: &str, sep: char) -> Vec<&str> {
    let (mut out, mut depth, mut in_str, mut escaped, mut start) =
        (Vec::new(), 0i32, false, false, 0);
    for (i, c) in body.char_indices() {
        if in_str {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            _ if c == sep && depth == 0 => {
                out.push(&body[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&body[start..]);
    out
}

/// An inline table `{ k = v, k2 = [a, b] }` as its `(key, raw value)` pairs in order (keys
/// unquoted, values trimmed raw text); `None` when `raw` is not one.
pub fn inline_table(raw: &str) -> Option<Vec<(String, String)>> {
    let body = raw.trim().strip_prefix('{')?.strip_suffix('}')?;
    split_top(body, ',')
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .map(|item| {
            let parts = split_top(item, '=');
            let (key, value) = (parts.first()?, item.get(parts.first()?.len() + 1..)?);
            Some((unquote(key), value.trim().to_string()))
        })
        .collect()
}

/// A raw scalar's text: a basic string unquoted with its `\"` and `\\` escapes undone; any other
/// scalar (a number, a bool) as written.
pub fn string_value(raw: &str) -> String {
    let t = raw.trim();
    match t.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => {
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                } else {
                    out.push(c);
                }
            }
            out
        }
        None => unquote(t),
    }
}

/// A raw single-line array `[a, "b"]` as its items' scalar texts.
pub fn array_items(raw: &str) -> Option<Vec<String>> {
    let body = raw.trim().strip_prefix('[')?.strip_suffix(']')?;
    Some(
        split_top(body, ',')
            .into_iter()
            .filter(|i| !i.trim().is_empty())
            .map(string_value)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `body` to a uniquely-named temp file and parse it.
    fn parse_str(tag: &str, body: &str) -> Document {
        let path = std::env::temp_dir().join(format!(
            "busbar-toml-lite-{tag}-{}.toml",
            std::process::id()
        ));
        fs::write(&path, body).expect("write temp toml");
        let doc = parse(&path);
        let _ = fs::remove_file(&path);
        doc
    }

    /// The prose inside a `"""` block is text, not configuration. A reader that records the block
    /// as an empty scalar and then keeps parsing its body line by line turns any sentence holding
    /// an `=` into a key of the enclosing table — so a `why` paragraph that happens to say
    /// `max_hits = 0` would be obeyed as a setting the file never declared. Nothing inside the
    /// block may reach the table, and the keys after the block must still be read normally.
    #[test]
    fn multiline_string_body_is_not_parsed_as_keys() {
        let doc = parse_str(
            "multiline",
            r#"
[rules.demo]
why = """This rule is here because a run that reports max_hits = 0 has
proven nothing at all. severity = "advisory" would be worse still.
patterns = [ 'not-a-pattern' ]"""
patterns = [ 'libc' ]
severity = "error"
"#,
        );
        let t = doc.table("rules.demo");

        assert_eq!(
            t.get_one("why"),
            Some(""),
            "the block itself should still be recorded as an opaque empty scalar"
        );
        assert_eq!(
            t.get_one("max_hits"),
            None,
            "a prose line inside the block was recorded as a key of the table"
        );
        assert_eq!(
            t.get_one("severity"),
            Some("error"),
            "the real key after the block must win over the one quoted inside its prose"
        );
        assert_eq!(
            t.get_list("patterns"),
            vec!["libc".to_string()],
            "the real `patterns` after the block must win over the one quoted inside its prose"
        );
    }

    /// A `"""` block opened and closed on ONE line must not put the reader into multi-line mode —
    /// doing so would swallow every key after it to the end of the file.
    #[test]
    fn single_line_triple_quoted_value_does_not_swallow_the_rest() {
        let doc = parse_str(
            "single-line",
            r#"
[rules.demo]
why = """short reason"""
patterns = [ 'libc' ]
"#,
        );
        let t = doc.table("rules.demo");
        assert_eq!(t.get_one("why"), Some(""));
        assert_eq!(t.get_list("patterns"), vec!["libc".to_string()]);
    }

    /// A `#` inside the prose is ordinary text. The closing-delimiter scan runs on the raw line
    /// precisely so a comment-strip cannot hide a `"""` that follows one.
    #[test]
    fn hash_before_the_closing_delimiter_still_closes_the_block() {
        let doc = parse_str(
            "hash",
            r#"
[rules.demo]
why = """a reason
mentioning #1 and then closing """
patterns = [ 'libc' ]
"#,
        );
        let t = doc.table("rules.demo");
        assert_eq!(t.get_list("patterns"), vec!["libc".to_string()]);
    }

    /// X-1206 RED: a line that is neither a header nor `key = value` is RECORDED and the checked
    /// reader refuses it, naming the line. Before, `parse_text` had no error path and the line
    /// simply vanished.
    #[test]
    fn a_line_the_reader_cannot_place_is_refused_not_dropped() {
        let raw = "[rules.demo]\nkinds = [\"a\"]\nthis line is not toml\n";
        let doc = parse_text(raw);
        assert_eq!(doc.unread, vec![(3, "this line is not toml".to_string())]);
        let err = parse_text_checked(raw).expect_err("refused");
        assert!(err.contains("line 3: `this line is not toml`"), "{err}");
        assert!(parse_text_checked("[a]\nk = \"v\"\n").is_ok());
    }

    /// The cause X-1206 hid in `qa/construction.toml`: a multi-line array whose items are regexes
    /// holding `]` was closed by the FIRST item, and every item after it was dropped unseen. The array
    /// now closes only on a `]` outside a string, and every item is read.
    #[test]
    fn a_bracket_inside_a_quoted_item_does_not_close_the_array() {
        let raw = "[rules.r]\npattern_families = [\n  '(?<![A-Za-z0-9_])Pass::<[^<>]*>::mint\\(',\n  \"Grant::<[^<>]*>::mint\",\n  'third',\n]\nafter = \"x\"\n";
        let doc = parse_text_checked(raw).expect("whole document read");
        let t = doc.table("rules.r");
        assert_eq!(t.get_list("pattern_families").len(), 3, "{:?}", t.values);
        assert_eq!(t.get_one("after"), Some("x"));
    }

    /// The committed configuration this reader serves is read WHOLE: no line of
    /// `qa/construction.toml` or `qa/denylist-allow.toml` is dropped.
    #[test]
    fn the_committed_denylist_inputs_are_read_whole() {
        let cx = crate::ctx::Ctx::workspace().expect("workspace context");
        for rel in ["qa/construction.toml", "qa/denylist-allow.toml"] {
            let text = cx.read(rel).expect(rel);
            if let Err(e) = parse_text_checked(&text) {
                panic!("{rel}: {e}");
            }
        }
    }
}
