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

    for raw_line in raw.lines() {
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
            if trimmed.contains(']') {
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

        if let Some((key, value)) = trimmed.split_once('=') {
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
                cur_table.values.insert(key, vec![unquote(value)]);
            }
        }
    }
    commit_table(&mut doc, &cur_path, cur_is_array, cur_table);
    doc
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
}
