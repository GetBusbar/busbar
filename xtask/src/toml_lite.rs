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
        self.values.get(key).and_then(|v| v.first()).map(|s| s.as_str())
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

    for raw_line in raw.lines() {
        let line = strip_comment(raw_line);
        let trimmed = line.trim();

        if pending_key.is_some() {
            pending_buf.push(' ');
            pending_buf.push_str(trimmed);
            if trimmed.contains(']') {
                // `pending_buf` already excludes the opening `[` (sliced off when the array was
                // first opened), so only the closing `]` needs trimming here.
                let body = pending_buf.rsplit_once(']').map_or("", |(before, _)| before);
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
            commit_table(&mut doc, &cur_path, cur_is_array, std::mem::take(&mut cur_table));
            cur_path = Some(trimmed[2..trimmed.len() - 2].trim().to_string());
            cur_is_array = true;
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            commit_table(&mut doc, &cur_path, cur_is_array, std::mem::take(&mut cur_table));
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
            } else if value.starts_with("\"\"\"") {
                // A triple-quoted `why =` prose field: this tool never reads one, so it is
                // dropped as a single-line opaque scalar rather than taught to span lines.
                cur_table.values.insert(key, vec![String::new()]);
            } else {
                cur_table.values.insert(key, vec![unquote(value)]);
            }
        }
    }
    commit_table(&mut doc, &cur_path, cur_is_array, cur_table);
    doc
}
