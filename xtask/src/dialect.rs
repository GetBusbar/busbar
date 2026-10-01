//! `cargo xtask dialect compile`: THE DIALECT MAPPING COMPILER.
//!
//! Each LLM dialect states its wire <> IR mapping by hand in
//! `crates/busbar-plane-llm/dialects/<d>.toml`. This compiles every such file into the committed
//! `crates/busbar-plane-llm/src/codec/<d>/map.gen.rs`: `const` tables of the plane's own mapping
//! types (`codec::carry::{Field, Slot, Codec, Hook, Word, Dir}`), so nothing is parsed at run time.
//! The `dialect-map` gate ([`crate::gates::dialect_map`]) runs the same compile and refuses a
//! committed file that differs from it.
//!
//! The file format (stage 0: flat request rows and word tables), read through [`crate::toml_lite`]:
//!
//! * `[dialect] request = ["<group>", "<other dialect>.<group>", ..]`: the request row groups,
//!   walked in order;
//! * `[rows.<group>]`: one row per line, `"<wire path>" = { ir = "<slot>" [, words = "<table>"]
//!   [, hook = "<hook>"] }`, the path in inventory notation (`a.b`), the slot and hook in snake
//!   case, resolved against the plane's one registry (`Slot`, `Hook`) when the table compiles;
//! * `[words.<table>]`: `base = "<table>"` (its rows come first), then one row per line,
//!   `"<ir word>" = { wire = "<word>" [, dir = "read" | "write"] }`.

use crate::ctx::{Ctx, WalkSpec};
use crate::toml_lite;
use std::collections::BTreeSet;

/// Where the hand-written mapping files live.
pub const DIALECT_DIR: &str = "crates/busbar-plane-llm/dialects";

/// The generated table file for dialect `name`.
pub fn gen_path(name: &str) -> String {
    format!("crates/busbar-plane-llm/src/codec/{name}/map.gen.rs")
}

/// One compiled dialect: its mapping file, its table file and the table file's fresh text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub source: String,
    pub target: String,
    pub text: String,
}

/// One parsed mapping file.
struct Dialect {
    name: String,
    doc: toml_lite::Document,
}

/// `snake_case` -> `CamelCase` (a registry name -> its Rust variant).
fn camel(snake: &str) -> String {
    snake
        .split('_')
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// A Rust string literal for `s`.
fn lit(s: &str) -> String {
    format!("{s:?}")
}

/// The const naming `kind` table `name` of `dialect`, as seen from `from`'s table file.
fn const_ref(from: &str, dialect: &str, kind: &str, name: &str) -> String {
    let c = format!("{kind}_{}", name.to_ascii_uppercase());
    if from == dialect {
        c
    } else {
        format!("crate::codec::{dialect}::map::{c}")
    }
}

/// `"<dialect>.<name>"` or `"<name>"` (this dialect) -> (dialect, name).
fn qualified(this: &str, reference: &str) -> (String, String) {
    let (d, n) = reference.split_once('.').unwrap_or((this, reference));
    (d.to_string(), n.to_string())
}

/// The inline-table fields of one row, or an error naming the file and row.
fn row_fields(source: &str, key: &str, raw: &str) -> Result<Vec<(String, String)>, String> {
    toml_lite::inline_table(raw)
        .ok_or_else(|| format!("{source}: row \"{key}\" is not an inline table: {raw}"))
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Every word row of table `name` in `dialect`, its `base` table's rows first.
fn word_rows(
    all: &[Dialect],
    dialect: &str,
    name: &str,
    depth: usize,
) -> Result<Vec<(String, String, String)>, String> {
    let d = all
        .iter()
        .find(|d| d.name == dialect)
        .ok_or_else(|| format!("word table {dialect}.{name}: no dialect {dialect}"))?;
    let path = format!("words.{name}");
    let table = d
        .doc
        .tables
        .get(&path)
        .ok_or_else(|| format!("{dialect}.toml: no [{path}]"))?;
    if depth > 4 {
        return Err(format!("{dialect}.toml: [{path}] base chain is too deep"));
    }
    let mut out = Vec::new();
    for (key, raw) in &table.entries {
        if key == "base" {
            let (bd, bn) = qualified(dialect, &toml_lite::string_value(raw));
            out.extend(word_rows(all, &bd, &bn, depth + 1)?);
            continue;
        }
        let f = row_fields(&format!("{dialect}.toml"), key, raw)?;
        let wire = field(&f, "wire")
            .map(toml_lite::string_value)
            .ok_or_else(|| format!("{dialect}.toml: [{path}] \"{key}\" has no wire word"))?;
        let dir = match field(&f, "dir").map(toml_lite::string_value).as_deref() {
            None => "Both",
            Some("read") => "Read",
            Some("write") => "Write",
            Some(other) => {
                return Err(format!(
                    "{dialect}.toml: [{path}] \"{key}\": dir \"{other}\" is not read or write"
                ))
            }
        };
        out.push((wire, key.clone(), dir.to_string()));
    }
    Ok(out)
}

/// Compile one dialect's table file text.
fn compile_one(all: &[Dialect], d: &Dialect) -> Result<String, String> {
    let source = format!("{DIALECT_DIR}/{}.toml", d.name);
    let mut uses: BTreeSet<&str> = BTreeSet::new();
    let mut body = String::new();

    // The row groups this file declares, in name order.
    let groups: Vec<&String> = d
        .doc
        .tables
        .keys()
        .filter(|k| k.starts_with("rows."))
        .collect();
    for path in &groups {
        let name = &path["rows.".len()..];
        let table = &d.doc.tables[*path];
        body.push_str(&format!(
            "\n/// Row group `{name}`.\npub(crate) const ROWS_{}: &[Field] = &[\n",
            name.to_ascii_uppercase()
        ));
        uses.insert("Field");
        uses.insert("Slot");
        uses.insert("row");
        for (key, raw) in &table.entries {
            let f = row_fields(&source, key, raw)?;
            let slot = field(&f, "ir")
                .map(toml_lite::string_value)
                .ok_or_else(|| format!("{source}: [{path}] \"{key}\" names no ir slot"))?;
            let codec = match (field(&f, "words"), field(&f, "hook")) {
                (None, None) => "Codec::Plain".to_string(),
                (Some(w), None) => {
                    let (wd, wn) = qualified(&d.name, &toml_lite::string_value(w));
                    format!("Codec::Words({})", const_ref(&d.name, &wd, "WORDS", &wn))
                }
                (None, Some(h)) => {
                    uses.insert("Hook");
                    format!("Codec::Hook(Hook::{})", camel(&toml_lite::string_value(h)))
                }
                (Some(_), Some(_)) => {
                    return Err(format!("{source}: [{path}] \"{key}\" names both words and a hook"))
                }
            };
            uses.insert("Codec");
            for (k, _) in &f {
                if !["ir", "words", "hook"].contains(&k.as_str()) {
                    return Err(format!("{source}: [{path}] \"{key}\": unknown modifier `{k}`"));
                }
            }
            let segs: Vec<String> = key.split('.').map(lit).collect();
            body.push_str(&format!(
                "    row(&[{}], Slot::{}, {codec}),\n",
                segs.join(", "),
                camel(&slot)
            ));
        }
        body.push_str("];\n");
    }

    // The request table.
    let dialect_t = d.doc.table("dialect");
    if dialect_t.values.contains_key("request") {
        uses.insert("Table");
        let refs: Vec<String> = dialect_t
            .get_list("request")
            .iter()
            .map(|g| {
                let (gd, gn) = qualified(&d.name, g);
                const_ref(&d.name, &gd, "ROWS", &gn)
            })
            .collect();
        body.push_str(&format!(
            "\n/// The request table, walked in order.\npub(crate) const REQUEST: Table = &[{}];\n",
            refs.join(", ")
        ));
    }

    // The word tables, in name order.
    for path in d.doc.tables.keys().filter(|k| k.starts_with("words.")) {
        let name = &path["words.".len()..];
        uses.insert("Word");
        uses.insert("Dir");
        body.push_str(&format!(
            "\n/// Word table `{name}`: (wire word, IR word, direction).\npub(crate) const WORDS_{}: &[Word] = &[\n",
            name.to_ascii_uppercase()
        ));
        for (wire, ir, dir) in word_rows(all, &d.name, name, 0)? {
            body.push_str(&format!("    ({}, {}, Dir::{dir}),\n", lit(&wire), lit(&ir)));
        }
        body.push_str("];\n");
    }

    let uses: Vec<&str> = uses.into_iter().collect();
    Ok(format!(
        "// SPDX-License-Identifier: Apache-2.0\n\
         // Copyright (C) 2026 Busbar Inc and contributors\n\
         \n\
         // @generated by `cargo xtask dialect compile` from {source}.\n\
         // DO NOT EDIT: edit the mapping file and re-run the compile; the `dialect-map` gate refuses\n\
         // a table file that differs from a fresh compile.\n\
         \n\
         use crate::codec::carry::{{{}}};\n{body}",
        uses.join(", ")
    ))
}

/// Compile every mapping file under [`DIALECT_DIR`].
pub fn compile_all(cx: &Ctx) -> Result<Vec<Compiled>, String> {
    let files = cx
        .walk(&WalkSpec::new([DIALECT_DIR]).ext("toml").min_files(1))
        .map_err(|e| e.to_string())?;
    let all: Vec<Dialect> = files
        .iter()
        .map(|f| Dialect {
            name: f
                .rel
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            doc: toml_lite::parse_text(&f.text),
        })
        .collect();
    all.iter()
        .map(|d| {
            Ok(Compiled {
                source: format!("{DIALECT_DIR}/{}.toml", d.name),
                target: gen_path(&d.name),
                text: compile_one(&all, d)?,
            })
        })
        .collect()
}

/// `cargo xtask dialect compile`: write every table file.
pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    if args.first().map(String::as_str) != Some("compile") || args.len() != 1 {
        eprintln!("usage: cargo xtask dialect compile");
        return 2;
    }
    match compile_all(cx) {
        Ok(compiled) => {
            for c in compiled {
                if let Err(e) = cx.write_file(&c.target, &c.text) {
                    eprintln!("xtask dialect: cannot write {}: {e}", c.target);
                    return 3;
                }
                println!("{} -> {}", c.source, c.target);
            }
            0
        }
        Err(e) => {
            eprintln!("xtask dialect: {e}");
            1
        }
    }
}
