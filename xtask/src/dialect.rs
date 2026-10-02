//! `cargo xtask dialect compile`: THE DIALECT MAPPING COMPILER.
//!
//! Each LLM dialect states its wire <> IR mapping by hand in
//! `crates/busbar-plane-llm/dialects/<d>.toml`. This compiles every such file into the committed
//! `crates/busbar-plane-llm/src/codec/<d>/map.gen.rs`: `const` tables of the plane's own mapping
//! types (`codec::carry::{Field, Slot, ValueCodec, Hook, Word, Dir}`), so nothing is parsed at run time.
//! The `dialect-map` gate ([`crate::gates::dialect_map`]) runs the same compile and refuses a
//! committed file that differs from it.
//!
//! The file format (stage 1: request, response and stream rows, word tables, no-equivalent marks),
//! read through [`crate::toml_lite`]. A mapping file is SELF-CONTAINED: it never names another
//! dialect's rows or word tables (a shared spelling is copied, so editing one dialect never moves
//! another).
//!
//! * `[dialect] wire = "<lock>"`: the dialect's wire lock, `testing/llm-conformance/wire/<lock>.wire.json`;
//! * `[dialect] request = ["<group>", ..]`, `response = [..]`, `stream = [..]`: the row groups of
//!   each direction, walked in order. Every `[rows.<group>]` is listed by exactly one direction;
//! * `[dialect] label = "<name>"`: the dialect's name in a `cap` truncation diagnostic;
//! * `[rows.<group>]`: one row per line, `"<wire path>" = { ir = "<slot>" [, words = "<table>"]
//!   [, hook = "<hook>"] [, modifiers] }`, the path in wire-lock notation A (`a.b`, `a[]`, `a{}`,
//!   `<tag>=<arm>`; see [`crate::wire_lock`]), the slot and hook in snake case, resolved against the
//!   plane's one registry (`Slot`, `Hook`) when the table compiles. `park = true` on its own line
//!   marks every row of the group. Modifiers: `park = true` (same-dialect fidelity park);
//!   `clamp = [min, max]` with `clamp_warn = "<text>"` and `clamp_parameter = true|false`;
//!   `cap = <n>`; `drop_if = "thinking"` with `drop_warn = "<text>"` and
//!   `drop_warn_value = true|false` (default true); `off_wire = "<reason>"` (a member busbar itself
//!   reads or writes that is not in the published protocol, so not in the wire lock);
//! * a `prim = "<name>"` row is a member the dialect's named structural code models: the walker
//!   only counts it among the modelled keys (`ir` is optional);
//! * `[controls]`: how a control slot beyond the rows is handled, one per line, `"<slot>" =
//!   { silent = true }` (a 1.5.5 silent drop, its reason cited in a comment), `{ code = "<name>" }`
//!   (carried or reported by named dialect code) or `{ warn = "<text>" [, value = true] }` (the
//!   slot's own drop warn);
//! * `[dialect] drop_warn = "<text>"`, `drop_field = "control" | "parameter"`: the warn for every
//!   other derived drop (`parameter` texts name the slot as `{slot}`);
//! * `[words.<table>]`: `base = "<table>"` (its rows come first), then one row per line,
//!   `"<ir word>" = { wire = "<word>" [, dir = "read" | "write"] }`;
//! * `[unmapped.<direction>]`: one line per wire path this dialect deliberately does not map although
//!   another dialect maps a field of that name, `"<wire path>" = { no-equivalent = "<reason>" }`
//!   (the `dialect-candidates` gate).
//!
//! Only the request direction is emitted into `map.gen.rs` (the plane walks it at run time); every
//! direction is read by the coverage gates ([`load_maps`]) and rendered into the generated
//! translation matrix ([`MATRIX`]).

use crate::ctx::{Ctx, WalkSpec};
use crate::toml_lite;
use std::collections::{BTreeMap, BTreeSet};

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

/// The const naming `kind` table `name` in the dialect's own table file.
fn const_ref(kind: &str, name: &str) -> String {
    format!("{kind}_{}", name.to_ascii_uppercase())
}

/// A row group or word table named by this file: a bare name. A `"<other dialect>.<name>"`
/// reference is refused, since a map file never includes another dialect's rows.
fn local<'a>(source: &str, what: &str, reference: &'a str) -> Result<&'a str, String> {
    if reference.contains('.') {
        return Err(format!(
            "{source}: {what} `{reference}` names another dialect's table; a map file is \
             self-contained, so copy the rows in"
        ));
    }
    Ok(reference)
}

/// The directions a mapping file declares row groups for, in the wire locks' names.
pub const DIRECTIONS: [&str; 3] = crate::wire_lock::DIRECTIONS;

/// The directions the plane walks at run time, and so the ones emitted into `map.gen.rs`.
const EMITTED: [&str; 1] = ["request"];

/// One segment of a wire path in notation A.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seg<'a> {
    /// `name`: an object member.
    Key(&'a str),
    /// `name[]`, `name{}`, `name{}[]`: the items of an array, the values of a map.
    Each(&'a str),
    /// `<tag>=<arm>`: one arm of a tagged union.
    Arm(&'a str, &'a str),
}

/// Split a notation-A wire path into its segments; `Err` names the malformed segment.
pub fn segments(path: &str) -> Result<Vec<Seg<'_>>, String> {
    let word = |w: &str| !w.is_empty() && !w.contains(['[', ']', '{', '}', '=', ' ']);
    path.split('.')
        .map(|s| {
            if let Some((tag, arm)) = s.split_once('=') {
                return (word(tag) && word(arm))
                    .then_some(Seg::Arm(tag, arm))
                    .ok_or_else(|| format!("`{path}`: segment `{s}` is not <tag>=<arm>"));
            }
            let name = s
                .strip_suffix("{}[]")
                .or_else(|| s.strip_suffix("[]"))
                .or_else(|| s.strip_suffix("{}"));
            match name {
                Some(n) if word(n) => Ok(Seg::Each(n)),
                None if word(s) => Ok(Seg::Key(s)),
                _ => Err(format!("`{path}`: segment `{s}` is not notation A")),
            }
        })
        .collect()
}

/// Every `[rows.<group>]` this file lists, with the direction that lists it; `Err` for a listed
/// group the file lacks, a group listed twice, or a group no direction lists.
fn group_directions(
    source: &str,
    doc: &toml_lite::Document,
) -> Result<Vec<(String, &'static str)>, String> {
    let dialect_t = doc.table("dialect");
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for dir in DIRECTIONS {
        for g in dialect_t.get_list(dir) {
            let g = local(source, "row group", &g)?.to_string();
            if !doc.tables.contains_key(&format!("rows.{g}")) {
                return Err(format!(
                    "{source}: [dialect] {dir} lists `{g}` but there is no [rows.{g}]"
                ));
            }
            if out.iter().any(|(have, _)| *have == g) {
                return Err(format!("{source}: row group `{g}` is listed twice"));
            }
            out.push((g, dir));
        }
    }
    for path in doc.tables.keys().filter(|k| k.starts_with("rows.")) {
        let g = &path["rows.".len()..];
        if !out.iter().any(|(have, _)| have == g) {
            return Err(format!("{source}: [{path}] is listed by no direction"));
        }
    }
    Ok(out)
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
            let base = toml_lite::string_value(raw);
            let base = local(&format!("{dialect}.toml"), "word table base", &base)?;
            out.extend(word_rows(all, dialect, base, depth + 1)?);
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

/// The dialect's `[dialect] label`.
fn dialect_label(doc: &toml_lite::Document) -> Option<String> {
    doc.table("dialect").get_one("label").map(String::from)
}

/// Compile one dialect's table file text.
fn compile_one(all: &[Dialect], d: &Dialect) -> Result<String, String> {
    let source = format!("{DIALECT_DIR}/{}.toml", d.name);
    let mut uses: BTreeSet<&str> = BTreeSet::new();
    let mut body = String::new();

    for t in d.doc.tables.keys() {
        let known = t == "dialect"
            || t == "controls"
            || ["rows.", "words.", "unmapped."]
                .iter()
                .any(|p| t.starts_with(p));
        if !known {
            return Err(format!("{source}: [{t}] is not a mapping-file table"));
        }
    }

    // The row groups this file declares, in name order. Every group's rows are checked; only the
    // groups of an EMITTED direction are written.
    let directions: BTreeMap<String, &str> =
        group_directions(&source, &d.doc)?.into_iter().collect();
    for (name, dir) in &directions {
        let path = format!("rows.{name}");
        let table = &d.doc.tables[&path];
        let emitted = EMITTED.contains(dir);
        let mut group = format!(
            "\n/// Row group `{name}`.\npub(crate) const ROWS_{}: &[Field] = &[\n",
            name.to_ascii_uppercase()
        );
        let mut group_uses: BTreeSet<&str> = ["Field", "Slot", "row", "ValueCodec"].into();
        let mut group_park = false;
        for (key, raw) in &table.entries {
            if key == "park" {
                group_park = toml_lite::string_value(raw) == "true";
                continue;
            }
            let f = row_fields(&source, key, raw)?;
            let segs = segments(key).map_err(|e| format!("{source}: [{path}] {e}"))?;
            let prim = field(&f, "prim").map(toml_lite::string_value);
            let slot = match (field(&f, "ir").map(toml_lite::string_value), &prim) {
                (Some(slot), _) => slot,
                (None, Some(_)) => "structure".to_string(),
                (None, None) => {
                    return Err(format!("{source}: [{path}] \"{key}\" names no ir slot"))
                }
            };
            if emitted && prim.is_none() && segs.iter().any(|s| !matches!(s, Seg::Key(_))) {
                return Err(format!(
                    "{source}: [{path}] \"{key}\": the {dir} walker carries object members only; \
                     an array, map or union-arm path is a `prim` row (its structure is code)"
                ));
            }
            let codec = match (field(&f, "words"), field(&f, "hook")) {
                (None, None) if prim.is_some() => {
                    format!(
                        "ValueCodec::Prim({})",
                        lit(prim.as_deref().unwrap_or_default())
                    )
                }
                (None, None) => "ValueCodec::Plain".to_string(),
                (Some(w), None) => {
                    let w = toml_lite::string_value(w);
                    let w = local(&source, "word table", &w)?;
                    format!("ValueCodec::Words({})", const_ref("WORDS", w))
                }
                (None, Some(h)) => {
                    group_uses.insert("Hook");
                    format!(
                        "ValueCodec::Hook(Hook::{})",
                        camel(&toml_lite::string_value(h))
                    )
                }
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "{source}: [{path}] \"{key}\" names both words and a hook"
                    ))
                }
            };
            const KNOWN: &[&str] = &[
                "ir",
                "prim",
                "words",
                "hook",
                "park",
                "clamp",
                "clamp_warn",
                "clamp_parameter",
                "cap",
                "drop_if",
                "drop_warn",
                "drop_warn_value",
                "off_wire",
            ];
            for (k, _) in &f {
                if !KNOWN.contains(&k.as_str()) {
                    return Err(format!(
                        "{source}: [{path}] \"{key}\": unknown modifier `{k}`"
                    ));
                }
            }
            let text = |name: &str| field(&f, name).map(toml_lite::string_value);
            if text("off_wire").is_some_and(|why| why.trim().is_empty()) {
                return Err(format!(
                    "{source}: [{path}] \"{key}\": off_wire needs its reason"
                ));
            }
            let flag = |name: &str, default: bool| text(name).map_or(default, |v| v == "true");
            let mut mods = String::new();
            if group_park || flag("park", false) {
                mods.push_str(".park()");
            }
            if let Some(range) = field(&f, "clamp") {
                let bounds: Vec<f64> = toml_lite::array_items(range)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|b| b.parse().ok())
                    .collect();
                let (Some(min), Some(max), Some(warn), 2) = (
                    bounds.first(),
                    bounds.get(1),
                    text("clamp_warn"),
                    bounds.len(),
                ) else {
                    return Err(format!(
                        "{source}: [{path}] \"{key}\": clamp needs [min, max] and clamp_warn"
                    ));
                };
                mods.push_str(&format!(
                    ".clamp({min:?}, {max:?}, {}, {})",
                    lit(&warn),
                    flag("clamp_parameter", false)
                ));
            }
            if let Some(n) = text("cap") {
                let n: usize = n
                    .parse()
                    .map_err(|_| format!("{source}: [{path}] \"{key}\": cap is not a count"))?;
                let label = dialect_label(&d.doc)
                    .ok_or_else(|| format!("{source}: a cap needs [dialect] label"))?;
                mods.push_str(&format!(".cap({n}, {})", lit(&label)));
            }
            if let Some(cond) = text("drop_if") {
                let cond = match cond.as_str() {
                    "thinking" => "Cond::Thinking",
                    other => {
                        return Err(format!(
                            "{source}: [{path}] \"{key}\": unknown drop_if `{other}`"
                        ))
                    }
                };
                let warn = text("drop_warn").ok_or_else(|| {
                    format!("{source}: [{path}] \"{key}\": drop_if needs drop_warn")
                })?;
                group_uses.insert("Cond");
                mods.push_str(&format!(
                    ".drop_if({cond}, {}, {})",
                    lit(&warn),
                    flag("drop_warn_value", true)
                ));
            }
            let segs: Vec<String> = key.split('.').map(lit).collect();
            group.push_str(&format!(
                "    row(&[{}], Slot::{}, {codec}){mods},\n",
                segs.join(", "),
                camel(&slot)
            ));
        }
        group.push_str("];\n");
        if emitted {
            uses.extend(group_uses);
            body.push_str(&group);
        }
    }

    // The answer directions (response, stream): the wire paths this dialect carries, as written.
    // A translate attempt's drop walk names every path of an answer that is not one of these and
    // not under one (design F3 "Drops"). A dialect with no rows in a direction emits no table.
    for dir in ["response", "stream"] {
        let paths: Vec<&str> = directions
            .iter()
            .filter(|(_, d2)| **d2 == dir)
            .flat_map(|(name, _)| d.doc.tables[&format!("rows.{name}")].entries.iter())
            .map(|(key, _)| key.as_str())
            .filter(|key| *key != "park")
            .collect();
        if paths.is_empty() {
            continue;
        }
        body.push_str(&format!(
            "\n/// The {dir} wire paths this dialect carries (the drop walk's map).\npub(crate) const {}_PATHS: &[&str] = &[\n",
            dir.to_ascii_uppercase()
        ));
        for p in paths {
            body.push_str(&format!("    {},\n", lit(p)));
        }
        body.push_str("];\n");
    }

    // The emitted direction tables.
    let dialect_t = d.doc.table("dialect");
    for dir in EMITTED {
        if !dialect_t.values.contains_key(dir) {
            continue;
        }
        uses.insert("Table");
        let refs: Vec<String> = dialect_t
            .get_list(dir)
            .iter()
            .map(|g| const_ref("ROWS", g))
            .collect();
        body.push_str(&format!(
            "\n/// The {dir} table, walked in order.\npub(crate) const {}: Table = &[{}];\n",
            dir.to_ascii_uppercase(),
            refs.join(", ")
        ));
    }

    // How each control slot beyond the rows is handled.
    let controls = d.doc.tables.get("controls");
    if let Some(controls) = controls {
        uses.insert("Handled");
        uses.insert("Slot");
        body.push_str(
            "\n/// How each control slot beyond the rows is handled.\npub(crate) const CONTROLS: &[(Slot, Handled)] = &[\n",
        );
        for (key, raw) in &controls.entries {
            let f = row_fields(&source, key, raw)?;
            let text = |name: &str| field(&f, name).map(toml_lite::string_value);
            let handled = match (text("silent").as_deref(), text("code"), text("warn")) {
                (Some("true"), None, None) => "Handled::Silent".to_string(),
                (None, Some(code), None) => format!("Handled::Code({})", lit(&code)),
                (None, None, Some(warn)) => format!(
                    "Handled::Warn({}, {})",
                    lit(&warn),
                    text("value").as_deref() == Some("true")
                ),
                _ => {
                    return Err(format!(
                        "{source}: [controls] \"{key}\" is not one of silent / code / warn"
                    ))
                }
            };
            body.push_str(&format!("    (Slot::{}, {handled}),\n", camel(key)));
        }
        body.push_str("];\n");
    }
    if let Some(warn) = dialect_t.get_one("drop_warn") {
        let kind = match dialect_t.get_one("drop_field") {
            Some("parameter") => "Parameter",
            _ => "Control",
        };
        let warn = dialect_t
            .entries
            .iter()
            .find(|(k, _)| k == "drop_warn")
            .map_or_else(|| warn.to_string(), |(_, raw)| toml_lite::string_value(raw));
        body.push_str(&format!(
            "\n/// The warn for every other derived drop.\npub(crate) const DROP_WARN: crate::codec::dialect::DropWarn =\n    crate::codec::dialect::DropWarn::{kind}({});\n",
            lit(&warn)
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
            body.push_str(&format!(
                "    ({}, {}, Dir::{dir}),\n",
                lit(&wire),
                lit(&ir)
            ));
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

/// Read every mapping file under [`DIALECT_DIR`].
fn read_all(cx: &Ctx) -> Result<Vec<Dialect>, String> {
    let files = cx
        .walk(&WalkSpec::new([DIALECT_DIR]).ext("toml").min_files(1))
        .map_err(|e| e.to_string())?;
    Ok(files
        .iter()
        .map(|f| Dialect {
            name: f
                .rel
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            doc: toml_lite::parse_text(&f.text),
        })
        .collect())
}

/// Compile every mapping file under [`DIALECT_DIR`].
pub fn compile_all(cx: &Ctx) -> Result<Vec<Compiled>, String> {
    let all = read_all(cx)?;
    let mut out = all
        .iter()
        .map(|d| {
            Ok(Compiled {
                source: format!("{DIALECT_DIR}/{}.toml", d.name),
                target: gen_path(&d.name),
                text: compile_one(&all, d)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    out.push(Compiled {
        source: format!("{DIALECT_DIR}/*.toml"),
        target: MATRIX.to_string(),
        text: render_matrix(&maps_of(&all)?),
    });
    Ok(out)
}

/// The generated translation matrix: what each dialect maps, concept by concept.
pub const MATRIX: &str = "docs/llm-translation-matrix.md";

/// The translation matrix text: per direction, one row per concept (a slot, or the `prim` name of
/// the structural code that carries it), one column per dialect, each cell the wire paths that
/// map it.
fn render_matrix(maps: &[MapFile]) -> String {
    let mut s = String::from(
        "<!-- @generated by `cargo xtask dialect compile` from crates/busbar-plane-llm/dialects/*.toml.\n     \
         DO NOT EDIT: edit a mapping file and re-run the compile; the `dialect-map` gate refuses a stale copy. -->\n\n\
         # LLM translation matrix\n\n\
         What busbar translates between LLM dialects. A request or answer that stays in its own dialect\n\
         passes through whole; one that crosses dialects carries every concept both dialects map and\n\
         drops the rest with a warning. Each cell is the dialect's wire path for the concept (notation A:\n\
         `a.b` member, `a[]` items, `<tag>=<arm>` union arm); `code` names the dialect code that carries\n\
         it; `-` means the dialect has no form for it.\n",
    );
    s.push_str("\n## Coverage\n\n| dialect | direction | mapped paths | no-equivalent marks |\n| --- | --- | ---: | ---: |\n");
    for m in maps {
        for dir in DIRECTIONS {
            let rows = m.rows.iter().filter(|r| r.dir == dir).count();
            let marks = m.marks.iter().filter(|k| k.dir == dir).count();
            if rows + marks > 0 {
                s.push_str(&format!("| {} | {dir} | {rows} | {marks} |\n", m.name));
            }
        }
    }
    for dir in DIRECTIONS {
        let concepts: BTreeSet<&str> = maps
            .iter()
            .flat_map(|m| m.rows.iter())
            .filter(|r| r.dir == dir && !r.concept.is_empty())
            .map(|r| r.concept.as_str())
            .collect();
        if concepts.is_empty() {
            continue;
        }
        s.push_str(&format!("\n## {dir}\n\n| concept |"));
        for m in maps {
            s.push_str(&format!(" {} |", m.name));
        }
        s.push_str("\n| --- |");
        s.push_str(&" --- |".repeat(maps.len()));
        s.push('\n');
        for c in concepts {
            s.push_str(&format!("| {c} |"));
            for m in maps {
                let paths: Vec<String> = m
                    .rows
                    .iter()
                    .filter(|r| r.dir == dir && r.concept == c)
                    .map(|r| match r.off_wire {
                        Some(_) => format!("`{}` (busbar's own)", r.path),
                        None => format!("`{}`", r.path),
                    })
                    .collect();
                let code = m.code_controls.iter().find(|(slot, _)| slot == c);
                let cell = match (paths.is_empty(), code) {
                    (false, _) => paths.join("<br>"),
                    (true, Some((_, name))) => format!("code `{name}`"),
                    (true, None) => "-".to_string(),
                };
                s.push_str(&format!(" {cell} |"));
            }
            s.push('\n');
        }
    }
    s
}

/// One row of a mapping file as the coverage gates read it: the direction, the wire path, the
/// concept it maps (the slot, or the `prim` name of the structural code that models it) and its
/// `off_wire` reason, when it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRow {
    pub dir: &'static str,
    pub path: String,
    pub concept: String,
    pub off_wire: Option<String>,
}

/// One `no-equivalent` mark: a wire path the dialect deliberately does not map, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub dir: &'static str,
    pub path: String,
    pub reason: String,
}

/// One mapping file as the coverage gates read it.
#[derive(Debug, Clone)]
pub struct MapFile {
    /// The file's stem (`openai_chat`).
    pub name: String,
    pub source: String,
    /// The wire lock it maps (`openai`).
    pub wire: String,
    pub rows: Vec<MapRow>,
    pub marks: Vec<Mark>,
    /// `[controls]`: (slot, `code` name) for each control slot the dialect's own code carries.
    pub code_controls: Vec<(String, String)>,
}

/// Every mapping file, read for the coverage gates, in file-name order. A file that does not
/// compile is an `Err` naming it.
pub fn load_maps(cx: &Ctx) -> Result<Vec<MapFile>, String> {
    let all = read_all(cx)?;
    for d in &all {
        compile_one(&all, d)?;
    }
    maps_of(&all)
}

/// The coverage view of every parsed mapping file.
fn maps_of(all: &[Dialect]) -> Result<Vec<MapFile>, String> {
    let mut out = Vec::new();
    for d in all {
        let source = format!("{DIALECT_DIR}/{}.toml", d.name);
        let wire = d
            .doc
            .table("dialect")
            .get_one("wire")
            .map(String::from)
            .ok_or_else(|| format!("{source}: [dialect] names no wire lock"))?;
        let mut rows = Vec::new();
        for (g, dir) in group_directions(&source, &d.doc)? {
            for (key, raw) in &d.doc.tables[&format!("rows.{g}")].entries {
                if key == "park" {
                    continue;
                }
                let f = row_fields(&source, key, raw)?;
                let text = |name: &str| field(&f, name).map(toml_lite::string_value);
                rows.push(MapRow {
                    dir,
                    path: key.clone(),
                    concept: text("ir").or_else(|| text("prim")).unwrap_or_default(),
                    off_wire: text("off_wire"),
                });
            }
        }
        let mut marks = Vec::new();
        for (table, t) in d
            .doc
            .tables
            .iter()
            .filter(|(k, _)| k.starts_with("unmapped."))
        {
            let dir = DIRECTIONS
                .into_iter()
                .find(|dir| table["unmapped.".len()..] == **dir)
                .ok_or_else(|| format!("{source}: [{table}] is not a direction"))?;
            for (key, raw) in &t.entries {
                segments(key).map_err(|e| format!("{source}: [{table}] {e}"))?;
                let f = row_fields(&source, key, raw)?;
                let reason = match f.as_slice() {
                    [(k, v)] if k == "no-equivalent" => toml_lite::string_value(v),
                    _ => String::new(),
                };
                if reason.trim().is_empty() {
                    return Err(format!(
                        "{source}: [{table}] \"{key}\" is not {{ no-equivalent = \"<reason>\" }}"
                    ));
                }
                marks.push(Mark {
                    dir,
                    path: key.clone(),
                    reason,
                });
            }
        }
        let mut code_controls = Vec::new();
        if let Some(controls) = d.doc.tables.get("controls") {
            for (key, raw) in &controls.entries {
                let f = row_fields(&source, key, raw)?;
                if let Some(code) = field(&f, "code") {
                    code_controls.push((key.clone(), toml_lite::string_value(code)));
                }
            }
        }
        out.push(MapFile {
            name: d.name.clone(),
            source,
            wire,
            rows,
            marks,
            code_controls,
        });
    }
    Ok(out)
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
