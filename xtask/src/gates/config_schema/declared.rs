// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-DECLARED TOP-LEVEL SECTIONS, read from the plane declarations themselves.
//!
//! The kernel's config pre-pass lifts every top-level section a REGISTERED plane declares
//! (`PlaneDeclaration::config_section` and `::owned_config_sections`) and spells none of them (#49).
//! So the lift list this gate fingerprints by is not in the kernel's source any more: it is the union
//! of what the planes' `PLANE_DECLARATION` items say, minus the sections core still owns concretely
//! (`CORE_OWNED_CONCRETE_SECTIONS` — a frozen field, never lifted).
//!
//! A section a plane declares BESIDE its own declaring section is that plane's endpoint DOOR: the
//! pre-pass carrier written `Declared::Door` is tied to it here.
//!
//! Every census here refuses to come back empty or unreadable: a declaration this reader cannot
//! resolve, or a tree with no declaration at all, is a coverage hole and a hard error — never a
//! smaller lift list, which would silently un-freeze the sections it dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;

use super::scan;
use crate::ctx::{Change, Ctx, Overlay, WalkSpec};

/// The walk every declaration lives under: production source, never a test target.
const ROOT: &str = "crates";
/// The registration item each plane crate exports (the K0 contract shape).
const ITEM: &str = "const PLANE_DECLARATION";
/// The kernel's reserved list: sections core still declares as concrete `DeployCfg` fields.
const CORE_OWNED: &str = "CORE_OWNED_CONCRETE_SECTIONS";

/// What the plane declarations declare, ready for the lift reader.
#[derive(Debug, Default, Clone)]
pub struct Declarations {
    /// Every declared top-level section a plane owns, minus core's concrete ones.
    pub sections: BTreeSet<String>,
    /// The subset declared BESIDE a plane's own declaring section — its endpoint door.
    pub doors: BTreeSet<String>,
    /// The subset that is a plane's declaring section AND listed in its own owned sections: a plane
    /// that parses its own grammar, carried by the pre-pass's map carrier (`Declared::Any`).
    pub owned: BTreeSet<String>,
}

fn stripped(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    scan::strip_cfg_test_mods(&scan::strip_comments(&chars))
        .into_iter()
        .collect()
}

fn spec() -> WalkSpec {
    WalkSpec::new([ROOT])
        .ext("rs")
        .exclude(["/tests/", "/target/"])
}

/// What one file contributes: its string constants (`const NAME: &str = "lit";`), its plane
/// declarations (the raw `config_section` / `owned_config_sections` expressions, or the refusal for
/// a field it lacks), and the kernel's reserved list if it holds it.
#[derive(Clone, Default)]
struct Facts {
    consts: Vec<(String, String)>,
    decls: Vec<Result<(String, Vec<String>), String>>,
    core_owned: Option<Vec<String>>,
}

fn facts(path: &str, raw: &str) -> Facts {
    let mut out = Facts::default();
    if !raw.contains("const ") {
        return out;
    }
    let text = stripped(raw);
    let mut rest = text.as_str();
    while let Some(at) = rest.find("const ") {
        let after = &rest[at + 6..];
        rest = after;
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let Some(tail) = after[name.len()..].trim_start().strip_prefix(':') else {
            continue;
        };
        let Some(eq) = tail.find('=') else { continue };
        let Some(end) = tail[eq..].find(';') else {
            continue;
        };
        let (ty, value) = (&tail[..eq], tail[eq + 1..eq + end].trim());
        if name == CORE_OWNED {
            out.core_owned = Some(scan::string_literals(value));
        } else if ty.contains("str") && !ty.contains('[') && value.len() >= 2 {
            if let Some(lit) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                out.consts.push((name, lit.to_string()));
            }
        }
    }
    let mut from = 0;
    while let Some(at) = text[from..].find(ITEM) {
        let start = from + at + ITEM.len();
        from = start;
        let whole_word = !text[start..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        let body = text[start..]
            .find('=')
            .and_then(|eq| block(&text, start + eq));
        let Some(body) = body.filter(|_| whole_word) else {
            continue;
        };
        let lacks =
            |f: &str| format!("config-schema: the plane declaration in {path} has no `{f}`");
        out.decls.push(
            field(body, "config_section")
                .ok_or_else(|| lacks("config_section"))
                .and_then(|d| {
                    let owned = field(body, "owned_config_sections")
                        .ok_or_else(|| lacks("owned_config_sections"))?;
                    let owned = owned
                        .split(',')
                        .map(|e| e.trim().to_string())
                        .filter(|e| !e.is_empty())
                        .collect();
                    Ok((d.trim().to_string(), owned))
                }),
        );
    }
    out
}

/// The REAL tree's per-file [`Facts`], walked once per process per root: the selftest renders this
/// gate dozens of times and the tree under it does not change between renders.
fn base(cx: &Ctx) -> Result<BTreeMap<String, Facts>, String> {
    static MEMO: Mutex<BTreeMap<PathBuf, BTreeMap<String, Facts>>> = Mutex::new(BTreeMap::new());
    let key = cx.root().to_path_buf();
    if let Some(hit) = MEMO.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(hit.clone());
    }
    let real = cx.with_overlay(Overlay::new());
    let files = real
        .walk(&spec())
        .map_err(|e| format!("config-schema: the plane-declaration walk failed: {e:?}"))?;
    let mut out = BTreeMap::new();
    for f in files {
        let rel = f.rel_str();
        let facts = facts(&rel, &f.text);
        if facts.consts.len() + facts.decls.len() > 0 || facts.core_owned.is_some() {
            out.insert(rel, facts);
        }
    }
    MEMO.lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, out.clone());
    Ok(out)
}

/// The per-file facts as THIS context sees them: the real tree, with the overlay's plants under
/// [`ROOT`] laid over it (a plant is re-read through the context, so an unreadable one refuses).
fn files(cx: &Ctx) -> Result<BTreeMap<String, Facts>, String> {
    let mut out = base(cx)?;
    if let Some(ov) = cx.overlay() {
        for (path, change) in ov.changes() {
            let rel = path.to_string_lossy().replace('\\', "/");
            let probe = format!("/{rel}");
            if !rel.starts_with(&format!("{ROOT}/"))
                || !rel.ends_with(".rs")
                || probe.contains("/tests/")
                || probe.contains("/target/")
            {
                continue;
            }
            out.remove(&rel);
            if !matches!(change, Change::Absent) {
                let text = cx.read(&rel)?;
                out.insert(rel.clone(), facts(&rel, &text));
            }
        }
    }
    Ok(out)
}

/// A declaration field's value: a `"literal"`, or a path to a string constant (`NAME`,
/// `krate::NAME`) resolved in the declaring file first, then in the named crate, then — only when
/// every definition agrees — anywhere.
fn resolve(
    expr: &str,
    file: &str,
    consts: &BTreeMap<String, Vec<(String, String)>>,
) -> Result<String, String> {
    let e = expr.trim();
    if e.len() >= 2 && e.starts_with('"') && e.ends_with('"') {
        return Ok(e[1..e.len() - 1].to_string());
    }
    let segs: Vec<&str> = e.split("::").map(str::trim).collect();
    let name = segs.last().copied().unwrap_or_default();
    let defs = consts.get(name).cloned().unwrap_or_default();
    let pick = |pred: &dyn Fn(&str) -> bool| -> Option<String> {
        defs.iter().find(|(p, _)| pred(p)).map(|(_, v)| v.clone())
    };
    let found = if segs.len() == 1 {
        pick(&|p| p == file)
    } else {
        let dir = format!("{ROOT}/{}/", segs[0].replace('_', "-"));
        pick(&|p| p.starts_with(&dir))
    };
    if let Some(v) = found {
        return Ok(v);
    }
    let values: BTreeSet<&String> = defs.iter().map(|(_, v)| v).collect();
    match values.len() {
        1 => Ok(values.into_iter().next().cloned().unwrap_or_default()),
        _ => Err(format!(
            "config-schema: the plane declaration in {file} names its section as `{e}`, which this \
             reader cannot resolve to one string constant. A declared section it cannot read is a \
             section it cannot freeze — write a literal or a plain `const NAME: &str = \"…\";`."
        )),
    }
}

/// The text of the `{ … }` block starting at the first `{` at or after `from`.
fn block(text: &str, from: usize) -> Option<&str> {
    let open = from + text[from..].find('{')?;
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The value written after `field:` in a declaration block — `field` matched as a whole word, so
/// `config_section` never matches inside `owned_config_sections`.
fn field<'a>(body: &'a str, field: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(at) = body[from..].find(field) {
        let start = from + at;
        from = start + field.len();
        let before = body[..start].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let rest = body[from..].trim_start();
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(list) = rest.strip_prefix("&[") {
            return list.find(']').map(|end| &list[..end]);
        }
        return rest.find(',').map(|end| &rest[..end]);
    }
    None
}

/// Read every `PLANE_DECLARATION` under [`ROOT`] and fold its sections.
pub fn read(cx: &Ctx) -> Result<Declarations, String> {
    let files = files(cx)?;
    let mut consts: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (path, f) in &files {
        for (name, lit) in &f.consts {
            consts
                .entry(name.clone())
                .or_default()
                .push((path.clone(), lit.clone()));
        }
    }
    let core_owned: BTreeSet<String> = files
        .values()
        .find_map(|f| f.core_owned.clone())
        .ok_or_else(|| {
            format!(
                "config-schema: no `const {CORE_OWNED}` under {ROOT}/. Without the kernel's \
                 reserved list a plane declaration naming a concrete section would read as a \
                 lifted key."
            )
        })?
        .into_iter()
        .collect();
    let mut out = Declarations::default();
    let mut seen = 0usize;
    for (path, f) in &files {
        for decl in &f.decls {
            seen += 1;
            let (declaring, owned) = decl.clone()?;
            let declaring = resolve(&declaring, path, &consts)?;
            let mut declared = vec![(declaring.clone(), false)];
            for e in owned {
                let section = resolve(&e, path, &consts)?;
                let door = section != declaring;
                if !door && !core_owned.contains(&section) {
                    out.owned.insert(section.clone());
                }
                declared.push((section, door));
            }
            for (section, door) in declared {
                if core_owned.contains(&section) {
                    continue;
                }
                if door {
                    out.doors.insert(section.clone());
                }
                out.sections.insert(section);
            }
        }
    }
    if seen == 0 {
        return Err(format!(
            "config-schema: no `{ITEM}` under {ROOT}/. The plane sections the config pre-pass lifts \
             are read from the plane declarations; a census that finds none lifts nothing, and a \
             render that lifts nothing has silently dropped every plane section from the grammar."
        ));
    }
    Ok(out)
}
