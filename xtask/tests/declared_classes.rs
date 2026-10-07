// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY CLASS A PLANE REPORTS, IT DECLARES (`BUSBAR-1.6.0.md` §7).
//!
//! A unit's one line refuses a reported class no plane declared — fail-closed, never billed at
//! zero. That refusal is the backstop for a plugin defect; an in-tree plane must never trip it. So
//! this test reads every report site in the in-tree planes — each place a class key enters a usage
//! report (`usage_units`) — and holds the classes each emits against its plane's DECLARED billable
//! classes (`PlaneDeclaration::billable_classes`), both read off the source.
//!
//! Two halves, both RED-able:
//! * COMPLETENESS: every report-site shape found in the scanned crates is a site listed below. A new
//!   site is RED until it is listed with the classes it emits.
//! * DECLARATION: every class a listed site emits resolves (by its constant, read off its defining
//!   file) to a class its plane declares. A site emitting an undeclared class is RED.
//!
//! A listed site marked DEAD has no non-test caller: it is held instead to STAY dead, so the day it
//! gains a caller it has to be declared first.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the workspace")
        .to_path_buf()
}

/// The crates whose non-test sources are scanned for report sites.
const SCANNED: &[&str] = &[
    "crates/busbar-plane-llm/src",
    "crates/busbar-plane-mcp/src",
    "crates/busbar-plane-a2a/src",
    "crates/busbar-plane-streaming/src",
    "crates/busbar-plane-decisions/src",
    "crates/busbar-mcp/src",
    "crates/busbar-a2a/src",
    "crates/busbar-voice/src",
];

/// The shapes a class key enters a usage report through.
const SHAPES: &[&str] = &[
    "usage_units.insert(",
    "usage_units.entry(",
    "=> Billing::Counted {",
    "usage_units: std::collections::BTreeMap::from(",
    "usage_units: class_counts(",
];

/// Where a plane's `PlaneDeclaration` (and so its `billable_classes`) is written.
const DECLARATIONS: &[(&str, &str)] = &[
    // A door plane's billable classes are its tail's, built from the class constants it lists
    // (`door_declared`); the llm plane is served through its door since FLIP-LLM deleted `busbar-llm`.
    ("llm", "crates/busbar-plane-llm/src/plane_door.rs"),
    ("mcp", "crates/busbar-mcp/src/mcp/mod.rs"),
    ("a2a", "crates/busbar-a2a/src/a2a/mod.rs"),
    ("streaming", "crates/busbar-voice/src/lib.rs"),
];

/// One report site: its plane, its file, its shape and how many times the shape occurs there, and
/// the classes it emits — each a constant path, resolved off its defining file.
struct Site {
    plane: &'static str,
    file: &'static str,
    shape: &'static str,
    occurrences: usize,
    emits: &'static [&'static str],
    /// `Some(fn)`: the site has no non-test caller of `fn`, and must keep having none.
    dead: Option<&'static str>,
}

const SITES: &[Site] = &[
    // The four reserved token tiers every llm dialect reports (`tier_usage`).
    Site {
        plane: "llm",
        file: "crates/busbar-plane-llm/src/codec/wire_shim.rs",
        shape: "usage_units.insert(",
        occurrences: 1,
        emits: &[
            "busbar_contract::records::UNIT_INPUT",
            "busbar_contract::records::UNIT_OUTPUT",
            "busbar_contract::records::UNIT_CACHE_READ",
            "busbar_contract::records::UNIT_CACHE_WRITE",
        ],
        dead: None,
    },
    // A rerank's billed search units: the one open class an llm codec counts.
    Site {
        plane: "llm",
        file: "crates/busbar-plane-llm/src/codec/ir/rerank.rs",
        shape: "=> Billing::Counted {",
        occurrences: 1,
        emits: &["busbar_plane_llm::codec::ir::rerank::SEARCH_UNITS_CLASS"],
        dead: None,
    },
    // (The engine's Meter step, `busbar-llm/src/unit/meter.rs`, left with the engine (FLIP-LLM): the
    // door reports its counts by INDEX into its tail's billable classes, through no shape above.)
    Site {
        plane: "mcp",
        file: "crates/busbar-mcp/src/mcp/method.rs",
        shape: "usage_units: std::collections::BTreeMap::from(",
        occurrences: 1,
        emits: &["busbar_plane_mcp::meta::CLASS_TOOL_CALLS"],
        dead: None,
    },
    Site {
        plane: "a2a",
        file: "crates/busbar-a2a/src/a2a/receive.rs",
        shape: "usage_units: std::collections::BTreeMap::from(",
        occurrences: 1,
        emits: &["busbar_plane_a2a::meta::CLASS_BYTES"],
        dead: None,
    },
    // `class_counts` (busbar-plane-streaming's session.rs) names these six.
    Site {
        plane: "streaming",
        file: "crates/busbar-voice/src/runtime/metering.rs",
        shape: "usage_units: class_counts(",
        occurrences: 1,
        emits: &[
            "busbar_plane_streaming::meta::CLASS_AUDIO_TOKENS_IN",
            "busbar_plane_streaming::meta::CLASS_AUDIO_TOKENS_OUT",
            "busbar_plane_streaming::meta::CLASS_TEXT_TOKENS_IN",
            "busbar_plane_streaming::meta::CLASS_TEXT_TOKENS_OUT",
            "busbar_plane_streaming::meta::CLASS_AUDIO_SECONDS_IN",
            "busbar_plane_streaming::meta::CLASS_TOOL_CALLS",
        ],
        dead: None,
    },
    // DEAD: `to_billing_usage` would report the reserved tiers, which streaming does not declare.
    // It has no non-test caller, and its owner deletes it (FOLD-STREAMING); once it is gone this
    // entry is struck.
    Site {
        plane: "streaming",
        file: "crates/busbar-plane-streaming/src/codec/ir/usage.rs",
        shape: "usage_units.insert(",
        occurrences: 3,
        emits: &[
            "busbar_contract::records::UNIT_INPUT",
            "busbar_contract::records::UNIT_OUTPUT",
            "busbar_contract::records::UNIT_CACHE_READ",
        ],
        dead: Some("to_billing_usage("),
    },
];

/// Every non-test `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" && name != "fixtures" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// The literal a constant path names, read off the file that defines it:
/// `busbar_plane_mcp::meta::CLASS_BYTES` is `crates/busbar-plane-mcp/src/meta.rs`'s
/// `const CLASS_BYTES: … = MeterClassId::new("bytes")` (or `= "bytes"`).
fn resolve(root: &Path, path: &str) -> Result<String, String> {
    let (file, src, name) = defining(root, path)?;
    literal_of(&src, name).ok_or_else(|| format!("{path}: no `const {name}` literal in {file:?}"))
}

/// The file that defines the item a constant path names, its text, and the item's name.
fn defining<'p>(root: &Path, path: &'p str) -> Result<(PathBuf, String, &'p str), String> {
    let segments: Vec<&str> = path.split("::").collect();
    let (krate, rest) = segments.split_first().ok_or("an empty path")?;
    let (name, modules) = rest.split_last().ok_or("a path with no constant")?;
    let dir = root
        .join("crates")
        .join(krate.replace('_', "-"))
        .join("src");
    let candidates = if modules.is_empty() {
        vec![dir.join("lib.rs")]
    } else {
        let joined = modules.join("/");
        vec![
            dir.join(format!("{joined}.rs")),
            dir.join(joined).join("mod.rs"),
        ]
    };
    let file = candidates
        .iter()
        .find(|f| f.exists())
        .ok_or_else(|| format!("{path}: no defining file among {candidates:?}"))?;
    let src = std::fs::read_to_string(file).map_err(|e| format!("{path}: {e}"))?;
    Ok((file.clone(), src, name))
}

/// The string literal `const name` is defined as in `src`.
fn literal_of(src: &str, name: &str) -> Option<String> {
    let at = src.find(&format!("const {name}:"))?;
    let tail = &src[at..];
    let end = tail.find(';')?;
    let def = &tail[..end];
    let open = def.find('"')?;
    let close = def[open + 1..].find('"')?;
    Some(def[open + 1..open + 1 + close].to_string())
}

/// The classes a plane's `PlaneDeclaration::billable_classes` names, resolved.
fn declared(root: &Path, plane: &str) -> Result<BTreeSet<String>, String> {
    let (_, file) = DECLARATIONS
        .iter()
        .find(|(p, _)| *p == plane)
        .ok_or_else(|| format!("no declaration file for plane {plane}"))?;
    let src = std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))?;
    // A door plane's tail is built from its own tables (`billable_classes: TABLE.as_ptr()`).
    let Some(start) = src.find("billable_classes: &") else {
        return door_declared(root, file, &src);
    };
    let after = &src[start + "billable_classes: &".len()..];
    // Either a literal list (`&[ BillableClass { class: … }, … ]`) or a named const table in the
    // same file (`&LLM_BILLABLE_CLASSES`), whose body states the classes the same way.
    let block = if after.starts_with('[') {
        let end = after.find("],").ok_or("an unterminated billable_classes")?;
        &after[..end]
    } else {
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let at = src
            .find(&format!("const {name}:"))
            .ok_or_else(|| format!("{file}: billable_classes names `{name}`, defined nowhere"))?;
        let body = &src[at..];
        let end = body
            .find("\n};")
            .ok_or_else(|| format!("{file}: an unterminated `const {name}`"))?;
        &body[..end]
    };
    let mut classes = BTreeSet::new();
    // A table that splices in the codec's open classes (`OPEN_CLASSES[k].0`) declares every one
    // of them: read that table off its own defining file, by the path the block imports it from.
    if let Some(at) = block.find("::{OPEN_CLASSES") {
        let line_start = block[..at]
            .rfind("use ")
            .ok_or("an OPEN_CLASSES import with no `use`")?;
        let module = block[line_start + 4..at].trim();
        for class in open_classes(root, &format!("{module}::OPEN_CLASSES"))? {
            classes.insert(class);
        }
    }
    for line in block.lines() {
        let Some(expr) = line.trim().strip_prefix("class:") else {
            continue;
        };
        // The spliced open classes are read above; `""` is the table's fill before it is written.
        if expr.trim().starts_with("OPEN_CLASSES[") || expr.trim().starts_with("\"\"") {
            continue;
        }
        let expr = expr
            .trim()
            .trim_end_matches(',')
            .trim_end_matches(".as_str()");
        classes.insert(if let Some(lit) = expr.strip_prefix('"') {
            lit.trim_end_matches('"').to_string()
        } else {
            resolve(root, expr)?
        });
    }
    Ok(classes)
}

/// A DOOR PLANE'S DECLARED CLASSES: its tail's billable classes are built from `TOKEN_CLASSES` (a
/// list of class constants) and `OPEN_CLASSES` (`(class, family)` pairs), the source of every class
/// it may report. Each constant is resolved as a declaration's is; a bare name through the file's own
/// `use`, its `crate::` read as the file's crate.
fn door_declared(root: &Path, file: &str, src: &str) -> Result<BTreeSet<String>, String> {
    let body = |name: &str| -> Result<&str, String> {
        let at = src
            .find(&format!("const {name}:"))
            .ok_or_else(|| format!("{file}: no billable_classes and no `const {name}`"))?;
        let def = &src[at..];
        let open = def
            .find("= ")
            .ok_or_else(|| format!("{file}: `{name}` has no value"))?;
        let end = def
            .find("];")
            .ok_or_else(|| format!("{file}: `{name}` is unterminated"))?;
        Ok(&def[open + 2..end])
    };
    let krate = file
        .strip_prefix("crates/")
        .and_then(|r| r.split('/').next())
        .ok_or_else(|| format!("{file}: not under crates/"))?
        .replace('-', "_");
    let path_of = |expr: &str| -> Result<String, String> {
        if expr.contains("::") {
            return Ok(expr.to_string());
        }
        let used = src
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                l.strip_prefix("use ")
                    .or_else(|| l.strip_prefix("pub use "))
            })
            .filter_map(|l| l.strip_suffix(';'))
            .find(|l| l.ends_with(&format!("::{expr}")))
            .ok_or_else(|| format!("{file}: `{expr}` is neither a path nor a `use`d name"))?;
        Ok(used.replacen("crate::", &format!("{krate}::"), 1))
    };
    let mut classes = BTreeSet::new();
    for expr in body("TOKEN_CLASSES")?
        .trim_start_matches(['[', '&'])
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        classes.insert(resolve(root, &path_of(expr)?)?);
    }
    // `OPEN_CLASSES` is the file's own table, or a `use`d one read off its defining file.
    if let Ok(table) = body("OPEN_CLASSES") {
        for pair in table.split('(').skip(1) {
            let expr = pair.split(',').next().unwrap_or_default().trim();
            classes.insert(if let Some(lit) = expr.strip_prefix('"') {
                lit.trim_end_matches('"').to_string()
            } else {
                resolve(root, &path_of(expr)?)?
            });
        }
    } else {
        for class in open_classes(root, &path_of("OPEN_CLASSES")?)? {
            classes.insert(class);
        }
    }
    Ok(classes)
}

/// The class of every `(CLASS, family)` row of the `&[(&str, &str)]` table `path` names, each
/// resolved off the table's own file.
fn open_classes(root: &Path, path: &str) -> Result<Vec<String>, String> {
    let (file, src, name) = defining(root, path)?;
    let at = src
        .find(&format!("const {name}:"))
        .ok_or_else(|| format!("{path}: no `const {name}` in {file:?}"))?;
    let body = &src[at..];
    let open = body
        .find("= &[")
        .ok_or_else(|| format!("{path}: not a table"))?
        + 4;
    let end = body[open..]
        .find("\n];")
        .ok_or_else(|| format!("{path}: an unterminated table"))?;
    let mut out = Vec::new();
    // The rows, line comments dropped (a comment may hold a parenthesis).
    let rows: String = body[open..open + end]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for row in rows.split('(').skip(1) {
        let class = row.split(',').next().unwrap_or("").trim();
        if class.is_empty() {
            continue;
        }
        out.push(if let Some(lit) = class.strip_prefix('"') {
            lit.trim_end_matches('"').to_string()
        } else {
            match literal_of(&src, class) {
                Some(lit) => lit,
                // Defined elsewhere in the same crate and imported (`use crate::a::b::NAME;`).
                None => {
                    let krate = path.split("::").next().unwrap_or("");
                    let import = src
                        .lines()
                        .filter_map(|l| l.trim().strip_prefix("use crate::"))
                        .filter_map(|l| l.strip_suffix(';'))
                        .find(|l| l.rsplit("::").next() == Some(class))
                        .ok_or_else(|| {
                            format!(
                                "{path}: row `{class}` is neither defined nor imported in {file:?}"
                            )
                        })?;
                    resolve(root, &format!("{krate}::{import}"))?
                }
            }
        });
    }
    if out.is_empty() {
        return Err(format!("{path}: a table with no rows"));
    }
    Ok(out)
}

/// Every finding for `sites` over `found` (file -> shape -> count) — empty is the only good answer.
fn findings(
    root: &Path,
    sites: &[Site],
    found: &[(String, &'static str, usize)],
    callers_of: &dyn Fn(&str, &str) -> usize,
) -> Vec<String> {
    let mut out = Vec::new();
    for (file, shape, count) in found {
        let listed = sites
            .iter()
            .find(|s| s.file == file && s.shape == *shape)
            .map_or(0, |s| s.occurrences);
        if listed != *count {
            out.push(format!(
                "{file}: `{shape}` occurs {count} time(s), {listed} listed — list the new report \
                 site with the classes it emits"
            ));
        }
    }
    for site in sites {
        // A DEAD site that has been deleted is the outcome it is listed for; any other listed site
        // must still be in the source, exactly as listed.
        let present = found
            .iter()
            .any(|(f, s, n)| f == site.file && *s == site.shape && *n == site.occurrences);
        let deleted = !found
            .iter()
            .any(|(f, s, _)| f == site.file && *s == site.shape);
        if !present && !(site.dead.is_some() && deleted) {
            out.push(format!(
                "{}: listed `{}` x{} is not in the source",
                site.file, site.shape, site.occurrences
            ));
        }
        if let Some(func) = site.dead {
            let n = callers_of(func, site.file);
            if n != 0 {
                out.push(format!(
                    "{}: `{func}` gained {n} non-test caller(s); declare what it reports first",
                    site.file
                ));
            }
            continue;
        }
        let declared = match declared(root, site.plane) {
            Ok(d) => d,
            Err(e) => {
                out.push(e);
                continue;
            }
        };
        for path in site.emits {
            match resolve(root, path) {
                Ok(class) if declared.contains(&class) => {}
                Ok(class) => out.push(format!(
                    "{}: reports `{class}` ({path}), which plane `{}` does not declare \
                     (declared: {declared:?})",
                    site.file, site.plane
                )),
                Err(e) => out.push(e),
            }
        }
    }
    out
}

/// Each (file, shape, count) the scanned sources hold.
type Found = Vec<(String, &'static str, usize)>;

/// Every (file, shape, count) the scanned sources hold, and every scanned file's text.
fn scan(root: &Path) -> (Found, Vec<(String, String)>) {
    let mut files = Vec::new();
    for dir in SCANNED {
        sources(&root.join(dir), &mut files);
    }
    files.sort();
    let mut found = Vec::new();
    let mut texts = Vec::new();
    for file in files {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .into_owned();
        for shape in SHAPES {
            let n = src.matches(shape).count();
            if n > 0 {
                found.push((rel.clone(), *shape, n));
            }
        }
        texts.push((rel, src));
    }
    (found, texts)
}

#[test]
fn every_class_an_in_tree_plane_reports_is_one_it_declares() {
    let root = root();
    let (found, texts) = scan(&root);
    let callers_of = |func: &str, defined_in: &str| {
        texts
            .iter()
            .map(|(file, src)| {
                let n = src.matches(func).count();
                // The definition's own line is not a caller.
                if file == defined_in {
                    n.saturating_sub(src.matches(&format!("fn {func}")).count())
                } else {
                    n
                }
            })
            .sum()
    };
    let findings = findings(&root, SITES, &found, &callers_of);
    assert!(findings.is_empty(), "{findings:#?}");
}

/// THE RED ARM: the same check, fed a site that reports a class its plane does not declare, and a
/// report site nobody listed, must find both.
#[test]
fn an_undeclared_class_and_an_unlisted_site_are_both_red() {
    let root = root();
    let undeclared = [Site {
        plane: "a2a",
        file: "crates/busbar-a2a/src/a2a/receive.rs",
        shape: "usage_units: std::collections::BTreeMap::from(",
        occurrences: 1,
        // mcp's tool calls, reported by a2a — which declares only bytes.
        emits: &["busbar_plane_mcp::meta::CLASS_TOOL_CALLS"],
        dead: None,
    }];
    let found = vec![
        (
            "crates/busbar-a2a/src/a2a/receive.rs".to_string(),
            "usage_units: std::collections::BTreeMap::from(",
            1,
        ),
        (
            "crates/busbar-plane-a2a/src/new_site.rs".to_string(),
            "usage_units.insert(",
            1,
        ),
    ];
    let red = findings(&root, &undeclared, &found, &|_, _| 0);
    assert!(
        red.iter()
            .any(|f| f.contains("tool_calls") && f.contains("does not declare")),
        "{red:#?}"
    );
    assert!(red.iter().any(|f| f.contains("new_site.rs")), "{red:#?}");
}
