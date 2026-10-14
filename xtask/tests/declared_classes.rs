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
use std::path::PathBuf;

use xtask::ctx::{Ctx, WalkSpec};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the workspace")
        .to_path_buf()
}

/// The tree, as every gate reads it: the pinned planes laid at the directories they lived at
/// (`Ctx::with_pinned_planes`, ARCHITECT row 106 (A)), so a plane that left for its own repo is
/// scanned here exactly as it was when its crate lived in this tree.
fn cx() -> Ctx {
    Ctx::new(root())
        .and_then(|cx| cx.with_pinned_planes())
        .expect("the workspace opens with its pinned planes")
}

/// The crates whose non-test sources are scanned for report sites.
const SCANNED: &[&str] = &[
    "crates/busbar-plane-llm/src",
    "crates/busbar-plane-mcp/src",
    "crates/busbar-plane-a2a/src",
    "crates/busbar-plane-streaming/src",
    "crates/busbar-plane-decisions/src",
    "crates/busbar-llm/src",
    // `crates/busbar-mcp/src` STRUCK (P3 DEL-MCP, ARCHITECT 2026-10-05): the engine is deleted; the
    // mcp plane is `crates/busbar-plane-mcp/src`, scanned above. `crates/busbar-a2a/src` STRUCK the
    // same way (FLIP-A2A): the a2a plane is `crates/busbar-plane-a2a/src`, scanned above.
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
    ("llm", "crates/busbar-llm/src/lib.rs"),
    // mcp and a2a carry no row: each is door-only (P3 DEL-MCP; FLIP-A2A) and lists no site below.
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
    // The Meter step's billed map: the tiers above plus the tap's `Billing::Counted` classes,
    // FORWARDED verbatim — it mints no class of its own.
    Site {
        plane: "llm",
        file: "crates/busbar-llm/src/unit/meter.rs",
        shape: "usage_units.entry(",
        occurrences: 1,
        emits: &[],
        dead: None,
    },
    // The engine's `busbar-mcp/src/mcp/method.rs` report site is STRUCK with its crate (P3 DEL-MCP,
    // ARCHITECT 2026-10-05). The mcp door reports through none of the SHAPES above (a door plane
    // bills through the plane driver's money seam), so it lists no site here; were it to grow one,
    // COMPLETENESS reds until it is listed, with a declaration row for its plane.
    //
    // a2a has no site here since FLIP-A2A deleted `busbar-a2a` (its one was the engine's
    // `a2a/receive.rs`): the plane's door reports its usage by INDEX into its own declared
    // `BILLABLE_CLASSES` (`busbar-plane-a2a/src/door.rs`), through no shape above, so no
    // undeclared class can be named there. A shape appearing under `busbar-plane-a2a/src` is
    // still RED here until it is listed.
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

/// Every non-test `.rs` file under `dir` (repo-relative), read through the tree `cx` shows. A
/// directory the tree has not got contributes nothing.
fn sources(cx: &Ctx, dir: &str, out: &mut Vec<String>) {
    let Ok(listed) = cx.list(&WalkSpec::new([dir]).ext("rs").allow_empty()) else {
        return;
    };
    for path in listed {
        let rel = path.to_string_lossy().replace('\\', "/");
        let below = rel.strip_prefix(&format!("{dir}/")).unwrap_or(&rel);
        let mut parts: Vec<&str> = below.split('/').collect();
        let name = parts.pop().unwrap_or("");
        if parts.iter().any(|d| *d == "tests" || *d == "fixtures") {
            continue;
        }
        if name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs" {
            out.push(rel);
        }
    }
}

/// The literal a constant path names, read off the file that defines it:
/// `busbar_plane_mcp::tool_meta::CLASS_BYTES` is `crates/busbar-plane-mcp/src/tool_meta.rs`'s
/// `const CLASS_BYTES: … = MeterClassId::new("bytes")` (or `= "bytes"`).
fn resolve(cx: &Ctx, path: &str) -> Result<String, String> {
    let (file, src, name) = defining(cx, path)?;
    literal_of(&src, name).ok_or_else(|| format!("{path}: no `const {name}` literal in {file:?}"))
}

/// The file that defines the item a constant path names, its text, and the item's name.
fn defining<'p>(cx: &Ctx, path: &'p str) -> Result<(PathBuf, String, &'p str), String> {
    let segments: Vec<&str> = path.split("::").collect();
    let (krate, rest) = segments.split_first().ok_or("an empty path")?;
    let (name, modules) = rest.split_last().ok_or("a path with no constant")?;
    let dir = PathBuf::from("crates")
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
        .find(|f| cx.exists(f))
        .ok_or_else(|| format!("{path}: no defining file among {candidates:?}"))?;
    let src = cx.read(file).map_err(|e| format!("{path}: {e}"))?;
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
fn declared(cx: &Ctx, plane: &str) -> Result<BTreeSet<String>, String> {
    let (_, file) = DECLARATIONS
        .iter()
        .find(|(p, _)| *p == plane)
        .ok_or_else(|| format!("no declaration file for plane {plane}"))?;
    let src = cx.read(file).map_err(|e| format!("{file}: {e}"))?;
    let start = src
        .find("billable_classes: &")
        .ok_or_else(|| format!("{file}: no billable_classes"))?;
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
        for class in open_classes(cx, &format!("{module}::OPEN_CLASSES"))? {
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
            resolve(cx, expr)?
        });
    }
    Ok(classes)
}

/// The class of every `(CLASS, family)` row of the `&[(&str, &str)]` table `path` names, each
/// resolved off the table's own file.
fn open_classes(cx: &Ctx, path: &str) -> Result<Vec<String>, String> {
    let (file, src, name) = defining(cx, path)?;
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
                    resolve(cx, &format!("{krate}::{import}"))?
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
    cx: &Ctx,
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
        let declared = match declared(cx, site.plane) {
            Ok(d) => d,
            Err(e) => {
                out.push(e);
                continue;
            }
        };
        for path in site.emits {
            match resolve(cx, path) {
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
fn scan(cx: &Ctx) -> (Found, Vec<(String, String)>) {
    let mut files = Vec::new();
    for dir in SCANNED {
        sources(cx, dir, &mut files);
    }
    files.sort();
    let mut found = Vec::new();
    let mut texts = Vec::new();
    for rel in files {
        let Ok(src) = cx.read(&rel) else {
            continue;
        };
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
    let cx = cx();
    let (found, texts) = scan(&cx);
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
    let findings = findings(&cx, SITES, &found, &callers_of);
    assert!(findings.is_empty(), "{findings:#?}");
}

/// THE RED ARM: the same check, fed a site that reports a class its plane does not declare, and a
/// report site nobody listed, must find both.
#[test]
fn an_undeclared_class_and_an_unlisted_site_are_both_red() {
    let cx = cx();
    let undeclared = [Site {
        plane: "llm",
        file: "crates/busbar-plane-llm/src/codec/wire_shim.rs",
        shape: "usage_units.insert(",
        occurrences: 1,
        // mcp's tool calls, reported by llm — which declares only the token tiers.
        emits: &["busbar_plane_mcp::tool_meta::CLASS_TOOL_CALLS"],
        dead: None,
    }];
    let found = vec![
        (
            "crates/busbar-plane-llm/src/codec/wire_shim.rs".to_string(),
            "usage_units.insert(",
            1,
        ),
        (
            "crates/busbar-plane-a2a/src/new_site.rs".to_string(),
            "usage_units.insert(",
            1,
        ),
    ];
    let red = findings(&cx, &undeclared, &found, &|_, _| 0);
    assert!(
        red.iter()
            .any(|f| f.contains("tool_calls") && f.contains("does not declare")),
        "{red:#?}"
    );
    assert!(red.iter().any(|f| f.contains("new_site.rs")), "{red:#?}");
}

/// THE PINNED PLANES ARE READ, NOT SKIPPED (ARCHITECT row 106 (A), condition 3): the scan reads a
/// pinned plane's sources through the BASE layer, and the same scan with the base removed reads
/// none of them. A scan that quietly read nothing there would hold every class of that plane to
/// nothing and stay green.
#[test]
fn the_scan_reads_the_pinned_planes_and_reads_none_without_the_base() {
    let cx = cx();
    let base = cx
        .base()
        .expect("the workspace pins a plane, laid as the base layer");
    let laid = |file: &str| base.paths().any(|p| p.to_string_lossy() == file);
    let (_, with) = scan(&cx);
    let pinned: Vec<&String> = with.iter().map(|(f, _)| f).filter(|f| laid(f)).collect();
    assert!(
        !pinned.is_empty(),
        "the scan read no source of a pinned plane: {SCANNED:?} names none of the base's crates"
    );
    let (_, without) = scan(&cx.without_base());
    let still: Vec<&String> = without.iter().map(|(f, _)| f).filter(|f| laid(f)).collect();
    assert!(
        still.is_empty(),
        "with the base removed the scan still read {still:?}: the pinned plane is not read through \
         the base"
    );
}
