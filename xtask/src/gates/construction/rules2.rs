//! THE KIND, CEILING AND MONEY RULES: the section 1.1 LOC ceilings by call graph, the section 1.2
//! manifest allow-list and source denylist, the sealed traits, the hold discipline, the capability
//! seal sites, and the plane/price wall.
//!
//! The second half of the `scripts/construction-gate/rules.py` port. Same contract as its sibling:
//! every `detail` column is the Python's, verbatim, because that is what parity compares.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::gates::construction::model::{need_int, need_str, plain, py_list, CRow, Cfg, VACUOUS};
use crate::gates::construction::rules::call_sites;
use crate::gates::construction::tree::{
    crate_name_of_dir, dirs_for_globs, fnmatch, read_cargo_deps_text, Tree,
};
use crate::rx::{self, Regex};
use crate::toml_doc::Table;

fn basename(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join("; ")
    }
}

fn head(items: &[String], n: usize) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.iter().take(n).cloned().collect::<Vec<_>>().join("; ")
    }
}

/// Every scanned file whose path matches one of the globs, in path order. `fnmatch`'s `*` crosses
/// directory separators, so `crates/busbar-unit-*/src/*` reaches nested modules too.
fn scoped_files(tree: &Tree, globs: &[String]) -> Vec<String> {
    tree.files
        .keys()
        .filter(|rel| globs.iter().any(|g| fnmatch(rel, g)))
        .cloned()
        .collect()
}

fn kind_crate_dirs(cx: &Ctx, cfg: &Cfg, kind: &str) -> Vec<String> {
    dirs_for_globs(cx, &cfg.kind_globs(kind))
}

// ── 14. loc-ceilings ─────────────────────────────────────────────────────────────────────────────

pub fn loc_ceilings(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("loc-ceilings")?;
    let kernel_crate = need_str(c, "kernel_crate", "loc-ceilings")?;
    let kernel_ceiling = need_int(c, "kernel_ceiling", "loc-ceilings")?;
    let caps_crate = need_str(c, "caps_crate", "loc-ceilings")?;
    let contract_crate = need_str(c, "contract_crate", "loc-ceilings")?;
    let caps_contract_ceiling = need_int(c, "caps_contract_ceiling", "loc-ceilings")?;
    let unit_glob = need_str(c, "unit_crate_glob", "loc-ceilings")?;
    let unit_total_ceiling = need_int(c, "unit_total_ceiling", "loc-ceilings")?;
    let verbs_crate = need_str(c, "verbs_crate", "loc-ceilings")?;
    let verbs_ceiling = need_int(c, "verbs_ceiling", "loc-ceilings")?;
    let union_ceiling = need_int(c, "union_ceiling", "loc-ceilings")?;
    let teller_file_names = c.list_of("teller_files");

    // SURFACE lines only, per the owner's counting decision: non-blank, non-comment lines under
    // src/, excluding `#[cfg(test)]` module bodies and `src/tests/**`.
    let loc = |rel: &str| -> i64 {
        tree.files
            .get(rel)
            .map(|ls| {
                ls.iter()
                    .filter(|l| !l.intest && !l.code.trim().is_empty())
                    .count() as i64
            })
            .unwrap_or(0)
    };
    let crate_total = |name: &str| -> i64 { tree.crate_files(name).iter().map(|r| loc(r)).sum() };

    let unit_dirs = dirs_for_globs(cx, &[format!("crates/{unit_glob}")]);
    let unit_crates: Vec<String> = unit_dirs.iter().map(|d| crate_name_of_dir(d)).collect();

    let kernel_files_all = tree.crate_files(kernel_crate);
    let teller_files: Vec<&String> = kernel_files_all
        .iter()
        .filter(|rel| teller_file_names.iter().any(|n| n == basename(rel)))
        .collect();
    let local_kernel_fns: BTreeSet<&str> = kernel_files_all
        .iter()
        .flat_map(|rel| tree.fns.get(rel).into_iter().flat_map(|v| v.iter()))
        .map(|f| f.name.as_str())
        .collect();
    let call_rx = Regex::new(r"(?<![A-Za-z0-9_.:])([a-z_][A-Za-z0-9_]*)\s*\(")?;
    let mut called_names: BTreeSet<String> = BTreeSet::new();
    for rel in &teller_files {
        for l in tree.files[rel.as_str()].iter() {
            if l.intest {
                continue;
            }
            for m in call_rx.find_iter(l.code_bytes()) {
                if let Some(nm) = m.str_of(l.code_bytes(), 1) {
                    if !local_kernel_fns.contains(nm.as_str()) && nm.len() >= 4 {
                        called_names.insert(nm);
                    }
                }
            }
        }
    }
    let mut extra_files: BTreeSet<String> = BTreeSet::new();
    let mut extra_hits: BTreeSet<String> = BTreeSet::new();
    for cr in &unit_crates {
        for rel in tree.crate_files(cr) {
            for f in tree.fns.get(&rel).into_iter().flat_map(|v| v.iter()) {
                if !f.intest && called_names.contains(&f.name) {
                    extra_files.insert(rel.clone());
                    extra_hits.insert(f.name.clone());
                }
            }
        }
    }
    let extra_loc: i64 = extra_files.iter().map(|r| loc(r)).sum();
    let kernel_own = crate_total(kernel_crate);
    let kernel_total = kernel_own + extra_loc;

    let mut rows = Vec::new();
    let offenders: Vec<String> = extra_files
        .iter()
        .take(10)
        .map(|rel| {
            let here: BTreeSet<&str> = tree
                .fns
                .get(rel)
                .into_iter()
                .flat_map(|v| v.iter())
                .map(|f| f.name.as_str())
                .collect();
            let shared: Vec<&str> = extra_hits
                .iter()
                .filter(|n| here.contains(n.as_str()))
                .map(String::as_str)
                .collect();
            format!(
                "{rel} ({} lines) shares a name with a call from {}: {}",
                loc(rel),
                py_list(&teller_file_names),
                shared.join(", ")
            )
        })
        .collect();
    rows.push(plain(
        "loc-ceilings:kernel",
        kernel_total <= kernel_ceiling,
        "busbar-kernel (own files + call-graph-reachable busbar-unit-* files) stays within its LOC \
         ceiling",
        format!(
            "{kernel_own} own + {extra_loc} reachable-by-name in {} busbar-unit-* file(s) = \
             {kernel_total} (ceiling {kernel_ceiling}); reachability is a NAME-MATCH approximation \
             (see rule why), never a true call graph",
            extra_files.len()
        ),
        kernel_total,
        kernel_ceiling,
        offenders,
    ));

    for (key, spec) in cfg.doc.children("rules.loc-ceilings.kernel_files") {
        let patterns = spec.list_of("patterns");
        let ceiling = need_int(spec, "ceiling", "loc-ceilings.kernel_files")?;
        let label = need_str(spec, "label", "loc-ceilings.kernel_files")?;
        let matched: Vec<String> = kernel_files_all
            .iter()
            .filter(|rel| patterns.iter().any(|p| p == basename(rel)))
            .cloned()
            .collect();
        let cur: i64 = matched.iter().map(|r| loc(r)).sum();
        let note = if matched.is_empty() {
            " -- no matching file under busbar-kernel/src yet (vacuous 0)"
        } else {
            ""
        };
        rows.push(plain(
            format!("loc-ceilings:kernel:{key}"),
            cur <= ceiling,
            format!("busbar-kernel's {label} stays within its LOC ceiling"),
            format!(
                "{label} ({}): {cur} line(s) (ceiling {ceiling}){note}",
                patterns.join(", ")
            ),
            cur,
            ceiling,
            matched,
        ));
    }

    let caps = crate_total(caps_crate);
    let contract = crate_total(contract_crate);
    let caps_contract = caps + contract;
    rows.push(plain(
        "loc-ceilings:caps-contract",
        caps_contract <= caps_contract_ceiling,
        format!("{caps_crate} + {contract_crate} together stay within their LOC ceiling"),
        format!(
            "{caps_crate} {caps} + {contract_crate} {contract} = {caps_contract} (ceiling \
             {caps_contract_ceiling})"
        ),
        caps_contract,
        caps_contract_ceiling,
        vec![],
    ));

    let mut per_unit: Vec<(i64, String)> = unit_crates
        .iter()
        .map(|cr| (crate_total(cr), cr.clone()))
        .collect();
    per_unit.sort_by(|a, b| b.cmp(a));
    let unit_total: i64 = per_unit.iter().map(|(n, _)| n).sum();
    rows.push(plain(
        "loc-ceilings:unit-total",
        unit_total <= unit_total_ceiling,
        "all busbar-unit-* crates together stay within their LOC ceiling",
        format!(
            "{} busbar-unit-* crate(s), {unit_total} line(s) total (ceiling {unit_total_ceiling})",
            unit_crates.len()
        ),
        unit_total,
        unit_total_ceiling,
        per_unit
            .iter()
            .take(8)
            .map(|(n, cr)| format!("{cr}: {n}"))
            .collect(),
    ));

    let has_verbs = unit_crates.iter().any(|c| c == verbs_crate);
    let verbs_total = if has_verbs {
        crate_total(verbs_crate)
    } else {
        0
    };
    let note = if has_verbs {
        String::new()
    } else {
        format!(" -- {verbs_crate} does not exist yet (vacuous 0)")
    };
    rows.push(plain(
        "loc-ceilings:unit-verbs",
        verbs_total <= verbs_ceiling,
        format!("{verbs_crate} stays within its LOC ceiling"),
        format!("{verbs_crate}: {verbs_total} line(s) (ceiling {verbs_ceiling}){note}"),
        verbs_total,
        verbs_ceiling,
        vec![],
    ));

    let union_total = kernel_total + caps_contract + unit_total;
    rows.push(plain(
        "loc-ceilings:union",
        union_total <= union_ceiling,
        "the kernel + caps/contract + unit-* union stays within its LOC ceiling",
        format!(
            "kernel {kernel_total} + caps/contract {caps_contract} + unit-* {unit_total} = \
             {union_total} (ceiling {union_ceiling}); a call-graph-reachable unit file counts once \
             here AND once in its own crate's unit-total, so this sum over-counts rather than \
             hides an overage"
        ),
        union_total,
        union_ceiling,
        vec![],
    ));
    Ok(rows)
}

// ── 15. manifest-allowlist ───────────────────────────────────────────────────────────────────────

pub fn manifest_allowlist(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("manifest-allowlist")?;
    let kinds = [
        "plane",
        "store",
        "pure_auth",
        "hook",
        "export",
        "secret",
        "egress_auth",
    ];
    let unit_names: BTreeSet<String> = match cfg.rule("loc-ceilings") {
        Ok(lc) => dirs_for_globs(
            cx,
            &[format!(
                "crates/{}",
                lc.str_of("unit_crate_glob").unwrap_or("")
            )],
        )
        .iter()
        .map(|d| crate_name_of_dir(d))
        .collect(),
        Err(_) => BTreeSet::new(),
    };
    let mut plane_names: BTreeSet<String> = cfg.plane_crates()?.into_iter().collect();
    plane_names.extend(
        kind_crate_dirs(cx, cfg, "plane")
            .iter()
            .map(|d| crate_name_of_dir(d)),
    );
    let transport_names: BTreeSet<String> = kind_crate_dirs(cx, cfg, "transport")
        .iter()
        .map(|d| crate_name_of_dir(d))
        .collect();
    // The contract, and the closed grammar the contract is written on and re-exports as `spans`.
    let mut global_ok: BTreeSet<String> = c.list_of("reviewed_allowlist").into_iter().collect();
    global_ok.insert("busbar-contract".to_string());
    global_ok.insert("busbar-grammar".to_string());
    let extra = cfg
        .doc
        .table_or_empty("rules.manifest-allowlist.reviewed_extra");
    let known_red = cfg
        .doc
        .table_or_empty("rules.manifest-allowlist.known_red_deps");

    let mut rows = Vec::new();
    let mut seen_dirs: Vec<(&str, String)> = Vec::new();
    for kind in kinds {
        for d in kind_crate_dirs(cx, cfg, kind) {
            seen_dirs.push((kind, d));
        }
    }
    for (kind, d) in seen_dirs {
        let crate_name = crate_name_of_dir(&d);
        let deps = read_cargo_deps_text(&cx.read(format!("{d}/Cargo.toml")).unwrap_or_default());
        let mut ok = global_ok.clone();
        ok.extend(extra.list_of(&crate_name));
        let tracked: Vec<String> = known_red.list_of(&crate_name);
        let (mut red, mut tracked_red, mut unreviewed) = (Vec::new(), Vec::new(), Vec::new());
        for dep in deps {
            let is_red = dep == "busbar-kernel"
                || dep == "busbar-caps"
                || unit_names.contains(&dep)
                || (plane_names.contains(&dep) && dep != crate_name)
                || transport_names.contains(&dep);
            if is_red && tracked.contains(&dep) {
                tracked_red.push(dep);
            } else if is_red {
                red.push(dep);
            } else if !ok.contains(&dep) {
                unreviewed.push(dep);
            }
        }
        let current = (red.len() + unreviewed.len()) as i64;
        let mut parts = Vec::new();
        if !red.is_empty() {
            parts.push(format!(
                "RED (kernel/caps/unit/plane/transport): {}",
                red.join(", ")
            ));
        }
        if !unreviewed.is_empty() {
            parts.push(format!(
                "not on the reviewed list: {}",
                unreviewed.join(", ")
            ));
        }
        if !tracked_red.is_empty() {
            parts.push(format!(
                "tracked migration debt (qa/construction.toml known_red_deps): {}",
                tracked_red.join(", ")
            ));
        }
        let detail = format!(
            "{crate_name} ({kind}): {}",
            if parts.is_empty() {
                "every dependency is busbar-contract or reviewed".to_string()
            } else {
                parts.join("; ")
            }
        );
        let mut offenders = red;
        offenders.extend(unreviewed);
        rows.push(plain(
            format!("manifest-allowlist:{crate_name}"),
            current == 0,
            format!("{crate_name} depends only on busbar-contract plus reviewed crates"),
            detail,
            current,
            0,
            offenders,
        ));
    }
    if rows.is_empty() {
        rows.push(plain(
            "manifest-allowlist",
            true,
            "depends only on busbar-contract plus reviewed crates",
            "vacuous: no plugin-kind crate exists yet under gate.plugin_kinds",
            0,
            0,
            vec![],
        ));
    }
    let _ = tree;
    Ok(rows)
}

// ── 16. source-denylist ──────────────────────────────────────────────────────────────────────────

pub fn source_denylist(
    cx: &Ctx,
    tree: &Tree,
    cfg: &Cfg,
    xtask_hits: Option<&BTreeMap<String, Vec<String>>>,
) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("source-denylist")?;
    let patterns = c.list_of("patterns");
    let pat_rx = Regex::new(
        &patterns
            .iter()
            .map(|p| rx::escape(p))
            .collect::<Vec<_>>()
            .join("|"),
    )?;
    let allow = cfg.doc.table_or_empty("rules.source-denylist.allowlist");
    // `None` = the transitive-closure half never answered. Every row then says so and is RED: an
    // unproven half of an invariant is not a met one.
    let unproven = xtask_hits.is_none();

    let mut rows = Vec::new();
    let mut seen: Vec<(String, String)> = Vec::new();
    for kind in c.list_of("kinds") {
        for d in kind_crate_dirs(cx, cfg, &kind) {
            seen.push((kind.clone(), d));
        }
    }
    for (kind, d) in seen {
        let crate_name = crate_name_of_dir(&d);
        let allowed_here = allow.list_of(&crate_name);
        let mut offenders = Vec::new();
        for rel in tree.crate_files(&crate_name) {
            for l in tree.files[&rel].iter() {
                if l.intest {
                    continue;
                }
                if let Some(m) = pat_rx.search(l.code_bytes()) {
                    let hit = m.str_of(l.code_bytes(), 0).unwrap_or_default();
                    if !allowed_here.contains(&hit) {
                        offenders.push(format!("`{hit}` at {rel}:{}", l.no));
                    }
                }
            }
        }
        match xtask_hits {
            None => offenders.push(
                "UNPROVEN: `cargo xtask denylist` did not answer, so no transitive dependency was \
                 checked (reason on stderr)"
                    .to_string(),
            ),
            Some(h) => offenders.extend(h.get(&crate_name).cloned().unwrap_or_default()),
        }
        let current = offenders.len() as i64;
        let detail = format!(
            "{crate_name} ({kind}): {current} denylisted path(s)/transitive dep(s) (ceiling 0): {}",
            head(&offenders, 5)
        );
        rows.push(plain(
            format!("source-denylist:{crate_name}"),
            current == 0,
            format!("{crate_name} performs no I/O of its own (pure kind)"),
            detail,
            current,
            0,
            offenders,
        ));
    }
    if rows.is_empty() {
        rows.push(plain(
            "source-denylist",
            true,
            "pure kinds perform no I/O of their own",
            "vacuous: no plane/hook/pure-auth/egress-auth crate exists yet",
            0,
            0,
            vec![],
        ));
    }
    let _ = unproven;
    Ok(rows)
}

// ── 17. lean-core ────────────────────────────────────────────────────────────────────────────────

pub fn lean_core(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("lean-core")?;
    let max_hits = need_int(c, "max_hits", "lean-core")?;
    let words = c.list_of("words");
    let word_rx = Regex::new(&format!(
        r"(?i)\b({})\b",
        words
            .iter()
            .map(|w| rx::escape(w))
            .collect::<Vec<_>>()
            .join("|")
    ))?;
    let mut crates = c.list_of("crates_kernel");
    let glob = need_str(c, "crate_glob", "lean-core")?;
    crates.extend(
        dirs_for_globs(cx, &[format!("crates/{glob}")])
            .iter()
            .map(|d| crate_name_of_dir(d)),
    );

    let mut offenders = Vec::new();
    for crate_name in &crates {
        for rel in tree.crate_files(crate_name) {
            for l in tree.files[&rel].iter() {
                if l.intest {
                    continue;
                }
                for (_, (bs, be)) in tree.lexer.string_literals(&l.code) {
                    let content = &l.code.as_bytes()[bs..be];
                    if word_rx.is_match(content) {
                        offenders.push(format!(
                            "\"{}\" at {rel}:{}",
                            String::from_utf8_lossy(content),
                            l.no
                        ));
                    }
                }
            }
        }
    }
    let current = offenders.len() as i64;
    let detail = format!(
        "{current} string literal(s) in {} naming a dialect or the section 1.3 pinned word list \
         (ceiling {max_hits}): {}",
        py_list(&crates),
        head(&offenders, 8)
    );
    Ok(vec![plain(
        "lean-core",
        current <= max_hits,
        "the kernel and unit crates name no dialect and no open-vocabulary word",
        detail,
        current,
        max_hits,
        offenders,
    )])
}

// ── 18. no-default-bodies ────────────────────────────────────────────────────────────────────────

/// `(start_line, end_line)` of `trait <name>` in `rel`, by brace matching on the blanked text.
fn trait_span(tree: &Tree, rel: &str, name: &str) -> Result<Option<(usize, usize)>, String> {
    let Some(lines) = tree.files.get(rel) else {
        return Ok(None);
    };
    let joined: String = lines
        .iter()
        .map(|l| l.blank.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let text = joined.as_bytes();
    let rx_trait = Regex::new(&format!(
        r"trait\s+{}(?![A-Za-z0-9_])[^{{]*\{{",
        rx::escape(name)
    ))?;
    let Some(m) = rx_trait.search(text) else {
        return Ok(None);
    };
    let mut starts = Vec::with_capacity(lines.len());
    let mut off = 0usize;
    for l in lines.iter() {
        starts.push(off);
        off += l.blank.len() + 1;
    }
    let line_of = |pos: usize| -> usize {
        match starts.binary_search(&pos) {
            Ok(i) => i + 1,
            Err(0) => 1,
            Err(i) => i,
        }
    };
    let mut depth: i64 = 0;
    let mut i = m.end - 1;
    let mut end: i64 = -1;
    while i < text.len() {
        match text[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i as i64;
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if end < 0 {
        return Ok(None);
    }
    Ok(Some((line_of(m.start), line_of(end as usize))))
}

pub fn no_default_bodies(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("no-default-bodies")?;
    let max_defaulted = need_int(c, "max_defaulted", "no-default-bodies")?;
    // The three declaring files, in the order the ceilings file names them. Each configured trait
    // lives in exactly one of them, so the order decides nothing; it is fixed anyway, because a
    // rule whose answer depends on a hash order is a rule that can change without an edit.
    let files = [
        need_str(c, "file", "no-default-bodies")?,
        need_str(c, "plane_file", "no-default-bodies")?,
        need_str(c, "transport_file", "no-default-bodies")?,
    ];
    let (mut offenders, mut missing) = (Vec::new(), Vec::new());
    for name in c.list_of("traits") {
        let mut found: Option<(&str, (usize, usize))> = None;
        for rel in files {
            if let Some(span) = trait_span(tree, rel, &name)? {
                found = Some((rel, span));
                break;
            }
        }
        let Some((home, (start, end))) = found else {
            missing.push(name);
            continue;
        };
        for f in tree.fns.get(home).into_iter().flat_map(|v| v.iter()) {
            if start <= f.start && f.start <= end && !f.intest {
                offenders.push(format!(
                    "{name}::{} has a default body at {home}:{}",
                    f.name, f.start
                ));
            }
        }
    }
    let current = offenders.len() as i64;
    let detail = format!(
        "{current} defaulted kind-trait method(s) (ceiling {max_defaulted}): {}{}",
        join_or_none(&offenders),
        if missing.is_empty() {
            String::new()
        } else {
            format!("; trait(s) not found yet: {}", py_list(&missing))
        }
    );
    Ok(vec![plain(
        "no-default-bodies",
        current <= max_defaulted,
        "every kind-trait method is bodiless; implementing the trait is the only way to answer it",
        detail,
        current,
        max_defaulted,
        offenders,
    )])
}

// ── 19. sealed-unit-traits ───────────────────────────────────────────────────────────────────────

pub fn sealed_unit_traits(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("sealed-unit-traits")?;
    let max_unsealed = need_int(c, "max_unsealed", "sealed-unit-traits")?;
    let seal_word = Regex::new(r"[Ss]eal")?;
    let (mut offenders, mut checked) = (Vec::new(), Vec::new());
    for (_key, spec) in cfg.doc.children("rules.sealed-unit-traits.traits") {
        let rel = need_str(spec, "file", "sealed-unit-traits.traits")?;
        let trait_name = need_str(spec, "trait", "sealed-unit-traits.traits")?;
        let crate_name = need_str(spec, "crate", "sealed-unit-traits.traits")?;
        let Some(lines) = tree.files.get(rel) else {
            continue;
        };
        let joined: String = lines
            .iter()
            .map(|l| l.blank.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let rx_trait = Regex::new(&format!(
            r"trait\s+{}(?![A-Za-z0-9_])[^{{]*\{{",
            rx::escape(trait_name)
        ))?;
        let Some(m) = rx_trait.search(joined.as_bytes()) else {
            continue;
        };
        checked.push(trait_name.to_string());
        let header = &joined.as_bytes()[m.start..m.end];
        if !seal_word.is_match(header) {
            offenders.push(format!(
                "{crate_name}::{trait_name} has no private-supertrait seal ({rel})"
            ));
        }
    }
    let current = offenders.len() as i64;
    let detail = if checked.is_empty() {
        "vacuous: none of the configured unit traits exist in this tree yet".to_string()
    } else {
        format!(
            "{current} of {} configured unit trait(s) unsealed (ceiling {max_unsealed}): {}",
            checked.len(),
            join_or_none(&offenders)
        )
    };
    Ok(vec![plain(
        "sealed-unit-traits",
        current <= max_unsealed,
        "a unit's kernel-facing trait is sealed on a private supertrait",
        detail,
        current,
        max_unsealed,
        offenders,
    )])
}

// ── 20. hold-discipline ──────────────────────────────────────────────────────────────────────────

pub fn hold_discipline(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("hold-discipline")?;
    let mut crates = c.list_of("scope_crates_kernel");
    let glob = need_str(c, "scope_crate_glob", "hold-discipline")?;
    crates.extend(
        dirs_for_globs(cx, &[format!("crates/{glob}")])
            .iter()
            .map(|d| crate_name_of_dir(d)),
    );
    let files: Vec<String> = crates.iter().flat_map(|cr| tree.crate_files(cr)).collect();
    let take_rx = Regex::new(need_str(c, "take_pattern", "hold-discipline")?)?;
    let settle_rx = Regex::new(need_str(c, "settle_pattern", "hold-discipline")?)?;
    let return_rx = Regex::new(r"\breturn\b")?;
    let mut rows = Vec::new();

    // (a) no `?` / early `return` between a take and its settle, in the same function.
    let mut early_exit = Vec::new();
    for rel in &files {
        for f in tree.fns.get(rel).into_iter().flat_map(|v| v.iter()) {
            if f.intest {
                continue;
            }
            let body = &tree.files[rel][f.start - 1..f.end];
            let take_i = body.iter().position(|l| take_rx.is_match(l.code_bytes()));
            let settle_i = body.iter().position(|l| settle_rx.is_match(l.code_bytes()));
            let (Some(take_i), Some(settle_i)) = (take_i, settle_i) else {
                continue;
            };
            if settle_i <= take_i {
                continue;
            }
            for l in &body[take_i..settle_i] {
                if l.blank.contains('?') || return_rx.is_match(l.code_bytes()) {
                    early_exit.push(format!("{} at {rel}:{}", f.name, l.no));
                }
            }
        }
    }
    let max_early = need_int(c, "max_early_exit", "hold-discipline")?;
    let any_take = files
        .iter()
        .flat_map(|rel| tree.files[rel].iter())
        .any(|l| take_rx.is_match(l.code_bytes()));
    rows.push(plain(
        "hold-discipline:no-early-exit",
        early_exit.len() as i64 <= max_early,
        "no `?` or early return between a Hold take and its settle",
        if any_take {
            format!(
                "{} finding(s) (ceiling {max_early}): {}",
                early_exit.len(),
                join_or_none(&early_exit)
            )
        } else {
            format!("{VACUOUS}no take/settle pair found in scope")
        },
        early_exit.len() as i64,
        max_early,
        early_exit,
    ));

    // (b) no Hold captured in a catch_unwind closure — an over-approximation, stated honestly.
    let hold_word = need_str(c, "hold_word", "hold-discipline")?;
    let hold_rx = Regex::new(&format!(
        "(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])",
        rx::escape(hold_word)
    ))?;
    let catch_rx = Regex::new(need_str(c, "catch_unwind_pattern", "hold-discipline")?)?;
    let catch_sites = tree.grep(&catch_rx, true, None);
    let mut captured = Vec::new();
    for (rel, l) in &catch_sites {
        let Some(f) = tree.enclosing_fn(rel, l.no) else {
            continue;
        };
        let body: String = tree.files[*rel][f.start - 1..f.end]
            .iter()
            .map(|x| x.code.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if hold_rx.is_match_str(&body) {
            captured.push(format!("{} at {rel}:{}", f.name, l.no));
        }
    }
    let max_catch = need_int(c, "max_catch_unwind_capture", "hold-discipline")?;
    rows.push(plain(
        "hold-discipline:no-catch-unwind-capture",
        captured.len() as i64 <= max_catch,
        "no `Hold` is captured in a `catch_unwind` closure",
        if catch_sites.is_empty() {
            format!("{VACUOUS}no catch_unwind site found in scope")
        } else {
            format!(
                "{} finding(s) (ceiling {max_catch}): {}",
                captured.len(),
                join_or_none(&captured)
            )
        },
        captured.len() as i64,
        max_catch,
        captured,
    ));

    // (c) no JoinHandle::abort, and (d) no mem::forget/drop of a value named like a hold.
    for (id, pat_key, ceil_key, title) in [
        (
            "hold-discipline:no-join-abort",
            "abort_pattern",
            "max_join_abort",
            "no `JoinHandle::abort` in scope",
        ),
        (
            "hold-discipline:no-forget-or-drop",
            "forget_or_drop_pattern",
            "max_forget_or_drop",
            "no `mem::forget`/`drop(...)` of a value named like a Hold",
        ),
    ] {
        let rx_pat = Regex::new(need_str(c, pat_key, "hold-discipline")?)?;
        let hits: Vec<String> = tree
            .grep(&rx_pat, true, Some(&files))
            .into_iter()
            .map(|(rel, l)| format!("{rel}:{}", l.no))
            .collect();
        let ceiling = need_int(c, ceil_key, "hold-discipline")?;
        rows.push(plain(
            id,
            hits.len() as i64 <= ceiling,
            title,
            format!(
                "{} finding(s) (ceiling {ceiling}): {}",
                hits.len(),
                join_or_none(&hits)
            ),
            hits.len() as i64,
            ceiling,
            hits,
        ));
    }

    // (e) a cancellation-token check before every `.await` in the route step.
    let cancel_rx = Regex::new(need_str(c, "cancel_check_pattern", "hold-discipline")?)?;
    let route_fns = c.list_of("route_step_functions");
    let mut uncancellable = Vec::new();
    let mut any_route_await = false;
    for rel in &files {
        for f in tree.fns.get(rel).into_iter().flat_map(|v| v.iter()) {
            if f.intest || !route_fns.contains(&f.name) {
                continue;
            }
            let mut seen_check = false;
            for l in &tree.files[rel][f.start - 1..f.end] {
                if cancel_rx.is_match(l.code_bytes()) {
                    seen_check = true;
                }
                if l.code.contains(".await") {
                    any_route_await = true;
                    if !seen_check {
                        uncancellable.push(format!("{} at {rel}:{}", f.name, l.no));
                    }
                }
            }
        }
    }
    let max_uncancellable = need_int(c, "max_uncancellable_await", "hold-discipline")?;
    rows.push(plain(
        "hold-discipline:cancellation-before-await",
        uncancellable.len() as i64 <= max_uncancellable,
        "a cancellation-token check precedes every `.await` in the route step",
        if any_route_await {
            format!(
                "{} `.await` in a route step with no prior cancellation check (ceiling \
                 {max_uncancellable}): {}",
                uncancellable.len(),
                join_or_none(&uncancellable)
            )
        } else {
            format!("{VACUOUS}no `.await` found inside a route-step function in scope")
        },
        uncancellable.len() as i64,
        max_uncancellable,
        uncancellable,
    ));
    Ok(rows)
}

// ── 21. kernel-seal-impls and forbid-unsafe ──────────────────────────────────────────────────────

/// The two legal spellings of one Rust module, read as one path.
///
/// `a/b/foo.rs` and `a/b/foo/mod.rs` are the SAME module; which one a module is written as depends
/// only on whether it has grown children yet. A ratchet that pins a file by its exact path would
/// otherwise let a pure module split — no seal edited, no site added — read as a pinned site
/// vanishing and a brand-new finding appearing in the same commit. Normalising the `mod.rs`
/// spelling onto the flat one makes a pin survive the split, and it makes the reverse impossible
/// too: a site cannot be re-pinned as new by moving the file the other way.
fn same_module(known: &str, rel: &str) -> bool {
    fn flat(path: &str) -> &str {
        path.strip_suffix("/mod.rs").unwrap_or(path)
    }
    let (k, r) = (flat(known), flat(rel));
    k == r || k.strip_suffix(".rs") == Some(r) || r.strip_suffix(".rs") == Some(k)
}

pub fn kernel_seal_impls(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("kernel-seal-impls")?;
    let allowed_root = need_str(c, "allowed_root", "kernel-seal-impls")?;
    let root = format!("{}/", allowed_root.trim_end_matches('/'));
    let max_sites = need_int(c, "max_sites", "kernel-seal-impls")?;
    let known = c.list_of("known_sites");
    let pat = Regex::new(need_str(c, "pattern", "kernel-seal-impls")?)?;

    let (mut offenders, mut tracked) = (Vec::new(), Vec::new());
    // Scans test code as well as production: every forging impl in the tree lives in a test module,
    // so a production-only reading would be vacuous by construction.
    for (rel, l) in tree.grep(&pat, false, None) {
        if rel.starts_with(root.as_str()) {
            continue;
        }
        let where_ = format!("{rel}:{}", l.no);
        if known.iter().any(|k| same_module(k, rel)) {
            tracked.push(where_);
        } else {
            offenders.push(where_);
        }
    }
    let current = offenders.len() as i64;
    let mut parts = Vec::new();
    if !offenders.is_empty() {
        parts.push(format!(
            "forging the contract's seal: {}",
            offenders.join("; ")
        ));
    }
    if !tracked.is_empty() {
        parts.push(format!(
            "tracked debt (qa/construction.toml known_sites): {}",
            tracked.join("; ")
        ));
    }
    let detail = format!(
        "{current} impl(s) of the contract's KernelSeal outside {allowed_root} (ceiling \
         {max_sites}): {}",
        join_or_none(&parts)
    );
    Ok(vec![plain(
        "kernel-seal-impls",
        current <= max_sites,
        "the contract's sealing trait is implemented only inside busbar-caps",
        detail,
        current,
        max_sites,
        offenders,
    )])
}

pub fn forbid_unsafe(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("forbid-unsafe")?;
    let forbid_rx = Regex::new(r"forbid\s*\(\s*unsafe_code\s*\)")?;
    let deny_rx = Regex::new(r"(forbid|deny)\s*\(\s*unsafe_code\s*\)")?;
    let mut rows = Vec::new();
    for (kinds_key, level, rid_prefix, label, missing_key, rx_pat) in [
        (
            "forbid_kinds",
            "forbid",
            "forbid-unsafe",
            "#![forbid(unsafe_code)]",
            "known_missing_forbid",
            &forbid_rx,
        ),
        (
            "deny_kinds",
            "deny",
            "forbid-unsafe-deny",
            "#![deny(unsafe_code)] (or stronger)",
            "known_missing_deny",
            &deny_rx,
        ),
    ] {
        let known_missing = c.list_of(missing_key);
        let mut seen = Vec::new();
        for kind in c.list_of(kinds_key) {
            seen.extend(kind_crate_dirs(cx, cfg, &kind));
        }
        let mut out = Vec::new();
        for d in seen {
            let crate_name = crate_name_of_dir(&d);
            let has_it = tree.crate_files(&crate_name).iter().any(|rel| {
                tree.files[rel]
                    .iter()
                    .any(|l| rx_pat.is_match(l.code_bytes()))
            });
            let current = i64::from(!has_it);
            let is_known = known_missing.contains(&crate_name);
            let ceiling = i64::from(is_known);
            let debt_note = if is_known {
                " (tracked debt, ratcheted in qa/construction.toml)"
            } else {
                ""
            };
            out.push(plain(
                format!("{rid_prefix}:{crate_name}"),
                current <= ceiling,
                format!("{crate_name} carries `#![{level}(unsafe_code)]`"),
                format!(
                    "{crate_name}: {} `{label}`{}",
                    if has_it { "present" } else { "MISSING" },
                    if has_it { "" } else { debt_note }
                ),
                current,
                ceiling,
                if has_it {
                    vec![]
                } else {
                    vec![format!("{crate_name}: missing {label}")]
                },
            ));
        }
        if out.is_empty() {
            out.push(plain(
                rid_prefix,
                true,
                format!("{label} present"),
                "vacuous: no crate of this kind exists yet",
                0,
                0,
                vec![],
            ));
        }
        rows.extend(out);
    }
    Ok(rows)
}

// ── 22/23. hold-escapes and seal-sites, one scan shared ──────────────────────────────────────────

fn symbol_table_scan(
    cx: &Ctx,
    tree: &Tree,
    cfg: &Cfg,
    rule: &str,
    title: &str,
    noun: &str,
) -> Result<Vec<CRow>, String> {
    let c = cfg.rule(rule)?;
    let max_sites = need_int(c, "max_sites", rule)?;
    let dirs = dirs_for_globs(cx, &c.list_of("scan_globs"));
    let mut files: Vec<String> = Vec::new();
    for d in &dirs {
        let prefix = format!("{d}/");
        files.extend(
            tree.files
                .keys()
                .filter(|rel| rel.starts_with(prefix.as_str()))
                .cloned(),
        );
    }
    let known = c.list_of("known_sites");

    let reviewed = |rel: &str, fname: &str| -> bool {
        known.iter().any(|entry| {
            if entry.ends_with('/') {
                rel.starts_with(entry.as_str())
            } else if let Some((path, want)) = entry.split_once("::") {
                rel == path && fname == want
            } else {
                rel == entry
            }
        })
    };

    let (mut offenders, mut tracked) = (Vec::new(), Vec::new());
    for (_key, spec) in cfg.doc.children(&format!("rules.{rule}.symbols")) {
        let symbol = need_str(spec, "symbol", rule)?;
        let because = need_str(spec, "because", rule)?;
        let confined: Vec<String> = spec.list_of("confined_to_paths");
        let sym_rx = Regex::new(&rx::escape(symbol))?;
        for (rel, l) in tree.grep(&sym_rx, true, Some(&files)) {
            // ANCHORED, and matched as a path prefix: `confined_to` is the busbar-caps fixture's
            // prose spelling and excuses any path containing those characters; the resolved
            // `confined_to_paths` excuses a file exactly, or a directory and everything under it.
            let here = confined.iter().any(|p| {
                let p = p.trim_end_matches('/');
                !p.is_empty() && (rel == p || rel.starts_with(&format!("{p}/")))
            });
            if here {
                continue;
            }
            let fname = tree
                .enclosing_fn(rel, l.no)
                .map_or(String::new(), |f| f.name.clone());
            let where_ = format!("`{symbol}` at {rel}:{} ({because})", l.no);
            if reviewed(rel, &fname) {
                tracked.push(where_);
            } else {
                offenders.push(where_);
            }
        }
    }
    let current = offenders.len() as i64;
    let mut parts = Vec::new();
    if !offenders.is_empty() {
        parts.push(offenders.join("; "));
    }
    if !tracked.is_empty() {
        parts.push(format!(
            "reviewed escapes (qa/construction.toml known_sites): {}",
            tracked.join("; ")
        ));
    }
    let detail = format!(
        "{current} {noun} in production source (ceiling {max_sites}): {}",
        join_or_none(&parts)
    );
    Ok(vec![plain(
        rule,
        current <= max_sites,
        title,
        detail,
        current,
        max_sites,
        offenders,
    )])
}

pub fn hold_escapes(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    symbol_table_scan(
        cx,
        tree,
        cfg,
        "hold-escapes",
        "no production source deliberately forgets, leaks or unwind-smuggles a hold",
        "deliberate hold escape(s)",
    )
}

pub fn seal_sites(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    symbol_table_scan(
        cx,
        tree,
        cfg,
        "seal-sites",
        "no production source outside its one reviewed home names a capability-minting symbol",
        "capability-minting symbol(s) out of place",
    )
}

// ── 24. secret-carrier-debug ─────────────────────────────────────────────────────────────────────

pub fn secret_carrier_debug(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("secret-carrier-debug")?;
    let max_derived = need_int(c, "max_derived", "secret-carrier-debug")?;
    let stop_rx = Regex::new(r"[};]|(?:^|[^A-Za-z0-9_])(?:struct|enum|fn)(?![A-Za-z0-9_])")?;
    let derive_rx = Regex::new(r"derive\s*\([^)]*\bDebug\b")?;

    let (mut offenders, mut checked) = (Vec::new(), 0usize);
    for name in c.list_of("carriers") {
        let decl_rx = Regex::new(&format!(
            r"(?:^|[^A-Za-z0-9_])(?:struct|enum)\s+{}(?![A-Za-z0-9_])",
            rx::escape(&name)
        ))?;
        for (rel, l) in tree.grep(&decl_rx, true, None) {
            checked += 1;
            let lines = &tree.files[rel];
            // Walk back over the attribute block sitting directly on the declaration. A blank line
            // (which is also what a doc comment strips to) or the end of the item above stops the
            // walk, so no other item's derives are read as this one's.
            let mut attrs: Vec<&str> = Vec::new();
            let mut i = l.no as i64 - 2;
            while i >= 0 {
                let above = lines[i as usize].code.trim();
                if above.is_empty() || stop_rx.is_match_str(above) {
                    break;
                }
                attrs.push(above);
                i -= 1;
            }
            attrs.reverse();
            if derive_rx.is_match_str(&attrs.join(" ")) {
                offenders.push(format!("`{name}` derives Debug at {rel}:{}", l.no));
            }
        }
    }
    let current = offenders.len() as i64;
    let detail = if checked == 0 {
        format!("{VACUOUS}no named secret carrier is declared in the scanned tree")
    } else {
        format!(
            "{current} secret carrier(s) with a derived Debug (ceiling {max_derived}): {}",
            join_or_none(&offenders)
        )
    };
    Ok(vec![plain(
        "secret-carrier-debug",
        current <= max_derived,
        "a type carrying secret bytes hand-rolls its Debug",
        detail,
        current,
        max_derived,
        offenders,
    )])
}

// ── 25. no-escaped-newline-doc-comment ───────────────────────────────────────────────────────────

pub fn no_escaped_newline_doc_comment(
    cx: &Ctx,
    tree: &Tree,
    cfg: &Cfg,
) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("no-escaped-newline-doc-comment")?;
    let max_hits = need_int(c, "max_hits", "no-escaped-newline-doc-comment")?;
    // Scanned on the RAW file text, not the comment-stripped view, because the escape sequence
    // lives inside the doc comment itself.
    let rx_pat = Regex::new(r"\\n//[!/]")?;
    let mut offenders = Vec::new();
    for rel in tree.files.keys() {
        if !rel.starts_with("crates/") {
            continue;
        }
        let Ok(text) = cx.read(rel) else { continue };
        for (i, raw) in text.split('\n').enumerate() {
            if rx_pat.is_match_str(raw) {
                offenders.push(format!("{rel}:{}", i + 1));
            }
        }
    }
    let current = offenders.len() as i64;
    let detail = format!(
        "{current} line(s) under crates/ carrying a literal backslash-n immediately before \
         `//!`/`///` (ceiling {max_hits}): {}",
        join_or_none(&offenders)
    );
    Ok(vec![plain(
        "no-escaped-newline-doc-comment",
        current <= max_hits,
        "no doc comment carries a literal backslash-n instead of a real line break",
        detail,
        current,
        max_hits,
        offenders,
    )])
}

// ── 26. unit-no-wall-clock ───────────────────────────────────────────────────────────────────────

pub fn unit_no_wall_clock(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("unit-no-wall-clock")?;
    let max_hits = need_int(c, "max_hits", "unit-no-wall-clock")?;
    let exempt = c.list_of("exempt_files");
    let files: Vec<String> = scoped_files(tree, &c.list_of("scope_globs"))
        .into_iter()
        .filter(|rel| !exempt.contains(rel))
        .collect();
    let rx_pat = Regex::new(
        &c.list_of("forbidden")
            .iter()
            .map(|v| rx::escape(v))
            .collect::<Vec<_>>()
            .join("|"),
    )?;
    let offenders: Vec<String> = tree
        .grep(&rx_pat, true, Some(&files))
        .into_iter()
        .map(|(rel, l)| format!("{rel}:{}", l.no))
        .collect();
    let current = offenders.len() as i64;
    let detail = if files.is_empty() {
        format!("{VACUOUS}no unit crate source is present in the scanned tree")
    } else {
        format!(
            "{current} clock read(s) in unit-crate production code (ceiling {max_hits}): {}",
            join_or_none(&offenders)
        )
    };
    Ok(vec![plain(
        "unit-no-wall-clock",
        current <= max_hits,
        "no unit crate reads the wall or monotonic clock",
        detail,
        current,
        max_hits,
        offenders,
    )])
}

// ── 27. unit-no-finding-ids ──────────────────────────────────────────────────────────────────────

pub fn unit_no_finding_ids(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("unit-no-finding-ids")?;
    let max_hits = need_int(c, "max_hits", "unit-no-finding-ids")?;
    // The shapes are regular expressions, not literals; escaping them here would search for the
    // backslash the ceilings file spells.
    let rx_pat = Regex::new(&c.list_of("patterns").join("|"))?;
    let exempt = c.list_of("exempt_crates");
    let scoped = scoped_files(tree, &c.list_of("scope_globs"));
    let mut offenders = Vec::new();
    for rel in &scoped {
        if exempt.contains(&tree.crate_of(rel)) {
            continue;
        }
        let lines = &tree.files[rel];
        // Read on the RAW file text, because the citations live in comments.
        let Ok(text) = cx.read(rel) else { continue };
        for (i, raw) in text.split('\n').enumerate() {
            if i < lines.len() && lines[i].intest {
                continue;
            }
            if rx_pat.is_match_str(raw) {
                offenders.push(format!("{rel}:{}", i + 1));
            }
        }
    }
    let current = offenders.len() as i64;
    let detail = if scoped.is_empty() {
        format!("{VACUOUS}no unit crate source is present in the scanned tree")
    } else {
        format!(
            "{current} finding-identifier citation(s) in unit-crate production code (ceiling \
             {max_hits}): {}",
            join_or_none(&offenders)
        )
    };
    Ok(vec![plain(
        "unit-no-finding-ids",
        current <= max_hits,
        "a unit crate states its rule in words, not as a finding identifier",
        detail,
        current,
        max_hits,
        offenders,
    )])
}

// ── 28. plane-no-money ───────────────────────────────────────────────────────────────────────────

/// The whole identifier containing `pos`, so a match on a fragment is judged as the word a reader
/// sees: `priced` inside `unpriced_message` is that field's name, not a price.
fn identifier_at(ident_rx: &Regex, code: &[u8], pos: usize) -> Option<String> {
    ident_rx
        .find_iter(code)
        .into_iter()
        .find(|m| m.start <= pos && pos < m.end)
        .and_then(|m| m.str_of(code, 0))
}

pub fn plane_no_money(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("plane-no-money")?;
    let max_hits = need_int(c, "max_hits", "plane-no-money")?;
    let scope_globs = c.list_of("scope_globs");
    let files = scoped_files(tree, &scope_globs);
    let allowed = c.list_of("allowed_vocabulary");
    let allowlist: &Table = &cfg.doc.table_or_empty("rules.plane-no-money.allowlist");
    let symbols = c.list_of("symbols");
    let sym_rx = Regex::new(
        &symbols
            .iter()
            .map(|s| {
                if s.starts_with('_') {
                    rx::escape(s)
                } else {
                    crate::gates::construction::model::word(s)
                }
            })
            .collect::<Vec<_>>()
            .join("|"),
    )?;
    let path_rx = Regex::new(
        &c.list_of("forbidden_module_paths")
            .iter()
            .map(|p| rx::escape(p))
            .collect::<Vec<_>>()
            .join("|"),
    )?;
    let ident_rx = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*")?;

    let mut offenders = Vec::new();
    for rel in &files {
        let here = allowlist.list_of(rel);
        for l in tree.files[rel].iter() {
            if l.intest {
                continue;
            }
            let bytes = l.code_bytes();
            for m in sym_rx.find_iter(bytes) {
                let raw = m.str_of(bytes, 0).unwrap_or_default();
                let w = identifier_at(&ident_rx, bytes, m.start).unwrap_or_else(|| raw.clone());
                if allowed.contains(&w) || here.contains(&w) || here.contains(&raw) {
                    continue;
                }
                offenders.push(format!("`{w}` at {rel}:{}", l.no));
                break;
            }
            if let Some(pm) = path_rx.search(bytes) {
                offenders.push(format!(
                    "`{}` at {rel}:{}",
                    pm.str_of(bytes, 0).unwrap_or_default(),
                    l.no
                ));
            }
        }
    }
    let forbidden_deps = c.list_of("forbidden_deps");
    let mut crates: Vec<String> = files.iter().map(|rel| tree.crate_of(rel)).collect();
    crates.sort();
    crates.dedup();
    for crate_name in crates {
        for dep in read_cargo_deps_text(
            &cx.read(format!("crates/{crate_name}/Cargo.toml"))
                .unwrap_or_default(),
        ) {
            if forbidden_deps.contains(&dep) {
                offenders.push(format!("{crate_name}/Cargo.toml depends on `{dep}`"));
            }
        }
    }
    let current = offenders.len() as i64;
    let empty: Vec<String> = scope_globs
        .iter()
        .filter(|g| scoped_files(tree, std::slice::from_ref(g)).is_empty())
        .cloned()
        .collect();
    let detail = if files.is_empty() {
        format!("{VACUOUS}no plane crate, plane codec or plane unit module is present in this tree")
    } else {
        format!(
            "{current} money symbol(s) in the plane crates, plane codecs and plane unit modules \
             (ceiling {max_hits}): {}{}",
            head(&offenders, 8),
            if empty.is_empty() {
                String::new()
            } else {
                format!(
                    "; scope glob(s) matching no file yet (not a finding): {}",
                    empty.join(", ")
                )
            }
        )
    };
    Ok(vec![plain(
        "plane-no-money",
        current <= max_hits,
        "a plane names usage classes and quantities, never a price",
        detail,
        current,
        max_hits,
        offenders,
    )])
}

// ── 29. one-pricing-site ─────────────────────────────────────────────────────────────────────────

pub fn one_pricing_site(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("one-pricing-site")?;
    let max_extra = need_int(c, "max_extra_sites", "one-pricing-site")?;
    let homes: Vec<(String, String)> = cfg
        .doc
        .children("rules.one-pricing-site.allowed")
        .into_iter()
        .map(|(k, t)| {
            (
                k,
                t.str_of("path")
                    .unwrap_or("")
                    .trim_end_matches('/')
                    .to_string(),
            )
        })
        .collect();
    let home_of = |rel: &str| -> Option<&String> {
        homes
            .iter()
            .find(|(_, p)| rel == p || rel.starts_with(&format!("{p}/")))
            .map(|(k, _)| k)
    };

    let mut sites: Vec<(String, String, usize)> = Vec::new();
    for verb in c.list_of("entry_verbs") {
        for (rel, l) in call_sites(tree, &verb, None)? {
            sites.push((format!("`{verb}(`"), rel.to_string(), l.no));
        }
    }
    let path_rx = Regex::new(&c.list_of("entry_path_patterns").join("|"))?;
    for (rel, l) in tree.grep(&path_rx, true, None) {
        let hit = path_rx
            .search(l.code_bytes())
            .and_then(|m| m.str_of(l.code_bytes(), 0))
            .unwrap_or_default();
        sites.push((format!("`{hit}`"), rel.to_string(), l.no));
    }
    let (mut extra, mut inside) = (Vec::new(), Vec::new());
    for (what, rel, no) in &sites {
        match home_of(rel) {
            Some(key) => inside.push(format!("{what} at {rel}:{no} ({key})")),
            None => extra.push(format!("{what} at {rel}:{no}")),
        }
    }
    let current = extra.len() as i64;
    let mut home_keys: Vec<String> = homes.iter().map(|(k, _)| k.clone()).collect();
    home_keys.sort();
    let detail = format!(
        "{current} pricing-entry call site(s) outside the reviewed homes {} (ceiling \
         {max_extra}): {}; reviewed sites seen: {}",
        py_list(&home_keys),
        join_or_none(&extra),
        if inside.is_empty() {
            "NONE \u{2014} no production code prices at all today".to_string()
        } else {
            inside.join("; ")
        }
    );
    let mut rows = vec![plain(
        "one-pricing-site",
        current <= max_extra,
        "only the root's meter/admission wiring and the kernel's settle sites price a unit",
        detail,
        current,
        max_extra,
        extra,
    )];

    let fee_fields = c.list_of("fee_fields");
    let fee_crates = c.list_of("fee_reader_crates");
    let max_fee = need_int(c, "max_fee_readers", "one-pricing-site")?;
    let fee_rx = Regex::new(
        &fee_fields
            .iter()
            .map(|f| crate::gates::construction::model::word(f))
            .collect::<Vec<_>>()
            .join("|"),
    )?;
    let readers: Vec<String> = tree
        .grep(&fee_rx, true, None)
        .into_iter()
        .filter(|(rel, _)| !fee_crates.contains(&tree.crate_of(rel)))
        .map(|(rel, l)| format!("{rel}:{}", l.no))
        .collect();
    let mut sorted_crates = fee_crates.clone();
    sorted_crates.sort();
    let detail = format!(
        "{} production read(s) of {} outside {} (ceiling {max_fee}): {}",
        readers.len(),
        py_list(&fee_fields),
        py_list(&sorted_crates),
        join_or_none(&readers)
    );
    rows.push(plain(
        "one-pricing-site:fee-fields",
        readers.len() as i64 <= max_fee,
        "the per-request fee is read only where the card lives",
        detail,
        readers.len() as i64,
        max_fee,
        readers,
    ));
    Ok(rows)
}

// ── 30. legacy-reach ─────────────────────────────────────────────────────────────────────────────

fn split_top(text: &str, sep: char) -> Vec<String> {
    let (mut out, mut depth, mut cur) = (Vec::new(), 0i64, String::new());
    for ch in text.chars() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
        }
        if ch == sep && depth == 0 {
            out.push(std::mem::take(&mut cur));
            continue;
        }
        cur.push(ch);
    }
    out.push(cur);
    out
}

/// One entry of a `use` group, which may itself be a path or another group.
fn expand_item(item: &str, base: &str, out: &mut BTreeSet<String>) {
    let item = item.split(" as ").next().unwrap_or(item).trim();
    if item.is_empty() || item == "self" || item == "*" {
        return;
    }
    if item.contains('{') {
        let (head, rest) = match item.split_once("::{") {
            Some((h, r)) => (h, r),
            None => (item, ""),
        };
        let inner = rest.trim_end().trim_end_matches('}');
        for sub in split_top(inner, ',') {
            expand_item(&sub, &format!("{base}{head}::"), out);
        }
        return;
    }
    out.insert(format!("{base}{item}"));
}

/// Every distinct symbol named through `prefix` in production code, with where each is named. A
/// grouped `use a::{b, c::{d, e}}` is expanded, because a symbol imported in a brace group is named
/// exactly as much as one spelled in full.
fn named_symbols(
    tree: &Tree,
    files: &[String],
    prefix: &str,
    exclude: &[String],
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let path_rx = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*")?;
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rel in files {
        for l in tree.files.get(rel).into_iter().flat_map(|v| v.iter()) {
            if l.intest {
                continue;
            }
            let code = l.code.as_bytes();
            let mut pos = 0usize;
            while let Some(i) = find_from(code, prefix.as_bytes(), pos) {
                let j = i + prefix.len();
                pos = j;
                let mut found: BTreeSet<String> = BTreeSet::new();
                if code.get(j) == Some(&b'{') {
                    let mut depth = 0i64;
                    let mut k = j;
                    while k < code.len() {
                        if code[k] == b'{' {
                            depth += 1;
                        } else if code[k] == b'}' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        k += 1;
                    }
                    let inner =
                        String::from_utf8_lossy(&code[(j + 1).min(code.len())..k.min(code.len())]);
                    for entry in split_top(&inner, ',') {
                        expand_item(&entry, prefix, &mut found);
                    }
                    pos = k + 1;
                } else if let Some(m) = path_rx.match_at(code, j) {
                    if m.end > j {
                        found.insert(format!(
                            "{prefix}{}",
                            String::from_utf8_lossy(&code[j..m.end])
                        ));
                        pos = m.end;
                    }
                }
                for s in found {
                    if exclude.iter().any(|e| s.starts_with(e.as_str())) {
                        continue;
                    }
                    seen.entry(s).or_default().push(format!("{rel}:{}", l.no));
                }
            }
        }
    }
    Ok(seen)
}

fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > haystack.len() || needle.is_empty() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

pub fn legacy_reach(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("legacy-reach")?;
    let ceiling = need_int(c, "ceiling", "legacy-reach")?;
    let files = scoped_files(tree, &c.list_of("scope_globs"));
    let prefixes = cfg.doc.children("rules.legacy-reach.prefixes");

    let (mut rows, mut total_offenders, mut total) = (Vec::new(), Vec::new(), 0i64);
    for (key, spec) in &prefixes {
        let prefix = need_str(spec, "prefix", "legacy-reach.prefixes")?;
        let figure = need_int(spec, "figure", "legacy-reach.prefixes")?;
        let seen = named_symbols(tree, &files, prefix, &spec.list_of("exclude"))?;
        let current = seen.len() as i64;
        total += current;
        let offenders: Vec<String> = seen
            .iter()
            .map(|(s, sites)| format!("{s} ({} site(s), first {})", sites.len(), sites[0]))
            .collect();
        total_offenders.extend(offenders.clone());
        let detail = if files.is_empty() {
            format!("{VACUOUS}no composition-root source is present in this tree")
        } else {
            format!(
                "the root names {current} distinct `{prefix}` symbol(s) (ratchet {figure}, pinned \
                 to the measurement and may only go down): {}",
                if seen.is_empty() {
                    "none".to_string()
                } else {
                    format!(
                        "{}{}",
                        seen.keys().take(6).cloned().collect::<Vec<_>>().join(", "),
                        if current > 6 { " \u{2026}" } else { "" }
                    )
                }
            )
        };
        // GATING, AND EXACT. This row was `informational()` — PASS whatever it measured, titled
        // `WARN` — on the reasoning that the total was the claim and a per-crate figure could
        // legitimately rise while the total fell. What that bought was `busbar_substrate` at 47
        // against a figure of 26, twenty-one over, PASSING, for as long as the total held: the
        // slack mechanism firing exactly as designed, inside the row built to make it invisible. A
        // figure nothing fails on is a comment. Both directions are the gate now — over its figure
        // is this row, under it is `ceiling-slack` — and the intermediate step the WARN posture
        // existed to permit is a re-pin of the two figures in the commit that makes it.
        rows.push(plain(
            format!("legacy-reach:{key}"),
            current <= figure,
            format!("the root's reach into `{prefix}` only shrinks"),
            detail,
            current,
            figure,
            offenders,
        ));
    }
    let named = prefixes
        .iter()
        .map(|(_, s)| format!("`{}`", s.str_of("prefix").unwrap_or("")))
        .collect::<Vec<_>>()
        .join(", ");
    let detail = if files.is_empty() {
        format!("{VACUOUS}no composition-root source is present in this tree")
    } else {
        format!(
            "the root names {total} distinct symbol(s) across the retiring crates ({named}) \
             (ratchet {ceiling}, may only go down); per-crate figures are in the WARN sub-rows above"
        )
    };
    rows.push(plain(
        "legacy-reach",
        total <= ceiling,
        "the root's total reach into the retiring crates only shrinks",
        detail,
        total,
        ceiling,
        total_offenders,
    ));
    Ok(rows)
}

// ── 31. no-test-doubles-in-production ────────────────────────────────────────────────────────────

pub fn no_test_doubles_in_production(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("no-test-doubles-in-production")?;
    let max_unlisted = need_int(c, "max_unlisted", "no-test-doubles-in-production")?;
    let max_doubles = need_int(c, "max_doubles", "no-test-doubles-in-production")?;
    let files = scoped_files(tree, &c.list_of("scope_globs"));
    let forbidden = c.list_of("forbidden");
    // Enumerated by file and spelling rather than by line: a line number moves under an edit that
    // changes nothing about what is constructed.
    let mut known: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
    for (_k, entry) in cfg
        .doc
        .children("rules.no-test-doubles-in-production.known_sites")
    {
        let file = need_str(entry, "file", "no-test-doubles-in-production.known_sites")?;
        let symbol = need_str(entry, "symbol", "no-test-doubles-in-production.known_sites")?;
        let verdict = need_str(
            entry,
            "verdict",
            "no-test-doubles-in-production.known_sites",
        )?;
        let because = need_str(
            entry,
            "because",
            "no-test-doubles-in-production.known_sites",
        )?;
        known.insert(
            (file.to_string(), symbol.to_string()),
            (verdict.to_string(), because.to_string()),
        );
    }

    let (mut unlisted, mut doubles) = (Vec::new(), Vec::new());
    for rel in &files {
        for l in tree.files[rel].iter() {
            if l.intest {
                continue;
            }
            for symbol in &forbidden {
                if !l.code.contains(symbol.as_str()) {
                    continue;
                }
                match known.get(&(rel.clone(), symbol.clone())) {
                    None => unlisted.push(format!("`{symbol}` at {rel}:{}", l.no)),
                    Some((verdict, because)) if verdict == "double" => {
                        doubles.push(format!("`{symbol}` at {rel}:{} \u{2014} {because}", l.no))
                    }
                    Some(_) => {}
                }
            }
        }
    }
    let (detail, listed_detail) = if files.is_empty() {
        let v = format!("{VACUOUS}no composition-root source is present in this tree");
        (v.clone(), v)
    } else {
        (
            format!(
                "{} stand-in construction(s) on a production line of the composition root that no \
                 reviewed site names (ceiling {max_unlisted}): {}",
                unlisted.len(),
                join_or_none(&unlisted)
            ),
            format!(
                "{} reviewed site(s) that are a test double in the shipped binary (ratchet \
                 {max_doubles}, may only go down): {}",
                doubles.len(),
                join_or_none(&doubles)
            ),
        )
    };
    Ok(vec![
        plain(
            "no-test-doubles-in-production",
            unlisted.len() as i64 <= max_unlisted,
            "a stand-in the shipped binary constructs is one somebody reviewed",
            detail,
            unlisted.len() as i64,
            max_unlisted,
            unlisted,
        ),
        plain(
            "no-test-doubles-in-production:doubles",
            doubles.len() as i64 <= max_doubles,
            "the reviewed stand-ins that are doubles rather than real values only shrink",
            listed_detail,
            doubles.len() as i64,
            max_doubles,
            doubles,
        ),
    ])
}

#[cfg(test)]
mod module_spelling_tests {
    use super::same_module;

    /// A pinned site keeps its pin when the module it lives in grows children and is rewritten
    /// from `tests.rs` to `tests/mod.rs`. Nothing about the seal changed, so nothing about the
    /// ratchet may either — in EITHER direction, which is what stops a site being re-pinned as
    /// new by moving the file back.
    #[test]
    fn the_two_spellings_of_one_module_are_one_pin() {
        let flat = "crates/busbar-transport-tcp/src/tests.rs";
        let dir = "crates/busbar-transport-tcp/src/tests/mod.rs";
        assert!(same_module(flat, dir));
        assert!(same_module(dir, flat));
        assert!(same_module(flat, flat));
        assert!(same_module(dir, dir));
    }

    /// And a DIFFERENT file in the same directory is still a different file: the normalisation
    /// reads `mod.rs` and nothing else, so a pin never spreads to the module's siblings.
    #[test]
    fn a_sibling_of_a_pinned_module_is_not_pinned() {
        let pinned = "crates/busbar-transport-tcp/src/tests.rs";
        assert!(!same_module(
            pinned,
            "crates/busbar-transport-tcp/src/tests/battery.rs"
        ));
        assert!(!same_module(
            pinned,
            "crates/busbar-transport-tls/src/tests/mod.rs"
        ));
        assert!(!same_module(
            pinned,
            "crates/busbar-transport-tcp/src/lib.rs"
        ));
    }
}
