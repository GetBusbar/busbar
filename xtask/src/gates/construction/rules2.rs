//! THE KIND, CEILING AND MONEY RULES: the zero-armed `busbar-unit-*` tripwire, the section 1.2
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
    crate_name_of_dir, dirs_for_globs, fnmatch, memo_file_scan, read_cargo_deps_text, Fnc, Line,
    Tree,
};
use crate::rx::{self, Regex};
use crate::toml_doc::Table;

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

fn kind_crate_dirs(cx: &Ctx, cfg: &Cfg, kind: &str) -> Result<Vec<String>, String> {
    Ok(dirs_for_globs(cx, &cfg.kind_globs(kind)?))
}

// ── 14. no-unit-crates ───────────────────────────────────────────────────────────────────────────

/// The row id of the zero-armed `busbar-unit-*` tripwire.
pub const ROW_NO_UNIT_CRATES: &str = "no-unit-crates";

/// NO `busbar-unit-*` CRATE, ARMED AT ZERO. Fold F14 2/2 deleted the last unit crate; a crate that
/// matches `unit_crate_glob` coming back is an architecture regression, not a size, so this row is
/// a STRUCTURAL tripwire with no figure to raise. It replaces the `loc-ceilings` family, whose size
/// ceilings are gone: size is not a CI check (owner 2026-10-02) and is measured by hand at PERF.
///
/// A unit crate the TREE holds source for counts whether or not its directory is on disk: the
/// directory listing reads the filesystem only, so a crate in the tree this rule was handed (a
/// selftest plant) and not in the checkout would otherwise be invisible.
pub fn no_unit_crates(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule(ROW_NO_UNIT_CRATES)?;
    let unit_glob = need_str(c, "unit_crate_glob", ROW_NO_UNIT_CRATES)?;
    let mut unit_crates: BTreeSet<String> = dirs_for_globs(cx, &[format!("crates/{unit_glob}")])
        .iter()
        .map(|d| crate_name_of_dir(d))
        .collect();
    for rel in tree.files.keys() {
        let name = tree.crate_of(rel);
        if rel.starts_with("crates/") && fnmatch(&name, unit_glob) {
            unit_crates.insert(name);
        }
    }
    let found: Vec<String> = unit_crates.into_iter().collect();
    let n = found.len() as i64;
    Ok(vec![plain(
        ROW_NO_UNIT_CRATES,
        found.is_empty(),
        format!("no {unit_glob} crate exists (armed at 0)"),
        format!(
            "{n} {unit_glob} crate(s) (ceiling 0): {}",
            join_or_none(&found)
        ),
        n,
        0,
        found,
    )])
}

// ── 15. manifest-allowlist ───────────────────────────────────────────────────────────────────────

pub fn manifest_allowlist(cx: &Ctx, tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("manifest-allowlist")?;
    // THE KEYS OF `[gate.plugin_kinds]`, SPELLED THE WAY THAT FILE SPELLS THEM. `pure_auth` and
    // `egress_auth` stood here until 2026-09-22 and neither is a key: DECISIONS #3 collapsed the
    // split into ONE `auth` kind, because direction is a property of the leg — this transport,
    // this auth, this direction — and never a kind. Both stale spellings resolved to zero crates,
    // so `crates/auth-admin-tokens` and `crates/auth-static-plugin` were scanned by nothing and
    // this rule printed twelve green rows where fourteen were owed. `Cfg::kind_globs` now refuses
    // a key the config does not declare, so the next such typo is a RED instead of a silence.
    //
    // AND `transport` WAS MISSING TOO (item 120): the list named six of the seven plugin kinds of
    // `[gate.plugin_kinds]` (DECISIONS #3), so the seven `busbar-transport-*` crates got no row at
    // all and this rule printed green while `busbar-transport-tls` (since deleted) path-depended on
    // `busbar-unit-transport-key`. A transport is a plugin behind the wall like any other kind.
    let kinds = [
        "plane",
        "store",
        "auth",
        "hook",
        "export",
        "secret",
        "transport",
    ];
    let unit_names: BTreeSet<String> = match cfg.rule(ROW_NO_UNIT_CRATES) {
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
        kind_crate_dirs(cx, cfg, "plane")?
            .iter()
            .map(|d| crate_name_of_dir(d)),
    );
    let transport_names: BTreeSet<String> = kind_crate_dirs(cx, cfg, "transport")?
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
        for d in kind_crate_dirs(cx, cfg, kind)? {
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
    xtask_hits: Result<&BTreeMap<String, Vec<String>>, &str>,
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
    // `Err` = the transitive-closure half never answered (or answered with its own defects). Every
    // row then says so, with the reason, and is RED: an unproven half of an invariant is not a met
    // one.
    let mut rows = Vec::new();
    let mut seen: Vec<(String, String)> = Vec::new();
    for kind in c.list_of("kinds") {
        for d in kind_crate_dirs(cx, cfg, &kind)? {
            seen.push((kind.clone(), d));
        }
    }
    for (kind, d) in seen {
        let crate_name = crate_name_of_dir(&d);
        let allowed_here = allow.list_of(&crate_name);
        let mut offenders = Vec::new();
        for rel in tree.crate_files(&crate_name) {
            let mut direct: BTreeSet<(usize, String)> = BTreeSet::new();
            for l in tree.files[&rel].iter() {
                if l.intest {
                    continue;
                }
                if let Some(m) = pat_rx.search(l.code_bytes()) {
                    let hit = m.str_of(l.code_bytes(), 0).unwrap_or_default();
                    direct.insert((l.no, hit.clone()));
                    if !allowed_here.contains(&hit) {
                        offenders.push(format!("`{hit}` at {rel}:{}", l.no));
                    }
                }
            }
            // A grouped import (`use std::{fs, net::TcpStream};`) spells no banned path whole, so
            // the line search above reads it as clean; the expanded use tree names it.
            let production: Vec<(usize, &str)> = tree.files[&rel]
                .iter()
                .filter(|l| !l.intest)
                .map(|l| (l.no, l.code.as_str()))
                .collect();
            for (no, hit) in crate::denylist::use_tree_hits(&production, &patterns) {
                if !direct.contains(&(no, hit.clone())) && !allowed_here.contains(&hit) {
                    offenders.push(format!("`{hit}` at {rel}:{no}"));
                }
            }
        }
        match xtask_hits {
            Err(why) => offenders.push(format!(
                "UNPROVEN: `cargo xtask denylist` did not answer, so no transitive dependency was \
                 checked ({why})"
            )),
            Ok(h) => offenders.extend(h.get(&crate_name).cloned().unwrap_or_default()),
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

    // A SITE-LEVEL review, not a file-level one: a busbar-kernel file this size is otherwise-neutral
    // and a directory-wide excuse would hide a genuinely new dialect word landing anywhere else in
    // it. Each entry is `<path> :: <literal text>` (ARCHITECT 2026-10-02, STANDING-REDS lean-core
    // option 2): the reviewed STRING in the reviewed FILE, so the review follows its code when lines
    // move above it, and a different literal in the same file is still unreviewed. A `path:line`
    // entry went stale on every edit above it, and five reviewed literals turned this row red that
    // way. An entry that matches no literal is reported, so the list cannot carry a dead waiver.
    let mut known: BTreeMap<String, bool> = BTreeMap::new();
    for entry in c.list_of("known_sites") {
        if entry.split_once(LEAN_CORE_SEP).is_none() {
            return Err(format!(
                "lean-core known_sites entry `{entry}` is not `<path>{LEAN_CORE_SEP}<literal text>`"
            ));
        }
        known.insert(entry, false);
    }

    let (mut offenders, mut tracked) = (Vec::new(), Vec::new());
    for crate_name in &crates {
        for rel in tree.crate_files(crate_name) {
            // The per-file hits, memoised on the file's scan (`memo_file_scan`); the review list is
            // applied after, so it is not an input of the memoised half.
            let tag = format!("lean-core\u{1}{rel}\u{1}{}", word_rx.as_str());
            let hits = memo_file_scan(tag, &tree.files[&rel], |lines| {
                let mut out = Vec::new();
                for l in lines {
                    if l.intest {
                        continue;
                    }
                    for (_, (bs, be)) in tree.lexer.string_literals(&l.code) {
                        let content = &l.code.as_bytes()[bs..be];
                        if word_rx.is_match(content) {
                            let text = String::from_utf8_lossy(content);
                            out.push(format!("{text}\u{1}\"{text}\" at {rel}:{}", l.no));
                        }
                    }
                }
                out
            });
            for h in hits.iter() {
                let (text, where_) = h.split_once('\u{1}').unwrap_or(("", h));
                match known.get_mut(&lean_core_key(&rel, text)) {
                    Some(seen) => {
                        *seen = true;
                        tracked.push(where_.to_string());
                    }
                    None => offenders.push(where_.to_string()),
                }
            }
        }
    }
    for (entry, seen) in &known {
        if !seen {
            offenders.push(format!(
                "stale known_sites entry `{entry}`: no such literal in that file; strike it"
            ));
        }
    }
    let current = offenders.len() as i64;
    let mut parts = vec![head(&offenders, 8)];
    if !tracked.is_empty() {
        parts.push(format!(
            "reviewed frozen-wire/schema sites (qa/construction.toml known_sites): {} of {}",
            tracked.len().min(3),
            tracked.len()
        ));
    }
    let detail = format!(
        "{current} string literal(s) in {} naming a dialect or the section 1.3 pinned word list \
         (ceiling {max_hits}): {}",
        py_list(&crates),
        parts.join("; ")
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

/// The separator of a `lean-core` `known_sites` entry: `<path> :: <literal text>`.
pub const LEAN_CORE_SEP: &str = " :: ";

/// The `known_sites` entry that reviews `text` (a string literal's body, as written) in `rel`.
pub fn lean_core_key(rel: &str, text: &str) -> String {
    format!("{rel}{LEAN_CORE_SEP}{text}")
}

/// The `known_sites` entry that would review one `lean-core` offender (`"<text>" at <rel>:<line>`),
/// or `None` for an offender that is not a literal (a stale entry).
pub fn lean_core_key_of(offender: &str) -> Option<String> {
    let body = offender.strip_prefix('"')?;
    let (text, loc) = body.rsplit_once("\" at ")?;
    let (rel, _line) = loc.rsplit_once(':')?;
    Some(lean_core_key(rel, text))
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
            format!(
                "; trait(s) NOT FOUND in any declaring file, so they were not scanned at all: {} \
                 — a trait this rule cannot find is a trait it cannot judge, and a ceiling of 0 \
                 met by scanning nothing is the passing answer to every ban. Point the rule's \
                 `file`/`plane_file`/`transport_file` at the trait's real home, or strike the \
                 trait from `traits` in the same commit that deletes it",
                py_list(&missing)
            )
        }
    );
    // A MISSING TRAIT IS A FAILURE, NOT A FOOTNOTE. This used to be `current <= max_defaulted`
    // alone, with the missing set mentioned only in a detail string that a green run never prints.
    // Measured 2026-09-22: with `transport_file` naming `crates/busbar-contract/src/transport.rs`
    // (the value this file carried until a197ad2f5 moved the trait into `transport/mod.rs`), a
    // default body planted on `Transport` scored `PASS ... 0 defaulted kind-trait method(s)
    // (ceiling 0): none; trait(s) not found yet: ['Transport']`. The identical plant on `Store`,
    // whose declaring file the rule still named correctly, scored FAIL. The only difference was
    // whether the configured path still existed, and the rule already KNEW — it said so in the
    // detail and passed anyway.
    Ok(vec![plain(
        "no-default-bodies",
        current <= max_defaulted && missing.is_empty(),
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
    let (mut offenders, mut checked, mut missing) = (Vec::new(), Vec::new(), Vec::new());
    for (_key, spec) in cfg.doc.children("rules.sealed-unit-traits.traits") {
        let rel = need_str(spec, "file", "sealed-unit-traits.traits")?;
        let trait_name = need_str(spec, "trait", "sealed-unit-traits.traits")?;
        let crate_name = need_str(spec, "crate", "sealed-unit-traits.traits")?;
        let Some(lines) = tree.files.get(rel) else {
            missing.push(format!(
                "{crate_name}::{trait_name} (file {rel} is not in the tree)"
            ));
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
            missing.push(format!(
                "{crate_name}::{trait_name} (no `trait {trait_name}` declaration in {rel})"
            ));
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
    let unresolved = if missing.is_empty() {
        String::new()
    } else {
        format!(
            "; configured trait(s) NOT FOUND, so they were not judged at all: {} — a trait this \
             rule cannot find is a trait it cannot judge. Point the entry's `file` at the trait's \
             real home, or strike the entry in the same commit that deletes the trait",
            missing.join(", ")
        )
    };
    let detail = if checked.is_empty() && missing.is_empty() {
        "vacuous: none of the configured unit traits exist in this tree yet".to_string()
    } else {
        format!(
            "{current} of {} configured unit trait(s) unsealed (ceiling {max_unsealed}): {}{unresolved}",
            checked.len() + missing.len(),
            join_or_none(&offenders)
        )
    };
    // ITEMS 191/192: A MISSING TRAIT IS A FAILURE, the fix `no-default-bodies` above already
    // carries. This dropped a configured trait whose file moved or whose header no longer matched
    // — not counted, not named — and passed on the shrunken set: moving `Breaker`'s file made the
    // one sealed trait vanish from the denominator and the row stayed green.
    Ok(vec![plain(
        "sealed-unit-traits",
        current <= max_unsealed && missing.is_empty(),
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

    // (e) The route step it once scanned is sync, so the row was vacuous there. Its real subject is the dispatcher's deadline/cancel path: in
    // every function of `cancel_scope_dirs` that names a cancel or a deadline, a money hold open at
    // or after that point is released or settled BEFORE any `.await` or `return` that follows it.
    let dirs = c.list_of("cancel_scope_dirs");
    let cancel_rx = Regex::new(need_str(c, "cancel_path_pattern", "hold-discipline")?)?;
    let open_rx = Regex::new(need_str(c, "hold_open_pattern", "hold-discipline")?)?;
    let close_rx = Regex::new(need_str(c, "hold_close_pattern", "hold-discipline")?)?;
    let cancel_files: Vec<&String> = tree
        .files
        .keys()
        .filter(|r| dirs.iter().any(|d| r.starts_with(d.as_str())))
        .collect();
    let (mut open_across, mut cancel_fns) = (Vec::new(), 0usize);
    for rel in cancel_files {
        for f in tree.fns.get(rel).into_iter().flat_map(|v| v.iter()) {
            if f.intest {
                continue;
            }
            let body = &tree.files[rel][f.start - 1..f.end];
            let Some(cancel_i) = body.iter().position(|l| cancel_rx.is_match(l.code_bytes()))
            else {
                continue;
            };
            cancel_fns += 1;
            let mut open = false;
            for (i, l) in body.iter().enumerate() {
                if open_rx.is_match(l.code_bytes()) {
                    open = true;
                }
                if close_rx.is_match(l.code_bytes()) {
                    open = false;
                }
                let exits = l.code.contains(".await") || return_rx.is_match(l.code_bytes());
                if open && exits && i >= cancel_i {
                    open_across.push(format!("{} at {rel}:{}", f.name, l.no));
                }
            }
        }
    }
    let max_open = need_int(c, "max_await_with_open_hold", "hold-discipline")?;
    rows.push(plain(
        "hold-discipline:cancellation-before-await",
        open_across.len() as i64 <= max_open,
        "a money hold is released or settled before any `.await` or `return` after a cancel or deadline",
        if cancel_fns > 0 {
            format!(
                "{} `.await`/`return` with a hold open after a cancel or deadline, over {cancel_fns} \
                 cancel-path function(s) in {} (ceiling {max_open}): {}",
                open_across.len(),
                dirs.join(", "),
                join_or_none(&open_across)
            )
        } else {
            format!("{VACUOUS}no cancel-path function found in {}", dirs.join(", "))
        },
        open_across.len() as i64,
        max_open,
        open_across,
    ));
    Ok(rows)
}

// ── 21. kernel-seal-impls and forbid-unsafe ──────────────────────────────────────────────────────

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
        if known.iter().any(|k| k == rel) {
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
    // THE CRATE-LEVEL INNER ATTRIBUTE, IN THE CRATE ROOT, AND NOTHING ELSE COUNTS (item 89).
    //
    // This matched `forbid(unsafe_code)` anywhere in any file of the crate, over the `code` text,
    // which keeps string literals intact. So `assert!(lib.contains("#![forbid(unsafe_code)]"))` in
    // `crates/busbar-plane-{a2a,llm,mcp,decision}/tests/*.rs` — a TEST ABOUT the attribute — was
    // scored as the attribute itself, and stripping the real one from `src/lib.rs` left every one
    // of those rows PASS: the self-test's "every crate of this kind loses its attribute" plant went
    // GREEN, which is this rule unable to see the one thing it exists for. A module-level
    // `#![forbid(unsafe_code)]` (busbar-contract's `json_grammar.rs`, `caps/mod.rs`) does not bind
    // the crate either. So: the blanked text (literal bodies emptied), production lines only, the
    // `#![...]` inner-attribute spelling, in `src/lib.rs` or `src/main.rs`.
    let forbid_rx = Regex::new(r"#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]")?;
    let deny_rx = Regex::new(r"#!\s*\[\s*(forbid|deny)\s*\(\s*unsafe_code\s*\)\s*\]")?;
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
            seen.extend(kind_crate_dirs(cx, cfg, &kind)?);
        }
        let mut out = Vec::new();
        for d in seen {
            let crate_name = crate_name_of_dir(&d);
            let roots = [format!("{d}/src/lib.rs"), format!("{d}/src/main.rs")];
            let has_it = roots.iter().any(|rel| {
                tree.files.get(rel.as_str()).is_some_and(|lines| {
                    lines
                        .iter()
                        .any(|l| !l.intest && rx_pat.is_match(l.blank.as_bytes()))
                })
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
        // THE SITES INSIDE THE HOME, counted where a spec states how many there are (item 130).
        // Confinement alone says WHERE a symbol may appear and nothing about how often: a fourth
        // `HoldCell::take` written next to the other three sat inside the confined file and the
        // row stayed PASS. A `sites = N` spec holds the home to exactly N, so a fourth goes red and
        // so does a site that stops spelling the literal the count is taken over.
        let mut homed: Vec<String> = Vec::new();
        for (rel, l) in tree.grep(&sym_rx, true, Some(&files)) {
            // ANCHORED, and matched as a path prefix: `confined_to` is the busbar-caps fixture's
            // prose spelling and excuses any path containing those characters; the resolved
            // `confined_to_paths` excuses a file exactly, or a directory and everything under it.
            let here = confined.iter().any(|p| {
                let p = p.trim_end_matches('/');
                !p.is_empty() && (rel == p || rel.starts_with(&format!("{p}/")))
            });
            if here {
                homed.push(format!("{rel}:{}", l.no));
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
        if let Some(want) = spec.int_of("sites") {
            if homed.len() as i64 != want {
                offenders.push(format!(
                    "`{symbol}` has {} site(s) inside its home, the spec says exactly {want} \
                     ({because}): {}",
                    homed.len(),
                    join_or_none(&homed)
                ));
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

// ── 27b. kernel-no-protocol-registry ────────────────────────────────────────────────────────────

/// The row id of the installed-store half.
pub const ROW_INSTALLED_STORE: &str = "kernel-no-protocol-registry:installed-store";

/// The row id of the counted debt: the plane- and protocol-keyed stores the kernel still holds.
pub const ROW_STORE_DEBT: &str = "kernel-no-protocol-registry:debt";

/// Every name an alias declared anywhere in the tree binds to one of `targets`, followed to a fixed
/// point (an alias of an alias is an alias): `type X = …T…;`, `T as X` (a `use` or re-export), and a
/// `const`/`static` bound to `T` (a fn pointer). Read over every file the tree holds, test or not.
fn aliases_of(tree: &Tree, targets: &[String]) -> Result<Vec<String>, String> {
    let texts: Vec<String> = tree
        .files
        .values()
        .map(|lines| {
            lines
                .iter()
                .map(|l| l.code.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect();
    let mut known: Vec<String> = targets.to_vec();
    let mut i = 0;
    while i < known.len() {
        let t = rx::escape(&known[i]);
        let shapes = [
            Regex::new(&format!(r"\b{t}\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"))?,
            Regex::new(&format!(
                r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)[^=;]*=[^;]*\b{t}\b"
            ))?,
            Regex::new(&format!(
                r"\b(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:[^=;]*=\s*[A-Za-z0-9_:]*\b{t}\s*;"
            ))?,
        ];
        let needle = known[i].clone();
        let mut found = Vec::new();
        for text in texts.iter().filter(|x| x.contains(needle.as_str())) {
            for shape in &shapes {
                for m in shape.find_iter(text.as_bytes()) {
                    if let Some(alias) = m.str_of(text.as_bytes(), 1) {
                        found.push(alias);
                    }
                }
            }
        }
        for alias in found {
            if !known.contains(&alias) {
                known.push(alias);
            }
        }
        i += 1;
    }
    Ok(known)
}

/// Every type the tree defines, by name, with the text a value of it holds: a `type X<…> = …;`
/// alias's right-hand side, and the field list of a `struct` (named or tuple) or the variant list of
/// an `enum`. Each is kept with the crate directory it is declared in, so a name two crates define
/// is read as the static's own crate's first. Test code defines nothing here.
type TypeDefs = BTreeMap<String, Vec<(String, String)>>;

fn crate_dir_of(rel: &str) -> &str {
    let mut parts = rel.splitn(3, '/');
    match (parts.next(), parts.next()) {
        (Some("crates"), Some(name)) => &rel[..7 + name.len()],
        _ => "",
    }
}

fn type_defs(tree: &Tree) -> Result<TypeDefs, String> {
    let alias = Regex::new(r"(?:^|[^A-Za-z0-9_])type\s+([A-Za-z_][A-Za-z0-9_]*)[^=;{}]*=([^;]*);")?;
    let item = Regex::new(r"(?:^|[^A-Za-z0-9_])(?:struct|enum|union)\s+([A-Za-z_][A-Za-z0-9_]*)")?;
    let mut defs: TypeDefs = BTreeMap::new();
    for (rel, lines) in &tree.files {
        let krate = crate_dir_of(rel).to_string();
        // Memoised on the file's scan: a plant re-reads only the files it touches.
        let found = memo_file_scan(
            "kernel-no-protocol-registry:type-defs".to_string(),
            lines,
            |lines| defs_in(lines, &alias, &item),
        );
        for entry in found.iter() {
            if let Some((name, body)) = entry.split_once('\u{1}') {
                defs.entry(name.to_string())
                    .or_default()
                    .push((krate.clone(), body.to_string()));
            }
        }
    }
    Ok(defs)
}

/// The definitions one file holds, each `name\u{1}body` (see [`type_defs`]).
fn defs_in(lines: &[Line], alias: &Regex, item: &Regex) -> Vec<String> {
    let text: String = lines
        .iter()
        .map(|l| if l.intest { "" } else { l.blank.as_str() })
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for m in alias.find_iter(bytes) {
        if let (Some(name), Some(rhs)) = (m.str_of(bytes, 1), m.str_of(bytes, 2)) {
            out.push(format!("{name}\u{1}{rhs}"));
        }
    }
    for m in item.find_iter(bytes) {
        let Some(name) = m.str_of(bytes, 1) else {
            continue;
        };
        // Past the generics (an `->` inside them is not a closing `>`), to the body's opener.
        let mut i = m.end;
        let mut angle = 0i64;
        let mut open = None;
        while i < bytes.len() {
            match bytes[i] {
                b'<' => angle += 1,
                b'>' if bytes[i - 1] == b'-' => {}
                b'>' => angle -= 1,
                b'{' | b'(' if angle <= 0 => {
                    open = Some(i);
                    break;
                }
                b';' if angle <= 0 => break,
                _ => {}
            }
            i += 1;
        }
        let Some(open) = open else {
            continue;
        };
        let (o, c) = if bytes[open] == b'{' {
            (b'{', b'}')
        } else {
            (b'(', b')')
        };
        let mut depth = 0i64;
        let mut close = bytes.len();
        for (k, &ch) in bytes[open..].iter().enumerate() {
            if ch == o {
                depth += 1;
            } else if ch == c {
                depth -= 1;
                if depth == 0 {
                    close = open + k;
                    break;
                }
            }
        }
        let body = String::from_utf8_lossy(&bytes[open + 1..close]).into_owned();
        out.push(format!("{name}\u{1}{body}"));
    }
    out
}

/// `ty` with every type it names opened, to a fixed point: an alias is read as what it aliases and
/// a struct or enum as what its fields hold, so `OnceLock<Erased>` with `type Erased =
/// Arc<RwLock<HashMap<…>>>` reads as the map it is, and so does a struct wrapping one. A name is
/// read as its definition in the crate the text sits in; failing that, as its definition in a crate
/// that text (`context`, the store's whole file for the static's own type) reaches by path
/// (`busbar_contract::…`). A name spelled through `std::`, `core::` or `alloc::` is the standard
/// library's, never a workspace type of the same name.
fn expand_type(ty: &str, rel: &str, context: &str, defs: &TypeDefs) -> Result<String, String> {
    let ident = Regex::new(
        r"(?:\b(?:std|core|alloc)::(?:[A-Za-z_][A-Za-z0-9_]*::)*)?[A-Za-z_][A-Za-z0-9_]*",
    )?;
    let reaches = |text: &str, krate: &str| {
        krate
            .strip_prefix("crates/")
            .is_some_and(|name| text.contains(&format!("{}::", name.replace('-', "_"))))
    };
    let mut out = ty.to_string();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut frontier = vec![(
        ty.to_string(),
        crate_dir_of(rel).to_string(),
        context.to_string(),
    )];
    while let Some((t, krate, ctx)) = frontier.pop() {
        for m in ident.find_iter(t.as_bytes()) {
            let Some(name) = m.str_of(t.as_bytes(), 0) else {
                continue;
            };
            if name.contains("::") || seen.len() >= 512 || !seen.insert(name.clone()) {
                continue;
            }
            let Some(all) = defs.get(&name) else {
                continue;
            };
            let own: Vec<&(String, String)> = all.iter().filter(|(k, _)| *k == krate).collect();
            let picked: Vec<&(String, String)> = if own.is_empty() {
                all.iter().filter(|(k, _)| reaches(&ctx, k)).collect()
            } else {
                own
            };
            for (k, body) in picked {
                out.push('\n');
                out.push_str(body);
                frontier.push((body.clone(), k.clone(), body.clone()));
            }
        }
    }
    Ok(out)
}

/// Lines `from..=to` (1-based, as [`Line::no`] counts them) of a file's scan, by index: a scan's
/// lines are numbered from 1 with no gaps.
fn span(lines: &[Line], from: usize, to: usize) -> &[Line] {
    let lo = from.saturating_sub(1).min(lines.len());
    let hi = to.min(lines.len()).max(lo);
    &lines[lo..hi]
}

/// The text of `f`'s header (from `fn` to the body's opening brace), its parameter list and its
/// return type (empty when it returns `()`).
fn header_parts(lines: &[Line], f: &Fnc) -> Result<(String, String, String), String> {
    let header: String = span(lines, f.start, f.body_start)
        .iter()
        .map(|x| x.code.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let Some(at) = Regex::new(&format!(r"(?<![A-Za-z0-9_])fn\s+{}\b", rx::escape(&f.name)))?
        .search(header.as_bytes())
    else {
        return Ok((header, String::new(), String::new()));
    };
    let Some(open) = header[at.end..].find('(').map(|o| at.end + o) else {
        return Ok((header, String::new(), String::new()));
    };
    let mut depth = 0i64;
    let mut close = header.len();
    for (i, ch) in header[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let params = header[open + 1..close.min(header.len())].to_string();
    let rest = &header[close.min(header.len())..];
    let ret = match rest.find("->") {
        Some(a) => {
            let r = &rest[a + 2..];
            let end = [r.find('{'), r.find(" where ")]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(r.len());
            r[..end].to_string()
        }
        None => String::new(),
    };
    Ok((header, params, ret))
}

/// The module name a path call reaches `rel`'s fns through: the file stem, or the directory's name
/// for a `mod.rs` or `lib.rs`.
fn module_of(rel: &str) -> &str {
    let mut parts = rel.rsplit('/');
    let file = parts.next().unwrap_or_default();
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    if stem == "mod" || stem == "lib" {
        parts.next().unwrap_or(stem)
    } else {
        stem
    }
}

/// WHERE A STATIC'S TYPE ENDS: the first `;` or `=` (not a `=>`) at bracket depth 0. A `;` inside
/// `[u8; 0]` or a tuple, and an `=` inside `dyn Iterator<Item = T>`, are the type's own (a6 on
/// #1454: `static TUPLED: ([u8; 0], OnceLock<Vec<String>>)` read as `([u8`). An `->` is not a
/// closing `>`. `None`: the type has not ended in `text`.
fn type_end(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let mut depth = 0i64;
    for (i, &ch) in b.iter().enumerate() {
        match ch {
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            b'>' if i > 0 && (b[i - 1] == b'-' || b[i - 1] == b'=') => {}
            b')' | b']' | b'}' | b'>' => depth -= 1,
            b';' if depth <= 0 => return Some(i),
            b'=' if depth <= 0 && b.get(i + 1) != Some(&b'>') => return Some(i),
            _ => {}
        }
    }
    None
}

/// The line spans (1-based, inclusive) of a file's trait bodies and trait impls: a method there is
/// callable by whoever holds the trait object or the type, `pub` or not (a6 on #1454: a
/// trait-method installer). Read on the blanked text, so a brace in a literal is not structure.
fn trait_spans(lines: &[Line], head: &Regex) -> Vec<(usize, usize)> {
    let text: String = lines
        .iter()
        .map(|l| l.blank.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = text.as_bytes();
    let breaks: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter(|(_, c)| **c == b'\n')
        .map(|(i, _)| i)
        .collect();
    let line_of = |at: usize| breaks.partition_point(|&b| b < at) + 1;
    let mut out = Vec::new();
    for m in head.find_iter(bytes) {
        let open = m.end.saturating_sub(1);
        let mut depth = 0i64;
        let mut close = bytes.len().saturating_sub(1);
        for (k, &ch) in bytes[open..].iter().enumerate() {
            if ch == b'{' {
                depth += 1;
            } else if ch == b'}' {
                depth -= 1;
                if depth == 0 {
                    close = open + k;
                    break;
                }
            }
        }
        out.push((line_of(open), line_of(close)));
    }
    out
}

/// A static a `macro_rules!` body declares under a metavariable name (`static $name: …`) is the
/// static each invocation of that macro names (a6 on #1454: a macro-generated static). The macro is
/// the last `macro_rules!` opened above line `idx`; every invocation of it in `texts` is read, and
/// returned are the names its arguments carry (an identifier not spelled as a type, a path segment
/// or a call) and the arguments' text, which is read with the static's type (a `$ty` metavariable
/// is whatever the invocation hands it).
fn macro_static_names(
    lines: &[Line],
    idx: usize,
    texts: &BTreeMap<&str, String>,
) -> Result<(Vec<String>, String), String> {
    let opener = Regex::new(r"\bmacro_rules!\s*([A-Za-z_][A-Za-z0-9_]*)")?;
    let Some(mac) = lines[..=idx].iter().rev().find_map(|l| {
        opener
            .search(l.code_bytes())
            .and_then(|m| m.str_of(l.code_bytes(), 1))
    }) else {
        return Ok((Vec::new(), String::new()));
    };
    let call = Regex::new(&format!(
        r"(?<![A-Za-z0-9_]){}!\s*[(\[{{]",
        rx::escape(&mac)
    ))?;
    let ident =
        Regex::new(r"(?<![A-Za-z0-9_:$])[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])(?!\s*(?:::|!|\())")?;
    const NOT_NAMES: &[&str] = &[
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
        "f32", "f64", "bool", "char", "str", "mut", "ref", "dyn", "impl", "const", "static",
        "crate", "self", "super", "pub", "fn", "move", "as", "where", "for",
    ];
    let mut names = Vec::new();
    let mut args_all = String::new();
    for text in texts.values().filter(|t| t.contains(&format!("{mac}!"))) {
        let bytes = text.as_bytes();
        for m in call.find_iter(bytes) {
            let open = m.end - 1;
            let mut depth = 0i64;
            let mut close = bytes.len();
            for (k, &ch) in bytes[open..].iter().enumerate() {
                match ch {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = open + k;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let args = String::from_utf8_lossy(&bytes[open + 1..close]).into_owned();
            for a in ident.find_iter(args.as_bytes()) {
                let Some(word) = a.str_of(args.as_bytes(), 0) else {
                    continue;
                };
                let camel = word.starts_with(|c: char| c.is_ascii_uppercase())
                    && word.contains(|c: char| c.is_ascii_lowercase());
                if !camel && !NOT_NAMES.contains(&word.as_str()) && !names.contains(&word) {
                    names.push(word);
                }
            }
            args_all.push('\n');
            args_all.push_str(&args);
        }
    }
    Ok((names, args_all))
}

/// One installed store: its file, line and name, and every way the code outside the kernel reaches
/// it (`pub static`, `pub fn x`, `pub fn x (returns the cell)`, `pub fn x (through y)`).
struct Store {
    rel: String,
    no: usize,
    name: String,
    installers: Vec<String>,
}

/// One fn of the scanned scope, read once: whether it is `pub`, whether it takes a value, and the
/// type it returns.
struct F<'a> {
    rel: &'a str,
    f: &'a Fnc,
    public: bool,
    valued: bool,
    ret: String,
}

/// The installed stores of `files`. A STORE is a static of any name, plain, `mut`, inside a
/// `thread_local!` or a `lazy_static!` (`static ref`), or declared by a `macro_rules!` under a
/// metavariable ([`macro_static_names`]), whose type, read to its top-level end ([`type_end`]),
/// through every alias and into every field ([`expand_type`]), names a cell of `cells` and matches
/// one of `holds`. It is INSTALLED when code outside the kernel can reach it: the static is `pub`;
/// a `pub fn` or a trait method ([`trait_spans`]) that takes a value names it; one names it and
/// returns a cell; or one that takes a value calls, anywhere in `files`, a fn of the store's file
/// that takes a value and names it (a setter one call away, by path or by the name a `use` imports
/// it under).
fn installed_stores(
    tree: &Tree,
    files: &[&String],
    cells: &Regex,
    holds: &[Regex],
) -> Result<Vec<Store>, String> {
    let decl = Regex::new(
        r"(?:^|[^A-Za-z0-9_'])static\s+(?:(mut|ref)\s+)?(\$?[A-Za-z_][A-Za-z0-9_]*)\s*:",
    )?;
    let pub_static = Regex::new(r"(?:^|[^A-Za-z0-9_'(])pub\s+static\b")?;
    let pub_fn = Regex::new(
        r#"(?:^|[^A-Za-z0-9_(])pub\s+(?:(?:const|async|unsafe)\s+|extern\s+"[^"]*"\s+)*fn\s"#,
    )?;
    let self_param = Regex::new(r"^\s*&?\s*(?:'[A-Za-z_]+\s+)?(?:mut\s+)?self\b")?;
    let trait_head = Regex::new(
        r"(?:^|[^A-Za-z0-9_])(?:impl\b[^{;]*\bfor\b[^{;]*|trait\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*)\{",
    )?;
    // AN INTEGER CELL HOLDING AN ERASED POINTER (a6 on #1454: a ptr/len pair of `AtomicUsize`s). A
    // static whose type is a pointer-sized atomic integer holds a collection when a fn of its file
    // names it and launders a pointer through an integer: one way in (`as_ptr`, `into_raw`, `leak`,
    // an `as *const` cast, `addr`) or the other way out (`from_raw`, `from_raw_parts`). It is then
    // read as a store, with the same installers as any other.
    let int_cell = Regex::new(r"\bAtomic(?:Usize|Isize|U64|I64)\b")?;
    let launder = Regex::new(
        r"\bas_(?:mut_)?ptr\s*\(|\binto_raw\s*\(|\bfrom_raw(?:_parts)?\s*\(|\bleak\s*\(|\bas\s+\*\s*(?:const|mut)\b|\.addr\s*\(|\bexpose_provenance\s*\(",
    )?;
    let defs = type_defs(tree)?;
    let takes_a_value = |params: &str| {
        params
            .split(',')
            .any(|p| !p.trim().is_empty() && !self_param.is_match_str(p))
    };
    // Every non-test fn of the scope, with its header parts, once.
    let mut all_fns: Vec<F> = Vec::new();
    for rel in files {
        let (Some(lines), Some(fns)) = (tree.files.get(rel.as_str()), tree.fns.get(rel.as_str()))
        else {
            continue;
        };
        // A method of a trait body or a trait impl is reachable as the trait is, `pub` or not.
        // Memoised on the file's scan, as the type definitions are.
        let traits: Vec<(usize, usize)> = memo_file_scan(
            "kernel-no-protocol-registry:trait-spans".to_string(),
            lines,
            |lines| {
                trait_spans(lines, &trait_head)
                    .into_iter()
                    .map(|(a, b)| format!("{a} {b}"))
                    .collect()
            },
        )
        .iter()
        .filter_map(|s| {
            let (a, b) = s.split_once(' ')?;
            Some((a.parse().ok()?, b.parse().ok()?))
        })
        .collect();
        for f in fns.iter().filter(|f| !f.intest) {
            let (header, params, ret) = header_parts(lines, f)?;
            let in_trait = traits.iter().any(|&(a, b)| a < f.start && f.start <= b);
            all_fns.push(F {
                rel: rel.as_str(),
                f,
                public: in_trait || pub_fn.is_match_str(&header),
                valued: takes_a_value(&params),
                ret,
            });
        }
    }
    let body_names = |rel: &str, f: &Fnc, rx_: &Regex, skip_line: usize| -> bool {
        tree.files.get(rel).is_some_and(|lines| {
            span(lines, f.start, f.end)
                .iter()
                .filter(|x| x.no != skip_line)
                .any(|x| rx_.is_match(x.code_bytes()))
        })
    };
    // Each scanned file's code, joined once.
    let texts: BTreeMap<&str, String> = files
        .iter()
        .filter_map(|rel| {
            let lines = tree.files.get(rel.as_str())?;
            let text = lines
                .iter()
                .map(|x| x.code.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            Some((rel.as_str(), text))
        })
        .collect();
    let mut out = Vec::new();
    for rel in files {
        let Some(lines) = tree.files.get(rel.as_str()) else {
            continue;
        };
        let context = texts.get(rel.as_str()).map_or("", String::as_str);
        for (idx, l) in lines.iter().enumerate() {
            if l.intest {
                continue;
            }
            let Some(m) = decl.search(l.code_bytes()) else {
                continue;
            };
            let Some(name) = m.str_of(l.code_bytes(), 2) else {
                continue;
            };
            // A `static mut` is its own cell, and a `lazy_static!` `static ref` is a lazy one.
            let own_cell = m.group(1).is_some();
            // The type: from the `:` to the first `=` that is not a `=>`, or the first `;` (a
            // `task_local!` static has no initialiser), at bracket depth 0 ([`type_end`]), across
            // lines (at most 64: a type that never ends is read as far as that).
            let mut ty = l.code[m.end..].to_string();
            let mut j = idx;
            while type_end(&ty).is_none() && j + 1 < lines.len() && j < idx + 64 {
                j += 1;
                ty.push('\n');
                ty.push_str(&lines[j].code);
            }
            let ty = match type_end(&ty) {
                Some(end) => ty[..end].to_string(),
                None => ty,
            };
            // A static a macro declares under a metavariable is each static its invocations name,
            // its type read with what they hand it.
            let (names, handed) = if name.starts_with('$') {
                macro_static_names(lines, idx, &texts)?
            } else {
                (vec![name], String::new())
            };
            let ty = expand_type(&format!("{ty}{handed}"), rel, context, &defs)?;
            let celled =
                (own_cell || cells.is_match_str(&ty)) && holds.iter().any(|h| h.is_match_str(&ty));
            if !celled && !int_cell.is_match_str(&ty) {
                continue;
            }
            for name in names {
                let named = Regex::new(&format!(
                    r"(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])",
                    rx::escape(&name)
                ))?;
                let own: Vec<&F> = all_fns
                    .iter()
                    .filter(|x| x.rel == rel.as_str() && body_names(x.rel, x.f, &named, l.no))
                    .collect();
                if !celled && !own.iter().any(|x| body_names(x.rel, x.f, &launder, 0)) {
                    continue;
                }
                let mut installers = Vec::new();
                if pub_static.is_match(&l.code_bytes()[..m.end.min(l.code.len())]) {
                    installers.push("pub static".to_string());
                }
                for x in &own {
                    if x.public && x.valued {
                        installers.push(format!("pub fn {}", x.f.name));
                    } else if x.public
                        && cells.is_match_str(&expand_type(&x.ret, rel, context, &defs)?)
                    {
                        installers.push(format!("pub fn {} (returns the cell)", x.f.name));
                    }
                }
                // A setter one call away: a fn of this file that takes a value and names the
                // store, called by a `pub fn` that takes a value: from this file by a bare, path or
                // `self.` call (not another receiver's method), and from any other file by a call
                // through the store's module (`door::setter(`), or by a bare call of the name that
                // file `use`s it under (`use …::door::setter;`, `door::{setter as put}`,
                // `door::*`; a6 on #1454), so a same-named fn elsewhere is not read as this one.
                for setter in own.iter().filter(|x| x.valued) {
                    let (module, fname) = (rx::escape(module_of(rel)), rx::escape(&setter.f.name));
                    let near =
                        Regex::new(&format!(r"(?:(?<![.A-Za-z0-9_])|\bself\.){fname}\s*\("))?;
                    let far = Regex::new(&format!(r"\b{module}::{fname}\s*\("))?;
                    let braced = r"(?:\{[^;]*?)?";
                    let alias = r"(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?";
                    let import = Regex::new(&format!(
                        r"\buse\b[^;]*\b{module}::{braced}\b{fname}\b{alias}"
                    ))?;
                    let glob = Regex::new(&format!(r"\buse\b[^;]*\b{module}::\*"))?;
                    // A file that never spells the path and imports no name of it holds no far
                    // call: skipped unread.
                    let path = format!("{}::{}", module_of(rel), setter.f.name);
                    let prefix = format!("{}::", module_of(rel));
                    let star = format!("{prefix}*");
                    let mut far_calls: BTreeMap<&str, Vec<Regex>> = BTreeMap::new();
                    for (file, text) in &texts {
                        if *file == setter.rel {
                            continue;
                        }
                        let mut calls = Vec::new();
                        if text.contains(&path) {
                            calls.push(far.clone());
                        }
                        let mut imported: Vec<String> = Vec::new();
                        if text.contains(&prefix) && text.contains(setter.f.name.as_str()) {
                            for mm in import.find_iter(text.as_bytes()) {
                                imported.push(
                                    mm.str_of(text.as_bytes(), 1)
                                        .unwrap_or_else(|| setter.f.name.clone()),
                                );
                            }
                        }
                        if text.contains(&star) && glob.is_match_str(text) {
                            imported.push(setter.f.name.clone());
                        }
                        for n in imported {
                            let n = rx::escape(&n);
                            calls.push(Regex::new(&format!(r"(?<![.A-Za-z0-9_:]){n}\s*\("))?);
                        }
                        if !calls.is_empty() {
                            far_calls.insert(*file, calls);
                        }
                    }
                    for caller in all_fns.iter().filter(|x| {
                        x.public
                            && x.valued
                            && !(x.rel == setter.rel && x.f.start == setter.f.start)
                            && (x.rel == setter.rel || far_calls.contains_key(x.rel))
                    }) {
                        let label = format!("pub fn {} (through {})", caller.f.name, setter.f.name);
                        let direct = format!("pub fn {}", caller.f.name);
                        if installers.contains(&label) || installers.contains(&direct) {
                            continue;
                        }
                        let same = [near.clone()];
                        let call: &[Regex] = if caller.rel == setter.rel {
                            &same
                        } else {
                            far_calls.get(caller.rel).map(Vec::as_slice).unwrap_or(&[])
                        };
                        let calls = tree.files.get(caller.rel).is_some_and(|ls| {
                            span(ls, caller.f.start + 1, caller.f.end)
                                .iter()
                                .any(|y| call.iter().any(|c| c.is_match(y.code_bytes())))
                        });
                        if calls {
                            installers.push(label);
                        }
                    }
                }
                if !installers.is_empty() {
                    out.push(Store {
                        rel: rel.to_string(),
                        no: l.no,
                        name,
                        installers,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// THE KERNEL HOLDS NO PROTOCOL REGISTRY (status row 82, D2; spec Part 1, Law 5). The kernel's
/// `proto/` registry left the tree, and with it the census row that held `fn decl_for(` to one
/// site: a ban whose subject left reads green over nothing, and a registry grown back in the kernel
/// (a `ProtocolDecl` table behind a static, an `install_protocols` seam the root fills, a by-name
/// `decl_for`) would pass `no-uninstalled-seam` because the root installs it.
///
/// Two rows. The NAMES row refuses those spellings in the kernel's production code, and every alias
/// of them the workspace declares, so a `pub type Dialect = ProtocolDecl;` in the contract hides
/// nothing. The INSTALLED-STORE row refuses the same registry with no name to find, by its shape
/// ([`installed_stores`]): a kernel static of any name and spelling whose type, read through its
/// aliases and fields, is a cell holding a collection, a slice, an array or a trait object, and
/// that code outside the kernel reaches (a `pub static`, a `pub fn` taking a value, an accessor
/// returning the cell, a setter one call away). The DEBT row counts the root-installed stores keyed
/// by plane, protocol or plugin identity the kernel still holds (`debt_stores`, ceiling `max_debt`, which only falls);
/// every other store it holds today is named in `exempt_stores` with why. A new store is a finding,
/// and a named one that no longer matches is stale. Each row's floor is its scope: a kernel with no
/// production source in the tree is refused.
pub fn kernel_no_protocol_registry(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("kernel-no-protocol-registry")?;
    let max_hits = need_int(c, "max_hits", "kernel-no-protocol-registry")?;
    // Each row holds its own ceiling: a store held under the NAMES row's figure would let a
    // `ProtocolDecl` back in under the store row's, and the reverse (a6 on #1454).
    let max_stores = need_int(c, "max_stores", "kernel-no-protocol-registry")?;
    let (names, fn_names) = (c.list_of("names"), c.list_of("fn_names"));
    if names.is_empty() && fn_names.is_empty() {
        return Err("kernel-no-protocol-registry: no `names`, so it bans nothing".into());
    }
    let files = scoped_files(tree, &c.list_of("scope_globs"));

    // ── NAMES, and every alias of them.
    let mut targets = names.clone();
    targets.extend(fn_names.iter().cloned());
    let known = aliases_of(tree, &targets)?;
    let mut alternatives: Vec<String> = known
        .iter()
        .filter(|n| !fn_names.contains(n))
        .map(|n| format!(r"\b{}\b", rx::escape(n)))
        .collect();
    alternatives.extend(
        fn_names
            .iter()
            .map(|n| format!(r"\bfn\s+{}\b", rx::escape(n))),
    );
    let rx_pat = Regex::new(&alternatives.join("|"))?;
    let offenders: Vec<String> = tree
        .grep(&rx_pat, true, Some(&files))
        .into_iter()
        .map(|(rel, l)| format!("{rel}:{}", l.no))
        .collect();
    let aliases: Vec<String> = known
        .iter()
        .filter(|n| !targets.contains(n))
        .cloned()
        .collect();
    let current = offenders.len() as i64;
    let detail = if files.is_empty() {
        format!("{VACUOUS}no kernel production source is present in the scanned tree")
    } else {
        format!(
            "{current} protocol-registry spelling(s) in the kernel's production code (ceiling \
             {max_hits}; aliases read: {}): {}",
            join_or_none(&aliases),
            join_or_none(&offenders)
        )
    };
    let names_row = plain(
        "kernel-no-protocol-registry",
        !files.is_empty() && current <= max_hits,
        "the kernel holds no protocol registry: no ProtocolDecl, no install_protocols, no decl_for, \
         under any alias",
        detail,
        current,
        max_hits,
        offenders,
    );

    // ── THE INSTALLED STORE, by shape.
    let cells = Regex::new(&format!(
        r"\b(?:{})\b",
        c.list_of("store_cells")
            .iter()
            .map(|w| rx::escape(w))
            .collect::<Vec<_>>()
            .join("|")
    ))?;
    let holds = c
        .list_of("store_holds")
        .iter()
        .map(|h| Regex::new(h))
        .collect::<Result<Vec<_>, _>>()?;
    let skip = c.list_of("store_exempt_path_fragments");
    let keys_of = |list: &str| -> Vec<String> {
        c.list_of(list)
            .iter()
            .map(|e| {
                e.split(" -- ")
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            })
            .collect()
    };
    let exempt = keys_of("exempt_stores");
    let debt = keys_of("debt_stores");
    let max_debt = need_int(c, "max_debt", "kernel-no-protocol-registry")?;
    let mut stores = Vec::new();
    let mut seen = Vec::new();
    let mut debt_seen = Vec::new();
    let store_files: Vec<&String> = files
        .iter()
        .filter(|r| !skip.iter().any(|s| r.contains(s.as_str())))
        .collect();
    for Store {
        rel,
        no,
        name,
        installers,
    } in installed_stores(tree, &store_files, &cells, &holds)?
    {
        let key = format!("{rel}::{name}");
        if debt.contains(&key) {
            if !debt_seen.contains(&key) {
                debt_seen.push(key);
            }
        } else if exempt.contains(&key) {
            if !seen.contains(&key) {
                seen.push(key);
            }
        } else {
            stores.push(format!(
                "static {name} at {rel}:{no}, installed through {}",
                installers.join(", ")
            ));
        }
    }
    let stale: Vec<String> = exempt
        .iter()
        .filter(|e| !seen.contains(e))
        .map(|e| format!("stale exemption {e}: no installed store of that name"))
        .collect();
    let mut found = stores.clone();
    found.extend(stale.iter().cloned());
    let current = found.len() as i64;
    let detail = if files.is_empty() {
        format!("{VACUOUS}no kernel production source is present in the scanned tree")
    } else {
        format!(
            "{} installed store(s) in the kernel outside the {} named ones, {} stale exemption(s) \
             (ceiling {max_stores}): {}",
            stores.len(),
            exempt.len(),
            stale.len(),
            join_or_none(&found)
        )
    };
    let store_row = plain(
        ROW_INSTALLED_STORE,
        !files.is_empty() && current <= max_stores,
        "the kernel holds no installed store beside the named ones: no registry behind a type-erased \
         static",
        detail,
        current,
        max_stores,
        found,
    );

    // ── THE DEBT: the stores keyed by plane or protocol identity the kernel still holds. The list
    // may not grow past `max_debt`, a drained entry is struck, and `max_debt` falls to the count.
    let mut debt_findings: Vec<String> = debt
        .iter()
        .filter(|d| !debt_seen.contains(d))
        .map(|d| format!("drained debt {d}: strike it and lower max_debt"))
        .collect();
    // Every debt site is ledgered by name WITH ITS DRAIN (ARCHITECT ruling on #1454): an entry
    // whose reason cites no `drain:` is debt nobody owns.
    debt_findings.extend(
        c.list_of("debt_stores")
            .iter()
            .filter(|e| !cites_drain(e))
            .map(|e| {
                format!(
                    "debt {} cites no drain: name its drain lane (`-- why; drain: <lane>`)",
                    e.split(" -- ").next().unwrap_or_default().trim()
                )
            }),
    );
    let counted = debt_seen.len() as i64;
    if debt.len() as i64 > max_debt {
        debt_findings.push(format!(
            "the debt list names {} store(s) over its ceiling of {max_debt}: it may not grow",
            debt.len()
        ));
    }
    if counted < max_debt {
        debt_findings.push(format!(
            "{counted} debt store(s) under a ceiling of {max_debt}: lower max_debt to {counted} in \
             the commit that drained it"
        ));
    }
    let detail = if files.is_empty() {
        format!("{VACUOUS}no kernel production source is present in the scanned tree")
    } else {
        format!(
            "{counted} installed store(s) keyed by plane or protocol identity (ceiling {max_debt}): \
             {}; {}",
            join_or_none(&debt_seen),
            join_or_none(&debt_findings)
        )
    };
    let debt_row = plain(
        ROW_STORE_DEBT,
        !files.is_empty() && debt_findings.is_empty() && counted <= max_debt,
        "the kernel's plane- and protocol-keyed stores are counted debt, and the count only falls",
        detail,
        counted,
        max_debt,
        debt_findings,
    );
    Ok(vec![names_row, store_row, debt_row])
}

/// A debt entry's reason names its drain: `path::STATIC -- why; drain: <lane>`.
fn cites_drain(entry: &str) -> bool {
    let why = entry.split_once(" -- ").map_or("", |(_, why)| why);
    let drain = why.split_once("drain:").map_or("", |(_, d)| d);
    !drain.trim().is_empty()
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
        // Every input of the per-file scan is in the tag; see `memo_file_scan`.
        let tag = format!(
            "plane-no-money\u{1}{rel}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
            sym_rx.as_str(),
            path_rx.as_str(),
            allowed.join("\u{2}"),
            here.join("\u{2}")
        );
        let found = memo_file_scan(tag, &tree.files[rel], |lines| {
            let mut out = Vec::new();
            for l in lines {
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
                    out.push(format!("`{w}` at {rel}:{}", l.no));
                    break;
                }
                if let Some(pm) = path_rx.search(bytes) {
                    out.push(format!(
                        "`{}` at {rel}:{}",
                        pm.str_of(bytes, 0).unwrap_or_default(),
                        l.no
                    ));
                }
            }
            out
        });
        offenders.extend(found.iter().cloned());
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

/// THE ONE FUNCTION UNDER ANOTHER NAME: every production function in the cost unit (`cost_path`)
/// whose signature names one of `wrapper_inputs` (the one function's own input, the ledger slice)
/// and whose body reaches a pricing entry. "Reaches" is a call matching an `entry_path_patterns`
/// tail (`price_in_view(`, `price_exact(`, `apply_tier(`), one of `wrapper_reaches` (the
/// accumulator itself), or a call to a wrapper already found, so a wrapper around a wrapper is
/// found too. The NAME plays no part: renaming a wrapper does not hide it.
///
/// Returns the wrappers the path patterns do NOT already see (those are counted there), and how
/// many functions matched in all, the one function itself included. A count of zero is a blind
/// scan, not a clean one.
fn pricing_wrappers(
    tree: &Tree,
    c: &Table,
    cost_path: &str,
    path_rx: &Regex,
) -> Result<(Vec<String>, usize), String> {
    use crate::gates::construction::model::word;
    const COST_PATH: &str = "busbar_kernel_ledger::cost::";
    let inputs = c.list_of("wrapper_inputs");
    if inputs.is_empty() {
        return Err(
            "[rules.one-pricing-site] lists no `wrapper_inputs`, so a pricing entry under another \
             name is invisible"
                .to_string(),
        );
    }
    let input_rx = Regex::new(&inputs.iter().map(|t| word(t)).collect::<Vec<_>>().join("|"))?;
    let mut reach: Vec<String> = c
        .list_of("entry_path_patterns")
        .iter()
        .map(|p| {
            let tail = p.strip_prefix(COST_PATH).unwrap_or(p);
            format!(r"(?<![A-Za-z0-9_])(?:{tail})[A-Za-z0-9_]*\s*\(")
        })
        .collect();
    reach.extend(c.list_of("wrapper_reaches"));

    // (name, signature, body), over the blanked text so a string literal neither opens a body nor
    // reads as a call.
    let mut candidates: Vec<(String, String, String)> = Vec::new();
    for (rel, fns) in &tree.fns {
        if !(rel == cost_path || rel.starts_with(&format!("{cost_path}/"))) {
            continue;
        }
        let Some(lines) = tree.files.get(rel) else {
            continue;
        };
        for f in fns.iter().filter(|f| !f.intest) {
            let text = lines
                .iter()
                .filter(|l| l.no >= f.start && l.no <= f.end)
                .map(|l| l.blank.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let Some(open) = text.find('{') else {
                continue;
            };
            candidates.push((
                f.name.clone(),
                text[..open].to_string(),
                text[open..].to_string(),
            ));
        }
    }

    let mut found: Vec<String> = Vec::new();
    loop {
        let mut pats = reach.clone();
        pats.extend(found.iter().map(|n| format!(r"{}\s*\(", word(n))));
        let reach_rx = Regex::new(&pats.join("|"))?;
        let before = found.len();
        for (name, sig, body) in &candidates {
            if !found.contains(name) && input_rx.is_match_str(sig) && reach_rx.is_match_str(body) {
                found.push(name.clone());
            }
        }
        if found.len() == before {
            break;
        }
    }
    let seen = found.len();
    let mut wrappers: Vec<String> = found
        .into_iter()
        .filter(|n| !path_rx.is_match_str(&format!("{COST_PATH}{n}")))
        .collect();
    wrappers.sort();
    wrappers.dedup();
    Ok((wrappers, seen))
}

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
    // THE ONE FUNCTION UNDER ANOTHER NAME (ARCHITECT 2026-09-30). A cost-unit function that
    // takes the one function's own input and hands it on to a pricing entry IS that entry, whatever
    // it is called, so a call to it from outside the homes is counted like a call to the entry.
    let cost_home = need_str(c, "wrapper_home", "one-pricing-site")?;
    let cost_path = homes
        .iter()
        .find(|(k, _)| k == cost_home)
        .map(|(_, p)| p.clone())
        .ok_or_else(|| {
            format!(
                "[rules.one-pricing-site] wrapper_home = \"{cost_home}\" names no \
                 [rules.one-pricing-site.allowed.*] home"
            )
        })?;
    let (wrappers, seen_inputs) = pricing_wrappers(tree, c, &cost_path, &path_rx)?;
    for w in &wrappers {
        for (rel, l) in call_sites(tree, w, None)? {
            let names_cost_unit = tree
                .files
                .get(rel)
                .is_some_and(|ls| ls.iter().any(|x| x.code.contains("busbar_kernel_ledger")));
            if names_cost_unit {
                sites.push((
                    format!("`busbar_kernel_ledger::cost::{w}` (a renamed pricing entry)"),
                    rel.to_string(),
                    l.no,
                ));
            }
        }
    }
    let (mut extra, mut inside) = (Vec::new(), Vec::new());
    for (what, rel, no) in &sites {
        match home_of(rel) {
            Some(key) => inside.push(format!("{what} at {rel}:{no} ({key})")),
            None => extra.push(format!("{what} at {rel}:{no}")),
        }
    }
    // BLIND, NOT CLEAN: the wrapper scan must at least see the one function itself take its input.
    // Zero means the input type was renamed under the scan, and every wrapper would go unseen.
    if seen_inputs == 0 {
        extra.push(format!(
            "the wrapper scan is BLIND: no function in {cost_path} takes any of {} and reaches a \
             pricing entry, not even the one function",
            py_list(&c.list_of("wrapper_inputs"))
        ));
    }
    let current = extra.len() as i64;
    let mut home_keys: Vec<String> = homes.iter().map(|(k, _)| k.clone()).collect();
    home_keys.sort();
    let detail = format!(
        "{current} pricing-entry call site(s) outside the reviewed homes {} (ceiling \
         {max_extra}): {}; reviewed sites seen: {}; entries under another name: {}",
        py_list(&home_keys),
        join_or_none(&extra),
        if inside.is_empty() {
            "NONE \u{2014} no production code prices at all today".to_string()
        } else {
            inside.join("; ")
        },
        join_or_none(&wrappers)
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
    let all_hits = tree.grep(&fee_rx, true, None);
    let mut sorted_crates = fee_crates.clone();
    sorted_crates.sort();
    if all_hits.is_empty() {
        // Zero hits for every spelling this rule knows means the rule is BLIND, not that the fee
        // is priced nowhere: a field rename can silently retire every spelling in `fee_fields`
        // while the rule keeps reporting whatever count it last saw. Zero is only ever read as
        // "I cannot see the fee" — it is always a FAIL, independent of `max_fee_readers`.
        rows.push(plain(
            "one-pricing-site:fee-fields",
            false,
            "the per-request fee is read only where the card lives",
            format!(
                "0 production read(s) anywhere in the tree of any of {} — the rule cannot see the \
                 fee (a spelling in `fee_fields` may no longer match the field the card uses), not \
                 evidence that the fee is priced nowhere",
                py_list(&fee_fields)
            ),
            0,
            max_fee,
            Vec::new(),
        ));
    } else {
        // THE REVIEWED FEE HOMES, and why this half has them at all. The entry-verb half above is
        // scoped by PATH (`[rules.one-pricing-site.allowed.*]`), and one of its homes is
        // `crates/busbar/src/root/` — "the composition root's meter and admission wiring". This
        // half was scoped by CRATE only, so the same rule said two different things about the same
        // root in the same breath. A crate list cannot express "this one reviewed file", and the
        // only widening it can offer is the whole `busbar` crate, which would bless `main.rs` and
        // every `units_*.rs` in one unargued stroke. So the grant is per PATH, with a COUNT, and
        // both halves of it bite: a read above `max` at a home is reported exactly like a read with
        // no home at all, and a home whose count falls to ZERO is reported too, because a grant
        // that describes nothing is the dead name this file has already been bitten by five times
        // — it stops applying in silence, and the next real read at that path inherits a waiver
        // nobody reviewed.
        let fee_homes: Vec<(String, String, i64)> = cfg
            .doc
            .children("rules.one-pricing-site.fee_allowed")
            .into_iter()
            .map(|(k, t)| {
                (
                    k,
                    t.str_of("path").unwrap_or("").to_string(),
                    t.int_of("max").unwrap_or(0),
                )
            })
            .collect();
        let mut seen_at_home: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut readers: Vec<String> = Vec::new();
        for (rel, l) in all_hits {
            if fee_crates.contains(&tree.crate_of(rel)) {
                continue;
            }
            let site = format!("{rel}:{}", l.no);
            match fee_homes
                .iter()
                .find(|(_, p, _)| !p.is_empty() && (rel == *p || rel.starts_with(&format!("{p}/"))))
            {
                Some((key, _, _)) => seen_at_home.entry(key.clone()).or_default().push(site),
                None => readers.push(site),
            }
        }
        let mut homes_detail: Vec<String> = Vec::new();
        for (key, _, max) in &fee_homes {
            let at = seen_at_home.get(key).cloned().unwrap_or_default();
            homes_detail.push(format!("{key} {}/{max}", at.len()));
            if at.is_empty() {
                readers.push(format!(
                    "[rules.one-pricing-site.fee_allowed.{key}] grants a reviewed fee home that \
                     reads no fee on this tree — a dead grant, to be deleted or repointed"
                ));
            }
            // Over the reviewed count, the SURPLUS is named. Which of the reads is the new one is
            // not knowable from a count, so the whole home is named once rather than an arbitrary
            // tail of it being blamed.
            if at.len() as i64 > *max {
                readers.push(format!(
                    "{key}: {} read(s) where {max} were reviewed ({})",
                    at.len(),
                    at.join(", ")
                ));
            }
        }
        let detail = format!(
            "{} production read(s) of {} outside {} (ceiling {max_fee}){}: {}",
            readers.len(),
            py_list(&fee_fields),
            py_list(&sorted_crates),
            if homes_detail.is_empty() {
                String::new()
            } else {
                format!(" and the reviewed fee homes [{}]", homes_detail.join(", "))
            },
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
    }
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
