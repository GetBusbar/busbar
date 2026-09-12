//! THE SHAPE RULES: the attempt seam, request-path function size, the plane/kernel wall, the
//! installable seams, the neutral crates' vocabulary, the request terminal, and the Teller loop.
//!
//! Each is a line-for-line port of the matching `rule_*` in `scripts/construction-gate/rules.py`,
//! including the wording of every `detail` column, because those columns are what
//! `cargo xtask gate construction --parity` compares.

use std::collections::BTreeMap;

use crate::ctx::Ctx;
use crate::gates::construction::model::{
    self, need_int, need_str, plain, py_dict, py_list, sorted_unique, use_line_rx, word, CRow, Cfg,
    VACUOUS,
};
use crate::gates::construction::step_order;
use crate::gates::construction::tree::{fnmatch, Fnc, Line, Tree};
use crate::ledger::Status;
use crate::rx::{self, Regex};

/// Production lines calling `verb(`, excluding its own definition and `use` lines.
pub fn call_sites<'t>(
    tree: &'t Tree,
    verb: &str,
    files: Option<&[String]>,
) -> Result<Vec<(&'t str, &'t Line)>, String> {
    let call_rx = Regex::new(&format!(r"{}\s*\(", word(verb)))?;
    let defn_rx = Regex::new(&format!(r"fn\s+{}(?![A-Za-z0-9_])", rx::escape(verb)))?;
    let use_rx = use_line_rx();
    Ok(tree
        .grep(&call_rx, true, files)
        .into_iter()
        .filter(|(_, l)| {
            !defn_rx.is_match(l.code_bytes()) && use_rx.match_at(l.code_bytes(), 0).is_none()
        })
        .collect())
}

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

// ── 1. one-attempt-seam ──────────────────────────────────────────────────────────────────────────

pub fn one_attempt_seam(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("one-attempt-seam")?;
    let allowed = need_str(c, "allowed_function", "one-attempt-seam")?;
    let ceiling = need_int(c, "max_extra_sites", "one-attempt-seam")?;
    let send = Regex::new(need_str(c, "send_verb", "one-attempt-seam")?)?;

    let mut extra: Vec<String> = Vec::new();
    let mut inside = 0usize;
    for (rel, l) in tree.grep(&send, true, None) {
        let fname = tree
            .enclosing_fn(rel, l.no)
            .map_or("<no enclosing fn>".to_string(), |f| f.name.clone());
        if fname == allowed {
            inside += 1;
        } else {
            extra.push(format!("{fname} at {rel}:{}", l.no));
        }
    }
    let mut offenders = extra;
    if inside == 0 {
        offenders.push(format!(
            "allowed function `{allowed}` performs no attempt at all (the seam moved; update \
             qa/construction.toml or restore it)"
        ));
    }
    let current = offenders.len() as i64;
    let detail = format!(
        "{current} attempt site(s) outside `{allowed}` (ceiling {ceiling}): {}",
        join_or_none(&offenders)
    );
    Ok(vec![plain(
        "one-attempt-seam",
        current <= ceiling,
        format!("exactly one function sends the upstream attempt (`{allowed}`)"),
        detail,
        current,
        ceiling,
        offenders,
    )])
}

// ── 2. request-path-fn-size ──────────────────────────────────────────────────────────────────────

fn is_glob(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

/// Resolve a `files` list that may mix exact paths and globs. A glob matching nothing is a NOTE,
/// not a finding: it names files a later step adds.
fn expand_files(tree: &Tree, patterns: &[String]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut matched, mut missing, mut empty_globs) = (Vec::new(), Vec::new(), Vec::new());
    for pat in patterns {
        if is_glob(pat) {
            let mut hits: Vec<String> = tree
                .fns
                .keys()
                .filter(|k| fnmatch(k, pat))
                .cloned()
                .collect();
            hits.sort();
            if hits.is_empty() {
                empty_globs.push(pat.clone());
            } else {
                for h in hits {
                    if !matched.contains(&h) {
                        matched.push(h);
                    }
                }
            }
        } else if tree.fns.contains_key(pat) {
            if !matched.contains(pat) {
                matched.push(pat.clone());
            }
        } else {
            missing.push(pat.clone());
        }
    }
    (matched, missing, empty_globs)
}

pub fn request_path_fn_size(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("request-path-fn-size")?;
    let max_lines = need_int(c, "max_lines", "request-path-fn-size")?;
    let top = need_int(c, "top", "request-path-fn-size")? as usize;
    let (files, missing, empty_globs) = expand_files(tree, &c.list_of("files"));

    let mut sized: Vec<&Fnc> = Vec::new();
    for rel in &files {
        for f in tree.fns.get(rel).into_iter().flat_map(|v| v.iter()) {
            if !f.intest {
                sized.push(f);
            }
        }
    }
    sized.sort_by_key(|f| std::cmp::Reverse(f.lines()));
    let over = sized
        .iter()
        .filter(|f| f.lines() as i64 > max_lines)
        .count();
    let worst = sized.first().map_or(0, |f| f.lines()) as i64;

    let code_lines = |f: &Fnc| -> usize {
        tree.files
            .get(&f.path)
            .map(|ls| {
                ls[f.start - 1..f.end]
                    .iter()
                    .filter(|l| !l.code.trim().is_empty())
                    .count()
            })
            .unwrap_or(0)
    };
    let mut offenders: Vec<String> = sized
        .iter()
        .take(top)
        .map(|f| {
            format!(
                "{} {} lines, {} of them code ({}:{})",
                f.name,
                f.lines(),
                code_lines(f),
                f.path,
                f.start
            )
        })
        .collect();
    if !missing.is_empty() {
        offenders.push(format!("listed file(s) not found: {}", missing.join(", ")));
    }
    if !empty_globs.is_empty() {
        offenders.push(format!(
            "glob(s) matching no file yet (not a finding): {}",
            empty_globs.join(", ")
        ));
    }
    let detail = format!(
        "{over} function(s) over {max_lines} lines; worst {worst}: {}",
        if offenders.is_empty() {
            "none".to_string()
        } else {
            offenders
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        }
    );
    Ok(vec![plain(
        "request-path-fn-size",
        over == 0 && missing.is_empty(),
        format!("request-path functions stay under {max_lines} lines"),
        detail,
        worst,
        max_lines,
        offenders,
    )])
}

// ── 3. ports-only / ports-only-tests ─────────────────────────────────────────────────────────────

pub fn ports_only(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let prod = cfg.rule("ports-only")?;
    let test = cfg.rule("ports-only-tests")?;
    let needle_raw = need_str(prod, "needle", "ports-only")?.to_string();
    let needle = Regex::new(&rx::escape(&needle_raw))?;
    let codecs = cfg.doc.table_or_empty("gate.plane_codec_crates");
    let prod_max = cfg
        .doc
        .table_or_empty("rules.ports-only.max_per_crate")
        .clone();
    let test_max = cfg
        .doc
        .table_or_empty("rules.ports-only-tests.max_per_crate")
        .clone();
    let _ = (prod, test);

    let mut rows = Vec::new();
    for crate_name in cfg.plane_crates()? {
        // A plane is BOTH halves: the crate under its own name and the pure `-codec` crate it shed.
        let mut prefixes = vec![format!("crates/{crate_name}/")];
        for extra in codecs.list_of(&crate_name) {
            prefixes.push(format!("crates/{extra}/"));
        }
        let mut per_file_prod: Vec<(String, usize)> = Vec::new();
        let mut per_file_test: Vec<(String, usize)> = Vec::new();
        for (rel, lines) in &tree.files {
            if !prefixes.iter().any(|p| rel.starts_with(p.as_str())) {
                continue;
            }
            let (mut np, mut nt) = (0usize, 0usize);
            for l in lines.iter() {
                if needle.is_match(l.code_bytes()) {
                    if l.intest {
                        nt += 1;
                    } else {
                        np += 1;
                    }
                }
            }
            if np > 0 {
                per_file_prod.push((rel.clone(), np));
            }
            if nt > 0 {
                per_file_test.push((rel.clone(), nt));
            }
        }
        for (rid, per_file, ceilings) in [
            ("ports-only", &per_file_prod, &prod_max),
            ("ports-only-tests", &per_file_test, &test_max),
        ] {
            let ceiling = ceilings.int_of(&crate_name).unwrap_or(0);
            let current: i64 = per_file.iter().map(|(_, n)| *n as i64).sum();
            let mut top = per_file.clone();
            top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            let offenders: Vec<String> = top
                .iter()
                .take(5)
                .map(|(rel, n)| format!("{n} in {rel}"))
                .collect();
            let kind = if rid == "ports-only" {
                "production"
            } else {
                "test"
            };
            let detail = format!(
                "{crate_name}: {current} `{needle_raw}` line(s) in {kind} code (ceiling {ceiling}){}",
                if offenders.is_empty() {
                    String::new()
                } else {
                    format!(": {}", offenders.join("; "))
                }
            );
            rows.push(plain(
                format!("{rid}:{crate_name}"),
                current <= ceiling,
                format!("{crate_name} names no `{needle_raw}` in {kind} code"),
                detail,
                current,
                ceiling,
                offenders,
            ));
        }
    }
    Ok(rows)
}

// ── 4. no-uninstalled-seam ───────────────────────────────────────────────────────────────────────

pub fn no_uninstalled_seam(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("no-uninstalled-seam")?;
    let max_uninstalled = need_int(c, "max_uninstalled", "no-uninstalled-seam")?;
    let name_rx = Regex::new(need_str(c, "seam_name_pattern", "no-uninstalled-seam")?)?;
    let exempt = c.list_of("exempt_seam_path_fragments");
    let non_production = c.list_of("non_production_path_fragments");
    // `seam_root` is one root or a LIST of them; the substrate is two crates now.
    let roots: Vec<String> = match c.get("seam_root") {
        Some(crate::toml_doc::Value::Str(s)) => vec![s.clone()],
        Some(crate::toml_doc::Value::Array(_)) => c.list_of("seam_root"),
        _ => return Err("[rules.no-uninstalled-seam] has no `seam_root`".to_string()),
    };
    let roots: Vec<String> = roots
        .iter()
        .map(|r| format!("{}/", r.trim_end_matches('/')))
        .collect();

    let static_rx =
        Regex::new(r"(?<![A-Za-z0-9_])static\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")?;
    let use_rx = use_line_rx();

    let mut seams: Vec<&Fnc> = Vec::new();
    for (rel, fns) in &tree.fns {
        if !roots.iter().any(|r| rel.starts_with(r.as_str())) {
            continue;
        }
        if exempt.iter().any(|f| rel.contains(f.as_str())) {
            continue;
        }
        let lines = &tree.files[rel];
        let mut statics: Vec<String> = Vec::new();
        for l in lines.iter() {
            for m in static_rx.find_iter(l.blank.as_bytes()) {
                if let Some(s) = m.str_of(l.blank.as_bytes(), 1) {
                    if !statics.contains(&s) {
                        statics.push(s);
                    }
                }
            }
        }
        if statics.is_empty() {
            continue;
        }
        let static_rxs: Vec<Regex> = statics
            .iter()
            .map(|s| {
                Regex::new(&format!(
                    "(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])",
                    rx::escape(s)
                ))
            })
            .collect::<Result<_, _>>()?;
        for f in fns.iter() {
            if f.intest || name_rx.match_at(f.name.as_bytes(), 0).is_none() {
                continue;
            }
            let body: String = lines[f.body_start - 1..f.end]
                .iter()
                .map(|l| l.code.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            if static_rxs.iter().any(|r| r.is_match_str(&body)) {
                seams.push(f);
            }
        }
    }

    let (mut offenders, mut installed) = (Vec::new(), Vec::new());
    for f in &seams {
        let call_rx = Regex::new(&format!(r"(?<![A-Za-z0-9_]){}\s*\(", rx::escape(&f.name)))?;
        let defn_rx = Regex::new(&format!(r"fn\s+{}(?![A-Za-z0-9_])", rx::escape(&f.name)))?;
        let mut callers: Vec<String> = Vec::new();
        for (rel, l) in tree.grep(&call_rx, true, None) {
            if non_production
                .iter()
                .any(|frag| rel.contains(frag.as_str()))
            {
                continue;
            }
            if defn_rx.is_match(l.code_bytes()) || use_rx.match_at(l.code_bytes(), 0).is_some() {
                continue;
            }
            callers.push(format!("{rel}:{}", l.no));
        }
        if !callers.is_empty() {
            installed.push(format!(
                "{} <- {}{}",
                f.name,
                callers[0],
                if callers.len() > 1 {
                    format!(" (+{})", callers.len() - 1)
                } else {
                    String::new()
                }
            ));
        } else {
            offenders.push(format!(
                "{} ({}:{}) has NO production installer",
                f.name, f.path, f.start
            ));
        }
    }
    let current = offenders.len() as i64;
    let detail = format!(
        "{} installable seam(s) found, {current} without a production installer (ceiling \
         {max_uninstalled}): {}",
        seams.len(),
        join_or_none(&offenders)
    );
    let mut r = plain(
        "no-uninstalled-seam",
        current <= max_uninstalled && !seams.is_empty(),
        "every installable substrate seam has a production installer",
        detail,
        current,
        max_uninstalled,
        offenders,
    );
    if seams.is_empty() {
        r.status = Status::Fail;
        r.detail =
            "no installable seam matched the pattern at all; the scanner found nothing to check"
                .to_string();
    }
    Ok(vec![r])
}

// ── 5. neutral-no-dialect ────────────────────────────────────────────────────────────────────────

/// The delegated scan's artefact, exactly as `plane-purity-lint.sh --baseline` leaves it.
pub fn neutral_no_dialect(cfg: &Cfg, hits: Option<&str>) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("neutral-no-dialect")?;
    let max_hits = need_int(c, "max_hits", "neutral-no-dialect")?;
    let cats = c.list_of("categories");
    let title = "neutral crates name no dialect or plane (delegated to plane-purity-lint.sh)";

    let Some(hits) = hits else {
        return Ok(vec![plain(
            "neutral-no-dialect",
            false,
            title,
            "plane-purity-lint.sh produced no hits file; the delegated scan did not run",
            -1,
            max_hits,
            vec![],
        )]);
    };

    let mut per_file: Vec<(String, usize)> = Vec::new();
    let mut samples: Vec<String> = Vec::new();
    let mut scanned: BTreeMap<String, i64> = BTreeMap::new();
    for ln in hits.split('\n') {
        let parts: Vec<&str> = ln.trim_end_matches('\n').split('\t').collect();
        if parts.first() == Some(&"#SCAN") {
            for kv in &parts[1..] {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
                    scanned.insert(k.to_string(), v.parse().unwrap_or(0));
                }
            }
            continue;
        }
        if parts.len() < 3 || !cats.iter().any(|c| c == parts[0]) {
            continue;
        }
        let f = parts[1].split(':').next().unwrap_or(parts[1]).to_string();
        match per_file.iter_mut().find(|(k, _)| *k == f) {
            Some((_, n)) => *n += 1,
            None => per_file.push((f, 1)),
        }
        if samples.len() < 5 {
            let body = parts[2];
            let cut = body.char_indices().nth(80).map_or(body.len(), |(i, _)| i);
            samples.push(format!("{} {}: {}", parts[0], parts[1], &body[..cut]));
        }
    }

    // A zero-file scan is RED for the same reason a missing hits file is.
    let blind: Vec<String> = ["neutral_files", "plane_files"]
        .into_iter()
        .filter(|k| scanned.get(*k).copied().unwrap_or(-1) == 0)
        .map(String::from)
        .collect();
    if !blind.is_empty() {
        let listed = scanned
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Ok(vec![plain(
            "neutral-no-dialect",
            false,
            title,
            format!(
                "plane-purity-lint.sh scanned zero files ({listed}); zero hits over zero files is \
                 not a clean tree"
            ),
            -1,
            max_hits,
            blind,
        )]);
    }

    let current: i64 = per_file.iter().map(|(_, n)| *n as i64).sum();
    let mut top = per_file.clone();
    top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let mut offenders: Vec<String> = top
        .iter()
        .take(5)
        .map(|(f, n)| format!("{n} in {f}"))
        .collect();
    offenders.extend(samples);
    let over = scanned
        .get("neutral_files")
        .map(|n| format!(" over {n} neutral file(s)"))
        .unwrap_or_default();
    let mut sorted_cats = cats.clone();
    sorted_cats.sort();
    let detail = format!(
        "{current} {} hit(s) in the neutral crates per plane-purity-lint.sh{over} (ceiling \
         {max_hits}){}",
        sorted_cats.join("/"),
        if offenders.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                offenders
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        }
    );
    Ok(vec![plain(
        "neutral-no-dialect",
        current <= max_hits,
        title,
        detail,
        current,
        max_hits,
        offenders,
    )])
}

// ── 6. single-terminal ───────────────────────────────────────────────────────────────────────────

pub fn single_terminal(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("single-terminal")?;
    let term = need_str(c, "terminal", "single-terminal")?;
    let ceiling = need_int(c, "max_extra_sites", "single-terminal")?;
    let allowed = c.list_of("allowed_callers");
    let call_rx = Regex::new(&format!(r"{}\s*\(", word(term)))?;
    let defn_rx = Regex::new(&format!(r"fn\s+{}(?![A-Za-z0-9_])", rx::escape(term)))?;

    let (mut extra, mut seen_allowed) = (Vec::new(), Vec::new());
    for (rel, l) in tree.grep(&call_rx, true, None) {
        if defn_rx.is_match(l.code_bytes()) {
            continue;
        }
        let fname = tree
            .enclosing_fn(rel, l.no)
            .map_or("<no enclosing fn>".to_string(), |f| f.name.clone());
        if allowed.contains(&fname) {
            seen_allowed.push(fname);
        } else {
            extra.push(format!("{fname} at {rel}:{}", l.no));
        }
    }
    let current = extra.len() as i64;
    let mut sorted_allowed = allowed.clone();
    sorted_allowed.sort();
    let detail = format!(
        "{current} call(s) of `{term}` outside the allowed callers {} (ceiling {ceiling}): {}; \
         allowed callers seen: {}",
        py_list(&sorted_allowed),
        join_or_none(&extra),
        py_list(&sorted_unique(&seen_allowed))
    );
    Ok(vec![plain(
        "single-terminal",
        current <= ceiling,
        format!("`{term}` is called only from its allowed doors"),
        detail,
        current,
        ceiling,
        extra,
    )])
}

// ── 7. duplicate-dispatch (informational) ────────────────────────────────────────────────────────

fn tokens(tree: &Tree, f: &Fnc, tok_rx: &Regex) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let Some(lines) = tree.files.get(&f.path) else {
        return out;
    };
    for l in &lines[f.start - 1..f.end] {
        for m in tok_rx.find_iter(l.code_bytes()) {
            if let Some(t) = m.str_of(l.code_bytes(), 0) {
                out.push((t, l.no));
            }
        }
    }
    let _ = tree;
    out
}

struct Chain {
    ia0: usize,
    ib0: usize,
    ia1: usize,
    ib1: usize,
    d: i64,
}

pub fn duplicate_dispatch(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("duplicate-dispatch")?;
    let k = need_int(c, "shingle_tokens", "duplicate-dispatch")? as usize;
    let min_block = need_int(c, "min_block_lines", "duplicate-dispatch")?;
    let top_pairs = need_int(c, "top_pairs", "duplicate-dispatch")? as usize;
    let max_dup = need_int(c, "max_duplicated_lines", "duplicate-dispatch")?;
    let names = c.list_of("twins");
    let informational = c.bool_of("informational").unwrap_or(true);
    let tok_rx = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")?;

    let mut fns: Vec<&Fnc> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for nm in &names {
        match tree.find_fn_by_name(nm).first() {
            Some(f) => fns.push(f),
            None => missing.push(nm.clone()),
        }
    }

    // (span, a, la0, la1, b, lb0, lb1)
    let mut blocks: Vec<(i64, &Fnc, usize, usize, &Fnc, usize, usize)> = Vec::new();
    let mut total: i64 = 0;
    if fns.len() >= 2 {
        for ai in 0..fns.len() {
            for bi in ai + 1..fns.len() {
                let (a, b) = (fns[ai], fns[bi]);
                let ta = tokens(tree, a, &tok_rx);
                let tb = tokens(tree, b, &tok_rx);
                if ta.len() < k || tb.len() < k {
                    continue;
                }
                let mut index: BTreeMap<Vec<&str>, Vec<usize>> = BTreeMap::new();
                for i in 0..=ta.len() - k {
                    index
                        .entry(ta[i..i + k].iter().map(|(t, _)| t.as_str()).collect())
                        .or_default()
                        .push(i);
                }
                let mut matches: Vec<(usize, usize)> = Vec::new();
                for j in 0..=tb.len() - k {
                    let key: Vec<&str> = tb[j..j + k].iter().map(|(t, _)| t.as_str()).collect();
                    for i in index.get(&key).into_iter().flatten() {
                        matches.push((*i, j));
                    }
                }
                matches.sort_unstable();
                let mut chains: Vec<Chain> = Vec::new();
                for (i, j) in matches {
                    let d = j as i64 - i as i64;
                    let mut placed = false;
                    for ch in chains.iter_mut() {
                        let di = i as i64 - ch.ia1 as i64;
                        if (ch.d - d).abs() <= 6 && (0..=60).contains(&di) {
                            ch.ia1 = i;
                            ch.ib1 = j;
                            ch.d = d;
                            placed = true;
                            break;
                        }
                    }
                    if !placed {
                        chains.push(Chain {
                            ia0: i,
                            ib0: j,
                            ia1: i,
                            ib1: j,
                            d,
                        });
                    }
                }
                for ch in &chains {
                    let la0 = ta[ch.ia0].1;
                    let la1 = ta[(ch.ia1 + k - 1).min(ta.len() - 1)].1;
                    let lb0 = tb[ch.ib0].1;
                    let lb1 = tb[(ch.ib1 + k - 1).min(tb.len() - 1)].1;
                    let span = la1 as i64 - la0 as i64 + 1;
                    if span >= min_block {
                        blocks.push((span, a, la0, la1, b, lb0, lb1));
                    }
                }
            }
        }
        blocks.sort_by_key(|x| std::cmp::Reverse(x.0));
        let mut ivs: Vec<(usize, usize)> = blocks.iter().map(|x| (x.2, x.3)).collect();
        ivs.sort_unstable();
        let mut cur: Option<(usize, usize)> = None;
        for (s, e) in ivs {
            match cur {
                Some((cs, ce)) if s <= ce + 1 => cur = Some((cs, ce.max(e))),
                Some((cs, ce)) => {
                    total += ce as i64 - cs as i64 + 1;
                    cur = Some((s, e));
                }
                None => cur = Some((s, e)),
            }
        }
        if let Some((cs, ce)) = cur {
            total += ce as i64 - cs as i64 + 1;
        }
    }

    let mut offenders: Vec<String> = blocks
        .iter()
        .take(top_pairs)
        .map(|(span, a, la0, la1, b, lb0, lb1)| {
            format!(
                "{span} lines: {} {}:{la0}-{la1} ~ {} {}:{lb0}-{lb1}",
                a.name, a.path, b.name, b.path
            )
        })
        .collect();
    if !missing.is_empty() {
        offenders.push(format!("twin(s) not found: {}", missing.join(", ")));
    }
    let detail = format!(
        "informational: {total} duplicated line(s) across {} shared block(s) >= {min_block} lines \
         between {}{}",
        blocks.len(),
        py_list(&names),
        offenders
            .first()
            .map(|o| format!(": {o}"))
            .unwrap_or_default()
    );
    // The two postures are two CONSTRUCTORS now, not one constructor and a flag. While this rule is
    // informational it reports and does not judge; the day `informational = false` is written in
    // the ceilings file it starts comparing what it measured against `max_duplicated_lines`, which
    // is what the key has always claimed it does. Under the old shared constructor that second arm
    // was handed `true` and gated on nothing whatever the file said.
    let title = "near-duplicate blocks between the attempt twins";
    Ok(vec![if informational {
        model::informational(
            "duplicate-dispatch",
            title,
            detail,
            total,
            max_dup,
            offenders,
        )
    } else {
        plain(
            "duplicate-dispatch",
            total <= max_dup,
            title,
            detail,
            total,
            max_dup,
            offenders,
        )
    }])
}

// ── 8. token-sealed ──────────────────────────────────────────────────────────────────────────────

pub fn token_sealed(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("token-sealed")?;
    let allowed_root = need_str(c, "allowed_root", "token-sealed")?;
    let root = format!("{}/", allowed_root.trim_end_matches('/'));
    let max_sites = need_int(c, "max_sites", "token-sealed")?;
    // EACH ROW OWNS A DISJOINT SET OF SITES: the two dedicated sub-rows below scan the same two
    // symbols this list would, and one forged mint counted twice is not two proofs.
    let delegated: Vec<String> = ["kernel_seal_pattern", "admit_token_mint_pattern"]
        .into_iter()
        .map(|k| need_str(c, k, "token-sealed").map(|s| s.replace('\\', "")))
        .collect::<Result<_, _>>()?;

    let mut offenders = Vec::new();
    for pat in c.list_of("patterns") {
        if delegated.contains(&pat) {
            continue;
        }
        let rx_pat = Regex::new(&word(&pat))?;
        for (rel, l) in tree.grep(&rx_pat, true, None) {
            if rel.starts_with(root.as_str()) {
                continue;
            }
            offenders.push(format!("`{pat}` at {rel}:{}", l.no));
        }
    }
    let current = offenders.len() as i64;
    let mut detail = format!(
        "{current} token constructor(s) spelled outside {allowed_root} (ceiling {max_sites}): {}",
        join_or_none(&offenders)
    );
    if !tree.files.keys().any(|rel| rel.starts_with(root.as_str())) {
        detail = format!("{VACUOUS}{allowed_root} does not exist yet; nothing to seal");
    }
    let mut rows = vec![plain(
        "token-sealed",
        current <= max_sites,
        "the Teller's tokens are minted only inside the Teller",
        detail,
        current,
        max_sites,
        offenders,
    )];

    let kernel_root = need_str(c, "kernel_root", "token-sealed")?;
    let kroot = format!("{}/", kernel_root.trim_end_matches('/'));
    for (sub_id, pat_key, ceil_key, subject) in [
        (
            "token-sealed:kernel-seal",
            "kernel_seal_pattern",
            "max_kernel_seal_sites",
            "`KernelSeal::acquire_for_kernel(`",
        ),
        (
            "token-sealed:admit-token-mint",
            "admit_token_mint_pattern",
            "max_admit_token_mint_sites",
            "`AdmitToken::mint(`",
        ),
    ] {
        let rx_pat = Regex::new(need_str(c, pat_key, "token-sealed")?)?;
        let sites: Vec<String> = tree
            .grep(&rx_pat, true, None)
            .into_iter()
            .filter(|(rel, _)| !rel.starts_with(kroot.as_str()))
            .map(|(rel, l)| format!("{rel}:{}", l.no))
            .collect();
        let ceiling = need_int(c, ceil_key, "token-sealed")?;
        let detail = format!(
            "{} production call site(s) of {subject} outside {kernel_root} (ceiling {ceiling}): {}",
            sites.len(),
            join_or_none(&sites)
        );
        rows.push(plain(
            sub_id,
            sites.len() as i64 <= ceiling,
            format!("{subject} is spelled only inside {kernel_root}"),
            detail,
            sites.len() as i64,
            ceiling,
            sites,
        ));
    }
    Ok(rows)
}

// ── 9. teller-step-order ─────────────────────────────────────────────────────────────────────────

/// The ten steps, in EVALUATION order, on every path a request can take through the loop.
///
/// The reading this rule judges is built by [`step_order`], and the reason it is not a
/// top-to-bottom read of the loop's lines is written out at the top of that module: a `match` whose
/// refused arm is written above its admitted arm, a tail that lives in a helper two arms call, and
/// a Route dispatched through a leg all make source order a fact about the FILE and not about the
/// request. Evaluation order is the order the steps actually happen in — arguments before the call
/// they feed, one arm of a choice and never two, a helper spliced where it is called, a leg-
/// dispatched step counted as the step it performs — so it is the only reading a gate over "the
/// steps happen once each, in this order" can be built on.
pub fn teller_step_order(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("teller-step-order")?;
    let rel = need_str(c, "file", "teller-step-order")?;
    let steps = c.list_of("steps");
    let max_findings = need_int(c, "max_findings", "teller-step-order")?;
    let loop_function = need_str(c, "loop_function", "teller-step-order")?;
    let driver_function = need_str(c, "driver_function", "teller-step-order")?;
    let follow_depth = need_int(c, "follow_depth", "teller-step-order")?;
    let title = "the Teller loop calls the ten steps once each, in the canonical order";

    if steps.is_empty() {
        return Err("[rules.teller-step-order] has no `steps`".to_string());
    }
    let performed = cfg
        .doc
        .table("rules.teller-step-order.performed_by")
        .ok_or_else(|| {
            "qa/construction.toml has no [rules.teller-step-order.performed_by] table".to_string()
        })?;
    let mut performed_by: Vec<Vec<String>> = Vec::new();
    for s in &steps {
        let calls = performed.list_of(s);
        if calls.is_empty() {
            return Err(format!(
                "[rules.teller-step-order.performed_by] names no call that performs `{s}`"
            ));
        }
        performed_by.push(calls);
    }
    let tbl = step_order::StepTable {
        steps: steps.clone(),
        performed_by,
    };

    // A subject that is not in the tree is VACUOUS and therefore RED: a rule that keeps the ceiling
    // it earned while its subject is gone is a gate measuring nothing.
    let Some(src) = step_order::Source::load(tree, rel) else {
        return Ok(vec![plain(
            "teller-step-order",
            false,
            title,
            format!("{VACUOUS}{rel} does not exist; the loop this rule reads has no subject"),
            1,
            max_findings,
            vec![rel.to_string()],
        )]);
    };

    let mut findings: Vec<String> = Vec::new();
    let loops = tree.fns[rel]
        .iter()
        .filter(|f| f.name == loop_function && !f.intest)
        .count();
    if loops != 1 {
        findings.push(format!(
            "expected exactly one `fn {loop_function}` in {rel}, found {loops}"
        ));
    }
    let depth = follow_depth.max(0) as usize;
    let mut admitted: Vec<String> = Vec::new();
    for entry in [loop_function, driver_function] {
        if !src.has_fn(entry) {
            findings.push(format!("`{entry}` is not a function in {rel}"));
            continue;
        }
        let paths = src.paths(&tbl, entry, depth);
        if paths.is_empty() {
            findings.push(format!("`{entry}` reaches no step at all in {rel}"));
            continue;
        }
        // 2. EVERY path is in canonical order, and 3. no path repeats a step. A refusal arm is
        //    allowed to be short; it is not allowed to meter before it admits, or to run a step
        //    twice.
        for p in &paths {
            if !step_order::ascending(p) {
                findings.push(format!(
                    "`{entry}` has a path that evaluates {}; the canonical order is {}",
                    py_list(&step_order::names(p, &steps)),
                    py_list(&steps)
                ));
            }
        }
        // 1. Some path — the admitted one, the path a request that reaches the wire takes — meets
        //    every step once each, in order.
        match paths
            .iter()
            .find(|p| p.len() == steps.len() && step_order::ascending(p))
        {
            Some(full) => admitted = step_order::names(full, &steps),
            None => {
                let best = paths.iter().max_by_key(|p| p.len()).expect("non-empty");
                findings.push(format!(
                    "no path through `{entry}` evaluates all {} steps in order; its longest \
                     evaluates {}, and the canonical order is {}",
                    steps.len(),
                    py_list(&step_order::names(best, &steps)),
                    py_list(&steps)
                ));
            }
        }
    }
    findings = sorted_unique(&findings);
    let current = findings.len() as i64;
    let detail = format!(
        "{current} order finding(s) in {rel} (ceiling {max_findings}): {}",
        if findings.is_empty() {
            format!(
                "`{loop_function}` evaluates {} on its admitted path, and every other path is a \
                 shorter run of the same order",
                admitted.join(" \u{2192} ")
            )
        } else {
            findings.join("; ")
        }
    );
    Ok(vec![plain(
        "teller-step-order",
        current <= max_findings,
        title,
        detail,
        current,
        max_findings,
        findings,
    )])
}

// ── 10. one-teller-loop ──────────────────────────────────────────────────────────────────────────

pub fn one_teller_loop(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("one-teller-loop")?;
    let loop_verb = need_str(c, "loop_verb", "one-teller-loop")?;
    let loop_root = need_str(c, "loop_root", "one-teller-loop")?;
    let root = format!("{}/", loop_root.trim_end_matches('/'));
    let per_plane = need_int(c, "max_callers_per_plane_crate", "one-teller-loop")?;
    let legacy_verb = need_str(c, "legacy_verb", "one-teller-loop")?;
    let max_legacy = need_int(c, "max_legacy_sites", "one-teller-loop")?;
    let planes = cfg.plane_crates()?;

    let mut per_crate: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (rel, l) in call_sites(tree, loop_verb, None)? {
        if rel.starts_with(root.as_str()) {
            continue;
        }
        per_crate
            .entry(tree.crate_of(rel))
            .or_default()
            .push(format!("{rel}:{}", l.no));
    }
    let count = |p: &String| per_crate.get(p).map_or(0, Vec::len);
    let worst = planes.iter().map(count).max().unwrap_or(0) as i64;
    let offenders: Vec<String> = planes
        .iter()
        .filter(|p| count(p) as i64 > per_plane)
        .map(|p| {
            format!(
                "{p}: {} caller(s) of `{loop_verb}(`: {}",
                count(p),
                per_crate[p].join(", ")
            )
        })
        .collect();
    let seen: Vec<(String, usize)> = planes.iter().map(|p| (p.clone(), count(p))).collect();
    let mut detail = format!(
        "callers of `{loop_verb}(` per plane crate {} (ceiling {per_plane} each): {}",
        py_dict(&seen),
        if offenders.is_empty() {
            "none over".to_string()
        } else {
            offenders.join("; ")
        }
    );
    if !tree.files.keys().any(|rel| rel.starts_with(root.as_str())) {
        detail = format!("{VACUOUS}{loop_root} does not exist yet; no loop to call");
    }
    let mut rows = vec![plain(
        "one-teller-loop",
        worst <= per_plane,
        "each plane runs its units through the one Teller loop, from one place",
        detail,
        worst,
        per_plane,
        offenders,
    )];

    let legacy: Vec<String> = call_sites(tree, legacy_verb, None)?
        .into_iter()
        .map(|(rel, l)| format!("{rel}:{}", l.no))
        .collect();
    let detail = format!(
        "{} production call site(s) of the legacy `{legacy_verb}(` adapter (ceiling {max_legacy}): \
         {}",
        legacy.len(),
        join_or_none(&legacy)
    );
    rows.push(plain(
        "one-teller-loop:run_gauntlet",
        legacy.len() as i64 <= max_legacy,
        "the legacy adapter's call sites only ever shrink",
        detail,
        legacy.len() as i64,
        max_legacy,
        legacy,
    ));
    Ok(rows)
}

// ── 11. no-response-escapes-audit ────────────────────────────────────────────────────────────────

pub fn no_response_escapes_audit(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("no-response-escapes-audit")?;
    let root_raw = need_str(c, "root", "no-response-escapes-audit")?;
    let root = format!("{}/", root_raw.trim_end_matches('/'));
    let max_escapes = need_int(c, "max_escapes", "no-response-escapes-audit")?;
    let allowed = c.list_of("allowed_files");
    let returns = Regex::new(r"->[^{;]*(?<![A-Za-z0-9_])Response(?![A-Za-z0-9_])")?;

    let files: Vec<&String> = tree
        .fns
        .keys()
        .filter(|rel| rel.starts_with(root.as_str()))
        .collect();
    let mut offenders = Vec::new();
    for rel in &files {
        if allowed.iter().any(|a| a == basename(rel)) {
            continue;
        }
        for f in tree.fns[*rel].iter() {
            if f.intest {
                continue;
            }
            let sig: String = tree.files[*rel][f.start - 1..f.body_start]
                .iter()
                .map(|l| l.code.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            if returns.is_match_str(&sig) {
                offenders.push(format!(
                    "{} returns a Response at {rel}:{}",
                    f.name, f.start
                ));
            }
        }
    }
    let current = offenders.len() as i64;
    let mut sorted_allowed = allowed.clone();
    sorted_allowed.sort();
    let detail = if files.is_empty() {
        format!("{VACUOUS}{root_raw} does not exist yet; no step file to check")
    } else {
        format!(
            "{current} function(s) under {root_raw} returning a Response outside {} (ceiling \
             {max_escapes}): {}",
            py_list(&sorted_allowed),
            join_or_none(&offenders)
        )
    };
    Ok(vec![plain(
        "no-response-escapes-audit",
        current <= max_escapes,
        "only the Audit step hands a Response back to the loop",
        detail,
        current,
        max_escapes,
        offenders,
    )])
}

// ── 12. terminal-doors-in-audit-step ─────────────────────────────────────────────────────────────

pub fn terminal_doors_in_audit_step(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("terminal-doors-in-audit-step")?;
    let crate_name = need_str(c, "crate", "terminal-doors-in-audit-step")?;
    let allowed_file = need_str(c, "allowed_file", "terminal-doors-in-audit-step")?;
    let ceiling = need_int(c, "max_extra_sites", "terminal-doors-in-audit-step")?;
    let prefix = format!("crates/{crate_name}/");
    let files: Vec<String> = tree
        .files
        .keys()
        .filter(|r| r.starts_with(prefix.as_str()))
        .cloned()
        .collect();

    let mut offenders = Vec::new();
    for door in c.list_of("doors") {
        for (rel, l) in call_sites(tree, &door, Some(&files))? {
            if rel == allowed_file {
                continue;
            }
            offenders.push(format!("`{door}(` at {rel}:{}", l.no));
        }
    }
    let current = offenders.len() as i64;
    let detail = if current == 0 && !tree.files.contains_key(allowed_file) {
        format!("{VACUOUS}no door is called in {crate_name} and {allowed_file} does not exist yet")
    } else {
        format!(
            "{current} terminal-door call(s) in {crate_name} outside {allowed_file} (ceiling \
             {ceiling}): {}",
            join_or_none(&offenders)
        )
    };
    Ok(vec![plain(
        "terminal-doors-in-audit-step",
        current <= ceiling,
        "the plane's terminal doors are called only from its Audit step",
        detail,
        current,
        ceiling,
        offenders,
    )])
}

// ── 13. one-pick-site ────────────────────────────────────────────────────────────────────────────

pub fn one_pick_site(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("one-pick-site")?;
    let verb = need_str(c, "verb", "one-pick-site")?;
    let max_sites = need_int(c, "max_sites", "one-pick-site")?;
    let sites: Vec<String> = call_sites(tree, verb, None)?
        .into_iter()
        .map(|(rel, l)| format!("{rel}:{}", l.no))
        .collect();
    let current = sites.len() as i64;
    let detail = format!(
        "{current} production call site(s) of `{verb}(` (ceiling {max_sites}): {}",
        join_or_none(&sites)
    );
    Ok(vec![plain(
        "one-pick-site",
        current <= max_sites,
        "the lane pick is called from at most the loop and the fallback re-entry",
        detail,
        current,
        max_sites,
        sites,
    )])
}

/// The unused-parameter shim: several rules take a `Ctx` they only need for the tree walk, and
/// keeping the signature uniform is what lets the rule table stay a table.
pub fn unused(_cx: &Ctx) {}
