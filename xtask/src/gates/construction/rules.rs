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
use crate::gates::construction::teller_paths::{expanded_paths, judge, summary, Allowance};
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
    // THE NAMED KNOWN SITES (`file::fn`): a send that is not a unit's attempt, each with its cite in
    // the ceilings file. Measured, never assumed: a known site that sends nothing is RED.
    let known = c.list_of("known_sites");
    let mut known_seen: Vec<String> = Vec::new();

    let mut extra: Vec<String> = Vec::new();
    let mut inside = 0usize;
    for (rel, l) in tree.grep(&send, true, None) {
        let fname = tree
            .enclosing_fn(rel, l.no)
            .map_or("<no enclosing fn>".to_string(), |f| f.name.clone());
        let site = format!("{rel}::{fname}");
        if fname == allowed {
            inside += 1;
        } else if known.contains(&site) {
            known_seen.push(site);
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
    for site in &known {
        if !known_seen.contains(site) {
            offenders.push(format!(
                "known site `{site}` opens nothing any more (strike it from known_sites)"
            ));
        }
    }
    known_seen.sort();
    known_seen.dedup();
    let current = offenders.len() as i64;
    let detail = format!(
        "{current} attempt site(s) outside `{allowed}` (ceiling {ceiling}): {}; known site(s) \
         measured: {} ({})",
        join_or_none(&offenders),
        known_seen.len(),
        join_or_none(&known_seen)
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

/// THE PLANES ON THIS TREE: the plane kind's crates, plus any legacy engine `gate.plane_crates`
/// still lists. That list is empty since the last engine crate was deleted (DEV-GREEN row 83), and
/// a per-plane rule over no plane passes by reading nothing (Law 10); every door crate the
/// `[gate.plugin_kinds].plane` globs match on the tree is a plane the per-plane rules hold.
fn planes_on_tree(tree: &Tree, cfg: &Cfg) -> Result<Vec<String>, String> {
    let plane_globs = cfg.kind_globs("plane")?;
    let mut planes = cfg.plane_crates()?;
    for rel in tree.files.keys() {
        let krate = tree.crate_of(rel);
        let dir = format!("crates/{krate}");
        if rel.starts_with("crates/")
            && plane_globs.iter().any(|g| fnmatch(&dir, g))
            && !planes.contains(&krate)
        {
            planes.push(krate);
        }
    }
    planes.sort();
    Ok(planes)
}

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
    for crate_name in planes_on_tree(tree, cfg)? {
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
            // A RED ROW NAMES EVERY FILE IT COUNTED. It used to name the five largest, so the reach
            // that crossed the ceiling went unnamed whenever it landed in a file smaller than the
            // fifth: a new test file with 40 kernel lines sat under five llm test files of 54 to
            // 217 and the row said only that the count rose. The reader of a red ratchet needs the
            // file that grew, and nothing short of the whole list is sure to hold it. A green row
            // keeps the five as a summary.
            let shown = if current > ceiling { top.len() } else { 5 };
            let offenders: Vec<String> = top
                .iter()
                .take(shown)
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

/// One configured terminal: its type when spelled `Type::fn` (`None`: a bare `fn`, matched by name
/// alone), its fn name, its spelling, and the doors that may call it (each `Type::fn` or a bare
/// name).
struct Terminal {
    ty: Option<String>,
    name: String,
    spelled: String,
    allowed: Vec<String>,
}

/// `Type::fn` -> (`Some(Type)`, `fn`); a bare name -> (`None`, name). A longer path keeps only its
/// last type segment, as an impl header does.
fn split_spelling(spelled: &str) -> (Option<String>, String) {
    match spelled.rsplit_once("::") {
        Some((ty, name)) => (
            Some(ty.rsplit("::").next().unwrap_or(ty).to_string()),
            name.to_string(),
        ),
        None => (None, spelled.to_string()),
    }
}

/// The terminals the rule judges: each `[rules.single-terminal.<x>]` sub-table, or (the one-
/// terminal form) the rule table's own `terminal` and `allowed_callers`.
fn terminals(cfg: &Cfg) -> Result<Vec<Terminal>, String> {
    let c = cfg.rule("single-terminal")?;
    let subs = cfg.doc.children("rules.single-terminal");
    let tables: Vec<&crate::toml_doc::Table> = if subs.is_empty() {
        vec![c]
    } else {
        subs.into_iter().map(|(_, t)| t).collect()
    };
    tables
        .into_iter()
        .map(|t| {
            let spelled = need_str(t, "terminal", "single-terminal")?.to_string();
            let (ty, name) = split_spelling(&spelled);
            Ok(Terminal {
                ty,
                name,
                spelled,
                allowed: t.list_of("allowed_callers"),
            })
        })
        .collect()
}

/// The type an `impl` header (its text up to the `{`) is for: the self type's last path segment,
/// past any generics and any `Trait for`.
fn owner_of_header(header: &str) -> Option<String> {
    let mut rest = header.trim_start();
    rest = rest.strip_prefix("unsafe").map_or(rest, str::trim_start);
    rest = rest.strip_prefix("impl")?;
    rest = rest.trim_start();
    if rest.starts_with('<') {
        let mut depth = 0i32;
        let mut cut = rest.len();
        for (i, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        cut = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = rest[cut..].trim_start();
    }
    let ty = rest
        .find(" for ")
        .map_or(rest, |i| &rest[i + 5..])
        .trim_start();
    let ty = ty
        .split(|ch: char| ch == '<' || ch == '{' || ch.is_whitespace())
        .next()?;
    let last = ty.rsplit("::").next()?.trim_start_matches('&');
    (!last.is_empty()).then(|| last.to_string())
}

/// The type whose innermost `impl` block holds line `line` of `rel`; `None` outside every impl.
fn impl_owner(tree: &Tree, rel: &str, line: usize) -> Option<String> {
    let lines = tree.files.get(rel)?;
    let mut best: Option<(usize, String)> = None;
    for (i, l) in lines.iter().enumerate() {
        if l.no > line {
            break;
        }
        let t = l.blank.trim_start();
        let t = t.strip_prefix("unsafe").map_or(t, str::trim_start);
        let opens = t
            .strip_prefix("impl")
            .is_some_and(|r| r.starts_with('<') || r.starts_with(char::is_whitespace));
        if !opens {
            continue;
        }
        let (mut header, mut depth, mut opened, mut end) = (String::new(), 0i64, false, None);
        'scan: for m in &lines[i..] {
            for ch in m.blank.chars() {
                if !opened {
                    match ch {
                        '{' => {
                            opened = true;
                            depth = 1;
                        }
                        ';' => break 'scan,
                        _ => header.push(ch),
                    }
                    continue;
                }
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(m.no);
                            break 'scan;
                        }
                    }
                    _ => {}
                }
            }
            header.push(' ');
        }
        let Some(end) = end else { continue };
        if line > end {
            continue;
        }
        let Some(owner) = owner_of_header(&header) else {
            continue;
        };
        let span = end - l.no;
        if best.as_ref().is_none_or(|(b, _)| span < *b) {
            best = Some((span, owner));
        }
    }
    best.map(|(_, owner)| owner)
}

/// How the enclosing fn is named for an allowed-callers list: `Type::fn` inside an impl, the bare
/// name outside one.
fn caller_of(tree: &Tree, rel: &str, f: &Fnc) -> (String, String) {
    let qualified = impl_owner(tree, rel, f.start)
        .map_or_else(|| f.name.clone(), |owner| format!("{owner}::{}", f.name));
    (qualified, f.name.clone())
}

/// What a call of the terminal's name is made on.
enum Receiver {
    /// A path call, `Type::fn(`: the type it names.
    Path(String),
    /// A bare binding, `money.fn(` or `self.fn(`: a local, an argument or `self`, declared in the
    /// calling file if anywhere.
    Binding(String),
    /// A field, `served.money.fn(`: the trailing field name, declared on its struct, which may live
    /// in another file.
    Field(String),
}

/// The receiver a call at byte `at` of line `idx` of `rel` is made on, read off the line above for
/// a chain broken before its `.`; `None` when no single identifier names it.
fn receiver_of(lines: &[Line], idx: usize, at: usize) -> Option<Receiver> {
    let trailing_ident = |text: &str| -> String {
        let rev: String = text
            .chars()
            .rev()
            .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
            .collect();
        rev.chars().rev().collect()
    };
    let code = &lines[idx].code;
    let pre = code.get(..at).unwrap_or_default().trim_end();
    if let Some(path) = pre.strip_suffix("::") {
        let ty = trailing_ident(path);
        return (!ty.is_empty()).then_some(Receiver::Path(ty));
    }
    let pre = pre.strip_suffix('.')?.trim_end();
    let pre = if pre.is_empty() {
        idx.checked_sub(1)
            .map_or("", |up| lines[up].code.trim_end())
            .to_string()
    } else {
        pre.to_string()
    };
    let ident = trailing_ident(&pre);
    if ident.is_empty() {
        return None;
    }
    let before = pre[..pre.len() - ident.len()].trim_end();
    Some(if before.ends_with('.') {
        Receiver::Field(ident)
    } else {
        Receiver::Binding(ident)
    })
}

/// The types among `owners` that a declaration of `ident` (`ident: …Type…`, a field, an argument
/// or a typed binding) names, searched in `rel` first and then, when `tree_wide`, across the
/// production tree.
fn declared_types(
    tree: &Tree,
    rel: &str,
    ident: &str,
    owners: &[String],
    tree_wide: bool,
) -> Vec<String> {
    let names = |l: &Line, found: &mut Vec<String>| {
        let code = &l.code;
        let mut from = 0;
        while let Some(i) = code[from..].find(ident) {
            let at = from + i;
            from = at + ident.len();
            let before_ok = code[..at]
                .chars()
                .next_back()
                .is_none_or(|ch| !(ch.is_alphanumeric() || ch == '_'));
            let rest = code[from..].trim_start();
            if !before_ok || !rest.starts_with(':') || rest.starts_with("::") {
                continue;
            }
            let ty: String = rest[1..]
                .chars()
                .take_while(|ch| !matches!(ch, ',' | ';' | '=' | '{' | ')'))
                .collect();
            for owner in owners {
                let whole = ty
                    .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                    .any(|w| w == owner);
                if whole && !found.contains(owner) {
                    found.push(owner.clone());
                }
            }
        }
    };
    let mut found = Vec::new();
    for l in tree.files.get(rel).into_iter().flat_map(|v| v.iter()) {
        if !l.intest {
            names(l, &mut found);
        }
    }
    if found.is_empty() && tree_wide {
        for lines in tree.files.values() {
            for l in lines.iter().filter(|l| !l.intest) {
                names(l, &mut found);
            }
        }
    }
    found
}

/// Does a production line of the file bind `ident` with a `let` that names no type? Such a binding
/// is a value nobody declared, so a call on it cannot be attributed. A pattern that fails to build
/// answers yes (fail-safe: an unread call is a finding).
fn untyped_let(lines: &[Line], ident: &str) -> bool {
    let Ok(rx_let) = Regex::new(&format!(r"\blet\s+(mut\s+)?{}\s*=", rx::escape(ident))) else {
        return true;
    };
    lines
        .iter()
        .any(|l| !l.intest && rx_let.is_match(l.code_bytes()))
}

/// Is the call of `t.name` at byte `at` of line `idx` of `rel` a call of the TERMINAL? A bare
/// terminal is matched by name. A `Type::fn` terminal whose name no other type defines is too; one
/// whose name another type also defines is attributed by its receiver: a path names its type,
/// `self` is the enclosing impl's type, a binding is the type its declaration in the calling file
/// names, and a field is the type its declaration names wherever it is.
/// A receiver that resolves to no single type is counted (fail-safe: an unread call is a finding,
/// never a pass).
fn calls_terminal(
    tree: &Tree,
    rel: &str,
    idx: usize,
    at: usize,
    t: &Terminal,
    owners: &[String],
) -> bool {
    let Some(ty) = &t.ty else {
        return true;
    };
    if owners.iter().all(|o| o == ty) {
        return true;
    }
    let Some(lines) = tree.files.get(rel) else {
        return true;
    };
    match receiver_of(lines, idx, at) {
        Some(Receiver::Path(path_ty)) => &path_ty == ty,
        Some(Receiver::Binding(ident)) if ident == "self" => impl_owner(tree, rel, lines[idx].no)
            .is_none_or(|owner| &owner == ty || !owners.contains(&owner)),
        // A bare binding is declared in the calling file or nowhere the scan can read: an untyped
        // `let` of it there (`let money = …;`) is unread, so counted, and otherwise a typed
        // declaration there attributes it. A same-named field of another type, in this file or
        // elsewhere in the tree, says nothing about it.
        Some(Receiver::Binding(ident)) => {
            untyped_let(lines, &ident) || {
                let named = declared_types(tree, rel, &ident, owners, false);
                named.is_empty() || named.contains(ty)
            }
        }
        // A field is declared on its struct, wherever that lives. Declared as another defining
        // type alone: that type's call. As the terminal's type, as several, or undeclared: counted.
        Some(Receiver::Field(ident)) => {
            let named = declared_types(tree, rel, &ident, owners, true);
            named.is_empty() || named.contains(ty)
        }
        None => true,
    }
}

pub fn single_terminal(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("single-terminal")?;
    let ceiling = need_int(c, "max_extra_sites", "single-terminal")?;
    let terms = terminals(cfg)?;

    let (mut extra, mut seen_all, mut refusals, mut allowed_all) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for t in &terms {
        let call_rx = Regex::new(&format!(r"{}\s*\(", word(&t.name)))?;
        let defn_rx = Regex::new(&format!(r"fn\s+{}(?![A-Za-z0-9_])", rx::escape(&t.name)))?;
        // The types that define a production fn of this name (`""`: a free fn).
        let defined: Vec<(String, &Fnc)> = tree
            .find_fn_by_name(&t.name)
            .into_iter()
            .map(|f| (impl_owner(tree, &f.path, f.start).unwrap_or_default(), f))
            .collect();
        let owners: Vec<String> =
            sorted_unique(&defined.iter().map(|(o, _)| o.clone()).collect::<Vec<_>>());
        let mut seen = Vec::new();
        for (rel, l) in tree.grep(&call_rx, true, None) {
            if defn_rx.is_match(l.code_bytes()) {
                continue;
            }
            let Some(lines) = tree.files.get(rel) else {
                continue;
            };
            let Some(idx) = lines.iter().position(|x| x.no == l.no) else {
                continue;
            };
            for m in call_rx.find_iter(l.code_bytes()) {
                if !calls_terminal(tree, rel, idx, m.start, t, &owners) {
                    continue;
                }
                let (qualified, bare) = tree.enclosing_fn(rel, l.no).map_or_else(
                    || {
                        (
                            "<no enclosing fn>".to_string(),
                            "<no enclosing fn>".to_string(),
                        )
                    },
                    |f| caller_of(tree, rel, f),
                );
                let door = t.allowed.iter().find(|a| {
                    if a.contains("::") {
                        **a == qualified
                    } else {
                        **a == bare
                    }
                });
                match door {
                    Some(a) => seen.push(a.clone()),
                    None => extra.push(format!(
                        "{qualified} at {rel}:{} calls `{}`",
                        l.no, t.spelled
                    )),
                }
            }
        }
        // ITEM 190: THE FLOOR FOR "I FOUND NONE". A terminal renamed away is called from nowhere,
        // so zero extra sites was a pass forever while the detail printed `allowed callers seen:
        // []`. A configured terminal with no production definition (on its type, when spelled
        // with one), or a configured door that never calls it, is the configuration having lost
        // its subject -- refused, and named.
        let resolves = defined
            .iter()
            .any(|(owner, _)| t.ty.as_ref().is_none_or(|ty| ty == owner));
        if !resolves {
            refusals.push(format!(
                "no production `fn {}` found -- the configured terminal does not resolve, so zero \
                 calls of it proves nothing",
                t.spelled
            ));
        }
        let seen = sorted_unique(&seen);
        let mut allowed = t.allowed.clone();
        allowed.sort();
        let unseen: Vec<String> = allowed
            .iter()
            .filter(|a| !seen.contains(a))
            .cloned()
            .collect();
        if !unseen.is_empty() {
            refusals.push(format!(
                "allowed caller(s) never seen calling `{}`: {}",
                t.spelled,
                unseen.join(", ")
            ));
        }
        seen_all.extend(seen.into_iter().map(|s| format!("{s} -> {}", t.spelled)));
        allowed_all.extend(allowed.into_iter().map(|a| format!("{a} -> {}", t.spelled)));
    }
    let current = extra.len() as i64;
    let spelled: Vec<String> = terms.iter().map(|t| format!("`{}`", t.spelled)).collect();
    let spelled = spelled.join(", ");
    let detail = format!(
        "{current} call(s) of {spelled} outside the allowed callers {} (ceiling {ceiling}): {}; \
         allowed callers seen: {}{}",
        py_list(&allowed_all),
        join_or_none(&extra),
        py_list(&seen_all),
        if refusals.is_empty() {
            String::new()
        } else {
            format!("; REFUSED: {}", refusals.join("; "))
        }
    );
    let pass = current <= ceiling && refusals.is_empty();
    let mut offenders = extra;
    offenders.extend(refusals);
    Ok(vec![plain(
        "single-terminal",
        pass,
        format!("{spelled} is called only from its allowed doors"),
        detail,
        current,
        ceiling,
        offenders,
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

// THE token-sealed SUB-ROWS, DECLARED ONCE AND READ THREE TIMES (the third reader is the
// self-test's green fixture, via [`token_sealed_scans`]): `(row id, pattern key, ceiling key, subject key,
// ROOT KEY)`.
//
// THE ROOT IS PER SUB-ROW, because "sealed" does not mean "kernel" for every sealed
// constructor. `SecretOnce::mint(`'s own doc says "Verbs unit only" and its one production site
// is the Verbs unit, so a row that judged it against `kernel_root` would stand RED on the single
// call the design REQUIRES — and the only way to green it would be a waiver for a correct call,
// which is how a gate learns to lie. A symbol whose home is not the kernel gets a row that says
// so, not an exemption from being scanned at all.
//
// ONE TABLE, NOT TWO LISTS. The delegation set immediately below and the rows emitted further
// down are this same table read twice. When they were two lists, a sub-row added to one and
// forgotten in the other produced either a symbol counted twice (once by its own row, once by
// the family scan) or a symbol whose row exists while the family scan still claims its sites —
// and that drift is the exact shape of X-177. Adding a fourth sub-row is now one edit.
const SUB_ROWS: [(&str, &str, &str, &str, &str); 3] = [
    (
        "token-sealed:kernel-seal",
        "kernel_seal_pattern",
        "max_kernel_seal_sites",
        "kernel_seal_subject",
        "kernel_root",
    ),
    (
        "token-sealed:admit-token-mint",
        "admit_token_mint_pattern",
        "max_admit_token_mint_sites",
        "admit_token_mint_subject",
        "kernel_root",
    ),
    (
        "token-sealed:secret-once-mint",
        "secret_once_mint_pattern",
        "max_secret_once_mint_sites",
        "secret_once_mint_subject",
        "secret_once_root",
    ),
];

/// EVERY SPELLING `token-sealed` AND ITS SUB-ROWS SCAN FOR, compiled — the literals (word-anchored
/// exactly as the rule anchors them), the families and each sub-row's own pattern. The self-test's
/// green fixture reads this to neutralise today's sites in its overlay, so the fixture and the rule
/// cannot disagree about what a site is.
pub fn token_sealed_scans(cfg: &Cfg) -> Result<Vec<Regex>, String> {
    let c = cfg.rule("token-sealed")?;
    let mut out = Vec::new();
    for pat in c.list_of("patterns") {
        out.push(Regex::new(&word(&pat))?);
    }
    for pat in c.list_of("pattern_families") {
        out.push(Regex::new(&pat)?);
    }
    for (_, pat_key, ..) in SUB_ROWS {
        out.push(Regex::new(need_str(c, pat_key, "token-sealed")?)?);
    }
    Ok(out)
}

pub fn token_sealed(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("token-sealed")?;
    let allowed_root = need_str(c, "allowed_root", "token-sealed")?;
    let root = format!("{}/", allowed_root.trim_end_matches('/'));
    let max_sites = need_int(c, "max_sites", "token-sealed")?;

    // EACH ROW OWNS A DISJOINT SET OF SITES: the dedicated sub-rows below scan symbols this
    // list would otherwise reach too, and one forged mint counted twice is not two proofs.
    //
    // THE DELEGATION IS BY SITE, NOT BY PATTERN STRING. It used to drop a `patterns` entry
    // whose literal text equalled a sub-rule's unescaped pattern — a test that no entry has ever
    // satisfied, and one that cannot work at all now that this rule also scans constructor
    // FAMILIES: a family regex is never string-equal to the one spelling a sub-row owns, so the
    // only way to keep the two sets disjoint is to ask, per line, whether a sub-row already claims
    // it.
    let delegated_rx: Vec<Regex> = SUB_ROWS
        .iter()
        .map(|(_, pat_key, _, _, _)| need_str(c, pat_key, "token-sealed").and_then(Regex::new))
        .collect::<Result<_, _>>()?;

    // Files that are the SPECIFICATION for this very scan rather than surface it scans (e.g. the
    // lint fixture whose doc comments and string literals self-match the patterns it defines).
    // Exact-path or directory-prefix, matching `confined_to_paths`'s semantics elsewhere in this
    // module.
    let exclude_files: Vec<String> = c.list_of("exclude_files");
    let excluded = |rel: &str| -> bool {
        exclude_files.iter().any(|p| {
            let p = p.trim_end_matches('/');
            !p.is_empty() && (rel == p || rel.starts_with(&format!("{p}/")))
        })
    };

    // THE SCAN SET IS LITERALS PLUS FAMILIES. `patterns` are exact spellings, escaped and
    // word-anchored; `pattern_families` are REGEXES, because `Grant<C>::mint` and `Pass<S>::mint`
    // are one generic constructor each over a sealed marker set, and a list of per-marker literals
    // is blind to every marker nobody remembered to add to it.
    let mut scans: Vec<(String, Regex)> = Vec::new();
    for pat in c.list_of("patterns") {
        let rx_pat = Regex::new(&word(&pat))?;
        scans.push((pat, rx_pat));
    }
    for pat in c.list_of("pattern_families") {
        let rx_pat = Regex::new(&pat)?;
        scans.push((pat, rx_pat));
    }

    // ── THE SCAN IS NO LONGER PRODUCTION-ONLY (2026-09-23), AND THAT IS HALF OF ONE FIX ─────────
    //
    // `qa/construction.toml`'s `scan_roots` and this `production_only` flag are ONE blind spot, not
    // two, and widening either alone moves nothing: every file under `crates/*/tests` also matches
    // the `/tests/` entry in `test_path_fragments`, so the widened walk yields the file and this
    // filter then drops every line of it. The census proved that by planting a mint in
    // `crates/busbar-llm/tests/` and in a `#[cfg(test)] mod` body and watching both stay invisible
    // through seven simultaneous forgeries of which the gate found one.
    //
    // THE AUTHORITY FOR SCANNING TEST SCOPE IS THE SPEC'S OWN BINDING, NOT A PREFERENCE. #65
    // (`docs/design/BUSBAR-1.6.0.md:401`) reads "a gate proves **no non-kernel code** can mint a
    // seal" — code, not production code. `qa/construction.toml` carried the opposite in prose
    // ("allowed there because production_only test-classification already excludes them"), which
    // was never an owner ruling: it is a description of what this flag happened to do, written down
    // beside the rule as though it were the rule.
    //
    // NOTHING HERE IS PERMITTED THAT WAS NOT PERMITTED BEFORE: `allowed_root` is unchanged,
    // `max_sites` is unchanged at 0, and no site gains an excuse. The row simply now sees the sites
    // its own claim has always been about, and the count it reports is the count the tree carries.
    // Named for the argument it IS, not for the intent behind it: `Tree::grep`'s third state is
    // `production_only`, and this rule now passes `false` to it. A const called
    // "scan test scope too = false" reads as the opposite of what it does.
    const PRODUCTION_ONLY: bool = false;

    // ONE SITE IS ONE FINDING. A line a literal and a family both name is a single forged mint, so
    // the first scan to reach it labels it and the rest pass over.
    let mut seen: std::collections::BTreeSet<(&str, usize)> = std::collections::BTreeSet::new();
    let mut offenders = Vec::new();
    for (pat, rx_pat) in &scans {
        for (rel, l) in tree.grep(rx_pat, PRODUCTION_ONLY, None) {
            if rel.starts_with(root.as_str()) || excluded(rel) {
                continue;
            }
            if delegated_rx.iter().any(|d| d.is_match(l.code_bytes())) {
                continue;
            }
            if !seen.insert((rel, l.no)) {
                continue;
            }
            // NAME THE SPELLING, NOT THE SCANNER. A literal pattern IS its own match, so this is
            // unchanged for `patterns`; a family pattern would otherwise print its regex, and
            // "`(?<![A-Za-z0-9_])Grant::<[^<>]*>::mint(_bound)?\(` at x.rs:12" tells a reader
            // which scanner fired rather than which token was forged.
            // `get` rather than an index: the match bounds are byte offsets, and a gate that
            // panics slicing a line is worse than one that falls back to naming its pattern.
            let hit = rx_pat
                .find_iter(l.code_bytes())
                .first()
                .and_then(|m| l.code.get(m.start..m.end))
                .map(str::to_string)
                .unwrap_or_else(|| pat.clone());
            offenders.push(format!("`{hit}` at {rel}:{}", l.no));
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

    // THE SUBJECT IS READ BESIDE THE PATTERN, NEVER HARD-CODED HERE. These two strings used
    // to be literals in this table, and `token-sealed:admit-token-mint` printed "`AdmitToken::mint(`
    // is spelled only inside crates/busbar-kernel/src" while its pattern scanned for
    // `Grant::<Admittance>::mint(` — the pre-#73 name the claim NAMED was the one spelling the row
    // could not see. A row that asserts a property about a symbol it does not scan is worse than no
    // row. `need_str` makes a missing subject a refusal, so the label cannot drift from the pattern
    // again without the gate saying so.
    for (sub_id, pat_key, ceil_key, subj_key, root_key) in SUB_ROWS {
        // THE HOME IS READ BESIDE THE PATTERN TOO. Same argument as the subject one line
        // down: a row that prints "is spelled only inside X" while filtering against Y is a row
        // whose claim and whose scan are two different assertions.
        let home = need_str(c, root_key, "token-sealed")?;
        let hroot = format!("{}/", home.trim_end_matches('/'));
        let subject = need_str(c, subj_key, "token-sealed")?;
        let rx_pat = Regex::new(need_str(c, pat_key, "token-sealed")?)?;
        // SAME SCOPE AS THE FAMILY SCAN ABOVE, and it has to be the same or the four rows of this
        // family disagree about what "spelled only inside X" ranges over.
        let sites: Vec<String> = tree
            .grep(&rx_pat, PRODUCTION_ONLY, None)
            .into_iter()
            .filter(|(rel, _)| !rel.starts_with(hroot.as_str()))
            .map(|(rel, l)| format!("{rel}:{}", l.no))
            .collect();
        let ceiling = need_int(c, ceil_key, "token-sealed")?;
        let detail = format!(
            // "production" is gone from this sentence because the scan is no longer production-only
            // (see PRODUCTION_ONLY above): #65 binds "no NON-KERNEL CODE can mint a seal", and a
            // row whose text narrows its own claim to production is a row asserting less than it
            // checks — which is the drift X-177 was about, in the other direction.
            "{} call site(s) of {subject} outside {home} (ceiling {ceiling}): {}",
            sites.len(),
            join_or_none(&sites)
        );
        rows.push(plain(
            sub_id,
            sites.len() as i64 <= ceiling,
            format!("{subject} is spelled only inside {home}"),
            detail,
            sites.len() as i64,
            ceiling,
            sites,
        ));
    }
    Ok(rows)
}

// ── 9. teller-step-order ───────────────────────────────────────────────────────────────────────

/// The declared omissions, read from `[[rules.teller-step-order.arm_may_omit]]`.
///
/// Each entry is a branch arm and the steps that arm may legitimately not run, WITH ITS REASON.
/// This is the half of the per-path rule that keeps it a rule: a path is never excused because it
/// was a branch, only because somebody wrote down which arm skips what and why.
fn arm_allowances(cfg: &Cfg) -> Result<Vec<Allowance>, String> {
    let mut out = Vec::new();
    for t in cfg
        .doc
        .array_of_tables("rules.teller-step-order.arm_may_omit")
    {
        let function = need_str(t, "function", "teller-step-order.arm_may_omit")?.to_string();
        let arm = need_str(t, "arm", "teller-step-order.arm_may_omit")?.to_string();
        let why = need_str(t, "why", "teller-step-order.arm_may_omit")?.to_string();
        let steps = t.list_of("steps");
        if steps.is_empty() {
            return Err(format!(
                "[[rules.teller-step-order.arm_may_omit]] for `{function}`'s `{arm}` arm names no \
                 `steps`; an omission licence that omits nothing is a licence nobody can read"
            ));
        }
        out.push(Allowance {
            function,
            arm,
            steps,
            why,
        });
    }
    Ok(out)
}

pub fn teller_step_order(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("teller-step-order")?;
    let rel = need_str(c, "file", "teller-step-order")?;
    let steps = c.list_of("steps");
    let max_findings = need_int(c, "max_findings", "teller-step-order")?;
    let loop_function = need_str(c, "loop_function", "teller-step-order")?;
    let opener_function = need_str(c, "opener_function", "teller-step-order")?;
    let door_step = need_str(c, "door_step", "teller-step-order")?;
    let step_receivers = c.list_of("step_receivers");
    if step_receivers.is_empty() {
        return Err(
            "[rules.teller-step-order] `step_receivers` is empty — a step site is unanchored \
             without at least one receiver naming the door driver's `units` handle"
                .to_string(),
        );
    }
    let dispatch_methods = c.list_of("dispatch_methods");
    let allow = arm_allowances(cfg)?;
    let title = "the Teller loop calls the nine steps once each, in the canonical order";

    if !tree.fns.contains_key(rel) {
        return Ok(vec![plain(
            "teller-step-order",
            true,
            title,
            format!("{VACUOUS}{rel} does not exist yet; no loop to order"),
            0,
            max_findings,
            vec![],
        )]);
    }
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
    let run_paths = expanded_paths(
        tree,
        rel,
        loop_function,
        &steps,
        &step_receivers,
        &dispatch_methods,
        &allow,
        4,
    )?;
    findings.extend(judge(loop_function, &run_paths, &steps, &allow));

    let door_at = steps.iter().position(|s| s == door_step).ok_or_else(|| {
        format!("[rules.teller-step-order] door_step `{door_step}` is not a step")
    })?;
    let door = &steps[..door_at + 1];
    // The opener's allowed sequence: the door steps, optionally followed by ONE named closing step
    // (the opener's own documented post-door seal — `audit`, for the Teller). Nothing else — `route`
    // and `meter` stay just as forbidden for the opener as before.
    let mut allowed: Vec<String> = door.to_vec();
    let closing_step = c.str_of("opener_closing_step");
    if let Some(cs) = closing_step {
        allowed.push(cs.to_string());
    }
    let open_paths = expanded_paths(
        tree,
        rel,
        opener_function,
        &steps,
        &step_receivers,
        &dispatch_methods,
        &allow,
        4,
    )?;
    findings.extend(judge(opener_function, &open_paths, &allowed, &allow));

    // A LICENCE NOBODY USES IS A LICENCE THAT OUTLIVED ITS ARM. `Authenticated::Challenge` is the
    // reason `verify` may be absent from a path; delete that arm and the declaration would sit here
    // quietly widening the rule for whatever arm happened to match next. So an entry neither walk
    // ever reached is a finding, not a comment.
    for (i, a) in allow.iter().enumerate() {
        if !run_paths.hits.contains(&i) && !open_paths.hits.contains(&i) {
            findings.push(format!(
                "[[rules.teller-step-order.arm_may_omit]] licenses {} to omit {}, and no arm the \
                 walk reached matches it — the declaration is stale",
                a.names(),
                py_list(&a.steps)
            ));
        }
    }

    let current = findings.len() as i64;
    let detail = format!(
        "{current} order finding(s) in {rel} (ceiling {max_findings}): {}",
        if findings.is_empty() {
            format!(
                "{}; {}",
                summary(loop_function, &run_paths),
                summary(opener_function, &open_paths)
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
    let planes = planes_on_tree(tree, cfg)?;

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
    } else if planes.is_empty() {
        detail = format!("{VACUOUS}no plane crate is on this tree; no plane to hold to one entry");
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
// STRUCK (DEV-GREEN row 83, coordinator ruling 2026-10-18): the rule's subject, the retired engine
// crate's step directory (`crates/busbar-llm/src/unit`, whose Audit step was the one file allowed to
// answer), left the tree with the crate. No plane has a step directory: a plane answers the kernel
// through its door's ABI table, and a unit is sealed by the kernel loop's one Audit step, which
// one-teller-loop and teller-step-order hold. Its table is struck from qa/construction.toml in the
// same commit.

// ── 12. terminal-doors-in-audit-step ─────────────────────────────────────────────────────────────
// STRUCK (DEV-GREEN row 83, coordinator ruling 2026-10-18): the rule's subject, the retired engine crate's terminal doors and Audit step,
// left the tree with the crate; its table is struck from qa/construction.toml in the same commit.

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
