//! THE DERIVATION: `docs/design/ARCHITECTURE.md` Appendix B, plus the oracle's own citations and
//! the curated tables, into `qa/design-bindings.json` and `qa/DESIGN-BINDINGS.md`.
//!
//! A port of `scripts/design-bindings.py`'s `build`/`render_md` half. Byte-for-byte fidelity is the
//! whole contract here and it is not a nicety: the strict form of this gate REFUSES a committed
//! ledger that differs from a fresh derivation, so any spelling this port chose differently would
//! read as "the ledger is stale" for ever. `cargo test -p xtask` proves the round trip on the
//! committed artifact, and the conversion proved `--write` byte-identical against the Python's with
//! `cmp` before the Python was deleted.

use std::collections::BTreeMap;

use crate::gates::design_bindings::json::{dumps, s, J};
use crate::gates::design_bindings::tables;
use crate::jobj;
use crate::rx::Regex;

/// A family is collapsed to one `oracle-family` check when at least this many of its cells cite the
/// binding; below that the cells are listed one by one.
pub const FAMILY_COLLAPSE_MIN: usize = 6;

pub const ARCH_REL: &str = "docs/design/ARCHITECTURE.md";
pub const CELLS_REL: &str = "testing/shadow-oracle/cells.json";
pub const OUT_JSON_REL: &str = "qa/design-bindings.json";
pub const OUT_MD_REL: &str = "qa/DESIGN-BINDINGS.md";
pub const GOLDEN_LEDGER_REL: &str = "testing/shadow-oracle/golden/1.5.5/ledger.tsv";

fn lookup<'a>(table: &'a [(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

// ── Appendix B parsing ───────────────────────────────────────────────────────────────────────────

/// A table row's cells. Cells may contain escaped pipes (`\|`); only the unescaped ones split.
fn split_row(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev_backslash = false;
    for ch in trimmed.chars() {
        if ch == '|' && !prev_backslash {
            parts.push(std::mem::take(&mut cur));
            prev_backslash = false;
            continue;
        }
        prev_backslash = ch == '\\';
        cur.push(ch);
    }
    parts.push(cur);
    if parts.len() >= 2 {
        parts = parts[1..parts.len() - 1].to_vec();
    }
    parts
        .into_iter()
        .map(|p| p.trim().replace("\\|", "|"))
        .collect()
}

pub struct Row {
    pub id: String,
    pub surface: String,
    pub binding: String,
    pub inventory: String,
}

pub fn parse_appendix_b(text: &str) -> Result<(Option<Row>, Vec<Row>), String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let Some(start) = lines.iter().position(|l| l.starts_with("## Appendix B")) else {
        return Ok((None, Vec::new()));
    };
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.starts_with("## "))
        .map(|i| start + 1 + i)
        .unwrap_or(lines.len());
    let master_rx = Regex::new(r"\*\*PB-0 \(master rule\)\.\*\*\s*")?;
    let row_rx = Regex::new(r"^\|\s*PB-\d+\s*\|")?;
    let mut master = None;
    let mut rows = Vec::new();
    for l in &lines[start..end] {
        if let Some(m) = master_rx.match_at(l.as_bytes(), 0) {
            master = Some(Row {
                id: "PB-0".to_string(),
                surface: "master rule".to_string(),
                binding: l[m.end..].trim().to_string(),
                inventory: "every row of every inventory file under docs/design/inventory/"
                    .to_string(),
            });
            continue;
        }
        if row_rx.match_at(l.as_bytes(), 0).is_some() {
            let cells = split_row(l);
            if cells.len() < 4 {
                continue;
            }
            rows.push(Row {
                id: cells[0].clone(),
                surface: cells[1].clone(),
                binding: cells[2].clone(),
                inventory: cells[3].clone(),
            });
        }
    }
    Ok((master, rows))
}

/// Appendix A is prose separated by ` · `; the decisions carry no ids, so they are recorded as text
/// only — no ledger row can be owed for something with no stable identifier.
pub fn parse_appendix_a(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let Some(start) = lines.iter().position(|l| l.starts_with("## Appendix A")) else {
        return Vec::new();
    };
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.starts_with("## "))
        .map(|i| start + 1 + i)
        .unwrap_or(lines.len());
    let body = lines[start + 1..end]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    body.split(" \u{b7} ")
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(String::from)
        .collect()
}

// ── the two public-projection redactions ─────────────────────────────────────────────────────────

/// `surface`, with the round's bare audit-shorthand ids named in words.
pub fn public_surface(text: &str) -> Result<String, String> {
    if text.is_empty() {
        return Ok(String::new());
    }
    let rx = Regex::new(r"\(([A-Za-z]{1,3}\d{1,3})\)")?;
    let b = text.as_bytes();
    let mut out = String::new();
    let mut at = 0usize;
    for m in rx.find_iter(b) {
        out.push_str(&text[at..m.start]);
        let id = m.str_of(b, 1).unwrap_or_default();
        out.push('(');
        out.push_str(lookup(tables::PUBLIC_WORDED, &id).unwrap_or(&id));
        out.push(')');
        at = m.end;
    }
    out.push_str(&text[at..]);
    Ok(out)
}

/// Split on `sep` only where it is not inside parentheses or a backtick span.
fn split_top(text: &str, sep: char) -> Vec<String> {
    let (mut parts, mut buf, mut depth, mut tick) = (Vec::new(), String::new(), 0i32, false);
    for ch in text.chars() {
        if ch == '`' {
            tick = !tick;
        } else if !tick && ch == '(' {
            depth += 1;
        } else if !tick && ch == ')' {
            depth = (depth - 1).max(0);
        }
        if ch == sep && depth == 0 && !tick {
            parts.push(std::mem::take(&mut buf));
            continue;
        }
        buf.push(ch);
    }
    parts.push(buf);
    parts
}

struct Redactor {
    section_run: Regex,
    bare_section: Regex,
    family_row_id: Regex,
    empty_paren: Regex,
    dangling_sep: Regex,
    runs: Regex,
    trailing_dash: Regex,
    rows_word: Regex,
    alnum: Regex,
    join_prefix: Regex,
}

impl Redactor {
    fn new() -> Result<Redactor, String> {
        Ok(Redactor {
            section_run: Regex::new(
                r"§\s*\d+(?:\.\d+)*(?:\s*[/,–—-]\s*(?:§\s*)?\d+(?:\.\d+)*)*(?:\s*\(\s*[a-z]\s*\))?",
            )?,
            bare_section: Regex::new(r"(?<![\w.\-])\d+(?:\.\d+)+(?![\w\-.])")?,
            family_row_id: Regex::new(
                r"(?<![\w-])(?!PB-)[A-Z]{2,8}-(?:\*|[A-Z]?\d{1,3}(?:\s*(?:/|\.\.)\s*\d{1,3})*)|(?<![\w-])[A-Z]\d{1,3}(?![\w-])",
            )?,
            empty_paren: Regex::new(r"\(\s*[;,/–—-]*\s*\)")?,
            dangling_sep: Regex::new(r"(?<![\w`])/+\s*")?,
            runs: Regex::new(r"\s+")?,
            trailing_dash: Regex::new(r"\s*[–—]$")?,
            rows_word: Regex::new(r"\s+(?:rows?|steps?)$")?,
            alnum: Regex::new(r"[A-Za-z0-9]")?,
            join_prefix: Regex::new(r"(?<=[A-Za-z]),\s*(?=[(:])")?,
        })
    }

    fn strip_all(&self, rx: &Regex, text: &str, with: &str) -> String {
        let b = text.as_bytes();
        let mut out = String::new();
        let mut at = 0usize;
        for m in rx.find_iter(b) {
            out.push_str(&text[at..m.start]);
            out.push_str(with);
            at = m.end;
        }
        out.push_str(&text[at..]);
        out
    }

    fn part(&self, part: &str) -> String {
        let p = self.strip_all(&self.section_run, part, "");
        let p = self.strip_all(&self.bare_section, &p, "");
        let p = self.strip_all(&self.family_row_id, &p, "");
        // a parenthetical emptied of its only anchor
        let p = self.strip_all(&self.empty_paren, &p, "");
        // a separator whose operands are gone
        let p = self.strip_all(&self.dangling_sep, &p, "");
        let p = self.strip_all(&self.runs, &p, " ");
        let p = p.trim().trim_matches([' ', ',', ';']).to_string();
        // the dangling half of a stripped range, then `rows` with its numbers gone
        let p = self.strip_all(&self.trailing_dash, &p, "");
        let p = self.strip_all(&self.rows_word, &p, "");
        p.trim_matches([' ', ',', ';']).to_string()
    }
}

/// The `inventory` column as a public reader can actually use it: the file-prefix word (and any
/// bare source path beside it), with the within-file anchors removed.
pub fn public_inventory(text: &str) -> Result<String, String> {
    if text.is_empty() {
        return Ok(String::new());
    }
    let r = Redactor::new()?;
    let mut segments: Vec<String> = Vec::new();
    for seg in split_top(text, ';') {
        let parts: Vec<String> = split_top(&seg, ',')
            .iter()
            .map(|p| r.part(p))
            .filter(|p| r.alnum.is_match_str(p))
            .collect();
        if !parts.is_empty() {
            segments.push(parts.join(", "));
        }
    }
    let out = segments.join("; ");
    // A prefix word left alone by its own anchor reads better joined to the source span that
    // followed it: `config, (:267)` was one citation, not two.
    Ok(r.strip_all(&r.join_prefix, &out, " "))
}

// ── the oracle's own citations ───────────────────────────────────────────────────────────────────

fn strings_in(v: &J, out: &mut String) {
    match v {
        J::Str(x) => {
            out.push(' ');
            out.push_str(x);
        }
        J::Arr(items) => items.iter().for_each(|i| strings_in(i, out)),
        J::Obj(kv) => {
            for (k, val) in kv {
                out.push(' ');
                out.push_str(k);
                strings_in(val, out);
            }
        }
        _ => {}
    }
}

/// binding id -> the cells whose text names it. The Python scanned `json.dumps(cell)`; every
/// `PB-N` token lives inside a string, so scanning the cell's own strings finds exactly the same
/// set without depending on a serialiser's spacing.
pub fn cited_cells(cells: &[J]) -> Result<BTreeMap<String, Vec<usize>>, String> {
    let rx = Regex::new(r"PB-\d+")?;
    let mut out: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, c) in cells.iter().enumerate() {
        let mut text = String::new();
        strings_in(c, &mut text);
        let mut seen: Vec<String> = Vec::new();
        for m in rx.find_iter(text.as_bytes()) {
            if let Some(pb) = m.str_of(text.as_bytes(), 0) {
                if !seen.contains(&pb) {
                    seen.push(pb);
                }
            }
        }
        for pb in seen {
            out.entry(pb).or_default().push(i);
        }
    }
    Ok(out)
}

pub fn family_of(cell: &J) -> String {
    cell.str_of("family")
        .filter(|f| !f.is_empty())
        .or_else(|| cell.str_of("plane").filter(|p| !p.is_empty()))
        .unwrap_or("?")
        .to_string()
}

fn derive_oracle_checks(pb: &str, cited: &BTreeMap<String, Vec<usize>>, all_cells: &[J]) -> Vec<J> {
    let mut checks = Vec::new();
    let mut by_family: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for i in cited.get(pb).into_iter().flatten() {
        by_family
            .entry(family_of(&all_cells[*i]))
            .or_default()
            .push(*i);
    }
    let mut fam_sizes: BTreeMap<String, usize> = BTreeMap::new();
    for c in all_cells {
        *fam_sizes.entry(family_of(c)).or_default() += 1;
    }
    for (fam, cs) in &by_family {
        if cs.len() >= FAMILY_COLLAPSE_MIN {
            checks.push(jobj! {
                "kind" => s("oracle-family"),
                "ref" => s(fam.clone()),
                "status" => s("mapped"),
                "cites" => J::Int(cs.len() as i64),
                "family_size" => J::Int(fam_sizes.get(fam).copied().unwrap_or(0) as i64),
                "source" => s("cells.json why"),
            });
        } else {
            let mut ids: Vec<&J> = cs.iter().map(|i| &all_cells[*i]).collect();
            ids.sort_by_key(|c| c.str_of("id").unwrap_or("").to_string());
            for c in ids {
                checks.push(jobj! {
                    "kind" => s("oracle-cell"),
                    "ref" => s(c.str_of("id").unwrap_or("")),
                    "status" => s("mapped"),
                    "why" => s(c.str_of("why").unwrap_or("")),
                    "source" => s("cells.json why"),
                });
            }
        }
    }
    checks
}

/// De-duplicate by `(kind, ref)`, dropping a check with no ref, and stamp every survivor `mapped`.
/// Each source dict keeps ITS OWN key order — that is what makes a hand-added check re-emit exactly
/// as somebody wrote it.
fn merge_checks(lists: &[&[J]]) -> Vec<J> {
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out = Vec::new();
    for lst in lists {
        for ch in *lst {
            let key = (
                ch.str_of("kind").unwrap_or("?").to_string(),
                ch.str_of("ref").unwrap_or("").to_string(),
            );
            if key.1.is_empty() || seen.contains(&key) {
                continue;
            }
            seen.push(key);
            let mut ch = ch.clone();
            ch.set("status", s("mapped"));
            out.push(ch);
        }
    }
    out
}

// ── suggestions for an unmapped binding ──────────────────────────────────────────────────────────

/// A default suggestion when a binding has no hand-written one: pick by the inventory column.
pub fn default_suggestion(inventory: &str) -> &'static str {
    let inv = inventory;
    if inv.contains("config") && (inv.contains("BOOT") || inv.contains("CONF")) {
        return "oracle cell in family boot.refusal / boot.warning (config mutation fixture), plus a unit test on the parse";
    }
    if inv.contains("routes-admin") {
        return "oracle cell in family admin.ops or http.crosscut, plus an axum handler test asserting the literal body";
    }
    if inv.contains("governance") {
        return "unit test on the admission state machine asserting the literal status/message, plus a billing family cell";
    }
    if inv.contains("dialects") {
        return "byte-exact unit test in busbar-llm over a fixture pair, plus a llm.wire cell";
    }
    if inv.contains("proxy-hooks") {
        return "engine unit test with a hook fixture asserting the pick/charge order, plus a route.failover cell";
    }
    if inv.contains("plugins-stores") {
        return "plugin-loader unit test against an ABI-2 fixture, plus a plugins cell";
    }
    if inv.contains("auth-secrets") {
        return "auth chain unit test asserting the verdict, plus an http.crosscut cell";
    }
    if inv.contains("ops") {
        return "cli / ops.scrape cell diffing the 1.5.5 binary output";
    }
    "a unit test asserting the literal rule, plus an oracle cell on the surface"
}

pub fn suggest_kind(sug: &str) -> &'static str {
    let s = sug.to_lowercase();
    if s.contains("lint") {
        return "lint";
    }
    if s.contains("gate") && !s.contains("cell") {
        return "gate";
    }
    if s.contains("conformance") {
        return "conformance";
    }
    if s.contains("cell") && !s.contains("test") {
        return "oracle-cell";
    }
    "test"
}

// ── the whole document ───────────────────────────────────────────────────────────────────────────

/// The summary, counted off the VERDICTS. `mapped` here means PASS — a binding whose checks were
/// listed but proved nothing is counted under `unproven`, never folded into `mapped`.
pub fn counts(bindings: &[J]) -> J {
    let mut by_status: BTreeMap<&str, i64> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, i64> = BTreeMap::new();
    for b in bindings {
        let st = b.str_of("status").unwrap_or("unmapped");
        *by_status.entry(st).or_default() += 1;
        if st == "mapped" {
            for c in b.get("checks").and_then(J::as_array).unwrap_or(&[]) {
                *by_kind
                    .entry(c.str_of("kind").unwrap_or("?").to_string())
                    .or_default() += 1;
            }
        }
    }
    jobj! {
        "bindings" => J::Int(bindings.len() as i64),
        "mapped" => J::Int(by_status.get("mapped").copied().unwrap_or(0)),
        "unproven" => J::Int(by_status.get("unproven").copied().unwrap_or(0)),
        "unmapped" => J::Int(by_status.get("unmapped").copied().unwrap_or(0)),
        // THE DECLARED-GAP COUNT, and it is emitted even when it is zero because the summary is a
        // fixed shape somebody diffs, not a bag of the statuses that happened to occur.
        //
        // NOT YET PORTED, and this is the honest spelling of that: nothing in this module produces
        // the `gap` status, so the count is structurally 0. `qa/design-bindings-gaps.json` declares
        // `expected: 0` with an empty `gaps` list today, so the number is also CORRECT today and
        // the artifact this writes is byte-identical to the Python's. The moment a gap is declared
        // the two would part company, which is why the register is carried as a named unported
        // feature rather than as a difference nobody wrote down.
        "gap" => J::Int(by_status.get("gap").copied().unwrap_or(0)),
        "checks_by_kind" => J::Obj(by_kind.into_iter().map(|(k, v)| (k, J::Int(v))).collect()),
    }
}

const COMMENT: &[&str] = &[
    "GENERATED by scripts/design-bindings.py --write. Hand-added `checks` entries are preserved across regeneration;",
    "derived entries (source = 'cells.json why' or 'curated') are recomputed each time.",
    "status is the VERDICT the cited checks earn, not the fact that checks were cited:",
    "  mapped   = every cited check exists and compares something (verdict PASS)",
    "  unproven = checks are cited but nothing they name compares anything today -- a golden SKIP,",
    "             a vanished ref, or a ref that asserts nothing (verdict FAIL). Never counted as proof.",
    "  unmapped = no check at all: a NAMED gap, carrying the check that would prove it (verdict SKIP)",
    "Checked by scripts/design-bindings.sh --check (existence only; nothing is executed).",
];

/// Build the ledger document. `existing` is the committed JSON, read only for the hand-added
/// checks it carries; nothing else in it is trusted.
pub fn build(
    arch_text: &str,
    cells_doc: &J,
    existing: Option<&J>,
    ctx: &crate::gates::design_bindings::verify::Ctx,
) -> Result<J, String> {
    let (master, rows) = parse_appendix_b(arch_text)?;
    let bindings: Vec<Row> = master.into_iter().chain(rows).collect();
    let empty: Vec<J> = Vec::new();
    let all_cells = cells_doc
        .get("cells")
        .and_then(J::as_array)
        .unwrap_or(&empty);
    let cited = cited_cells(all_cells)?;
    let prior: Vec<&J> = existing
        .and_then(|e| e.get("bindings"))
        .and_then(J::as_array)
        .unwrap_or(&empty)
        .iter()
        .collect();
    let prior_of = |pb: &str| prior.iter().find(|b| b.str_of("id") == Some(pb)).copied();

    let mut out_b: Vec<J> = Vec::new();
    for b in &bindings {
        let pb = b.id.as_str();
        let seed: Vec<J> = tables::SEED
            .iter()
            .find(|(k, _)| *k == pb)
            .map(|(_, entries)| {
                entries
                    .iter()
                    .map(|(k, r, p)| {
                        jobj! {
                            "kind" => s(*k),
                            "ref" => s(*r),
                            "proves" => s(*p),
                            "source" => s("curated"),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        // hand-curated = anything in the prior JSON this derivation did not produce itself
        let hand: Vec<J> = prior_of(pb)
            .and_then(|p| p.get("checks"))
            .and_then(J::as_array)
            .unwrap_or(&empty)
            .iter()
            .filter(|c| {
                c.str_of("status") == Some("mapped")
                    && !matches!(c.str_of("source"), Some("cells.json why") | Some("curated"))
            })
            .map(|c| {
                let mut c = c.clone();
                c.set_default("source", s("hand"));
                c
            })
            .collect();
        let derived = derive_oracle_checks(pb, &cited, all_cells);
        let checks = merge_checks(&[&derived, &seed, &hand]);

        let mut entry = jobj! {
            "id" => s(pb),
            "surface" => s(public_surface(&b.surface)?),
            "binding" => s(b.binding.clone()),
            "inventory" => s(public_inventory(&b.inventory)?),
        };
        if let Some(note) = lookup(tables::NOTES, pb) {
            entry.set("note", s(note));
        }
        if checks.is_empty() {
            // `default_suggestion` keys off the RAW Appendix B row, because its heuristic reads the
            // family prefix `public_inventory` drops.
            let sug = lookup(tables::SUGGEST, pb)
                .map(String::from)
                .unwrap_or_else(|| default_suggestion(&b.inventory).to_string());
            entry.set("status", s("unmapped"));
            entry.set("suggestion", s(sug.clone()));
            entry.set(
                "checks",
                J::Arr(vec![jobj! {
                    "kind" => s(suggest_kind(&sug)),
                    "ref" => s(""),
                    "status" => s("unmapped"),
                    "suggestion" => s(sug),
                }]),
            );
        } else {
            entry.set("status", s("mapped"));
            entry.set("checks", J::Arr(checks));
        }
        out_b.push(entry);
    }

    // The status written here is the VERDICT the checks earn, not the fact that checks were listed.
    crate::gates::design_bindings::verify::classify(&mut out_b, ctx);

    let mut dropped: Vec<String> = prior
        .iter()
        .filter_map(|p| p.str_of("id").map(String::from))
        .filter(|id| !bindings.iter().any(|b| &b.id == id))
        .collect();
    dropped.sort();
    dropped.dedup();

    Ok(jobj! {
        "_comment" => J::Arr(COMMENT.iter().map(|c| s(*c)).collect()),
        "derived_from" => jobj! {
            "architecture" => s(ARCH_REL),
            "cells" => s(CELLS_REL),
        },
        "counts" => counts(&out_b),
        "owner_decisions" => jobj! {
            "note" => s("Appendix A carries no per-decision ids, so its decisions are recorded as text only and owe no ledger row."),
            "decisions" => J::Arr(parse_appendix_a(arch_text).into_iter().map(s).collect()),
        },
        "dropped_since_last_write" => J::Arr(dropped.into_iter().map(s).collect()),
        "bindings" => J::Arr(out_b),
    })
}

pub fn to_json_text(doc: &J) -> String {
    dumps(doc) + "\n"
}

// ── Markdown ─────────────────────────────────────────────────────────────────────────────────────

fn md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn render_md(doc: &J) -> String {
    let empty: Vec<J> = Vec::new();
    let c = doc.get("counts").cloned().unwrap_or(J::obj());
    let n = |k: &str| -> i64 {
        match c.get(k) {
            Some(J::Int(i)) => *i,
            _ => 0,
        }
    };
    let bindings = doc.get("bindings").and_then(J::as_array).unwrap_or(&empty);
    let by_kind = c
        .get("checks_by_kind")
        .map(|k| {
            k.keys()
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let by_kind_text = by_kind
        .iter()
        .map(|k| {
            let v = match c.get("checks_by_kind").and_then(|m| m.get(k)) {
                Some(J::Int(i)) => *i,
                _ => 0,
            };
            format!("{k} {v}")
        })
        .collect::<Vec<_>>()
        .join(", ");

    let mut out: Vec<String> = vec![
        "# Design bindings ledger".into(),
        String::new(),
        "GENERATED by `scripts/design-bindings.py --write` from `docs/design/ARCHITECTURE.md` Appendix B. Do not edit by hand.".into(),
        String::new(),
        "One row per parity binding; `checks` lists what it CITES, and `verdict` says what those".into(),
        "citations actually earned (existence-checked by `scripts/design-bindings.sh --check`; nothing".into(),
        "is executed).".into(),
        String::new(),
        "The three words are not interchangeable:".into(),
        String::new(),
        "- **mapped** (PASS) -- every cited check exists and compares something.".into(),
        "- **unproven** (FAIL) -- checks are cited, but nothing they name compares anything today: an".into(),
        "  oracle cell the pinned golden never recorded, a ref that has vanished, a ref that asserts".into(),
        "  nothing. This is NOT proof, and it is never counted as `mapped`.".into(),
        "- **unmapped** (SKIP) -- no check at all: a named gap, carrying the check that would close it.".into(),
        String::new(),
        "## Summary".into(),
        String::new(),
        format!("- bindings: **{}**  (PB-0 master rule + {} table rows)", n("bindings"), n("bindings") - 1),
        format!("- mapped (proven): **{}**", n("mapped")),
        format!("- unproven (cited, but nothing compared): **{}**", n("unproven")),
        format!("- unmapped (named gap): **{}**", n("unmapped")),
        format!("- checks by kind (mapped bindings only): {by_kind_text}"),
        String::new(),
        "## Bindings".into(),
        String::new(),
        "| # | Surface | Status | Verdict | Why | Checks |".into(),
        "|---|---|---|---|---|---|".into(),
    ];

    for b in bindings {
        let checks_list = b.get("checks").and_then(J::as_array).unwrap_or(&empty);
        let checks = if !checks_list.is_empty()
            && checks_list
                .iter()
                .any(|ch| !ch.str_of("ref").unwrap_or("").is_empty())
        {
            let parts: Vec<String> = checks_list
                .iter()
                .filter(|ch| !ch.str_of("ref").unwrap_or("").is_empty())
                .map(|ch| {
                    let kind = ch.str_of("kind").unwrap_or("?");
                    let extra = match (kind, ch.get("cites"), ch.get("family_size")) {
                        ("oracle-family", Some(J::Int(cites)), Some(J::Int(size))) => {
                            format!(" ({cites}/{size} cells cite it)")
                        }
                        _ => String::new(),
                    };
                    format!("{kind}: `{}`{extra}", ch.str_of("ref").unwrap_or(""))
                })
                .collect();
            parts.iter().map(|p| md(p)).collect::<Vec<_>>().join("<br>")
        } else {
            "_none_".to_string()
        };
        let status = b.str_of("status").unwrap_or("");
        let why = if status != "mapped" {
            md(b.str_of("verdict_detail").unwrap_or(""))
        } else {
            String::new()
        };
        out.push(format!(
            "| {} | {} | {status} | {} | {why} | {checks} |",
            b.str_of("id").unwrap_or(""),
            md(b.str_of("surface").unwrap_or("")),
            b.str_of("verdict").unwrap_or("")
        ));
    }

    let unproven: Vec<&J> = bindings
        .iter()
        .filter(|b| b.str_of("status") == Some("unproven"))
        .collect();
    if !unproven.is_empty() {
        out.extend([
            String::new(),
            "## The unproven bindings: cited, but nothing was compared".into(),
            String::new(),
            "Each of these names one or more checks and is still proof of nothing. A binding here is".into(),
            "red under `scripts/design-bindings.sh --check`; it is fixed by making the citation real,".into(),
            "or it is demoted to a named gap. It is never waived.".into(),
            String::new(),
        ]);
        for b in unproven {
            out.push(format!(
                "- **{}** ({}): {}",
                b.str_of("id").unwrap_or(""),
                md(b.str_of("surface").unwrap_or("")),
                md(b.str_of("verdict_detail").unwrap_or(""))
            ));
        }
    }

    let noted: Vec<&J> = bindings
        .iter()
        .filter(|b| b.get("note").is_some())
        .collect();
    if !noted.is_empty() {
        out.extend([
            String::new(),
            "## Findings: bindings in conflict with the tree".into(),
            String::new(),
            "A green test that asserts the opposite of a binding is not a proof. These need an owner decision.".into(),
            String::new(),
        ]);
        for b in noted {
            out.push(format!(
                "- **{}** ({}): {}",
                b.str_of("id").unwrap_or(""),
                md(b.str_of("surface").unwrap_or("")),
                md(b.str_of("note").unwrap_or(""))
            ));
        }
    }

    out.extend([
        String::new(),
        "## Post-check plan: the unmapped bindings".into(),
        String::new(),
        "Each line is the check that would move the binding to `mapped`.".into(),
        String::new(),
    ]);
    for b in bindings {
        if b.str_of("status") == Some("unmapped") {
            out.push(format!(
                "- **{}** ({}): {}",
                b.str_of("id").unwrap_or(""),
                md(b.str_of("surface").unwrap_or("")),
                md(b.str_of("suggestion").unwrap_or(""))
            ));
        }
    }

    out.extend([
        String::new(),
        "## Running the checks (a slower tier)".into(),
        String::new(),
        "`scripts/design-bindings.sh --check` proves existence only. The mapped kinds can be executed later by a slower tier:".into(),
        String::new(),
        "- `test`: `cargo test -p <crate> <fn>` per ref (the crate is the first path segment under crates/ where the fn is declared).".into(),
        "- `oracle-cell` / `oracle-family`: `testing/shadow-oracle/record.sh` + `replay.sh` over the named cell ids, against the pinned 1.5.5 golden.".into(),
        "- `gate` / `lint`: run the script with its own `--selftest` first, then its check mode.".into(),
        "- `conformance`: the rig under testing/*-conformance for the named row.".into(),
        String::new(),
    ]);

    let od = doc.get("owner_decisions").cloned().unwrap_or(J::obj());
    let decisions = od.get("decisions").and_then(J::as_array).unwrap_or(&empty);
    out.extend([
        String::new(),
        "## Appendix A owner decisions".into(),
        String::new(),
        od.str_of("note").unwrap_or("").to_string(),
        String::new(),
        format!(
            "{} decisions recorded as text in the JSON.",
            decisions.len()
        ),
    ]);
    out.join("\n") + "\n"
}
