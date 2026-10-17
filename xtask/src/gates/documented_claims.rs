//! `cargo xtask gate documented-claims` — THE DOCUMENTED-BEHAVIOUR CLAIM GATE.
//!
//! `qa/documented-claims.json` records every README and CHANGELOG behaviour claim the ops inventory
//! (`qa/evidence/inventory/1.5.5-ops-observability.md`) cross-checks, each either pinned by a
//! shadow-oracle cell (`status: "cell"`) or written off as untestable prose with a stated reason
//! (`status: "prose"`), and the two rows the design calls CONTRADICTED, which carry the CODE's
//! behaviour as the parity target rather than the document's.
//!
//! WHY THIS GATE EXISTS. That register was cited as a `gate` by the design-bindings ledger while
//! nothing in the tree opened it. A data file compares nothing: it is an INPUT to a gate, never a
//! gate. Until a checker existed, a cited cell could be renamed away, a claim dropped, or a
//! CONTRADICTED row quietly demoted to prose, with every check in the tree still green.
//!
//! Ported from the retired documented-claims shell and Python checkers. Every problem line they printed is
//! printed here, on the row of the arm that found it:
//!
//! * `documented-claims:register` — the register is readable JSON with a non-empty `claims` list.
//!   Unreadable or empty is RED and the arms below have nothing to judge.
//! * `documented-claims:shape` — arm 1. Every claim has an id of the form `<README|CHANGELOG>:<line>`
//!   (listed once), a quote and a status; a `cell` claim names a cell and no reason, a `prose` claim
//!   states a reason and names no cell. A claim neither pinned nor excused is the hole this register
//!   exists to make visible.
//! * `documented-claims:cells` — arm 4. Every cited cell is in `cells.json` AND was recorded PASS by
//!   the pinned golden ledger. A cell present but never recorded reads as a pin while the comparison
//!   behind it has never once run.
//! * `documented-claims:run` — arm 2. The claim ids are line addresses into the cross-check, so each
//!   run (README 1048-1074, CHANGELOG 1088-1116) must be present exactly, with no hole and nothing
//!   beyond it.
//! * `documented-claims:counts` — arm 3. The `counts` block is re-derived from `claims` and compared
//!   field by field; a hand-kept summary drifts.
//! * `documented-claims:contradicted` — arm 5. `README:1062` and `CHANGELOG:1100` stay flagged
//!   `contradicted`, keep their `code_wins` and `doc_line`, stay pinned by a cell, and no other row
//!   carries the flag.
//! * `documented-claims:addresses` — arm 6. Every claim's quote is found on the line its id names in
//!   the cross-check document: every word of the quote (a leading `x.y.z:` version tag dropped) must
//!   appear on that line, at a floor of [`QUOTE_MATCH_FLOOR`]. Measured on the real register, the
//!   right line scores 1.00 on every claim and a line one off scores at most 0.58. An unreadable
//!   document is RED, never "no drift".
//!
//! Existence and content only; nothing is executed and no cell is recorded.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_REGISTER: &str = "documented-claims:register";
pub const ROW_SHAPE: &str = "documented-claims:shape";
pub const ROW_CELLS: &str = "documented-claims:cells";
pub const ROW_RUN: &str = "documented-claims:run";
pub const ROW_COUNTS: &str = "documented-claims:counts";
pub const ROW_CONTRADICTED: &str = "documented-claims:contradicted";
pub const ROW_ADDRESSES: &str = "documented-claims:addresses";

const ROWS: &[&str] = &[
    ROW_REGISTER,
    ROW_SHAPE,
    ROW_CELLS,
    ROW_RUN,
    ROW_COUNTS,
    ROW_CONTRADICTED,
    ROW_ADDRESSES,
];

const CLAIMS: &str = "qa/documented-claims.json";
const CELLS: &str = "testing/shadow-oracle/cells.json";
const LEDGER: &str = "testing/shadow-oracle/golden/1.5.5/ledger.tsv";
const DOC: &str = "qa/evidence/inventory/1.5.5-ops-observability.md";

/// Arm 6: the fraction of a quote's words that must appear on the line its id addresses.
pub const QUOTE_MATCH_FLOOR: f64 = 0.9;

/// The two runs the binding names, as (prefix, first, last). These are line addresses into the
/// cross-check's two sections, so the span is part of the claim: a register that silently narrows
/// its own range has stopped covering the document.
pub const RUNS: &[(&str, u64, u64)] = &[("README", 1048, 1074), ("CHANGELOG", 1088, 1116)];

/// The rows the design pins as code-wins. Named here so that demoting one to prose is RED.
pub const CONTRADICTED: &[&str] = &["README:1062", "CHANGELOG:1100"];

pub struct DocumentedClaimsGate;

// ── Python-faithful value helpers ───────────────────────────────────────────────────────────────

/// `str(v)` as the script's `str(c.get(..))` would give it, as far as emptiness and word content go.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => other.to_string(),
    }
}

/// `str(c.get(key, ""))`: the default applies only to an absent key; a present null is `"None"`.
fn get_str(c: &Map<String, Value>, key: &str) -> String {
    c.get(key).map(py_str).unwrap_or_default()
}

/// Python truthiness.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `repr(v)` for the status field's message.
fn py_repr(v: &Value) -> String {
    match v {
        Value::String(s) if s.contains('\'') && !s.contains('"') => format!("\"{s}\""),
        Value::String(s) => format!("'{}'", s.replace('\'', "\\'")),
        other => py_str(other),
    }
}

/// `c.get("cell") or []`.
fn cell_field(c: &Map<String, Value>) -> Value {
    match c.get("cell") {
        Some(v) if truthy(v) => v.clone(),
        _ => Value::Array(Vec::new()),
    }
}

/// `str.splitlines()`: Python splits on more than `\n`.
fn py_splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        let is_break = matches!(
            ch,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !is_break {
            continue;
        }
        out.push(&text[start..i]);
        let mut end = i + ch.len_utf8();
        if ch == '\r' {
            if let Some(&(j, '\n')) = chars.peek() {
                chars.next();
                end = j + 1;
            }
        }
        start = end;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

// ── the id and the quote ────────────────────────────────────────────────────────────────────────

/// `^(README|CHANGELOG):([0-9]+)$` — the prefix and the line number.
fn parse_id(id: &str) -> Option<(&'static str, u64)> {
    let (prefix, rest) = if let Some(r) = id.strip_prefix("README:") {
        ("README", r)
    } else {
        ("CHANGELOG", id.strip_prefix("CHANGELOG:")?)
    };
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((prefix, rest.parse::<u64>().unwrap_or(u64::MAX)))
}

/// `_VERSION_TAG.sub("", quote)`: drop a leading `\s*N.N.N:\s*`.
fn drop_version_tag(quote: &str) -> &str {
    let s = quote.trim_start();
    let digits = |s: &str| s.bytes().take_while(u8::is_ascii_digit).count();
    let mut at = 0;
    for part in 0..3 {
        let n = digits(&s[at..]);
        if n == 0 {
            return quote;
        }
        at += n;
        let sep = if part < 2 { b'.' } else { b':' };
        if s.as_bytes().get(at) != Some(&sep) {
            return quote;
        }
        at += 1;
    }
    s[at..].trim_start()
}

/// `_WORD.findall(text.lower())`: runs of `[a-z0-9]`.
fn words(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Fraction of the quote's words (version tag dropped) present on `line`.
pub fn quote_match(quote: &str, line: &str) -> f64 {
    let w = words(drop_version_tag(quote));
    if w.is_empty() {
        return 0.0;
    }
    let have: BTreeSet<String> = words(line).into_iter().collect();
    w.iter().filter(|x| have.contains(*x)).count() as f64 / w.len() as f64
}

/// Arm 6: every claim id's line in the document carries that claim's quote.
pub fn address_drift(
    claims: &[Value],
    doc_label: &str,
    doc_name: &str,
    doc_text: Result<&str, String>,
) -> Vec<String> {
    let text = match doc_text {
        Ok(t) => t,
        Err(e) => {
            return vec![format!(
                "{doc_label}: unreadable cross-check document ({e}) -- the claim ids address \
                 nothing that can be checked"
            )];
        }
    };
    let lines = py_splitlines(text);
    let mut bad = Vec::new();
    for c in claims {
        let Some(c) = c.as_object() else { continue };
        let id = get_str(c, "id");
        let quote = get_str(c, "quote");
        let Some((_, n)) = parse_id(&id) else {
            continue;
        };
        if quote.trim().is_empty() {
            continue; // arm 1 already reports it
        }
        let line = if n >= 1 && n <= lines.len() as u64 {
            lines[(n - 1) as usize]
        } else {
            ""
        };
        let score = quote_match(&quote, line);
        if score < QUOTE_MATCH_FLOOR {
            let lo = n.saturating_sub(3).max(1);
            let hi = (n.saturating_add(3)).min(lines.len() as u64);
            let near: Vec<String> = (lo..=hi)
                .filter(|k| quote_match(&quote, lines[(*k - 1) as usize]) >= QUOTE_MATCH_FLOOR)
                .map(|k| k.to_string())
                .collect();
            let mut m = format!(
                "{id}: {doc_name}:{n} does not carry this claim's quote ({score:.2} of its words)"
            );
            if !near.is_empty() {
                m.push_str(&format!("; it is at line {}", near.join(", ")));
            }
            bad.push(m);
        }
    }
    bad
}

// ── the golden ledger ───────────────────────────────────────────────────────────────────────────

/// Cell ids the pinned golden actually recorded a comparable answer for (PASS rows only).
fn golden_recorded(cx: &Ctx) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Ok(text) = cx.read(LEDGER) {
        for line in py_splitlines(&text) {
            let p: Vec<&str> = line.split('\t').collect();
            if p.len() >= 2 && p[1] == "PASS" {
                out.insert(p[0].to_string());
            }
        }
    }
    out
}

// ── the check ───────────────────────────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
pub struct Findings {
    pub register: Vec<String>,
    pub shape: Vec<String>,
    pub cells: Vec<String>,
    pub run: Vec<String>,
    pub counts: Vec<String>,
    pub contradicted: Vec<String>,
    pub addresses: Vec<String>,
    /// The `counts` block for the green line.
    pub summary: String,
}

/// `said[k] != v` for an integer `v`, as Python compares numbers.
fn num_eq(said: &Value, v: u64) -> bool {
    match said {
        Value::Number(n) => n.as_u64() == Some(v) || n.as_f64() == Some(v as f64),
        Value::Bool(b) => u64::from(*b) == v,
        _ => false,
    }
}

pub fn check(cx: &Ctx) -> Findings {
    let mut f = Findings::default();
    let register: Value = match cx.read(CLAIMS) {
        Ok(t) => match serde_json::from_str(&t) {
            Ok(v) => v,
            Err(e) => {
                f.register
                    .push(format!("{CLAIMS}: unreadable claim register ({e})"));
                return f;
            }
        },
        Err(e) => {
            f.register
                .push(format!("{CLAIMS}: unreadable claim register ({e})"));
            return f;
        }
    };
    let claims: &[Value] = match register.get("claims").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a,
        _ => {
            f.register.push(format!(
                "{CLAIMS}: no `claims` list -- a register with no claims asserts nothing"
            ));
            return f;
        }
    };

    // cells.json: {"cells": [{"id": ..}, ..]}
    let mut cell_ids: BTreeSet<String> = BTreeSet::new();
    let cells_name = CELLS.rsplit('/').next().unwrap_or(CELLS);
    match cx.read(CELLS) {
        Err(e) => f.cells.push(format!("{CELLS}: unreadable cell list ({e})")),
        Ok(t) => match serde_json::from_str::<Value>(&t) {
            Err(e) => f.cells.push(format!("{CELLS}: unreadable cell list ({e})")),
            Ok(v) => {
                let list = v.get("cells").cloned().unwrap_or(Value::Array(Vec::new()));
                let mut ids = BTreeSet::new();
                let mut err = None;
                match list.as_array() {
                    Some(arr) => {
                        for c in arr {
                            match c.get("id") {
                                Some(id) => {
                                    ids.insert(py_str(id));
                                }
                                None => {
                                    err = Some("KeyError: 'id'".to_string());
                                    break;
                                }
                            }
                        }
                    }
                    None => err = Some("'cells' is not a list".to_string()),
                }
                match err {
                    Some(e) => f.cells.push(format!("{CELLS}: unreadable cell list ({e})")),
                    None => cell_ids = ids,
                }
            }
        },
    }
    let recorded = golden_recorded(cx);

    // 1. shape, and 4. every cited cell is real and was recorded
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (i, cv) in claims.iter().enumerate() {
        let Some(c) = cv.as_object() else {
            f.shape.push(format!(
                "claims[{i}]: not an object -- a claim must be a JSON object"
            ));
            continue;
        };
        let cid_v = c.get("id");
        let cid = cid_v.map(py_str).unwrap_or_default();
        let has_id = cid_v.is_some_and(truthy);
        let where_ = if has_id {
            cid.clone()
        } else {
            format!("claims[{i}]")
        };
        if !has_id || parse_id(&cid).is_none() {
            f.shape.push(format!(
                "{where_}: id is not a <README|CHANGELOG>:<line> address"
            ));
            continue;
        }
        if let Some(prev) = seen.get(&cid) {
            f.shape
                .push(format!("{cid}: listed twice (also at claims[{prev}])"));
        }
        seen.insert(cid.clone(), i);
        if get_str(c, "quote").trim().is_empty() {
            f.shape.push(format!(
                "{cid}: no quote -- a claim that does not say what was claimed"
            ));
        }
        let st = c.get("status");
        let cells = cell_field(c);
        let reason = get_str(c, "reason").trim().to_string();
        match st.and_then(Value::as_str) {
            Some("cell") => {
                if !cells.as_array().is_some_and(|a| !a.is_empty()) {
                    f.shape.push(format!(
                        "{cid}: status 'cell' but names no cell -- nothing pins this claim"
                    ));
                }
                if !reason.is_empty() {
                    f.shape.push(format!(
                        "{cid}: status 'cell' but also carries a prose `reason`; a claim is pinned or excused, never both"
                    ));
                }
            }
            Some("prose") => {
                if reason.is_empty() {
                    f.shape.push(format!(
                        "{cid}: status 'prose' with no reason -- a claim dropped without saying why"
                    ));
                }
                if truthy(&cells) {
                    f.shape.push(format!(
                        "{cid}: status 'prose' but names a cell; a pinned claim is `cell`"
                    ));
                }
            }
            _ => {
                let shown = st.map_or("None".to_string(), py_repr);
                f.shape.push(format!(
                    "{cid}: status {shown} is neither 'cell' nor 'prose'"
                ));
            }
        }
        if let Some(refs) = cells.as_array() {
            for r in refs {
                let r = py_str(r);
                if !cell_ids.is_empty() && !cell_ids.contains(&r) {
                    f.cells.push(format!(
                        "{cid}: cites {r}, which is in no cell of {cells_name}"
                    ));
                } else if !recorded.contains(&r) {
                    f.cells.push(format!(
                        "{cid}: cites {r}, which the pinned golden never recorded -- a pin whose comparison has never run"
                    ));
                }
            }
        }
    }

    // 2. the claim set is complete and contiguous
    for (prefix, first, last) in RUNS {
        let want: Vec<String> = (*first..=*last).map(|n| format!("{prefix}:{n}")).collect();
        let want_set: BTreeSet<&String> = want.iter().collect();
        let missing: Vec<&String> = want.iter().filter(|i| !seen.contains_key(*i)).collect();
        let pre = format!("{prefix}:");
        let extra: Vec<&String> = seen
            .keys()
            .filter(|i| i.starts_with(&pre) && !want_set.contains(i))
            .collect();
        if !missing.is_empty() {
            f.run.push(format!(
                "{prefix}: {} claim(s) missing from the {first}-{last} run: {}",
                missing.len(),
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !extra.is_empty() {
            f.run.push(format!(
                "{prefix}: claim(s) outside the {first}-{last} run: {}",
                extra
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    // 3. the counts block is the truth
    let objs: Vec<&Map<String, Value>> = claims.iter().filter_map(Value::as_object).collect();
    let id_of = |c: &Map<String, Value>| c.get("id").map(py_str).unwrap_or_default();
    let status_is =
        |c: &Map<String, Value>, s: &str| c.get("status").and_then(Value::as_str) == Some(s);
    let got: [(&str, u64); 6] = [
        ("total", claims.len() as u64),
        (
            "readme",
            objs.iter()
                .filter(|c| id_of(c).starts_with("README:"))
                .count() as u64,
        ),
        (
            "changelog",
            objs.iter()
                .filter(|c| id_of(c).starts_with("CHANGELOG:"))
                .count() as u64,
        ),
        (
            "cell",
            objs.iter().filter(|c| status_is(c, "cell")).count() as u64,
        ),
        (
            "prose",
            objs.iter().filter(|c| status_is(c, "prose")).count() as u64,
        ),
        (
            "contradicted",
            objs.iter()
                .filter(|c| c.get("contradicted") == Some(&Value::Bool(true)))
                .count() as u64,
        ),
    ];
    let said = register
        .get("counts")
        .filter(|v| truthy(v))
        .and_then(Value::as_object);
    for (k, v) in got {
        match said.and_then(|s| s.get(k)) {
            Some(s) if !num_eq(s, v) => {
                f.counts.push(format!(
                    "counts.{k} says {}, the claims list holds {v}",
                    py_str(s)
                ));
            }
            Some(_) => {}
            None => f.counts.push(format!("counts.{k} is missing")),
        }
    }

    // 5. the contradicted rows stay contradicted
    for cid in CONTRADICTED {
        let Some(c) = seen.get(*cid).and_then(|i| claims[*i].as_object()) else {
            f.contradicted.push(format!(
                "{cid}: the register no longer carries this CONTRADICTED claim"
            ));
            continue;
        };
        if c.get("contradicted") != Some(&Value::Bool(true)) {
            f.contradicted.push(format!(
                "{cid}: is a CONTRADICTED row and is no longer flagged `contradicted`"
            ));
        }
        if get_str(c, "code_wins").trim().is_empty() {
            f.contradicted.push(format!(
                "{cid}: CONTRADICTED with no `code_wins` -- the parity target is the code's behaviour, and it is not written down"
            ));
        }
        if get_str(c, "doc_line").trim().is_empty() {
            f.contradicted.push(format!(
                "{cid}: CONTRADICTED with no `doc_line` naming the documentation it contradicts"
            ));
        }
        if !status_is(c, "cell") || !truthy(&cell_field(c)) {
            f.contradicted.push(format!(
                "{cid}: CONTRADICTED rows are pinned by a cell of their own; this one is not"
            ));
        }
    }
    for c in &objs {
        let cid = c.get("id").map(py_str).unwrap_or_default();
        if c.get("contradicted") == Some(&Value::Bool(true))
            && !CONTRADICTED.contains(&cid.as_str())
        {
            f.contradicted.push(format!(
                "{cid}: flagged `contradicted`, but the design names only {}",
                CONTRADICTED.join(" and ")
            ));
        }
    }

    // 6. every id still addresses its claim
    let doc_name = DOC.rsplit('/').next().unwrap_or(DOC);
    f.addresses = address_drift(
        claims,
        DOC,
        doc_name,
        cx.read(DOC).as_deref().map_err(Clone::clone),
    );

    let cn = register.get("counts");
    let show = |k: &str| cn.and_then(|c| c.get(k)).map_or("None".to_string(), py_str);
    f.summary = format!(
        "{} claims ({} README + {} CHANGELOG), {} pinned by a recorded cell, {} excused as prose, {} pinned code-wins",
        show("total"),
        show("readme"),
        show("changelog"),
        show("cell"),
        show("prose"),
        show("contradicted")
    );
    f
}

fn row(id: &str, title: &str, bad: &[String], green: &str) -> Row {
    if bad.is_empty() {
        Row::pass(id, title, green)
    } else {
        Row::fail(
            id,
            title,
            format!("{} problem(s): {}", bad.len(), bad.join(" | ")),
        )
    }
}

impl Gate for DocumentedClaimsGate {
    fn name(&self) -> &'static str {
        "documented-claims"
    }

    fn owed(&self) -> Vec<String> {
        ROWS.iter().map(|r| (*r).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let f = check(cx);
        if !f.register.is_empty() {
            let why = f.register.join(" | ");
            let mut rows = vec![Row::fail(
                ROW_REGISTER,
                "the claim register is readable and holds claims",
                why.clone(),
            )];
            for id in &ROWS[1..] {
                rows.push(Row::fail(
                    *id,
                    "not judged: the claim register is unreadable or empty",
                    why.clone(),
                ));
            }
            return Verdict::of(rows);
        }
        Verdict::of(vec![
            Row::pass(
                ROW_REGISTER,
                "the claim register is readable and holds claims",
                f.summary.clone(),
            ),
            row(
                ROW_SHAPE,
                "every claim has an id, a quote, and is pinned by a cell or excused by a reason",
                &f.shape,
                "every claim is well-formed",
            ),
            row(
                ROW_CELLS,
                "every cited cell is in cells.json and was recorded PASS by the pinned golden",
                &f.cells,
                "every cited cell is real and recorded",
            ),
            row(
                ROW_RUN,
                "the README and CHANGELOG claim runs are complete and contiguous",
                &f.run,
                "README:1048-1074 and CHANGELOG:1088-1116 are exact",
            ),
            row(
                ROW_COUNTS,
                "the counts block is what the claims add up to",
                &f.counts,
                "counts match the claims",
            ),
            row(
                ROW_CONTRADICTED,
                "the two CONTRADICTED rows stay flagged, pinned, and carry the code's behaviour",
                &f.contradicted,
                "README:1062 and CHANGELOG:1100 are the only code-wins rows",
            ),
            row(
                ROW_ADDRESSES,
                "every claim id addresses the line that carries its quote",
                &f.addresses,
                "every id's line carries its quote",
            ),
        ])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // The register mutated in place, as the script's `plant` did with `d`.
        let plant = |mutate: fn(&mut Value)| {
            let cx = cx.clone();
            move || {
                let mut ov = Overlay::new();
                let mut d: Value = serde_json::from_str(&cx.read(CLAIMS).unwrap_or_default())
                    .unwrap_or(Value::Null);
                mutate(&mut d);
                ov.set(CLAIMS, serde_json::to_string_pretty(&d).unwrap_or_default());
                ov
            }
        };

        // (0) the register as committed is green: the fixture every case is a delta from.
        report.push(prove_green(
            cx,
            self,
            "the committed register is green",
            ROWS,
        ));

        // (a) a claim that is neither pinned nor excused
        report.push(prove_red(
            cx,
            self,
            "a 'cell' claim naming no cell is caught",
            &[ROW_SHAPE],
            plant(|d| {
                claim(d, "README:1055").insert("cell".into(), Value::Array(vec![]));
            }),
            &["names no cell"],
        ));
        // (b) a claim dropped without a stated reason
        report.push(prove_red(
            cx,
            self,
            "a 'prose' claim with no reason is caught",
            &[ROW_SHAPE],
            plant(|d| {
                claim(d, "README:1067").remove("reason");
            }),
            &["dropped without saying why"],
        ));
        // (c) a hole in the claim run: the last CHANGELOG claim deleted
        report.push(prove_red(
            cx,
            self,
            "a dropped claim leaves a hole in the run",
            &[ROW_RUN],
            plant(|d| {
                if let Some(a) = d.get_mut("claims").and_then(Value::as_array_mut) {
                    a.retain(|c| c.get("id").and_then(Value::as_str) != Some("CHANGELOG:1116"));
                }
            }),
            &["CHANGELOG:1116"],
        ));
        // (d) the hand-written summary drifting from the claims it summarises
        report.push(prove_red(
            cx,
            self,
            "a drifted counts block is caught",
            &[ROW_COUNTS],
            plant(|d| {
                let n = d["counts"]["cell"].as_i64().unwrap_or(0) + 1;
                d["counts"]["cell"] = Value::from(n);
            }),
            &["counts.cell says"],
        ));
        // (e) a cited cell that names nothing in cells.json
        report.push(prove_red(
            cx,
            self,
            "a cited cell absent from cells.json is caught",
            &[ROW_CELLS],
            plant(|d| {
                claim(d, "README:1058").insert(
                    "cell".into(),
                    Value::Array(vec![Value::from("documented|readme|no-such-cell-selftest")]),
                );
            }),
            &["is in no cell of"],
        ));
        // (f) a cited cell that EXISTS but the pinned golden never recorded: a pin whose comparison
        //     has never once run. DERIVED (the first cells.json id with no PASS row in the golden
        //     ledger), never named: a hard-coded one went stale the day the golden recorded it.
        {
            let cxc = cx.clone();
            report.push(prove_red(
                cx,
                self,
                "a cited cell the golden never recorded is caught",
                &[ROW_CELLS],
                move || {
                    let recorded = golden_recorded(&cxc);
                    let unrec = cxc
                        .read(CELLS)
                        .ok()
                        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                        .and_then(|v| v.get("cells").and_then(Value::as_array).cloned())
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_string))
                        .find(|id| !recorded.contains(id))
                        .unwrap_or_default();
                    let mut d: Value = serde_json::from_str(&cxc.read(CLAIMS).unwrap_or_default())
                        .unwrap_or(Value::Null);
                    claim(&mut d, "README:1058")
                        .insert("cell".into(), Value::Array(vec![Value::from(unrec)]));
                    let mut ov = Overlay::new();
                    ov.set(CLAIMS, serde_json::to_string_pretty(&d).unwrap_or_default());
                    ov
                },
                &["never recorded"],
            ));
        }
        // (g) a CONTRADICTED row demoted to ordinary prose: a known documentation defect deleted
        report.push(prove_red(
            cx,
            self,
            "a CONTRADICTED row demoted to prose is caught",
            &[ROW_CONTRADICTED],
            plant(|d| {
                let c = claim(d, "README:1062");
                c.insert("status".into(), Value::from("prose"));
                c.remove("contradicted");
                c.remove("cell");
                c.insert("reason".into(), Value::from("selftest"));
            }),
            &["README:1062"],
        ));
        // (h) a CONTRADICTED row that stops saying what the code actually does
        report.push(prove_red(
            cx,
            self,
            "a CONTRADICTED row with no code_wins is caught",
            &[ROW_CONTRADICTED],
            plant(|d| {
                claim(d, "CHANGELOG:1100").remove("code_wins");
            }),
            &["no `code_wins`"],
        ));
        // (i) an unreadable register is RED, never vacuously green
        {
            let mut ov = Overlay::new();
            ov.set(CLAIMS, "not json at all\n");
            report.push(prove_red(
                cx,
                self,
                "an unreadable register is red, not vacuously green",
                &[ROW_REGISTER],
                ov,
                &["unreadable claim register"],
            ));
        }
        // (j) arm 6: an unreadable register ... see below; a line inserted above the document's
        //     tables shifts every id, and the red names where the quote went.
        {
            let cxc = cx.clone();
            report.push(prove_red(
                cx,
                self,
                "a line inserted above the table reds every shifted id, naming the new line",
                &[ROW_ADDRESSES],
                move || {
                    let mut ov = Overlay::new();
                    let doc = cxc.read(DOC).unwrap_or_default();
                    ov.set(DOC, format!("| inserted line |\n{doc}"));
                    ov
                },
                &["does not carry this claim's quote", "it is at line"],
            ));
        }
        // (k) a missing document is RED, not "no drift"
        {
            let mut ov = Overlay::new();
            ov.remove(DOC);
            report.push(prove_red(
                cx,
                self,
                "a missing cross-check document is RED, not 'no drift'",
                &[ROW_ADDRESSES],
                ov,
                &["unreadable cross-check document"],
            ));
        }
        report
    }
}

fn claim<'v>(d: &'v mut Value, id: &str) -> &'v mut Map<String, Value> {
    d.get_mut("claims")
        .and_then(Value::as_array_mut)
        .and_then(|a| {
            a.iter_mut()
                .find(|c| c.get("id").and_then(Value::as_str) == Some(id))
        })
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("the committed register carries {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Vec<Value>, Vec<&'static str>) {
        let claims = vec![
            json!({"id": "README:2", "quote": "Six wire protocols, first class on both sides."}),
            json!({"id": "CHANGELOG:3", "quote": "1.5.5: There is no config change."}),
        ];
        let doc = vec![
            "| head |",
            "| \"Six wire protocols, first class on both sides.\" | `README.md:22` |",
            "| 1.5.5 | \"There is no config change.\" | `:11` |",
        ];
        (claims, doc)
    }

    fn drift(claims: &[Value], doc: Result<&str, String>) -> Vec<String> {
        address_drift(claims, "doc.md", "doc.md", doc)
    }

    #[test]
    fn aligned_ids_carry_their_quotes() {
        let (claims, doc) = fixture();
        assert!(drift(&claims, Ok(&(doc.join("\n") + "\n"))).is_empty());
    }

    #[test]
    fn a_shifted_document_reds_every_id_naming_the_new_line() {
        let (claims, mut doc) = fixture();
        doc.insert(0, "| inserted line |");
        let got = drift(&claims, Ok(&(doc.join("\n") + "\n")));
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(
            got[0].contains("README:2") && got[0].contains("it is at line 3"),
            "{got:?}"
        );
    }

    #[test]
    fn a_missing_document_is_red() {
        let (claims, _) = fixture();
        let got = drift(&claims, Err("absent".into()));
        assert_eq!(got.len(), 1);
        assert!(got[0].contains("unreadable"));
    }

    #[test]
    fn version_tags_and_words() {
        assert_eq!(drop_version_tag("  1.5.5: There"), "There");
        assert_eq!(drop_version_tag("1.5: x"), "1.5: x");
        assert_eq!(drop_version_tag("1.5.5 x"), "1.5.5 x");
        assert_eq!(
            words("Six, wire-protocols 1.5"),
            ["six", "wire", "protocols", "1", "5"]
        );
        assert_eq!(quote_match("", "x"), 0.0);
        assert_eq!(quote_match("a b c d", "a b"), 0.5);
    }

    #[test]
    fn ids_and_python_lines() {
        assert_eq!(parse_id("README:12"), Some(("README", 12)));
        assert_eq!(parse_id("README:"), None);
        assert_eq!(parse_id("README:1x"), None);
        assert_eq!(parse_id("OTHER:1"), None);
        assert_eq!(py_splitlines("a\r\nb\u{2028}c\n"), ["a", "b", "c"]);
        assert_eq!(py_splitlines("a\n\nb"), ["a", "", "b"]);
    }
}
