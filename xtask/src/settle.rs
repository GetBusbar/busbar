//! `cargo xtask gate --settle` — THE MEASURED NUMBERS, SETTLED TO THE TREE THEY ARE IN.
//!
//! Several gates hold a hand-set number that must EQUAL what the gate measures: a ceiling armed at
//! today's measured value and ratcheted down by every drain, or a census floor pinned at today's
//! population (BUSBAR-1.6.0.md Law 9, "arm at today's number"; Law 8, a measurement states its
//! denominator and a floor beneath it). Each PR measures those numbers on its own base, so two PRs
//! that each drain the same cell are each right alone and stale against the other: every landing
//! invalidated the rest of the queue (#1217, #1230, #1386, each lowering `busbar-kernel × plane`
//! and moving the file floors). The merge train runs this command on a PR's MERGED tree when the
//! only red is one of these measured values, commits what it wrote, and lands it.
//!
//! WHAT IT WRITES, and nothing else ([`FILES`]):
//!
//! * `qa/kind-isolation.toml`: each `[[law0]]` row's `count` (a CEILING), read off the
//!   `kind-isolation:law0` row's per-cell measure (the law0-slack figures), and each `[[dep]]` /
//!   `[[face]]` row's `count` (a CEILING), off the same measure `gate kind-isolation --write`
//!   re-pins from;
//! * `qa/instance-noun-neutrality.toml`: `[pragma_ceiling] frozen_literal` (a CEILING; Law 9 names
//!   the pragma rule), off the `instance-noun-neutrality:pragma-ceiling` row;
//! * `MIN_FILES` in `xtask/src/gates/plane_transport_neutrality.rs` (a FLOOR), off the
//!   `plane-transport-neutrality:zero-file-refusal` row;
//! * `NEUTRAL_FLOOR` and `PLANE_FLOOR` in `xtask/src/gates/plane_purity/mod.rs` (FLOORS), off the
//!   gate's own walk ([`crate::gates::plane_purity::settle_measure`]);
//! * `SPAN_FLOOR` in `xtask/src/gates/tracing.rs` (a FLOOR), off the `tracing:scan-floor` row.
//!
//! THE SAFE DIRECTION ONLY. A ceiling may only fall to its measure and a floor may only rise to it.
//! A measure that would LOOSEN a number (a ceiling up, a floor down, or a new law0 cell with no
//! row) is refused: the command prints every such row, writes NOTHING, and exits 1, so the train
//! hands the PR back to its author. Loosening is a person's call in a reviewed diff, never a tool's.
//!
//! THE PROSE STAYS. Every existing cite and doc comment is byte-identical; each changed row gets one
//! clause appended to its `cite` (`; SETTLED <old> -> <new>, the gate's measure on <HEAD>`), the
//! pragma key gets that clause as a `#` line under it, and a Rust constant gets it as one `///` line
//! directly above it. A second run over its own output measures the same numbers and changes
//! nothing, which the train checks.
//!
//! Exit codes are the CLI's contract: 0 settled (or nothing to settle), 1 refused, 3 could not
//! measure or could not write.

use std::collections::BTreeMap;

use crate::ctx::Ctx;
use crate::gates;
use crate::ledger::{Row, Status};

pub const KIND_ISOLATION: &str = "qa/kind-isolation.toml";
pub const NOUN_NEUTRALITY: &str = "qa/instance-noun-neutrality.toml";
pub const TRANSPORT_NEUTRALITY: &str = "xtask/src/gates/plane_transport_neutrality.rs";
pub const PLANE_PURITY: &str = "xtask/src/gates/plane_purity/mod.rs";
pub const TRACING: &str = "xtask/src/gates/tracing.rs";

/// EVERY FILE THIS COMMAND MAY WRITE. A field in any other file is refused by [`plan`], so the
/// train's `files:` rule and this list are the same list.
pub const FILES: &[&str] = &[
    KIND_ISOLATION,
    NOUN_NEUTRALITY,
    TRANSPORT_NEUTRALITY,
    PLANE_PURITY,
    TRACING,
];

/// Which way a number is safe to move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// May only fall to the measure.
    Ceiling,
    /// May only rise to the measure.
    Floor,
}

impl Bound {
    fn word(self) -> &'static str {
        match self {
            Bound::Ceiling => "ceiling",
            Bound::Floor => "floor",
        }
    }
}

/// Where a measured number sits in its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Site {
    /// The `count` of the one `[[table]]` row whose `keys` all match; the clause goes on its `cite`.
    Row {
        table: String,
        keys: Vec<(String, String)>,
    },
    /// `key = N` in the `[table]` section; the clause is a `#` line directly under it.
    Key { table: String, key: String },
    /// `const NAME: usize = N;`; the clause is a `///` line directly above it.
    Const { name: String },
}

impl Site {
    fn label(&self) -> String {
        match self {
            Site::Row { table, keys } => format!(
                "[[{table}]] {}",
                keys.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            Site::Key { table, key } => format!("[{table}] {key}"),
            Site::Const { name } => name.clone(),
        }
    }
}

/// One hand-set number and what the gate measures for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub file: String,
    pub site: Site,
    pub bound: Bound,
    pub now: u64,
}

/// One number off its measure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    pub file: String,
    pub label: String,
    pub bound: Bound,
    pub was: u64,
    pub now: u64,
}

impl std::fmt::Display for Move {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} ({}): {} -> {}",
            self.file,
            self.label,
            self.bound.word(),
            self.was,
            self.now
        )
    }
}

/// What a settle would do. `texts` holds only the files that change, and is EMPTY whenever
/// `refused` is not: the refusal is wholesale.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    pub settled: Vec<Move>,
    pub refused: Vec<Move>,
    pub texts: BTreeMap<String, String>,
}

/// The one clause appended per changed row.
pub fn clause(was: u64, now: u64, sha: &str) -> String {
    format!("SETTLED {was} -> {now}, the gate's measure on {sha}")
}

/// THE PURE CORE: every field read off `texts`, judged, and written. No tree, no git, no gate: the
/// self-test drives exactly this.
pub fn plan(texts: &BTreeMap<String, String>, fields: &[Field], sha: &str) -> Result<Plan, String> {
    let mut work = texts.clone();
    let mut out = Plan::default();
    for f in fields {
        if !FILES.contains(&f.file.as_str()) {
            return Err(format!(
                "{} {}: not a file `gate --settle` may write (it writes only {})",
                f.file,
                f.site.label(),
                FILES.join(", ")
            ));
        }
        let text = work
            .get(&f.file)
            .ok_or_else(|| format!("{}: not read", f.file))?;
        let was = read(text, &f.site).map_err(|e| format!("{} {}: {e}", f.file, f.site.label()))?;
        if was == f.now {
            continue;
        }
        let mv = Move {
            file: f.file.clone(),
            label: f.site.label(),
            bound: f.bound,
            was,
            now: f.now,
        };
        let loosens = match f.bound {
            Bound::Ceiling => f.now > was,
            Bound::Floor => f.now < was,
        };
        if loosens {
            out.refused.push(mv);
            continue;
        }
        let new = write(text, &f.site, f.now, &clause(was, f.now, sha))
            .map_err(|e| format!("{} {}: {e}", f.file, f.site.label()))?;
        work.insert(f.file.clone(), new);
        out.settled.push(mv);
    }
    if !out.refused.is_empty() {
        out.settled.clear();
        return Ok(out);
    }
    out.texts = work
        .into_iter()
        .filter(|(file, text)| texts.get(file) != Some(text))
        .collect();
    Ok(out)
}

// ------------------------------------------------------------------------------------------------
// reading and writing one site, line by line, every other byte kept
// ------------------------------------------------------------------------------------------------

fn lines_of(text: &str) -> Vec<&str> {
    text.split('\n').collect()
}

/// `key = value`, both trimmed; `None` for a comment or a line with no `=`.
fn kv(line: &str) -> Option<(&str, &str)> {
    if line.trim_start().starts_with('#') || line.trim_start().starts_with("//") {
        return None;
    }
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

fn unquote(v: &str) -> &str {
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
}

fn number(v: &str) -> Result<u64, String> {
    let bare = unquote(v.trim_end_matches(';').trim()).replace('_', "");
    bare.parse::<u64>()
        .map_err(|e| format!("`{v}` is not a count: {e}"))
}

/// Each `[[table]]` row as the half-open line span of its body.
fn row_spans(lines: &[&str], table: &str) -> Vec<(usize, usize)> {
    let head = format!("[[{table}]]");
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        if lines[i].trim() != head {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < lines.len() && !lines[end].trim_start().starts_with('[') {
            end += 1;
        }
        out.push((start, end));
        i = end;
    }
    out
}

fn line_with(lines: &[&str], (s, e): (usize, usize), key: &str) -> Option<usize> {
    (s..e).find(|&i| kv(lines[i]).is_some_and(|(k, _)| k == key))
}

fn value_in(lines: &[&str], span: (usize, usize), key: &str) -> Option<String> {
    line_with(lines, span, key).and_then(|i| kv(lines[i]).map(|(_, v)| unquote(v).to_string()))
}

/// The one row whose keys all match. None, or two, is an error: a settle never guesses a row.
fn find_row(
    lines: &[&str],
    table: &str,
    keys: &[(String, String)],
) -> Result<(usize, usize), String> {
    let hits: Vec<(usize, usize)> = row_spans(lines, table)
        .into_iter()
        .filter(|&sp| {
            keys.iter()
                .all(|(k, v)| value_in(lines, sp, k).as_deref() == Some(v.as_str()))
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err("no row matches".to_string()),
        many => Err(format!(
            "{} rows match, and a settle never picks one",
            many.len()
        )),
    }
}

/// The line of `key` in the `[table]` section.
fn find_key(lines: &[&str], table: &str, key: &str) -> Result<usize, String> {
    let head = format!("[{table}]");
    let start = lines
        .iter()
        .position(|l| l.trim() == head)
        .ok_or_else(|| format!("no `{head}` section"))?;
    let mut i = start + 1;
    while i < lines.len() && !lines[i].trim_start().starts_with('[') {
        if kv(lines[i]).is_some_and(|(k, _)| k == key) {
            return Ok(i);
        }
        i += 1;
    }
    Err(format!("no `{key}` in `{head}`"))
}

/// The line declaring `const NAME:`, at any visibility. Exactly one.
fn find_const(lines: &[&str], name: &str) -> Result<usize, String> {
    let want = format!("const {name}:");
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start();
            let t = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub(super) "))
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            t.starts_with(&want)
        })
        .map(|(i, _)| i)
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!("no `const {name}`")),
        many => Err(format!("{} `const {name}` lines", many.len())),
    }
}

fn read(text: &str, site: &Site) -> Result<u64, String> {
    let lines = lines_of(text);
    let at = match site {
        Site::Row { table, keys } => {
            let span = find_row(&lines, table, keys)?;
            line_with(&lines, span, "count").ok_or("the row has no `count`")?
        }
        Site::Key { table, key } => find_key(&lines, table, key)?,
        Site::Const { name } => find_const(&lines, name)?,
    };
    let (_, v) = kv(lines[at]).ok_or("no value")?;
    number(v)
}

/// `line` with its value replaced by `now`, the key, the spacing, the quoting and whatever follows
/// the value (a `;`, a comment) kept byte for byte.
fn set_value(line: &str, now: u64) -> Result<String, String> {
    let (k, v) = line
        .split_once('=')
        .ok_or_else(|| format!("no `=` in `{line}`"))?;
    let body = v.trim_start();
    let lead = &v[..v.len() - body.len()];
    let (new, rest) = if let Some(q) = body.strip_prefix('"') {
        let close = q
            .find('"')
            .ok_or_else(|| format!("an unclosed string in `{line}`"))?;
        (format!("\"{now}\""), &q[close + 1..])
    } else {
        let n = body
            .find(|c: char| !(c.is_ascii_digit() || c == '_'))
            .unwrap_or(body.len());
        if n == 0 {
            return Err(format!("no number in `{line}`"));
        }
        (now.to_string(), &body[n..])
    };
    Ok(format!("{k}={lead}{new}{rest}"))
}

/// `line`'s quoted value with `clause` appended inside the closing quote; the text before it is
/// left byte-identical.
fn append_clause(line: &str, clause: &str) -> Result<String, String> {
    let eq = line.find('=').ok_or("no `=` on the cite line")?;
    let open = line[eq..]
        .find('"')
        .map(|i| eq + i)
        .ok_or("the cite is not a quoted string")?;
    let close = line
        .rfind('"')
        .filter(|&c| c > open)
        .ok_or("the cite string does not close on its line")?;
    let sep = if close == open + 1 { "" } else { "; " };
    Ok(format!("{}{sep}{clause}{}", &line[..close], &line[close..]))
}

fn write(text: &str, site: &Site, now: u64, clause: &str) -> Result<String, String> {
    let lines = lines_of(text);
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();
    match site {
        Site::Row { table, keys } => {
            let span = find_row(&lines, table, keys)?;
            let at = line_with(&lines, span, "count").ok_or("the row has no `count`")?;
            out[at] = set_value(lines[at], now)?;
            match line_with(&lines, span, "cite") {
                Some(c) => out[c] = append_clause(lines[c], clause)?,
                None => out.insert(at + 1, format!("cite  = \"{clause}\"")),
            }
        }
        Site::Key { table, key } => {
            let at = find_key(&lines, table, key)?;
            out[at] = set_value(lines[at], now)?;
            out.insert(at + 1, format!("# {clause}"));
        }
        Site::Const { name } => {
            let at = find_const(&lines, name)?;
            out[at] = set_value(lines[at], now)?;
            let line = lines[at];
            let indent = &line[..line.len() - line.trim_start().len()];
            out.insert(at, format!("{indent}/// {clause}"));
        }
    }
    Ok(out.join("\n"))
}

// ------------------------------------------------------------------------------------------------
// the measures: each one the gate's own
// ------------------------------------------------------------------------------------------------

/// The fields measured on a tree, and the measures no row can hold (a new law0 cell): those are
/// refusals by themselves.
#[derive(Debug, Default)]
pub struct Measured {
    pub fields: Vec<Field>,
    pub orphans: Vec<String>,
}

fn gate_rows(cx: &Ctx, name: &str) -> Result<Vec<Row>, String> {
    let reg = gates::find(name).ok_or_else(|| format!("no registered gate `{name}`"))?;
    let gate = (reg.build)();
    Ok(gate.run(cx).rows)
}

fn the_row<'a>(rows: &'a [Row], id: &str) -> Result<&'a Row, String> {
    rows.iter()
        .find(|r| r.id == id)
        .ok_or_else(|| format!("the gate emitted no `{id}` row"))
}

/// The count printed immediately before `marker` in a row's detail.
fn count_before(row: &Row, marker: &str) -> Result<u64, String> {
    row.detail
        .split_once(marker)
        .and_then(|(head, _)| head.split_whitespace().next_back())
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| {
            format!(
                "`{}` carries no measure before `{marker}`: {}",
                row.id, row.detail
            )
        })
}

fn const_field(file: &str, name: &str, now: u64) -> Field {
    Field {
        file: file.to_string(),
        site: Site::Const {
            name: name.to_string(),
        },
        bound: Bound::Floor,
        now,
    }
}

/// EVERY MEASURED FIELD ON THIS TREE, each read off the gate that judges it.
pub fn measure(cx: &Ctx) -> Result<Measured, String> {
    let mut m = Measured::default();

    // [[law0]]: the cells of the `kind-isolation:law0` row. A PASS row is every cell at its row.
    let rows = gate_rows(cx, "kind-isolation")?;
    let law0 = the_row(&rows, gates::kind_isolation::ROW_LAW0)?;
    if law0.status != Status::Pass {
        if law0.cells.is_empty() {
            return Err(format!(
                "`{}` is red with no cell measured: {}",
                law0.id, law0.detail
            ));
        }
        let text = cx.read(KIND_ISOLATION)?;
        let lines = lines_of(&text);
        let spans = row_spans(&lines, "law0");
        for cell in &law0.cells {
            let Some(now) = cell.figure else {
                continue;
            };
            let Some((krate, axis)) = cell.key.split_once(" \u{d7} ") else {
                return Err(format!(
                    "a law0 cell key `{}` is not `crate × axis`",
                    cell.key
                ));
            };
            let has_row = spans.iter().any(|&sp| {
                value_in(&lines, sp, "crate").as_deref() == Some(krate)
                    && value_in(&lines, sp, "axis").as_deref() == Some(axis)
            });
            if has_row {
                m.fields.push(Field {
                    file: KIND_ISOLATION.to_string(),
                    site: Site::Row {
                        table: "law0".to_string(),
                        keys: vec![
                            ("crate".to_string(), krate.to_string()),
                            ("axis".to_string(), axis.to_string()),
                        ],
                    },
                    bound: Bound::Ceiling,
                    now,
                });
            } else if now > 0 {
                m.orphans.push(format!(
                    "{KIND_ISOLATION} [[law0]] crate={krate} axis={axis} (ceiling): no row, \
                     {now} hit(s) measured; a new cell is a rise from 0 and nothing raises a ceiling"
                ));
            }
        }
    }

    // [[dep]] / [[face]]: the measure `gate kind-isolation --write` re-pins from.
    for r in gates::kind_isolation::settle_repins(cx)? {
        let now = u64::try_from(r.now)
            .map_err(|_| format!("{}: measured a negative count {}", r.label, r.now))?;
        m.fields.push(Field {
            file: KIND_ISOLATION.to_string(),
            site: Site::Row {
                table: r.table.to_string(),
                keys: r.keys.clone(),
            },
            bound: Bound::Ceiling,
            now,
        });
    }

    // [pragma_ceiling] frozen_literal.
    let rows = gate_rows(cx, "instance-noun-neutrality")?;
    let row = the_row(&rows, gates::instance_noun_neutrality::ROW_PRAGMA_CEILING)?;
    let pragmas = row
        .detail
        .strip_prefix("frozen_literal ")
        .map(|d| {
            d.strip_prefix("ROSE: ")
                .or_else(|| d.strip_prefix("fell to "))
                .unwrap_or(d)
        })
        .and_then(|d| d.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| format!("`{}` carries no pragma count: {}", row.id, row.detail))?;
    m.fields.push(Field {
        file: NOUN_NEUTRALITY.to_string(),
        site: Site::Key {
            table: "pragma_ceiling".to_string(),
            key: "frozen_literal".to_string(),
        },
        bound: Bound::Ceiling,
        now: pragmas,
    });

    // MIN_FILES.
    let rows = gate_rows(cx, "plane-transport-neutrality")?;
    let row = the_row(&rows, gates::plane_transport_neutrality::ROW_ZERO_FILES)?;
    let files = count_before(row, " file(s) across")?;
    m.fields
        .push(const_field(TRANSPORT_NEUTRALITY, "MIN_FILES", files));

    // NEUTRAL_FLOOR, PLANE_FLOOR.
    let (neutral, plane) = gates::plane_purity::settle_measure(cx)?;
    m.fields
        .push(const_field(PLANE_PURITY, "NEUTRAL_FLOOR", neutral as u64));
    m.fields
        .push(const_field(PLANE_PURITY, "PLANE_FLOOR", plane as u64));

    // SPAN_FLOOR.
    let rows = gate_rows(cx, "tracing")?;
    let row = the_row(&rows, gates::tracing::ROW_SCAN_FLOOR)?;
    let spans = count_before(row, " #[instrument] ")?;
    m.fields.push(const_field(TRACING, "SPAN_FLOOR", spans));

    Ok(m)
}

/// The HEAD the clause names.
fn head_sha(cx: &Ctx) -> Result<String, String> {
    let sha = crate::gitp::git(cx.root(), &["rev-parse", "--short=10", "HEAD"])?;
    Ok(sha.trim().to_string())
}

/// `cargo xtask gate --settle`.
pub fn run(cx: &Ctx) -> i32 {
    let sha = match head_sha(cx) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask gate --settle: HEAD could not be read: {e}");
            return 3;
        }
    };
    let measured = match measure(cx) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "xtask gate --settle: the measure could not be taken, NOTHING was written: {e}"
            );
            return 3;
        }
    };
    let mut texts = BTreeMap::new();
    for f in FILES {
        match cx.read(f) {
            Ok(t) => {
                texts.insert((*f).to_string(), t);
            }
            Err(e) => {
                eprintln!("xtask gate --settle: {f} could not be read: {e}");
                return 3;
            }
        }
    }
    let plan = match plan(&texts, &measured.fields, &sha) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("xtask gate --settle: NOTHING was written: {e}");
            return 3;
        }
    };
    for o in &measured.orphans {
        println!("REFUSED {o}");
    }
    for mv in &plan.refused {
        println!(
            "REFUSED {mv}: the measure would loosen this {}",
            mv.bound.word()
        );
    }
    if !measured.orphans.is_empty() || !plan.refused.is_empty() {
        eprintln!(
            "xtask gate --settle: REFUSED, NOTHING was written: {} row(s) would loosen. A ceiling \
             only falls to its measure and a floor only rises to it (BUSBAR-1.6.0.md Law 9); the \
             change goes back to its author.",
            measured.orphans.len() + plan.refused.len()
        );
        return 1;
    }
    for (file, text) in &plan.texts {
        if let Err(e) = cx.write_file(file, text) {
            eprintln!("xtask gate --settle: {file} could not be written: {e}");
            return 3;
        }
    }
    for mv in &plan.settled {
        println!("SETTLED {mv}");
    }
    if plan.settled.is_empty() {
        println!("xtask gate --settle: every measured field already equals its measure at {sha}");
    } else {
        println!(
            "xtask gate --settle: {} field(s) settled in {} file(s) at {sha}",
            plan.settled.len(),
            plan.texts.len()
        );
    }
    0
}

// ------------------------------------------------------------------------------------------------
// the self-test: RED plants over the pure core
// ------------------------------------------------------------------------------------------------

pub const SHA: &str = "0123456789";

pub const TOML_IN: &str = r#"# [[law0]] fixture: a comment naming count = "9" is no row
[[law0]]
crate = "busbar"
axis  = "auth"
count = "23"
cite  = "measured on predev f830faa691 (Law 9); LOWERED 24 -> 23: prose"

[[law0]]
crate = "busbar"
axis  = "auth-x"
count = "23"
cite  = "a decoy row with the same count"

[[dep]]
from    = "busbar"
to      = "busbar-auth-header"
half    = "shipped"
count   = "3"
verdict = "allowed"
cite    = "a dep row"
why     = "count = 3 in prose stays prose"

[[law0]]
crate = "busbar-kernel"
axis  = "plane"
count = "7"
cite  = ""
"#;

pub const TOML_OUT: &str = r#"# [[law0]] fixture: a comment naming count = "9" is no row
[[law0]]
crate = "busbar"
axis  = "auth"
count = "22"
cite  = "measured on predev f830faa691 (Law 9); LOWERED 24 -> 23: prose; SETTLED 23 -> 22, the gate's measure on 0123456789"

[[law0]]
crate = "busbar"
axis  = "auth-x"
count = "23"
cite  = "a decoy row with the same count"

[[dep]]
from    = "busbar"
to      = "busbar-auth-header"
half    = "shipped"
count   = "2"
verdict = "allowed"
cite    = "a dep row; SETTLED 3 -> 2, the gate's measure on 0123456789"
why     = "count = 3 in prose stays prose"

[[law0]]
crate = "busbar-kernel"
axis  = "plane"
count = "5"
cite  = "SETTLED 7 -> 5, the gate's measure on 0123456789"
"#;

pub const PRAGMA_IN: &str = "# May only fall.
[pragma_ceiling]
frozen_literal = 2

[[leak]]
frozen_literal = 9
";

pub const PRAGMA_OUT: &str = "# May only fall.
[pragma_ceiling]
frozen_literal = 1
# SETTLED 2 -> 1, the gate's measure on 0123456789

[[leak]]
frozen_literal = 9
";

pub const RUST_IN: &str = "/// THE FLOOR, measured.
/// LOWERED 5 -> 2 in a reviewed diff.
pub const SPAN_FLOOR: usize = 2;
const SPAN_FLOOR_X: usize = 2;

    /// An indented one.
    pub(crate) const MIN_FILES: usize = 1_234;
";

pub const RUST_OUT: &str = "/// THE FLOOR, measured.
/// LOWERED 5 -> 2 in a reviewed diff.
/// SETTLED 2 -> 3, the gate's measure on 0123456789
pub const SPAN_FLOOR: usize = 3;
const SPAN_FLOOR_X: usize = 2;

    /// An indented one.
    /// SETTLED 1234 -> 1240, the gate's measure on 0123456789
    pub(crate) const MIN_FILES: usize = 1240;
";

/// The three fixture files, keyed by real [`FILES`] paths.
pub fn fixture_texts() -> BTreeMap<String, String> {
    [
        (KIND_ISOLATION, TOML_IN),
        (NOUN_NEUTRALITY, PRAGMA_IN),
        (TRACING, RUST_IN),
    ]
    .into_iter()
    .map(|(f, t)| (f.to_string(), t.to_string()))
    .collect()
}

fn law0(krate: &str, axis: &str, now: u64) -> Field {
    Field {
        file: KIND_ISOLATION.to_string(),
        site: Site::Row {
            table: "law0".to_string(),
            keys: vec![
                ("crate".to_string(), krate.to_string()),
                ("axis".to_string(), axis.to_string()),
            ],
        },
        bound: Bound::Ceiling,
        now,
    }
}

/// The fields every settling case moves, each in the safe direction.
pub fn fixture_fields() -> Vec<Field> {
    vec![
        law0("busbar", "auth", 22),
        Field {
            file: KIND_ISOLATION.to_string(),
            site: Site::Row {
                table: "dep".to_string(),
                keys: vec![
                    ("from".to_string(), "busbar".to_string()),
                    ("to".to_string(), "busbar-auth-header".to_string()),
                    ("half".to_string(), "shipped".to_string()),
                ],
            },
            bound: Bound::Ceiling,
            now: 2,
        },
        law0("busbar-kernel", "plane", 5),
        Field {
            file: NOUN_NEUTRALITY.to_string(),
            site: Site::Key {
                table: "pragma_ceiling".to_string(),
                key: "frozen_literal".to_string(),
            },
            bound: Bound::Ceiling,
            now: 1,
        },
        const_field(TRACING, "SPAN_FLOOR", 3),
        const_field(TRACING, "MIN_FILES", 1240),
    ]
}

type Case = (&'static str, fn() -> Result<(), String>);

/// EVERY CASE, each a plant the settle must answer the one way that is right.
pub const CASES: &[Case] = &[
    ("refuses-to-raise-a-ceiling", case_refuses_ceiling_up),
    ("refuses-to-lower-a-floor", case_refuses_floor_down),
    ("refuses-wholesale", case_refuses_wholesale),
    ("touches-only-listed-fields", case_only_listed),
    ("refuses-a-file-off-the-list", case_file_off_list),
    ("refuses-an-ambiguous-row", case_ambiguous_row),
    ("idempotent", case_idempotent),
    ("the-clause-is-exact", case_clause),
];

fn expect_refused(fields: &[Field], label: &str) -> Result<(), String> {
    let p = plan(&fixture_texts(), fields, SHA)?;
    if !p.refused.iter().any(|m| m.label == label) {
        return Err(format!("`{label}` was not refused: {p:?}"));
    }
    if !p.texts.is_empty() || !p.settled.is_empty() {
        return Err(format!("a refused settle still wrote: {p:?}"));
    }
    Ok(())
}

fn case_refuses_ceiling_up() -> Result<(), String> {
    expect_refused(
        &[law0("busbar", "auth", 24)],
        "[[law0]] crate=busbar axis=auth",
    )
}

fn case_refuses_floor_down() -> Result<(), String> {
    expect_refused(&[const_field(TRACING, "SPAN_FLOOR", 1)], "SPAN_FLOOR")
}

fn case_refuses_wholesale() -> Result<(), String> {
    let mut fields = fixture_fields();
    fields.push(const_field(TRACING, "MIN_FILES", 1200));
    expect_refused(&fields, "MIN_FILES")
}

fn case_only_listed() -> Result<(), String> {
    let p = plan(&fixture_texts(), &fixture_fields(), SHA)?;
    let want: BTreeMap<String, String> = [
        (KIND_ISOLATION, TOML_OUT),
        (NOUN_NEUTRALITY, PRAGMA_OUT),
        (TRACING, RUST_OUT),
    ]
    .into_iter()
    .map(|(f, t)| (f.to_string(), t.to_string()))
    .collect();
    for (file, text) in &want {
        let got = p.texts.get(file).map(String::as_str).unwrap_or("");
        if got != text {
            return Err(format!("{file}: wrote\n{got}\nexpected\n{text}"));
        }
    }
    if p.texts.len() != want.len() || p.settled.len() != fixture_fields().len() {
        return Err(format!("settled the wrong set: {p:?}"));
    }
    Ok(())
}

fn case_file_off_list() -> Result<(), String> {
    let mut texts = fixture_texts();
    texts.insert("README.md".to_string(), RUST_IN.to_string());
    let field = const_field("README.md", "SPAN_FLOOR", 3);
    match plan(&texts, &[field], SHA) {
        Err(e) if e.contains("not a file") => Ok(()),
        other => Err(format!("a field outside FILES was accepted: {other:?}")),
    }
}

fn case_ambiguous_row() -> Result<(), String> {
    let mut texts = fixture_texts();
    let doubled =
        format!("{TOML_IN}\n[[law0]]\ncrate = \"busbar\"\naxis  = \"auth\"\ncount = \"23\"\n");
    texts.insert(KIND_ISOLATION.to_string(), doubled);
    match plan(&texts, &[law0("busbar", "auth", 22)], SHA) {
        Err(e) if e.contains("2 rows match") => Ok(()),
        other => Err(format!("an ambiguous row was settled: {other:?}")),
    }
}

fn case_idempotent() -> Result<(), String> {
    let first = plan(&fixture_texts(), &fixture_fields(), SHA)?;
    let mut texts = fixture_texts();
    texts.extend(first.texts.clone());
    let second = plan(&texts, &fixture_fields(), SHA)?;
    if !second.texts.is_empty() || !second.settled.is_empty() || !second.refused.is_empty() {
        return Err(format!("the second run was not a no-op: {second:?}"));
    }
    Ok(())
}

fn case_clause() -> Result<(), String> {
    if clause(23, 22, SHA) != "SETTLED 23 -> 22, the gate's measure on 0123456789" {
        return Err(format!("the clause reads `{}`", clause(23, 22, SHA)));
    }
    let p = plan(&fixture_texts(), &fixture_fields(), SHA)?;
    let toml = p.texts.get(KIND_ISOLATION).cloned().unwrap_or_default();
    let old = "cite  = \"measured on predev f830faa691 (Law 9); LOWERED 24 -> 23: prose";
    let new = format!("{old}; {}\"", clause(23, 22, SHA));
    if !toml.lines().any(|l| l == new) {
        return Err(format!("the cite does not end with the clause: {toml}"));
    }
    let rust = p.texts.get(TRACING).cloned().unwrap_or_default();
    let lines: Vec<&str> = rust.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with("pub const SPAN_FLOOR"))
        .ok_or("SPAN_FLOOR is gone")?;
    if at == 0 || lines[at - 1] != format!("/// {}", clause(2, 3, SHA)) {
        return Err(format!(
            "the doc line is not directly above the constant: {rust}"
        ));
    }
    Ok(())
}

/// Run every case; `Err` names the first that did not hold.
pub fn selftest() -> Result<usize, String> {
    for (name, case) in CASES {
        case().map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(CASES.len())
}

/// `cargo xtask gate --settle --selftest`.
pub fn selftest_cmd() -> i32 {
    match selftest() {
        Ok(n) => {
            for (name, _) in CASES {
                println!("ok  settle:{name}");
            }
            println!("xtask gate --settle --selftest: {n} case(s) hold");
            0
        }
        Err(e) => {
            eprintln!("xtask gate --settle --selftest: RED: {e}");
            1
        }
    }
}

#[cfg(test)]
#[path = "tests/settle_tests.rs"]
mod tests;
