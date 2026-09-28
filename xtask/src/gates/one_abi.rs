//! THE ONE-MEMORY-ABI GATES' SHARED PARTS (M0 ABI-SPEC; the design's locked plugin ABI).
//!
//! Six gates measure how far the tree is from the one memory ABI: `one-memory-abi`,
//! `contract-stateless`, `plugin-closure-deps`, `c1-literals`, `door-only` and
//! `linked-dropped-features`. They land REPORT-ONLY: each is armed at the count it measured on the
//! day it landed, as a DRAIN-ONLY ledger `qa/<gate>.toml` whose rows are the M2 work list, and CI
//! runs them in a job the umbrella does not count.
//!
//! The ledger discipline is `abi-location`'s, shared here so the six cannot drift apart:
//!
//! * a finding with no ledger row is NEW and reds its rule's row — the fix is to not add it;
//! * a ledger row with no finding is STALE and reds `<gate>:ledger` — a drain strikes its row in
//!   the same commit, so the count on record is always the count in the tree;
//! * `--write` regenerates the ledger from the tree. That is how a gate is ARMED, and how a drain
//!   strikes; a row it adds is a raise and is reviewed as one.
//!
//! Rows are keyed `(rule, file, item)` — never a line number, which rots on every edit above it.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_red, Report};
use crate::ledger::{Row, Verdict};
use crate::manifest::{self, DepDecl};
use crate::scan::{self, ScopeLine};

/// One thing a gate found, keyed by `(rule, file, item)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The owed row id the finding reds when it is new.
    pub rule: &'static str,
    /// Workspace-relative path.
    pub file: String,
    /// What was found: a symbol, a dependency, a needle.
    pub item: String,
    /// 1-based line, for the report only; `0` for a manifest-level fact.
    pub line: usize,
}

type Key = (String, String, String);

impl Finding {
    pub fn new(rule: &'static str, file: &str, item: impl Into<String>, line: usize) -> Finding {
        Finding {
            rule,
            file: file.to_string(),
            item: sanitize(&item.into()),
            line,
        }
    }

    fn key(&self) -> Key {
        (self.rule.to_string(), self.file.clone(), self.item.clone())
    }
}

/// A ledger value is written between double quotes and read back by `toml_lite`; an item never
/// needs a quote or a backslash, so it never carries one.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c == '"' || c == '\\' { '\'' } else { c })
        .collect()
}

/// A gate's name, its ledger and its rules.
pub struct Spec {
    pub gate: &'static str,
    pub ledger: &'static str,
    /// `(row id, what the row holds)`.
    pub rules: &'static [(&'static str, &'static str)],
    /// The ledger file's header, written by `--write`.
    pub header: &'static str,
}

impl Spec {
    pub fn ledger_row(&self) -> String {
        format!("{}:ledger", self.gate)
    }

    pub fn owed(&self) -> Vec<String> {
        let mut out: Vec<String> = self.rules.iter().map(|(id, _)| id.to_string()).collect();
        out.push(self.ledger_row());
        out
    }
}

struct Ledger {
    rows: BTreeSet<Key>,
    errors: Vec<String>,
}

fn load_ledger(cx: &Ctx, spec: &Spec) -> Ledger {
    let text = match cx.read(spec.ledger) {
        Ok(t) => t,
        Err(e) => {
            return Ledger {
                rows: BTreeSet::new(),
                errors: vec![format!(
                    "{} is unreadable ({e}); every finding is therefore NEW",
                    spec.ledger
                )],
            }
        }
    };
    let doc = crate::toml_lite::parse_text(&text);
    let known: BTreeSet<&str> = spec.rules.iter().map(|(id, _)| *id).collect();
    let mut led = Ledger {
        rows: BTreeSet::new(),
        errors: Vec::new(),
    };
    for (n, t) in doc.array_table("finding").iter().enumerate() {
        let rule = t.get_one("rule").unwrap_or("").to_string();
        let file = t.get_one("file").unwrap_or("").to_string();
        let item = t.get_one("item").unwrap_or("").to_string();
        if file.is_empty() || item.is_empty() || !known.contains(rule.as_str()) {
            led.errors.push(format!(
                "[[finding]] #{}: needs a rule this gate owes, a file and an item (got rule `{rule}`, file `{file}`, item `{item}`)",
                n + 1
            ));
            continue;
        }
        if !led.rows.insert((rule, file, item)) {
            led.errors.push(format!(
                "[[finding]] #{}: a duplicate row — one row per (rule, file, item)",
                n + 1
            ));
        }
    }
    led
}

/// The ledger text `--write` commits.
fn render_ledger(spec: &Spec, findings: &[Finding]) -> String {
    let keys: BTreeSet<Key> = findings.iter().map(Finding::key).collect();
    let mut s = String::from(spec.header);
    if !s.ends_with('\n') {
        s.push('\n');
    }
    for (rule, file, item) in keys {
        s.push_str(&format!(
            "\n[[finding]]\nrule = \"{rule}\"\nfile = \"{file}\"\nitem = \"{item}\"\n"
        ));
    }
    s
}

/// THE VERDICT: every finding against the drain-only ledger.
pub fn verdict(cx: &Ctx, spec: &Spec, mut findings: Vec<Finding>, errors: Vec<String>) -> Verdict {
    findings.sort();
    if cx.env().write && errors.is_empty() {
        if let Err(e) = std::fs::write(cx.abs(spec.ledger), render_ledger(spec, &findings)) {
            return Verdict::of(vec![Row::fail(
                spec.ledger_row(),
                "the ledger could not be written",
                format!("{}: {e}", spec.ledger),
            )]);
        }
    }
    let led = load_ledger(cx, spec);
    let found: BTreeSet<Key> = findings.iter().map(Finding::key).collect();
    let mut rows = Vec::new();
    for (id, what) in spec.rules {
        let mine: Vec<&Finding> = findings.iter().filter(|f| f.rule == *id).collect();
        let fresh: Vec<String> = mine
            .iter()
            .filter(|f| !led.rows.contains(&f.key()))
            .map(|f| format!("{}:{} {}", f.file, f.line, f.item))
            .collect();
        let distinct: BTreeSet<Key> = mine.iter().map(|f| f.key()).collect();
        if fresh.is_empty() {
            rows.push(Row::pass(
                *id,
                *what,
                format!(
                    "{} finding(s) at {} site(s), every one on the drain-only ledger {} (report-only: the M2 work list)",
                    distinct.len(),
                    mine.len(),
                    spec.ledger
                ),
            ));
        } else {
            rows.push(Row::fail(
                *id,
                *what,
                format!(
                    "{} NEW finding(s) no ledger row names — the fix is to not add them, never a row: {}",
                    fresh.len(),
                    fresh.join(" | ")
                ),
            ));
        }
    }
    let stale: Vec<String> = led
        .rows
        .iter()
        .filter(|k| !found.contains(*k))
        .map(|(r, f, i)| format!("{r} {f} {i}"))
        .collect();
    let mut problems = led.errors;
    problems.extend(errors);
    if !stale.is_empty() {
        problems.push(format!(
            "{} STALE row(s) — drained in the tree and not struck from {} in the same commit: {}",
            stale.len(),
            spec.ledger,
            stale.join(" | ")
        ));
    }
    rows.push(if problems.is_empty() {
        Row::pass(
            spec.ledger_row(),
            "the ledger is exactly the tree's findings",
            format!("{} row(s), none stale", led.rows.len()),
        )
    } else {
        Row::fail(
            spec.ledger_row(),
            "the ledger is not exactly the tree's findings",
            problems.join(" ; "),
        )
    });
    Verdict::of(rows)
}

/// The shared selftest: the tree is green, every planted rule is RED naming its plant, and a row
/// the tree does not carry is RED as STALE.
pub fn selftest<'a>(
    cx: &'a Ctx,
    gate: &'a dyn crate::gates::Gate,
    spec: &Spec,
    plants: Vec<(&'static str, &'static str, Overlay, Vec<&'static str>)>,
) -> Report<'a> {
    let mut report = Report::new();
    report.push(prove_green(
        cx,
        gate,
        format!(
            "{} is green on this tree: every finding is on its ledger",
            spec.gate
        ),
        &spec.owed().iter().map(String::as_str).collect::<Vec<_>>(),
    ));
    for (rule, name, ov, naming) in plants {
        report.push(prove_rows_red(cx, gate, name, &[rule], ov, &naming));
    }
    let mut ledger = cx.read(spec.ledger).unwrap_or_default();
    let first = spec.rules.first().map_or("", |(id, _)| *id);
    ledger.push_str(&format!(
        "\n[[finding]]\nrule = \"{first}\"\nfile = \"crates/planted-stale/src/lib.rs\"\nitem = \"planted_stale_item\"\n"
    ));
    let mut ov = Overlay::new();
    ov.set(spec.ledger, ledger);
    let ledger_row = spec.ledger_row();
    report.push(prove_rows_red(
        cx,
        gate,
        "a ledger row the tree does not carry is STALE",
        &[ledger_row.as_str()],
        ov,
        &["crates/planted-stale/src/lib.rs", "STALE"],
    ));
    report
}

// ── THE WORKSPACE ────────────────────────────────────────────────────────────────────────────────

/// One workspace member.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    /// `crates/x`.
    pub dir: String,
    pub manifest: String,
    pub decls: Vec<DepDecl>,
}

impl Member {
    pub fn manifest_rel(&self) -> String {
        format!("{}/Cargo.toml", self.dir)
    }
}

/// Every workspace member, read through the overlay.
pub fn members(cx: &Ctx) -> Result<Vec<Member>, String> {
    let root = cx.read("Cargo.toml")?;
    let mut out = Vec::new();
    for dir in manifest::workspace_members(&root) {
        let rel = format!("{dir}/Cargo.toml");
        let text = cx.read(&rel)?;
        let name = package_name(&text).ok_or_else(|| format!("{rel}: no [package] name"))?;
        out.push(Member {
            name,
            dir,
            decls: manifest::dep_decls(&text),
            manifest: text,
        });
    }
    if out.len() < 10 {
        return Err(format!(
            "the workspace read as {} member(s); a scan that saw so few has gone blind",
            out.len()
        ));
    }
    Ok(out)
}

fn package_name(text: &str) -> Option<String> {
    let mut inside = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') {
            inside = t == "[package]";
            continue;
        }
        if inside {
            if let Some(v) = t.strip_prefix("name") {
                let v = v.trim_start();
                if let Some(v) = v.strip_prefix('=') {
                    return Some(v.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

/// THE PLUGIN KINDS' CRATE-NAME HEADS. A crate whose name — `busbar-` prefix or not — starts with
/// one of these is a plugin of that kind: `busbar-transport-tcp`, `store-memory`, `hooks-ranking`.
const PLUGIN_HEADS: &[&str] = &[
    "plane-",
    "transport-",
    "store-",
    "auth-",
    "secret-",
    "hook-",
    "hooks-",
    "export-",
];

/// Is `name` a plugin crate?
pub fn is_plugin_crate(name: &str) -> bool {
    let bare = name.strip_prefix("busbar-").unwrap_or(name);
    PLUGIN_HEADS.iter().any(|h| bare.starts_with(h))
}

/// The members the `busbar` binary links, through shipped workspace edges, the binary included.
pub fn binary_closure(members: &[Member]) -> BTreeSet<String> {
    let names: BTreeSet<&str> = members.iter().map(|m| m.name.as_str()).collect();
    let by_name: BTreeMap<&str, &Member> = members.iter().map(|m| (m.name.as_str(), m)).collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut todo = vec!["busbar".to_string()];
    while let Some(n) = todo.pop() {
        if !seen.insert(n.clone()) {
            continue;
        }
        let Some(m) = by_name.get(n.as_str()) else {
            continue;
        };
        for d in &m.decls {
            if d.table.shipped() && names.contains(d.pkg.as_str()) {
                todo.push(d.pkg.clone());
            }
        }
    }
    seen
}

/// A member's production Rust files, through the overlay.
pub fn rs_files(cx: &Ctx, dir: &str) -> Result<Vec<crate::ctx::SourceFile>, String> {
    cx.walk(
        &WalkSpec::new([format!("{dir}/src")])
            .ext("rs")
            .exclude(["/tests/", "/benches/"])
            .allow_empty(),
    )
    .map_err(|e| format!("{dir}/src: {e:?}"))
}

/// The production lines of a file: not test code, not a whole-line comment.
pub fn production(text: &str) -> Vec<ScopeLine> {
    scan::test_scope(text)
        .into_iter()
        .filter(|l| !l.gated && !l.is_comment)
        .collect()
}

/// `word` occurs in `hay` bounded by non-identifier characters.
pub fn has_word(hay: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(i) = hay[from..].find(word) {
        let at = from + i;
        let before = hay[..at].chars().next_back().is_none_or(|c| !ident(c));
        let after = hay[at + word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !ident(c));
        if before && after {
            return true;
        }
        from = at + word.len();
    }
    false
}

/// The string literal bodies on a line, read off the raw line at the positions the blanker kept
/// the quotes at. A literal that runs past the end of the line is read to the end of the line.
pub fn literals(sl: &ScopeLine) -> Vec<String> {
    let c: Vec<char> = sl.counted.chars().collect();
    let r: Vec<char> = sl.raw.chars().collect();
    if c.len() != r.len() {
        return Vec::new();
    }
    let quotes: Vec<usize> = (0..c.len()).filter(|&i| c[i] == '"').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < quotes.len() {
        let open = quotes[i];
        let close = quotes.get(i + 1).copied().unwrap_or(c.len());
        out.push(r[open + 1..close].iter().collect());
        i += 2;
    }
    out
}
