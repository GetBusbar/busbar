//! `cargo xtask gate qa-names` — EVERY NAME IN `qa/*.toml` AND IN A `const` UNDER `xtask/src/`
//! RESOLVES TO SOMETHING THAT EXISTS.
//!
//! A gate's config table names a kind, a crate, a path or a glob. Every one of those is a STRING,
//! and a string does not move when the thing it names is renamed, folded or deleted. What happens
//! then is NOT a red row. The lookup resolves to EMPTY, the rule scans a population of ZERO, and a
//! ban over nothing PASSES. The instrument stops watching and says nothing while it stops.
//!
//! THIS CLASS WAS FOUND FIVE TIMES IN ONE DAY (2026-09-22), all in `qa/construction.toml`:
//!
//! 1. `[gate.plugin_kinds].plane` did not name `crates/busbar-plane-decision` — the fifth plane was
//!    in NO kind list, so `source-denylist` never scanned it. Proven with a positive control, not
//!    inferred: the same `use std::net::TcpStream` planted in `busbar-plane-decision` scored
//!    `PASS denylist:hits`, the identical plant in the listed `busbar-plane-streaming` scored RED.
//!    One caught, one invisible; the only difference was membership in a list. Fixed `2b2de9712`.
//! 2. `[gate.plugin_kinds].export` read `crates/export-*` while DECISION #34 puts every plugin
//!    instance at `crates/busbar-<kind>-<name>`. It matched the one pre-#34 crate and would have
//!    gone on printing a green row with every real export sink outside the family. Fixed
//!    `2b5727416`.
//! 3. `[rules.source-denylist].kinds` named `pure_auth` and `egress_auth`. NEITHER IS A KEY IN
//!    `[gate.plugin_kinds]` — DECISION #3 collapsed them into one `auth` key — so both resolved to
//!    an empty glob list and the whole auth kind went unscanned. Fixed `383f23875`.
//! 4. `[rules.forbid-unsafe].forbid_kinds` carried the SAME two phantom names, so the auth kind was
//!    never held to `forbid-unsafe` at all, and neither auth plugin carries
//!    `#![forbid(unsafe_code)]`. Fixed `ab5bcb45c`.
//! 5. Open at the time this gate was written, and reported by it: `[rules.no-uninstalled-seam]`'s
//!    `seam_root` names a deleted crate, `[rules.hold-escapes].known_sites` names six paths under
//!    two deleted crates, `[rules.kernel-seal-impls].known_sites` names a deleted path, and more
//!    besides — the standing list is printed on every run.
//!
//! THE RULE THIS ENCODES, from `docs/design/BUSBAR-1.6.0.md`: *"A crate that is in no list is in no
//! gate — and a KIND that is in no list is in no gate either. The census rows count the roster;
//! neither can see a population that was never enrolled. Enrolment is the gap no count detects."*
//!
//! THE SHAPE OF THE CONTRACT is `package-selectors`' and `feature-sets`': every universe is DERIVED
//! from the tree — the workspace members plus `Cargo.lock` for packages, `[gate.plugin_kinds]`'s own
//! keys for kinds, the filesystem for paths — and ASSERTED against every name in every covered file.
//! A deliberate exception is possible only IN WRITING, beside the site, as a comment:
//!
//! ```text
//! # qa-names: <name> -- <covered file> -- <reason, at least MIN_REASON characters>
//! ```
//!
//! and the declaration is itself held to three liveness rules, because an exemption that outlives
//! what it excused silently excuses the next name to take the spelling.
//!
//! WHAT A NAME IS, AND WHY SO NARROWLY. A `qa/*.toml` carries prose as well as configuration — a
//! `why = """…"""`, a `reason`, a `because`, a `cite`, a ledger row's `drain` — and prose names
//! deleted crates and moved files on purpose, because prose is what RECORDS a deletion. So a value
//! is a name only in one of three positions:
//!
//! 1. **A PATH**, recognised by SHAPE: the whole value, with no whitespace anywhere in it, contains
//!    a `/`, and its first segment is a directory that exists at the repo root. The no-whitespace
//!    rule is the whole discrimination — a paragraph that mentions `docs/design/ARCHITECTURE.md` is
//!    a paragraph, and `crates/busbar-substrate/src` is a scan root. An optional `:LINE` or
//!    `::function` tail is stripped (`known_sites` writes both), as is a trailing `/`.
//! 2. **A KIND**, recognised by the key: a key with a `kind`/`kinds` token, in `qa/construction.toml`
//!    only. It must be a key of `[gate.plugin_kinds]`. The other files' `kind` columns are a
//!    DIFFERENT vocabulary (`api`, `cleanliness`, `legacy`, `substrate`) and are `kind-isolation`'s,
//!    not this gate's.
//! 3. **A CRATE**, recognised by the key: a key with a `crate`/`crates` token and no path token, and
//!    both halves of `[gate.plane_codec_crates]`. It must be a package `cargo` resolves.
//!
//! A key whose tokens say FRAGMENT or PATTERN — `*_fragments`, `*_pattern(s)`, `symbol(s)`,
//! `word(s)`, `needle`, `prefix`, `verb(s)` — is never a name: `/testkit/` is a substring test and
//! `busbar_kernel_ledger::cost::` is a module prefix, and reporting either as a missing path is how
//! a gate earns a `|| true` in front of it.
//!
//! WHAT IS DELIBERATELY NOT COVERED, stated so it is not mistaken for held: ENROLMENT. This gate
//! answers "does every name resolve", not "is everything that should be named, named" — an omission
//! is not a name, and defect 1 above was visible to it only because the same list ALSO carried a
//! path to a plane that had since been folded away. Defect 2 was not visible to it at all:
//! `crates/export-*` resolved to exactly one real directory and zero `busbar-export-*` crates
//! existed, so there was no dead name and no population to count. Closing that needs a different
//! rule — that a kind's family glob must cover the path DECISION #34 puts its instances at — and
//! that rule is a roster decision with seven live answers owed, not a name check.
//!
//! THE RULES, each its own ledger row:
//!
//! 1. [`ROW_UNIVERSE`] — the package universe and the kind table were read, each above its floor. A
//!    reader that lost its input resolves nothing, and every name in `qa/` would be reported for a
//!    defect in this gate.
//! 2. [`ROW_FLOOR`] — at least [`NAME_FLOOR`] names were discovered. Zero is never clean: "every
//!    name resolves" is vacuously true over no names, which is exactly what a scanner whose
//!    classifier stopped matching reports.
//! 3. [`ROW_KIND`] — every kind name is a key of `[gate.plugin_kinds]`. A `[gate.census.plugin_kinds]`
//!    key is held to the same rule with ONE way out, and it is the one the table itself provides: a
//!    row that declares `= 0` declares a kind with no crate yet, which the header over
//!    `[gate.plugin_kinds]` says in terms is legitimate. A row that declares a POPULATION for a kind
//!    with no glob — `pure_auth = 2` — claims two crates nothing can find, and is RED.
//! 4. [`ROW_CRATE`] — every crate name is a package this workspace resolves.
//! 5. [`ROW_PATH`] — every path names something on disk.
//! 6. [`ROW_GLOB`] — every glob matches at least one thing. Judged PER ENTRY everywhere except
//!    `[gate.plugin_kinds]`, where the unit is the KIND: a kind's list may carry a forward-looking
//!    entry (`crates/busbar-export-*`, zero today, and the entry that closes defect 2) as long as
//!    the kind as a whole finds something, and a kind that finds nothing is excused only by its own
//!    census row declaring zero.
//! 7. [`ROW_DECL_LIVE`] — a declaration names a name that is still written down AND still fails to
//!    resolve. A stale exemption outlives the site it excused and silently excuses the next name to
//!    take the spelling; one for a name that resolves again is an exemption nobody needs, and
//!    leaving it hides the day it stops resolving.
//! 8. [`ROW_DECL_FILE`] — the file a declaration names is one of the covered files.
//! 9. [`ROW_DECL_REASON`] — a declaration carries a reason of at least [`MIN_REASON`] characters. An
//!    exemption without a reason becomes permanent by accident.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::construction::tree::glob_dirs;
use crate::gates::{prove_rows_green, prove_rows_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::toml_doc::{self, Value};

/// The covered root. One extension, one shape, one reader.
pub const QA_ROOT: &str = "qa";
pub const QA_EXT: &str = "toml";

/// THE SECOND COVERED ROOT, AND THE REASON IT IS HERE. Every scan root, named-file list, allowlist
/// and floor a gate in this crate owns is a Rust `const`, not a `qa/*.toml` value — and until this
/// root was added, the instrument for *"does this name still resolve"* could not see the place most
/// names live. That is LEDGER **G25** in terms (*"it reads only `qa/*.toml` — not Rust, not shell,
/// not `qa/*.json`"*) and **G22**'s generalisation (*"FIXING A RULE'S TOML DOES NOT FIX THE RULE"*).
///
/// It was not a hypothetical. The census that closed this took 277 path-shaped literals out of the
/// constants under `xtask/src/` and found **two live money-path scan-set entries naming nothing**:
/// `no_float_money.rs`'s `COUNT_READ_ROOTS` still led its MCP group with `crates/busbar-mcp-codec/src`
/// (the crate dissolved at `5fbd891e0`), and `PERSISTED_RECORD_HOMES` still named
/// `crates/busbar-kernel-ledger/src/records.rs` (renamed `R100` into the contract at `1059d3c36`).
/// The first held `no-float-money:scan-floor` red; the SECOND COULD NOT GO RED AT ALL, because an
/// absent home is a `continue` there. Nothing in the tree could have told anyone about the second
/// one. That is the whole argument for this root.
pub const XTASK_ROOT: &str = "xtask/src";
pub const XTASK_EXT: &str = "rs";

/// The file that carries the kind vocabulary every other kind name is checked against.
pub const CONFIG_REL: &str = "qa/construction.toml";
/// The kind table: its KEYS are the kind universe.
pub const KIND_TABLE: &str = "gate.plugin_kinds";
/// The census table: its KEYS are kind names and its VALUES are the declared population, which is
/// what lets a kind with no crate yet say so.
pub const CENSUS_TABLE: &str = "gate.census.plugin_kinds";
/// The codec table: BOTH halves are crate names — the key is the plane, the values are its pure
/// halves — and neither is spelled in a key this gate's token rule would otherwise reach.
pub const CODEC_TABLE: &str = "gate.plane_codec_crates";

/// The declaration, in the one comment spelling a TOML file has. Matched on the TRIMMED line.
pub const DECL: &str = "# qa-names:";
/// The same declaration, in the one comment spelling a Rust file has.
pub const DECL_RS: &str = "// qa-names:";
/// The separator between a declaration's three fields.
pub const SEP: &str = " -- ";

pub const ROW_UNIVERSE: &str = "qa-names:universe-read";
pub const ROW_FLOOR: &str = "qa-names:name-floor";
pub const ROW_KIND: &str = "qa-names:kind-names-a-live-kind";
pub const ROW_CRATE: &str = "qa-names:crate-names-a-live-package";
pub const ROW_PATH: &str = "qa-names:path-names-a-live-path";
pub const ROW_GLOB: &str = "qa-names:glob-matches-something";
pub const ROW_DECL_LIVE: &str = "qa-names:declaration-names-a-live-name";
pub const ROW_DECL_FILE: &str = "qa-names:declaration-names-a-live-file";
pub const ROW_DECL_REASON: &str = "qa-names:declaration-reason";
pub const ROW_XTASK_FLOOR: &str = "qa-names:xtask-const-floor";

// ── TWO DECLARATIONS THAT BELONG BESIDE THEIR SITE AND ARE NOT, AND THE REASON IS WRITTEN DOWN ──
//
// `config_schema`'s `SNAPSHOT_HOMES` is "EVERY HOME THE COMMITTED FINGERPRINT HAS EVER HAD, newest
// first" — its own words. The two older homes are read with `git show <ref>:<path>` AT A REF WHERE
// THEY EXISTED, so their absence from the working tree is the fact the constant records, not a
// defect in it. That is the same shape `qa/audit-ledger.json`'s `moved_from[]` has and which
// `audit-ledger:scope-paths-exist` correctly leaves alone: historical by construction.
//
// They are declared HERE rather than beside the site because `xtask/src/gates/config_schema/mod.rs`
// carries another agent's uncommitted work as this lands, and `git commit --only` on a path commits
// the WORKING TREE state of that path — which would sweep their in-flight edit into this commit.
// The mechanism is name-scoped, not file-scoped, so a declaration is valid wherever it is written
// and names the covered file it excuses; MOVE THESE TWO LINES BESIDE `SNAPSHOT_HOMES` the moment
// that file is free. If the constant is struck instead, `qa-names:declaration-names-a-live-name`
// reds on both of these, which is the mechanism working and not a surprise.
// qa-names: crates/busbar-core/src/config/config-schema.snapshot.json -- xtask/src/gates/config_schema/mod.rs -- a HISTORICAL home of the config fingerprint, read with `git show <ref>:<path>` at a ref where it existed; absence from the working tree is the fact it records
// qa-names: crates/busbar/src/config/config-schema.snapshot.json -- xtask/src/gates/config_schema/mod.rs -- the ORIGINAL home, the one the released tags v1.5.3/v1.5.4/v1.5.5 carry; a baseline older than the move has to ask for the path as it was THEN

/// The floor under the resolvable package universe. `package-selectors`' number and its reason: a
/// universe that COLLAPSED makes every live crate name look dead, which is a defect in the
/// instrument reported as a defect in the tree.
pub const UNIVERSE_FLOOR: usize = 40;
/// The floor under the kind universe. Measured at 10 on the 1.6.0 integration tree; DECISIONS #3
/// locks SEVEN plugin kinds and the table adds three non-plugin infra families. Set at the locked
/// seven, because a kind table that lost rows makes every kind name in the file look phantom.
pub const KIND_FLOOR: usize = 7;
/// The floor under the discovered names. Measured at 1_182 across ten covered files on the 1.6.0
/// integration tree. Set well below that: the number this floor exists to reject is a scan that
/// COLLAPSED, and an empty scan set is the one state in which "every name resolves" is true and
/// means nothing.
pub const NAME_FLOOR: usize = 400;
/// The floor under the names discovered in `xtask/src/**.rs` CONSTANTS, counted on its own.
///
/// SEPARATE FROM [`NAME_FLOOR`] ON PURPOSE. The `qa/*.toml` half alone is ~1_182 names, so a
/// combined floor of 400 is cleared by the TOML scan whatever the Rust scan does — and a Rust
/// reader whose item parser stopped matching would report ZERO dead constants and a green row. A
/// scan set gets its own floor or it has none.
pub const XTASK_NAME_FLOOR: usize = 150;
/// The shortest exemption reason that is a reason rather than a shrug. `feature-sets`' number, kept.
pub const MIN_REASON: usize = 30;

/// Key tokens that put a value in a PATH position — used ONLY to VETO the crate reading, so that
/// `crate_roots = ["crates"]` is a directory list and not a package called `crates`. A path is
/// recognised by its SHAPE, never by its key.
const PATH_TOKENS: &[&str] = &[
    "root", "roots", "path", "paths", "file", "files", "site", "sites", "dir", "dirs", "module",
    "script", "scripts", "glob", "globs",
];
/// Key tokens that put a value in a CRATE position.
const CRATE_TOKENS: &[&str] = &["crate", "crates"];
/// Key tokens that put a value in a KIND position.
const KIND_TOKENS: &[&str] = &["kind", "kinds"];
/// Key tokens that mean the value is a FRAGMENT, a PATTERN or a SYMBOL — a thing matched against
/// names, never a name itself. `/testkit/` is a substring test; `busbar_kernel_ledger::cost::` is a
/// module prefix; `'^(install_[a-z0-9_]+|set_[a-z0-9_]+_factory)$'` is a regex.
const FRAGMENT_TOKENS: &[&str] = &[
    "fragment",
    "fragments",
    "pattern",
    "patterns",
    "regex",
    "symbol",
    "symbols",
    "word",
    "words",
    "needle",
    "prefix",
    "verb",
    "verbs",
];

// ---------------------------------------------------------------------------------------------
// what a name is
// ---------------------------------------------------------------------------------------------

/// What universe a name is resolved against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A key of `[gate.plugin_kinds]`.
    Kind,
    /// A key of `[gate.census.plugin_kinds]`, carrying the population it declares. The declared zero
    /// is the one way a kind with no glob is legitimate.
    CensusKind(i64),
    /// A package `cargo` resolves.
    Crate,
    /// Something on disk.
    Path,
}

/// One name, cited where a reader has to open it rather than in the file it is somewhere inside.
#[derive(Debug, Clone)]
struct Name {
    text: String,
    file: String,
    line: usize,
    /// The dotted table path plus the key, as the owner would search for it.
    site: String,
    class: Class,
    /// Was it written as an item of an ARRAY? Only an array item can have a sibling planted beside
    /// it without rewriting the value, which is what the self-test needs.
    in_array: bool,
}

impl Name {
    fn cite(&self) -> String {
        format!(
            "{}:{} `{}` ({})",
            self.file, self.line, self.text, self.site
        )
    }

    /// The path this name resolves against, with the tails `known_sites` writes stripped: a
    /// `:240` line number, a `::function` selector, a trailing `/` marking a directory.
    fn core(&self) -> String {
        let t = &self.text;
        let t = match t.rfind("::") {
            Some(i)
                if t[i + 2..]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_') =>
            {
                &t[..i]
            }
            _ => t.as_str(),
        };
        let t = match t.rfind(':') {
            Some(i) if !t[i + 1..].is_empty() && t[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
                &t[..i]
            }
            _ => t,
        };
        t.trim_end_matches('/').to_string()
    }

    fn is_glob(&self) -> bool {
        self.text.contains('*')
    }
}

/// One `# qa-names:` line.
#[derive(Debug, Clone)]
struct Decl {
    name: String,
    file: String,
    reason: String,
}

/// A `key = [ "a", "b" ]` list, dropping any item that is not a string. `toml_doc::Table::list_of`
/// PANICS on a mixed array, which is the right answer for a rule reading its own threshold and the
/// wrong one for a gate whose whole job is to survive a config nobody has checked yet.
fn string_list(t: &toml_doc::Table, key: &str) -> Vec<String> {
    t.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn tokens(key: &str) -> Vec<&str> {
    key.split(['_', '-', '.']).collect()
}

fn has_token(key: &str, set: &[&str]) -> bool {
    tokens(key).iter().any(|t| set.contains(t))
}

/// Is the whole value a repo path? No whitespace anywhere, a `/` in it, and a first segment that is
/// a directory at the repo root. This is the rule that makes prose safe by construction rather than
/// by allowlist: a sentence has a space in it.
fn is_path_shaped(value: &str, tops: &BTreeSet<String>) -> bool {
    !value.is_empty()
        && !value.chars().any(char::is_whitespace)
        && value.contains('/')
        && value
            .split('/')
            .next()
            .is_some_and(|head| tops.contains(head))
}

/// The classification, in the order the header states it.
fn classify(rel: &str, key: &str, value: &str, tops: &BTreeSet<String>) -> Option<Class> {
    if has_token(key, FRAGMENT_TOKENS) {
        return None;
    }
    if is_path_shaped(value, tops) {
        return Some(Class::Path);
    }
    if has_token(key, KIND_TOKENS) {
        // ONE FILE'S KIND VOCABULARY. `qa/kind-isolation.toml` and `qa/instance-noun-neutrality.toml`
        // spell `kind = "api"` / `"cleanliness"` / `"legacy"`, which are that gate's own census
        // words and are reconciled by `kind-isolation:truths`, not here.
        return (rel == CONFIG_REL).then_some(Class::Kind);
    }
    if has_token(key, CRATE_TOKENS) && !has_token(key, PATH_TOKENS) && !value.contains('/') {
        return Some(Class::Crate);
    }
    None
}

/// The line a name is written on, 1-based, or 0 when it is written nowhere this reader can see.
///
/// SEARCHED FROM ITS OWN TABLE HEADER, never from the top of the file. `qa/kind-isolation.toml`
/// carries 221 `crate = "…"` rows under 221 `[[cell]]` headers and the same crate name appears in
/// dozens of them; a citation that always pointed at the first occurrence would send a reader to
/// the wrong row every time but one. The table path is the position: `cell.136` is the 137th
/// `[[cell]]`, and the value is the first match at or after that header.
fn line_of(text: &str, table: &str, needle: &str) -> usize {
    let lines: Vec<&str> = text.lines().collect();
    let from = table_line(&lines, table).unwrap_or(0);
    // QUOTED FIRST. `[rules.source-denylist]`'s own `why` paragraph opens "The pure kinds (plane,
    // hook, …)", three lines above the `kinds = ["plane", …]` it describes; a reader sent to the
    // prose is a reader sent to the wrong line, and the self-test plants beside the value it is
    // given, so a citation landing on prose is a plant that cannot be made.
    let quoted =
        |l: &str| l.contains(&format!("\"{needle}\"")) || l.contains(&format!("'{needle}'"));
    for pass in [0u8, 1] {
        let hit = lines.iter().enumerate().skip(from).find(|(_, l)| {
            if pass == 0 {
                quoted(l)
            } else {
                l.contains(needle)
            }
        });
        if let Some((i, _)) = hit {
            return i + 1;
        }
    }
    lines
        .iter()
        .position(|l| l.contains(needle))
        .map_or(0, |i| i + 1)
}

/// The 0-based index of the line carrying `[table]`, or the Nth `[[base]]` when the path ends in a
/// numeric segment (which is how `toml_doc` registers an array of tables).
fn table_line(lines: &[&str], table: &str) -> Option<usize> {
    if table.is_empty() {
        return None;
    }
    if let Some((base, idx)) = table.rsplit_once('.') {
        if let Ok(n) = idx.parse::<usize>() {
            let header = format!("[[{base}]]");
            return lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.trim() == header)
                .nth(n)
                .map(|(i, _)| i);
        }
    }
    let header = format!("[{table}]");
    lines.iter().position(|l| l.trim() == header)
}

// ---------------------------------------------------------------------------------------------
// the universes
// ---------------------------------------------------------------------------------------------

/// Every directory at the repo root. DERIVED, because a hard-coded list of top-level directories is
/// the same hand-kept thing this gate exists to refuse.
fn top_level_dirs(cx: &Ctx) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(rd) = std::fs::read_dir(cx.root()) else {
        return out;
    };
    for e in rd.flatten() {
        if e.path().is_dir() {
            out.insert(e.file_name().to_string_lossy().into_owned());
        }
    }
    out
}

/// The kind universe and the declared census, both read out of `qa/construction.toml`.
fn kind_universe(cx: &Ctx) -> Result<(Vec<String>, BTreeMap<String, i64>), String> {
    let text = cx.read(CONFIG_REL).map_err(|e| {
        format!(
            "{CONFIG_REL} is unreadable ({e}) — `[{KIND_TABLE}]` IS the kind vocabulary, so without \
             it every kind name in the tree resolves to nothing and this gate would report the \
             whole file"
        )
    })?;
    let doc = toml_doc::parse_str(&text).map_err(|e| {
        format!("{CONFIG_REL} does not parse ({e}) — a half-read config is not read")
    })?;
    let kinds: Vec<String> = doc
        .table(KIND_TABLE)
        .map(|t| t.keys().to_vec())
        .unwrap_or_default();
    if kinds.is_empty() {
        return Err(format!(
            "{CONFIG_REL} carries no `[{KIND_TABLE}]` table — the key was renamed or the file \
             changed shape, which reads as zero kinds and therefore as every kind name phantom"
        ));
    }
    let mut census = BTreeMap::new();
    if let Some(t) = doc.table(CENSUS_TABLE) {
        for k in t.keys() {
            if let Some(n) = t.int_of(k) {
                census.insert(k.clone(), n);
            }
        }
    }
    Ok((kinds, census))
}

// ---------------------------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------------------------

/// Every covered file, DERIVED by walking `qa/` for `.toml` and `xtask/src/` for `.rs`. A hand-kept
/// list of config files is how a config file stops being checked, and a hand-kept list of GATE
/// files is how a scan root stops being checked.
///
/// The `qa/` half comes FIRST and the order is load-bearing: the self-test's stale-declaration plant
/// appends a `#`-spelled declaration to `files.first()`, which has to be a TOML.
fn covered(cx: &Ctx) -> Result<Vec<(String, String)>, String> {
    let qa = cx
        .walk(&WalkSpec::new([QA_ROOT]).ext(QA_EXT))
        .map_err(|e| format!("the `{QA_ROOT}` walk failed: {e}"))?;
    let rust = cx
        .walk(&WalkSpec::new([XTASK_ROOT]).ext(XTASK_EXT))
        .map_err(|e| format!("the `{XTASK_ROOT}` walk failed: {e}"))?;
    Ok(qa
        .into_iter()
        .chain(rust)
        .map(|f| (f.rel_str(), f.text))
        .collect())
}

/// Is this covered file read as Rust rather than as TOML?
fn is_rust(rel: &str) -> bool {
    rel.ends_with(".rs")
}

/// Every name and every declaration one covered file carries.
fn scan(rel: &str, text: &str, tops: &BTreeSet<String>) -> (Vec<Name>, Vec<(usize, Decl)>) {
    if is_rust(rel) {
        return scan_rust(rel, text, tops);
    }
    let mut names = Vec::new();
    let mut decls = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        if let Some(d) = parse_decl(raw.trim()) {
            decls.push((idx + 1, d));
        }
    }

    let Ok(doc) = toml_doc::parse_str(text) else {
        // A FILE THIS GATE CANNOT PARSE YIELDS NO NAMES AND SAYS SO THROUGH THE FLOOR, never
        // through silence: ten unparseable files is a scan set of zero, which is exactly what
        // [`ROW_FLOOR`] refuses.
        return (names, decls);
    };

    for (table, t) in doc.tables() {
        for key in t.keys() {
            let site = if table.is_empty() {
                key.clone()
            } else {
                format!("[{table}] {key}")
            };
            let mut push = |value: &str, in_array: bool| {
                if let Some(class) = classify(rel, key, value, tops) {
                    names.push(Name {
                        line: line_of(text, table, value),
                        text: value.to_string(),
                        file: rel.to_string(),
                        site: site.clone(),
                        class,
                        in_array,
                    });
                }
            };
            match t.get(key) {
                Some(Value::Str(s)) => push(s, false),
                Some(Value::Array(items)) => {
                    for v in items.iter().filter_map(Value::as_str) {
                        push(v, true);
                    }
                }
                _ => {}
            }
        }
    }

    // THE TWO TABLES WHOSE KEYS ARE NAMES. A key is not a value, so the loop above cannot see them,
    // and both are exactly the kind of roster this gate exists for: the census key that names a kind
    // nothing defines, and the codec key that names a plane crate that was folded away.
    if rel == CONFIG_REL {
        if let Some(t) = doc.table(CENSUS_TABLE) {
            for key in t.keys() {
                names.push(Name {
                    text: key.clone(),
                    file: rel.to_string(),
                    line: line_of(text, CENSUS_TABLE, key),
                    site: format!("[{CENSUS_TABLE}] {key}"),
                    class: Class::CensusKind(t.int_of(key).unwrap_or(-1)),
                    in_array: false,
                });
            }
        }
        if let Some(t) = doc.table(CODEC_TABLE) {
            for key in t.keys() {
                names.push(Name {
                    text: key.clone(),
                    file: rel.to_string(),
                    line: line_of(text, CODEC_TABLE, key),
                    site: format!("[{CODEC_TABLE}] <key>"),
                    class: Class::Crate,
                    in_array: false,
                });
                for v in string_list(t, key) {
                    names.push(Name {
                        line: line_of(text, CODEC_TABLE, &v),
                        text: v,
                        file: rel.to_string(),
                        site: format!("[{CODEC_TABLE}] {key}"),
                        class: Class::Crate,
                        in_array: true,
                    });
                }
            }
        }
    }

    (names, decls)
}

/// `# qa-names: name -- file -- reason`. A line that carries the prefix and does not have this shape
/// is NOT silently skipped: it comes back with the empty fields it parsed to, so the file and reason
/// rules report it.
fn parse_decl(trimmed: &str) -> Option<Decl> {
    // ONE DECLARATION, TWO COMMENT SPELLINGS. A `.toml` writes `#` and a `.rs` writes `//`; the
    // three fields, the separator and all three liveness rules are the same either way, because an
    // exemption that means something different in Rust is a second mechanism to forget about.
    let rest = trimmed
        .strip_prefix(DECL)
        .or_else(|| trimmed.strip_prefix(DECL_RS))?
        .trim();
    let mut parts = rest.splitn(3, SEP);
    Some(Decl {
        name: parts.next().unwrap_or_default().trim().to_string(),
        file: parts.next().unwrap_or_default().trim().to_string(),
        reason: parts.next().unwrap_or_default().trim().to_string(),
    })
}

// ---------------------------------------------------------------------------------------------
// the SECOND covered root: the Rust the gates are written in
// ---------------------------------------------------------------------------------------------

/// The name of the `const` or `static` a line opens, or `None` if it opens neither.
///
/// Hand-parsed rather than matched, because this crate has no regex dependency and
/// `segregation:xtask-dep-closure` is the reason it never will.
fn const_name(code: &str) -> Option<String> {
    let mut s = code.trim_start();
    if let Some(rest) = s.strip_prefix("pub") {
        // `pub`, `pub(crate)`, `pub(super)`, `pub(in path)` — and never `public_thing`.
        let rest = if rest.starts_with('(') {
            rest.split_once(')').map(|(_, t)| t)?
        } else if rest.starts_with(char::is_whitespace) {
            rest
        } else {
            return None;
        };
        s = rest.trim_start();
    }
    let rest = s
        .strip_prefix("const ")
        .or_else(|| s.strip_prefix("static "))?
        .trim_start();
    let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    // `const fn f(` opens no constant: the token after the identifier decides, and only `:` does.
    rest[name.len()..]
        .trim_start()
        .starts_with(':')
        .then_some(name)
}

/// The string literals one already-blanked line carries, as `(char offset, text)`.
///
/// [`crate::scan::blank_code`] keeps every `"` delimiter and blanks the body to spaces without
/// changing the char count, so the blanked copy is a MASK: each pair of `"` in it marks a literal,
/// and the same char range of the unblanked line is that literal's text. Reusing the house lexer
/// rather than writing a second one is the point — it is the only thing in this crate that knows
/// `r#"…"#` from `"…"` from `'{'`, and a second copy would be the first to get one of them wrong.
fn literals_via_mask(raw: &[char], blanked: &[char]) -> Vec<String> {
    let mut out = Vec::new();
    let mut open: Option<usize> = None;
    for (i, c) in blanked.iter().enumerate() {
        if *c != '"' {
            continue;
        }
        match open.take() {
            None => open = Some(i),
            Some(start) if i > start + 1 => out.push(raw[start + 1..i].iter().collect()),
            Some(_) => {}
        }
    }
    out
}

/// Every path-shaped literal the `const`s and `static`s of one xtask source file name.
///
/// THE SCOPE IS AN ITEM, NOT A FILE, AND THAT IS THE WHOLE DISCRIMINATION. A scan root, a named
/// file list, an allowlist and a floor are written as constants; a path built at a call site or
/// handed to a plant is not. Reading only constants is what keeps the rule from flagging the
/// hundreds of fixture paths a self-test hands to an `Overlay`, without a single per-file
/// exclusion — the technique this gate's own header warns about under the name SHAPE C.
///
/// TWO NARROWINGS, BOTH DELIBERATE AND BOTH STATED SO NEITHER IS MISTAKEN FOR HELD:
///
/// 1. `#[cfg(test)]` module bodies are out, via [`crate::scan::production_lines`]. A constant that
///    cargo compiles only under `--test` is not a scan set the gate reads at run time; `probe`'s
///    `qa/zz-falsification-marker.txt` is the shape, and the gate READS ITS ABSENCE on purpose.
/// 2. Only the PATH class is read. A bare `busbar-foo` literal in Rust could be a crate, a feature,
///    a needle or a word, and no key says which — where a `qa/*.toml` has a key that does. So the
///    dead KIND names still spelled in `construction/rules2.rs` (LEDGER G22) are NOT covered by
///    this and are not claimed to be.
fn scan_rust(rel: &str, text: &str, tops: &BTreeSet<String>) -> (Vec<Name>, Vec<(usize, Decl)>) {
    let mut names = Vec::new();
    let mut decls = Vec::new();

    // ONE PASS, AND IT IS A BUDGET DECISION AS MUCH AS A CORRECTNESS ONE. `xtask/src` is 98_715
    // lines against `qa/*.toml`'s 13_506, so this reader is seven-eighths of everything this gate
    // looks at and every self-test case pays for it three times (baseline, planted, inert). The
    // first shape called `scan::production_lines` for the `#[cfg(test)]` line set and then lexed
    // the file again for the literals — three full lexes per file, which took the self-test to
    // 10_050 work units against a budget of 9_000. `gates::mod`'s own budget doctrine is explicit
    // about which way that gets resolved: *"FIXED, NOT RE-BASELINED"*. So the test-module
    // bookkeeping is folded in here and the file is lexed ONCE.
    //
    // THE LEXER IS `blank_code` AND **NOT** `strip_comment_line`, AND THAT IS NOT A PREFERENCE.
    // `strip_comment_line` carries no multi-line literal state, so the first continued string in a
    // file (`"… \` at end of line) leaves it believing it is outside a literal for the remainder,
    // and the next `/*` or `*/` it then meets INSIDE one flips it into a phantom block comment that
    // eats the rest of the file. Measured, not supposed: reading this very file through it returned
    // an EMPTY line for `const PLANTED_PATH` and the fragment `src";` for `const PLANTED_GLOB`,
    // whose value ends `*/` — a block-comment close. Two of this gate's own dead names were
    // invisible to this gate for exactly that reason, and the defect is upstream in
    // `scan::production_lines`, which every gate that calls it inherits.
    let mut lex = crate::scan::LexState::default();
    let mut item: Option<(String, i32)> = None;
    let mut depth: i32 = 0;
    let mut brace: i32 = 0;
    let mut pending_test_attr = false;
    let mut test_mod_depth: Option<i32> = None;

    for (idx, raw) in text.lines().enumerate() {
        let no = idx + 1;
        if let Some(d) = parse_decl(raw.trim()) {
            decls.push((no, d));
        }

        // THE FAST PATH, AND WHY IT IS SAFE. `blank_code` can only change what it returns, or carry
        // state to the next line, when the line holds a quote, an apostrophe or a slash. A line
        // with none of the three, read with no literal or comment already open, blanks to itself —
        // so it is used as-is and neither the allocation nor the walk is paid. Roughly half of a
        // Rust file is such a line.
        let neutral = lex == crate::scan::LexState::default()
            && !raw.bytes().any(|b| b == b'"' || b == b'\'' || b == b'/');
        let owned;
        let blanked: &str = if neutral {
            raw
        } else {
            owned = crate::scan::blank_code(raw, &mut lex);
            &owned
        };
        let trimmed = blanked.trim();

        // `#[cfg(test)]` MODULES ARE OUT, tracked over the blanked copy exactly as
        // `scan::production_lines` tracks it over its own — same attribute, same `mod … {` shape,
        // same "the opening and the closing line are themselves test lines" arithmetic. A constant
        // cargo compiles only under `--test` is not a scan set any gate reads at run time; `probe`'s
        // `qa/zz-falsification-marker.txt` is the shape, and that gate READS ITS ABSENCE on purpose.
        let this_line_is_test = test_mod_depth.is_some();
        if !this_line_is_test && trimmed.contains("#[cfg(test)]") {
            pending_test_attr = true;
        } else if !this_line_is_test
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.contains("mod ")
        {
            pending_test_attr = false;
        }
        if !this_line_is_test
            && pending_test_attr
            && trimmed.contains("mod ")
            && blanked.contains('{')
        {
            test_mod_depth = Some(brace);
            pending_test_attr = false;
        }

        if item.is_none() {
            if let Some(name) = const_name(raw) {
                item = Some((name, depth));
            }
        }

        let was_test = test_mod_depth.is_some();
        if let Some((konst, _)) = &item {
            // A constant whose NAME says FRAGMENT, PATTERN, SYMBOL or NEEDLE holds a thing matched
            // against names, never a name — the same veto the TOML half applies by key.
            if !was_test
                && !this_line_is_test
                && raw.contains('/')
                && !has_token(&konst.to_ascii_lowercase(), FRAGMENT_TOKENS)
            {
                let raw_chars: Vec<char> = raw.chars().collect();
                let mask: Vec<char> = blanked.chars().collect();
                for value in literals_via_mask(&raw_chars, &mask) {
                    if !is_path_shaped(&value, tops) {
                        continue;
                    }
                    names.push(Name {
                        text: value,
                        file: rel.to_string(),
                        line: no,
                        site: format!("const {konst}"),
                        class: Class::Path,
                        // A Rust array item cannot take a planted sibling without the file ceasing
                        // to compile, and this gate's plants are read as text by a gate that is
                        // itself compiled from it. The Rust arm plants a WHOLE FILE instead.
                        in_array: false,
                    });
                }
            }
        }

        // ONE WALK FOR ALL THREE PAIRS. `scan::delta` is two passes per pair, which is six over a
        // line this gate already touches four times.
        let (mut opens, mut closes, mut braces_moved, mut semi) = (0i32, 0i32, false, false);
        for b in blanked.bytes() {
            match b {
                b'(' | b'[' => opens += 1,
                b')' | b']' => closes += 1,
                b'{' => {
                    opens += 1;
                    brace += 1;
                    braces_moved = true;
                }
                b'}' => {
                    closes += 1;
                    brace -= 1;
                    braces_moved = true;
                }
                b';' => semi = true,
                _ => {}
            }
        }
        depth += opens - closes;

        if let Some(d) = test_mod_depth {
            if brace <= d && braces_moved {
                test_mod_depth = None;
            }
        }

        if let Some((_, start)) = &item {
            if depth <= *start && semi {
                item = None;
            }
        }
    }

    (names, decls)
}

// ---------------------------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------------------------

pub struct QaNamesGate;

/// The rows every rule below [`ROW_UNIVERSE`] answers on when there was nothing to read.
fn unproven(why: &str) -> Verdict {
    let detail = format!("unproven: a universe did not load — {why}");
    let mut rows = vec![Row::fail(ROW_UNIVERSE, "a universe did not load", why)];
    for id in [
        ROW_FLOOR,
        ROW_XTASK_FLOOR,
        ROW_KIND,
        ROW_CRATE,
        ROW_PATH,
        ROW_GLOB,
        ROW_DECL_LIVE,
        ROW_DECL_FILE,
        ROW_DECL_REASON,
    ] {
        rows.push(Row::fail(id, "no name was checked", detail.clone()));
    }
    Verdict::of(rows)
}

fn row(
    id: &str,
    ok: bool,
    title_ok: &str,
    detail_ok: String,
    title_bad: &str,
    detail_bad: String,
) -> Row {
    if ok {
        Row::pass(id, title_ok, detail_ok)
    } else {
        Row::fail(id, title_bad, detail_bad)
    }
}

impl Gate for QaNamesGate {
    fn name(&self) -> &'static str {
        "qa-names"
    }

    fn owed(&self) -> Vec<String> {
        [
            ROW_UNIVERSE,
            ROW_FLOOR,
            ROW_XTASK_FLOOR,
            ROW_KIND,
            ROW_CRATE,
            ROW_PATH,
            ROW_GLOB,
            ROW_DECL_LIVE,
            ROW_DECL_FILE,
            ROW_DECL_REASON,
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let packages = match crate::gates::package_selectors::universe(cx) {
            Ok(u) => u,
            Err(why) => return unproven(&why),
        };
        if packages.len() < UNIVERSE_FLOOR {
            return unproven(&format!(
                "only {} package name(s) resolved from the workspace manifests and the lockfile \
                 (floor {UNIVERSE_FLOOR}). A universe that collapsed makes every live crate name in \
                 qa/ look dead, which is a defect in this gate reported as a defect in the tree.",
                packages.len()
            ));
        }
        let (kinds, census) = match kind_universe(cx) {
            Ok(k) => k,
            Err(why) => return unproven(&why),
        };
        if kinds.len() < KIND_FLOOR {
            return unproven(&format!(
                "`[{KIND_TABLE}]` in {CONFIG_REL} names only {} kind(s) (floor {KIND_FLOOR}). \
                 DECISIONS #3 locks seven plugin kinds; a kind table that lost rows makes every \
                 kind name in the file look phantom.",
                kinds.len()
            ));
        }
        let files = match covered(cx) {
            Ok(f) => f,
            Err(why) => return unproven(&why),
        };

        let tops = top_level_dirs(cx);
        let mut names: Vec<Name> = Vec::new();
        let mut decls: Vec<(String, usize, Decl)> = Vec::new();
        for (rel, text) in &files {
            let (n, d) = scan(rel, text, &tops);
            names.extend(n);
            decls.extend(d.into_iter().map(|(line, decl)| (rel.clone(), line, decl)));
        }
        let covered_paths: BTreeSet<&str> = files.iter().map(|(r, _)| r.as_str()).collect();
        let declared: BTreeSet<&str> = decls.iter().map(|(_, _, d)| d.name.as_str()).collect();
        let kindset: BTreeSet<&str> = kinds.iter().map(String::as_str).collect();

        let mut rows = vec![Row::pass(
            ROW_UNIVERSE,
            "the package universe and the kind table both loaded",
            format!(
                "{} resolvable package name(s) (floor {UNIVERSE_FLOOR}); {} kind(s) in \
                 `[{KIND_TABLE}]` (floor {KIND_FLOOR}); {} census row(s)",
                packages.len(),
                kinds.len(),
                census.len()
            ),
        )];

        rows.push(row(
            ROW_FLOOR,
            names.len() >= NAME_FLOOR,
            "enough names were discovered for the check to mean something",
            format!(
                "{} name(s) across {} covered file(s) (floor {NAME_FLOOR})",
                names.len(),
                files.len()
            ),
            "the name scan collapsed below its discovery floor",
            format!(
                "only {} name(s) were found across {} covered file(s) under `{QA_ROOT}/*.{QA_EXT}` \
                 (floor {NAME_FLOOR}). An empty scan set is the one state in which 'every name \
                 resolves' is true and means nothing.",
                names.len(),
                files.len()
            ),
        ));

        // THE RUST HALF GETS ITS OWN DENOMINATOR, because the TOML half clears the combined floor
        // on its own and would mask a Rust reader that had stopped reading.
        let rust_files = files.iter().filter(|(r, _)| is_rust(r)).count();
        let rust_names = names.iter().filter(|n| is_rust(&n.file)).count();
        rows.push(row(
            ROW_XTASK_FLOOR,
            rust_names >= XTASK_NAME_FLOOR,
            "the gates' own constants were read, above their floor",
            format!(
                "{rust_names} path(s) named by `const`s across {rust_files} file(s) under \
                 `{XTASK_ROOT}/**.{XTASK_EXT}` (floor {XTASK_NAME_FLOOR})"
            ),
            "the scan of the gates' own constants collapsed",
            format!(
                "only {rust_names} path(s) were found in `const`s across {rust_files} file(s) under \
                 `{XTASK_ROOT}/**.{XTASK_EXT}` (floor {XTASK_NAME_FLOOR}). Every scan root this \
                 crate owns is a Rust constant; a reader that stopped matching them reports zero \
                 dead names and a green row, which is the exact failure this gate is named for, \
                 turned on itself.",
            ),
        ));

        // THE FOUR RESOLUTION RULES. A declared name discharges every one of them; the declaration's
        // own validity is rules 7-9, so exactly one row moves per defect.
        let live = |n: &Name| -> bool {
            if declared.contains(n.text.as_str()) {
                return true;
            }
            match n.class {
                Class::Kind => kindset.contains(n.text.as_str()),
                Class::CensusKind(count) => kindset.contains(n.text.as_str()) || count == 0,
                Class::Crate => {
                    if n.is_glob() {
                        packages.iter().any(|p| glob_one(&n.text, p))
                    } else {
                        packages.contains(&n.text)
                    }
                }
                Class::Path => {
                    if n.is_glob() {
                        !glob_dirs(cx, &n.core()).is_empty()
                    } else {
                        cx.exists(n.core())
                    }
                }
            }
        };

        let mut dead_kind = Vec::new();
        let mut dead_crate = Vec::new();
        let mut dead_path = Vec::new();
        let mut dead_glob = Vec::new();
        for n in &names {
            // `[gate.plugin_kinds]`' OWN GLOBS ARE JUDGED AT THE KIND LEVEL, below: the unit there is
            // the kind, not the entry, so a forward-looking second spelling is not a defect while
            // the kind as a whole still finds its crates.
            let kind_level = n.site.starts_with(&format!("[{KIND_TABLE}]")) && n.is_glob();
            if kind_level || live(n) {
                continue;
            }
            match (n.class, n.is_glob()) {
                (Class::Kind, _) | (Class::CensusKind(_), _) => dead_kind.push(n),
                (_, true) => dead_glob.push(n),
                (Class::Crate, false) => dead_crate.push(n),
                (Class::Path, false) => dead_path.push(n),
            }
        }

        // The kind-level reading of `[gate.plugin_kinds]`.
        let kind_globs = kind_glob_counts(cx, &files, &kinds);
        let mut empty_kinds = Vec::new();
        for (kind, (entries, hits)) in &kind_globs {
            if *hits == 0
                && census.get(kind).copied() != Some(0)
                && !declared.contains(kind.as_str())
            {
                empty_kinds.push(format!(
                    "[{KIND_TABLE}] {kind} = {entries:?} matches nothing (census declares {})",
                    census
                        .get(kind)
                        .map_or_else(|| "no population".to_string(), |n| n.to_string())
                ));
            }
        }

        rows.push(row(
            ROW_KIND,
            dead_kind.is_empty(),
            "every kind name is a key of the kind table",
            format!(
                "{} kind name(s) against {} key(s) in `[{KIND_TABLE}]`",
                names
                    .iter()
                    .filter(|n| matches!(n.class, Class::Kind | Class::CensusKind(_)))
                    .count(),
                kinds.len()
            ),
            "a config table names a KIND that does not exist",
            format!(
                "{} — a kind with no key in `[{KIND_TABLE}]` resolves to an EMPTY GLOB LIST, so the \
                 rule that names it scans nothing and PASSES. That is how `pure_auth`/`egress_auth` \
                 left the whole auth kind out of `source-denylist` and `forbid-unsafe` at once. \
                 Spell the live key, or write a `{DECL} <name>{SEP}<file>{SEP}<reason>` line beside \
                 it. A `[{CENSUS_TABLE}]` row may instead declare `= 0`, which says the kind has no \
                 crate yet — but a row declaring a POPULATION for a kind with no glob claims crates \
                 nothing can find.",
                cites(&dead_kind)
            ),
        ));

        rows.push(row(
            ROW_CRATE,
            dead_crate.is_empty(),
            "every crate name is a package this workspace resolves",
            format!(
                "{} crate name(s) against {} resolvable package(s)",
                names.iter().filter(|n| n.class == Class::Crate).count(),
                packages.len()
            ),
            "a config table names a CRATE this workspace does not have",
            format!(
                "{} — a rule scoped to a crate that is not here is a rule scoped to nothing, and it \
                 reports clean. Repoint the name, or write a `{DECL} <name>{SEP}<file>{SEP}<reason>` \
                 line beside it.",
                cites(&dead_crate)
            ),
        ));

        rows.push(row(
            ROW_PATH,
            dead_path.is_empty(),
            "every path a config table or a gate constant names exists",
            format!(
                "{} path(s) checked",
                names
                    .iter()
                    .filter(|n| n.class == Class::Path && !n.is_glob())
                    .count()
            ),
            "a config table or a gate CONSTANT names a PATH that is not on this tree",
            format!(
                "{} — a scan root, a reviewed site or a ratchet entry that names a path the tree no \
                 longer has scans zero files and passes. Repoint it, strike it, or write a `{DECL} \
                 <name>{SEP}<file>{SEP}<reason>` line beside it (`{DECL_RS}` in a `.rs`). A \
                 REPOINT is a fix; a STRIKE is a claim that the rule is obsolete and owes the same \
                 proof as any delete.",
                cites(&dead_path)
            ),
        ));

        let mut glob_detail: Vec<String> = dead_glob.iter().map(|n| n.cite()).collect();
        glob_detail.extend(empty_kinds.iter().cloned());
        rows.push(row(
            ROW_GLOB,
            dead_glob.is_empty() && empty_kinds.is_empty(),
            "every glob matches at least one thing",
            format!(
                "{} glob(s) plus {} kind(s) read as a whole",
                names.iter().filter(|n| n.is_glob()).count(),
                kind_globs.len()
            ),
            "a config table carries a GLOB that matches nothing",
            format!(
                "{} — a glob matching zero is a scan over zero, and a ban over zero passes. A \
                 legitimate zero exists (a kind with no crate yet) and it must be DECLARED: a \
                 `[{CENSUS_TABLE}]` row of `0` for a kind, or a `{DECL} <name>{SEP}<file>{SEP}\
                 <reason>` line for anything else.",
                glob_detail.join(" | ")
            ),
        ));

        let mut unused = Vec::new();
        let mut needless = Vec::new();
        let mut bad_file = Vec::new();
        let mut thin = Vec::new();
        let written: BTreeSet<&str> = names.iter().map(|n| n.text.as_str()).collect();
        for (rel, line, d) in &decls {
            if !written.contains(d.name.as_str()) {
                unused.push(format!("{rel}:{line} `{}`", d.name));
            } else if names
                .iter()
                .filter(|n| n.text == d.name)
                .all(|n| resolves_without_declaration(cx, n, &packages, &kindset))
            {
                needless.push(format!("{rel}:{line} `{}`", d.name));
            }
            if !covered_paths.contains(d.file.as_str()) {
                bad_file.push(format!("{rel}:{line} `{}` names `{}`", d.name, d.file));
            }
            if d.reason.chars().count() < MIN_REASON {
                thin.push(format!(
                    "{rel}:{line} `{}` ({} char reason)",
                    d.name,
                    d.reason.chars().count()
                ));
            }
        }

        let mut live_detail = String::new();
        if !unused.is_empty() {
            live_detail.push_str(&format!(
                "no covered file writes {} — a stale exemption outlives the name it excused and \
                 then silently excuses the next name to take the spelling. ",
                unused.join(", ")
            ));
        }
        if !needless.is_empty() {
            live_detail.push_str(&format!(
                "{} resolves fine now and needs no exemption; leaving one hides the day it stops \
                 resolving again.",
                needless.join(", ")
            ));
        }
        rows.push(row(
            ROW_DECL_LIVE,
            unused.is_empty() && needless.is_empty(),
            "every declared exception names a name that is still there and still unresolvable",
            format!("{} declaration(s)", decls.len()),
            "a declared exception names a name that is not there to excuse",
            live_detail.trim_end().to_string(),
        ));

        rows.push(row(
            ROW_DECL_FILE,
            bad_file.is_empty(),
            "every declared exception names a file this gate covers",
            format!("{} covered file(s)", files.len()),
            "a declared exception names a file this gate does not cover",
            format!(
                "{} — a claim pointing at a path that was renamed away is a claim nobody can check. \
                 The file must be one of the covered files: `{QA_ROOT}/*.{QA_EXT}` or \
                 `{XTASK_ROOT}/**.{XTASK_EXT}`.",
                bad_file.join(" | ")
            ),
        ));

        rows.push(row(
            ROW_DECL_REASON,
            thin.is_empty(),
            "every declared exception carries a reason",
            format!(
                "{} declaration(s), minimum {MIN_REASON} characters",
                decls.len()
            ),
            "a declared exception carries no reason worth the name",
            format!(
                "{} — minimum {MIN_REASON}. An exemption without a reason becomes permanent by \
                 accident.",
                thin.join(" | ")
            ),
        ));

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        // THE GREEN ARM IS NARROWED, AND THE NARROWING IS THE HONEST FORM. Three rows carry real
        // standing debt on this tree — the dead names this gate was written to find and which are
        // another change's to drain — and asking "is the WHOLE gate green" would hold every case in
        // this file hostage to that debt, which is how a self-test ends up deleted rather than
        // fixed. The rows read here are the ones that ARE clean, and each red row is separately
        // proven able to name a planted offender below.
        report.push(prove_rows_green(
            cx,
            self,
            "the rules with no standing debt are green on this tree",
            &[
                ROW_UNIVERSE,
                ROW_FLOOR,
                ROW_KIND,
                ROW_DECL_LIVE,
                ROW_DECL_FILE,
                ROW_DECL_REASON,
            ],
            Overlay::new(),
        ));
        // THE TWO NEGATIVE CONTROLS FOR THE RUST ARM. `prove_rows_green` takes a baseline and the
        // planted run, so a row that was already green stays a pass on its own merit and a row that
        // was already RED cannot be scored as this case's green.
        report.push(prove_rows_green(
            cx,
            self,
            "a gate constant naming a path that IS on this tree is not flagged",
            &[ROW_PATH, ROW_GLOB, ROW_XTASK_FLOOR],
            planted_rs_live_only(),
        ));
        report.push(prove_rows_green(
            cx,
            self,
            "a dead path in a comment or a fn body is not a constant and is not flagged",
            &[ROW_PATH, ROW_GLOB],
            planted_rs_not_a_const(),
        ));
        for plant in plants(cx) {
            report.push(plant.case(cx, self));
        }
        report
    }
}

/// `fnmatch` over ONE segment-free token — the shape a crate-name glob (`busbar-unit-*`) has. `*`
/// matches anything, `?` one character; nothing else is special.
fn glob_one(pattern: &str, candidate: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let c: Vec<char> = candidate.chars().collect();
    let (mut pi, mut ci, mut star, mut mark) = (0usize, 0usize, usize::MAX, 0usize);
    while ci < c.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == c[ci]) {
            pi += 1;
            ci += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ci;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ci = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Would this name resolve if no declaration existed? The declaration-liveness rule needs the
/// unexcused answer, or every declaration would look needed forever.
fn resolves_without_declaration(
    cx: &Ctx,
    n: &Name,
    packages: &BTreeSet<String>,
    kindset: &BTreeSet<&str>,
) -> bool {
    match n.class {
        Class::Kind => kindset.contains(n.text.as_str()),
        Class::CensusKind(count) => kindset.contains(n.text.as_str()) || count == 0,
        Class::Crate if n.is_glob() => packages.iter().any(|p| glob_one(&n.text, p)),
        Class::Crate => packages.contains(&n.text),
        Class::Path if n.is_glob() => !glob_dirs(cx, &n.core()).is_empty(),
        Class::Path => cx.exists(n.core()),
    }
}

/// Per kind: the entries `[gate.plugin_kinds]` gives it, and how many things they match between
/// them. Read straight off the covered `qa/construction.toml` text so a self-test plant into it is
/// seen, exactly as every other name is.
fn kind_glob_counts(
    cx: &Ctx,
    files: &[(String, String)],
    kinds: &[String],
) -> BTreeMap<String, (Vec<String>, usize)> {
    let mut out = BTreeMap::new();
    let Some((_, text)) = files.iter().find(|(r, _)| r == CONFIG_REL) else {
        return out;
    };
    let Ok(doc) = toml_doc::parse_str(text) else {
        return out;
    };
    let Some(t) = doc.table(KIND_TABLE) else {
        return out;
    };
    for kind in kinds {
        let entries = string_list(t, kind);
        let hits = entries
            .iter()
            .map(|g| glob_dirs(cx, g.trim_end_matches('/')).len())
            .sum();
        out.insert(kind.clone(), (entries, hits));
    }
    out
}

fn cites(v: &[&Name]) -> String {
    v.iter().map(|n| n.cite()).collect::<Vec<_>>().join(" | ")
}

// ---------------------------------------------------------------------------------------------
// the plants
// ---------------------------------------------------------------------------------------------

struct Plant {
    label: &'static str,
    rule: &'static str,
    naming: Vec<String>,
    overlay: Option<Overlay>,
}

impl Plant {
    fn case<'a>(self, cx: &'a Ctx, gate: &'a dyn Gate) -> crate::gates::CasePlan<'a> {
        let Some(overlay) = self.overlay else {
            // NOTHING TO PLANT is a visible, counted case — never a silent green.
            return Case {
                name: self.label.to_string(),
                covers: vec![self.rule.to_string()],
                expected: Expect::Red {
                    naming: self.naming.clone(),
                },
                got: Expect::Skipped,
            }
            .into();
        };
        let naming: Vec<&str> = self.naming.iter().map(String::as_str).collect();
        prove_rows_red(cx, gate, self.label, &[self.rule], overlay, &naming)
    }
}

/// The names planted into a real covered file — deliberately ones no table, manifest, lockfile or
/// directory in this tree carries.
///
/// THREE OF THESE ARE PATH-SHAPED AND THEREFORE NAMES THIS GATE READS OUT OF ITS OWN SOURCE, which
/// is the correct outcome and not an embarrassment: the Rust arm makes no exception for the file it
/// is written in. They are declared rather than renamed, because "a path this tree does not have"
/// is the entire specification of a plant and a spelling that resolved would make every case
/// vacuous.
const PLANTED_KIND: &str = "busbar_selftest_no_such_kind";
const PLANTED_CRATE: &str = "busbar-selftest-no-such-package";
/// THE PLANTED PATH AND THE PLANTED GLOB, IN HALVES, AND THE REASON IS THE RULE ITSELF.
///
/// Writing either of these whole as a `const` makes it a name this gate reads OUT OF ITS OWN
/// SOURCE — the Rust arm makes no exception for the file it is written in — and the only way to
/// clear the row it would then redden is to DECLARE it. A declaration excuses a name GLOBALLY, by
/// spelling, which would leave both plants unable to redden anything at all: the gate would have
/// been told to ignore the very string the case plants. **A plant its own gate has been instructed
/// to overlook proves nothing, and it proves it in green.** That is `prove_red`'s `Inert` verdict
/// arriving through the front door, and the Rust arm found it in this file on its first run.
///
/// So the halves. Neither is path-shaped on its own — `crates` carries no `/`, and
/// `busbar-selftest-…/src` has a first segment that is no directory at the repo root — so neither
/// is a name, and the whole is assembled where it is used.
const PLANTED_UNDER: &str = "crates";
const PLANTED_PATH_TAIL: &str = "busbar-selftest-no-such-crate/src/lib.rs";
const PLANTED_GLOB_TAIL: &str = "busbar-selftest-no-such-family-*/src";

/// A path no directory in this tree carries, assembled rather than spelled. See [`PLANTED_UNDER`].
fn planted_path() -> String {
    format!("{PLANTED_UNDER}/{PLANTED_PATH_TAIL}")
}

/// A glob no directory in this tree matches, assembled rather than spelled. See [`PLANTED_UNDER`].
fn planted_glob() -> String {
    format!("{PLANTED_UNDER}/{PLANTED_GLOB_TAIL}")
}
const PLANTED_NEVER: &str = "busbar-selftest-never-written-down";
/// A path this gate does not cover, for the stale-file plant.
// qa-names: qa/deleted-by-this-fixture.toml -- xtask/src/gates/qa_names.rs -- the stale-declaration plant names a covered file that is not there on purpose; the rule under proof is that the FILE field must resolve
const PLANTED_GONE_FILE: &str = "qa/deleted-by-this-fixture.toml";
/// A reason long enough to satisfy [`MIN_REASON`], so a plant aimed at one rule cannot redden two.
const PLANTED_REASON: &str = "planted by this gate's own self-test, which is a reason of its own";

/// Where the Rust arm's plants live: under the covered Rust root, reached by no `mod`, and present
/// only in an [`Overlay`]. It is not path-shaped as written (`xtask` is a directory at the repo
/// root, so it WOULD be — and the file it names is not there, which is the point), so it carries
/// its own declaration below.
// qa-names: xtask/src/zzz_qa_names_planted.rs -- xtask/src/gates/qa_names.rs -- the Rust arm's overlay-only plant file; it exists for the length of one verdict and a spelling that resolved would leave a plant behind in the tree
const PLANTED_RS_FILE: &str = "xtask/src/zzz_qa_names_planted.rs";

/// The two dead subjects the Rust arm plants, in halves, for the reason [`PLANTED_UNDER`] gives.
const PLANTED_RS_ROOT_TAIL: &str = "busbar-selftest-no-such-rust-root/src";
const PLANTED_RS_GLOB_TAIL: &str = "busbar-selftest-no-such-rust-family-*/src";

/// THE NEGATIVE CONTROLS, SPELLED WHOLE ON PURPOSE. These two resolve, so writing them as ordinary
/// constants is exactly what the rule says is fine — and this file being GREEN with them in it is
/// the first half of the control, before any case runs at all.
const LIVE_ROOT: &str = "crates/busbar-kernel/src/lib.rs";
const LIVE_FAMILY: &str = "crates/busbar-plane-*/src";

fn planted_rs_root() -> String {
    format!("{PLANTED_UNDER}/{PLANTED_RS_ROOT_TAIL}")
}

fn planted_rs_glob() -> String {
    format!("{PLANTED_UNDER}/{PLANTED_RS_GLOB_TAIL}")
}

/// One overlay carrying one planted file under the covered Rust root.
fn planted_rs(body: String) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(PLANTED_RS_FILE, body);
    ov
}

/// THE FIRST NEGATIVE CONTROL: a planted constant naming a path that IS on this tree, and a planted
/// glob that DOES match. Without it, "every path a constant names is dead" would pass the red arm
/// and no repair could ever satisfy the rule.
fn planted_rs_live_only() -> Overlay {
    planted_rs(format!(
        "//! Planted by qa-names' own self-test. No `mod` reaches this file.\n\
         const LIVE_ROOT: &str = \"{LIVE_ROOT}\";\n\
         const LIVE_FAMILY: &str = \"{LIVE_FAMILY}\";\n"
    ))
}

/// THE SECOND NEGATIVE CONTROL: the identical dead path in the two positions that are NOT a
/// constant — a comment and a `fn` body. The scope of this rule is the ITEM, and that is the only
/// reason it can read 130 gate sources without drowning in the fixture paths their self-tests hand
/// to an `Overlay`. If either of these reddens a row, the rule has become a text grep.
fn planted_rs_not_a_const() -> Overlay {
    planted_rs(format!(
        "//! Planted by qa-names' own self-test. No `mod` reaches this file.\n\
         // {dead} — a dead path in a comment is prose, exactly as it is in a `qa/*.toml`.\n\
         fn planted() -> &'static str {{\n    \"{dead}\"\n}}\n\
         const LIVE_ROOT: &str = \"{LIVE_ROOT}\";\n",
        dead = planted_rs_root()
    ))
}

/// Insert `phantom` as a SIBLING of an existing array item, on the line that item is written on.
/// Purely additive: nothing the file already says stops being true, so a plant aimed at one rule
/// cannot move another by taking a name away.
fn plant_beside(text: &str, at: &Name, phantom: &str) -> Option<String> {
    let idx = at.line.checked_sub(1)?;
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let line = lines.get(idx)?;
    for (open, close) in [('"', '"'), ('\'', '\'')] {
        let needle = format!("{open}{}{close}", at.text);
        if let Some(pos) = line.find(&needle) {
            let mut next = line.clone();
            next.replace_range(pos..pos + needle.len(), &format!("{needle}, \"{phantom}\""));
            lines[idx] = next;
            return Some(format!("{}\n", lines.join("\n")));
        }
    }
    None
}

/// The first discovered name a phantom can actually be planted beside: an ARRAY item, in the class
/// asked for, on a line this reader can rewrite. DERIVED from the scan — never a hard-coded table
/// path, because a plant that names a table goes Skipped the day the table moves, and a Skipped
/// case is a rule nobody proved. Candidates are tried IN TURN rather than taken on the first
/// match, so one value whose line the citation could not pin does not cost the whole case.
fn anchor(cx: &Ctx, want: impl Fn(&Name) -> bool) -> Option<(String, String, Name)> {
    let tops = top_level_dirs(cx);
    for (rel, text) in covered(cx).ok()? {
        let (names, _) = scan(&rel, &text, &tops);
        for n in names
            .into_iter()
            .filter(|n| n.in_array && n.line > 0 && want(n))
        {
            if plant_beside(&text, &n, "probe").is_some() {
                return Some((rel, text, n));
            }
        }
    }
    None
}

fn beside(cx: &Ctx, want: impl Fn(&Name) -> bool, phantom: &str) -> Option<Overlay> {
    let (rel, text, at) = anchor(cx, want)?;
    let planted = plant_beside(&text, &at, phantom)?;
    let mut ov = Overlay::new();
    ov.set(&rel, planted);
    Some(ov)
}

/// A phantom name AND a declaration for it, so a plant aimed at the declaration rules leaves the
/// four resolution rules exactly as it found them.
fn beside_declared(
    cx: &Ctx,
    want: impl Fn(&Name) -> bool,
    phantom: &str,
    file_field: &str,
    reason: &str,
) -> Option<Overlay> {
    let (rel, text, at) = anchor(cx, want)?;
    let planted = plant_beside(&text, &at, phantom)?;
    let mut ov = Overlay::new();
    ov.set(
        &rel,
        format!("{planted}\n{DECL} {phantom}{SEP}{file_field}{SEP}{reason}\n"),
    );
    Some(ov)
}

fn plants(cx: &Ctx) -> Vec<Plant> {
    // THE DEFECT THIS GATE IS NAMED FOR, RE-PLANTED, once per universe.
    let kind = beside(cx, |n| n.class == Class::Kind, PLANTED_KIND);
    let krate = beside(cx, |n| n.class == Class::Crate, PLANTED_CRATE);
    let path = beside(
        cx,
        |n| n.class == Class::Path && !n.is_glob(),
        &planted_path(),
    );
    // NOT under `[gate.plugin_kinds]`: that table is judged per KIND, and a kind that still finds
    // its crates is not reddened by one more entry. The kind-level arm is planted separately.
    let glob = beside(
        cx,
        |n| n.class == Class::Path && !n.site.starts_with(&format!("[{KIND_TABLE}]")),
        &planted_glob(),
    );

    // A KIND WHOSE WHOLE GLOB LIST FINDS NOTHING, and whose census row does not declare the zero.
    // This is the arm the three documented zeros (`dialect`, `control`, `egress_auth`) go through,
    // proven from the other side: strike the declaration and the same shape is RED.
    // THE REDEFINITION MUST GO AT THE *END* OF THE TABLE, NOT THE TOP, AND THE DIFFERENCE IS THE
    // WHOLE PLANT.
    //
    // This inserted `<first> = ["<dead glob>"]` at `head + 1` — immediately under the
    // `[gate.plugin_kinds]` header and therefore immediately ABOVE the real `<first> = [...]` list.
    // `toml_doc::Table::insert` is LAST-WINS (`self.values.insert(key, value)` unconditionally), so
    // the genuine list overwrote the planted one on the very next line and the kind kept every glob
    // it had. The plant changed nothing.
    //
    // IT PASSED ANYWAY, FOR TWO YEARS OF NOTHING, BECAUSE `ROW_GLOB` WAS ALREADY RED: the three
    // `[rules.plane-no-money].scope_globs` over `crates/busbar-{mcp,a2a,voice}/src/unit/*` held that
    // row red on the real tree, so `got.contains(p.rule)` was satisfied by the STANDING DEBT rather
    // than by the plant, in both `each_plant_reddens_its_own_row...` and the selftest. Draining
    // those globs on 2026-09-22 took the mask away and the plant failed on its first honest run.
    // That is the same defect this whole gate exists to find, wearing the clothes of a positive
    // control: an instrument reporting a result it did not measure.
    //
    // Appending inside the table instead makes the planted definition the last one, so it wins.
    let empty_kind = covered(cx).ok().and_then(|files| {
        let (_, text) = files.iter().find(|(r, _)| r == CONFIG_REL)?;
        let doc = toml_doc::parse_str(text).ok()?;
        let first = doc.table(KIND_TABLE)?.keys().first()?.clone();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let head = lines
            .iter()
            .position(|l| l.trim() == format!("[{KIND_TABLE}]"))?;
        // The last line still inside this table: up to the next table header, or end of file.
        let tail = lines
            .iter()
            .skip(head + 1)
            .position(|l| l.starts_with('['))
            .map_or(lines.len(), |n| head + 1 + n);
        lines.insert(tail, format!("{first} = [\"{}\"]", planted_glob()));
        let mut ov = Overlay::new();
        ov.set(CONFIG_REL, format!("{}\n", lines.join("\n")));
        Some(ov)
    });

    // A DECLARATION THAT OUTLIVED THE NAME IT EXCUSED. The file field is real and the reason is
    // long, so only the liveness rule can move.
    let unused_decl = covered(cx).ok().and_then(|files| {
        let (rel, text) = files.first()?;
        let mut ov = Overlay::new();
        ov.set(
            rel,
            format!("{text}\n{DECL} {PLANTED_NEVER}{SEP}{rel}{SEP}{PLANTED_REASON}\n"),
        );
        Some(ov)
    });

    // A DECLARATION FOR A NAME THAT RESOLVES PERFECTLY WELL. An exemption nobody needs hides the day
    // it starts being needed.
    let needless_decl = anchor(cx, |n| n.class == Class::Crate).map(|(rel, text, at)| {
        let mut ov = Overlay::new();
        ov.set(
            &rel,
            format!(
                "{text}\n{DECL} {}{SEP}{rel}{SEP}{PLANTED_REASON}\n",
                at.text
            ),
        );
        ov
    });

    // A DECLARATION POINTING AT A FILE THAT IS NOT COVERED, and one WITH A SHRUG FOR A REASON.
    let bad_file_decl = beside_declared(
        cx,
        |n| n.class == Class::Crate,
        PLANTED_CRATE,
        PLANTED_GONE_FILE,
        PLANTED_REASON,
    );
    let thin_decl = anchor(cx, |n| n.class == Class::Crate).and_then(|(rel, text, at)| {
        let planted = plant_beside(&text, &at, PLANTED_CRATE)?;
        let mut ov = Overlay::new();
        ov.set(
            &rel,
            format!("{planted}\n{DECL} {PLANTED_CRATE}{SEP}{rel}{SEP}because\n"),
        );
        Some(ov)
    });

    // THE SCAN THAT MATCHED NOTHING. Every covered file is still THERE and still walked, and the
    // kind table is still readable — so every other rule passes, vacuously, which is exactly what a
    // classifier whose token rule stopped matching reports.
    let empty_scan = covered(cx).ok().and_then(|files| {
        let (_, config) = files.iter().find(|(r, _)| r == CONFIG_REL)?;
        let doc = toml_doc::parse_str(config).ok()?;
        let kinds = doc.table(KIND_TABLE)?.keys().to_vec();
        let mut minimal = format!("[{KIND_TABLE}]\n");
        for k in &kinds {
            minimal.push_str(&format!("{k} = []\n"));
        }
        minimal.push_str(&format!("\n[{CENSUS_TABLE}]\n"));
        for k in &kinds {
            minimal.push_str(&format!("{k} = 0\n"));
        }
        let mut ov = Overlay::new();
        for (rel, _) in &files {
            ov.set(
                rel,
                if rel == CONFIG_REL {
                    minimal.clone()
                } else {
                    String::new()
                },
            );
        }
        Some(ov)
    });

    // ── THE RUST ARM ─────────────────────────────────────────────────────────────────────────
    //
    // Planted as ONE file under the covered Rust root, carrying five constants at once, so the RED
    // arm and its two controls are measured against the same tree in the same run. The file is an
    // orphan module no `mod` reaches, and it exists only in the overlay — cargo never sees it.
    //
    // THE TWO CONTROLS ARE THE POINT. A rule that flagged every path-shaped string in `xtask/src/`
    // would pass the red arm and be useless, so the same planted file also carries:
    //
    //   * `LIVE_ROOT` — a constant naming a path that IS there. Flagging it would mean the rule is
    //     "every path in a const is dead", which no repair could ever satisfy.
    //   * a dead path written in a COMMENT and another written inside a `fn` BODY. Neither is a
    //     constant, and the scope of this rule is the ITEM, not the file — that is the whole reason
    //     it can read 130 gate sources without drowning in self-test fixtures, and it is only true
    //     if these two stay invisible.
    let rs_dead = planted_rs(format!(
        "//! Planted by qa-names' own self-test. No `mod` reaches this file.\n\
         const PLANTED_ROOT: &str = \"{}\";\n\
         const LIVE_ROOT: &str = \"{LIVE_ROOT}\";\n",
        planted_rs_root()
    ));
    let rs_glob = planted_rs(format!(
        "//! Planted by qa-names' own self-test. No `mod` reaches this file.\n\
         const PLANTED_FAMILY: &str = \"{}\";\n\
         const LIVE_ROOT: &str = \"{LIVE_ROOT}\";\n",
        planted_rs_glob()
    ));
    // THE RUST SCAN THAT READ NOTHING. Every `qa/*.toml` is untouched, so `name-floor` clears its
    // own floor on the TOML half alone — which is the entire reason the Rust half has a floor of
    // its own, and this case is what says so.
    let rs_empty = cx
        .walk(&WalkSpec::new([XTASK_ROOT]).ext(XTASK_EXT))
        .ok()
        .map(|files| {
            let mut ov = Overlay::new();
            for f in &files {
                ov.remove(&f.rel);
            }
            ov
        });

    // THE KIND TABLE GONE. Everything below rule 1 is UNPROVEN, never passed.
    let mut no_config = Overlay::new();
    no_config.remove(CONFIG_REL);

    vec![
        Plant {
            label: "a gate CONSTANT names a path that is not on this tree",
            rule: ROW_PATH,
            naming: vec![planted_rs_root()],
            overlay: Some(rs_dead),
        },
        Plant {
            label: "a gate CONSTANT carries a glob that matches nothing",
            rule: ROW_GLOB,
            naming: vec![planted_rs_glob()],
            overlay: Some(rs_glob),
        },
        Plant {
            label: "the scan of the gates' own constants reading nothing is refused",
            rule: ROW_XTASK_FLOOR,
            naming: vec!["floor".to_string()],
            overlay: rs_empty,
        },
        Plant {
            label: "a config table names a kind that is no key of the kind table",
            rule: ROW_KIND,
            naming: vec![PLANTED_KIND.to_string()],
            overlay: kind,
        },
        Plant {
            label: "a config table names a crate this workspace does not have",
            rule: ROW_CRATE,
            naming: vec![PLANTED_CRATE.to_string()],
            overlay: krate,
        },
        Plant {
            label: "a config table names a path that is not on this tree",
            rule: ROW_PATH,
            naming: vec![planted_path()],
            overlay: path,
        },
        Plant {
            label: "a config table carries a glob that matches nothing",
            rule: ROW_GLOB,
            naming: vec![planted_glob()],
            overlay: glob,
        },
        Plant {
            label: "a plugin kind's whole glob list matches nothing and no census row declares it",
            rule: ROW_GLOB,
            naming: vec!["matches nothing".to_string()],
            overlay: empty_kind,
        },
        Plant {
            label: "a declared exception outlived the name it excused",
            rule: ROW_DECL_LIVE,
            naming: vec![PLANTED_NEVER.to_string()],
            overlay: unused_decl,
        },
        Plant {
            label: "a declared exception excuses a name that resolves fine",
            rule: ROW_DECL_LIVE,
            naming: vec!["needs no exemption".to_string()],
            overlay: needless_decl,
        },
        Plant {
            label: "a declared exception names a file this gate does not cover",
            rule: ROW_DECL_FILE,
            naming: vec![PLANTED_GONE_FILE.to_string()],
            overlay: bad_file_decl,
        },
        Plant {
            label: "a declared exception carries a shrug for a reason",
            rule: ROW_DECL_REASON,
            naming: vec![format!("minimum {MIN_REASON}")],
            overlay: thin_decl,
        },
        Plant {
            label: "the name scan matched nothing at all",
            rule: ROW_FLOOR,
            naming: vec![format!("floor {NAME_FLOOR}")],
            overlay: empty_scan,
        },
        Plant {
            label: "the kind table is unreadable",
            rule: ROW_UNIVERSE,
            naming: vec!["is unreadable".to_string()],
            overlay: Some(no_config),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> Ctx {
        Ctx::workspace().expect("workspace context")
    }

    fn tops() -> BTreeSet<String> {
        ["crates", "docs", "qa", "scripts", "testing", "xtask"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    #[test]
    fn prose_is_never_a_path_and_a_scan_root_always_is() {
        let t = tops();
        assert!(is_path_shaped("crates/busbar-substrate/src", &t));
        assert!(is_path_shaped("qa/construction.toml", &t));
        assert!(!is_path_shaped(
            "An installable seam under crates/busbar-substrate/src is a promise",
            &t
        ));
        // A module path and a regex are not paths, whatever the key is called.
        assert!(!is_path_shaped("busbar_kernel_ledger::cost::", &t));
        assert!(!is_path_shaped("^(install_[a-z0-9_]+)$", &t));
        // A first segment that is not a directory of this repo is not a path either.
        assert!(!is_path_shaped("vendor/anthropic/v1", &t));
    }

    #[test]
    fn a_fragment_key_is_never_a_name_and_a_path_key_is_not_a_crate() {
        let t = tops();
        assert_eq!(
            classify(CONFIG_REL, "non_production_path_fragments", "testkit", &t),
            None
        );
        assert_eq!(
            classify(CONFIG_REL, "exempt_seam_path_fragments", "/testkit/", &t),
            None
        );
        assert_eq!(
            classify(CONFIG_REL, "entry_path_patterns", "crates/x/y.rs", &t),
            None
        );
        // `crate_roots = ["crates"]` is a directory list, not a package called `crates`.
        assert_eq!(classify("qa/loc.toml", "crate_roots", "crates", &t), None);
        assert_eq!(
            classify(CONFIG_REL, "fee_reader_crates", "busbar-kernel", &t),
            Some(Class::Crate)
        );
        assert_eq!(
            classify(CONFIG_REL, "kinds", "pure_auth", &t),
            Some(Class::Kind)
        );
        // ...and the SAME key in another file is another vocabulary, deliberately not read here.
        assert_eq!(classify("qa/kind-isolation.toml", "kind", "api", &t), None);
    }

    #[test]
    fn a_known_site_tail_is_stripped_before_the_path_is_resolved() {
        let mk = |text: &str| Name {
            text: text.to_string(),
            file: CONFIG_REL.to_string(),
            line: 1,
            site: String::new(),
            class: Class::Path,
            in_array: true,
        };
        assert_eq!(
            mk("crates/busbar-contract/src/ids.rs::key").core(),
            "crates/busbar-contract/src/ids.rs"
        );
        assert_eq!(
            mk("crates/busbar-kernel/src/appbuild.rs:240").core(),
            "crates/busbar-kernel/src/appbuild.rs"
        );
        assert_eq!(
            mk("crates/plugin-loader/src/").core(),
            "crates/plugin-loader/src"
        );
        // A crate name with a `::` that is not a function tail keeps its spelling.
        assert_eq!(mk("crates/a/b.rs").core(), "crates/a/b.rs");
    }

    #[test]
    fn a_crate_glob_matches_the_way_fnmatch_does() {
        assert!(glob_one("busbar-unit-*", "busbar-unit-transport-key"));
        assert!(!glob_one("busbar-unit-*", "busbar-kernel-wal"));
        assert!(glob_one("busbar*", "busbar"));
        assert!(!glob_one("busbar-*", "busbar"));
    }

    #[test]
    fn a_declaration_parses_into_its_three_fields() {
        let d =
            parse_decl(&format!("{DECL} n{SEP}qa/construction.toml{SEP}a reason")).expect("parses");
        assert_eq!(
            (d.name.as_str(), d.file.as_str()),
            ("n", "qa/construction.toml")
        );
        assert_eq!(d.reason, "a reason");
        // A line that carries the prefix and not the shape comes back with empty fields, so the
        // file and reason rules report it rather than the parser swallowing it.
        let d = parse_decl(&format!("{DECL} n")).expect("parses");
        assert!(d.file.is_empty() && d.reason.is_empty());
        assert!(parse_decl("# something else").is_none());
    }

    #[test]
    fn a_phantom_is_planted_as_a_sibling_and_takes_nothing_away() {
        let text = "[t]\nkinds = [\"plane\", \"hook\"]\n";
        let at = Name {
            text: "hook".to_string(),
            file: CONFIG_REL.to_string(),
            line: 2,
            site: String::new(),
            class: Class::Kind,
            in_array: true,
        };
        assert_eq!(
            plant_beside(text, &at, "ghost").as_deref(),
            Some("[t]\nkinds = [\"plane\", \"hook\", \"ghost\"]\n")
        );
    }

    /// The ids that went non-PASS under one planted overlay.
    fn failed_ids(cx: &Ctx, ov: Overlay) -> BTreeSet<String> {
        crate::gates::execute(&QaNamesGate, &cx.with_overlay(ov))
            .rows
            .iter()
            .filter(|r| r.status != crate::ledger::Status::Pass)
            .map(|r| r.id.clone())
            .collect()
    }

    /// EVERY PLANT MUST REDDEN ITS OWN ROW AND TURN NOTHING ELSE RED THAT WAS GREEN — except the
    /// kind-table plant, whose whole point is that everything below it is unproven. Stated against
    /// the tree's OWN baseline rather than against "nothing else is red", because three rows carry
    /// standing dead names that are not this change's to drain and a case that demanded they be
    /// clean would be a case nobody could keep.
    #[test]
    fn each_plant_reddens_its_own_row_and_nothing_that_was_green() {
        let cx = cx();
        let base = failed_ids(&cx, Overlay::new());
        for p in plants(&cx) {
            if p.rule == ROW_UNIVERSE {
                continue;
            }
            let ov = p
                .overlay
                .unwrap_or_else(|| panic!("nothing to plant: {}", p.label));
            let got = failed_ids(&cx, ov);
            assert!(
                got.contains(p.rule),
                "plant `{}` did not redden `{}` (red: {got:?})",
                p.label,
                p.rule
            );
            let fresh: Vec<&String> = got
                .iter()
                .filter(|id| id.as_str() != p.rule && !base.contains(*id))
                .collect();
            assert!(
                fresh.is_empty(),
                "plant `{}` also reddened rows that were green: {fresh:?}",
                p.label
            );
        }
    }

    /// The rows with no standing debt are green, and the scan is over a real population.
    #[test]
    fn the_clean_rows_are_green_and_the_scan_is_not_empty() {
        let verdict = crate::gates::execute(&QaNamesGate, &cx());
        for id in [
            ROW_UNIVERSE,
            ROW_FLOOR,
            ROW_KIND,
            ROW_DECL_LIVE,
            ROW_DECL_FILE,
            ROW_DECL_REASON,
        ] {
            let r = verdict
                .rows
                .iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("{id} did not run"));
            assert_eq!(
                r.status,
                crate::ledger::Status::Pass,
                "{id} is RED on the real tree: {}",
                r.detail
            );
        }
    }

    /// THE DAY'S FOUR FIXES, OLDEST FIRST, each as `(<sha>, <what it fixed>, <what the gate must
    /// name in the config its PARENT carried>)`. `<sha>^:qa/construction.toml` is the pre-fix
    /// config, and the needles differ per commit because each fix struck a different name: by
    /// `ab5bcb45c^` the `[rules.source-denylist].kinds` half had already been corrected by
    /// `383f23875`, so demanding it there would be demanding a defect that was gone.
    #[allow(clippy::type_complexity)]
    const FIXES: &[(&str, &str, &[&str])] = &[
        (
            "2b5727416",
            "the export family glob at the wrong path",
            &[
                // Defect 1's own table, naming a plane folded into busbar-plane-streaming.
                "`crates/busbar-plane-voice` ([gate.plugin_kinds] plane)",
                // Defects 3 and 4: four phantom kind names across two rules.
                "`pure_auth` ([rules.source-denylist] kinds)",
                "`egress_auth` ([rules.source-denylist] kinds)",
                "`pure_auth` ([rules.forbid-unsafe] forbid_kinds)",
                "`egress_auth` ([rules.forbid-unsafe] forbid_kinds)",
                // The same kind again as a census KEY, declaring a population of two.
                "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
                // Defect 5's open names, and two codec crates that had already been deleted.
                "`busbar-a2a-codec` ([gate.plane_codec_crates] busbar-a2a)",
                "`busbar-mcp-codec` ([gate.plane_codec_crates] busbar-mcp)",
                "`busbar-admin` ([rules.one-pricing-site] fee_reader_crates)",
                "`crates/busbar-substrate/src` ([rules.no-uninstalled-seam] seam_root)",
            ],
        ),
        (
            "2b2de9712",
            "the fifth plane in no kind list",
            &[
                "`pure_auth` ([rules.source-denylist] kinds)",
                "`egress_auth` ([rules.forbid-unsafe] forbid_kinds)",
                "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
                "`busbar-a2a-codec` ([gate.plane_codec_crates] busbar-a2a)",
            ],
        ),
        (
            "383f23875",
            "source-denylist naming kinds that do not exist",
            &[
                "`pure_auth` ([rules.source-denylist] kinds)",
                "`egress_auth` ([rules.source-denylist] kinds)",
                "`pure_auth` ([rules.forbid-unsafe] forbid_kinds)",
                "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
            ],
        ),
        (
            "ab5bcb45c",
            "forbid-unsafe naming the same two, and the census re-pin",
            &[
                "`pure_auth` ([rules.forbid-unsafe] forbid_kinds)",
                "`egress_auth` ([rules.forbid-unsafe] forbid_kinds)",
                "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
            ],
        ),
    ];

    /// THE HISTORICAL CATCH, AND IT IS THE WHOLE PROOF.
    ///
    /// A gate written against an already-cleaned tree proves nothing: it was shaped until it
    /// passed, and "it passes" is exactly what the config it replaced did. So this reconstructs the
    /// config as it stood BEFORE each of the day's four fixes — read from history with `git show`,
    /// never from the working tree, which the same change is free to edit — lays it over TODAY'S
    /// tree, and requires the gate to name each defect BY ITS TABLE AND ITS KEY.
    ///
    /// THE OTHER HALF OF THE PROOF is the three names it must NOT report. `dialect = 0`,
    /// `control = 0` and `egress_auth = 0` stood in the same pre-fix `[gate.census.plugin_kinds]`
    /// as `pure_auth = 2`, and all four name no key in `[gate.plugin_kinds]`. The three declaring
    /// ZERO are kinds with no crate yet, which the header over that table says in terms is
    /// legitimate; the one declaring TWO claims a population nothing can find. A rule that reported
    /// all four would be a rule with no way to satisfy it, which is a rule somebody deletes.
    #[test]
    fn the_pre_fix_config_of_the_day_is_named_in_full() {
        let cx = cx();
        for (sha, what, needles) in FIXES {
            assert!(
                cx.git_ref_resolves(&format!("{sha}^")),
                "{sha}^ ({what}) does not resolve — this proof needs history, not a shallow clone"
            );
            let before = cx
                .git_show(&format!("{sha}^"), CONFIG_REL)
                .unwrap_or_else(|e| panic!("{sha}^:{CONFIG_REL}: {e}"));
            let mut ov = Overlay::new();
            ov.set(CONFIG_REL, before);
            let verdict = crate::gates::execute(&QaNamesGate, &cx.with_overlay(ov));
            let said: String = verdict
                .rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass)
                .map(|r| format!("{} {}\n", r.id, r.detail))
                .collect();
            println!("\n===== {sha}^ ({what}) =====\n{said}");

            for needle in *needles {
                assert!(
                    said.contains(needle),
                    "{sha}^: the gate did not name {needle:?}"
                );
            }
            for zero in [
                "`dialect`",
                "`control`",
                "`egress_auth` ([gate.census.plugin_kinds]",
            ] {
                assert!(
                    !said.contains(zero),
                    "{sha}^: a DECLARED zero was reported: {zero}"
                );
            }
        }
    }

    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = cx();
        let report = QaNamesGate.selftest(&cx);
        crate::gates::verify_report(&QaNamesGate, &report)
            .unwrap_or_else(|errs| panic!("qa-names selftest: {errs:#?}"));
        assert_eq!(report.skipped(), 0, "a case had nothing to plant");
    }
}
