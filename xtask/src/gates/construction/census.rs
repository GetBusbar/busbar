//! `ceiling-census` — THE RATCHET ON THE RATCHETS.
//!
//! `owed()` is derived from the SAME `Cfg` the rules read. Delete a
//! `[rules.legacy-reach.prefixes.*]` table and both the check and the obligation to run it vanish
//! in one edit — measured on the (since deleted) kernel-file LOC tables: 112 rows became 111 and
//! nothing complained. `gate.plane_crates` has the same shape, and so does every
//! `[gate.plugin_kinds]` glob: narrow
//! `crates/busbar-plane-*` to `crates/busbar-plane-llm` and the key is still present, still
//! cross-checked by `kind-isolation:truths`, and four crates quietly stop being scanned.
//!
//! So the COUNTS are pinned, in `[gate.census]`, and this row is owed UNCONDITIONALLY — a literal
//! in `ids()`, not something derived from the config. That is the property the rest of the owed
//! register lacks and the only reason this row cannot be deleted the same way its subjects could.
//!
//! AND THE RULE CEILINGS ARE HELD AGAINST THE SAME BASE ([`raised_ceilings`]). Every rule reads its
//! ceiling from the file under judgement (`max_sites`, `max_hits`, a per-crate figure), so a
//! ceiling raised in the change that adds the site it would have caught was green. Law 9: a
//! ceiling "refuses every rise from that moment".

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::gates::construction::ceilings::{base_ref, Base};
use crate::gates::construction::model::{plain, py_list, CRow, Cfg};
use crate::gates::construction::rules2;
use crate::gates::construction::tree::Tree;
use crate::gates::construction::{dirs_for_globs, CEILINGS};
use crate::toml_doc::{Document, Value};

pub const ROW_CENSUS: &str = "ceiling-census";

const TITLE: &str = "every rule table, plane crate and kind glob is still counted";

/// CENSUS PINS WHOSE SUBJECT THIS CODE NO LONGER COUNTS, by name. A base that still carries one is
/// not a floor that went down: the subject left the gate in a reviewed code change, not in a data
/// edit. Each entry is a deletion the owner ruled, and the list never names a live subject.
///
/// * `loc_ceilings_kernel_files` — the `[rules.loc-ceilings.kernel_files]` LOC tables. Size is
///   not a CI check (owner 2026-10-02); the tables and their rows are deleted.
const RETIRED_PINS: &[&str] = &["loc_ceilings_kernel_files"];

/// One census subject: what is counted, where its floor is pinned, and how many there are today.
struct Subject {
    pin_key: &'static str,
    what: &'static str,
    actual: usize,
}

/// THE PIN IS A FLOOR, NOT AN EQUALITY. Adding a kernel file or a legacy prefix is the ordinary
/// direction of this work and must not need a ceremony; removing one is the manoeuvre. So
/// `actual < pinned` is RED and `actual > pinned` is fine.
///
/// AND THE FLOOR ITSELF IS PINNED AGAINST THE BASE, which is the half that makes it hold. Without
/// it, deleting a rule table and dropping its census number in the same edit would be exactly as
/// silent as deleting the table alone was. A census floor lower than it was at the base is RED —
/// unless its key is on [`RETIRED_PINS`], the named list of subjects this code no longer counts.
pub fn ceiling_census(cx: &Ctx, cfg: &Cfg) -> Vec<CRow> {
    let Some(census) = cfg.doc.table("gate.census") else {
        return vec![plain(
            ROW_CENSUS,
            false,
            TITLE,
            format!(
                "{CEILINGS} has no [gate.census] table. That table is the count of how many rule \
                 tables, plane crates and kind globs this gate is supposed to be reading, and \
                 without it a rule table can be deleted together with the ceiling it holds and \
                 nothing is short of anything. A census that is absent is not a census that passed."
            ),
            -1,
            0,
            vec![],
        )];
    };

    let plane_crates = cfg.plane_crates().unwrap_or_default();
    let subjects = [
        Subject {
            pin_key: "legacy_reach_prefixes",
            what: "[rules.legacy-reach.prefixes] entries",
            actual: cfg.doc.children("rules.legacy-reach.prefixes").len(),
        },
        Subject {
            pin_key: "plane_crates",
            what: "gate.plane_crates entries",
            actual: plane_crates.len(),
        },
    ];

    let mut bad: Vec<String> = Vec::new();
    let mut counted: i64 = 0;

    for s in &subjects {
        match census.int_of(s.pin_key) {
            Some(pin) => {
                counted += s.actual as i64;
                if (s.actual as i64) < pin {
                    bad.push(format!(
                        "{}: {} on this tree, {pin} pinned as [gate.census] {}",
                        s.what, s.actual, s.pin_key
                    ));
                }
            }
            None => bad.push(format!(
                "[gate.census] has no integer `{}`, so {} are counted by nothing",
                s.pin_key, s.what
            )),
        }
    }

    // A plane crate that names no directory is a `ports-only:<crate>` pair measuring an absent
    // subject. The list is exact crate names rather than globs, so this is the same question the
    // kind globs are asked below.
    for c in &plane_crates {
        if !cx.exists(format!("crates/{c}")) {
            bad.push(format!(
                "gate.plane_crates names `{c}`, and crates/{c} is not in this tree — its \
                 ports-only rows have no subject to measure"
            ));
        }
    }

    // ── the kind globs ───────────────────────────────────────────────────────────────────────────
    // A glob is pinned by HOW MANY DIRECTORIES IT MATCHES, not by "at least one". `dialect` matches
    // nothing today and qa/construction.toml says so deliberately — it is the kind whose first
    // crate the codec split creates — so a blanket "≥1" would red a documented, intended zero while
    // still saying nothing about `plane` dropping from four crates to one. The count catches both.
    let kinds = cfg.doc.table_or_empty("gate.plugin_kinds");
    let kind_pins = cfg.doc.table_or_empty("gate.census.plugin_kinds");
    let mut pinned: BTreeSet<String> = BTreeSet::new();
    for key in kinds.keys() {
        // Every key here came out of `[gate.plugin_kinds]` itself, so the refusal `kind_globs`
        // raises for an undeclared key is unreachable from this loop. It is reported rather than
        // unwrapped anyway: a census that panicked would say nothing, and a census that swallowed
        // the error would count the kind as zero — the shape this whole rule exists to catch.
        let globs = match cfg.kind_globs(key) {
            Ok(g) => g,
            Err(e) => {
                bad.push(e);
                continue;
            }
        };
        let n = dirs_for_globs(cx, &globs).len();
        match kind_pins.int_of(key) {
            Some(pin) => {
                pinned.insert(key.clone());
                counted += n as i64;
                if (n as i64) < pin {
                    bad.push(format!(
                        "[gate.plugin_kinds] {key} = {}: matches {n} crate director{} on this \
                         tree, {pin} pinned as [gate.census.plugin_kinds] {key}. A glob that \
                         stopped matching its crates is a rule that stopped reading them",
                        py_list(&globs),
                        if n == 1 { "y" } else { "ies" }
                    ));
                }
            }
            None => bad.push(format!(
                "[gate.census.plugin_kinds] has no integer `{key}`, so that kind's globs are \
                 counted by nothing"
            )),
        }
    }
    // A pin naming no glob is stale in exactly the way a ceiling naming no row is.
    bad.extend(
        kind_pins
            .keys()
            .iter()
            .filter(|k| !pinned.contains(*k))
            .map(|k| format!("[gate.census.plugin_kinds] {k} names no key in [gate.plugin_kinds]")),
    );

    // ── the floors themselves, against the base ──────────────────────────────────────────────────
    // The rename rows are read (and a broken one is refused) whether or not a base is established.
    let (renamed, problems) = renames(cx, &cfg.doc);
    bad.extend(problems);
    match base_ceilings(cx) {
        Ok((base, doc)) => {
            let base_deleted = deleted_ledger(&doc);
            let now_deleted = deleted_ledger(&cfg.doc);
            bad.extend(deleted_ledger_findings(&now_deleted, &base_deleted, |d| {
                cx.abs(d).exists()
            }));
            let mut moved = moved_out_by_kind(cx, cfg, &doc, &base.sha, &now_deleted, &renamed);
            let base_planes = doc.table_or_empty("gate").list_of("plane_crates");
            let now_planes = cfg.plane_crates().unwrap_or_default();
            if let Some(n) = deleted_plane_crates(&base_planes, &now_planes, |dir| {
                now_deleted.contains(dir) && !cx.abs(dir).exists()
            }) {
                moved.insert("plane_crates".to_string(), n as i64);
            }
            bad.extend(lowered_floors(&cfg.doc, &doc, base.short(), &moved));
            let (struck, problems) = struck_rule_tables(&cfg.doc, &doc, |dir| {
                now_deleted.contains(dir) && !cx.abs(dir).exists()
            });
            bad.extend(problems);
            let remeasure =
                |table: &str, key: &str| base_remeasure(cx, &cfg.doc, &base.sha, &doc, table, key);
            let (measured, problems) = measured_ceilings(&cfg.doc, &doc, &remeasure);
            bad.extend(problems);
            bad.extend(raised_ceilings(
                &cfg.doc,
                &doc,
                base.short(),
                &now_planes,
                &struck,
                &measured,
            ));
        }
        Err(e) => bad.push(e),
    }

    if bad.is_empty() {
        return vec![plain(
            ROW_CENSUS,
            true,
            TITLE,
            format!(
                "{counted} rule-table, plane-crate and kind-glob subject(s) counted, none below \
                 its pinned floor, and no rule ceiling above the base's"
            ),
            counted,
            counted,
            vec![],
        )];
    }
    let n = bad.len() as i64;
    vec![plain(
        ROW_CENSUS,
        false,
        TITLE,
        format!(
            "{n} census problem(s). A rule table, a plane crate or a kind glob went away, or the \
             floor under one did. Deleting a rule table deletes the obligation to run it, so this \
             row is what makes that a RED rather than one fewer row nobody was counting: {}",
            bad.join("; ")
        ),
        n,
        0,
        bad,
    )]
}

/// THE BASE'S COPY OF THE CEILINGS FILE, or why there is none. Every arm that fails is a census
/// problem: with no base copy the floors are compared against nothing, and "none below its pinned
/// floor" would then be a claim nothing checked. A base that cannot be established is RED (see
/// [`base_ref`]), never a skipped comparison. CI names the base (`XTASK_CEILING_BASE`).
fn base_ceilings(cx: &Ctx) -> Result<(Base, Document), String> {
    let base = base_ref(cx).map_err(|e| {
        format!("no base to hold the census floors against, so no floor is checked: {e}")
    })?;
    let was = cx.git_show(&base.sha, CEILINGS).map_err(|e| {
        format!(
            "the base {} ({}) has no readable {CEILINGS}, so no census floor is checked against \
             it: {e}",
            base.short(),
            base.how
        )
    })?;
    let doc = crate::toml_doc::parse_str(&was).map_err(|e| {
        format!(
            "the base {}'s copy of {CEILINGS} does not parse, so no census floor is checked \
             against it: {e}",
            base.short()
        )
    })?;
    Ok((base, doc))
}

/// EVERY CENSUS FLOOR THAT WENT DOWN, or was deleted outright, since the base.
///
/// This is the half that makes the census hold. Without it, "delete the rule table AND drop its
/// census number" is one edit and is exactly as silent as deleting the table alone was. A key on
/// [`RETIRED_PINS`] is skipped: its subject left the code, not the data.
///
/// A floor the base carried and this tree does not is scored as a drop to 0, not skipped: deleting
/// the KEY is the cheapest way to lower it.
///
/// A separate function from [`ceiling_census`] because the base is real git history, and the one
/// property that most needs a test is the one a branch cannot stage — until this table lands on the
/// integration line, no base commit carries it.
///
/// THE ONE ACCEPTED WAY DOWN (ARCHITECT 2026-10-02, TODO PATH TO DEV-GREEN P5): a
/// `plugin_kinds.<kind>` floor may drop by at most `moved[<key>]`, the number of that kind's crate
/// directories that left the tree as MOVED-OUT plugins or ruled deletions ([`excused_out`]), and
/// `plane_crates` by the legacy engines deleted under `[gate.census.deleted]`
/// ([`deleted_plane_crates`], P3 DEL-MCP, ARCHITECT 2026-10-05; and `busbar-voice`, FLIP-STREAMING).
/// Every other drop is RED.
/// A crate whose package name changed with the move counts only through a rename row ([`renames`],
/// ARCHITECT 2026-10-03 Q-L7B2-CENSUS).
fn lowered_floors(
    now_doc: &Document,
    base_doc: &Document,
    short: &str,
    moved: &BTreeMap<String, i64>,
) -> Vec<String> {
    let now = census_pins(now_doc);
    census_pins(base_doc)
        .into_iter()
        .filter(|(k, _)| !RETIRED_PINS.contains(&k.as_str()))
        .filter_map(|(k, before)| {
            let after = now.get(&k).copied().unwrap_or(0);
            let excused = moved.get(&k).copied().unwrap_or(0);
            (after < before && before - after > excused).then(|| {
                format!(
                    "[gate.census] {k}: the floor itself went {before} -> {after} since the base \
                     {short}. Lowering a census floor is how a deleted rule table would be made to \
                     look accounted for"
                )
            })
        })
        .collect()
}

/// Per `plugin_kinds.<kind>` census key, how many of that kind's crate directories MOVED OUT since
/// the base (`sha`): the directories the base's globs matched that this tree's globs no longer
/// match. The count is entered only when EVERY such directory moved out or were deleted under the ledger ([`excused_out`]); a kind
/// that lost one directory any other way gets no entry, so its floor drop stays RED.
fn moved_out_by_kind(
    cx: &Ctx,
    cfg: &Cfg,
    base_doc: &Document,
    sha: &str,
    deleted: &BTreeSet<String>,
    renamed: &BTreeMap<String, String>,
) -> BTreeMap<String, i64> {
    let root_manifest = cx.read("Cargo.toml").unwrap_or_default();
    let base_kinds = base_doc.table_or_empty("gate.plugin_kinds");
    let mut out = BTreeMap::new();
    for kind in base_kinds.keys() {
        let base_globs = base_kinds.list_of(kind);
        let now: Vec<String> = cfg
            .kind_globs(kind)
            .map(|g| dirs_for_globs(cx, &g))
            .unwrap_or_default();
        let gone: Vec<String> = base_dirs(cx, sha, &base_globs)
            .into_iter()
            .filter(|d| !now.contains(d))
            .collect();
        let package_at_base = |dir: &str| {
            cx.git_show(sha, &format!("{dir}/Cargo.toml"))
                .ok()
                .and_then(|m| {
                    crate::toml_lite::parse_text(&m)
                        .table("package")
                        .get_one("name")
                        .map(|n| n.trim().trim_matches('"').to_string())
                })
        };
        if let Some(n) = excused_out(
            &gone,
            |dir| moved_out(&[dir.to_string()], package_at_base, &root_manifest, renamed).is_some(),
            |dir| deleted.contains(dir) && !cx.abs(dir).exists(),
        ) {
            out.insert(format!("plugin_kinds.{kind}"), n as i64);
        }
    }
    out
}

/// THE SAME RULED WAY DOWN FOR `gate.plane_crates` (P3 DEL-MCP, ARCHITECT 2026-10-05: "delete
/// busbar-mcp, add `crates/busbar-mcp` to [gate.census.deleted]"). The legacy-engine list may lose
/// an entry only when its crate was DELETED under the ledger: the entries the base listed and this
/// tree does not, `Some(n)` when EVERY one names a `crates/<entry>` that is a ruled deletion
/// (`is_deleted`: `[gate.census.deleted]` lists it and it is absent from this tree; [`excused_out`],
/// no move-out arm — a legacy engine is retired, never pinned back). `None` when nothing left the
/// list or any one left any other way, so the `plane_crates` floor drop stays RED.
fn deleted_plane_crates(
    base: &[String],
    now: &[String],
    is_deleted: impl Fn(&str) -> bool,
) -> Option<usize> {
    let gone: Vec<String> = base
        .iter()
        .filter(|c| !now.contains(c))
        .map(|c| format!("crates/{c}"))
        .collect();
    excused_out(&gone, |_| false, is_deleted)
}

/// A plugin crate MOVED OUT (TODO PATH TO DEV-GREEN P5: filter-repo into its own repo, pinned back
/// in busbar as one git dependency at an exact commit), or was DELETED under a ruled TODO deletion
/// (ARCHITECT 2026-10-04: named in `[gate.census.deleted]`, absent from this tree).
/// `Some(gone.len())` when EVERY directory in `gone` is one or the other (`is_moved`, `is_deleted`);
/// `None` when any one is neither (an unlisted vanished directory stays RED), and for an empty
/// `gone`.
fn excused_out(
    gone: &[String],
    is_moved: impl Fn(&str) -> bool,
    is_deleted: impl Fn(&str) -> bool,
) -> Option<usize> {
    if gone.is_empty() {
        return None;
    }
    gone.iter()
        .all(|dir| is_moved(dir) || is_deleted(dir))
        .then_some(gone.len())
}

/// A plugin crate MOVED OUT (TODO PATH TO DEV-GREEN P5: filter-repo into its own repo, pinned back
/// in busbar as one git dependency at an exact commit). `Some(gone.len())` when every directory in
/// `gone` is a crate whose package (`package_at_base`) the root manifest now pins as a git
/// dependency at a `rev`; `None` when any one is not (deleted, or pulled by branch), and for an
/// empty `gone`.
///
/// A RENAMED move (ARCHITECT 2026-10-03, Q-L7B2-CENSUS) counts only when BOTH hold: `renamed` — the
/// census ledger's rename rows, old package name to new — carries a row for the base package, AND
/// the root pins the NEW name as a git dependency at a `rev`. A rename with no row is not a move:
/// nothing but a reviewed row says the new crate is the old one.
fn moved_out(
    gone: &[String],
    package_at_base: impl Fn(&str) -> Option<String>,
    root_manifest: &str,
    renamed: &BTreeMap<String, String>,
) -> Option<usize> {
    if gone.is_empty() {
        return None;
    }
    let pinned = |name: &str| crate::gates::workspace_deps::pinned_git_dep(root_manifest, name);
    gone.iter()
        .all(|dir| {
            package_at_base(dir).is_some_and(|name| {
                pinned(&name) || renamed.get(&name).is_some_and(|new| pinned(new))
            })
        })
        .then_some(gone.len())
}

/// The directories `[gate.census.deleted]` names, by key.
fn deleted_ledger(doc: &Document) -> BTreeSet<String> {
    doc.table_or_empty("gate.census.deleted")
        .keys()
        .iter()
        .map(|k| k.trim().trim_matches('"').to_string())
        .collect()
}

/// The `[gate.census.deleted]` ledger's own rules: add-only against the base (an entry the base
/// carried and this tree does not is RED), and an entry whose directory is still present is a
/// stale entry (RED).
fn deleted_ledger_findings(
    now: &BTreeSet<String>,
    base: &BTreeSet<String>,
    present: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut out: Vec<String> = base
        .difference(now)
        .map(|d| {
            format!(
                "[gate.census.deleted] `{d}` was removed since the base; the ledger is add-only"
            )
        })
        .collect();
    out.extend(now.iter().filter(|d| present(d)).map(|d| {
        format!("[gate.census.deleted] `{d}` is listed but still present in the tree (stale entry)")
    }));
    out
}

/// THE CENSUS LEDGER'S RENAME ROWS: `[[gate.census.renamed]]`, each `from` (the package name at the
/// base) -> `to` (the crate name the root now pins), with the `commit` that moved it and the
/// `reason` (ARCHITECT 2026-10-03, Q-L7B2-CENSUS). Answers the rows as `from -> to`, and one census
/// problem per row that is not a whole row: a field missing or empty, `from` equal to `to`, a
/// `from` written twice, or a `commit` that does not resolve. A broken row excuses nothing.
pub(crate) fn renames(cx: &Ctx, doc: &Document) -> (BTreeMap<String, String>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut problems = Vec::new();
    for (i, row) in doc.array_of_tables(RENAMED).into_iter().enumerate() {
        let field = |k: &str| row.str_of(k).map(str::trim).filter(|v| !v.is_empty());
        let (Some(from), Some(to), Some(commit), Some(_reason)) =
            (field("from"), field("to"), field("commit"), field("reason"))
        else {
            problems.push(format!(
                "[[{RENAMED}]] row {} is not a whole rename row: it needs `from`, `to`, `commit` and \
                 `reason`, each non-empty",
                i + 1
            ));
            continue;
        };
        if from == to {
            problems.push(format!(
                "[[{RENAMED}]] row {} renames `{from}` to itself",
                i + 1
            ));
            continue;
        }
        if !cx.git_ref_resolves(commit) {
            problems.push(format!(
                "[[{RENAMED}]] {from} -> {to}: its commit `{commit}` does not resolve in this checkout"
            ));
            continue;
        }
        if out.insert(from.to_string(), to.to_string()).is_some() {
            problems.push(format!("[[{RENAMED}]] renames `{from}` twice"));
        }
    }
    (out, problems)
}

/// Where the rename rows live in the ceilings file.
pub const RENAMED: &str = "gate.census.renamed";

/// The overlay key a self-test plants to answer `git ls-tree -d --name-only <sha> <parent>/` (see
/// [`base_dirs`]): one directory per line.
pub const LS_TREE_KEY: &str = "git-ls-tree";

/// The directories the globs `globs` matched at commit `sha`: each glob's parent listed at that
/// commit (`git ls-tree -d`), kept where the glob matches.
fn base_dirs(cx: &Ctx, sha: &str, globs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for g in globs {
        let parent = g.rsplit_once('/').map_or(".", |(p, _)| p);
        // A self-test's synthetic base answers from the overlay; every real run asks git.
        let listed = match cx.overlay_command(&format!("{LS_TREE_KEY}:{sha}:{parent}/")) {
            Some(text) => text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            None => cx
                .git_lines(&["ls-tree", "-d", "--name-only", sha, &format!("{parent}/")])
                .unwrap_or_default(),
        };
        for d in listed {
            if glob_matches(g, &d) && !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

/// `pattern` (at most one `*`, never crossing a `/`) matches `path`.
fn glob_matches(pattern: &str, path: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == path,
        Some((head, tail)) => {
            path.len() >= head.len() + tail.len()
                && path.starts_with(head)
                && path.ends_with(tail)
                && !path[head.len()..path.len() - tail.len()].contains('/')
        }
    }
}

/// THE INTEGERS UNDER `[rules.*]` THAT BOUND NOTHING: how many of the worst offenders a report
/// lists. Every other integer of a rule table is a ceiling (a `max_*`, a ratchet `ceiling` or
/// `figure`, a counted `sites`, a per-crate figure) or a matcher setting whose rise narrows what the
/// rule sees (`min_block_lines`, `shingle_tokens`), and none of them may rise.
const NOT_CEILINGS: &[&str] = &["top", "top_pairs"];

/// Every integer under `[rules.*]` but [`NOT_CEILINGS`], by `(table, key)`.
fn rule_ceilings(doc: &Document) -> BTreeMap<(String, String), i64> {
    let mut out = BTreeMap::new();
    for (path, t) in doc.tables() {
        if !path.starts_with("rules.") {
            continue;
        }
        for key in t.keys() {
            if NOT_CEILINGS.contains(&key.as_str()) {
                continue;
            }
            if let Some(v) = t.int_of(key) {
                out.insert((path.to_string(), key.clone()), v);
            }
        }
    }
    out
}

/// EVERY RULE CEILING THAT ROSE, or was deleted, since the base (Law 9, BUSBAR-1.6.0.md: a ceiling
/// "refuses every rise from that moment"). A ceiling read from the file under judgement can be
/// raised in the same change as the violation it would have caught — a fourth pick site and
/// `max_sites = 4`, a ban's `max_hits = 0` set to 3 — and every rule would read the new number and
/// pass. So each is compared with the base's copy, the comparison `lowered_floors` makes for the
/// census floors, in the other direction. Deleting the key is the cheapest rise and is scored as
/// one. Two deletions are not rises: a `max_per_crate` figure for a crate that left
/// `gate.plane_crates`, whose floor the census already holds against the base, and a rule table
/// whose whole subject was deleted with a ledgered crate ([`struck_rule_tables`]). One rise is not
/// a rise: a ceiling SET from 0 in the change whose detector first makes that debt visible
/// ([`measured_ceilings`]); from any other figure, or in any change after that one, it is refused.
fn raised_ceilings(
    now_doc: &Document,
    base_doc: &Document,
    short: &str,
    plane_crates_now: &[String],
    struck: &BTreeSet<String>,
    measured: &BTreeSet<(String, String)>,
) -> Vec<String> {
    let now = rule_ceilings(now_doc);
    rule_ceilings(base_doc)
        .into_iter()
        .filter_map(
            |((table, key), before)| match now.get(&(table.clone(), key.clone())) {
                Some(_) if before == 0 && measured.contains(&(table.clone(), key.clone())) => None,
                Some(after) if *after > before => Some(format!(
                "[{table}] {key}: the ceiling rose {before} -> {after} since the base {short}. A \
                 ceiling refuses every rise (Law 9): drain the sites instead"
            )),
                Some(_) => None,
                None if table.ends_with(".max_per_crate") && !plane_crates_now.contains(&key) => {
                    None
                }
                None if struck.contains(&table) => None,
                None => Some(format!(
                "[{table}] {key}: the ceiling {before} at the base {short} is gone from this tree. \
                 Deleting a ceiling is the cheapest way to raise it"
            )),
            },
        )
        .collect()
}

/// THE LEDGER OF CEILINGS SET BY THE CHANGE THAT FIRST MEASURES THEIR DEBT:
/// `[gate.census.measured]`.
pub const MEASURED: &str = "gate.census.measured";

/// THE RULES WHOSE CEILINGS A MEASUREMENT MAY SET, each with its DETECTOR KEYS: the keys whose
/// values that rule matches the tree with (ARCHITECT ruling on a6's second review of #1454). Prose
/// (`why`), a ledger of debt or exemptions, a path it skips and a ceiling are not detectors, and
/// neither is a key the rule does not read. A rule is listed only where [`base_remeasure`] can run
/// it over the base, so every ceiling a measurement sets is checked against the base's own count.
const MEASURABLE: &[(&str, &[&str])] = &[
    (
        "kernel-no-protocol-registry",
        &[
            "scope_globs",
            "names",
            "fn_names",
            "store_cells",
            "store_holds",
        ],
    ),
    ("unit-no-wall-clock", &["scope_globs", "forbidden"]),
];

/// The detector keys of `rule`, when the census can re-measure it ([`MEASURABLE`]).
fn detectors_of(rule: &str) -> Option<&'static [&'static str]> {
    MEASURABLE
        .iter()
        .find(|(r, _)| *r == rule)
        .map(|(_, keys)| *keys)
}

/// One `[gate.census.measured]` value, read by its fields: `<detector>[, <detector>…] -- <why>;
/// drain: <ref>`. The drain is the `;`-separated field that starts `drain:`; the word anywhere else
/// in the prose is not one.
struct MeasuredWhy {
    detectors: Vec<String>,
    drain: Option<String>,
}

fn parse_measured(value: &str) -> MeasuredWhy {
    let (detectors, why) = value.split_once(" -- ").unwrap_or(("", value));
    MeasuredWhy {
        detectors: detectors
            .split(',')
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect(),
        drain: why
            .split(';')
            .find_map(|field| field.trim().strip_prefix("drain:"))
            .map(|r| r.trim().to_string()),
    }
}

/// A drain reference names something a reader can open: a PR (`#1454`), a status row (`row 82`)
/// or a file (`crates/busbar-kernel/src/preflight.rs`). SYNTAX ONLY, by ruling: it is not looked up
/// as a PR, a row or a path that exists. The drain is the reviewer's pointer; what keeps a measured
/// ceiling honest is the base re-measure ([`base_remeasure`]), which no reference can satisfy.
fn names_a_ref(r: &str) -> bool {
    let digit_at = |s: &str| s.chars().next().is_some_and(|c| c.is_ascii_digit());
    let pr = r.match_indices('#').any(|(i, _)| digit_at(&r[i + 1..]));
    let lower = r.to_ascii_lowercase();
    let row = lower.match_indices("row ").any(|(i, _)| {
        digit_at(&lower[i + 4..]) && (i == 0 || !lower.as_bytes()[i - 1].is_ascii_alphanumeric())
    });
    let file = r
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| "`'\"(),;:".contains(c)))
        .any(|t| {
            t.contains('/')
                && t.rsplit('/').next().is_some_and(|leaf| {
                    leaf.contains('.') && !leaf.starts_with('.') && !leaf.ends_with('.')
                })
        });
    pr || row || file
}

/// THE CEILINGS A DETECTOR CHANGE MEASURED INTO BEING (ARCHITECT rulings on #1454, the #1418
/// MINTED precedent): debt that was in the tree, unseen, until this change's detector could see it
/// may be SET at its measured count in that same change, and only then. Each entry of
/// `[gate.census.measured]` is `"rules.<table>.<key>" = "<detector key>[, <detector key>…] -- <why>;
/// drain: <PR, row or file>"`, and it excuses the rise of that one ceiling only when ALL hold:
///   * the base does not carry the entry (it is this change's own; at any base after it, it
///     excuses nothing, and the figure it set is then held like every other);
///   * the ceiling was 0 at the base (a ceiling is SET from nothing; a rise from N stays refused);
///   * (a) every named detector is a detector key of that rule ([`MEASURABLE`]; never prose, a
///     ledger or a ceiling), the base carried it, and its value differs from the base's;
///   * (b) the figure equals the BASE re-measured with this tree's rule and the base's own
///     exemptions, never counting a stale one (`remeasure`): the sites it covers were all at the
///     base, newly seen, so it never covers a site this change adds;
///   * (c) the reason carries a `drain:` field that names a PR, a row or a file ([`names_a_ref`],
///     syntax only).
/// An entry that fails any condition is RED with every reason it fails, and excuses nothing; the
/// ledger is add-only against the base.
fn measured_ceilings(
    now_doc: &Document,
    base_doc: &Document,
    remeasure: &dyn Fn(&str, &str) -> Result<i64, String>,
) -> (BTreeSet<(String, String)>, Vec<String>) {
    let ledger = |doc: &Document| -> Vec<(String, String)> {
        let t = doc.table_or_empty(MEASURED);
        t.keys()
            .iter()
            .map(|k| {
                (
                    k.trim().trim_matches('"').to_string(),
                    t.str_of(k).unwrap_or_default().trim().to_string(),
                )
            })
            .collect()
    };
    let now = ledger(now_doc);
    let base = ledger(base_doc);
    let mut problems: Vec<String> = base
        .iter()
        .filter(|(b, _)| !now.iter().any(|(n, _)| n == b))
        .map(|(b, _)| {
            format!("[{MEASURED}] `{b}` was removed since the base; the ledger is add-only")
        })
        .collect();
    let mut out = BTreeSet::new();
    for (entry, value) in &now {
        if base.iter().any(|(b, _)| b == entry) {
            // Measured at an earlier base: the figure it set is that base's, held like any other.
            continue;
        }
        let Some((table, key)) = entry
            .rsplit_once('.')
            .filter(|(t, k)| t.starts_with("rules.") && !k.is_empty())
        else {
            problems.push(format!(
                "[{MEASURED}] `{entry}` names no `rules.<table>.<key>` ceiling"
            ));
            continue;
        };
        let rule = table.strip_prefix("rules.").unwrap_or(table);
        let MeasuredWhy { detectors, drain } = parse_measured(value);
        let mut wrong: Vec<String> = Vec::new();
        match drain.as_deref() {
            None => wrong.push(
                "its reason carries no `drain:` field (`<detector>, … -- <why>; drain: <PR, row \
                 or file>`)"
                    .to_string(),
            ),
            Some(r) if !names_a_ref(r) => wrong.push(format!(
                "its drain `{r}` names no PR (`#<n>`), status row (`row <n>`) or file"
            )),
            Some(_) => {}
        }
        let (Some(now_t), Some(base_t)) = (now_doc.table(table), base_doc.table(table)) else {
            wrong.push(format!(
                "the rule table [{table}] is not in both this tree and the base, so no detector \
                 change can be shown"
            ));
            problems.push(format!(
                "[{MEASURED}] `{entry}` excuses nothing: {}",
                wrong.join("; ")
            ));
            continue;
        };
        match base_t.int_of(key) {
            Some(0) => {}
            Some(b) => wrong.push(format!(
                "the ceiling was {b} at the base; a measured ceiling is SET from 0, and a rise \
                 from any figure is refused (Law 9)"
            )),
            None => wrong.push(format!(
                "the base carries no `{key}` in [{table}] for it to be SET from 0"
            )),
        }
        let matchers = detectors_of(rule);
        if matchers.is_none() {
            wrong.push(format!(
                "the census cannot re-measure [{table}] at the base (it re-measures {}), so no \
                 ceiling of it is set by measurement",
                MEASURABLE
                    .iter()
                    .map(|(r, _)| format!("[rules.{r}]"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if detectors.is_empty() {
            wrong.push(
                "it names no detector key: name the matcher this change widened (`<key>, <key> \
                 -- <why>; drain: <ref>`)"
                    .to_string(),
            );
        }
        for d in &detectors {
            if !matchers.is_some_and(|m| m.contains(&d.as_str())) {
                wrong.push(format!(
                    "`{d}` is not a detector key of [{table}] (prose, a ledger, a ceiling and a \
                     key the rule does not match with never count)"
                ));
            } else if base_t.get(d).is_none() {
                wrong.push(format!(
                    "detector `{d}` is new against the base: it did not change, it appeared"
                ));
            } else if now_t.get(d) == base_t.get(d) {
                wrong.push(format!("detector `{d}` did not change since the base"));
            }
        }
        match now_t.int_of(key) {
            None => wrong.push(format!("this tree carries no integer `{key}` in [{table}]")),
            Some(_) if matchers.is_none() => {}
            Some(set_to) => match remeasure(table, key) {
                Ok(at_base) if at_base == set_to => {}
                Ok(at_base) => wrong.push(format!(
                    "the base re-measured with this tree's rule counts {at_base} under `{key}` \
                     and the ceiling is set to {set_to}: a measured ceiling covers only debt the \
                     base already held, newly seen, so it must equal the base's re-measure"
                )),
                Err(e) => wrong.push(format!(
                    "the base could not be re-measured with this tree's rule, so no site is \
                     shown to pre-date this change: {e}"
                )),
            },
        }
        if wrong.is_empty() {
            out.insert((table.to_string(), key.to_string()));
        } else {
            problems.push(format!(
                "[{MEASURED}] `{entry}` excuses nothing: {}",
                wrong.join("; ")
            ));
        }
    }
    (out, problems)
}

/// The overlay key a self-test plants to answer `git diff --name-only <sha>` plus the untracked
/// files (see [`base_view`]): one path per line.
pub const DIFF_NAMES_KEY: &str = "git-diff-names";

/// The ceiling a re-measure probes a key with, to find the rows that key holds: no rule's real
/// ceiling is this figure.
const PROBE: i64 = 987_654_321;

/// THIS TREE AS THE BASE `sha` HAD IT, for every `.rs` file the scan reads: each path that differs
/// from the base (`git diff --name-only <sha>`, the untracked files, and every path the overlay
/// claims) is read back at the base, or made absent where the base has no such file. The rest of
/// the tree is the base's already.
fn base_view(cx: &Ctx, sha: &str) -> Result<Ctx, String> {
    let mut changed: BTreeSet<String> = BTreeSet::new();
    match cx.overlay_command(&format!("{DIFF_NAMES_KEY}:{sha}")) {
        Some(text) => changed.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string),
        ),
        None => {
            changed.extend(cx.git_lines(&["diff", "--name-only", "--no-renames", sha, "--"])?);
            changed.extend(cx.git_lines(&["ls-files", "--others", "--exclude-standard"])?);
        }
    }
    let mut ov = cx.overlay().cloned().unwrap_or_default();
    changed.extend(ov.paths().map(|p| p.to_string_lossy().replace('\\', "/")));
    for rel in changed.iter().filter(|r| r.ends_with(".rs")) {
        match cx.git_show(sha, rel) {
            Ok(text) => ov.set(rel, text),
            Err(_) => ov.remove(rel),
        }
    }
    Ok(cx.with_overlay(ov))
}

/// THE LEDGERS A RE-MEASURE READS AS THE BASE HAD THEM (ARCHITECT ruling on a6's third review of
/// #1454). An exemption this change writes names a store this change may have added: read with this
/// tree's list, a new store exempted here is a stale name at the base and is counted there, which
/// lets a second new store sit under the ceiling it set. Read with the base's list, the base's count
/// is the stores the base held that its own ledger did not name: debt already there.
const BASE_LEDGERS: &[&str] = &["exempt_stores"];

/// THE RULE TABLE A RE-MEASURE RUNS WITH: this tree's PARSED ceilings file with `table.key` set to
/// [`PROBE`] and each of [`BASE_LEDGERS`] set to the base's PARSED value (an empty list when the
/// base has none). Edited as values, never as text: a comment in the file (`exempt_stores = [ # ]
/// store_holds = ['.',`) is a comment to the parser, so no key can be smuggled into the re-measure.
/// And it FAILS CLOSED unless every other key of that table equals this tree's parsed value, so the
/// re-measure runs this tree's rule and nothing else.
fn probed_doc(
    now_doc: &Document,
    base_doc: &Document,
    table: &str,
    key: &str,
) -> Result<Document, String> {
    let now_t = now_doc
        .table(table)
        .ok_or_else(|| format!("this tree has no [{table}] to re-measure"))?;
    if now_t.int_of(key).is_none() {
        return Err(format!("[{table}] has no integer `{key}` to probe"));
    }
    let mut doc = now_doc.with_value(table, key, Value::Int(PROBE));
    for ledger in BASE_LEDGERS {
        let was = base_doc
            .table(table)
            .and_then(|t| t.get(ledger))
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        let strings = was
            .as_array()
            .is_some_and(|items| items.iter().all(|v| v.as_str().is_some()));
        if !strings {
            return Err(format!(
                "the base's [{table}] {ledger} is not a list of strings, so the base is not \
                 re-measured"
            ));
        }
        doc = doc.with_value(table, ledger, was);
    }
    let probed_t = doc
        .table(table)
        .ok_or_else(|| format!("[{table}] left the probed file"))?;
    let skipped = |k: &str| k == key || BASE_LEDGERS.contains(&k);
    let moved: Vec<&String> = probed_t
        .keys()
        .iter()
        .chain(now_t.keys().iter())
        .filter(|k| !skipped(k.as_str()) && probed_t.get(k) != now_t.get(k))
        .collect();
    if !moved.is_empty() {
        return Err(format!(
            "the re-measure's [{table}] differs from this tree's at {}, so it would not run this \
             tree's rule",
            moved
                .iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(doc)
}

/// THE BASE RE-MEASURED WITH THIS TREE'S RULE: `[table]`'s rule run over [`base_view`] with
/// [`probed_doc`] (this tree's parsed ceilings, the base's own exemptions), and the count of the
/// rows `key` holds (the most any one of them counts). A stale exemption is never counted: the base
/// is re-measured for the stores it HOLDS, not for names its ledger lost. Only the rules of
/// [`MEASURABLE`] are run; any other is an error, so nothing it would set is excused.
fn base_remeasure(
    cx: &Ctx,
    now_doc: &Document,
    sha: &str,
    base_doc: &Document,
    table: &str,
    key: &str,
) -> Result<i64, String> {
    let cfg = Cfg {
        doc: probed_doc(now_doc, base_doc, table, key)?,
    };
    let roots = cfg.scan_roots()?;
    let tree = Tree::load(&base_view(cx, sha)?, &roots, &cfg.test_path_fragments()?)?;
    let rows = match table.strip_prefix("rules.").unwrap_or(table) {
        "kernel-no-protocol-registry" => rules2::kernel_no_protocol_registry(&tree, &cfg)?,
        "unit-no-wall-clock" => rules2::unit_no_wall_clock(&tree, &cfg)?,
        other => return Err(format!("the census has no re-measure for [rules.{other}]")),
    };
    rows.iter()
        .filter(|r| r.threshold == PROBE)
        .map(|r| {
            let stale = r
                .offenders
                .iter()
                .filter(|o| o.starts_with("stale exemption "))
                .count();
            r.current - stale as i64
        })
        .max()
        .ok_or_else(|| format!("no row of [{table}] is held to `{key}`"))
}

/// THE LEDGER OF RULE TABLES STRUCK WITH THEIR SUBJECT: `[gate.census.deleted_rules]`.
const DELETED_RULES: &str = "gate.census.deleted_rules";

/// The keys a rule table names its subject by: a directory it scans, the crate it scans (read as
/// `crates/<name>`), or the one file it allows.
const SUBJECT_KEYS: &[&str] = &["root", "crate", "allowed_file"];

/// THE RULE TABLES WHOSE CEILINGS LEFT WITH THEIR SUBJECT, and every problem with the ledger that
/// names them. A rule table is struck only when ALL of these hold, so a ceiling never disappears
/// silently (Law 9):
///   * `[gate.census.deleted_rules]` names it, with a non-empty reason (the citation and the
///     measured value);
///   * the table is gone from this tree (an entry whose table still stands is stale);
///   * the base carried it, and it named its subject by at least one of [`SUBJECT_KEYS`];
///   * every subject path lies under a `[gate.census.deleted]` directory that is absent from the
///     tree (`gone`), so the rule would measure nothing: its subject is deleted, not moved.
///
/// The ledger is add-only against the base, as `[gate.census.deleted]` is. Every struck table's
/// sub-tables (`[rules.x.y]`) are struck with it. An entry that fails any condition is RED and
/// excuses nothing.
fn struck_rule_tables(
    now_doc: &Document,
    base_doc: &Document,
    gone: impl Fn(&str) -> bool,
) -> (BTreeSet<String>, Vec<String>) {
    let ledger = |doc: &Document| -> Vec<(String, String)> {
        let t = doc.table_or_empty(DELETED_RULES);
        t.keys()
            .iter()
            .map(|k| {
                (
                    k.trim().trim_matches('"').to_string(),
                    t.str_of(k).unwrap_or_default().trim().to_string(),
                )
            })
            .collect()
    };
    let now = ledger(now_doc);
    let base = ledger(base_doc);
    let mut problems: Vec<String> = base
        .iter()
        .filter(|(b, _)| !now.iter().any(|(n, _)| n == b))
        .map(|(b, _)| {
            format!("[{DELETED_RULES}] `{b}` was removed since the base; the ledger is add-only")
        })
        .collect();
    let mut struck = BTreeSet::new();
    for (table, why) in &now {
        if why.is_empty() {
            problems.push(format!(
                "[{DELETED_RULES}] `{table}` gives no reason: name what was deleted, the status \
                 row and the measured value"
            ));
            continue;
        }
        if now_doc.table(table).is_some() {
            problems.push(format!(
                "[{DELETED_RULES}] `{table}` is listed but the table is still in this tree \
                 (stale entry)"
            ));
            continue;
        }
        if base.iter().any(|(b, _)| b == table) {
            // Struck at an earlier base and held there; nothing of it is left to compare.
            struck.insert(table.clone());
            continue;
        }
        let Some(was) = base_doc.table(table) else {
            problems.push(format!(
                "[{DELETED_RULES}] `{table}` names no table the base carried"
            ));
            continue;
        };
        let subjects: Vec<String> = SUBJECT_KEYS
            .iter()
            .filter_map(|k| {
                was.str_of(k).map(|v| match *k {
                    "crate" => format!("crates/{v}"),
                    _ => v.trim_end_matches('/').to_string(),
                })
            })
            .collect();
        if subjects.is_empty() {
            problems.push(format!(
                "[{DELETED_RULES}] `{table}` named no subject path at the base, so nothing shows \
                 its subject is gone"
            ));
            continue;
        }
        let live: Vec<&String> = subjects
            .iter()
            .filter(|p| !under_a_gone_dir(p, &gone))
            .collect();
        if !live.is_empty() {
            problems.push(format!(
                "[{DELETED_RULES}] `{table}`: its subject {} is not under a deleted directory \
                 in [gate.census.deleted] that is gone from the tree, so its ceiling did not \
                 leave with it",
                live.iter()
                    .map(|p| format!("`{p}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            continue;
        }
        struck.insert(table.clone());
    }
    let subs: Vec<String> = base_doc
        .tables()
        .into_iter()
        .map(|(p, _)| p.to_string())
        .filter(|p| struck.iter().any(|t| p.starts_with(&format!("{t}."))))
        .collect();
    struck.extend(subs);
    (struck, problems)
}

/// Whether `path` is, or lies under, a directory `gone` accepts (ledgered and absent).
fn under_a_gone_dir(path: &str, gone: impl Fn(&str) -> bool) -> bool {
    let mut at = path;
    loop {
        if gone(at) {
            return true;
        }
        match at.rfind('/') {
            Some(i) => at = &at[..i],
            None => return false,
        }
    }
}

/// Every integer under `[gate.census]`, including its `plugin_kinds` sub-table, by dotted key.
fn census_pins(doc: &Document) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    for (path, t) in doc.tables() {
        let rest = if path == "gate.census" {
            String::new()
        } else if let Some(r) = path.strip_prefix("gate.census.") {
            format!("{r}.")
        } else {
            continue;
        };
        for key in t.keys() {
            if let Some(v) = t.int_of(key) {
                out.insert(format!("{rest}{key}"), v);
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "census_moveout_tests.rs"]
mod moveout_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// RED: A PINNED PLANE IS COUNTED FROM ITS CHECKOUT. A plane extracted to its own repo is laid
    /// into the tree by the BASE layer only (ARCHITECT row 106 (A)); the kind census counted
    /// directories with a disk-only `is_dir`, so `plane` matched 3 of its 5 crates and the floor
    /// went red on a tree that had lost nothing. A census that silently stops seeing pinned planes
    /// is the fault this gate exists to catch, so the base-only plane must count.
    #[test]
    fn a_pinned_plane_present_only_in_the_base_layer_is_counted() {
        let cx = Ctx::workspace().expect("workspace").without_base();
        let cfg = crate::gates::construction::ConstructionGate::cfg(&cx).expect("ceilings");
        let globs = cfg.kind_globs("plane").expect("the plane kind");
        let probe = "crates/busbar-plane-mcp".to_string();
        assert!(
            globs.contains(&probe),
            "the control needs {probe} in [gate.plugin_kinds] plane: {globs:?}"
        );
        assert!(
            !cx.abs(&probe).exists(),
            "the control needs a plane that is not on disk"
        );
        let bare = dirs_for_globs(&cx, &globs);
        assert!(!bare.contains(&probe), "{probe} counted with no base");
        let mut base = crate::ctx::Overlay::new();
        base.set(
            format!("{probe}/Cargo.toml"),
            "[package]\nname = \"busbar-plane-mcp\"\n",
        );
        base.set(format!("{probe}/src/lib.rs"), "");
        let laid = dirs_for_globs(&cx.with_base(base), &globs);
        assert!(
            laid.contains(&probe),
            "a plane laid only by the base layer is not counted: {laid:?}"
        );
        assert_eq!(laid.len(), bare.len() + 1, "{laid:?} against {bare:?}");
    }

    const DOC: &str = "[gate.census]\nplane_crates = 4\n\n[gate.census.plugin_kinds]\nplane = 5\n";

    #[test]
    fn every_census_pin_is_read_including_the_sub_table() {
        let pins = census_pins(&crate::toml_doc::parse_str(DOC).expect("the fixture parses"));
        assert_eq!(pins.get("plane_crates"), Some(&4));
        assert_eq!(pins.get("plugin_kinds.plane"), Some(&5));
        assert_eq!(pins.len(), 2);
    }

    /// A pin outside `[gate.census]` is not a census pin: the base comparison must not start
    /// scoring every other integer in the ceilings file.
    #[test]
    fn an_integer_outside_the_census_table_is_not_a_census_pin() {
        let pins = census_pins(
            &crate::toml_doc::parse_str("[gate]\nplane_crates = 4\n[rules.x]\nn = 1\n")
                .expect("the fixture parses"),
        );
        assert!(pins.is_empty());
    }

    fn doc(s: &str) -> Document {
        crate::toml_doc::parse_str(s).expect("the fixture parses")
    }

    /// THE SECOND HALF OF THE ATTACK. Deleting a `[rules.legacy-reach.prefixes.*]` table is caught
    /// by the floor; deleting it AND dropping the floor in the same edit is caught only here.
    #[test]
    fn a_census_floor_that_went_down_is_red() {
        let out = lowered_floors(
            &doc(&DOC.replace("plane_crates = 4", "plane_crates = 3")),
            &doc(DOC),
            "abc1234",
            &BTreeMap::new(),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            out[0].contains("plane_crates: the floor itself went 4 -> 3"),
            "{out:?}"
        );
    }

    /// Deleting the KEY is the cheapest way to lower a floor, so an absent key is a drop to zero
    /// rather than a comparison that never happens.
    #[test]
    fn a_census_floor_that_was_deleted_outright_is_red() {
        let out = lowered_floors(
            &doc("[gate.census]\nplane_crates = 4\n"),
            &doc(DOC),
            "abc1234",
            &BTreeMap::new(),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            out[0].contains("plugin_kinds.plane: the floor itself went 5 -> 0"),
            "{out:?}"
        );
    }

    /// THE RULED WAY DOWN FOR `plane_crates` (P3 DEL-MCP): a legacy engine deleted under
    /// `[gate.census.deleted]` excuses exactly its own drop — 4 -> 3 with one deleted entry is not a
    /// finding, 4 -> 2 still is.
    #[test]
    fn a_plane_crates_drop_is_excused_only_by_its_deleted_entries() {
        let one = BTreeMap::from([("plane_crates".to_string(), 1)]);
        let to3 = doc(&DOC.replace("plane_crates = 4", "plane_crates = 3"));
        assert!(lowered_floors(&to3, &doc(DOC), "abc1234", &one).is_empty());
        let to2 = doc(&DOC.replace("plane_crates = 4", "plane_crates = 2"));
        let out = lowered_floors(&to2, &doc(DOC), "abc1234", &one);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            out[0].contains("plane_crates: the floor itself went 4 -> 2"),
            "{out:?}"
        );
    }

    /// Raising a floor, and adding a new one, are the ordinary direction and are not findings.
    #[test]
    fn a_floor_that_rose_or_appeared_is_not_a_finding() {
        let grown =
            format!("{DOC}egress_auth = 0\n").replace("plane_crates = 4", "plane_crates = 9");
        assert!(lowered_floors(&doc(&grown), &doc(DOC), "abc1234", &BTreeMap::new()).is_empty());
    }

    /// A RETIRED PIN IS NOT A LOWERED FLOOR. The base still carries `loc_ceilings_kernel_files`
    /// (the LOC tables the owner deleted); the tree does not. That is the one key the comparison
    /// skips, and a live key dropped in the same edit is still red.
    #[test]
    fn a_retired_pin_leaving_is_not_a_lowered_floor_and_a_live_one_still_is() {
        let base = DOC.replace(
            "[gate.census]\nplane_crates = 4\n",
            "[gate.census]\nplane_crates = 4\nloc_ceilings_kernel_files = 8\n",
        );
        assert!(lowered_floors(&doc(DOC), &doc(&base), "abc1234", &BTreeMap::new()).is_empty());
        let out = lowered_floors(
            &doc(&DOC.replace("plane_crates = 4", "plane_crates = 3")),
            &doc(&base),
            "abc1234",
            &BTreeMap::new(),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("plane_crates"), "{out:?}");
    }

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_listed_and_gone_directory_is_excused() {
        let gone = vec!["crates/hook-test-plugin".to_string()];
        let deleted = set(&["crates/hook-test-plugin"]);
        let n = excused_out(&gone, |_| false, |d| deleted.contains(d));
        assert_eq!(n, Some(1));
        assert!(deleted_ledger_findings(&deleted, &deleted, |_| false).is_empty());
    }

    #[test]
    fn an_unlisted_vanished_directory_is_red() {
        let gone = vec!["crates/hook-test-plugin".to_string()];
        let deleted = set(&[]);
        assert_eq!(excused_out(&gone, |_| false, |d| deleted.contains(d)), None);
        let out = lowered_floors(
            &doc(&DOC.replace("plane = 5", "plane = 4")),
            &doc(DOC),
            "abc1234",
            &BTreeMap::new(),
        );
        assert_eq!(out.len(), 1, "{out:?}");
    }

    #[test]
    fn a_listed_but_present_directory_is_red() {
        let deleted = set(&["crates/hook-test-plugin"]);
        let out = deleted_ledger_findings(&deleted, &deleted, |_| true);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("stale entry"), "{out:?}");
    }

    #[test]
    fn an_entry_removed_versus_the_base_is_red() {
        let out = deleted_ledger_findings(&set(&[]), &set(&["crates/hook-test-plugin"]), |_| false);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("add-only"), "{out:?}");
    }

    #[test]
    fn the_deleted_table_is_read_from_the_document() {
        let d = doc("[gate.census.deleted]\n\"crates/x\" = \"why\"\n");
        assert_eq!(deleted_ledger(&d), set(&["crates/x"]));
    }

    #[test]
    fn an_excused_drop_by_exactly_the_count_is_green_and_one_more_is_red() {
        let moved: BTreeMap<String, i64> = [("plugin_kinds.plane".to_string(), 1)].into();
        let down1 = DOC.replace("plane = 5", "plane = 4");
        assert!(lowered_floors(&doc(&down1), &doc(DOC), "abc1234", &moved).is_empty());
        let down2 = DOC.replace("plane = 5", "plane = 3");
        assert_eq!(
            lowered_floors(&doc(&down2), &doc(DOC), "abc1234", &moved).len(),
            1
        );
    }

    const RULE_BASE: &str = "[rules.a]\nroot = \"crates/gone/src/unit\"\nmax_escapes = 0\n\n\
                             [rules.b]\ncrate = \"gone\"\nallowed_file = \"crates/gone/src/x.rs\"\n\
                             max_extra_sites = 0\n\n[rules.c]\nroot = \"crates/kept\"\nmax_hits = 0\n";

    fn gone_dir(d: &str) -> bool {
        d == "crates/gone"
    }

    /// A ceiling never disappears silently (Law 9): a rule table deleted with no ledger entry is a
    /// deleted ceiling and stays RED, and so is one whose entry gives no reason.
    #[test]
    fn a_rule_table_deleted_without_a_ledger_entry_is_still_a_raised_ceiling() {
        let now = doc("[rules.c]\nroot = \"crates/kept\"\nmax_hits = 0\n");
        let (struck, problems) = struck_rule_tables(&now, &doc(RULE_BASE), gone_dir);
        assert!(
            struck.is_empty() && problems.is_empty(),
            "{struck:?} {problems:?}"
        );
        let none = BTreeSet::new();
        let out = raised_ceilings(&now, &doc(RULE_BASE), "abc1234", &[], &struck, &none);
        assert_eq!(out.len(), 2, "{out:?}");
        let blank = doc("[gate.census.deleted_rules]\n\"rules.a\" = \"\"\n");
        let (struck, problems) = struck_rule_tables(&blank, &doc(RULE_BASE), gone_dir);
        assert!(struck.is_empty(), "{struck:?}");
        assert!(problems[0].contains("gives no reason"), "{problems:?}");
    }

    /// THE RULED WAY OUT: a table named in the ledger whose every subject path lies under a deleted,
    /// absent directory leaves with its subject, and only that table.
    #[test]
    fn a_rule_table_whose_subject_was_deleted_is_struck_by_its_ledger_entry() {
        let now = doc(
            "[gate.census.deleted_rules]\n\"rules.a\" = \"row 83, measured 0\"\n\
             \"rules.b\" = \"row 83, measured 0\"\n\n[rules.c]\nroot = \"crates/kept\"\nmax_hits = 0\n",
        );
        let (struck, problems) = struck_rule_tables(&now, &doc(RULE_BASE), gone_dir);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(struck, set(&["rules.a", "rules.b"]));
        let none = BTreeSet::new();
        let out = raised_ceilings(&now, &doc(RULE_BASE), "abc1234", &[], &struck, &none);
        assert!(out.is_empty(), "{out:?}");
    }

    /// A ledger entry for a table whose subject is still in the tree excuses nothing, and neither
    /// does one whose table still stands.
    #[test]
    fn a_ledger_entry_whose_subject_lives_or_whose_table_stands_is_red() {
        let now = doc(
            "[gate.census.deleted_rules]\n\"rules.c\" = \"row 83\"\n\"rules.a\" = \"row 83\"\n\n\
             [rules.a]\nroot = \"crates/gone/src/unit\"\nmax_escapes = 0\n",
        );
        let (struck, problems) = struck_rule_tables(&now, &doc(RULE_BASE), gone_dir);
        assert!(struck.is_empty(), "{struck:?}");
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems
            .iter()
            .any(|p| p.contains("`rules.a` is listed but the table is still")));
        assert!(problems
            .iter()
            .any(|p| p.contains("`crates/kept` is not under a deleted")));
    }

    /// The ledger is add-only against the base.
    #[test]
    fn a_rule_ledger_entry_removed_since_the_base_is_red() {
        let base = format!("{RULE_BASE}\n[gate.census.deleted_rules]\n\"rules.z\" = \"row 1\"\n");
        let (_, problems) = struck_rule_tables(&doc(RULE_BASE), &doc(&base), gone_dir);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("add-only"), "{problems:?}");
    }

    const DEBT_BASE: &str = "[rules.kernel-no-protocol-registry]\nwhy = \"the kernel holds no \
                             registry\"\nstore_cells = [\"OnceLock\"]\nmax_hits = 0\nmax_debt = 0\n";
    const DEBT_WIDER: &str = "[rules.kernel-no-protocol-registry]\nwhy = \"the kernel holds no \
                              registry\"\nstore_cells = [\"OnceLock\", \"RefCell\"]\nmax_hits = \
                              0\nmax_debt = 4\n";
    const MEASURED_ROW: &str = "[gate.census.measured]\n\"rules.kernel-no-protocol-registry.\
                                max_debt\" = \"store_cells -- four sites the wider cells first \
                                see; drain: status row 82\"\n";

    /// The ceilings judged against the base, with the base re-measured at `at_base`.
    fn rises_at(now: &str, base: &str, at_base: i64) -> (Vec<String>, Vec<String>) {
        let (measured, problems) = measured_ceilings(&doc(now), &doc(base), &|_, _| Ok(at_base));
        let out = raised_ceilings(
            &doc(now),
            &doc(base),
            "abc1234",
            &[],
            &BTreeSet::new(),
            &measured,
        );
        (out, problems)
    }

    /// The same, with the base re-measuring exactly the four sites the fixture sets.
    fn rises(now: &str, base: &str) -> (Vec<String>, Vec<String>) {
        rises_at(now, base, 4)
    }

    /// RED: a plain rise of a debt ceiling from 0 is refused (Law 9), detector widened or not.
    #[test]
    fn a_plain_rise_from_zero_is_still_refused() {
        let (out, problems) = rises(DEBT_WIDER, DEBT_BASE);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("0 -> 4"), "{out:?}");
    }

    /// THE RULED WAY IN (#1454, the #1418 MINTED precedent): SET from 0, in the change whose
    /// detector first sees the debt, at exactly the base's re-measure, with its entry naming the
    /// widened matcher and a drain that names a row.
    #[test]
    fn a_ceiling_set_from_zero_with_its_detector_change_is_green() {
        let (out, problems) = rises(&format!("{DEBT_WIDER}\n{MEASURED_ROW}"), DEBT_BASE);
        assert!(
            problems.is_empty() && out.is_empty(),
            "{problems:?} {out:?}"
        );
    }

    /// RED: the entry with no detector change, from a figure other than 0, or carried by the base
    /// excuses nothing; nor does a ledger key named as its detector.
    #[test]
    fn a_measured_entry_without_its_detector_change_or_from_n_or_at_the_base_is_red() {
        let same = DEBT_WIDER.replace(", \"RefCell\"", "");
        let (out, problems) = rises(&format!("{same}\n{MEASURED_ROW}"), DEBT_BASE);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(problems[0].contains("did not change"), "{problems:?}");

        let from_two = DEBT_BASE.replace("max_debt = 0", "max_debt = 2");
        let (out, problems) = rises(&format!("{DEBT_WIDER}\n{MEASURED_ROW}"), &from_two);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(problems[0].contains("SET from 0"), "{problems:?}");

        let next_base = format!(
            "{}\n{MEASURED_ROW}",
            DEBT_BASE.replace("max_debt = 0", "max_debt = 4")
        );
        let more = DEBT_WIDER.replace("max_debt = 4", "max_debt = 5");
        let (out, problems) = rises(&format!("{more}\n{MEASURED_ROW}"), &next_base);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(out.len() == 1 && out[0].contains("4 -> 5"), "{out:?}");

        let ledger_only = format!(
            "{DEBT_WIDER}\n{}",
            MEASURED_ROW.replacen("store_cells --", "debt_stores --", 1)
        );
        let (out, problems) = rises(&ledger_only, DEBT_BASE);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(problems[0].contains("not a detector key"), "{problems:?}");
    }

    /// RED (a6's second review of #1454, abuse 1): a word added to the rule's `why` is not a
    /// detector change, and a reason that only mentions draining names no drain.
    #[test]
    fn a_prose_key_named_as_the_detector_excuses_nothing() {
        let now = DEBT_WIDER
            .replace(", \"RefCell\"", "")
            .replace("holds no registry", "holds no planted registry");
        let entry = "[gate.census.measured]\n\"rules.kernel-no-protocol-registry.max_debt\" = \
                     \"why -- nobody will drain this\"\n";
        let (out, problems) = rises(&format!("{now}\n{entry}"), DEBT_BASE);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            problems[0].contains("`why` is not a detector key"),
            "{problems:?}"
        );
        assert!(problems[0].contains("no `drain:` field"), "{problems:?}");
    }

    /// RED (abuse 2): a key new against the base is not a detector that changed, and the word
    /// `drain` with no field after it names nothing.
    #[test]
    fn a_key_new_against_the_base_excuses_nothing() {
        let now = DEBT_WIDER
            .replace(", \"RefCell\"", "")
            .replace("max_hits = 0", "max_hits = 0\nzz_unused = \"x\"");
        let entry = "[gate.census.measured]\n\"rules.kernel-no-protocol-registry.max_debt\" = \
                     \"zz_unused -- drain\"\n";
        let (out, problems) = rises(&format!("{now}\n{entry}"), DEBT_BASE);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            problems[0].contains("`zz_unused` is not a detector key"),
            "{problems:?}"
        );
        assert!(problems[0].contains("no `drain:` field"), "{problems:?}");
        // A real detector key the base did not carry appeared; it did not change.
        let holds = "store_holds = [\"Vec\"]\n";
        let now = format!("{DEBT_WIDER}{holds}").replace(", \"RefCell\"", "");
        let entry = MEASURED_ROW.replace("store_cells --", "store_holds --");
        let (out, problems) = rises(&format!("{now}\n{entry}"), DEBT_BASE);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            problems[0].contains("`store_holds` is new against the base"),
            "{problems:?}"
        );
    }

    /// RED (abuse 3): a real detector changed, but the ceiling covers a site the base did not
    /// hold (the base re-measures 0), and `drain: soon` names no PR, row or file.
    #[test]
    fn a_ceiling_over_the_base_re_measure_excuses_nothing() {
        let now = DEBT_WIDER
            .replace("max_debt = 4", "max_debt = 0")
            .replace("max_hits = 0", "max_hits = 1");
        let entry = "[gate.census.measured]\n\"rules.kernel-no-protocol-registry.max_hits\" = \
                     \"store_cells -- a new cell; drain: soon\"\n";
        let (out, problems) = rises_at(&format!("{now}\n{entry}"), DEBT_BASE, 0);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("max_hits"), "{out:?}");
        assert!(
            problems[0].contains("counts 0 under `max_hits`"),
            "{problems:?}"
        );
        assert!(
            problems[0].contains("drain `soon` names no"),
            "{problems:?}"
        );
        // And a figure under the base's re-measure is no more the measured count than one over.
        let (_, problems) = rises_at(&format!("{DEBT_WIDER}\n{MEASURED_ROW}"), DEBT_BASE, 5);
        assert!(
            problems[0].contains("counts 5 under `max_debt`"),
            "{problems:?}"
        );
        // A base that cannot be re-measured shows no site pre-dates the change.
        let (measured, problems) = measured_ceilings(
            &doc(&format!("{DEBT_WIDER}\n{MEASURED_ROW}")),
            &doc(DEBT_BASE),
            &|_, _| Err("planted".to_string()),
        );
        assert!(measured.is_empty(), "{measured:?}");
        assert!(
            problems[0].contains("could not be re-measured"),
            "{problems:?}"
        );
    }

    /// RED: an entry renamed, or removed and written again under another key, is a removal from an
    /// add-only ledger; and a rule the census cannot re-measure sets no ceiling by measurement.
    #[test]
    fn a_renamed_entry_or_an_unmeasurable_rule_excuses_nothing() {
        let base = format!("{DEBT_BASE}\n{MEASURED_ROW}");
        let renamed = MEASURED_ROW.replace(".max_debt", ".max_debts");
        let (measured, problems) = measured_ceilings(
            &doc(&format!("{DEBT_WIDER}\n{renamed}")),
            &doc(&base),
            &|_, _| Ok(4),
        );
        assert!(measured.is_empty(), "{measured:?}");
        assert!(
            problems.iter().any(|p| p.contains("add-only")),
            "{problems:?}"
        );

        let other = "[rules.lean-core]\nwords = [\"a\"]\nmax_hits = 0\n";
        let wider = "[rules.lean-core]\nwords = [\"a\", \"b\"]\nmax_hits = 2\n\
                     [gate.census.measured]\n\"rules.lean-core.max_hits\" = \"words -- two; \
                     drain: #1454\"\n";
        let (out, problems) = rises_at(wider, other, 2);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(problems[0].contains("cannot re-measure"), "{problems:?}");
    }

    /// The base's ledger replaces this tree's in a re-measure ON THE PARSED DOCUMENT: a `]` in a
    /// comment closes nothing (a6's third review: `exempt_stores = [ # ] store_holds = ['.',`), and
    /// every other key of the table is this tree's.
    #[test]
    fn a_ledger_is_replaced_on_the_parsed_document_and_nothing_else_moves() {
        let now = doc(
            "[rules.k]\nwhy = \"x\"\nstore_holds = ['Vec']\nexempt_stores = [ # ] store_holds = \
             ['.',\n  \"new [u8] ]\",\n]\nmax_stores = 13\n",
        );
        let base = doc("[rules.k]\nstore_holds = ['Vec']\nexempt_stores = [\"was\"]\n");
        let t = now.table("rules.k").expect("k");
        assert_eq!(t.list_of("store_holds"), vec!["Vec"]);
        assert_eq!(t.list_of("exempt_stores"), vec!["new [u8] ]"]);
        let probed = probed_doc(&now, &base, "rules.k", "max_stores").expect("probed");
        let p = probed.table("rules.k").expect("k");
        assert_eq!(p.int_of("max_stores"), Some(PROBE));
        assert_eq!(p.list_of("exempt_stores"), vec!["was"]);
        assert_eq!(p.list_of("store_holds"), vec!["Vec"]);
        assert_eq!(p.str_of("why"), Some("x"));
        // A base with no ledger is an empty one; a base ledger that is not a list is refused.
        let bare = probed_doc(&now, &doc("[rules.k]\n"), "rules.k", "max_stores").expect("bare");
        assert!(bare
            .table("rules.k")
            .expect("k")
            .list_of("exempt_stores")
            .is_empty());
        let odd = doc("[rules.k]\nexempt_stores = 3\n");
        assert!(probed_doc(&now, &odd, "rules.k", "max_stores").is_err());
        assert!(probed_doc(&now, &base, "rules.k", "max_debt").is_err());
        assert!(probed_doc(&now, &base, "rules.y", "max_stores").is_err());
    }

    /// The drain field names a PR, a row or a file, and nothing else is one.
    #[test]
    fn a_drain_names_a_pr_a_row_or_a_file() {
        for good in [
            "#1454",
            "status row 82",
            "Row 159 drain lanes",
            "crates/busbar-kernel/src/preflight.rs",
        ] {
            assert!(names_a_ref(good), "{good}");
        }
        for bad in [
            "soon",
            "",
            "lane-d2-drain-installed-doors",
            "arrow 5",
            "a/b",
            "#x",
        ] {
            assert!(!names_a_ref(bad), "{bad}");
        }
        assert_eq!(
            parse_measured("a -- b; drain: #1").drain.as_deref(),
            Some("#1")
        );
        assert_eq!(parse_measured("a -- will drain soon").drain, None);
    }
}
