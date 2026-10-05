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

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::gates::construction::ceilings::base_ref;
use crate::gates::construction::model::{plain, py_list, CRow, Cfg};
use crate::gates::construction::{dirs_for_globs, CEILINGS};
use crate::toml_doc::Document;

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
    if let Ok(base) = base_ref(cx) {
        if let Ok(was) = cx.git_show(&base.sha, CEILINGS) {
            if let Ok(doc) = crate::toml_doc::parse_str(&was) {
                let base_deleted = deleted_ledger(&doc);
                let now_deleted = deleted_ledger(&cfg.doc);
                bad.extend(deleted_ledger_findings(&now_deleted, &base_deleted, |d| {
                    cx.abs(d).exists()
                }));
                let moved = moved_out_by_kind(cx, cfg, &doc, &base.sha, &now_deleted);
                bad.extend(lowered_floors(&cfg.doc, &doc, base.short(), &moved));
            }
        }
    }

    if bad.is_empty() {
        return vec![plain(
            ROW_CENSUS,
            true,
            TITLE,
            format!(
                "{counted} rule-table, plane-crate and kind-glob subject(s) counted, none below \
                 its pinned floor"
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
/// directories that left the tree as MOVED-OUT plugins or ruled deletions ([`excused_out`]). Every other drop is RED.
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
            |dir| moved_out(&[dir.to_string()], package_at_base, &root_manifest).is_some(),
            |dir| deleted.contains(dir) && !cx.abs(dir).exists(),
        ) {
            out.insert(format!("plugin_kinds.{kind}"), n as i64);
        }
    }
    out
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
/// dependency at a `rev`; `None` when any one is not (deleted, renamed, or pulled by branch), and
/// for an empty `gone`.
fn moved_out(
    gone: &[String],
    package_at_base: impl Fn(&str) -> Option<String>,
    root_manifest: &str,
) -> Option<usize> {
    if gone.is_empty() {
        return None;
    }
    gone.iter()
        .all(|dir| {
            package_at_base(dir).is_some_and(|name| {
                crate::gates::workspace_deps::pinned_git_dep(root_manifest, &name)
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

/// The directories the globs `globs` matched at commit `sha`: each glob's parent listed at that
/// commit (`git ls-tree -d`), kept where the glob matches.
fn base_dirs(cx: &Ctx, sha: &str, globs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for g in globs {
        let parent = g.rsplit_once('/').map_or(".", |(p, _)| p);
        let listed = cx
            .git_lines(&["ls-tree", "-d", "--name-only", sha, &format!("{parent}/")])
            .unwrap_or_default();
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
}
