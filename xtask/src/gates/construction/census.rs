//! `ceiling-census` — THE RATCHET ON THE RATCHETS.
//!
//! `owed()` is derived from the SAME `Cfg` the rules read. Delete
//! `[rules.loc-ceilings.kernel_files.arena]` and both the check and the obligation to run it vanish
//! in one edit — measured: 112 rows became 111 and nothing complained, and the kernel's
//! arena/masking LOC ceiling simply stopped being measured. `rules.legacy-reach.prefixes.*` and
//! `gate.plane_crates` have the same shape, and so does every `[gate.plugin_kinds]` glob: narrow
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
/// AND THE FLOOR ITSELF IS PINNED AGAINST THE BASE, which is the half that makes it hold. Lowering
/// a floor is not something `ceiling-rose` sees — that row watches numbers going UP — so without
/// this, deleting a rule table and dropping its census number in the same edit would be exactly as
/// silent as deleting the table alone was. A census floor lower than it was at the base is RED.
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
            pin_key: "loc_ceilings_kernel_files",
            what: "[rules.loc-ceilings.kernel_files] entries",
            actual: cfg.doc.children("rules.loc-ceilings.kernel_files").len(),
        },
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
        let globs = cfg.kind_globs(key);
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

    // ── the retirements, and the floors themselves against the base ──────────────────────────────
    let (retired, mut retired_bad) = retirements(&cfg.doc);
    // A RETIREMENT EXPIRES WITH THE DELETION IT RECORDS. A row naming a crate that is still in the
    // tree has not retired anything: it is a lowered floor bought in advance, which is the same
    // manoeuvre the floor exists to refuse, one row further back.
    for r in &retired {
        if cx.exists(format!("crates/{}", r.krate)) {
            retired_bad.push(format!(
                "[[gate.census_retired]] names `{}` (retired in {}) and crates/{} is still in \
                 this tree. The row admits a census floor going down BECAUSE a crate was deleted; \
                 while the crate is there, nothing was retired and the floor has no reason to \
                 have moved",
                r.krate, r.commit, r.krate
            ));
        }
    }
    bad.extend(retired_bad);
    if let Ok(base) = base_ref(cx) {
        if let Ok(was) = cx.git_show(&base, CEILINGS) {
            if let Ok(doc) = crate::toml_doc::parse_str(&was) {
                bad.extend(lowered_floors(
                    &cfg.doc,
                    &doc,
                    &base[..base.len().min(10)],
                    &retired,
                ));
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
/// census number" is one edit and is exactly as silent as deleting the table alone was — because
/// `ceiling-rose`, the only other thing reading these numbers, watches for numbers going UP.
///
/// A floor the base carried and this tree does not is scored as a drop to 0, not skipped: deleting
/// the KEY is the cheapest way to lower it.
///
/// A separate function from [`ceiling_census`] because the base is real git history, and the one
/// property that most needs a test is the one a branch cannot stage — until this table lands on the
/// integration line, no base commit carries it.
fn lowered_floors(
    now_doc: &Document,
    base_doc: &Document,
    short: &str,
    retired: &[Retired],
) -> Vec<String> {
    let now = census_pins(now_doc);
    census_pins(base_doc)
        .into_iter()
        .filter_map(|(k, before)| {
            let after = now.get(&k).copied().unwrap_or(0);
            if after >= before {
                return None;
            }
            // THE ONE THING THAT ADMITS A LOWERED FLOOR, and it admits exactly this drop: the row
            // names the crate whose deletion caused it, the commit that deleted it, the floor, and
            // both numbers. A drop of two under a row that says one is not this row's drop.
            if retired
                .iter()
                .any(|r| r.floor == k && r.from == before && r.to == after)
            {
                return None;
            }
            Some(format!(
                "[gate.census] {k}: the floor itself went {before} -> {after} since the base \
                 {short}. `ceiling-rose` watches numbers going UP; lowering a census floor is how a \
                 deleted rule table would be made to look accounted for. A floor that went down \
                 because a CRATE was deleted says so in a `[[gate.census_retired]]` row — `crate`, \
                 `commit`, `floor = \"{k}\"`, `from = {before}`, `to = {after}` — and nothing else \
                 lowers one"
            ))
        })
        .collect()
}

/// One `[[gate.census_retired]]` row: THE ONLY THING THAT LOWERS A CENSUS FLOOR.
///
/// Deleting a legacy crate is the work 1.6.0 exists to do, and every deletion drops a census count:
/// `gate.plane_crates` loses an entry, `rules.legacy-reach.prefixes` loses a prefix, a kind glob
/// matches one directory fewer. The floor is what refuses that, correctly — "delete the rule table
/// and drop its number in the same edit" is exactly the manoeuvre it was built for, and it cannot
/// tell that edit apart from a retirement by looking at the numbers.
///
/// A NAME CAN. The row says which crate went, in which commit, which floor moved and from what to
/// what, and it is checked four ways: the crate must be GONE from the tree, the floor named must be
/// the floor that moved, the `from` must be the number the BASE carried, and the drop must be
/// EXACTLY ONE. A retirement deletes one crate; a row that lowers a floor by two is two retirements
/// under one sentence, and the second one is the one nobody read.
struct Retired {
    krate: String,
    commit: String,
    floor: String,
    from: i64,
    to: i64,
}

/// Every `[[gate.census_retired]]` row, and every row that could not be read as one.
fn retirements(doc: &Document) -> (Vec<Retired>, Vec<String>) {
    let mut rows = Vec::new();
    let mut bad = Vec::new();
    for (i, t) in doc
        .array_of_tables("gate.census_retired")
        .iter()
        .enumerate()
    {
        let at = i + 1;
        let (Some(krate), Some(commit), Some(floor), Some(from), Some(to)) = (
            t.str_of("crate").filter(|v| !v.is_empty()),
            t.str_of("commit").filter(|v| !v.is_empty()),
            t.str_of("floor").filter(|v| !v.is_empty()),
            t.int_of("from"),
            t.int_of("to"),
        ) else {
            bad.push(format!(
                "[[gate.census_retired]] #{at} is missing one of `crate`, `commit`, `floor`, \
                 `from`, `to`. A row nobody can read is not a retirement, and a half-read row that \
                 was skipped would be a floor lowered by nothing"
            ));
            continue;
        };
        if to != from - 1 {
            bad.push(format!(
                "[[gate.census_retired]] `{krate}`: `from = {from}`, `to = {to}` — a retirement \
                 deletes ONE crate, so it lowers its floor by exactly one. A row that lowers it by \
                 {} is that many retirements under one sentence, and only the first was read",
                from - to
            ));
            continue;
        }
        rows.push(Retired {
            krate: krate.to_string(),
            commit: commit.to_string(),
            floor: floor.to_string(),
            from,
            to,
        });
    }
    (rows, bad)
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
    /// scoring every other integer in the ceilings file, which is `ceiling-rose`'s job and has the
    /// opposite direction.
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

    /// THE SECOND HALF OF THE ATTACK. Deleting `[rules.loc-ceilings.kernel_files.arena]` is caught
    /// by the floor; deleting it AND dropping the floor from 9 to 8 in the same edit is caught only
    /// here. `ceiling-rose` cannot: it watches numbers going up.
    #[test]
    fn a_census_floor_that_went_down_is_red() {
        let out = lowered_floors(
            &doc(&DOC.replace("plane_crates = 4", "plane_crates = 3")),
            &doc(DOC),
            "abc1234",
            &[],
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
            &[],
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            out[0].contains("plugin_kinds.plane: the floor itself went 5 -> 0"),
            "{out:?}"
        );
    }

    fn retired(floor: &str, from: i64, to: i64) -> Vec<Retired> {
        let text = format!(
            "[[gate.census_retired]]\ncrate = \"busbar-voice\"\ncommit = \"deadbee\"\nfloor = \
             \"{floor}\"\nfrom = {from}\nto = {to}\n"
        );
        let (rows, bad) = retirements(&doc(&text));
        assert!(bad.is_empty(), "{bad:?}");
        rows
    }

    /// THE DOOR. A legacy crate's deletion drops `gate.plane_crates` by one, and the ONLY thing
    /// that admits the drop is a row naming the crate, the commit, the floor and both numbers.
    #[test]
    fn a_census_retired_row_admits_the_floor_it_names_and_nothing_else() {
        let now = doc(&DOC.replace("plane_crates = 4", "plane_crates = 3"));
        assert!(
            lowered_floors(&now, &doc(DOC), "abc1234", &retired("plane_crates", 4, 3)).is_empty(),
            "the row that names this exact drop admits it"
        );
        // …AND IT IS A DOOR AND NOT A HOLE. A row about a different floor, or about different
        // numbers, admits nothing: the drop it describes is not the drop that happened.
        for wrong in [
            retired("plugin_kinds.plane", 4, 3),
            retired("plane_crates", 9, 8),
        ] {
            let out = lowered_floors(&now, &doc(DOC), "abc1234", &wrong);
            assert_eq!(out.len(), 1, "{out:?}");
            assert!(
                out[0].contains("plane_crates: the floor itself went 4 -> 3"),
                "{out:?}"
            );
        }
    }

    /// A LOWERED FLOOR WITH NO ROW STAYS REFUSED, and the refusal now says which row would have
    /// admitted it — the finding is a scaffold, not a dead end.
    #[test]
    fn a_lowered_floor_with_no_retirement_row_is_still_red() {
        let out = lowered_floors(
            &doc(&DOC.replace("plane_crates = 4", "plane_crates = 3")),
            &doc(DOC),
            "abc1234",
            &[],
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("gate.census_retired"), "{out:?}");
        assert!(out[0].contains("from = 4"), "{out:?}");
        assert!(out[0].contains("to = 3"), "{out:?}");
    }

    /// ONE RETIREMENT DELETES ONE CRATE. A row that lowers its floor by two is two retirements
    /// under one sentence, and the second is the one nobody read.
    #[test]
    fn a_retirement_row_may_lower_its_floor_by_exactly_one() {
        let (rows, bad) = retirements(&doc(
            "[[gate.census_retired]]\ncrate = \"busbar-voice\"\ncommit = \"deadbee\"\nfloor = \
             \"plane_crates\"\nfrom = 4\nto = 2\n",
        ));
        assert!(rows.is_empty());
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert!(bad[0].contains("lowers it by 2"), "{bad:?}");
    }

    /// A ROW WITH HALF ITS FIELDS IS NOT A RETIREMENT. Skipping it silently would be a floor
    /// lowered by nothing at all.
    #[test]
    fn a_retirement_row_missing_a_field_is_refused_not_skipped() {
        let (rows, bad) = retirements(&doc(
            "[[gate.census_retired]]\ncrate = \"busbar-voice\"\nfloor = \"plane_crates\"\nfrom = \
             4\nto = 3\n",
        ));
        assert!(rows.is_empty());
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert!(bad[0].contains("missing one of"), "{bad:?}");
    }

    /// Raising a floor, and adding a new one, are the ordinary direction and are not findings.
    #[test]
    fn a_floor_that_rose_or_appeared_is_not_a_finding() {
        let grown =
            format!("{DOC}egress_auth = 0\n").replace("plane_crates = 4", "plane_crates = 9");
        assert!(lowered_floors(&doc(&grown), &doc(DOC), "abc1234", &[]).is_empty());
    }
}
