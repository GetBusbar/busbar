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
                "[[{RETIRED}]] names `{}` (retired in {}) and crates/{} is still in this tree. \
                 The row admits a census floor going down BECAUSE a crate was deleted; while the \
                 crate is there, nothing was retired and the floor has no reason to have moved",
                r.krate, r.commit, r.krate
            ));
        }
    }
    bad.extend(retired_bad);
    let mut warn: Vec<String> = Vec::new();
    if let Ok(base) = base_ref(cx) {
        if let Ok(was) = cx.git_show(&base, CEILINGS) {
            if let Ok(doc) = crate::toml_doc::parse_str(&was) {
                // WHICH ROWS THE BASE ALREADY CARRIES is the whole lifecycle: a row rides in the
                // commit that deletes the crate, and one batch later the base holds both the row
                // and the lowered floor. From then on it is SPENT.
                let (live, carried) = partition(retired, retirements(&doc).0);
                let (b, w) = judge(
                    &drops(&cfg.doc, &doc),
                    &live,
                    &carried,
                    &base[..base.len().min(10)],
                );
                bad.extend(b);
                warn.extend(w);
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
                 its pinned floor{}",
                warn_tail(&warn)
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
             row is what makes that a RED rather than one fewer row nobody was counting: {}{}",
            bad.join("; "),
            warn_tail(&warn)
        ),
        n,
        0,
        bad,
    )]
}

/// The array of tables the retirements are declared in.
pub const RETIRED: &str = "gate.census_retired";

/// A retirement shorter than this in its `why` is a shrug, not a reason.
const MIN_WHY: usize = 60;

/// THE SHAPE A RETIREMENT HAS, printed by every refusal that is about the shape.
pub const RETIRED_SHAPE: &str = "[[gate.census_retired]]\n\
    crate  = \"busbar-unit-egress-auth\"\n\
    commit = \"<the sha that DELETES the crate>\"\n\
    floor  = \"plugin_kinds.unit\"\n\
    from   = 14\n\
    to     = 13\n\
    why    = \"<what the crate was, and why the tree no longer needs it — at least 60 characters>\"";

/// EVERY CENSUS FLOOR THAT WENT DOWN, or was deleted outright, since the base — as a drop each.
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
fn drops(now_doc: &Document, base_doc: &Document) -> Vec<Drop> {
    let now = census_pins(now_doc);
    census_pins(base_doc)
        .into_iter()
        .filter_map(|(floor, from)| {
            let to = now.get(&floor).copied().unwrap_or(0);
            (to < from).then_some(Drop { floor, from, to })
        })
        .collect()
}

/// One census floor that went down since the base.
struct Drop {
    floor: String,
    from: i64,
    to: i64,
}

/// THE VERDICT OVER THE DROPS AND THE ROWS, on both sides at once, because they are one question.
///
/// * a drop a LIVE row names exactly is the retirement the row was written for — admitted;
/// * a drop a CARRIED row names is a row being SPENT TWICE: the base already holds the floor that
///   row bought, so whatever moved it a second time was not the deletion the row records;
/// * a drop no row names at all is the manoeuvre the floor exists to refuse;
/// * a LIVE row naming no drop retired nothing on this branch — a dead row, and dead rows are what
///   a later drop of that same floor would shelter under;
/// * a CARRIED row naming no drop has done its job and is a WARNING, struck by `--write`.
fn judge(
    drops: &[Drop],
    live: &[Retired],
    carried: &[Retired],
    short: &str,
) -> (Vec<String>, Vec<String>) {
    let mut bad = Vec::new();
    let mut spent: Vec<bool> = vec![false; live.len()];
    for d in drops {
        if let Some(i) = live.iter().position(|r| r.names(d)) {
            spent[i] = true;
            continue;
        }
        // THE ROW IS A ONE-SHOT, and this is the arm that keeps it one. An entry the base carries
        // was paid out at the base; leaving it in the file and moving the same floor the same way
        // again is one deletion's ceremony buying two.
        if let Some(r) = carried.iter().find(|r| r.names(d)) {
            bad.push(format!(
                "[gate.census] {}: the floor went {} -> {} since the base {short}, and the only \
                 row that names that drop is `{}`'s, which the BASE ALREADY CARRIES. A retirement \
                 is spent by the deletion it rode in with — the base holds the floor it bought — \
                 so it admits nothing a second time. `cargo xtask gate construction --write` \
                 strikes the spent row; whatever moved this floor again needs a row of its own",
                d.floor, d.from, d.to, r.krate
            ));
            continue;
        }
        bad.push(format!(
            "[gate.census] {}: the floor itself went {} -> {} since the base {short}. \
             `ceiling-rose` watches numbers going UP; lowering a census floor is how a deleted \
             rule table would be made to look accounted for. A floor that went down because a \
             CRATE was deleted says so in a `[[{RETIRED}]]` row — `crate`, `commit`, `floor = \
             \"{}\"`, `from = {}`, `to = {}`, `why` — and nothing else lowers one",
            d.floor, d.from, d.to, d.floor, d.from, d.to
        ));
    }
    for (i, r) in live.iter().enumerate() {
        if !spent[i] {
            bad.push(format!(
                "[[{RETIRED}]] `{}`: a retirement of `{}` {} -> {} that is not a drop at the base \
                 {short}. The base does not carry this row and the floor it names did not move on \
                 this branch: either the deletion is not on this branch — land the row with it — \
                 or the floor is misnamed. A row that admits a drop nobody made is a drop somebody \
                 else makes later, under a sentence written for a different crate ({})",
                r.krate,
                r.floor,
                r.from,
                r.to,
                r.why_short()
            ));
        }
    }
    let warn = carried
        .iter()
        .filter(|r| !drops.iter().any(|d| r.names(d)))
        .map(|r| r.line())
        .collect();
    (bad, warn)
}

/// The report tail for the spent rows — a WARNING, never a red. The row did its job, the base
/// holds the floor it bought, and the only thing left to do about it is strike it, which `--write`
/// does. Red here would be a red every retirement pays one batch after it lands, because the
/// strike cannot ride in the same batch as the deletion.
fn warn_tail(warn: &[String]) -> String {
    if warn.is_empty() {
        return String::new();
    }
    format!(
        "; WARN {} retirement(s) already carried by the base — spent, and admitting nothing \
         further; `cargo xtask gate construction --write` strikes them: {}",
        warn.len(),
        warn.join(", ")
    )
}

/// This tree's rows split into the ones the base already carries and the ones it does not, on the
/// same terms `ceiling-rose` partitions a declared raise. A base carrying one row covers one row
/// here, not every identical one.
fn partition(rows: Vec<Retired>, mut at_base: Vec<Retired>) -> (Vec<Retired>, Vec<Retired>) {
    let (mut live, mut carried) = (Vec::new(), Vec::new());
    for r in rows {
        match at_base.iter().position(|b| b.identity() == r.identity()) {
            Some(i) => {
                at_base.swap_remove(i);
                carried.push(r);
            }
            None => live.push(r),
        }
    }
    (live, carried)
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
/// what, and WHY the tree no longer needs it, and it is checked six ways: the crate must be GONE
/// from the tree, the floor named must be the floor that moved, the `from` must be the number the
/// BASE carried, the drop must be EXACTLY ONE, the `why` must be long enough to be one, and the
/// row must not already be carried by the base. A retirement deletes one crate; a row that lowers
/// a floor by two is two retirements under one sentence, and the second one is the one nobody read.
pub struct Retired {
    krate: String,
    commit: String,
    floor: String,
    from: i64,
    to: i64,
    why: String,
    /// Which `[[gate.census_retired]]` this is, counting from 1, so a strike can point at it.
    pub ordinal: usize,
}

impl Retired {
    /// Does this row name exactly this drop? A drop of two under a row that says one is not this
    /// row's drop, and neither is the same-sized drop of a different floor.
    fn names(&self, d: &Drop) -> bool {
        self.floor == d.floor && self.from == d.from && self.to == d.to
    }

    /// What makes two rows THE SAME ROW — the base carrying one of these is the base carrying
    /// this one.
    fn identity(&self) -> (&str, &str, &str, i64, i64) {
        (&self.krate, &self.commit, &self.floor, self.from, self.to)
    }

    /// What `--write` prints when it strikes this row.
    pub fn report(&self) -> String {
        format!(
            "struck [[{RETIRED}]] #{}: `{}` {} {} -> {} — the base already carries it",
            self.ordinal, self.krate, self.floor, self.from, self.to
        )
    }

    fn line(&self) -> String {
        format!(
            "#{} `{}` {} {} -> {} ({})",
            self.ordinal,
            self.krate,
            self.floor,
            self.from,
            self.to,
            self.why_short()
        )
    }

    /// The reason, cut to a report-sized excerpt. It is the half a reviewer reads, so it travels
    /// with the row into every report the row appears in.
    fn why_short(&self) -> String {
        const MAX: usize = 60;
        if self.why.chars().count() <= MAX {
            return self.why.clone();
        }
        let head: String = self.why.chars().take(MAX).collect();
        format!("{}…", head.trim_end())
    }
}

/// Every `[[gate.census_retired]]` row, and every row that could not be read as one.
fn retirements(doc: &Document) -> (Vec<Retired>, Vec<String>) {
    let mut rows = Vec::new();
    let mut bad = Vec::new();
    for (i, t) in doc.array_of_tables(RETIRED).iter().enumerate() {
        let ordinal = i + 1;
        let at = format!("[[{RETIRED}]] #{ordinal}");
        let (Some(krate), Some(commit), Some(floor), Some(from), Some(to)) = (
            t.str_of("crate").filter(|v| !v.is_empty()),
            t.str_of("commit").filter(|v| !v.is_empty()),
            t.str_of("floor").filter(|v| !v.is_empty()),
            t.int_of("from"),
            t.int_of("to"),
        ) else {
            bad.push(format!(
                "{at} is missing one of `crate`, `commit`, `floor`, `from`, `to`. A row nobody \
                 can read is not a retirement, and a half-read row that was skipped would be a \
                 floor lowered by nothing:\n{RETIRED_SHAPE}"
            ));
            continue;
        };
        if to != from - 1 {
            bad.push(format!(
                "{at} `{krate}`: `from = {from}`, `to = {to}` — a retirement deletes ONE crate, \
                 so it lowers its floor by exactly one. A row that lowers it by {} is that many \
                 retirements under one sentence, and only the first was read",
                from - to
            ));
            continue;
        }
        // THE `why` IS THE HALF A REVIEWER READS. Every other field is a number or a hash that
        // says WHAT moved; a deletion is admitted on the claim that the tree no longer needs the
        // crate, and that claim is made in words or it is not made at all.
        let why = t.str_of("why").unwrap_or("").trim().to_string();
        if why.chars().count() < MIN_WHY {
            bad.push(format!(
                "{at} `{krate}`: a {}-character `why` retires nothing. A retirement says what the \
                 crate was and why this tree no longer needs it, in at least {MIN_WHY} \
                 characters — the numbers say what moved, and only the `why` says whether it \
                 should have:\n{RETIRED_SHAPE}",
                why.chars().count()
            ));
            continue;
        }
        rows.push(Retired {
            krate: krate.to_string(),
            commit: commit.to_string(),
            floor: floor.to_string(),
            from,
            to,
            why,
            ordinal,
        });
    }
    (rows, bad)
}

/// THE ROWS `--write` STRIKES: every retirement the base already carries, in the ceilings text
/// given. Spent rows only — a live row is the one thing admitting this branch's drop, and striking
/// it would redden the very landing it rode in with.
pub fn spent(now: &str, at_base: &str) -> Vec<Retired> {
    let read = |t: &str| {
        crate::toml_doc::parse_str(t)
            .map(|d| retirements(&d).0)
            .unwrap_or_default()
    };
    partition(read(now), read(at_base)).1
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

    /// The whole verdict over one pair of ceilings texts: the reds first, then the warnings.
    fn verdict(now: &str, base: &str) -> (Vec<String>, Vec<String>) {
        let (now_doc, base_doc) = (doc(now), doc(base));
        let (live, carried) = partition(retirements(&now_doc).0, retirements(&base_doc).0);
        judge(&drops(&now_doc, &base_doc), &live, &carried, "abc1234")
    }

    fn reds(now: &str, base: &str) -> Vec<String> {
        verdict(now, base).0
    }

    /// THE SECOND HALF OF THE ATTACK. Deleting `[rules.loc-ceilings.kernel_files.arena]` is caught
    /// by the floor; deleting it AND dropping the floor from 9 to 8 in the same edit is caught only
    /// here. `ceiling-rose` cannot: it watches numbers going up.
    #[test]
    fn a_census_floor_that_went_down_is_red() {
        let out = reds(&DOC.replace("plane_crates = 4", "plane_crates = 3"), DOC);
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
        let out = reds("[gate.census]\nplane_crates = 4\n", DOC);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            out[0].contains("plugin_kinds.plane: the floor itself went 5 -> 0"),
            "{out:?}"
        );
    }

    const WHY: &str = "busbar-unit-egress-auth was the split-out auth step; the unit walks the \
                       one egress path now and nothing calls it";

    fn row(floor: &str, from: i64, to: i64) -> String {
        format!(
            "\n[[gate.census_retired]]\ncrate = \"busbar-voice\"\ncommit = \"deadbee\"\nfloor = \
             \"{floor}\"\nfrom = {from}\nto = {to}\nwhy = \"{WHY}\"\n"
        )
    }

    /// THE DOOR. A legacy crate's deletion drops `gate.plane_crates` by one, and the ONLY thing
    /// that admits the drop is a row naming the crate, the commit, the floor, both numbers and a
    /// reason.
    #[test]
    fn a_census_retired_row_admits_the_floor_it_names_and_nothing_else() {
        let lowered = DOC.replace("plane_crates = 4", "plane_crates = 3");
        let now = format!("{lowered}{}", row("plane_crates", 4, 3));
        assert!(
            reds(&now, DOC).is_empty(),
            "the row that names this exact drop admits it"
        );
        // …AND IT IS A DOOR AND NOT A HOLE. A row about a different floor, or about different
        // numbers, admits nothing: the drop it describes is not the drop that happened — and the
        // row itself is then a retirement of something that did not move.
        for wrong in [row("plugin_kinds.plane", 4, 3), row("plane_crates", 9, 8)] {
            let out = reds(&format!("{lowered}{wrong}"), DOC);
            assert_eq!(out.len(), 2, "{out:?}");
            assert!(
                out[0].contains("plane_crates: the floor itself went 4 -> 3"),
                "{out:?}"
            );
            assert!(out[1].contains("is not a drop at the base"), "{out:?}");
        }
    }

    /// A LOWERED FLOOR WITH NO ROW STAYS REFUSED, and the refusal now says which row would have
    /// admitted it — the finding is a scaffold, not a dead end.
    #[test]
    fn a_lowered_floor_with_no_retirement_row_is_still_red() {
        let out = reds(&DOC.replace("plane_crates = 4", "plane_crates = 3"), DOC);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("gate.census_retired"), "{out:?}");
        assert!(out[0].contains("from = 4"), "{out:?}");
        assert!(out[0].contains("to = 3"), "{out:?}");
        assert!(out[0].contains("`why`"), "{out:?}");
    }

    /// A RETIREMENT IS SPENT BY THE DELETION IT RODE IN WITH. Once the base carries the row, the
    /// base holds the floor the row bought — so the same row admitting a second drop of the same
    /// floor is one deletion's ceremony paying for two, which is the whole manoeuvre the floor
    /// exists to refuse.
    #[test]
    fn a_retirement_the_base_already_carries_cannot_be_spent_a_second_time() {
        let entry = row("plane_crates", 4, 3);
        let base = format!("{DOC}{entry}");
        let now = format!(
            "{}{entry}",
            DOC.replace("plane_crates = 4", "plane_crates = 3")
        );
        let (bad, warn) = verdict(&now, &base);
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert!(bad[0].contains("BASE ALREADY CARRIES"), "{bad:?}");
        assert!(warn.is_empty(), "{warn:?}");
    }

    /// AND WHEN IT HAS NOTHING LEFT TO ADMIT IT IS A WARNING, never a red: the strike cannot ride
    /// in the same batch as the deletion, so a red would be a red every retirement pays one batch
    /// late. `--write` strikes it — and `spent` is what `--write` reads.
    #[test]
    fn a_retirement_the_base_carries_and_that_admits_nothing_is_a_warning_write_strikes() {
        let entry = row("plane_crates", 4, 3);
        let base = format!("{DOC}{entry}");
        let now = base.clone();
        let (bad, warn) = verdict(&now, &base);
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(warn.len(), 1, "{warn:?}");
        assert!(
            warn[0].contains("`busbar-voice` plane_crates 4 -> 3"),
            "{warn:?}"
        );
        assert!(warn_tail(&warn).contains("--write"));
        let struck = spent(&now, &base);
        assert_eq!(struck.len(), 1);
        assert_eq!(struck[0].ordinal, 1);
        // A LIVE ROW IS NEVER STRUCK: it is the one thing admitting this branch's drop, and
        // striking it would redden the landing it rode in with.
        assert!(spent(&now, DOC).is_empty());
    }

    /// A ROW THAT RETIRES NOTHING IS A DEAD ROW, and a dead row is what the NEXT drop of that
    /// floor shelters under. The base does not carry it and the floor it names did not move.
    #[test]
    fn a_live_retirement_row_that_names_no_drop_is_red() {
        let out = reds(&format!("{DOC}{}", row("plane_crates", 4, 3)), DOC);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("is not a drop at the base"), "{out:?}");
        assert!(out[0].contains("`busbar-voice`"), "{out:?}");
    }

    /// ONE RETIREMENT DELETES ONE CRATE. A row that lowers its floor by two is two retirements
    /// under one sentence, and the second is the one nobody read.
    #[test]
    fn a_retirement_row_may_lower_its_floor_by_exactly_one() {
        let (rows, bad) = retirements(&doc(&row("plane_crates", 4, 2)));
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

    /// THE NUMBERS SAY WHAT MOVED; ONLY THE `why` SAYS WHETHER IT SHOULD HAVE. A retirement with
    /// no reason in it is a deletion nobody argued for.
    #[test]
    fn a_retirement_row_with_no_reason_in_it_is_refused() {
        let (rows, bad) = retirements(&doc(&row("plane_crates", 4, 3).replace(WHY, "dead code")));
        assert!(rows.is_empty());
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert!(bad[0].contains("retires nothing"), "{bad:?}");
    }

    /// Raising a floor, and adding a new one, are the ordinary direction and are not findings.
    #[test]
    fn a_floor_that_rose_or_appeared_is_not_a_finding() {
        let grown =
            format!("{DOC}egress_auth = 0\n").replace("plane_crates = 4", "plane_crates = 9");
        assert!(reds(&grown, DOC).is_empty());
    }
}
