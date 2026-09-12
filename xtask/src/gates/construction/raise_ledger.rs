//! `ceiling-rose` answers ONE question — did any ceiling rise without a declaration that sums to
//! exactly its rise. AUDIT-pass31's closing note is that the same arithmetic, run over the whole
//! land queue rather than one branch's HEAD, is the highest-yield check there is: two of its ten
//! findings (an under-declaration in `cell.busbar-mcp.api.count` and one in
//! `cell.busbar-a2a.plane.count`) were single-digit gaps between what a commit message claimed and
//! what the tree measured, and no amount of reading either would have found them.
//!
//! THIS MODULE IS THAT SWEEP, MADE CALLABLE ON DEMAND, over an arbitrary `<base>`/`<head>` pair
//! rather than only "this branch against its own merge-base". It reuses
//! [`crate::gates::construction::ceilings`]'s own readers rather than a second interpretation of
//! the same two files:
//!
//! * [`ceilings::Ordinals::at`] and [`ceilings::raises_in_at`] read the declared raises — both
//!   shapes, the retired `from`/`to` header and the array of deltas, with an ordinal key resolved
//!   against the base's row order exactly as `ceiling-rose` resolves it;
//! * [`ceilings::mints_in`] reads the `[[minted]]` / `[[minted_kind]]` admissions a carved-out
//!   crate's first figures are checked against.
//!
//! WHAT IS NOT REUSED, AND WHY. `ceilings::rose` walks the tree's own working copy (`Ctx::read`)
//! against one fixed base — it is `ceiling-rose`'s reader, built for "this branch against
//! `ceilings::base_ref`" and nothing else. A sweep over the land queue needs the figures at an
//! ARBITRARY commit on each side, so [`figures`] below reads through the same
//! [`crate::toml_doc`] parser with the same identity labelling (`cell.<crate>.<kind>.count`
//! rather than `cell.<n>.count`) so a struck row cannot manufacture a rise here any more than it
//! can in `ceiling-rose`, over text fetched by [`head_text`] — `Ctx::read`, exactly as
//! `ceiling-rose` fetches it, when `head` is the literal `"HEAD"` (which is how the row this gate
//! registers calls it, so a self-test plant that overlays a ceilings file's content reddens this
//! row the same way it reddens `ceiling-rose`), and `Ctx::git_show` for any other commit (which is
//! how the CLI arm and the queue sweep call it, over a tip that is not the checkout). It is kept
//! beside the module it mirrors rather than inside it because `ceilings.rs` is a second slot's
//! file this pass and a widened visibility there is a hunk that slot did not ask for.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay};
use crate::gates::construction::ceilings::{self, KIND_CEILINGS, RAISES};
use crate::gates::construction::model::{plain, CRow};
use crate::gates::construction::CEILINGS;
use crate::gates::{prove_rows_green, prove_rows_red, Gate, Report};

pub const ROW_LEDGER: &str = "raise-ledger";

/// See `ceilings::IDENTITIES` — the same table, kept here because the fields it names are read off
/// the same two files and a row of one of these tables must be labelled the same way on both sides
/// of this comparison as it is on both sides of `ceiling-rose`'s.
const IDENTITIES: &[(&str, &[&str])] = &[
    ("cell", &["crate", "kind"]),
    ("dep", &["from", "to", "half"]),
    ("face", &["crate", "face"]),
];

/// See `ceilings::NOT_CEILINGS` — the admissions tables, which carry numbers ABOUT ceilings
/// (`cells`, `edges`, `ceiling`) rather than a ceiling itself.
const NOT_CEILINGS: &[&str] = &["minted", "minted_kind"];

/// One ceiling key's verdict, run over a `<base>`/`<head>` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No rise with no declaration, or a rise the declared raises sum to exactly.
    Exact,
    /// The declared raises sum to more than the key rose by.
    Over(i64),
    /// The declared raises sum to less than the key rose by, and more than zero.
    Under(i64),
    /// The key rose and nothing declares any of it.
    UndeclaredRise,
    /// A live declared raise names this key and the key did not rise between base and head.
    Expired,
}

impl Verdict {
    pub fn is_exact(&self) -> bool {
        matches!(self, Verdict::Exact)
    }

    fn word(&self) -> String {
        match self {
            Verdict::Exact => "exact".to_string(),
            Verdict::Over(n) => format!("OVER-declared by {n}"),
            Verdict::Under(n) => format!("UNDER-declared by {n}"),
            Verdict::UndeclaredRise => "undeclared rise".to_string(),
            Verdict::Expired => "expired".to_string(),
        }
    }
}

/// One row of the ledger: `<file>:<dotted identity>`, the figure at each end, the rise, the sum of
/// the LIVE declared raises naming it, and the verdict those four numbers make.
#[derive(Debug, Clone)]
pub struct KeyRow {
    pub key: String,
    pub before: i64,
    pub after: i64,
    pub rise: i64,
    pub declared: i64,
    pub verdict: Verdict,
}

impl KeyRow {
    pub fn line(&self) -> String {
        format!(
            "{}: {} -> {} (rose {}, declared {}) — {}",
            self.key,
            self.before,
            self.after,
            self.rise,
            self.declared,
            self.verdict.word()
        )
    }
}

/// A KEY THAT DID NOT RISE NEEDS NO DECLARATION, WHATEVER ITS SIGN. `ceilings::rose` only ever
/// inserts a key into its map `if *after > before` — a fall or an unchanged figure is not a rise,
/// full stop, and is never even offered to `ceiling-rose`'s judgment. A live declaration naming
/// such a key all the same is the same thing `ceiling-rose` calls EXPIRED: it excuses a rise that
/// is not there.
fn classify(rise: i64, declared: i64) -> Verdict {
    if rise <= 0 {
        return if declared == 0 {
            Verdict::Exact
        } else {
            Verdict::Expired
        };
    }
    match declared {
        0 => Verdict::UndeclaredRise,
        d if d == rise => Verdict::Exact,
        d if d > rise => Verdict::Over(d - rise),
        d => Verdict::Under(rise - d),
    }
}

/// The identity label for one array-of-tables row — see `ceilings::identity_of`, the function this
/// mirrors. `None` for a table [`IDENTITIES`] does not name, or a row missing a field that would
/// name it; the caller keeps the ordinal path, exactly as `ceiling-rose` does.
fn identity_of(path: &str, table: &crate::toml_doc::Table) -> Option<String> {
    let (name, ord) = path.split_once('.')?;
    if ord.is_empty() || !ord.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let fields = IDENTITIES.iter().find(|(n, _)| *n == name)?.1;
    let mut out = String::from(name);
    for f in fields {
        let v = table
            .str_of(f)
            .filter(|v| !v.is_empty() && !v.contains('.'))?;
        out.push('.');
        out.push_str(v);
    }
    Some(out)
}

/// Every ceiling in one ceilings-file text, by its identity label — see `ceilings::ints_of`, the
/// function this mirrors byte for byte: an integer OR a quoted one (every `[[cell]] count` in
/// `qa/kind-isolation.toml` is written `count = "122"`), excluding the raise declarations
/// themselves and the mint admissions, neither of which is a ceiling.
pub fn figures(text: &str) -> Result<BTreeMap<String, i64>, String> {
    let doc = crate::toml_doc::parse_str(text)?;
    let mut out = BTreeMap::new();
    let raises_prefix = format!("{RAISES}.");
    for (path, table) in doc.tables() {
        if path == RAISES || path.starts_with(raises_prefix.as_str()) {
            continue;
        }
        if NOT_CEILINGS
            .iter()
            .any(|t| path == *t || path.starts_with(&format!("{t}.")))
        {
            continue;
        }
        let label = identity_of(path, table).unwrap_or_else(|| path.to_string());
        for key in table.keys() {
            if let Some(v) = table
                .int_of(key)
                .or_else(|| table.str_of(key).and_then(|s| s.trim().parse::<i64>().ok()))
            {
                let dotted = if label.is_empty() {
                    key.clone()
                } else {
                    format!("{label}.{key}")
                };
                out.insert(dotted, v);
            }
        }
    }
    Ok(out)
}

/// What a `[[minted]]` / `[[minted_kind]]` row of `head`'s `qa/kind-isolation.toml` admits a key
/// minted on this branch at — see `ceilings::minted_before`, the function this mirrors. `Ok(0)` for
/// `qa/construction.toml`, whose new keys are ordinary first-gating figures the declared-raise
/// mechanism covers directly.
fn mint_admits(mints: &ceilings::Mints, file: &str, path: &str) -> Result<i64, String> {
    if file != KIND_CEILINGS {
        return Ok(0);
    }
    let (table, rest) = path.split_once('.').unwrap_or((path, ""));
    let names: Vec<&str> = rest.split('.').collect();
    let (crates, kind): (Vec<&str>, Option<&str>) = match (table, names.as_slice()) {
        ("cell", [krate, kind, ..]) => (vec![*krate], Some(*kind)),
        ("face", [krate, ..]) => (vec![*krate], None),
        ("dep", [from, to, ..]) => (vec![*from, *to], None),
        _ => (vec![], None),
    };
    for name in &crates {
        if let Some(m) = mints.crates.get(*name) {
            return m.ceiling.ok_or_else(|| {
                format!("{file} {path}: minted under `[[minted]] crate = \"{name}\"` with no `ceiling` admitted")
            });
        }
    }
    if let Some(k) = kind {
        if let Some(m) = mints.kinds.get(k) {
            return m.ceiling.ok_or_else(|| {
                format!(
                    "{file} {path}: minted under `[[minted_kind]] kind = \"{k}\"` with no `ceiling` admitted"
                )
            });
        }
    }
    Err(format!(
        "{file} {path}: minted on this branch (the base carries no such key) and no `[[minted]]` \
         or `[[minted_kind]]` row admits it"
    ))
}

/// `head`'s copy of `file` — `Ctx::read` (the WORKING TREE) when `head` is the literal `"HEAD"`,
/// `Ctx::git_show` for any other revision.
///
/// THE LITERAL `"HEAD"` IS OVERLAY-AWARE AND A SHA IS NOT, and that difference is load-bearing
/// rather than an inconsistency. `ceilings::rose` and `ceilings::raises` read "this branch" with
/// `Ctx::read` for the same reason every other rule in this gate does: a self-test PLANTS a
/// violation by overlaying a file's content, never by writing a commit, so a reader that reached
/// past the overlay with `git show HEAD:<path>` would be unplantable — exactly the gap that left
/// the registered `raise-ledger` row uncovered before this existed. The registered row therefore
/// always calls this with `head = "HEAD"`; an explicit sha (from the CLI or the queue sweep) is a
/// commit that is not the checkout, and reading anything but its own git object would be reading
/// the wrong tree.
fn head_text(cx: &Ctx, head: &str, file: &str) -> Result<String, String> {
    if head == "HEAD" {
        cx.read(file)
    } else {
        cx.git_show(head, file)
    }
}

/// Every declared raise LIVE at `head` (the base's copy of `qa/construction.toml` does not carry
/// it), summed by the key it names — both transitional forms read (the array of deltas and the
/// retired `from`/`to` header), ordinals resolved against `base`'s row order, exactly as
/// [`ceilings::raises`] partitions them. Returns the sums, the refused entries, and the transition
/// warnings, so a caller can report a refused declaration as the reason a rise looks undeclared.
#[allow(clippy::type_complexity)]
fn declared_sums(
    cx: &Ctx,
    base: &str,
    head: &str,
) -> Result<(BTreeMap<String, i64>, Vec<String>, Vec<String>), String> {
    let ords = ceilings::Ordinals::at(cx, base);
    let text = head_text(cx, head, CEILINGS)?;
    let (head_raises, refused, warned) = ceilings::raises_in_at(&text, &ords);
    let base_raises = match cx.git_show(base, CEILINGS) {
        Ok(t) => ceilings::raises_in_at(&t, &ords).0,
        // A base with no ceilings file at all carries no declaration, so nothing here is carried.
        Err(_) => Vec::new(),
    };
    let mut sums: BTreeMap<String, i64> = BTreeMap::new();
    for r in head_raises {
        let carried = base_raises
            .iter()
            .any(|b| b.key == r.key && b.by == r.by && b.because == r.because);
        if !carried {
            *sums.entry(r.key.clone()).or_insert(0) += r.by;
        }
    }
    Ok((sums, refused, warned))
}

/// THE LEDGER: every ceiling key in `qa/construction.toml` and `qa/kind-isolation.toml`, at `base`
/// and at `head`, with the sum of the live declared raises that name it and the verdict the four
/// numbers make. `base` is always read with `Ctx::git_show`; `head` is read with `Ctx::read` when
/// it is the literal `"HEAD"` and with `Ctx::git_show` otherwise — see [`head_text`].
///
/// `problems` is a REFUSED declaration or a key that could not be compared — never a `warned`
/// entry. A retired-shape or ordinal-keyed declaration that RESOLVES is a live entry like any
/// other and is already folded into `declared`; warning about its shape is `ceiling-rose`'s job,
/// not a reason for this row to call the key unresolved.
pub fn ledger(cx: &Ctx, base: &str, head: &str) -> Result<(Vec<KeyRow>, Vec<String>), String> {
    let (declared, refused, _warned) = declared_sums(cx, base, head)?;
    let mut problems: Vec<String> = refused;
    let mints = match head_text(cx, head, KIND_CEILINGS) {
        Ok(t) => ceilings::mints_in(&t),
        Err(_) => ceilings::Mints::default(),
    };

    let mut rows = Vec::new();
    for file in [CEILINGS, KIND_CEILINGS] {
        let now_text = match head_text(cx, head, file) {
            Ok(t) => t,
            Err(e) => {
                problems.push(format!("{file} at {head}: {e}"));
                continue;
            }
        };
        // A file the base did not carry is a file `head` ADDED: every key in it is new, and a
        // brand-new file is not a ceiling that rose — see `ceilings::rose`, which skips it the
        // same way.
        let base_text = match cx.git_show(base, file) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let (now, was) = match (figures(&now_text), figures(&base_text)) {
            (Ok(a), Ok(b)) => (a, b),
            (a, b) => {
                for (which, r) in [("head", a), ("base", b)] {
                    if let Err(e) = r {
                        problems.push(format!("{file} at {which}: {e}"));
                    }
                }
                continue;
            }
        };
        for (path, after) in &now {
            let key = format!("{file}:{path}");
            let before = match was.get(path) {
                Some(b) => *b,
                None => match mint_admits(&mints, file, path) {
                    Ok(b) => b,
                    Err(why) => {
                        problems.push(why);
                        continue;
                    }
                },
            };
            let rise = after - before;
            let sum = declared.get(&key).copied().unwrap_or(0);
            rows.push(KeyRow {
                key,
                before,
                after: *after,
                rise,
                declared: sum,
                verdict: classify(rise, sum),
            });
        }
    }
    // A key naming a ceiling neither file's rose-map carries at all — a live declaration for a
    // struck row, or one that never named a real key — has nothing to compare against and is
    // reported once, plainly, rather than silently dropped.
    let seen: std::collections::BTreeSet<String> = rows.iter().map(|r| r.key.clone()).collect();
    for key in declared.keys() {
        if !seen.contains(key.as_str()) {
            rows.push(KeyRow {
                key: key.clone(),
                before: -1,
                after: -1,
                rise: 0,
                declared: *declared.get(key).unwrap_or(&0),
                verdict: Verdict::Expired,
            });
        }
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    Ok((rows, problems))
}

/// The ledger as a ledger row: PASS iff every key is exact and nothing could not be compared.
pub fn row(cx: &Ctx, base: &str, head: &str) -> CRow {
    match ledger(cx, base, head) {
        Ok((rows, problems)) if problems.is_empty() => {
            let offenders: Vec<String> = rows
                .iter()
                .filter(|r| !r.verdict.is_exact())
                .map(KeyRow::line)
                .collect();
            let ok = offenders.is_empty();
            let detail = if ok {
                format!(
                    "every ceiling key in {CEILINGS} and {KIND_CEILINGS} is exact between {base} \
                     and {head} ({} key(s) measured)",
                    rows.len()
                )
            } else {
                format!(
                    "{} key(s) between {base} and {head} are not exact: {}",
                    offenders.len(),
                    offenders.join("; ")
                )
            };
            plain(
                ROW_LEDGER,
                ok,
                "every ceiling's declared raises sum exactly to its measured rise",
                detail,
                offenders.len() as i64,
                0,
                offenders,
            )
        }
        Ok((_, problems)) => plain(
            ROW_LEDGER,
            false,
            "every ceiling's declared raises sum exactly to its measured rise",
            format!(
                "{} key(s) between {base} and {head} could not be compared: {}",
                problems.len(),
                problems.join("; ")
            ),
            problems.len() as i64,
            0,
            problems,
        ),
        Err(e) => plain(
            ROW_LEDGER,
            false,
            "every ceiling's declared raises sum exactly to its measured rise",
            format!("the ledger could not be built for {base}..{head}: {e}"),
            -1,
            0,
            vec![],
        ),
    }
}

/// `cargo xtask gate construction --raise-ledger <base> <head>`. Prints one line per key that is
/// not exact, plus the total measured, and exits non-zero the moment one is found — see
/// [`crate::cli`]'s dispatch.
pub fn run_cli(cx: &Ctx, base: &str, head: &str) -> i32 {
    match ledger(cx, base, head) {
        Ok((rows, problems)) => {
            let mut bad = 0;
            for r in &rows {
                if !r.verdict.is_exact() {
                    bad += 1;
                    println!("{}", r.line());
                }
            }
            for p in &problems {
                bad += 1;
                eprintln!("raise-ledger: {p}");
            }
            println!(
                "raise-ledger {base}..{head}: {} key(s) measured, {bad} not exact",
                rows.len()
            );
            i32::from(bad > 0)
        }
        Err(e) => {
            eprintln!("raise-ledger {base}..{head}: {e}");
            3
        }
    }
}

/// THE `raise-ledger` ROW'S OWN RED PROOF.
///
/// `xtask/src/gates/construction/selftest.rs` is a second slot's file this pass (see the module
/// header), so this row's coverage lives here instead, and [`ConstructionGate::selftest`] folds it
/// in with [`crate::gates::Report::append`] rather than the row being added to a case list that
/// lives there. The plant is the same one `ceiling-rose`'s own cases use — lower ONE key at the
/// real `base_ref` and leave `HEAD`'s copy of the file exactly as the working tree has it — so a
/// RED here and a RED on `ceiling-rose` come from the same fact, read by two different arithmetics.
pub fn selftest_cases<'a>(gate: &'a dyn Gate, cx: &'a Ctx) -> Report<'a> {
    let mut r = Report::new();
    let Ok(based) = ceilings::base_ref(cx) else {
        // `ceiling-rose`'s own case already proves this failure mode red; a base that cannot be
        // established is nothing new for this row to add on top of that.
        return r;
    };
    let Ok(now) = cx.read(CEILINGS) else {
        return r;
    };
    if let Some(lowered) = ceilings::set_int(&now, "rules.loc-ceilings", "verbs_ceiling", 0) {
        let mut ov = Overlay::new();
        ov.set_command(format!("git-show:{based}:{CEILINGS}"), lowered);
        r.push(prove_rows_red(
            cx,
            gate,
            "a ceiling higher than it was at the base is an undeclared rise the ledger names by \
             key, not only by 'something rose'",
            &[ROW_LEDGER],
            ov,
            &[&format!("{CEILINGS}:rules.loc-ceilings.verbs_ceiling")],
        ));
    } else {
        r.push(prove_rows_red(
            cx,
            gate,
            "a ceiling higher than it was at the base is an undeclared rise the ledger names by \
             key, not only by 'something rose'",
            &[ROW_LEDGER],
            Overlay::new(),
            &[
                "xtask/src/gates/construction/raise_ledger.rs: `rules.loc-ceilings.verbs_ceiling` \
               is not in the committed qa/construction.toml any more; repoint this plant",
            ],
        ));
    }
    r.push(prove_rows_green(
        cx,
        gate,
        "against the real base every ceiling key's declared raises sum exactly to its measured \
         rise",
        &[ROW_LEDGER],
        Overlay::new(),
    ));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rise_no_declaration_is_exact() {
        assert_eq!(classify(0, 0), Verdict::Exact);
    }

    #[test]
    fn a_rise_the_sum_matches_is_exact() {
        assert_eq!(classify(10, 10), Verdict::Exact);
    }

    #[test]
    fn a_rise_the_sum_exceeds_is_over_declared() {
        assert_eq!(classify(10, 14), Verdict::Over(4));
    }

    #[test]
    fn a_rise_the_sum_falls_short_of_is_under_declared() {
        assert_eq!(classify(10, 3), Verdict::Under(7));
    }

    #[test]
    fn a_rise_with_nothing_declared_is_an_undeclared_rise() {
        assert_eq!(classify(10, 0), Verdict::UndeclaredRise);
    }

    #[test]
    fn a_declaration_naming_no_rise_is_expired() {
        assert_eq!(classify(0, 5), Verdict::Expired);
    }

    /// A CEILING THAT FELL NEEDS NO DECLARATION, WHATEVER ITS SIGN — `ceilings::rose` never even
    /// offers a fallen key to `ceiling-rose`'s judgment (`if *after > before`), so this row must
    /// not call a fall "OVER-declared" just because a `by <= 0` can never be a live declared sum.
    #[test]
    fn a_fallen_ceiling_with_nothing_declared_is_exact() {
        assert_eq!(classify(-2, 0), Verdict::Exact);
    }

    #[test]
    fn a_fallen_ceiling_a_live_declaration_still_names_is_expired() {
        assert_eq!(classify(-2, 5), Verdict::Expired);
    }

    #[test]
    fn the_words_name_the_case() {
        assert_eq!(Verdict::Exact.word(), "exact");
        assert_eq!(Verdict::Over(4).word(), "OVER-declared by 4");
        assert_eq!(Verdict::Under(7).word(), "UNDER-declared by 7");
        assert_eq!(Verdict::UndeclaredRise.word(), "undeclared rise");
        assert_eq!(Verdict::Expired.word(), "expired");
    }

    /// AN ORDINAL-KEYED DECLARATION WITH NO BASE TO RESOLVE AGAINST IS REFUSED — the same rule
    /// `ceiling-rose` applies, exercised here through the same public reader
    /// (`ceilings::raises_in_at` + `ceilings::Ordinals`) this module calls. The RESOLVED case (an
    /// ordinal key that DOES land, against a real base row order) is exercised end to end in
    /// [`every_case_is_named_by_the_full_pipeline`] below.
    #[test]
    fn an_ordinal_keyed_entry_with_no_base_is_refused() {
        let text = "[[gate.ceiling_raises]]\n\
                     key = \"cell.0.count\"\n\
                     by = 5\n\
                     because = \"exercised only to prove an ordinal key without a base is \
                     refused, exactly as it is with no base at all\"\n";
        let (entries, refused, _warned) =
            ceilings::raises_in_at(text, &ceilings::Ordinals::default());
        assert!(
            entries.is_empty(),
            "an ordinal key with no base to resolve against is refused"
        );
        assert_eq!(refused.len(), 1);
        assert!(refused[0].contains("ORDINAL"));
    }

    /// A MOVE-CLASSED KEY: one minted on `head` under `[[minted]]`/`[[minted_kind]]`, admitted at
    /// the ceiling that row carries rather than at "the base has no such key so it rose from
    /// zero". `mint_admits` is this module's own reader for that admission (`ceilings::mint_admits`
    /// is private), built directly on the public `ceilings::mints_in`.
    #[test]
    fn a_move_classed_key_is_admitted_at_its_minted_ceiling_not_at_zero() {
        let kind_text = "[[minted]]\ncrate = \"busbar-core-config\"\nceiling = \"40\"\n\n\
                          [[cell]]\ncrate = \"busbar-core-config\"\nkind = \"api\"\ncount = \"40\"\n";
        let mints = ceilings::mints_in(kind_text);
        let before = mint_admits(&mints, KIND_CEILINGS, "cell.busbar-core-config.api.count")
            .expect("the crate's own [[minted]] row admits it");
        assert_eq!(before, 40);
        let figs = figures(kind_text).expect("the fixture parses");
        let after = *figs
            .get("cell.busbar-core-config.api.count")
            .expect("the cell is read by identity");
        assert_eq!(classify(after - before, 0), Verdict::Exact);
    }

    /// A key `figures` sees only through its POSITION when the row cannot be named — the neighbour
    /// finding `identity_of` documents: a row missing a field [`IDENTITIES`] requires keeps its
    /// ordinal path rather than vanishing.
    #[test]
    fn a_row_missing_its_naming_field_keeps_its_ordinal_path() {
        let text = "[[cell]]\nkind = \"api\"\ncount = \"7\"\n";
        let figs = figures(text).expect("the fixture parses");
        assert_eq!(figs.get("cell.0.count"), Some(&7));
    }

    #[test]
    fn every_integer_including_a_quoted_one_is_read() {
        let text = "[gate.surface_ceilings]\ngrammar = 500\n\n\
                     [[cell]]\ncrate = \"busbar\"\nkind = \"api\"\ncount = \"122\"\n";
        let figs = figures(text).expect("the fixture parses");
        assert_eq!(figs.get("gate.surface_ceilings.grammar"), Some(&500));
        assert_eq!(figs.get("cell.busbar.api.count"), Some(&122));
    }

    #[test]
    fn the_raise_declarations_table_is_not_itself_a_ceiling() {
        let text = "[[gate.ceiling_raises]]\nkey = \"x\"\nby = 5\nbecause = \"y\"\n";
        let figs = figures(text).expect("the fixture parses");
        assert!(figs.is_empty());
    }

    #[test]
    fn a_mint_admission_number_is_not_itself_a_ceiling() {
        let text = "[[minted]]\ncrate = \"busbar-x\"\nceiling = \"10\"\ncells = \"3\"\n";
        let figs = figures(text).expect("the fixture parses");
        assert!(figs.is_empty());
    }

    /// THE FULL PIPELINE, base to head, through `ledger()` — the entry point `run_cli` and the
    /// registered row both call. One base/head pair carries six keys, one of every case this row
    /// exists to name: an under-declaration, an over-declaration, an undeclared rise, an exact
    /// declared raise, an ordinal-keyed declaration (resolved against `base`'s row order) and a
    /// MOVE-classed key admitted through `[[minted]]` rather than measured from zero. Built with
    /// `Ctx`'s overlay — the same mechanism every other gate's self-test plants a tree through —
    /// so this proves the wiring `run_cli` and the ledger row use, not just `classify` in
    /// isolation.
    #[test]
    fn every_case_is_named_by_the_full_pipeline() {
        use crate::ctx::Overlay;

        let base = "basefeed00";
        let head = "headfeed00";

        // BASE: two loc-ceilings figures (for the plain under/over/undeclared cases) and one
        // `[[cell]]` row at position 0 (for the ordinal case to resolve against), plus no
        // `qa/kind-isolation.toml` `[[minted]]` row yet (the MOVE-classed key is minted on `head`).
        let base_construction = "\
[rules.loc-ceilings]
kernel_ceiling = 100
caps_contract_ceiling = 100
unit_total_ceiling = 100
verbs_ceiling = 50
";
        let base_kind = "[[cell]]\ncrate = \"busbar\"\nkind = \"api\"\ncount = \"10\"\n";

        // HEAD: `kernel_ceiling` rose 100 -> 110 with a declared raise of only 6 (UNDER by 4);
        // `caps_contract_ceiling` rose 100 -> 105 with a declared raise of 9 (OVER by 4);
        // `unit_total_ceiling` rose 100 -> 103 with nothing declared (undeclared rise);
        // the ordinal-keyed declaration below targets `cell.0.count` — `busbar.api` at the base —
        // and that cell rose 10 -> 10 + its declared `by`, exactly (exact, via an ordinal key);
        // a fourth loc-ceiling, `verbs_ceiling`, is unchanged and undeclared (exact, the ordinary
        // case); and `cell.busbar-carved.api.count` is MOVE-classed: minted on `head` and admitted
        // at the ceiling its own `[[minted]]` row carries, not raised from zero.
        let head_construction = "\
[rules.loc-ceilings]
kernel_ceiling = 110
caps_contract_ceiling = 105
unit_total_ceiling = 103
verbs_ceiling = 50

[[gate.ceiling_raises]]
key = \"rules.loc-ceilings.kernel_ceiling\"
by = 6
because = \"UNDER-declaration fixture: the face measured 6 of the 10 lines this row actually rose by\"

[[gate.ceiling_raises]]
key = \"rules.loc-ceilings.caps_contract_ceiling\"
by = 9
because = \"OVER-declaration fixture: the face declared 9 against a rise this tree only carries 5 of\"

[[gate.ceiling_raises]]
key = \"cell.0.count\"
by = 3
file = \"qa/kind-isolation.toml\"
because = \"ordinal-keyed fixture: cell.0 at the base is busbar x api, resolved by row order rather \
           than by the slot number this key is written with\"
";
        let head_kind = "\
[[cell]]
crate = \"busbar\"
kind = \"api\"
count = \"13\"

[[minted]]
crate = \"busbar-carved\"
ceiling = \"20\"

[[cell]]
crate = \"busbar-carved\"
kind = \"api\"
count = \"20\"
";

        let mut overlay = Overlay::new();
        overlay.set_command(format!("git-show:{base}:{CEILINGS}"), base_construction);
        overlay.set_command(format!("git-show:{base}:{KIND_CEILINGS}"), base_kind);
        overlay.set_command(format!("git-show:{head}:{CEILINGS}"), head_construction);
        overlay.set_command(format!("git-show:{head}:{KIND_CEILINGS}"), head_kind);
        let cx = Ctx::workspace()
            .expect("the workspace opens under `cargo test`")
            .with_overlay(overlay);

        let (rows, problems) = ledger(&cx, base, head).expect("the fixture ledger builds");
        assert!(problems.is_empty(), "no unresolved key: {problems:?}");
        let by_key: BTreeMap<&str, &KeyRow> = rows.iter().map(|r| (r.key.as_str(), r)).collect();

        assert_eq!(
            by_key["qa/construction.toml:rules.loc-ceilings.kernel_ceiling"].verdict,
            Verdict::Under(4),
        );
        assert_eq!(
            by_key["qa/construction.toml:rules.loc-ceilings.caps_contract_ceiling"].verdict,
            Verdict::Over(4),
        );
        assert_eq!(
            by_key["qa/construction.toml:rules.loc-ceilings.unit_total_ceiling"].verdict,
            Verdict::UndeclaredRise,
        );
        assert_eq!(
            by_key["qa/construction.toml:rules.loc-ceilings.verbs_ceiling"].verdict,
            Verdict::Exact,
        );
        assert_eq!(
            by_key["qa/kind-isolation.toml:cell.busbar.api.count"].verdict,
            Verdict::Exact,
            "the ordinal-keyed declaration resolves to this identity and covers its rise exactly",
        );
        assert_eq!(
            by_key["qa/kind-isolation.toml:cell.busbar-carved.api.count"].verdict,
            Verdict::Exact,
            "a MOVE-classed key is admitted at its minted ceiling, not raised from zero",
        );

        let named: Vec<String> = rows
            .iter()
            .filter(|r| !r.verdict.is_exact())
            .map(KeyRow::line)
            .collect();
        assert!(named.iter().any(|l| l.contains("UNDER-declared by 4")));
        assert!(named.iter().any(|l| l.contains("OVER-declared by 4")));
        assert!(named.iter().any(|l| l.contains("undeclared rise")));
    }
}
