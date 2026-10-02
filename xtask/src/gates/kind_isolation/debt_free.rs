//! THE DEBT-FREE BASE — the cure for standing-red poisoning in this gate's self-test (item 89).
//!
//! A red case is a proof only when the rows it covers go GREEN -> RED because of the plant. Five of
//! this gate's rows carry real, owned debt on today's tree (`:deps`, `:test-deps`, `:closure`,
//! `:registry`, `:matrix` — the drain is Phase 4's), so the unplanted baseline of every case that
//! covers one of them was already RED, and `prove_red` rightly scored each of those cases PROOF
//! IMPOSSIBLE: 88 of them on `kind-isolation`, 64 on `kind-isolation-ship`.
//!
//! The rule is not weakened and no case is dropped. The case is moved onto a sub-population the
//! debt does not touch — the brief's cure (b), in this gate's own shape. The debt here does not
//! live in files a plant could take out of view (structure-lint's `DebtFree` removes the offending
//! files): it lives in the ledger's stale rows and the kind table's own constants. So the
//! sub-population is the FINDINGS: [`DebtFree`] runs the shipped gate unchanged and takes out of
//! view exactly the findings the UNPLANTED tree already reports, row by row, under BOTH halves of
//! the proof. What is left for a covered row to report is what the plant introduced, so the
//! green -> red transition is the plant's alone.
//!
//! WHY THIS IS NOT A WAY TO PASS:
//!
//! * The debt is MEASURED, once per battery, by running the shipped gate over the unplanted tree —
//!   never a hand-written list, so it cannot hide a finding the tree does not have today.
//! * A plant whose red is a finding the tree ALREADY carries is taken out of view with it, and the
//!   case then comes back GREEN — a FAILED proof, printed as one. Subtraction can only ever cost a
//!   case its red; it cannot manufacture one.
//! * A rule that stopped firing reports nothing new under a plant, so its case goes GREEN and fails.
//! * The naming check still reads only the covered rows, and now only their NEW findings, so a case
//!   cannot be satisfied by debt that happens to contain its word.
//!
//! The real tree's debt stays RED on `cargo xtask gate kind-isolation`. Only the proofs moved.
//!
//! THE BASE IS PINNED, TOO. Two of the rules this subject runs (`:deps`' new-forbidden-edge and
//! `:matrix`'s minted-row) compare the tree against the merge-base, and a checkout that cannot
//! establish one (a detached worktree with no `XTASK_CEILING_BASE`) makes both rules answer
//! `no-base` and nothing else. That finding is standing debt, so it was taken out of view, and a
//! plant those rules must refuse came back GREEN or red for the wrong reason: the proof depended on
//! how the battery's checkout was made. Every run here is measured against `HEAD`, read once per
//! repository root, so a plant is exactly what the battery introduced on every checkout, and a
//! case can plant that base's own files (`git-show:<sha>:<path>`) through [`pinned_base`].

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::gates::construction::ceilings::BASE_PIN_KEY;
use crate::gates::{Gate, Report};
use crate::ledger::{Row, Status, Verdict};

/// The findings the unplanted tree reports, per row id.
pub(super) type Debt = BTreeMap<String, BTreeSet<String>>;

/// A row's detail, split into its HEADLINE and its FINDINGS.
///
/// Every multi-finding row in this gate is written `"<headline>: <f1> | <f2> | …"` and every finding
/// opens with a tab-separated code (`dead-dep-edge\t…`, `ratchet\t…`). So the headline is whatever
/// precedes the last `": "` before the first tab of the first fragment. A detail with no tab at all
/// is ONE finding, headline empty: a single-sentence refusal (`the census did not run`) is compared
/// whole, which is exactly right — the same sentence twice is the same finding.
///
/// The headline is NOT a finding. It carries totals (`145 shipped edge instance(s)`) that move with
/// any plant, and treating a moved total as a new finding would let a case go red on arithmetic
/// rather than on what the rule found.
pub(super) fn split_detail(detail: &str) -> (String, Vec<String>) {
    // A FINDING MAY CARRY ` | ` INSIDE IT — `:closure` prints a path as `a -> b | b -> c`. So a
    // ` | ` only OPENS a new finding when what follows it opens the way a finding does, with a
    // `code\t`; anything else is the previous finding continuing.
    let mut parts: Vec<String> = Vec::new();
    for piece in detail.split(" | ") {
        match parts.last_mut() {
            Some(prev) if !opens_finding(piece) => {
                prev.push_str(" | ");
                prev.push_str(piece);
            }
            _ => parts.push(piece.to_string()),
        }
    }
    let mut head = String::new();
    if let Some(first) = parts.first_mut() {
        if let Some(tab) = first.find('\t') {
            if let Some(h) = first[..tab].rfind(": ") {
                head = first[..h].to_string();
                *first = first[h + 2..].to_string();
            }
        }
    }
    (head, parts)
}

/// Whether `s` opens the way a coded finding does: `code\t…`, the code lowercase with dashes.
fn opens_finding(s: &str) -> bool {
    s.split_once('\t').is_some_and(|(code, _)| {
        !code.is_empty()
            && code
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// The debt a verdict carries: every non-passing row's findings.
pub(super) fn debt_of(verdict: &Verdict) -> Debt {
    let mut out = Debt::new();
    for row in &verdict.rows {
        if row.status != Status::Fail {
            continue;
        }
        let (_, findings) = split_detail(&row.detail);
        out.entry(row.id.clone()).or_default().extend(findings);
    }
    out
}

/// One row with the debt taken out of view. A row whose every finding is debt PASSES, and says how
/// many standing findings it is not showing — so a reader of a planted run can see the base it ran
/// on, rather than mistaking the green for the tree's.
pub(super) fn without_debt(row: Row, debt: &Debt) -> Row {
    if row.status != Status::Fail {
        return row;
    }
    let Some(known) = debt.get(&row.id) else {
        return row;
    };
    let (head, findings) = split_detail(&row.detail);
    let total = findings.len();
    let fresh: Vec<String> = findings
        .into_iter()
        .filter(|f| !known.contains(f))
        .collect();
    if fresh.is_empty() {
        return Row::pass(
            row.id,
            row.title,
            format!("{head} [debt-free base: {total} standing finding(s) out of view]"),
        );
    }
    let detail = if head.is_empty() {
        fresh.join(" | ")
    } else {
        format!("{head}: {}", fresh.join(" | "))
    };
    Row::fail(row.id, row.title, detail)
}

/// THE BASE EVERY DEBT-FREE RUN IS MEASURED AGAINST: the commit `HEAD` names, read ONCE per
/// repository root and then fixed, so a battery on a checkout other writers commit onto does not
/// see its base move between the case that planted against it and the case that reads it. `None`
/// only when `HEAD` itself cannot be read, and then the runs fall back to the live derivation.
pub(super) fn pinned_base(cx: &Ctx) -> Option<String> {
    type Pins = std::sync::Mutex<BTreeMap<std::path::PathBuf, Option<String>>>;
    static PINS: std::sync::OnceLock<Pins> = std::sync::OnceLock::new();
    let pins = PINS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    let mut guard = pins.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .entry(cx.root().to_path_buf())
        .or_insert_with(|| {
            cx.git(&["rev-parse", "HEAD"])
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .clone()
}

/// `cx` with the base pinned to `sha`, unless its overlay already pins one of its own.
fn pinned(cx: &Ctx, sha: Option<&str>) -> Ctx {
    let Some(sha) = sha else {
        return cx.clone();
    };
    if cx.overlay_command(BASE_PIN_KEY).is_some() {
        return cx.clone();
    }
    let mut ov = cx.overlay().cloned().unwrap_or_default();
    ov.set_command(BASE_PIN_KEY, sha);
    cx.with_overlay(ov)
}

/// THE SHIPPED GATE WITH TODAY'S DEBT OUT OF VIEW. See the module header.
pub(super) struct DebtFree {
    pub(super) inner: super::KindIsolationGate,
    pub(super) debt: Debt,
    /// The base every run is pinned to — see [`pinned_base`].
    pub(super) base: Option<String>,
}

impl DebtFree {
    /// Measure the debt of `inner` over the unplanted `cx`, against the pinned base, and wrap it.
    pub(super) fn measure(inner: super::KindIsolationGate, cx: &Ctx) -> DebtFree {
        let base = pinned_base(cx);
        let debt = debt_of(&inner.run(&pinned(cx, base.as_deref())));
        DebtFree { inner, debt, base }
    }
}

impl Gate for DebtFree {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    /// ITS OWN BASELINE, keyed by what it hides: the shipped gate's cached baseline is the real
    /// tree's, debt and all, and serving it here would put the IMPOSSIBLE straight back.
    fn baseline_key(&self) -> Option<String> {
        let hidden: usize = self.debt.values().map(BTreeSet::len).sum();
        let digest = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            self.debt.hash(&mut h);
            h.finish()
        };
        self.inner
            .baseline_key()
            .map(|k| format!("{k}\u{3}debt-free\u{3}{hidden}\u{3}{digest:016x}"))
    }

    fn owed(&self) -> Vec<String> {
        self.inner.owed()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let v = self.inner.run(&pinned(cx, self.base.as_deref()));
        Verdict::of(
            v.rows
                .into_iter()
                .map(|r| without_debt(r, &self.debt))
                .collect(),
        )
    }

    fn selftest<'a>(&'a self, _cx: &'a Ctx) -> Report<'a> {
        Report::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_headline_is_not_a_finding() {
        let (head, f) =
            split_detail("3 finding(s), 9 edge(s): dead\ta -> b\tstrike | unlisted\tc\tadd");
        assert_eq!(head, "3 finding(s), 9 edge(s)");
        assert_eq!(f, vec!["dead\ta -> b\tstrike", "unlisted\tc\tadd"]);
    }

    #[test]
    fn a_bar_inside_a_finding_does_not_split_it() {
        let (_, f) =
            split_detail("2 breach(es): closure-breach\tw -> l\tpath w -> h | h -> l | dead\tx");
        assert_eq!(
            f,
            vec!["closure-breach\tw -> l\tpath w -> h | h -> l", "dead\tx"]
        );
    }

    #[test]
    fn a_detail_with_no_coded_finding_is_one_finding() {
        let (head, f) = split_detail("the census did not run: floor 50");
        assert!(head.is_empty());
        assert_eq!(f, vec!["the census did not run: floor 50"]);
    }

    #[test]
    fn only_debt_is_taken_out_of_view() {
        let debt: Debt = [(
            "r".to_string(),
            ["old\tx\ty".to_string()].into_iter().collect(),
        )]
        .into_iter()
        .collect();
        let all_debt = without_debt(Row::fail("r", "t", "1 finding(s): old\tx\ty"), &debt);
        assert_eq!(all_debt.status, Status::Pass);
        let fresh = without_debt(
            Row::fail("r", "t", "2 finding(s): old\tx\ty | new\tplanted\tz"),
            &debt,
        );
        assert_eq!(fresh.status, Status::Fail);
        assert_eq!(fresh.detail, "2 finding(s): new\tplanted\tz");
        // A row with no recorded debt is untouched, whatever it says.
        let other = without_debt(Row::fail("s", "t", "old\tx\ty"), &debt);
        assert_eq!(other.status, Status::Fail);
    }
}
