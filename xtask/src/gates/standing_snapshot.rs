//! A STANDING RED THAT CAN ONLY SHRINK: a committed snapshot of the exact findings a gate's
//! standing rows carry, and the posture that excuses those findings and nothing else.
//!
//! [`crate::gates::Excused::OnlyRows`] excuses a whole row. That is right for a row whose red is
//! one fact, and wrong for a row that carries hundreds of findings. Excused wholesale, such a row
//! absorbs every new finding that lands under it, and the standing debt grows unseen. So a
//! row posted here is excused only for the findings the snapshot records, each at its recorded
//! figure:
//!
//! * a finding that is NOT in the snapshot turns the posture RED: a new edge, a new cell, a new
//!   vendor name, anything the debt did not already hold;
//! * a finding whose figure is ABOVE its snapshot figure turns the posture RED: the debt grew;
//! * a finding that points toward the drain (a `dead-*` allowance, a `STALE SLACK` ceiling) is
//!   never a new debt and is reported, not scored;
//! * a snapshot entry that no finding matches any more is STALE, and reported, not scored:
//!   `--write-standing` strikes it and lowers every figure that fell, and writes nothing else.
//!
//! A finding is `<tag>\t<subject>\t<message...>`; the findings of one row are its detail after the
//! summary, joined by ` | `. Its key is the row, the tag and the subject, with any ` = N` figure the
//! subject carries taken out of it; its figure is the number the message measures.

use std::collections::BTreeMap;

use crate::ctx::Ctx;
use crate::ledger::{Row, Status, Verdict};

/// One gate's snapshot-standing rows.
pub struct SnapshotReds {
    /// The row ids excused finding by finding.
    pub rows: &'static [&'static str],
    /// The committed snapshot, repository-relative.
    pub file: &'static str,
}

/// A finding's key: `<row>\t<tag>\t<subject>`.
pub type Key = String;

/// Every finding of `row`, as `(key, figure, drains)`. `drains` is true for a finding that points
/// toward the drain rather than at a debt.
pub fn findings(row: &Row) -> Vec<(Key, i64, bool)> {
    let mut out = Vec::new();
    for chunk in row.detail.split(" | ") {
        let Some(tab) = chunk.find('\t') else {
            continue;
        };
        let head = &chunk[..tab];
        let tag = head
            .rsplit([' ', ':'])
            .next()
            .unwrap_or(head)
            .trim()
            .to_string();
        if tag.is_empty() {
            continue;
        }
        let fields: Vec<&str> = chunk[tab + 1..].split('\t').collect();
        let (mut subject, rest) = match fields.split_first() {
            Some((s, r)) => (s.trim().to_string(), r.join("\t")),
            None => continue,
        };
        let mut figure = None;
        if let Some((s, n)) = subject.rsplit_once(" = ") {
            if let Ok(n) = n.trim().parse::<i64>() {
                figure = Some(n);
                subject = s.trim().to_string();
            }
        }
        if tag == "vendor-name" {
            // `<crate>\t<file>:<line>\t...`: keyed by crate and file, never by line (a line moves
            // with every edit above it), and the figure is how many such findings there are.
            let file = fields
                .get(1)
                .map(|f| f.rsplit_once(':').map_or(*f, |(p, _)| p))
                .unwrap_or("");
            subject = format!("{subject} {file}");
            figure = Some(1);
        }
        let figure = figure
            .or_else(|| number_after(&rest, "vs measured "))
            .or_else(|| number_after(&rest, "scored count is the higher, "))
            .or_else(|| number_before(&rest, " time(s)"))
            .unwrap_or(1);
        let drains = tag.starts_with("dead-") || rest.contains("STALE SLACK");
        out.push((format!("{}\t{tag}\t{subject}", row.id), figure, drains));
    }
    out
}

fn number_after(text: &str, needle: &str) -> Option<i64> {
    let at = text.find(needle)? + needle.len();
    let digits: String = text[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn number_before(text: &str, needle: &str) -> Option<i64> {
    let at = text.find(needle)?;
    let digits: String = text[..at]
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

/// The debt findings of the standing rows, summed by key.
fn debt(sr: &SnapshotReds, verdict: &Verdict) -> (BTreeMap<Key, i64>, Vec<String>) {
    let mut debt: BTreeMap<Key, i64> = BTreeMap::new();
    let mut drains = Vec::new();
    for row in verdict
        .rows
        .iter()
        .filter(|r| r.status != Status::Pass && sr.rows.contains(&r.id.as_str()))
    {
        for (key, figure, drain) in findings(row) {
            if drain {
                drains.push(key);
            } else {
                *debt.entry(key).or_insert(0) += figure;
            }
        }
    }
    (debt, drains)
}

/// Parse a snapshot: `<row>\t<tag>\t<subject>\t<figure>` per line, `#` comments and blanks ignored.
pub fn parse(text: &str) -> Result<BTreeMap<Key, i64>, String> {
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim_end();
        if t.trim().is_empty() || t.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, figure)) = t.rsplit_once('\t') else {
            return Err(format!(
                "line {}: not `<row>\\t<tag>\\t<subject>\\t<figure>`",
                n + 1
            ));
        };
        let figure: i64 = figure
            .trim()
            .parse()
            .map_err(|_| format!("line {}: figure `{figure}` is not a number", n + 1))?;
        if key.split('\t').count() != 3 {
            return Err(format!(
                "line {}: the key is not `<row>\\t<tag>\\t<subject>`",
                n + 1
            ));
        }
        out.insert(key.to_string(), figure);
    }
    Ok(out)
}

/// The judgement of `verdict` against `snapshot`: `(blocking, report_only)`. Empty `blocking` means
/// the posture holds.
pub fn judge(
    sr: &SnapshotReds,
    verdict: &Verdict,
    snapshot: &BTreeMap<Key, i64>,
) -> (Vec<String>, Vec<String>) {
    let mut blocking: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.status != Status::Pass && !sr.rows.contains(&r.id.as_str()))
        .map(|r| format!("NEW RED {} {}", r.id, r.detail))
        .collect();
    blocking.extend(
        verdict
            .problems
            .iter()
            .filter(|t| !sr.rows.iter().any(|id| t.starts_with(&format!("{id}: "))))
            .map(|t| format!("NEW RED {t}")),
    );
    let (debt, drains) = debt(sr, verdict);
    for (key, figure) in &debt {
        match snapshot.get(key) {
            None => blocking.push(format!(
                "NEW FINDING {} = {figure}: not in {} — a debt the snapshot does not hold",
                key.replace('\t', " "),
                sr.file
            )),
            Some(was) if figure > was => blocking.push(format!(
                "RISE {}: {was} -> {figure} — the standing debt grew",
                key.replace('\t', " ")
            )),
            Some(_) => {}
        }
    }
    let mut report: Vec<String> = snapshot
        .iter()
        .filter(|(k, _)| !debt.contains_key(*k))
        .map(|(k, v)| {
            format!(
                "STALE {} = {v}: no finding carries it any more — `--write-standing` strikes it",
                k.replace('\t', " ")
            )
        })
        .collect();
    report.extend(snapshot.iter().filter_map(|(k, was)| {
        let now = debt.get(k)?;
        (now < was).then(|| {
            format!(
                "LOWER {}: {was} -> {now} — `--write-standing` lowers it",
                k.replace('\t', " ")
            )
        })
    }));
    report.extend(drains.into_iter().map(|k| {
        format!(
            "DRAINING {}: an allowance the tree no longer needs — the ledger's own `--write` strikes it",
            k.replace('\t', " ")
        )
    }));
    (blocking, report)
}

/// Read the committed snapshot through `cx`.
pub fn load(cx: &Ctx, sr: &SnapshotReds) -> Result<BTreeMap<Key, i64>, String> {
    parse(&cx.read(sr.file).map_err(|e| format!("{}: {e}", sr.file))?)
}

const HEADER: &str = "\
# THE STANDING FINDINGS of a gate's snapshot-standing rows (see xtask/src/gates/standing_snapshot.rs).
# One line per finding: <row>\\t<tag>\\t<subject>\\t<figure>. The `--posture` run excuses exactly these,
# at or below these figures, and reds anything new or higher. Written ONLY by
# `cargo xtask gate <gate> --posture --write-standing`, which strikes and lowers and never adds.
";

/// The lowered snapshot text: every entry a finding still carries, at the lower of its two figures.
/// Nothing is added. `bootstrap` writes every current debt finding, and is refused unless the
/// snapshot does not exist yet.
pub fn rewrite(
    sr: &SnapshotReds,
    verdict: &Verdict,
    snapshot: Option<&BTreeMap<Key, i64>>,
) -> String {
    let (debt, _) = debt(sr, verdict);
    let kept: BTreeMap<&Key, i64> = match snapshot {
        Some(snap) => snap
            .iter()
            .filter_map(|(k, was)| debt.get(k).map(|now| (k, (*was).min(*now))))
            .collect(),
        None => debt.iter().map(|(k, v)| (k, *v)).collect(),
    };
    let mut out = HEADER.to_string();
    for (k, v) in kept {
        out.push_str(&format!("{k}\t{v}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SR: SnapshotReds = SnapshotReds {
        rows: &["g:matrix"],
        file: "qa/planted.standing.txt",
    };

    fn row(detail: &str) -> Row {
        Row::fail("g:matrix", "t", detail)
    }

    const TREE: &str = "2 hit(s): ratchet\tbusbar × auth\tceiling 26 vs measured 30 (RAISED). | \
                        unlisted-edge\tcleanliness -> auth\tbusbar-core-admin names auth vocabulary 29 time(s). | \
                        dead-cell\tbusbar-x × plane\tthe cell measures 0.";

    fn snap_of(tree: &str) -> BTreeMap<Key, i64> {
        parse(&rewrite(&SR, &Verdict::of(vec![row(tree)]), None)).expect("parses")
    }

    #[test]
    fn a_finding_is_keyed_by_row_tag_and_subject_and_carries_its_measurement() {
        let f = findings(&row(TREE));
        assert!(f.contains(&("g:matrix\tratchet\tbusbar × auth".to_string(), 30, false)));
        assert!(f.contains(&(
            "g:matrix\tunlisted-edge\tcleanliness -> auth".to_string(),
            29,
            false
        )));
        assert!(f.contains(&("g:matrix\tdead-cell\tbusbar-x × plane".to_string(), 1, true)));
        let cell = findings(&row(
            "x: unlisted-cell\tbusbar × export = 7\tadd `count = \"7\"`.",
        ));
        assert_eq!(
            cell,
            vec![(
                "g:matrix\tunlisted-cell\tbusbar × export".to_string(),
                7,
                false
            )]
        );
    }

    #[test]
    fn green_when_the_snapshot_equals_the_tree() {
        let v = Verdict::of(vec![row(TREE)]);
        let (blocking, _) = judge(&SR, &v, &snap_of(TREE));
        assert!(blocking.is_empty(), "{blocking:?}");
    }

    #[test]
    fn red_on_a_planted_new_edge() {
        let planted = format!(
            "{TREE} | unlisted-edge\thooks -> cleanliness\tbusbar-hooks-x names cleanliness vocabulary 1 time(s)."
        );
        let (blocking, _) = judge(&SR, &Verdict::of(vec![row(&planted)]), &snap_of(TREE));
        assert!(
            blocking
                .iter()
                .any(|b| b.starts_with("NEW FINDING") && b.contains("hooks -> cleanliness")),
            "{blocking:?}"
        );
    }

    #[test]
    fn red_on_a_planted_rise_in_a_standing_cell() {
        let planted = TREE.replace("vs measured 30", "vs measured 31");
        let (blocking, _) = judge(&SR, &Verdict::of(vec![row(&planted)]), &snap_of(TREE));
        assert!(
            blocking
                .iter()
                .any(|b| b.starts_with("RISE") && b.contains("30 -> 31")),
            "{blocking:?}"
        );
    }

    #[test]
    fn a_stale_or_lowered_entry_is_reported_not_scored_and_write_only_shrinks() {
        let drained = TREE
            .replace("vs measured 30", "vs measured 28")
            .replace(" | unlisted-edge\tcleanliness -> auth\tbusbar-core-admin names auth vocabulary 29 time(s).", "");
        let v = Verdict::of(vec![row(&drained)]);
        let snap = snap_of(TREE);
        let (blocking, report) = judge(&SR, &v, &snap);
        assert!(blocking.is_empty(), "{blocking:?}");
        assert!(report
            .iter()
            .any(|r| r.starts_with("STALE") && r.contains("cleanliness -> auth")));
        assert!(report
            .iter()
            .any(|r| r.starts_with("LOWER") && r.contains("30 -> 28")));
        let lowered = parse(&rewrite(&SR, &v, Some(&snap))).expect("parses");
        assert_eq!(lowered.get("g:matrix\tratchet\tbusbar × auth"), Some(&28));
        assert!(!lowered.contains_key("g:matrix\tunlisted-edge\tcleanliness -> auth"));
        // A new finding is never written by the lowering path.
        let grown = format!("{drained} | unlisted-cell\tnew × kind = 3\tadd it.");
        let still =
            parse(&rewrite(&SR, &Verdict::of(vec![row(&grown)]), Some(&snap))).expect("parses");
        assert!(!still.contains_key("g:matrix\tunlisted-cell\tnew × kind"));
    }

    #[test]
    fn a_red_row_outside_the_snapshot_rows_is_new() {
        let v = Verdict::of(vec![row(TREE), Row::fail("g:name", "t", "a fused name")]);
        let (blocking, _) = judge(&SR, &v, &snap_of(TREE));
        assert!(
            blocking.iter().any(|b| b.starts_with("NEW RED g:name")),
            "{blocking:?}"
        );
    }
}
