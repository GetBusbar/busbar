//! THE LEGACY TRANSLATOR: `scripts/structure-lint.sh`'s OWN OUTPUT, read into the rows this gate
//! would emit for the same tree.
//!
//! The shell writes no ledger — it prints prose and exits 0 or 1 — so a harness that only knew how
//! to read a ledger would be reduced to comparing two exit statuses, which is the weakest possible
//! parity claim: "both said red" says nothing about whether they said red about the SAME LINE OF
//! THE SAME FILE.
//!
//! NOTHING HERE RE-SCANS THE TREE. Every finding below is read out of what the script printed and
//! handed to the SAME constructor the run uses, so the prose in a row's title and detail comes from
//! one place and the only thing a comparison can be about is which offenders were named.
//!
//! ## Two refusals
//!
//! * AN UNRECOGNISED FINDING IS AN ERROR, never a line dropped on the floor. A translator that
//!   silently ignores what it cannot parse is how a rewrite gets proven faithful to a script nobody
//!   read. The informational lines the script prints — headers, `ok` lines, scanned-span reports,
//!   the continuation halves of multi-line notes — are recognised EXPLICITLY, one prefix at a time.
//! * RECOGNISING NOTHING AT ALL is an error too: silence read as a clean tree is the exact defect
//!   this gate exists for.
//!
//! ## The documented row splits
//!
//! The shell prints its findings PER LOCATION under one exit status; this gate owes one row per
//! RULE. Where one shell tag covers two rules the split is recorded in `docs/design/xtask-gates.md`
//! section 6, and the routing that implements it is [`route_tagged`] and the id lookups beside it.

use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{
    axis, census, choke_points, corpus, fn_scoped, hybrid, inline_tests, oversized, plane_dups,
    plane_store, roots, Findings, StructureLintGate, Tables, CORPUS_DEPENDENT,
};
use crate::ledger::Row;
use crate::parity::LegacyRun;

/// Addresses good enough to rebuild the tables' IDS AND TAGS, which is all the routing needs — no
/// cell that carries a path is read here.
fn nominal() -> Addresses {
    Addresses {
        core: roots::CORE.to_string(),
        bin: roots::BIN.to_string(),
        substrate: roots::SUBSTRATE.to_string(),
        substrate_values: roots::SUBSTRATE_VALUES.to_string(),
        proto_roots: Vec::new(),
        mcp: "crates/busbar-mcp/src/mcp".to_string(),
        a2a: "crates/busbar-a2a/src/a2a".to_string(),
    }
}

/// Lines the script prints that are not findings. Each one is listed rather than swallowed by a
/// catch-all, so a NEW kind of finding cannot arrive and be mistaken for chatter.
const CHATTER_PREFIXES: &[&str] = &[
    "== ",
    "ok",
    "scanned ",
    "structure-lint FAILED",
    "known duplication, ledgered and owed a unification:",
    "ledgered ",
    "OVERSIZED (grandfathered",
];

/// Chatter that is recognised by a phrase rather than a prefix: the summary lines the script prints
/// after a finding block, which restate a count this gate carries in the row itself.
const CHATTER_CONTAINS: &[&str] = &[
    "inline test body/bodies — see docs/code-layout.md",
    "are declared in two planes and are NOT on the ledger.",
];

/// Which collector an indented continuation line belongs to, while one is open.
enum Pending {
    /// A census count row: the locations follow it, one per indented line.
    Census {
        head: String,
        at: Vec<String>,
    },
    /// A plane-sink block: one `path:line:content` site per indented line.
    SinkNotNarrowed,
    SinkWidened,
    /// A boot-surface block: the offending FIELD LINES follow, numbered within the struct body
    /// rather than within the file — which is why the offender this gate records is the field
    /// itself. See the row-split note in `docs/design/xtask-gates.md` section 6.
    BootCtxWidened,
    /// A multi-line note whose continuation carries nothing this gate records.
    Discard,
}

impl StructureLintGate {
    pub(super) fn translate(&self, run: &LegacyRun) -> Result<Vec<Row>, String> {
        let tables = match &self.tables {
            Some(t) => t.clone(),
            None => Tables::real(&nominal()),
        };
        let mut f = Findings::default();
        let mut pending: Option<Pending> = None;
        let mut recognised = false;

        for raw in run.lines() {
            let indented = raw.len() - raw.trim_start().len() >= 4;
            let line = raw.trim();

            // An open collector owns the indented lines beneath its head.
            if indented {
                take_continuation(pending.as_mut(), line, &mut f);
                continue;
            }
            close(&mut pending, &mut f);

            if line.is_empty()
                || CHATTER_PREFIXES.iter().any(|p| line.starts_with(p))
                || CHATTER_CONTAINS.iter().any(|p| line.contains(p))
            {
                recognised = true;
                continue;
            }

            match classify(line, &tables, &mut f, &mut pending) {
                Ok(()) => recognised = true,
                Err(e) => return Err(e),
            }
        }
        close(&mut pending, &mut f);

        if !recognised {
            return Err(format!(
                "the legacy translator recognised nothing in `{}`'s output: no header, no verdict, \
                 no findings. Silence read as a clean tree is the exact defect this gate exists for.",
                run.argv.join(" ")
            ));
        }
        if !f.candidate_floor.is_empty() {
            f.did_not_run = CORPUS_DEPENDENT.to_vec();
        }
        Ok(f.sorted().rows())
    }
}

/// The indented lines beneath an open collector's head. A continuation nobody is collecting is the
/// second half of a multi-line note, which carries no offender.
fn take_continuation(p: Option<&mut Pending>, line: &str, f: &mut Findings) {
    let Some(p) = p else {
        return;
    };
    match p {
        Pending::Census { at, .. } => {
            // The `(why)` line closes the block; everything before it is a location.
            if !line.starts_with('(') {
                at.push(line.to_string());
            }
        }
        Pending::SinkNotNarrowed => {
            f.sink_not_narrowed
                .push(plane_store::finding_sink_not_narrowed(&normalise_site(
                    line,
                )));
        }
        Pending::SinkWidened => {
            f.sink_widened
                .push(plane_store::finding_sink_widened(&normalise_site(line)));
        }
        Pending::BootCtxWidened => {
            // `grep -n` numbers the STRUCT BODY, not the file, so the field itself is the offender.
            let field = line.split_once(':').map(|(_, s)| s).unwrap_or(line);
            f.bootctx_widened
                .push(plane_store::finding_bootctx_widened(field.trim()));
        }
        Pending::Discard => {}
    }
}

/// `path:line:content` → `path:line: content`, so a site read out of the script and a site the run
/// built are one string.
fn normalise_site(line: &str) -> String {
    let mut parts = line.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(path), Some(no), Some(rest)) if no.parse::<usize>().is_ok() => {
            format!("{path}:{no}: {}", rest.trim())
        }
        _ => line.to_string(),
    }
}

fn close(pending: &mut Option<Pending>, f: &mut Findings) {
    if let Some(Pending::Census { head, at }) = pending.take() {
        f.census_count.push(if at.is_empty() {
            head
        } else {
            format!("{head} at {}", at.join(" "))
        });
    }
}

/// The one place a printed line becomes a finding.
fn classify(
    line: &str,
    t: &Tables,
    f: &mut Findings,
    pending: &mut Option<Pending>,
) -> Result<(), String> {
    // ── where this lint looks ────────────────────────────────────────────────────────────────────
    if line.starts_with("PROTO-ROOTS-MISSING:") {
        f.proto_roots.push(roots::finding_proto_roots());
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("PLANE-ROOT-MISSING: no directory named ") {
        f.plane_roots
            .push(roots::finding_plane_missing(&backticked(rest)));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("PLANE-ROOT-AMBIGUOUS: ") {
        let plane = backticked(rest);
        let n = rest
            .split_whitespace()
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        f.plane_roots
            .push(roots::finding_plane_ambiguous(&plane, n));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if line.starts_with("PLANE-ROOTS-EMPTY:") {
        f.plane_roots.push(line.to_string());
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if line.starts_with("FAIL: the file list this lint scans holds") {
        f.candidate_floor.push(corpus::finding_floor(line));
        *pending = Some(Pending::Discard);
        return Ok(());
    }

    // ── invariants 1 and 2 ───────────────────────────────────────────────────────────────────────
    if let Some(rest) = line.strip_prefix("HYBRID: ") {
        let base = rest
            .split(".rs coexists")
            .next()
            .unwrap_or_default()
            .to_string();
        f.hybrid.push(hybrid::finding(&base));
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("OVERSIZED: ") {
        let (path, tail) = rest.split_once(" (").ok_or_else(|| unrecognised(line))?;
        let n: usize = tail
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| unrecognised(line))?;
        f.oversized.push(oversized::finding(path, n));
        return Ok(());
    }

    // ── invariant 3 ──────────────────────────────────────────────────────────────────────────────
    if let Some((loc, _)) = line.split_once(": INLINE-TEST:") {
        let (rel, no) = split_loc(loc).ok_or_else(|| unrecognised(line))?;
        f.inline_tests.push(inline_tests::finding_inline(&rel, no));
        return Ok(());
    }
    if let Some((loc, _)) = line.split_once(": ALLOW-WITHOUT-REASON:") {
        let (rel, no) = split_loc(loc).ok_or_else(|| unrecognised(line))?;
        f.allow_reason.push(inline_tests::finding_allow(&rel, no));
        return Ok(());
    }

    // ── the table-shape rules, routed by the id the row printed ──────────────────────────────────
    if let Some(rest) = line.strip_prefix("MALFORMED-ROW: ") {
        let (id, why) = split_em_dash(rest);
        route_by_id(
            t,
            &id,
            f,
            &choke_points::finding_malformed(&id, &why),
            &axis::finding_malformed(&id, &why),
            &census::finding_malformed(&id, &why),
        );
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("MISSING-CLASS-TEST: ") {
        let (id, detail) = split_em_dash(rest);
        f.choke_class_test
            .push(choke_points::finding_class_test(&id, &detail));
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("ALLOWED-PATH-MISSING: ") {
        let (id, detail) = split_em_dash(rest);
        let path = backticked(&detail);
        if detail.contains("arm's new home") {
            f.axis_allowed_path
                .push(axis::finding_allowed_path(&id, &path));
        } else {
            f.choke_allowed_path
                .push(choke_points::finding_allowed_path(&id, &path));
        }
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("ZERO-SCAN: choke point ") {
        let id = rest.split_whitespace().next().unwrap_or_default();
        f.choke_scan_set.push(choke_points::finding_zero_scan(id));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("SCOPE-MISSING: ") {
        let (id, detail) = split_em_dash(rest);
        let path = backticked(&detail);
        if detail.contains("axis's new root") {
            f.axis_scope.push(axis::finding_scope(&id, &path));
        } else {
            f.census_scope.push(census::finding_scope(&id, &path));
        }
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("NO-SUBJECT: ") {
        let (id, detail) = split_em_dash(rest);
        if detail.contains("allowed prefixes cover") {
            f.axis_scan_set.push(axis::finding_no_subject(&id));
        } else {
            f.census_scan_set.push(census::finding_no_subject(&id));
        }
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if line.starts_with("SCAN FAILED on the ") {
        let axis_name = line
            .split_whitespace()
            .nth(4)
            .unwrap_or_default()
            .to_string();
        f.axis_row_integrity.push(axis::finding_malformed(
            &axis_name,
            "the scanner exited non-zero, and an aborted scan returns no hits, which is this rule's \
             pass",
        ));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("NO-ROWS: the ") {
        if rest.contains("census table") {
            f.census_row_integrity.push(census::finding_malformed(
                "the census table",
                "it is EMPTY, so this invariant counted NOTHING",
            ));
        } else if rest.contains("request-path") {
            f.request_path_subject.push(fn_scoped::finding_subject(
                "request-path",
                "the table is EMPTY, so this invariant scanned NOTHING",
            ));
        } else {
            f.decision_input_subject.push(fn_scoped::finding_subject(
                "decision-input",
                "the table is EMPTY, so this invariant scanned NOTHING",
            ));
        }
        return Ok(());
    }

    // ── the subject rules ────────────────────────────────────────────────────────────────────────
    if let Some(rest) = line.strip_prefix("SUBJECT-MISSING: ") {
        let (id, detail) = split_em_dash(rest);
        if detail.contains("occurs NOWHERE") {
            let want = t
                .census
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.want)
                .unwrap_or(1);
            let pattern = backticked(&detail);
            f.census_subject
                .push(census::finding_subject_missing(&id, &pattern, want));
            *pending = Some(Pending::Discard);
            return Ok(());
        }
        let (target, row) = fn_family(t, &id, f);
        let detail = match row {
            Some(r) if detail.contains("declares no") => format!(
                "{} declares no `fn {}`, so this invariant scanned NOTHING and would have reported \
                 a pass ({})",
                r.file, r.func, r.why
            ),
            Some(r) => format!(
                "{} does not exist; point the row at the function's new home",
                r.file
            ),
            None => detail,
        };
        target.push(fn_scoped::finding_subject(&id, &detail));
        *pending = Some(Pending::Discard);
        return Ok(());
    }

    // ── invariant 6 ──────────────────────────────────────────────────────────────────────────────
    if let Some(rest) = line.strip_prefix("PLANE-DUPLICATE (") {
        let (kind, tail) = rest.split_once("): ").ok_or_else(|| unrecognised(line))?;
        let (name, where_) = split_em_dash(tail);
        f.unledgered.push(plane_dups::finding_duplicate(
            kind,
            &backticked(&name),
            &where_,
        ));
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("MALFORMED-LEDGER: ") {
        let (name, why) = split_em_dash(rest);
        let name = backticked(&name);
        if name.contains('|') {
            f.axis_row_integrity
                .push(axis::finding_malformed(&name, &why));
        } else {
            f.ledger_integrity
                .push(plane_dups::finding_malformed(&name, &why));
        }
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("STALE-LEDGER: ") {
        let name = backticked(rest);
        if rest.contains("AXIS_EXCEPTIONS") || rest.contains("axis") {
            let axis_name = rest
                .split("for the ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or_default();
            f.axis_stale_ledger
                .push(axis::finding_stale(axis_name, &name));
        } else {
            f.stale_ledger.push(plane_dups::finding_stale(&name));
        }
        *pending = Some(Pending::Discard);
        return Ok(());
    }

    // ── the plane-store seam and the boot surface ────────────────────────────────────────────────
    if line.starts_with("PLANE-SINK-SCOPE-MISSING:") {
        let scope = backticked(line);
        f.sink_scan_set
            .push(plane_store::finding_sink_scope(&scope));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if line.starts_with("NO-PLANE-SINK:") {
        let scope = line.split('`').nth(3).unwrap_or_default().to_string();
        f.sink_scan_set.push(plane_store::finding_no_sink(&scope));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if line.starts_with("PLANE-SINK-NOT-NARROWED:") {
        *pending = Some(Pending::SinkNotNarrowed);
        return Ok(());
    }
    if line.starts_with("PLANE-SINK-WIDENED:") {
        *pending = Some(Pending::SinkWidened);
        return Ok(());
    }
    if line.starts_with("BOOTCTX-MISSING:") {
        let file = backticked(line);
        f.bootctx_subject
            .push(plane_store::finding_bootctx_missing(&file));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if line.starts_with("BOOTCTX-NOT-NARROWED:") {
        f.bootctx_not_narrowed
            .push(plane_store::finding_bootctx_not_narrowed());
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    if line.starts_with("BOOTCTX-WIDENED:") {
        *pending = Some(Pending::BootCtxWidened);
        return Ok(());
    }

    // ── the tagged findings ──────────────────────────────────────────────────────────────────────
    route_tagged(line, t, f, pending)
}

/// A tagged line is `<TAG>: <rest>`, and the tag says which family owns it. Census rows print a
/// count; every other family prints a location.
fn route_tagged(
    line: &str,
    t: &Tables,
    f: &mut Findings,
    pending: &mut Option<Pending>,
) -> Result<(), String> {
    let Some((tag, rest)) = line.split_once(": ") else {
        return Err(unrecognised(line));
    };

    // A census row's tag is followed by `<id> — expected N … found M:`.
    if let Some(r) = t.census.iter().find(|r| r.tag == tag) {
        let _ = r;
        let (id, detail) = split_em_dash(rest);
        let Some(cs) = t.census.iter().find(|r| r.id == id) else {
            return Err(unrecognised(line));
        };
        let got = detail
            .rsplit_once("found ")
            .and_then(|(_, n)| n.trim_end_matches(':').parse().ok())
            .ok_or_else(|| unrecognised(line))?;
        *pending = Some(Pending::Census {
            head: census::finding_wrong(tag, &cs.id, &cs.pattern, cs.want, got),
            at: Vec::new(),
        });
        return Ok(());
    }

    // Everything else is `<TAG>: <file>:<line>: <what> — <remedy>`.
    let (body, _) = split_em_dash(rest);
    let (loc, what) = body.split_once(": ").ok_or_else(|| unrecognised(line))?;
    let (rel, no) = split_loc(loc).ok_or_else(|| unrecognised(line))?;
    let what = what.trim();

    if t.choke_points.iter().any(|r| r.tag == tag) {
        f.choke_bypass
            .push(choke_points::finding_bypass(tag, &rel, no, what));
        return Ok(());
    }
    if t.request_path.iter().any(|r| r.tag == tag) {
        f.request_path_purity
            .push(fn_scoped::finding_hit(tag, &rel, no, what));
        return Ok(());
    }
    if t.decision_input.iter().any(|r| r.tag == tag) {
        f.decision_input_purity
            .push(fn_scoped::finding_hit(tag, &rel, no, what));
        return Ok(());
    }
    if t.axis_branch.iter().any(|r| r.tag == tag) {
        f.axis_purity
            .push(axis::finding_branch(tag, &rel, no, what));
        *pending = Some(Pending::Discard);
        return Ok(());
    }
    Err(unrecognised(line))
}

/// A `MALFORMED-ROW` can come from any of three tables, and the id says which.
fn route_by_id(
    t: &Tables,
    id: &str,
    f: &mut Findings,
    choke: &str,
    axis_row: &str,
    census_row: &str,
) {
    if t.choke_points.iter().any(|r| r.id == id) {
        f.choke_row_integrity.push(choke.to_string());
    } else if t.axis_branch.iter().any(|r| r.axis == id) {
        f.axis_row_integrity.push(axis_row.to_string());
    } else if t.census.iter().any(|r| r.id == id) {
        f.census_row_integrity.push(census_row.to_string());
    } else {
        // An id in no table is a row somebody added to the script and not to the gate: loud.
        f.census_row_integrity.push(census_row.to_string());
    }
}

/// Which function-scoped family owns an id, and the row it names.
fn fn_family<'a>(
    t: &'a Tables,
    id: &str,
    f: &'a mut Findings,
) -> (&'a mut Vec<String>, Option<&'a fn_scoped::FnRow>) {
    if let Some(r) = t.request_path.iter().find(|r| r.id == id) {
        return (&mut f.request_path_subject, Some(r));
    }
    let row = t.decision_input.iter().find(|r| r.id == id);
    (&mut f.decision_input_subject, row)
}

/// `<file>:<line>` → the pair.
fn split_loc(loc: &str) -> Option<(String, usize)> {
    let (rel, no) = loc.rsplit_once(':')?;
    Some((rel.to_string(), no.parse().ok()?))
}

/// `<head> — <tail>`, the shell's own field separator inside a note.
fn split_em_dash(s: &str) -> (String, String) {
    match s.split_once(" — ") {
        Some((a, b)) => (a.trim().to_string(), b.trim().to_string()),
        None => (s.trim().to_string(), String::new()),
    }
}

/// The first backtick-quoted run in a line.
fn backticked(s: &str) -> String {
    s.split('`').nth(1).unwrap_or_default().to_string()
}

fn unrecognised(line: &str) -> String {
    format!(
        "the legacy translator does not recognise `{line}`. An unclassified finding dropped on the \
         floor is how a rewrite is proven faithful to a script nobody read."
    )
}
