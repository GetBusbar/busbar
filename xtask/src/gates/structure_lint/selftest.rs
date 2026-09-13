//! THE SCANNER THAT GUARDS THE TREE IS ITSELF GUARDED.
//!
//! Every owed row id gets a case that plants its violation and requires the run to NAME the planted
//! offender. A scanner with a bypass is worse than no scanner: it reports "ok, no bypass" while the
//! bypass sits in production.
//!
//! Two kinds of plant, and which one a rule needs is decided by what its subject IS:
//!
//! * A TREE PLANT — an [`Overlay`] — for every rule whose subject is source. The gate reads the
//!   planted tree through the same `Ctx` it reads the real one through, so nothing is copied,
//!   restored, or left behind.
//! * A TABLE PLANT — a [`StructureLintGate::with_tables`] variant — for the rules whose subject is
//!   a TABLE: a malformed row, an allowed path that moved, a ledger row that outlived its
//!   duplication. No overlay can plant those, because the table is source rather than tree. The
//!   case still reaches the gate only through `Gate::run`, so it drives the SHIPPED runner over a
//!   planted table exactly as the shell's `selftest_case` drove the shipped `scan_rule` over a
//!   planted fixture.

use crate::ctx::{Ctx, Overlay};
use crate::gates::structure_lint::{
    axis, census, choke_points, corpus, fn_scoped, hybrid, inline_tests, oversized, plane_dups,
    plane_store, roots, StructureLintGate, Tables,
};
use crate::gates::{prove_rows_green, prove_rows_red, Gate, Report};

/// A tree plant: the overlay, and the strings the ROWS THIS CASE COVERS must name.
fn tree_case<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    ov: Overlay,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    prove_rows_red(cx, gate, name, covers, ov, naming)
}

/// A table plant: the same proof, over a table this tree could not otherwise produce.
fn table_case<'a>(
    cx: &'a Ctx,
    name: &str,
    covers: &[&str],
    tables: Tables,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    // The gate is built FOR THIS CASE, so the case owns it: the plan is taken on whichever thread
    // reaches it, long after this function has returned.
    let name = name.to_string();
    let covers: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let naming: Vec<String> = naming.iter().map(|s| (*s).to_string()).collect();
    crate::gates::CasePlan::new(move || {
        let planted = StructureLintGate::with_tables(tables);
        let covers: Vec<&str> = covers.iter().map(String::as_str).collect();
        let naming: Vec<&str> = naming.iter().map(String::as_str).collect();
        prove_rows_red(cx, &planted, name, &covers, Overlay::new(), &naming).take()
    })
}

/// The green arm of a rule, over the rows that rule owns.
fn green_case<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    ov: Overlay,
) -> crate::gates::CasePlan<'a> {
    prove_rows_green(cx, gate, name, covers, ov)
}

/// The tree with a rule's PRE-EXISTING offenders taken out of view.
///
/// A green case says "this SHAPE is not a violation". On a branch whose tree already carries real
/// debt in the same row, asking the row to be green would be asking about the debt instead — and
/// the case would be deleted rather than fixed the first time somebody legitimately added an entry
/// to the grandfathered list. So the plant starts from a tree holding none of that rule's current
/// offenders, and the only thing left for the row to judge is what the case planted.
fn without_existing(
    cx: &Ctx,
    gate: &StructureLintGate,
    pick: fn(&crate::gates::structure_lint::Findings) -> &Vec<String>,
) -> Overlay {
    let mut ov = Overlay::new();
    for finding in pick(&gate.findings(cx)) {
        if let Some(path) = offender_path(finding) {
            ov.remove(path);
        }
    }
    ov
}

/// The file a finding is about, for the two shapes these rules' findings take.
fn offender_path(finding: &str) -> Option<String> {
    if let Some(rest) = finding.strip_prefix("OVERSIZED: ") {
        return rest.split_once(" (").map(|(p, _)| p.to_string());
    }
    if finding.contains(": INLINE-TEST") || finding.contains(": ALLOW-WITHOUT-REASON") {
        return finding.split(':').next().map(str::to_string);
    }
    None
}

/// The real tables, resolved against this tree, as the base every table plant edits.
fn base_tables(cx: &Ctx) -> Tables {
    let mut throwaway = crate::gates::structure_lint::Findings::default();
    Tables::real(&roots::resolve(cx, &mut throwaway))
}

pub fn run<'a>(gate: &'a StructureLintGate, cx: &'a Ctx) -> Report<'a> {
    let mut report = Report::new();
    let t = base_tables(cx);

    // ── where this lint looks ────────────────────────────────────────────────────────────────────
    //
    // Emptying every protocol crate is what a step-4 crate move looks like from the scan's side:
    // the axis rows keep their prefixes and read zero files through them.
    let mut ov = Overlay::new();
    let mut emptied = 0usize;
    if let Ok(files) = cx.walk(&crate::ctx::WalkSpec::new([roots::CRATES]).ext("rs")) {
        for s in &files {
            let rel = s.rel_str();
            if rel.starts_with("crates/busbar-llm/src/")
                || rel.starts_with("crates/busbar-mcp/src/")
                || rel.starts_with("crates/busbar-proto-")
                || (rel.starts_with("crates/busbar-") && rel.contains("-codec/src/"))
            {
                ov.remove(&s.rel);
                emptied += 1;
            }
        }
    }
    if emptied == 0 {
        report.note_infra_failure(
            "structure-lint selftest: this tree holds no protocol crate to empty, so the \
             proto-roots rule is unproven here rather than passing",
        );
    } else {
        report.push(tree_case(
            cx,
            gate,
            "a tree with no protocol crate left is refused, not read as a clean axis",
            &[roots::ROW_PROTO_ROOTS],
            ov,
            &["PROTO-ROOTS-MISSING"],
        ));
    }

    // A plane whose grammar left its `mod.rs` is a plane nothing can locate — and every rule that
    // names it would then scan zero files, which is the passing answer to a ban.
    match plane_grammar_file(cx, "mcp") {
        Some((rel, text)) => {
            let mut ov = Overlay::new();
            ov.set(
                &rel,
                text.replace(crate::planes::PLANE_GRAMMAR, "pub const MOVED_AWAY"),
            );
            report.push(tree_case(
                cx,
                gate,
                "a plane whose declaration moved is refused, not silently unscanned",
                &[roots::ROW_PLANE_ROOTS],
                ov,
                &["PLANE-ROOT-MISSING", "mcp"],
            ));
        }
        None => report.note_infra_failure(
            "structure-lint selftest: no file declares the mcp plane's grammar, so the plane-root \
             rule has nothing to plant against",
        ),
    }

    // ── the denominator ──────────────────────────────────────────────────────────────────────────
    match cx.walk(
        &crate::ctx::WalkSpec::new([roots::CRATES])
            .ext("rs")
            .exclude(["/tests/", "/benches/"]),
    ) {
        Ok(files) => {
            let mut ov = Overlay::new();
            for s in &files {
                ov.remove(&s.rel);
            }
            report.push(tree_case(
                cx,
                gate,
                "a candidate corpus below its floor is refused, not reported as a clean tree",
                &[corpus::ROW_CANDIDATE_FLOOR],
                ov,
                &["CANDIDATE-FLOOR"],
            ));
        }
        Err(e) => report.note_infra_failure(format!(
            "structure-lint selftest: the candidate walk is unreadable ({e}), so the floor plant \
             has nothing to empty"
        )),
    }

    // ── invariants 1 and 2 ───────────────────────────────────────────────────────────────────────
    let mut ov = Overlay::new();
    ov.set(
        format!("{}/plane.rs", roots::CORE),
        "// a module that is a file AND a folder\npub fn half_of_it() {}\n",
    );
    report.push(tree_case(
        cx,
        gate,
        "a module that is both a file and a folder is a hybrid",
        &[hybrid::ROW_HYBRID],
        ov,
        &["HYBRID", "plane.rs"],
    ));

    let mut ov = Overlay::new();
    ov.set(
        format!("{}/planted_monster.rs", roots::CORE),
        "pub fn f() {}\n".repeat(oversized::MAX_LINES_IMPL + 1),
    );
    report.push(tree_case(
        cx,
        gate,
        "a file over the cap that is not pre-existing debt is a finding",
        &[oversized::ROW_OVERSIZED],
        ov,
        &["OVERSIZED", "planted_monster.rs"],
    ));

    // A GRANDFATHERED FILE STAYS GREEN, which is the half of the rule an exception list can get
    // wrong in the expensive direction.
    if let Some(first) = t.grandfathered.first() {
        let mut ov = without_existing(cx, gate, |f| &f.oversized);
        ov.set(
            first,
            format!(
                "// grandfathered, still over the cap\n{}",
                "pub fn f() {}\n".repeat(oversized::MAX_LINES_IMPL + 1)
            ),
        );
        report.push(green_case(
            cx,
            gate,
            "a grandfathered file over the cap is tracked debt, not a fresh violation",
            &[oversized::ROW_OVERSIZED],
            ov,
        ));
    }

    // ── invariant 3 ──────────────────────────────────────────────────────────────────────────────
    let mut ov = Overlay::new();
    ov.set(
        format!("{}/planted_inline_test.rs", roots::CORE),
        "pub fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n",
    );
    report.push(tree_case(
        cx,
        gate,
        "an inline test body in an implementation file is a finding",
        &[inline_tests::ROW_INLINE_TEST],
        ov,
        &["INLINE-TEST", "planted_inline_test.rs:3"],
    ));

    let mut ov = Overlay::new();
    ov.set(
        format!("{}/planted_bare_allow.rs", roots::CORE),
        "pub fn prod() {}\n\n// structure-lint: allow inline-test\n#[cfg(test)]\nmod tests {\n    \
         #[test]\n    fn t() {}\n}\n",
    );
    report.push(tree_case(
        cx,
        gate,
        "an allow marker with no reason is its own violation, not a weaker pass",
        &[inline_tests::ROW_ALLOW_REASON],
        ov,
        &["ALLOW-WITHOUT-REASON", "planted_bare_allow.rs:4"],
    ));

    // A MARKER THAT NAMES ITS REASON is the arm an allow mechanism has to get right, and the
    // DECLARATION shape must not trip the rule either.
    let mut ov = without_existing(cx, gate, |f| &f.inline_tests);
    ov.set(
        format!("{}/planted_reasoned_allow.rs", roots::CORE),
        "pub fn prod() {}\n\n// structure-lint: allow inline-test: the harness cannot reach a \
         private const from another file\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n\n\
         #[cfg(test)]\n#[path = \"tests/prod_tests.rs\"]\nmod declared;\n",
    );
    report.push(green_case(
        cx,
        gate,
        "a reasoned allow and a #[path] declaration are both clean",
        &[
            inline_tests::ROW_INLINE_TEST,
            inline_tests::ROW_ALLOW_REASON,
        ],
        ov,
    ));

    // ── invariant 4 ──────────────────────────────────────────────────────────────────────────────
    let mut ov = Overlay::new();
    ov.set(
        format!("{}/planted_bypass.rs", roots::CORE),
        "pub fn publish() {\n    std::fs::rename(&tmp, &dst).unwrap();\n}\n",
    );
    report.push(tree_case(
        cx,
        gate,
        "a hand-rolled durable-write bypass is named by file and line",
        &[choke_points::ROW_BYPASS],
        ov,
        &["DURABLE-BYPASS", "planted_bypass.rs:2"],
    ));

    // A LINE INSIDE A `#[cfg(test)]` REGION IS NOT A BYPASS, and neither is one in a comment. Both
    // shapes were provably exploitable against the scanner this replaces.
    let mut ov = Overlay::new();
    ov.set(
        format!("{}/planted_not_a_bypass.rs", roots::CORE),
        "// prose may say std::fs::rename( without being one\n#[cfg(test)]\nmod tests {\n    \
         fn helper() { std::fs::rename(a, b); }\n}\npub fn prod() {}\n",
    );
    report.push(green_case(
        cx,
        gate,
        "prose and test code may name a banned call; production code may not",
        &[choke_points::ROW_BYPASS],
        ov,
    ));

    if let Some(r) = t.choke_points.first() {
        let file = r.class_test.rsplit_once("::").map(|(f, _)| f.to_string());
        if let Some(file) = file {
            if cx.exists(&file) {
                let mut ov = Overlay::new();
                ov.remove(&file);
                report.push(tree_case(
                    cx,
                    gate,
                    "a choke point whose class test was deleted is a choke point nothing proves",
                    &[choke_points::ROW_CLASS_TEST],
                    ov,
                    &["MISSING-CLASS-TEST", &r.id],
                ));
            }
        }
    }

    report.push(table_case(
        cx,
        "a registry row whose allowed path moved is named where the fix is one path",
        &[choke_points::ROW_ALLOWED_PATH],
        with_choke_allow_moved(&t),
        &["ALLOWED-PATH-MISSING"],
    ));
    report.push(table_case(
        cx,
        "a registry row that carries the separator, or will not compile, is refused",
        &[choke_points::ROW_ROW_INTEGRITY],
        with_choke_row_broken(&t),
        &["MALFORMED-ROW"],
    ));
    report.push(table_case(
        cx,
        "a ban whose allow-list swallowed every candidate did not run, and did not pass",
        &[choke_points::ROW_SCAN_SET],
        with_choke_allow_everything(cx, &t),
        &["ZERO-SCAN"],
    ));

    // ── invariants 5 and 8 ───────────────────────────────────────────────────────────────────────
    for (label, rows, subject_row, purity_row, planted) in [
        (
            "request-path",
            &t.request_path,
            fn_scoped::ROW_REQUEST_PATH_SUBJECT,
            fn_scoped::ROW_REQUEST_PATH_PURITY,
            "        let _ = self.store.get(k);\n",
        ),
        (
            "decision-input",
            &t.decision_input,
            fn_scoped::ROW_DECISION_INPUT_SUBJECT,
            fn_scoped::ROW_DECISION_INPUT_PURITY,
            "        let _ = tool.description.clone();\n",
        ),
    ] {
        let Some(r) = rows.first() else {
            report.note_infra_failure(format!(
                "structure-lint selftest: the {label} table is empty, so its rules are unproven"
            ));
            continue;
        };
        match plant_into_fn(cx, &r.file, &r.func, planted) {
            Some(ov) => report.push(tree_case(
                cx,
                gate,
                &format!("a banned call inside the {label} function is named by line"),
                &[purity_row],
                ov,
                &[&r.tag],
            )),
            None => report.note_infra_failure(format!(
                "structure-lint selftest: `fn {}` is not in {}, so the {label} plant has no body \
                 to plant into",
                r.func, r.file
            )),
        }
        // THE SUBJECT RULE: a function that was renamed away scans nothing and reports nothing,
        // which reads exactly like a pass.
        if let Ok(text) = cx.read(&r.file) {
            let mut ov = Overlay::new();
            ov.set(
                &r.file,
                text.replace(&format!("fn {}", r.func), "fn renamed_away"),
            );
            report.push(tree_case(
                cx,
                gate,
                &format!("a renamed {label} subject is refused, not read as a clean function"),
                &[subject_row],
                ov,
                &["SUBJECT-MISSING", &r.id],
            ));
        }
    }

    // ── invariant 6 ──────────────────────────────────────────────────────────────────────────────
    let addresses = {
        let mut throwaway = crate::gates::structure_lint::Findings::default();
        roots::resolve(cx, &mut throwaway)
    };
    let mut ov = Overlay::new();
    ov.set(
        format!("{}/planted_shared_concern.rs", addresses.mcp),
        "pub fn planted_shared_concern() {}\n",
    );
    ov.set(
        format!("{}/planted_shared_concern.rs", addresses.a2a),
        "pub fn planted_shared_concern() {}\n",
    );
    report.push(tree_case(
        cx,
        gate,
        "one name declared at file scope in two planes is a duplicate nobody signed for",
        &[plane_dups::ROW_UNLEDGERED],
        ov,
        &["PLANE-DUPLICATE", "planted_shared_concern"],
    ));

    report.push(table_case(
        cx,
        "a ledger row for duplication that is no longer there is refused, not left to rot",
        &[plane_dups::ROW_STALE_LEDGER],
        with_stale_plane_row(&t),
        &["STALE-LEDGER", "a_name_no_plane_declares"],
    ));
    report.push(table_case(
        cx,
        "a ledger row with no signed claim asserts nothing",
        &[plane_dups::ROW_LEDGER_INTEGRITY],
        with_malformed_plane_row(&t),
        &["MALFORMED-LEDGER"],
    ));

    // ── invariant 7 ──────────────────────────────────────────────────────────────────────────────
    let mut ov = Overlay::new();
    ov.set(
        format!("{}/planted_axis_branch.rs", roots::CORE),
        "pub fn pick(transport: Transport) -> u8 {\n    if transport == Transport::Http { 1 } else { 0 }\n}\n",
    );
    report.push(tree_case(
        cx,
        gate,
        "the agnostic core asking a transport its identity is a finding",
        &[axis::ROW_PURITY],
        ov,
        &["TRANSPORT-BRANCH", "planted_axis_branch.rs:2"],
    ));

    report.push(table_case(
        cx,
        "an axis row whose scope moved is refused, not read as a clean core",
        &[axis::ROW_SCOPE],
        with_axis_scope_moved(&t),
        &["SCOPE-MISSING"],
    ));
    report.push(table_case(
        cx,
        "an axis arm whose home moved is named before the ban widens onto it",
        &[axis::ROW_ALLOWED_PATH],
        with_axis_arm_moved(&t),
        &["ALLOWED-PATH-MISSING"],
    ));
    report.push(table_case(
        cx,
        "an axis whose allowed arms cover its whole scope scanned nothing",
        &[axis::ROW_SCAN_SET],
        with_axis_arm_covering_everything(&t),
        &["NO-SUBJECT"],
    ));
    report.push(table_case(
        cx,
        "an incomplete axis row is refused",
        &[axis::ROW_ROW_INTEGRITY],
        with_axis_row_broken(&t),
        &["MALFORMED-ROW"],
    ));
    report.push(table_case(
        cx,
        "an axis exception that outlived its branch is refused, not left as a permanent amnesty",
        &[axis::ROW_STALE_LEDGER],
        with_stale_axis_exception(&t),
        &["STALE-LEDGER"],
    ));

    // ── invariant 9 ──────────────────────────────────────────────────────────────────────────────
    if let Some(r) = t.census.first() {
        let spelling = r.pattern.replace(['\\', '"'], "");
        let mut ov = Overlay::new();
        ov.set(
            format!("{}/planted_second_spelling.rs", roots::CORE),
            format!("pub const SECOND: &str = \"{spelling}\";\n"),
        );
        report.push(tree_case(
            cx,
            gate,
            "a second spelling of a shared wire word is counted and named",
            &[census::ROW_COUNT],
            ov,
            &[&r.tag, &r.id],
        ));
    }
    report.push(table_case(
        cx,
        "a census subject that occurs nowhere asserted nothing, which is not a pass",
        &[census::ROW_SUBJECT],
        with_census_absent_subject(&t),
        &["SUBJECT-MISSING"],
    ));
    report.push(table_case(
        cx,
        // COVERS `:scope` AND NOT `:scan-set`. A scope that moved is refused BY THE SCOPE ROW and
        // stops there — the scan-set rule never gets a scope to count production source under, so
        // it stays green here and is proven by the plant below that leaves the scope in place and
        // empties it. Claiming both rows was the F11 shape: the red belonged to one of them, and
        // the other's coverage was a declaration nobody checked.
        "a census scope that moved is refused",
        &[census::ROW_SCOPE],
        with_census_scope_moved(&t),
        &["SCOPE-MISSING"],
    ));
    report.push(table_case(
        cx,
        "a census count of zero is a ban wearing a census's clothes",
        &[census::ROW_ROW_INTEGRITY],
        with_census_zero_count(&t),
        &["MALFORMED-ROW"],
    ));
    report.push(table_case(
        cx,
        "a census row whose scope holds no production source counted nothing",
        &[census::ROW_SCAN_SET],
        with_census_empty_scope(&t),
        &["NO-SUBJECT"],
    ));

    // ── invariant (a) ────────────────────────────────────────────────────────────────────────────
    if let Some((rel, text)) = sink_file(cx, &addresses) {
        let mut ov = Overlay::new();
        ov.set(&rel, text.replace("PlaneStore", "Store"));
        // TWO ROWS, TWO CASES, over the same plant. Listed together, a red from either one passed
        // the pair — and only `not-narrowed` was ever firing, so `widened` could have been deleted
        // with the selftest green. Each now reads its own row and nothing else.
        report.push(tree_case(
            cx,
            gate,
            "a plane sink that stops naming the narrowed store re-arms the forge",
            &[plane_store::ROW_SINK_NOT_NARROWED],
            ov,
            &["PLANE-SINK-NOT-NARROWED"],
        ));

        let mut ov = Overlay::new();
        ov.set(&rel, text.replace("PlaneStore", "Store"));
        report.push(tree_case(
            cx,
            gate,
            "a plane sink widened back to the audit-carrying store is a finding on its own row",
            &[plane_store::ROW_SINK_WIDENED],
            ov,
            &["PLANE-SINK-WIDENED"],
        ));

        // EVERY sink, not one of them: a rule that still finds a second attach has not been shown
        // the tree a rename produces.
        let mut ov = Overlay::new();
        if let Ok(files) =
            cx.walk(&crate::ctx::WalkSpec::new([format!("{}/plane", addresses.core)]).ext("rs"))
        {
            for s in &files {
                if s.text.contains("fn set_sink") {
                    ov.set(&s.rel, s.text.replace("fn set_sink", "fn attach_the_sink"));
                }
            }
        }
        report.push(tree_case(
            cx,
            gate,
            "a renamed sink attach is refused, not read as a clean seam",
            &[plane_store::ROW_SINK_SCAN_SET],
            ov,
            &["NO-PLANE-SINK"],
        ));
    } else {
        report.note_infra_failure(
            "structure-lint selftest: no plane sink attach to plant against, so invariant (a)'s \
             sink half is unproven here rather than passing",
        );
    }

    let bootctx = format!("{}/plane/registry.rs", addresses.core);
    if let Ok(text) = cx.read(&bootctx) {
        let mut ov = Overlay::new();
        ov.set(
            &bootctx,
            text.replace("pub struct BootCtx", "pub struct BootContext"),
        );
        report.push(tree_case(
            cx,
            gate,
            "a boot seam that moved or was renamed is refused",
            &[plane_store::ROW_BOOTCTX_SUBJECT],
            ov,
            &["BOOTCTX-MISSING"],
        ));

        let mut ov = Overlay::new();
        ov.set(&bootctx, widen_bootctx(&text));
        report.push(tree_case(
            cx,
            gate,
            "a boot-surface field that reaches the audit chain is a finding",
            &[plane_store::ROW_BOOTCTX_WIDENED],
            ov,
            &["BOOTCTX-WIDENED"],
        ));

        // THE POSITIVE HALF, ON ITS OWN ROW. It was listed beside the two cases above and proven by
        // neither: both of them go red on a row this one is not about, so the rule that requires the
        // boot surface to NAME the narrowed store could have been deleted with the selftest green.
        // Taking the trait's name out of the struct is the tree that rule exists to refuse.
        let mut ov = Overlay::new();
        ov.set(&bootctx, text.replace("PlaneStore", "Store"));
        report.push(tree_case(
            cx,
            gate,
            "a boot surface that stops naming the narrowed store is a finding on its own row",
            &[plane_store::ROW_BOOTCTX_NOT_NARROWED],
            ov,
            &["BOOTCTX-NOT-NARROWED"],
        ));
    } else {
        report.note_infra_failure(
            "structure-lint selftest: the boot seam file is unreadable, so invariant (a)'s boot \
             half is unproven here rather than passing",
        );
    }

    report
}

/// The `mod.rs` that declares a plane, and its text.
fn plane_grammar_file(cx: &Ctx, plane: &str) -> Option<(String, String)> {
    let files = cx
        .walk(&crate::ctx::WalkSpec::new([roots::CRATES]).ext("rs"))
        .ok()?;
    files
        .into_iter()
        .find(|s| {
            let rel = s.rel_str();
            rel.contains(&format!("/{plane}/")) && s.text.contains(crate::planes::PLANE_GRAMMAR)
        })
        .map(|s| (s.rel_str(), s.text))
}

/// The first plane sink attach, and its file's text.
fn sink_file(
    cx: &Ctx,
    a: &crate::gates::structure_lint::roots::Addresses,
) -> Option<(String, String)> {
    let files = cx
        .walk(&crate::ctx::WalkSpec::new([format!("{}/plane", a.core)]).ext("rs"))
        .ok()?;
    files
        .into_iter()
        .find(|s| s.text.contains("fn set_sink"))
        .map(|s| (s.rel_str(), s.text))
}

/// Add a line to a named function's body, so the plant lands INSIDE the span the rule scopes to
/// rather than merely in the same file.
fn plant_into_fn(cx: &Ctx, file: &str, func: &str, line: &str) -> Option<Overlay> {
    let text = cx.read(file).ok()?;
    let needle = format!("fn {func}");
    let at = text.find(&needle)?;
    let brace = text[at..].find('{')? + at;
    let mut out = String::with_capacity(text.len() + line.len());
    out.push_str(&text[..=brace]);
    out.push('\n');
    out.push_str(line);
    out.push_str(&text[brace + 1..]);
    let mut ov = Overlay::new();
    ov.set(file, out);
    Some(ov)
}

/// Widen the boot surface's first `PlaneStore` field back to the audit-carrying store.
fn widen_bootctx(text: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    let mut done = false;
    for line in text.lines() {
        if line.contains("pub struct BootCtx") {
            inside = true;
        }
        if inside && !done && line.contains("dyn PlaneStore") {
            out.push(line.replace("dyn PlaneStore", "dyn Store"));
            done = true;
            continue;
        }
        if inside && line.starts_with('}') {
            if !done {
                out.push("    pub chain: std::sync::Arc<dyn Store>,".to_string());
                done = true;
            }
            inside = false;
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

// ── the table plants ─────────────────────────────────────────────────────────────────────────────

fn with_choke_allow_moved(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.choke_points.iter_mut().find(|r| !r.rules.is_empty()) {
        if let Some(rule) = r.rules.first_mut() {
            rule.allow = vec!["crates/the-owner-that-moved/src/durable.rs".to_string()];
        }
    }
    t
}

fn with_choke_row_broken(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.choke_points.first_mut() {
        r.why = "a why with a | in it shifts every field of the row this gate's translator reads"
            .to_string();
    }
    t
}

fn with_choke_allow_everything(cx: &Ctx, t: &Tables) -> Tables {
    let mut t = t.clone();
    let every: Vec<String> = corpus::Corpus::build(cx)
        .map(|c| c.files.iter().map(|f| f.rel.clone()).collect())
        .unwrap_or_default();
    if let Some(r) = t.choke_points.iter_mut().find(|r| !r.rules.is_empty()) {
        if let Some(rule) = r.rules.first_mut() {
            rule.allow = every;
        }
    }
    t
}

fn with_stale_plane_row(t: &Tables) -> Tables {
    let mut t = t.clone();
    t.plane_ledger.push(plane_dups::LedgerRow {
        name: "a_name_no_plane_declares".to_string(),
        class: plane_dups::Class::Distinct,
        concern: String::new(),
        note: "a claim about duplication that is not there any more".to_string(),
    });
    t
}

fn with_malformed_plane_row(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.plane_ledger.first_mut() {
        r.note = String::new();
    }
    t
}

fn with_axis_scope_moved(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.axis_branch.first_mut() {
        r.scope = vec!["crates/the-core-that-moved/src/".to_string()];
    }
    t
}

fn with_axis_arm_moved(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.axis_branch.first_mut() {
        r.allowed.push("crates/the-arm-that-moved/src/".to_string());
    }
    t
}

fn with_axis_arm_covering_everything(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.axis_branch.first_mut() {
        r.allowed = r.scope.clone();
    }
    t
}

fn with_axis_row_broken(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.axis_branch.first_mut() {
        r.rules.clear();
    }
    t
}

fn with_stale_axis_exception(t: &Tables) -> Tables {
    let mut t = t.clone();
    let axis_name = t
        .axis_branch
        .first()
        .map(|r| r.axis.clone())
        .unwrap_or_else(|| "transport".to_string());
    t.axis_exceptions.push(axis::AxisException {
        axis: axis_name,
        file: "crates/busbar-core/src/a_file_that_no_longer_branches.rs".to_string(),
        why: "an exemption whose branch has already gone".to_string(),
    });
    t
}

fn with_census_absent_subject(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.census.first_mut() {
        r.pattern = "a_symbol_this_tree_never_declared".to_string();
    }
    t
}

fn with_census_scope_moved(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.census.first_mut() {
        r.scope = vec!["crates/the-subject-that-moved/src/".to_string()];
    }
    t
}

fn with_census_zero_count(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.census.first_mut() {
        r.want = 0;
    }
    t
}

/// A scope that EXISTS and holds no production source. Distinct from the scope rule above, which
/// is about a path that is not there at all — the two failures have two different remedies, and a
/// row that could only produce one of them is a rule that can be deleted with everything green.
fn with_census_empty_scope(t: &Tables) -> Tables {
    let mut t = t.clone();
    if let Some(r) = t.census.first_mut() {
        r.scope = vec!["Cargo.toml".to_string()];
    }
    t
}
