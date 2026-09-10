//! `cargo xtask gate structure-lint` — THE CODE-LAYOUT INVARIANTS AND THE BEHAVIOURAL INVARIANTS
//! ONLY A STRUCTURAL READ OF THE TREE CAN CATCH. The successor to `scripts/structure-lint.sh`, rule
//! family for rule family.
//!
//! The script was 2,312 lines and ~20 rules, and its shape is the thing worth carrying across: it
//! is not twenty scanners, it is four generic scanners driven by DECLARATIVE TABLES. Adding a choke
//! point is a one-row edit; adding a census question is a one-row edit. That property survives here
//! — the tables are Rust data in the family module that owns them, the EREs in their cells are read
//! by [`crate::ere`] rather than rewritten as predicates, and every rule reaches the tree through
//! one candidate corpus and one answer to "is this line test code?".
//!
//! ## One file per rule family
//!
//! | module | invariant | what it refuses |
//! | --- | --- | --- |
//! | [`roots`] | where this lint looks | a protocol crate or a plane root nothing can locate |
//! | [`corpus`] | the denominator | a scan set below its floor, and the three generic scanners |
//! | [`hybrid`] | 1 | `foo.rs` beside `foo/` |
//! | [`oversized`] | 2 | a monster impl file, with the grandfathered list as data |
//! | [`inline_tests`] | 3 | an inline test body in an implementation file |
//! | [`choke_points`] | 4 | a hand-rolled bypass of a hazard class's single owner |
//! | [`fn_scoped`] | 5 and 8 | a store call on the request path; a routing decision reading free text |
//! | [`plane_dups`] | 6 | a plane-local reimplementation of a shared concern |
//! | [`axis`] | 7 | a branch on an axis outside that axis's own arms |
//! | [`census`] | 9 | a shared decision or wire word that exists other than exactly once |
//! | [`plane_store`] | (a) | a plane sink or boot hook widened to the audit-carrying `Store` |
//!
//! ## Every row is owed, and every rule is proven RED
//!
//! The shell had ONE exit status for twenty rules, so "structure-lint failed" never said which
//! invariant, and a rule that stopped running was indistinguishable from a rule that passed. Here
//! each rule is a ledger row id in [`OWED`], reconciled against what the run emitted, and each id
//! carries a selftest case that plants its violation and requires the report to NAME it.
//!
//! ## The tables are a parameter, which is what makes the table rules provable
//!
//! Several rules are ABOUT the tables — a malformed row, an allowed path that moved, a ledger row
//! for duplication that is no longer there. No overlay can plant those, because the table is source
//! rather than tree. So the gate carries its [`Tables`] as a field: the real ones by default, and a
//! deliberately broken set in the case that proves the rule. The selftest still reaches the gate
//! only through [`Gate::run`] — it drives the SHIPPED runner over a planted table, exactly as the
//! shell's `selftest_case` drove the shipped `scan_rule` over a planted fixture.
//!
//! ## Floors are consts and there are no environment overrides
//!
//! `STRUCTURE_LINT_CANDIDATE_FLOOR` is gone. The only way to lower a floor is a reviewable source
//! edit, which is the point of a floor.

pub mod axis;
pub mod census;
pub mod choke_points;
pub mod corpus;
pub mod fn_scoped;
pub mod hybrid;
pub mod inline_tests;
pub mod oversized;
pub mod plane_dups;
pub mod plane_store;
pub mod roots;

use crate::ctx::Ctx;
use crate::gates::{Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;

use corpus::Corpus;
use roots::Addresses;

/// What a clean rule says, spelled once so a PASS row cannot drift between two families.
pub const CLEAN: &str = "the rule ran over its scan set and named nothing";

/// EVERY ROW THIS GATE CAN EMIT, which is every rule the script carried. The owed set is this list
/// and the reconciliation is the runner's, so a rule cannot be added without being owed, and an
/// owed rule that stops being emitted is DID NOT RUN rather than silence.
pub const OWED: &[&str] = &[
    roots::ROW_PROTO_ROOTS,
    roots::ROW_PLANE_ROOTS,
    corpus::ROW_CANDIDATE_FLOOR,
    hybrid::ROW_HYBRID,
    oversized::ROW_OVERSIZED,
    inline_tests::ROW_INLINE_TEST,
    inline_tests::ROW_ALLOW_REASON,
    choke_points::ROW_ROW_INTEGRITY,
    choke_points::ROW_CLASS_TEST,
    choke_points::ROW_ALLOWED_PATH,
    choke_points::ROW_SCAN_SET,
    choke_points::ROW_BYPASS,
    fn_scoped::ROW_REQUEST_PATH_SUBJECT,
    fn_scoped::ROW_REQUEST_PATH_PURITY,
    fn_scoped::ROW_DECISION_INPUT_SUBJECT,
    fn_scoped::ROW_DECISION_INPUT_PURITY,
    plane_dups::ROW_UNLEDGERED,
    plane_dups::ROW_LEDGER_INTEGRITY,
    plane_dups::ROW_STALE_LEDGER,
    axis::ROW_ROW_INTEGRITY,
    axis::ROW_SCOPE,
    axis::ROW_ALLOWED_PATH,
    axis::ROW_SCAN_SET,
    axis::ROW_PURITY,
    axis::ROW_STALE_LEDGER,
    census::ROW_ROW_INTEGRITY,
    census::ROW_SCOPE,
    census::ROW_SCAN_SET,
    census::ROW_SUBJECT,
    census::ROW_COUNT,
    plane_store::ROW_SINK_SCAN_SET,
    plane_store::ROW_SINK_NOT_NARROWED,
    plane_store::ROW_SINK_WIDENED,
    plane_store::ROW_BOOTCTX_SUBJECT,
    plane_store::ROW_BOOTCTX_NOT_NARROWED,
    plane_store::ROW_BOOTCTX_WIDENED,
];

/// The rows whose rule reads the candidate corpus, and which therefore DID NOT RUN when the corpus
/// is below its floor. The shell exited on that; exiting would leave every row below unrecorded,
/// and an unrecorded owed row already means "did not run" — this states it in the ledger instead,
/// so the reader is told which rules the empty scan set took down with it.
pub const CORPUS_DEPENDENT: &[&str] = &[
    inline_tests::ROW_INLINE_TEST,
    inline_tests::ROW_ALLOW_REASON,
    choke_points::ROW_SCAN_SET,
    choke_points::ROW_BYPASS,
    axis::ROW_SCAN_SET,
    axis::ROW_PURITY,
    axis::ROW_STALE_LEDGER,
    census::ROW_SCAN_SET,
    census::ROW_SUBJECT,
    census::ROW_COUNT,
];

/// Every finding this gate found, one list per owed row id. BOTH the run and the legacy translator
/// fill this in and then hand it to the SAME row constructors, so the only thing a parity diff can
/// be about is which offenders were named — never how a title is worded.
#[derive(Debug, Default, Clone)]
pub struct Findings {
    pub proto_roots: Vec<String>,
    pub plane_roots: Vec<String>,
    pub candidate_floor: Vec<String>,
    pub hybrid: Vec<String>,
    pub oversized: Vec<String>,
    pub inline_tests: Vec<String>,
    pub allow_reason: Vec<String>,
    pub choke_row_integrity: Vec<String>,
    pub choke_class_test: Vec<String>,
    pub choke_allowed_path: Vec<String>,
    pub choke_scan_set: Vec<String>,
    pub choke_bypass: Vec<String>,
    pub request_path_subject: Vec<String>,
    pub request_path_purity: Vec<String>,
    pub decision_input_subject: Vec<String>,
    pub decision_input_purity: Vec<String>,
    pub unledgered: Vec<String>,
    pub ledger_integrity: Vec<String>,
    pub stale_ledger: Vec<String>,
    pub axis_row_integrity: Vec<String>,
    pub axis_scope: Vec<String>,
    pub axis_allowed_path: Vec<String>,
    pub axis_scan_set: Vec<String>,
    pub axis_purity: Vec<String>,
    pub axis_stale_ledger: Vec<String>,
    pub census_row_integrity: Vec<String>,
    pub census_scope: Vec<String>,
    pub census_scan_set: Vec<String>,
    pub census_subject: Vec<String>,
    pub census_count: Vec<String>,
    pub sink_scan_set: Vec<String>,
    pub sink_not_narrowed: Vec<String>,
    pub sink_widened: Vec<String>,
    pub bootctx_subject: Vec<String>,
    pub bootctx_not_narrowed: Vec<String>,
    pub bootctx_widened: Vec<String>,
    /// The rules the corpus took down with it, if it was below its floor.
    pub did_not_run: Vec<&'static str>,
}

impl Findings {
    /// Sort every list. One awk pass over a `find | sort` file list is already ordered; a translator
    /// reading a script's printed output is not guaranteed to be, and an offender list that differs
    /// only in order is a parity diff about nothing.
    pub fn sorted(mut self) -> Findings {
        for v in [
            &mut self.proto_roots,
            &mut self.plane_roots,
            &mut self.candidate_floor,
            &mut self.hybrid,
            &mut self.oversized,
            &mut self.inline_tests,
            &mut self.allow_reason,
            &mut self.choke_row_integrity,
            &mut self.choke_class_test,
            &mut self.choke_allowed_path,
            &mut self.choke_scan_set,
            &mut self.choke_bypass,
            &mut self.request_path_subject,
            &mut self.request_path_purity,
            &mut self.decision_input_subject,
            &mut self.decision_input_purity,
            &mut self.unledgered,
            &mut self.ledger_integrity,
            &mut self.stale_ledger,
            &mut self.axis_row_integrity,
            &mut self.axis_scope,
            &mut self.axis_allowed_path,
            &mut self.axis_scan_set,
            &mut self.axis_purity,
            &mut self.axis_stale_ledger,
            &mut self.census_row_integrity,
            &mut self.census_scope,
            &mut self.census_scan_set,
            &mut self.census_subject,
            &mut self.census_count,
            &mut self.sink_scan_set,
            &mut self.sink_not_narrowed,
            &mut self.sink_widened,
            &mut self.bootctx_subject,
            &mut self.bootctx_not_narrowed,
            &mut self.bootctx_widened,
        ] {
            v.sort();
            v.dedup();
        }
        self
    }

    /// Every row, in owed order.
    pub fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        rows.extend(roots::rows(self));
        rows.extend(corpus::rows(self));
        rows.extend(hybrid::rows(self));
        rows.extend(oversized::rows(self));
        rows.extend(inline_tests::rows(self));
        rows.extend(choke_points::rows(self));
        rows.extend(fn_scoped::rows(self));
        rows.extend(plane_dups::rows(self));
        rows.extend(axis::rows(self));
        rows.extend(census::rows(self));
        rows.extend(plane_store::rows(self));
        // A rule the empty corpus took down reports DID NOT RUN, replacing whatever its own
        // constructor would otherwise have said about a scan set it never had.
        for id in &self.did_not_run {
            if let Some(slot) = rows.iter_mut().find(|r| r.id == *id) {
                *slot = Row::fail(
                    *id,
                    "the rule did not run",
                    "the candidate corpus was below its floor, so this rule scanned (almost) \
                     nothing — its verdict is meaningless, and meaningless is NOT a pass"
                        .to_string(),
                );
            }
        }
        rows
    }
}

/// The one row constructor: a rule is either clean over a scan set it actually had, or it names its
/// offenders and how many there were.
pub fn row(id: &'static str, clean_title: &str, fail_title: &str, offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(id, clean_title, CLEAN);
    }
    Row::fail(
        id,
        fail_title,
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

/// The rule tables, as one value, so the cases that are ABOUT a table can drive the shipped runner
/// over a planted one.
#[derive(Debug, Clone)]
pub struct Tables {
    pub grandfathered: Vec<String>,
    pub choke_points: Vec<choke_points::ChokeRow>,
    pub request_path: Vec<fn_scoped::FnRow>,
    pub decision_input: Vec<fn_scoped::FnRow>,
    pub plane_concerns: Vec<plane_dups::Concern>,
    pub plane_ledger: Vec<plane_dups::LedgerRow>,
    pub axis_branch: Vec<axis::AxisRow>,
    pub axis_exceptions: Vec<axis::AxisException>,
    pub census: Vec<census::CensusRow>,
}

impl Tables {
    /// The shipped tables, with every `$CORE`/`$MCP`/`$PROTO_ROOTS` interpolation resolved against
    /// the addresses this tree actually answered with.
    pub fn real(a: &Addresses) -> Tables {
        Tables {
            grandfathered: oversized::grandfathered(a),
            choke_points: choke_points::table(a),
            request_path: fn_scoped::request_path(a),
            decision_input: fn_scoped::decision_input(a),
            plane_concerns: plane_dups::concerns(a),
            plane_ledger: plane_dups::ledger(),
            axis_branch: axis::table(a),
            axis_exceptions: axis::exceptions(),
            census: census::table(a),
        }
    }
}

pub struct StructureLintGate {
    tables: Option<Tables>,
}

impl StructureLintGate {
    pub fn new() -> StructureLintGate {
        StructureLintGate { tables: None }
    }

    /// The gate driven over a DELIBERATELY BROKEN table, for the cases whose subject is the table
    /// rather than the tree.
    pub fn with_tables(tables: Tables) -> StructureLintGate {
        StructureLintGate {
            tables: Some(tables),
        }
    }

    fn tables_for(&self, a: &Addresses) -> Tables {
        match &self.tables {
            Some(t) => t.clone(),
            None => Tables::real(a),
        }
    }

    /// The whole scan, as findings. Separated from [`Gate::run`] so the legacy translator and the
    /// run reach the same row constructors from opposite directions.
    pub fn findings(&self, cx: &Ctx) -> Findings {
        let mut f = Findings::default();
        let addresses = roots::resolve(cx, &mut f);
        let tables = self.tables_for(&addresses);

        hybrid::scan(cx, &mut f);

        match Corpus::build(cx) {
            Ok(corpus) => {
                oversized::scan(cx, &tables, &mut f);
                inline_tests::scan(&corpus, &mut f);
                choke_points::scan(cx, &corpus, &tables, &mut f);
                fn_scoped::scan(cx, &tables, &mut f);
                plane_dups::scan(cx, &addresses, &tables, &mut f);
                axis::scan(cx, &corpus, &tables, &mut f);
                census::scan(cx, &corpus, &tables, &mut f);
                plane_store::scan(cx, &addresses, &mut f);
            }
            Err(why) => {
                f.candidate_floor.push(why);
                f.did_not_run = CORPUS_DEPENDENT.to_vec();
                // The rules that read the tree DIRECTLY rather than through the corpus still run:
                // an empty candidate list says nothing about whether a subject file exists.
                oversized::scan(cx, &tables, &mut f);
                fn_scoped::scan(cx, &tables, &mut f);
                plane_dups::scan(cx, &addresses, &tables, &mut f);
                choke_points::scan_class_tests(cx, &tables, &mut f);
                plane_store::scan(cx, &addresses, &mut f);
            }
        }
        f.sorted()
    }
}

impl Default for StructureLintGate {
    fn default() -> StructureLintGate {
        StructureLintGate::new()
    }
}

impl Gate for StructureLintGate {
    fn name(&self) -> &'static str {
        "structure-lint"
    }

    fn owed(&self) -> Vec<String> {
        OWED.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(self.findings(cx).rows())
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(self.translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        selftest::run(self, cx)
    }
}

mod selftest;
mod translate;
