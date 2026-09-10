//! INVARIANT 7: NOTHING BRANCHES ON AN AXIS OUTSIDE THAT AXIS'S OWN ARMS.
//!
//! THE RULE, owner's ruling: an `if transport ==` outside a `proto/` arm, its handler and its codec
//! means THE DESIGN FAILED AT THAT POINT — fix the model, not the protocol. The matrix is
//! `protocol × operation × transport`; a cell of it is selected by LOOKUP, never by a branch in the
//! agnostic core. Every core-side decision a transport influences is a VTABLE fact.
//!
//! WHY THIS EXISTED THE DAY THE AXIS DID, and not later. `Transport` had ONE variant when this
//! armed, so a branch on it was trivially constant and a reviewer would wave it through — which is
//! precisely when the first one gets written, and it is load-bearing by the time a second variant
//! makes it wrong. That day has since come and the rule held.
//!
//! WHY VALUE USE IS FINE AND ONLY COMPARISON IS BANNED: naming a transport at an arrival is a
//! STATEMENT OF FACT — an axum handler does know it is HTTP — and threading or labelling the value
//! costs nothing later. Comparing it is what forks the core.
//!
//! THE SCOPE IS A PATH PREFIX, NOT A NARROWER PATTERN, and that is honest about the blind spot: the
//! matrix is busbar's and the word "transport" is not — `plugin-loader` compares a plugin-ABI
//! `transport` VERSION number, an unrelated noun a type-blind scan cannot tell apart from the axis.
//! Narrowing the PATTERN instead would have quietly stopped catching `if transport ==`, which is
//! the exact line this invariant exists to catch.
//!
//! ## The exception ledger is EMPTY, and that is the point
//!
//! It briefly carried one row — a NOUN COLLISION of exactly the shape the scope note above names —
//! and the honest fix that row named as its own exit condition was taken instead of the exemption.
//! Same two rules as the plane ledger: a row that no longer matches is a HARD ERROR, and ADDING a
//! row for NEW code is evading the check rather than passing it.

use crate::ctx::Ctx;
use crate::ere::Ere;
use crate::gates::structure_lint::corpus::{Candidate, Corpus};
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings, Tables};
use crate::ledger::Row;

pub const ROW_ROW_INTEGRITY: &str = "structure-lint:axis:row-integrity";
pub const ROW_SCOPE: &str = "structure-lint:axis:scope";
pub const ROW_ALLOWED_PATH: &str = "structure-lint:axis:allowed-path";
pub const ROW_SCAN_SET: &str = "structure-lint:axis:scan-set";
pub const ROW_PURITY: &str = "structure-lint:axis:purity";
pub const ROW_STALE_LEDGER: &str = "structure-lint:axis:stale-ledger";

#[derive(Debug, Clone)]
pub struct AxisBan {
    pub pattern: String,
    pub what: String,
}

impl AxisBan {
    fn new(pattern: &str, what: &str) -> AxisBan {
        AxisBan {
            pattern: pattern.to_string(),
            what: what.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AxisRow {
    pub axis: String,
    pub tag: String,
    /// The path prefixes the axis GOVERNS.
    pub scope: Vec<String>,
    pub rules: Vec<AxisBan>,
    /// Path PREFIXES where a branch on this axis is legitimate: the axis's own module, the `proto/`
    /// arms, and the handlers that hold the codecs.
    pub allowed: Vec<String>,
    pub remedy: String,
    pub why: String,
}

/// A ledgered branch: `axis`, the file, and why this one is allowed to exist and when it goes.
#[derive(Debug, Clone)]
pub struct AxisException {
    pub axis: String,
    pub file: String,
    pub why: String,
}

/// THE OPERATION AXIS ARMS, and it could only arm once the axis was SPLIT. It was thirteen flat
/// variants, seven of them named for one protocol family's endpoints, and every request handler
/// carried a thirteen-arm `match` on it — so a rule banning "a match on the operation axis" would
/// have needed an allowlist the length of `handlers/`, which is an amnesty rather than a lint. The
/// axis is now a verb plus a SHAPE: a protocol's verbs are rows in its OWN table and the core
/// decides on the shape, which has exactly one comparison left in the tree and it is inside a
/// protocol arm. The row costs no exemptions, which is the bar the transport row set for itself.
///
/// THE OTHER AXES ARE NOT ARMED HERE, deliberately and with the reason recorded rather than
/// silently: `if protocol ==` and `match plane` are RED on this tree today, and arming them would
/// either fail the gate or need an exemption list long enough to be an amnesty. They arm in their
/// own units, against a tree that can pass them. A row here is one line when that day comes.
pub fn table(a: &Addresses) -> Vec<AxisRow> {
    let mut op_allowed = vec![
        "crates/busbar-contract/src/operation.rs".to_string(),
        format!("{}/proto/", a.core),
        format!("{}/handlers/", a.core),
    ];
    op_allowed.extend(a.proto_roots.iter().cloned());
    let mut tr_allowed = vec![
        format!("{}/transport.rs", a.substrate_values),
        format!("{}/proto/", a.core),
        format!("{}/handlers/", a.core),
    ];
    tr_allowed.extend(a.proto_roots.iter().cloned());

    vec![
        AxisRow {
            axis: "operation".into(),
            tag: "OPERATION-BRANCH".into(),
            scope: a.tree(),
            rules: vec![
                AxisBan::new(
                    r"[Oo]peration(\(\))?[[:space:]]*==",
                    "a comparison against an operation",
                ),
                AxisBan::new(
                    r"[Oo]peration(\(\))?[[:space:]]*!=",
                    "a comparison against an operation",
                ),
                AxisBan::new(
                    r"match[[:space:]]+[A-Za-z0-9_.:]*[Oo]peration(\(\))?[[:space:]]*\{",
                    "a match on the operation axis",
                ),
                AxisBan::new(
                    r"match[[:space:]]+[A-Za-z0-9_.:]*shape\(\)[[:space:]]*\{",
                    "a match on the operation axis's shape",
                ),
                AxisBan::new(
                    r"matches!\([^)]*OpShape::",
                    "a matches! on an operation shape",
                ),
                AxisBan::new(
                    r"if[[:space:]]+let[[:space:]]+[A-Za-z0-9_:]*OpShape::",
                    "an if-let on an operation shape",
                ),
                AxisBan::new(
                    r"matches!\([^)]*Operation::",
                    "a matches! on an operation verb",
                ),
            ],
            allowed: op_allowed,
            remedy: "put the decision on the OperationHandler vtable, or ask the SHAPE a named question; never ask an operation its identity in the agnostic core".into(),
            why: "`Operation` is the vocabulary the plugin ABI carries across a dlopen boundary, so a core that can compare one has learned a protocol's method names and the deletion test fails on line one".into(),
        },
        AxisRow {
            axis: "transport".into(),
            tag: "TRANSPORT-BRANCH".into(),
            scope: a.tree(),
            rules: vec![
                AxisBan::new(
                    r"[Tt]ransport(\(\))?[[:space:]]*==",
                    "a comparison against a transport",
                ),
                AxisBan::new(
                    r"[Tt]ransport(\(\))?[[:space:]]*!=",
                    "a comparison against a transport",
                ),
                AxisBan::new(
                    r"match[[:space:]]+[A-Za-z0-9_.:]*[Tt]ransport(\(\))?[[:space:]]*\{",
                    "a match on the transport axis",
                ),
                AxisBan::new(
                    r"matches!\([^)]*Transport::",
                    "a matches! on a transport variant",
                ),
                AxisBan::new(
                    r"if[[:space:]]+let[[:space:]]+[A-Za-z0-9_:]*Transport::",
                    "an if-let on a transport variant",
                ),
            ],
            allowed: tr_allowed,
            remedy: "put the decision on the codec/writer vtable and let the framing answer it, or take the branch inside the proto arm that owns the wire; never ask the transport its identity in the agnostic core".into(),
            why: "the six LLM protocols are six dialects over one transport and A2A is one dialect over three, so a core that can see the transport forks three ways the moment the second one arms".into(),
        },
    ]
}

/// EMPTY, and the ledger only shrinks.
pub fn exceptions() -> Vec<AxisException> {
    Vec::new()
}

pub fn finding_malformed(axis: &str, why: &str) -> String {
    format!("MALFORMED-ROW: {axis} — {why}")
}

pub fn finding_scope(axis: &str, path: &str) -> String {
    format!("SCOPE-MISSING: {axis} — `{path}` does not exist; point the row at the axis's new root")
}

pub fn finding_allowed_path(axis: &str, path: &str) -> String {
    format!("ALLOWED-PATH-MISSING: {axis} — `{path}` does not exist; point the row at the arm's new home")
}

pub fn finding_no_subject(axis: &str) -> String {
    format!(
        "NO-SUBJECT: {axis} — the allowed prefixes cover the whole scope, so this invariant scanned \
         NOTHING and would have reported a pass. That is the false green, not a clean bill."
    )
}

pub fn finding_branch(tag: &str, rel: &str, line: usize, what: &str) -> String {
    format!("{tag}: {rel}:{line}: {what}")
}

pub fn finding_stale(axis: &str, file: &str) -> String {
    format!(
        "STALE-LEDGER: `{file}` is on the axis exception ledger for the {axis} axis but no longer \
         branches on it. If you removed the branch — thank you — DELETE its row."
    )
}

pub fn scan(cx: &Ctx, corpus: &Corpus, t: &Tables, f: &mut Findings) {
    if t.axis_branch.is_empty() {
        f.axis_row_integrity.push(finding_malformed(
            "the axis table",
            "it is EMPTY, so this invariant scanned nothing",
        ));
    }
    // Which exception rows were actually hit, so a stale one is detectable. Exception rows stay IN
    // scope on purpose: their hits are counted and THEN suppressed.
    let mut exception_hits: Vec<(String, String)> = Vec::new();

    for r in &t.axis_branch {
        let mut malformed = false;
        for (name, value) in [("axis", &r.axis), ("tag", &r.tag), ("why", &r.why)] {
            if value.trim().is_empty() || value.contains('|') {
                f.axis_row_integrity.push(finding_malformed(
                    &r.axis,
                    &format!("the `{name}` cell is empty or carries the row separator"),
                ));
                malformed = true;
            }
        }
        if r.rules.is_empty() || r.allowed.is_empty() || r.scope.is_empty() {
            f.axis_row_integrity.push(finding_malformed(
                &r.axis,
                "a row must name a scope, an allowed set and at least one rule",
            ));
            malformed = true;
        }
        if malformed {
            continue;
        }

        // Every listed scope prefix must exist: a prefix pointing at nothing is a rule scanning
        // nothing, and a row whose scope moved reads as clean.
        let mut scope_missing = false;
        for sp in &r.scope {
            if !cx.exists(sp.trim_end_matches('/')) {
                f.axis_scope.push(finding_scope(&r.axis, sp));
                scope_missing = true;
            }
        }
        if scope_missing {
            continue;
        }
        // A prefix pointing at a moved module silently WIDENS the ban to a legitimate arm, and a
        // lint reporting a violation where the design is correct teaches people to add exceptions.
        for p in &r.allowed {
            if !cx.exists(p.trim_end_matches('/')) {
                f.axis_allowed_path.push(finding_allowed_path(&r.axis, p));
            }
        }

        let files: Vec<&Candidate> = corpus
            .in_scope(&r.scope)
            .filter(|c| !r.allowed.iter().any(|p| c.rel.starts_with(p.as_str())))
            .collect();
        if files.is_empty() {
            f.axis_scan_set.push(finding_no_subject(&r.axis));
            continue;
        }

        for rule in &r.rules {
            let Ok(pat) = Ere::new(&rule.pattern) else {
                f.axis_row_integrity.push(finding_malformed(
                    &r.axis,
                    &format!("its ban pattern `{}` does not compile", rule.pattern),
                ));
                continue;
            };
            for (rel, line) in Corpus::scan_rule(files.iter().copied(), &pat, None) {
                if t.axis_exceptions
                    .iter()
                    .any(|e| e.axis == r.axis && e.file == rel)
                {
                    exception_hits.push((r.axis.clone(), rel));
                    continue;
                }
                f.axis_purity
                    .push(finding_branch(&r.tag, &rel, line, &rule.what));
            }
        }
    }

    for e in &t.axis_exceptions {
        if e.why.trim().is_empty() || e.file.trim().is_empty() {
            f.axis_row_integrity.push(finding_malformed(
                &e.axis,
                "an exception row is `axis|file|why`, and the WHY may not be empty",
            ));
            continue;
        }
        if !exception_hits
            .iter()
            .any(|(axis, file)| *axis == e.axis && *file == e.file)
        {
            f.axis_stale_ledger.push(finding_stale(&e.axis, &e.file));
        }
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_ROW_INTEGRITY,
            "every axis row is complete and its patterns compile",
            "an axis row is incomplete, or will not compile",
            &f.axis_row_integrity,
        ),
        row(
            ROW_SCOPE,
            "every axis row's scope prefix names part of the tree that exists",
            "an axis row's scope moved, so the ban covers nothing",
            &f.axis_scope,
        ),
        row(
            ROW_ALLOWED_PATH,
            "every axis arm's allowed prefix names part of the tree that exists",
            "an axis arm moved, so the ban silently widened onto legitimate code",
            &f.axis_allowed_path,
        ),
        row(
            ROW_SCAN_SET,
            "every axis had a file left to scan after its allowed arms",
            "an axis's allowed prefixes cover its whole scope, so the rule did not run",
            &f.axis_scan_set,
        ),
        row(
            ROW_PURITY,
            "nothing branches on an axis outside that axis's own arms",
            "the agnostic core asked an axis its identity",
            &f.axis_purity,
        ),
        row(
            ROW_STALE_LEDGER,
            "every axis exception still describes a branch that is there",
            "an axis exception outlived its branch, which is an exemption nobody prunes",
            &f.axis_stale_ledger,
        ),
    ]
}
