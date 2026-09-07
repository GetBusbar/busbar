//! INVARIANT 9: THE DECLARATION CENSUS.
//!
//! Every other rule in this gate is a BAN — "this pattern appears nowhere". A ban has a blind spot
//! this project has been bitten by twice, and it is the same blind spot every time: a ban over a
//! pattern that no longer exists scans the whole tree, matches nothing, prints nothing, and reads
//! exactly like a clean bill of health. The bug is not in the scanner; it is that ZERO is the
//! passing answer AND the answer you get when the subject is gone.
//!
//! A CENSUS fixes that by making the expected answer A NUMBER THAT IS NOT ZERO. Each row declares a
//! pattern and how many production code lines must carry it:
//!
//! * [`ROW_SUBJECT`] — found NOTHING. Not a pass: a rule whose subject was renamed, moved or
//!   deleted, scanning the whole tree and asserting nothing. Its own row rather than folded into
//!   the count, because the remedy is different — you re-point the row, you do not go looking for a
//!   duplicate that is not there.
//! * [`ROW_COUNT`] — found some, but not the declared number. A second spelling, or a second
//!   decision.
//!
//! THE TRAP THIS AVOIDS, the same one the rest of this gate does: it counts CODE lines. Comments
//! and `#[cfg(test)]` regions are invisible to the scanner, so a doc comment quoting a wire word —
//! and the prose above these rows quotes several — is not a second spelling of it. A census that
//! read raw text would report its own documentation as a duplicate.
//!
//! A ROW WHOSE HONEST ANSWER IS ZERO IS A BAN wearing a census's clothes, and it reintroduces the
//! exact false green this invariant exists to remove. [`ROW_ROW_INTEGRITY`] refuses one.

use crate::ctx::Ctx;
use crate::ere::Ere;
use crate::gates::structure_lint::corpus::{Candidate, Corpus};
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings, Tables};
use crate::ledger::Row;

pub const ROW_ROW_INTEGRITY: &str = "structure-lint:census:row-integrity";
pub const ROW_SCOPE: &str = "structure-lint:census:scope";
pub const ROW_SCAN_SET: &str = "structure-lint:census:scan-set";
pub const ROW_SUBJECT: &str = "structure-lint:census:subject";
pub const ROW_COUNT: &str = "structure-lint:census:count";

#[derive(Debug, Clone)]
pub struct CensusRow {
    pub id: String,
    pub tag: String,
    /// Counted over production code lines.
    pub pattern: String,
    /// The exact number of production code lines that must match. NEVER 0.
    pub want: usize,
    /// The path prefixes the census covers.
    pub scope: Vec<String>,
    pub why: String,
}

fn r(id: &str, tag: &str, pattern: &str, want: usize, scope: Vec<String>, why: &str) -> CensusRow {
    CensusRow {
        id: id.to_string(),
        tag: tag.to_string(),
        pattern: pattern.to_string(),
        want,
        scope,
        why: why.to_string(),
    }
}

pub fn table(a: &Addresses) -> Vec<CensusRow> {
    let tree = a.tree();
    let mut tree_and_substrate = tree.clone();
    tree_and_substrate.push(format!("{}/", a.substrate));

    vec![
        // ── The five shared MCP wire words. One definition each; the outbound client imports them.
        //    A second occurrence is a second copy that can drift silently in the one direction no
        //    single-sided test can see — busbar refusing a request busbar sent. Zero occurrences
        //    means the word left the tree, which for a protocol constant is a rebuild that quietly
        //    stopped speaking the protocol.
        r("wire-word-meta-protocol-version", "WIRE-WORD-RESPELT", r#""io\.modelcontextprotocol/protocolVersion""#, 1, tree.clone(),
          "the `_meta` protocol-version key must have exactly one spelling in the tree: the ingress REQUIRES it and the client EMITS it, and two copies disagree in the direction where each side is internally consistent with itself"),
        r("wire-word-meta-client-capabilities", "WIRE-WORD-RESPELT", r#""io\.modelcontextprotocol/clientCapabilities""#, 1, tree.clone(),
          "the `_meta` client-capabilities key is REQUIRED on the way in and written on the way out; a second copy is a request busbar would send and then refuse"),
        r("wire-word-header-protocol-version", "WIRE-WORD-RESPELT", r#""mcp-protocol-version""#, 1, tree.clone(),
          "the protocol-version header name is read by the ingress and written by the client from one constant; a second literal is the drift the deleted symmetry test existed to catch"),
        r("wire-word-header-method", "WIRE-WORD-RESPELT", r#""mcp-method""#, 1, tree.clone(),
          "the method-mirror header name is required inbound and emitted outbound from one constant"),
        r("wire-word-header-name", "WIRE-WORD-RESPELT", r#""mcp-name""#, 1, tree.clone(),
          "the target-name header is required inbound on the three addressed methods and emitted outbound from one constant"),

        // ── THE ONE TRUST COMPARISON. A SECOND `fn serves` is two answers to one question, and the
        //    failure mode of a second answer is silent drift in the fail-OPEN direction, discovered
        //    as an in-flight call that served after the operator quarantined it.
        r("trust-serve-decision", "TRUST-DECISION-RESPELT", r"fn[[:space:]]+serves[[:space:]]*\(", 1, tree_and_substrate.clone(),
          "there is exactly ONE may-this-serve comparison in busbar; a second is two answers to one question and they diverge the first time either is fixed, and zero means the dispatch gate was routed somewhere this row cannot see"),

        // ── THE VALIDATOR'S REFUSAL WORDS HAVE ONE HOME, and these rows are here because this unit
        //    ALREADY got it wrong once: the validator defined its own `reason` module carrying the
        //    same tokens the audit vocabulary had just unified — two homes for one vocabulary,
        //    argued for in almost identical words on both sides. A chain that answers an operator
        //    differently depending on which module a plane imported from is the defect the audit
        //    unification existed to end. `audit::vocab` is the home and the validator RE-EXPORTS.
        r("refusal-word-identity-not-live", "REFUSAL-WORD-RESPELT", r#""identity_not_live""#, 1, tree_and_substrate.clone(),
          "the ordered validator's identity refusal has one spelling, defined once and re-exported; a second definition is two homes for one vocabulary"),
        r("refusal-word-not-serving", "REFUSAL-WORD-RESPELT", r#""not_serving""#, 1, tree_and_substrate.clone(),
          "the registration-level refusal has one spelling; a plane may render it more finely under its own words, but it may not respell this one"),
        r("refusal-word-artifact-drifted", "REFUSAL-WORD-RESPELT", r#""artifact_drifted""#, 1, tree_and_substrate.clone(),
          "the rug-pull refusal has one spelling: it is the one word that indicts the UPSTREAM rather than the config or the grant, and a second copy is two answers to who is at fault"),
        r("refusal-word-generation-moved", "REFUSAL-WORD-RESPELT", r#""generation_moved""#, 1, tree_and_substrate.clone(),
          "the lifecycle-race refusal has one spelling across both planes; two copies is the in-flight-outliving-an-approval story told two ways"),

        // ── THE FAILOVER SEAM'S REFUSAL WORDS: the seam is CORE, so its words are core's, and a
        //    plane that renders a refusal must render THIS word rather than invent a near-synonym.
        r("refusal-word-no-upstream-left", "REFUSAL-WORD-RESPELT", r#""no_upstream_left""#, 1, tree_and_substrate.clone(),
          "the nowhere-left-to-send refusal has one spelling across every plane that fails over; a second copy is one outage recorded under two words"),
        r("refusal-word-not-interchangeable", "REFUSAL-WORD-RESPELT", r#""not_interchangeable""#, 1, tree_and_substrate.clone(),
          "the pins-disagree refusal has one spelling: it is the one word that indicts the CONFIGURATION rather than the caller or the upstream"),
        r("refusal-word-not-repeatable", "REFUSAL-WORD-RESPELT", r#""not_repeatable""#, 1, tree_and_substrate.clone(),
          "the safety rule's refusal has one spelling; it is the one outcome an operator may deliberately want to change, and a second copy is a change they would make in one place and not the other"),

        r("the-one-ordered-request-validator", "VALIDATOR-RESPELT", r"fn[[:space:]]+validate_request[^a-zA-Z0-9_]", 1, tree_and_substrate.clone(),
          "there is exactly ONE ordered request validator in busbar and every protocol reaches it; a second is a protocol that has acquired its own order, and zero means the order was inlined back into a plane where nothing owns it"),

        // ── THE ONE GENERATION SOURCE. A generation only has to be DIFFERENT after a change, so a
        //    second counter buys nothing and adds a second thing to keep monotonic.
        r("the-one-generation-source", "GENERATION-SOURCE-FORKED", r"fn[[:space:]]+next_generation[^a-zA-Z0-9_]", 1, tree_and_substrate.clone(),
          "every versioned snapshot in the process takes its generation from one monotonic source; a second source is two numbering schemes that compare equal by accident, and zero means nothing is versioned"),

        // ── THE THIRD CATALOGUE WALK, RECORDED HERE BECAUSE THE PLANE LEDGER STRUCTURALLY CANNOT
        //    HOLD IT: that ledger's whole mechanism is CROSS-plane duplication, and this function
        //    exists once. A duplication the ledger cannot express is exactly the kind that gets
        //    forgotten, so it is expressed where the instrument fits — a count of the subject
        //    itself. THE TARGET IS THIS ROW'S DELETION, not its count: when the walk is routed
        //    through the one catalogue the function goes, the count becomes zero, and the failure is
        //    the instruction to delete the row.
        r("the-third-catalogue-walk", "THIRD-CATALOGUE-WALK", r"fn[[:space:]]+visible_catalogue[^a-zA-Z0-9_]", 1, tree.clone(),
          "the outbound client leg still walks its own catalogue instead of the one walk, filtering through the egress gate rather than the ordered validator; this row is that debt, and the count is 1 until somebody routes it through and deletes the row"),

        // ── THE ONE PARSE-TIME PLANE-BOUNDARY RULE. Both halves lived TWICE — each plane's config
        //    carried a byte-identical copy with its own hardcoded section list in a file no compiler
        //    links to the other. They agreed because one was pasted from the other, which is not a
        //    mechanism.
        r("one-parse-time-plane-boundary", "PLANE-BOUNDARY-RULE-RESPELT", r"fn[[:space:]]+refuse_cross_plane_reference[[:space:]]*\(", 1, tree_and_substrate,
          "there is exactly ONE parse-time answer to \"does this hook reference reach onto another plane\"; a second is two answers that drift the first time either is fixed, and zero means the rule left the tree and every dotted reference is now silently accepted"),
        r("one-section-attach-validator", "PLANE-BOUNDARY-RULE-RESPELT", r"fn[[:space:]]+validate_section_hooks[[:space:]]*\(", 1, tree.clone(),
          "the SECTION-level attach list must be judged by the same rule one entry is; a second copy is the place a looser rule grows, and it is the list an operator uses to attach a control to everything"),

        // ── THE ONE BY-NAME PROTOCOL RESOLUTION. Before the registry there were THREE, each a list
        //    of protocol names core had been edited to know. The failure mode of a second is a
        //    protocol that resolves for routing and not for dispatch, discovered as a 404 on a path
        //    that is mounted.
        r("protocol-name-resolution", "PROTOCOL-LOOKUP-RESPELT", r"fn[[:space:]]+decl_for[[:space:]]*\(", 1, tree.clone(),
          "there is exactly ONE by-name protocol resolution in busbar, and a second one is a second answer to which protocols exist"),

        // ── THE BUILT-IN DECLARATION TABLE. One slice, and it is DATA rather than a match — a
        //    registry whose population is a match in core has not removed the match, it has moved
        //    it.
        r("protocol-builtin-table", "PROTOCOL-TABLE-RESPELT", r"static[[:space:]]+BUILTIN_DECLS", 1, tree,
          "the set of built-in protocols is declared in exactly one place, as data; a second table or none at all is the match coming back"),
    ]
}

pub fn finding_malformed(id: &str, why: &str) -> String {
    format!("MALFORMED-ROW: {id} — {why}")
}

pub fn finding_scope(id: &str, path: &str) -> String {
    format!(
        "SCOPE-MISSING: {id} — `{path}` does not exist; point the row at the subject's new root"
    )
}

pub fn finding_no_subject(id: &str) -> String {
    format!(
        "NO-SUBJECT: {id} — its scope holds no production source file, so this census counted \
         NOTHING. That is the false green, not a clean bill."
    )
}

pub fn finding_subject_missing(id: &str, pattern: &str, want: usize) -> String {
    format!(
        "SUBJECT-MISSING: {id} — `{pattern}` occurs NOWHERE in production code under its scope, so \
         this row scanned the whole tree and asserted nothing. Expected {want}."
    )
}

pub fn finding_wrong(tag: &str, id: &str, pattern: &str, want: usize, got: usize) -> String {
    format!("{tag}: {id} — expected {want} production occurrence(s) of `{pattern}`, found {got}")
}

pub fn scan(cx: &Ctx, corpus: &Corpus, t: &Tables, f: &mut Findings) {
    if t.census.is_empty() {
        f.census_row_integrity.push(finding_malformed(
            "the census table",
            "it is EMPTY, so this invariant counted NOTHING",
        ));
    }
    for r in &t.census {
        if r.want == 0 {
            f.census_row_integrity.push(finding_malformed(
                &r.id,
                "a census count of 0 is a BAN; put it in the choke-point registry instead",
            ));
            continue;
        }
        if r.why.trim().is_empty() || r.pattern.trim().is_empty() || r.scope.is_empty() {
            f.census_row_integrity.push(finding_malformed(
                &r.id,
                "a row must name a pattern, a scope and a why",
            ));
            continue;
        }
        let Ok(pat) = Ere::new(&r.pattern) else {
            f.census_row_integrity.push(finding_malformed(
                &r.id,
                &format!("its pattern `{}` does not compile", r.pattern),
            ));
            continue;
        };

        // SCOPE EXISTENCE AND SCAN SET ARE TWO DIFFERENT FAILURES and they are asked of two
        // different things. A scope that does not EXIST is a row pointing at a path that moved; a
        // scope that exists and holds no production source is a row counting over a directory of
        // tests. Collapsing them would leave one of the two rules unreachable, which is a rule that
        // can be deleted with everything still green.
        let mut scope_missing = false;
        for sp in &r.scope {
            if !cx.exists(sp.trim_end_matches('/')) {
                f.census_scope.push(finding_scope(&r.id, sp));
                scope_missing = true;
            }
        }
        if scope_missing {
            continue;
        }

        let files: Vec<&Candidate> = corpus.in_scope(&r.scope).collect();
        if files.is_empty() {
            f.census_scan_set.push(finding_no_subject(&r.id));
            continue;
        }
        let hits = Corpus::scan_rule(files.iter().copied(), &pat, None);
        if hits.is_empty() {
            f.census_subject
                .push(finding_subject_missing(&r.id, &r.pattern, r.want));
        } else if hits.len() != r.want {
            let where_ = hits
                .iter()
                .map(|(rel, line)| format!("{rel}:{line}"))
                .collect::<Vec<_>>()
                .join(" ");
            f.census_count.push(format!(
                "{} at {where_}",
                finding_wrong(&r.tag, &r.id, &r.pattern, r.want, hits.len())
            ));
        }
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_ROW_INTEGRITY,
            "every census row is complete, non-zero, and compiles",
            "a census row is malformed, or its count is the zero that makes it a ban",
            &f.census_row_integrity,
        ),
        row(
            ROW_SCOPE,
            "every census scope prefix names part of the tree that exists",
            "a census scope moved, so the row counts over nothing",
            &f.census_scope,
        ),
        row(
            ROW_SCAN_SET,
            "every census row had production source to count over",
            "a census row's scope holds no production source, so it counted nothing",
            &f.census_scan_set,
        ),
        row(
            ROW_SUBJECT,
            "every census subject is still in the tree",
            "a census subject occurs nowhere, so its row asserts nothing",
            &f.census_subject,
        ),
        row(
            ROW_COUNT,
            "every shared decision and wire word occurs exactly the declared number of times",
            "a shared decision or wire word has a second spelling",
            &f.census_count,
        ),
    ]
}
