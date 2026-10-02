//! INVARIANTS 5 AND 8: TWO TABLES, ONE RUNNER — "THIS CALL APPEARS NOWHERE INSIDE THIS FUNCTION".
//!
//! They are the same SHAPE over two different subjects, so they share a runner rather than two
//! copies of a loop that would drift the first time either was fixed.
//!
//! ## Why function-scoped and not a choke-point row
//!
//! The registry bans a pattern TREE-WIDE with a list of allowed files. Here the same call is
//! entirely legitimate one function further down the same file: `GovState::try_admit` may make no
//! store call, and `flush_durable` two functions below EXISTS to make them. The unit of the rule is
//! the function.
//!
//! ## Invariant 5 — the request path does not touch the store
//!
//! `try_admit` makes ZERO store calls. The store is a DURABILITY SINK — the ledger flushes to it
//! BEHIND the request — and it is never on the path a request waits on. That is not a nicety: every
//! published latency number depends on it, and the function's own doc comment states it. It was
//! true on the day the check was written and NOTHING ENFORCED IT; the first `self.store.get_…()`
//! added inside the admission path to answer "what was this key's spend yesterday?" would be
//! correct-looking, would pass every test, and would put a network round-trip under every admitted
//! request.
//!
//! ## Invariant 8 — a decision never reads attacker-authored text
//!
//! A route is decided on BOUND IDENTITY — registered server, namespaced tool, approved digest — and
//! never on an upstream's free text. An upstream rewrites its own description at will; a router
//! that reads one is a router the upstream steers, which is the confused-deputy half of every MCP
//! tool-poisoning writeup.
//!
//! WHAT IT REPLACES, and why the replacement is shaped differently: this was a test that
//! `include_str!`-ed one file and failed on a word in it. A good check with one fatal property —
//! its SUBJECT was a file path, and a test whose subject stops existing does not fail, it stops
//! being COMPILED, and an absent control has no failing test. Here the path is a DECLARED FACT that
//! goes RED when it is wrong: point a row at a file that moved or a function that was renamed and
//! [`ROW_REQUEST_PATH_SUBJECT`] / [`ROW_DECISION_INPUT_SUBJECT`] say so. The rebuild cannot take
//! this control out of the tree by accident; it can only take it out by editing a row telling it
//! not to.

use crate::ctx::Ctx;
use crate::ere::Ere;
use crate::gates::structure_lint::corpus::scan_fn_body;
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings, Tables};
use crate::ledger::Row;
use crate::scan;

pub const ROW_REQUEST_PATH_SUBJECT: &str = "structure-lint:request-path:subject";
pub const ROW_REQUEST_PATH_PURITY: &str = "structure-lint:request-path:purity";
pub const ROW_DECISION_INPUT_SUBJECT: &str = "structure-lint:decision-input:subject";
pub const ROW_DECISION_INPUT_PURITY: &str = "structure-lint:decision-input:purity";

/// One banned pattern inside one function.
#[derive(Debug, Clone)]
pub struct FnBan {
    pub pattern: String,
    pub what: String,
}

impl FnBan {
    fn new(pattern: &str, what: &str) -> FnBan {
        FnBan {
            pattern: pattern.to_string(),
            what: what.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FnRow {
    pub id: String,
    pub tag: String,
    pub file: String,
    /// The function name, as an ERE fragment (usually a literal).
    pub func: String,
    pub rules: Vec<FnBan>,
    pub remedy: String,
    pub why: String,
}

/// INVARIANT 5's table.
///
/// `store`/`Store` is matched as a WHOLE WORD, so `restore_from_store` and `store_id` do not trip it
/// while `self.store`, `store.get(`, `&dyn Store` and `Store::` all do. The boundaries are spelled
/// with explicit non-identifier classes because `\b` is not portable across the awks the shell ran
/// on, and the mid-line and end-of-line cases are two rules for the same reason. `.await` rides the
/// same row because it is the same invariant seen from the other side: the reason the store may not
/// appear here is that nothing on this path may suspend.
pub fn request_path(a: &Addresses) -> Vec<FnRow> {
    let core = &a.core;
    vec![
        FnRow {
            id: "A7-govstate-try-admit".into(),
            tag: "STORE-ON-REQUEST-PATH".into(),
            file: format!("{core}/governance/state.rs"),
            func: "try_admit".into(),
            rules: vec![
                FnBan::new(
                    "[^A-Za-z0-9_][Ss]tore[^A-Za-z0-9_]",
                    "a store reference inside the admission path",
                ),
                FnBan::new(
                    "[^A-Za-z0-9_][Ss]tore$",
                    "a store reference inside the admission path",
                ),
                FnBan::new(
                    r"\.await",
                    "an await inside the admission path (it is declared SYNCHRONOUS and INFALLIBLE)",
                ),
            ],
            remedy: "keep the store off this path: admission reads in-memory cells only, and durability is flushed BEHIND the request (governance::state::flush / the ledger sink), never in front of it".into(),
            why: "the store is a durability sink, never on the request path — every latency figure busbar publishes is measured on an admission that does no I/O".into(),
        },
        // THE PROTOCOL LOOKUP ALLOCATES NOTHING. `decl_for` is the one by-name protocol resolution
        // in busbar and it is called several times per request. The `match` it replaced returned an
        // OWNED `Protocol` and therefore allocated two vtable boxes on EVERY call — including the
        // many calls that only wanted a `&'static` constant off the declaration. Everything
        // reachable through a `ProtocolDecl` is `&'static`, so this function has no legitimate
        // reason to allocate, own a string, or suspend.
        FnRow {
            id: "A8-protocol-decl-for".into(),
            tag: "ALLOC-ON-PROTOCOL-LOOKUP".into(),
            file: format!("{core}/proto/registry.rs"),
            func: "decl_for".into(),
            rules: vec![
                FnBan::new("Box::new", "a box allocated while resolving a protocol name"),
                FnBan::new("Vec::", "a vector allocated while resolving a protocol name"),
                FnBan::new(
                    "to_string",
                    "an owned string allocated while resolving a protocol name",
                ),
                FnBan::new(
                    "String::",
                    "an owned string allocated while resolving a protocol name",
                ),
                FnBan::new(r"\.await", "an await inside the by-name protocol lookup"),
            ],
            remedy: "read the `&'static` declaration and hand it back: every fact on a `ProtocolDecl` is a constant the protocol declared, so nothing on this path needs to be built".into(),
            why: "it is called several times per request, and the match it replaced allocated two vtable boxes on every call to answer a static question".into(),
        },
    ]
}

/// INVARIANT 8's table. The three functions that turn a caller's request into a destination, or
/// decide what a caller is allowed to see. `resolve` maps a namespaced name to a bound identity,
/// `revalidate` re-checks that identity against the live snapshot immediately before the call goes
/// out, and `visible_catalogue` decides which capabilities a caller is shown.
///
/// WHY FUNCTION-SCOPED AND NOT A TREE-WIDE BAN: `description` is a legitimate word almost
/// everywhere. The catalogue stores one, the admin projection renders one, the listing publishes the
/// OPERATOR's one. It is illegitimate in exactly one place — the code that decides WHERE A CALL GOES
/// — and the unit of that rule is the function.
pub fn decision_input(a: &Addresses) -> Vec<FnRow> {
    let dispatch = format!("{}/client/dispatch.rs", a.mcp);
    vec![
        FnRow {
            id: "B10-routing-reads-no-description".into(),
            tag: "DESCRIPTION-ON-ROUTING-PATH".into(),
            file: dispatch.clone(),
            func: "resolve".into(),
            rules: vec![FnBan::new(
                "description",
                "a tool description read while deciding a route",
            )],
            remedy: "route on the bound identity alone — registered server, namespaced tool, approved digest — and never on text the upstream authors".into(),
            why: "an upstream rewrites its own description at will, so a router that reads one is a router the upstream steers".into(),
        },
        FnRow {
            id: "B10-revalidate-reads-no-description".into(),
            tag: "DESCRIPTION-ON-ROUTING-PATH".into(),
            file: dispatch.clone(),
            func: "revalidate".into(),
            rules: vec![FnBan::new(
                "description",
                "a tool description read while re-validating a route",
            )],
            remedy: "re-validate on the bound identity and the snapshot generation, never on text the upstream authors".into(),
            why: "the pre-dispatch re-check is the last gate an in-flight call passes; a hostile description reaching it would undo the resolve-time rule one line before the call goes out".into(),
        },
        FnRow {
            id: "B10-visibility-reads-no-description".into(),
            tag: "DESCRIPTION-ON-ROUTING-PATH".into(),
            file: dispatch,
            func: "visible_catalogue".into(),
            rules: vec![FnBan::new(
                "description",
                "a tool description read while deciding what a caller may see",
            )],
            remedy: "filter the catalogue on the caller grant and the approval, never on text the upstream authors".into(),
            why: "what a caller is shown is an authorisation answer, and an upstream that could influence it would be choosing its own audience".into(),
        },
    ]
}

pub fn finding_subject(id: &str, detail: &str) -> String {
    format!("SUBJECT-MISSING: {id} — {detail}")
}

pub fn finding_hit(tag: &str, rel: &str, line: usize, what: &str) -> String {
    format!("{tag}: {rel}:{line}: {what}")
}

/// The definition-line pattern: `fn <name>` followed by `(` or a generic parameter list.
/// `pub(crate)`, `async`, `unsafe` and `const` prefixes are all accepted, and indentation is NOT
/// constrained — the function may be a free fn or a method inside an `impl` block.
fn def_pattern(func: &str) -> String {
    format!(
        r"^[[:space:]]*(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?((async|unsafe|const)[[:space:]]+)*fn[[:space:]]+{func}[[:space:]]*[(<]"
    )
}

pub fn scan(cx: &Ctx, t: &Tables, f: &mut Findings) {
    run_table(cx, &t.request_path, f, Kind::RequestPath);
    run_table(cx, &t.decision_input, f, Kind::DecisionInput);
}

#[derive(Clone, Copy)]
enum Kind {
    RequestPath,
    DecisionInput,
}

fn run_table(cx: &Ctx, rows: &[FnRow], f: &mut Findings, kind: Kind) {
    let (subject, purity, label) = match kind {
        Kind::RequestPath => (
            &mut f.request_path_subject,
            &mut f.request_path_purity,
            "request-path",
        ),
        Kind::DecisionInput => (
            &mut f.decision_input_subject,
            &mut f.decision_input_purity,
            "decision-input",
        ),
    };

    // A table that ran zero rows would report the same clean verdict a clean run reports. It is not
    // clean, it is UNARMED — the same false green the subject rule below exists to refuse.
    if rows.is_empty() {
        subject.push(finding_subject(
            label,
            "the table is EMPTY, so this invariant scanned NOTHING",
        ));
        return;
    }

    for r in rows {
        // The subject must EXIST. A rule pointed at a file that moved, or a function that was
        // renamed, scans nothing and prints nothing — which reads exactly like a pass.
        let Ok(text) = cx.read(&r.file) else {
            subject.push(finding_subject(
                &r.id,
                &format!(
                    "{} does not exist; point the row at the function's new home",
                    r.file
                ),
            ));
            continue;
        };
        let lines = scan::test_scope(&text);
        let Ok(def) = Ere::new(&def_pattern(&r.func)) else {
            subject.push(finding_subject(
                &r.id,
                &format!("the function name `{}` is not a usable pattern", r.func),
            ));
            continue;
        };

        let mut found_span = false;
        for rule in &r.rules {
            let Ok(pat) = Ere::new(&rule.pattern) else {
                subject.push(finding_subject(
                    &r.id,
                    &format!("its ban pattern `{}` does not compile", rule.pattern),
                ));
                continue;
            };
            let out = scan_fn_body(&lines, &def, &pat, None);
            found_span |= !out.spans.is_empty();
            for line in out.hits {
                purity.push(finding_hit(&r.tag, &r.file, line, &rule.what));
            }
        }
        if !found_span {
            subject.push(finding_subject(
                &r.id,
                &format!(
                    "{} declares no `fn {}`, so this invariant scanned NOTHING and would have \
                     reported a pass ({})",
                    r.file, r.func, r.why
                ),
            ));
        }
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_REQUEST_PATH_SUBJECT,
            "every request-path row names a function that is still there",
            "a request-path row points at a file or a function that moved, so it scanned nothing",
            &f.request_path_subject,
        ),
        row(
            ROW_REQUEST_PATH_PURITY,
            "the request path makes no store call and never suspends",
            "the request path reached the store, or suspended",
            &f.request_path_purity,
        ),
        row(
            ROW_DECISION_INPUT_SUBJECT,
            "every decision-input row names a function that is still there",
            "a decision-input row points at a file or a function that moved, so it scanned nothing",
            &f.decision_input_subject,
        ),
        row(
            ROW_DECISION_INPUT_PURITY,
            "no routing decision reads attacker-authored text",
            "a routing decision read text the upstream authors",
            &f.decision_input_purity,
        ),
    ]
}
