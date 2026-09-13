//! `cargo xtask gate response-header` — EVERY BUSBAR-INJECTED RESPONSE HEADER HAS ONE GATED SITE.
//! The successor to `scripts/response-header-lint.sh`, rule for rule.
//!
//! Every response header busbar ITSELF injects (as opposed to one it relays from an upstream) must
//! be an opt-in `advanced.response_headers` toggle, default OFF, emitted from exactly ONE sanctioned
//! site per header. Before the consolidation, `busbar;dur` was gated by a config flag but the
//! middleware computing it paid an `Arc<AtomicU64>`, an `Instant::now()` and a task-local `.scope()`
//! on EVERY request with the flag off — the guard was inside the function, after the cost was paid —
//! and `x-busbar-route-policy`/`x-busbar-route-target` had no config gate at all. This is the
//! can't-forget half: a new busbar-injected header, or a new hand-rolled emission of an existing one
//! outside its sanctioned site, fails the build instead of silently shipping unconditionally-on.
//!
//! Nine rows: four about whether the scan is worth reading, five about what it found.
//!
//! * `response-header:plane-roots` — mcp and a2a resolve. Both planes emit headers on their own
//!   front doors, which is precisely the population this gate counts, and 1.6.0 makes them plugin
//!   crates: 71 of 238 files, against a floor of 100, so their departure leaves the floor cleared.
//! * `response-header:scan-roots` — EACH root on its own. Three of the five happen to be covered by
//!   something else (two rules name a file inside `$SRC_DIR` and `$LLM`; the plane roots are
//!   resolved), but `$BIN` — the thin binary, the composition root, and the most natural place for
//!   someone to hand-roll a `.header("server-timing", …)` — was covered by nothing. Renaming it
//!   dropped the scan from 277 files to 259, nowhere near a floor of 100, and printed `passed`.
//! * `response-header:scan-floor` — the aggregate floor.
//! * `response-header:sanctioned-sites` — every file the rule table allowlists still EXISTS. An
//!   allowlist naming a vanished file quietly matches nothing, which reads as a clean tree.
//! * one row per rule, so a rule cannot be deleted without an owed row going missing.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::population;
use crate::gates::{
    prove_green, prove_red, prove_rows_red_at, Gate, Report, PLANE_ROOT_MISSING_FIXTURE,
};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::planes::PlaneRoots;

pub const ROW_PLANE_ROOTS: &str = "response-header:plane-roots";
pub const ROW_SCAN_ROOTS: &str = "response-header:scan-roots";
pub const ROW_SCAN_FLOOR: &str = "response-header:scan-floor";
pub const ROW_SITES: &str = "response-header:sanctioned-sites";

const CORE: &str = "crates/busbar-core/src";
const BIN: &str = "crates/busbar/src";
/// The LLM plane's front door. `busbar-llm` has no self-named `llm/` subdirectory (its code is
/// `engine/`, `arrival.rs`, …), so it is named by path rather than resolved like mcp and a2a.
const LLM: &str = "crates/busbar-llm/src";
const FIXED_ROOTS: &[&str] = &[CORE, BIN, LLM];
const PLANE_KEYS: &[&str] = &["mcp", "a2a"];
const EXCLUDE_TESTS_DIR: &str = "/tests/";
// THE FLOOR MOVED TO `gates::population`, along with the scan set it is a floor on.

/// The `x-busbar-route-*` NAME literals and their `HDR_ROUTE_*` consts live in the neutral
/// substrate; the ONE emission call lives in the LLM plane's wire; `server-timing` stayed in core's
/// router. The table names where they ACTUALLY are, or its allow column stops describing reality.
const HDR_ROUTE_POLICY_FILE: &str = "crates/busbar-substrate-values/src/proxy/mod.rs";
const HDR_ROUTE_WIRE_FILE: &str = "crates/busbar-llm/src/engine/wire.rs";
const HDR_SERVER_TIMING_FILE: &str = "crates/busbar-core/src/router.rs";

const CLEAN: &str = "the scan cleared its floors and named nothing";
const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a clean tree";

/// One rule: the code shape that WRITES a header, the row it answers on, the label it prints, and
/// the one file allowed to carry it.
struct Rule {
    row: &'static str,
    /// The needle, as a plain substring of a production line.
    needle: &'static str,
    what: &'static str,
    allow: &'static str,
    title_ok: &'static str,
    title_bad: &'static str,
}

/// The needles are BUILT rather than written as whole literals, so this module does not itself
/// carry the header spellings it hunts — the same discipline `segregation` uses, and the reason a
/// scanner searching for its own needle is a scanner that reports itself.
fn rules() -> Vec<Rule> {
    vec![
        Rule {
            row: "response-header:route-policy-literal",
            needle: "\"x-busbar-route-policy\"",
            what: "raw x-busbar-route-policy string literal outside its HDR_ROUTE_POLICY const \
                   definition",
            allow: HDR_ROUTE_POLICY_FILE,
            title_ok: "the route-policy header name is spelled only at its const definition",
            title_bad: "a raw route-policy header literal outside its const definition",
        },
        Rule {
            row: "response-header:route-target-literal",
            needle: "\"x-busbar-route-target\"",
            what: "raw x-busbar-route-target string literal outside its HDR_ROUTE_TARGET const \
                   definition",
            allow: HDR_ROUTE_POLICY_FILE,
            title_ok: "the route-target header name is spelled only at its const definition",
            title_bad: "a raw route-target header literal outside its const definition",
        },
        Rule {
            row: "response-header:route-emission-site",
            needle: ".header(HDR_ROUTE_",
            what: "x-busbar-route-* header write outside proxy::wire::maybe_attach_route_policy \
                   (bypasses the route_policy config gate)",
            allow: HDR_ROUTE_WIRE_FILE,
            title_ok: "the route-* headers are written from exactly one gated function",
            title_bad: "a route-* header write bypasses the route_policy config gate",
        },
        Rule {
            row: "response-header:server-timing-literal",
            needle: "\"server-timing\"",
            what: "raw server-timing string literal outside HEADER_SERVER_TIMING",
            allow: HDR_SERVER_TIMING_FILE,
            title_ok: "the server-timing header name is spelled only at its const definition",
            title_bad: "a raw server-timing header literal outside its const definition",
        },
        Rule {
            row: "response-header:server-timing-value",
            needle: "busbar;dur=",
            what: "busbar;dur= Server-Timing value formatted outside router.rs::server_timing",
            allow: HDR_SERVER_TIMING_FILE,
            title_ok: "the Server-Timing value shape is formatted at exactly one site",
            title_bad: "a second Server-Timing value formatter is a second ungated emission site",
        },
    ]
}

/// The one line a finding is written as, on BOTH sides of a parity run — the shell's
/// `UNGATED-HEADER: <file>:<line>: <what> — route through <allow>`, minus the prefix.
fn finding(rel: &str, line: usize, what: &str, allow: &str) -> String {
    format!("{rel}:{line}: {what} — route through {allow}")
}

fn row_for(rule: &Rule, offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(rule.row, rule.title_ok, CLEAN);
    }
    Row::fail(
        rule.row,
        rule.title_bad,
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

pub struct ResponseHeaderGate;

fn scan_roots(cx: &Ctx) -> Result<Vec<String>, String> {
    let roots = PlaneRoots::at(cx.abs("crates"));
    let mut out: Vec<String> = FIXED_ROOTS.iter().map(|r| (*r).to_string()).collect();
    let (ok, errs) = roots.resolve_all(PLANE_KEYS);
    if !errs.is_empty() {
        return Err(errs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | "));
    }
    for (_, dir) in ok {
        let rel = dir
            .strip_prefix(cx.root())
            .map_err(|_| format!("{} is not under the workspace root", dir.display()))?;
        out.push(rel.to_string_lossy().replace('\\', "/"));
    }
    Ok(out)
}

/// Every owed row answered `DID NOT RUN`, for the three ways the scan can refuse to happen.
fn refused(first: Row, rest_title: &'static str) -> Verdict {
    let mut rows = vec![first];
    for row in [ROW_PLANE_ROOTS, ROW_SCAN_ROOTS, ROW_SCAN_FLOOR, ROW_SITES] {
        if rows.iter().all(|r: &Row| r.id != row) {
            rows.push(Row::fail(row, rest_title, DID_NOT_RUN.to_string()));
        }
    }
    for rule in rules() {
        rows.push(Row::fail(rule.row, rest_title, DID_NOT_RUN.to_string()));
    }
    Verdict::of(rows)
}

impl Gate for ResponseHeaderGate {
    fn name(&self) -> &'static str {
        "response-header"
    }

    fn owed(&self) -> Vec<String> {
        let mut out = vec![
            ROW_PLANE_ROOTS.to_string(),
            ROW_SCAN_ROOTS.to_string(),
            ROW_SCAN_FLOOR.to_string(),
            ROW_SITES.to_string(),
        ];
        out.extend(rules().into_iter().map(|r| r.row.to_string()));
        out
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let roots = match scan_roots(cx) {
            Ok(r) => r,
            Err(why) => {
                return refused(
                    Row::fail(ROW_PLANE_ROOTS, "a plane root did not resolve", why),
                    "the root set is unknown",
                )
            }
        };

        // THE POPULATION IS DERIVED FROM THE TREE (see `gates::population`): every non-test `.rs`
        // under `crates/`, not the three fixed roots plus two plane homes that opened 280 of 725.
        // `roots` is still resolved, because a plane that cannot be located is its own refusal.
        let population = match population::source_population(cx) {
            Ok(p) => p,
            Err(why) => {
                let mut v = refused(
                    Row::fail(ROW_SCAN_ROOTS, "the tree would not list", why),
                    "the scan set is unknown",
                );
                v.rows.retain(|r| r.id != ROW_PLANE_ROOTS);
                v.rows.insert(
                    0,
                    Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                );
                return Verdict::of(v.rows);
            }
        };
        let mut unusable: Vec<String> = population
            .drained
            .iter()
            .map(|c| format!("crates/{c}: has a src/ and contributed no file to the scan"))
            .collect();
        for root in &roots {
            if !cx.exists(root) {
                unusable.push(format!("{root}: not on disk"));
            }
        }
        let files = population.files.clone();
        if !unusable.is_empty() {
            let mut v = refused(
                Row::fail(
                    ROW_SCAN_ROOTS,
                    "a scan root is missing or drained",
                    format!(
                        "{} — a root that is missing or drained is scanned as ZERO files, and zero \
                         files inject no header. If the layout moved, point the root at its new \
                         home in a reviewed diff that says so.",
                        unusable.join(" | ")
                    ),
                ),
                "the scan set is incomplete",
            );
            v.rows.retain(|r| r.id != ROW_PLANE_ROOTS);
            v.rows.insert(
                0,
                Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            );
            return Verdict::of(v.rows);
        }

        let mut head = vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::pass(
                ROW_SCAN_ROOTS,
                "every crate under crates/ contributed its source",
                population.census(),
            ),
        ];

        if population.below_floor() {
            head.push(Row::fail(
                ROW_SCAN_FLOOR,
                "the scan set is below its floor",
                format!(
                    "{}. This gate scanned (almost) nothing, so its verdict is meaningless — it is \
                     NOT a pass.",
                    population.census()
                ),
            ));
            head.push(Row::fail(
                ROW_SITES,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ));
            for rule in rules() {
                head.push(Row::fail(
                    rule.row,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ));
            }
            return Verdict::of(head);
        }
        head.push(Row::pass(
            ROW_SCAN_FLOOR,
            "the scan set cleared its floor",
            population.census(),
        ));

        // THE ALLOWLIST MUST DESCRIBE REALITY. A sanctioned site that no longer exists is an
        // allowlist matching nothing, which is indistinguishable from a tree with no bypass.
        let missing: Vec<&str> = [
            HDR_ROUTE_POLICY_FILE,
            HDR_ROUTE_WIRE_FILE,
            HDR_SERVER_TIMING_FILE,
        ]
        .into_iter()
        .filter(|f| !cx.exists(f))
        .collect();
        if missing.is_empty() {
            head.push(Row::pass(
                ROW_SITES,
                "every sanctioned emission site named by the rule table exists",
                CLEAN,
            ));
        } else {
            head.push(Row::fail(
                ROW_SITES,
                "the rule table names a sanctioned emission site that no longer exists",
                format!(
                    "{} — an allowlist naming a vanished file quietly matches nothing, which reads \
                     exactly like a clean tree. Update the table.",
                    missing.join(", ")
                ),
            ));
        }

        for rule in rules() {
            let mut offenders = Vec::new();
            for f in &files {
                let rel = f.rel_str();
                if rel == rule.allow {
                    continue;
                }
                for (lineno, code) in f.production_lines() {
                    if code.contains(rule.needle) {
                        offenders.push(finding(&rel, lineno, rule.what, rule.allow));
                    }
                }
            }
            offenders.sort();
            head.push(row_for(&rule, &offenders));
        }
        Verdict::of(head)
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every busbar-injected header has one gated site",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // EACH RULE ON ITS OWN FIXTURE. A single file tripping all five would let four of them be
        // deleted with this selftest still green -- the "independent floors exercised only
        // together" failure, which turned up in seven of the shell self-tests.
        for rule in rules() {
            let path = format!("{CORE}/planted_{}.rs", rule.row.replace([':', '-'], "_"));
            let mut ov = Overlay::new();
            ov.set(
                &path,
                format!(
                    "fn bypass(rb: Builder) -> Builder {{\n    let _ = {};\n    rb\n}}\n",
                    {
                        // A `.header(HDR_ROUTE_` needle needs a call shape around it; the literals do
                        // not. Either way the planted line is CODE, which is the point.
                        if rule.needle.starts_with('.') {
                            format!("rb{}POLICY, \"cheapest\")", rule.needle)
                        } else {
                            format!("\"{}\"", rule.needle.trim_matches('"'))
                        }
                    }
                ),
            );
            report.push(prove_red(
                cx,
                self,
                format!("a hand-rolled bypass of {} is flagged", rule.row),
                &[rule.row],
                ov,
                &["1 finding(s)", &format!("route through {}", rule.allow)],
            ));
        }

        // THE SANCTIONED SITE IS EXEMPT. The same bypass text, in the file the rule allowlists,
        // must stay silent -- otherwise the gate reds on the very site it sanctions.
        let mut ov = Overlay::new();
        let owner = cx.read(HDR_SERVER_TIMING_FILE).unwrap_or_default();
        ov.set(
            HDR_SERVER_TIMING_FILE,
            format!("{owner}\nfn planted_owner() {{ let _ = \"server-timing\"; }}\n"),
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "the allowlisted owner may carry the literal it owns",
            &["response-header:server-timing-literal"],
        ));

        // PROSE AND TESTS ARE NOT INJECTION. A comment naming a header and a `#[cfg(test)]` body
        // reading one back are both exempt -- and a gate its own explanation fails is a gate people
        // learn to skip.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_prose.rs"),
            "// The x-busbar-route-policy header names the deciding policy.\n\
             #[cfg(test)]\nmod tests {\n    #[test]\n    fn reads_it_back() {\n\
             \x20       let v = \"x-busbar-route-policy\";\n        let _ = v;\n    }\n}\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a comment mention and a #[cfg(test)] read-back are both exempt",
            &["response-header:route-policy-literal"],
        ));

        // THE SANCTIONED SITE THAT VANISHED: the allowlist then matches nothing.
        let mut ov = Overlay::new();
        ov.remove(HDR_ROUTE_WIRE_FILE);
        report.push(prove_red(
            cx,
            self,
            "a rule table naming a vanished sanctioned site is refused",
            &[ROW_SITES],
            ov,
            &["no longer exists"],
        ));

        // THE INSTRUMENT: the thin binary root, which no rule names a file inside.
        match cx.walk(&WalkSpec::new([BIN]).ext("rs").exclude([EXCLUDE_TESTS_DIR])) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "the binary root leaving the scan is refused, though no rule names a file in it",
                    &[ROW_SCAN_ROOTS],
                    ov,
                    &["missing or drained"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "response-header selftest: the binary root is unreadable ({e})"
            )),
        }

        // THE AGGREGATE FLOOR, with every root still holding a file.
        match scan_roots(cx) {
            Ok(roots) => {
                let mut ov = Overlay::new();
                let mut planted = false;
                for root in &roots {
                    if let Ok(files) = cx.walk(
                        &WalkSpec::new([root.clone()])
                            .ext("rs")
                            .exclude([EXCLUDE_TESTS_DIR]),
                    ) {
                        for f in files.iter().skip(1) {
                            ov.remove(&f.rel);
                            planted = true;
                        }
                    }
                }
                if planted {
                    report.push(prove_red(
                        cx,
                        self,
                        "a scan set below its floor is refused though every root still holds a file",
                        &[ROW_SCAN_FLOOR],
                        ov,
                        &["below its floor"],
                    ));
                }
            }
            Err(e) => report.note_infra_failure(format!(
                "response-header selftest: the plane roots do not resolve ({e})"
            )),
        }

        // THE PLANE ROOTS, which only this rule catches: a plane that SPLIT away is invisible to
        // every floor, because the floor is still cleared by what is left.
        //
        // Driven THROUGH `Gate::run`, over a fixture tree in which no plane declares its grammar.
        // The plane resolver reads `std::fs` under `cx.abs("crates")`, so no overlay can make a
        // plane vanish — re-rooting the whole context is what plants this one honestly.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a plane that cannot be located is refused, not scanned as a smaller tree",
            &[ROW_PLANE_ROOTS],
            PLANE_ROOT_MISSING_FIXTURE,
            &["PLANE-ROOT-MISSING"],
        ));

        report
    }
}

/// Read the shell gate's own output into the same nine rows. Its findings carry the rule's `what`
/// label, which is what routes each one back to the row it answers on.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let table = rules();
    let mut per_rule: Vec<Vec<String>> = vec![Vec::new(); table.len()];
    let mut plane_unresolved = None;
    let mut roots_unusable = None;
    let mut floor_broken = None;
    let mut site_missing = None;
    let mut ran = false;

    for raw in run.lines() {
        let t = raw.trim();
        if t.contains("PLANE ROOT UNRESOLVED") {
            plane_unresolved = Some(t.to_string());
            continue;
        }
        if t.contains("SCAN ROOT UNUSABLE") {
            roots_unusable = Some(t.to_string());
            continue;
        }
        if t.contains("SCAN ROOT EMPTY OR MOVED") {
            floor_broken = Some(t.to_string());
            continue;
        }
        if t.contains("sanctioned emission site missing") {
            site_missing = Some(t.to_string());
            continue;
        }
        if t.starts_with("scan set:") || t == "response-header-lint passed" {
            ran = true;
            continue;
        }
        let Some(hit) = t.strip_prefix("UNGATED-HEADER: ") else {
            continue;
        };
        ran = true;
        let Some(i) = table.iter().position(|r| hit.contains(r.what)) else {
            return Err(format!(
                "the legacy translator does not recognise the finding `{hit}`. An unclassified \
                 finding dropped on the floor is how a rewrite is proven faithful to a script \
                 nobody read."
            ));
        };
        per_rule[i].push(hit.to_string());
    }

    if plane_unresolved.is_none()
        && roots_unusable.is_none()
        && floor_broken.is_none()
        && site_missing.is_none()
        && !ran
    {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no scan-set line, no \
             verdict, no findings. Silence read as a clean tree is the exact defect this gate \
             exists for.",
            run.argv.join(" ")
        ));
    }

    let stop = |first: Row, title: &'static str| -> Vec<Row> {
        let mut v = refused(first, title);
        v.rows.sort_by(|a, b| a.id.cmp(&b.id));
        v.rows
    };
    if let Some(why) = plane_unresolved {
        return Ok(stop(
            Row::fail(ROW_PLANE_ROOTS, "a plane root did not resolve", why),
            "the root set is unknown",
        ));
    }

    let mut rows = vec![
        Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
        if let Some(why) = &roots_unusable {
            Row::fail(
                ROW_SCAN_ROOTS,
                "a scan root is missing or drained",
                why.clone(),
            )
        } else {
            Row::pass(
                ROW_SCAN_ROOTS,
                "every scan root holds production source",
                CLEAN,
            )
        },
    ];
    if roots_unusable.is_some() {
        rows.push(Row::fail(
            ROW_SCAN_FLOOR,
            "the scan set is incomplete",
            DID_NOT_RUN.to_string(),
        ));
        rows.push(Row::fail(
            ROW_SITES,
            "the scan set is incomplete",
            DID_NOT_RUN.to_string(),
        ));
        for rule in &table {
            rows.push(Row::fail(
                rule.row,
                "the scan set is incomplete",
                DID_NOT_RUN.to_string(),
            ));
        }
        return Ok(rows);
    }
    if let Some(why) = floor_broken {
        rows.push(Row::fail(
            ROW_SCAN_FLOOR,
            "the scan set is below its floor",
            why,
        ));
        rows.push(Row::fail(
            ROW_SITES,
            "the scan did not run",
            DID_NOT_RUN.to_string(),
        ));
        for rule in &table {
            rows.push(Row::fail(
                rule.row,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ));
        }
        return Ok(rows);
    }
    rows.push(Row::pass(
        ROW_SCAN_FLOOR,
        "the scan set cleared its floor",
        CLEAN,
    ));
    if let Some(why) = site_missing {
        rows.push(Row::fail(
            ROW_SITES,
            "the rule table names a sanctioned emission site that no longer exists",
            why,
        ));
        for rule in &table {
            rows.push(Row::fail(
                rule.row,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ));
        }
        return Ok(rows);
    }
    rows.push(Row::pass(
        ROW_SITES,
        "every sanctioned emission site named by the rule table exists",
        CLEAN,
    ));
    for (i, rule) in table.iter().enumerate() {
        per_rule[i].sort();
        rows.push(row_for(rule, &per_rule[i]));
    }
    Ok(rows)
}
