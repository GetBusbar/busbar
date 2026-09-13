//! `cargo xtask gate tracing` — EVERY SPAN IS BOUND TO AN EXPLICIT LEVEL, SET IN ONE PLACE. The
//! successor to `scripts/tracing-lint.sh`, rule for rule.
//!
//! A `#[tracing::instrument]` (or the prelude-imported `#[instrument]` form) that omits an explicit
//! `level = …` silently defaults to INFO — always on, on the hot path — which is what
//! `proxy/engine/mod.rs`'s `forward` span and `proxy/engine/walk.rs`'s `forward_once` span once
//! did. The scope is deliberately narrow: this enforces the mechanical, unambiguous half of the
//! tracing-seam contract and nothing else. The companion rule ("no per-request-happy-path `info!`")
//! was evaluated and REJECTED — distinguishing a happy-path event from a degraded one requires
//! reading the surrounding branch, and a lint that guesses wrong on that axis erodes trust in the
//! whole gate. `docs/observability.md` carries that half as a review rule.
//!
//! Three rows, because the shell had three ways to be wrong and only one of them was a rogue span:
//!
//! * `tracing:scan-floor` — the walk found the crates. "Every `#[instrument]` has a level" is
//!   VACUOUSLY TRUE over zero files, so a workspace restructure that moves crates out from under
//!   `crates/` would leave this reporting `ok` forever about a tree it never opened. The floor is
//!   not `> 0`: one surviving file is as vacuous as none.
//! * `tracing:instrument-level` — the finding.
//! * `tracing:attribute-closes` — an attribute whose parens never balance before EOF. This is its
//!   own row rather than a line in the finding row because it is the accumulator saying it lost
//!   track, and everything after it in that file went unscanned. Silence is what a clean file looks
//!   like, so it has to be a reported finding instead of the end of the scan.
//!
//! THE STRING-LITERAL RULE IS THE WHOLE SCANNER. `tracing-lint.sh` counted parens inside string
//! literals, so `#[instrument(level = "debug", name = "f(")]` never balanced: the accumulator
//! swallowed the rest of the file and reported every later level-less span in it as clean. Literals
//! are blanked before the parens are counted, and the SAME blanked text is what the `level` check
//! reads — so `name = "log_level"` does not count as declaring a level either.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::scan;

pub const ROW_SCAN_FLOOR: &str = "tracing:scan-floor";
pub const ROW_LEVEL: &str = "tracing:instrument-level";
pub const ROW_CLOSES: &str = "tracing:attribute-closes";

/// The candidate set: every crate `.rs` EXCEPT integration-test trees. A test helper span's level
/// is not an operator-visible hot-path concern, and the exemption is the same one
/// `structure-lint.sh` and `response-header-lint.sh` apply.
const SCAN_ROOT: &str = "crates";
const EXCLUDE_TESTS_DIR: &str = "/tests/";

/// The denominator floor, tracking the real workspace (160 files when the shell was written, 738
/// today). It is a `const` here and has no environment override: the only way to lower one is a
/// reviewable source edit.
const SCAN_FLOOR: usize = 130;

/// The two findings, spelled ONCE so both the gate and its legacy translator write them the same
/// way and a parity diff can only be about which spans were found.
fn finding_level(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: #[instrument] with no explicit level= — must reference \
         observability::HOTPATH_LEVEL (or a literal level) so it is filtered off by default"
    )
}

fn finding_unclosed(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: #[instrument] attribute never closes — its parens do not balance before the \
         end of the file, so this span AND EVERY LATER SPAN IN THIS FILE went unchecked"
    )
}

const CLEAN: &str = "the scan cleared its floor and named nothing";

/// One file's findings: the level-less spans and the attribute that never closed.
#[derive(Debug, Default)]
struct Findings {
    level: Vec<String>,
    unclosed: Vec<String>,
}

/// Does this line OPEN an `#[instrument]` / `#[tracing::instrument]` attribute? The shell's
/// `^[[:space:]]*#\[[[:space:]]*(tracing[[:space:]]*::[[:space:]]*)?instrument[[:space:]]*[](]`,
/// matched against the RAW line exactly as the awk did.
fn opens_instrument_attr(line: &str) -> bool {
    let t = line.trim_start();
    let Some(rest) = t.strip_prefix("#[") else {
        return false;
    };
    let rest = rest.trim_start();
    let rest = match rest.strip_prefix("tracing") {
        Some(after) => {
            let after = after.trim_start();
            match after.strip_prefix("::") {
                Some(a) => a.trim_start(),
                // `#[tracingfoo…]` is not the attribute; neither is a bare `#[tracing]`.
                None => return false,
            }
        }
        None => rest,
    };
    let Some(after) = rest.strip_prefix("instrument") else {
        return false;
    };
    let after = after.trim_start();
    after.starts_with(']') || after.starts_with('(')
}

/// The statement-window accumulator, per file. An attribute's token stream may span any number of
/// lines (a multi-line `fields(…)` list is the common shape); it is complete once the accumulated
/// code has equal `(` and `)` counts — true immediately for a bare `#[instrument]`.
fn scan_file(rel: &str, text: &str) -> Findings {
    let mut out = Findings::default();
    let mut in_attr = false;
    let mut start_line = 0usize;
    let mut code = String::new();
    let mut lex = scan::LexState::default();

    for (i, line) in text.lines().enumerate() {
        let is_comment = line.trim_start().starts_with("//");
        // A paren inside a STRING LITERAL or a COMMENT is text, not structure. The state is carried
        // so a `fields(…)` list interrupted by a multi-line literal is still read as one attribute.
        let nostr = scan::blank_code(line, &mut lex);

        if !in_attr {
            if is_comment || !opens_instrument_attr(line) {
                continue;
            }
            in_attr = true;
            start_line = i + 1;
            code = nostr;
        } else {
            code.push('\n');
            code.push_str(&nostr);
        }

        let opens = code.matches('(').count();
        let closes = code.matches(')').count();
        if opens == closes {
            if !code.contains("level") {
                out.level.push(finding_level(rel, start_line));
            }
            in_attr = false;
            code.clear();
        }
    }
    if in_attr {
        out.unclosed.push(finding_unclosed(rel, start_line));
    }
    out
}

/// The finding rows, built from offender lists — the ONE constructor `run` and the legacy
/// translator both call.
fn row_level(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_LEVEL,
            "every #[instrument] carries an explicit level=",
            CLEAN,
        );
    }
    Row::fail(
        ROW_LEVEL,
        "a #[instrument] span defaults to INFO",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

fn row_closes(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_CLOSES,
            "every #[instrument] attribute closes before the end of its file",
            CLEAN,
        );
    }
    Row::fail(
        ROW_CLOSES,
        "an #[instrument] attribute never closes, so the rest of its file went unscanned",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

pub struct TracingGate;

impl Gate for TracingGate {
    fn name(&self) -> &'static str {
        "tracing"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_SCAN_FLOOR.to_string(),
            ROW_LEVEL.to_string(),
            ROW_CLOSES.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let spec = WalkSpec::new([SCAN_ROOT])
            .ext("rs")
            .exclude([EXCLUDE_TESTS_DIR])
            .min_files(SCAN_FLOOR);
        let files = match cx.walk(&spec) {
            Ok(f) => f,
            Err(e) => {
                return Verdict::of(vec![
                    Row::fail(
                        ROW_SCAN_FLOOR,
                        "the crates walk did not clear its floor",
                        format!(
                            "{e} If the workspace layout legitimately changed, move the root AND \
                             the floor together, in a diff that says so."
                        ),
                    ),
                    Row::fail(
                        ROW_LEVEL,
                        "the instrument scan did not run",
                        "this lint scanned (almost) nothing, so its verdict is meaningless — it is \
                         NOT a pass"
                            .to_string(),
                    ),
                    Row::fail(
                        ROW_CLOSES,
                        "the instrument scan did not run",
                        "this lint scanned (almost) nothing, so its verdict is meaningless — it is \
                         NOT a pass"
                            .to_string(),
                    ),
                ]);
            }
        };

        let mut level = Vec::new();
        let mut unclosed = Vec::new();
        for f in &files {
            let found = scan_file(&f.rel_str(), &f.text);
            level.extend(found.level);
            unclosed.extend(found.unclosed);
        }
        level.sort();
        unclosed.sort();

        Verdict::of(vec![
            Row::pass(ROW_SCAN_FLOOR, "the crates walk cleared its floor", CLEAN),
            row_level(&level),
            row_closes(&unclosed),
        ])
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
            "every span in the tree carries an explicit level",
            &[ROW_SCAN_FLOOR, ROW_LEVEL, ROW_CLOSES],
        ));

        // The three level-less SHAPES, planted together: bare, single-line, and — the shape that
        // actually shipped rogue — multi-line with the closing paren several lines down.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_rogue_spans.rs",
            "#[instrument]\npub fn bare() {}\n\n\
             #[tracing::instrument(name = \"forward_once\", skip_all, fields(lane = i))]\n\
             pub fn single_line() {}\n\n\
             #[allow(clippy::too_many_arguments)]\n\
             #[tracing::instrument(\n    name = \"forward\",\n    skip_all,\n\
             \x20   fields(pool = %pool_name)\n)]\npub fn multi_line() {}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "the bare, single-line and multi-line level-less shapes are all flagged",
            &[ROW_LEVEL],
            ov,
            &[
                "3 finding(s)",
                "planted_rogue_spans.rs:1",
                "planted_rogue_spans.rs:8",
            ],
        ));

        // THE INSTRUMENT FOR THE FIX THIS PORT INHERITS. A paren inside a string is text. The first
        // attribute is legitimately levelled but carries an unbalanced `(` in a name; before the
        // fix the accumulator never closed, swallowed the rest of the file, and reported the rogue
        // span two declarations down as CLEAN. The third claims a level only inside a string,
        // which is not one. Exactly two findings, and which two is the point.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_paren_in_a_string.rs",
            "#[tracing::instrument(level = \"debug\", name = \"f(unbalanced\")]\n\
             pub fn levelled_with_a_paren_in_a_string() {}\n\n\
             #[tracing::instrument(name = \"rogue\", skip_all)]\n\
             pub fn rogue_after_the_paren() {}\n\n\
             #[tracing::instrument(name = \"log_level\", skip_all)]\n\
             pub fn level_only_inside_a_string() {}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a paren inside a string neither swallows the file nor declares a level",
            &[ROW_LEVEL],
            ov,
            &[
                "2 finding(s)",
                "planted_paren_in_a_string.rs:4",
                "planted_paren_in_a_string.rs:7",
            ],
        ));

        // AN ATTRIBUTE THAT NEVER BALANCES used to end the scan in silence, and silence is what a
        // clean file looks like.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_unclosed.rs",
            "#[tracing::instrument(\n    level = \"debug\",\n    name = \"never_closed\",\n\
             pub fn dangling() {}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "an attribute that never balances is reported, not dropped in silence",
            &[ROW_CLOSES],
            ov,
            &["never closes", "planted_unclosed.rs:1"],
        ));

        // A COMMENT MERELY NAMING THE ATTRIBUTE must not arm the scanner — the tree documents this
        // rule in prose, and a gate its own explanation fails is a gate people learn to skip.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_prose.rs",
            "// A comment naming #[instrument] must not arm the scanner.\n\
             // #[instrument]\npub fn prod_after() {}\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a comment mentioning the attribute stays green",
            &[ROW_LEVEL],
        ));

        // THE FLOOR, on the RUN path. Every candidate file is removed from the overlay's view,
        // which is what a workspace restructure looks like from the scan's side.
        match cx.walk(
            &WalkSpec::new([SCAN_ROOT])
                .ext("rs")
                .exclude([EXCLUDE_TESTS_DIR]),
        ) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a scan set below its floor is refused, not reported as a clean tree",
                    &[ROW_SCAN_FLOOR],
                    ov,
                    &["floor"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "tracing selftest: the base tree's crates walk is unreadable ({e}), so the floor \
                 plant has nothing to empty"
            )),
        }

        report
    }
}

/// Read the shell gate's own output into the same three rows. Its findings are printed one per
/// line under a `ROGUE-INSTRUMENT:` prefix; its floor refusal is its own sentence. Nothing here
/// re-scans the tree — a translator that scanned would be proving the Rust against itself.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut level = Vec::new();
    let mut unclosed = Vec::new();
    let mut floor_broken = None;
    let mut ran = false;

    for line in run.lines() {
        let t = line.trim();
        if t.contains("SCAN ROOT EMPTY OR MOVED") {
            floor_broken = Some(t.to_string());
            continue;
        }
        if t.starts_with("scan set:") || t == "tracing-lint passed" {
            ran = true;
            continue;
        }
        let Some(hit) = t.strip_prefix("ROGUE-INSTRUMENT: ") else {
            continue;
        };
        ran = true;
        if hit.contains("attribute never closes") {
            unclosed.push(hit.to_string());
        } else if hit.contains("with no explicit level=") {
            level.push(hit.to_string());
        } else {
            return Err(format!(
                "the legacy translator does not recognise the finding `{hit}`. An unclassified \
                 finding dropped on the floor is how a rewrite is proven faithful to a script \
                 nobody read."
            ));
        }
    }

    if floor_broken.is_none() && !ran {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no scan-set line, no \
             verdict, no findings. Silence read as a clean tree is the exact defect this gate \
             exists for.",
            run.argv.join(" ")
        ));
    }

    if let Some(why) = floor_broken {
        return Ok(vec![
            Row::fail(
                ROW_SCAN_FLOOR,
                "the crates walk did not clear its floor",
                why,
            ),
            Row::fail(
                ROW_LEVEL,
                "the instrument scan did not run",
                "this lint scanned (almost) nothing, so its verdict is meaningless — it is NOT a \
                 pass"
                    .to_string(),
            ),
            Row::fail(
                ROW_CLOSES,
                "the instrument scan did not run",
                "this lint scanned (almost) nothing, so its verdict is meaningless — it is NOT a \
                 pass"
                    .to_string(),
            ),
        ]);
    }

    level.sort();
    unclosed.sort();
    Ok(vec![
        Row::pass(ROW_SCAN_FLOOR, "the crates walk cleared its floor", CLEAN),
        row_level(&level),
        row_closes(&unclosed),
    ])
}
