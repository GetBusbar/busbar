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
//! * `tracing:scan-floor` — the walk read the crates. "Every `#[instrument]` has a level" is
//!   VACUOUSLY TRUE over zero files, so a workspace restructure that moves crates out from under
//!   `crates/` would leave this reporting `ok` forever about a tree it never opened. The scanned
//!   LIST is reconciled against the tracked set under the same scope (Law 8: "a census reports the
//!   LIST it scanned, not the count"): a tracked file the walk did not read, or a file it read that
//!   nothing tracks, is refused by name. It replaced a hand-kept file count (last 978) that every
//!   change adding or removing a source file had to re-pin.
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

use crate::ctx::{Coverage, Ctx, Overlay, WalkSpec};
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

/// THE SUBJECT FLOOR (item 228). The reconciliation proves the walk read every tracked file; it
/// says nothing about whether the thing this gate judges is still there. "Every `#[instrument]` has
/// a level" is as vacuous over zero SPANS as over zero files, and the files-to-spans ratio is
/// ~150:1 (977 files, 5 attributes), so every span could leave the tree with every file still
/// read. Armed at the measured count (arrival.rs 3, ingress/mod.rs 2); it has no override, and
/// lowering it is a reviewable source edit that says which span went where. It is the gate's
/// positive control, not a file count. LOWERED 5 -> 2 with the retired engine crate's deletion
/// (DEV-GREEN row 83, coordinator ruling 2026-10-18): the three spans of its test kit's arrival
/// shell (`gemini_ingress`, `bedrock_converse`, `bedrock_invoke`) left the tree with it; the two
/// left are the kernel ingress's `named` and `adhoc`. RAISED 2 -> 3 (row 82 D2, ARCHITECT ruling
/// 2026-10-20): `named` and `adhoc` left with the kernel's body-ingress, and the scan now reads the
/// hand-rolled span macros beside the attribute: the composition root's door `forward` span
/// (`span!` at HOTPATH_LEVEL) and the driver's two `debug_span!("forward")` spans. The measured
/// count; it never goes down without a diff saying which span went where.
const SPAN_FLOOR: usize = 3;

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
    /// How many `#[instrument]` attributes the scan read — the subject count [`SPAN_FLOOR`] judges.
    spans: usize,
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

/// Does this blanked attribute text set the span's LEVEL — a TOP-LEVEL `level = …` argument of the
/// `instrument(…)` list? (Item 229.) A substring test accepted `fields(level = %lvl)` (a span FIELD
/// named `level`, which leaves the span at the default INFO) and `skip(log_level)`; only an argument
/// at paren depth 1 whose key is exactly `level` followed by `=` sets the Level.
fn declares_level(code: &str) -> bool {
    let Some(open) = code.find("instrument").and_then(|at| {
        code[at..]
            .find('(')
            .map(|p| at + p)
            .filter(|p| code[at + "instrument".len()..*p].trim().is_empty())
    }) else {
        return false;
    };
    let mut depth = 0usize;
    let mut args: Vec<String> = vec![String::new()];
    for c in code[open..].chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                if depth == 1 {
                    continue;
                }
            }
            ')' | ']' | '}' => {
                if depth == 1 {
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            ',' if depth == 1 => {
                args.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(a) = args.last_mut() {
            a.push(c);
        }
    }
    args.iter().any(|a| {
        a.trim()
            .strip_prefix("level")
            .map(|rest| {
                let rest = rest.trim_start();
                rest.starts_with('=') && !rest.starts_with("==")
            })
            .unwrap_or(false)
    })
}

/// THE SPAN MACROS the scan reads beside the attribute (row 82 D2, ARCHITECT ruling 2026-10-20):
/// a hand-rolled span is a span. Each name with the level it fixes; `None` is `span!`, whose
/// level is its first argument.
const SPAN_MACROS: [(&str, Option<&str>); 6] = [
    ("span", None),
    ("trace_span", Some("TRACE")),
    ("debug_span", Some("DEBUG")),
    ("info_span", Some("INFO")),
    ("warn_span", Some("WARN")),
    ("error_span", Some("ERROR")),
];

/// Where the one hot-path level is set, and the declaration the scan reads it off.
const HOTPATH_HOME: &str = "crates/busbar-kernel/src/observability.rs";
const HOTPATH_DECL: &str = "pub const HOTPATH_LEVEL: tracing::Level = tracing::Level::";

/// The level `observability::HOTPATH_LEVEL` is set to (`DEBUG`), read off its declaration.
fn hotpath_level(text: &str) -> Option<String> {
    let at = text.find(HOTPATH_DECL)? + HOTPATH_DECL.len();
    let word: String = text[at..]
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    (!word.is_empty()).then_some(word)
}

/// The span MACROS a line invokes: each one's name, the level it fixes, and the byte index just
/// past its `(`. `debug_span!` is not also a `span!`: a match must not follow an identifier
/// character.
fn span_macros_in(line: &str) -> Vec<(&'static str, Option<&'static str>, usize)> {
    let mut hits = Vec::new();
    for (name, level) in SPAN_MACROS {
        let needle = format!("{name}!");
        let mut from = 0;
        while let Some(found) = line[from..].find(&needle) {
            let at = from + found;
            from = at + needle.len();
            let boundary = line[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
            let rest = &line[from..];
            let open = rest.len() - rest.trim_start().len();
            if boundary && rest.trim_start().starts_with('(') {
                hits.push((name, level, from + open + 1));
            }
        }
    }
    hits.sort_by_key(|h| h.2);
    hits
}

/// A `span!`'s first argument, read from `lines[at]` past `open` and on down the following lines
/// to the first top-level `,` or `)`.
fn first_argument(lines: &[String], at: usize, open: usize) -> String {
    let mut arg = String::new();
    let mut depth = 0usize;
    let mut first = true;
    for line in &lines[at..] {
        let text = if first { &line[open..] } else { line.as_str() };
        first = false;
        for c in text.chars() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => return arg,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => return arg,
                _ => {}
            }
            arg.push(c);
        }
        arg.push(' ');
    }
    arg
}

fn finding_macro(rel: &str, line: usize, name: &str, level: &str, hot: &str) -> String {
    format!(
        "{rel}:{line}: {name}! span at {level} -- a hand-rolled span must sit at \
         observability::HOTPATH_LEVEL ({hot})"
    )
}

/// The hand-rolled spans of one file (its code blanked of literals and comments): how many it
/// holds, and each one whose level is not `hot`.
fn scan_macros(rel: &str, text: &str, hot: Option<&str>) -> (usize, Vec<String>) {
    let mut lex = scan::LexState::default();
    let lines: Vec<String> = text
        .lines()
        .map(|l| scan::blank_code(l, &mut lex))
        .collect();
    let (mut spans, mut findings) = (0usize, Vec::new());
    for (i, line) in lines.iter().enumerate() {
        for (name, fixed, open) in span_macros_in(line) {
            spans += 1;
            let level = match fixed {
                Some(level) => level.to_string(),
                None => first_argument(&lines, i, open).trim().to_string(),
            };
            let ok = match hot {
                Some(h) => match fixed {
                    Some(level) => level == h,
                    None => {
                        level.ends_with("HOTPATH_LEVEL") || level.ends_with(&format!("Level::{h}"))
                    }
                },
                None => false,
            };
            if !ok {
                findings.push(finding_macro(
                    rel,
                    i + 1,
                    name,
                    &level,
                    hot.unwrap_or("unread: no HOTPATH_LEVEL declaration in its home"),
                ));
            }
        }
    }
    (spans, findings)
}

/// The statement-window accumulator, per file. An attribute's token stream may span any number of
/// lines (a multi-line `fields(…)` list is the common shape); it is complete once the accumulated
/// code has equal `(` and `)` counts — true immediately for a bare `#[instrument]`.
fn scan_file(rel: &str, text: &str, hot: Option<&str>) -> Findings {
    let mut out = Findings::default();
    let (macro_spans, macro_findings) = scan_macros(rel, text, hot);
    out.spans += macro_spans;
    out.level.extend(macro_findings);
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
            out.spans += 1;
            if !declares_level(&code) {
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
            "every span carries its level: #[instrument] an explicit level=, a span macro \
             HOTPATH_LEVEL",
            CLEAN,
        );
    }
    Row::fail(
        ROW_LEVEL,
        "a span defaults to INFO or sits off HOTPATH_LEVEL",
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

/// The walk the gate judges — the one place the scan set is spelled, so the tracked set it is
/// reconciled against is cut by exactly the same scope and filters.
fn scan_spec() -> WalkSpec {
    WalkSpec::new([SCAN_ROOT])
        .ext("rs")
        .exclude([EXCLUDE_TESTS_DIR])
}

/// THE COVERAGE PLANT: one tracked file that carries no span hidden from the walk while the index
/// still lists it, returned with its path. Only a span-free file is hidden, so the subject floor
/// stays out of it and the refusal is the reconciliation's alone.
fn coverage_plant(cx: &Ctx) -> Result<(Overlay, String), String> {
    let files = cx
        .walk(&scan_spec())
        .map_err(|e| format!("the base tree's crates walk is unreadable ({e})"))?;
    let rel = files
        .iter()
        .rev()
        .find(|f| {
            !f.text.contains("#[instrument")
                && !f.text.lines().any(|l| !span_macros_in(l).is_empty())
        })
        .map(|f| f.rel_str())
        .ok_or_else(|| "the crates walk holds no span-free file to hide".to_string())?;
    let ov = cx
        .hide_from_scan([&rel])
        .map_err(|why| format!("the coverage plant cannot hide {rel} ({why})"))?;
    Ok((ov, rel))
}

/// The three rows when the scan cannot draw a verdict: the coverage row says why, the other two
/// say they did not run.
fn not_run(title: &str, why: String) -> Verdict {
    Verdict::of(vec![
        Row::fail(ROW_SCAN_FLOOR, title, why),
        Row::fail(
            ROW_LEVEL,
            "the instrument scan did not run",
            "this lint did not read the tree it would report on, so its verdict is meaningless — \
             it is NOT a pass"
                .to_string(),
        ),
        Row::fail(
            ROW_CLOSES,
            "the instrument scan did not run",
            "this lint did not read the tree it would report on, so its verdict is meaningless — \
             it is NOT a pass"
                .to_string(),
        ),
    ])
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
        let files = match cx.walk(&scan_spec()) {
            Ok(f) => f,
            Err(e) => {
                return not_run(
                    "the crates walk did not read",
                    format!(
                        "{e} If the workspace layout legitimately changed, move the root in a diff \
                         that says so."
                    ),
                );
            }
        };
        let coverage = match cx.tracked(&scan_spec()) {
            Ok(whole) => Coverage::of(files.iter().map(|f| f.rel_str()), whole),
            Err(e) => {
                return not_run(
                    "the tracked set the walk is reconciled against would not read",
                    e,
                );
            }
        };
        if !coverage.is_whole() {
            return not_run(
                "the crates walk is not the tracked set",
                format!(
                    "{}. A scan that skipped a tracked file, or read one nothing tracks, is not a \
                     claim about this tree.",
                    coverage.census()
                ),
            );
        }

        // The one hot-path level every hand-rolled span is held to, read off its declaration.
        let hot = cx.read(HOTPATH_HOME).ok().and_then(|t| hotpath_level(&t));
        let mut level = Vec::new();
        let mut unclosed = Vec::new();
        let mut spans = 0usize;
        for f in &files {
            let found = scan_file(&f.rel_str(), &f.text, hot.as_deref());
            spans += found.spans;
            level.extend(found.level);
            unclosed.extend(found.unclosed);
        }
        level.sort();
        unclosed.sort();

        if spans < SPAN_FLOOR {
            return Verdict::of(vec![
                Row::fail(
                    ROW_SCAN_FLOOR,
                    "the scan found fewer spans than its subject floor",
                    format!(
                        "{} files walked but only {spans} span(s) read (#[instrument] attributes \
                         and span macros), below the span floor of {SPAN_FLOOR}. A span that left \
                         the tree took the subject with it: lower SPAN_FLOOR in a diff that says \
                         which one and why.",
                        files.len()
                    ),
                ),
                Row::fail(
                    ROW_LEVEL,
                    "the instrument scan read fewer spans than its floor",
                    format!(
                        "{spans} span(s) read against a floor of {SPAN_FLOOR}, so 'every span has a \
                         level' is vacuous — it is NOT a pass"
                    ),
                ),
                row_closes(&unclosed),
            ]);
        }

        Verdict::of(vec![
            Row::pass(
                ROW_SCAN_FLOOR,
                "the crates walk is the tracked set",
                format!(
                    "{}; {spans} span(s), #[instrument] and span macros (span floor \
                     {SPAN_FLOOR}); {CLEAN}",
                    coverage.census()
                ),
            ),
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

        // ITEM 229: a span FIELD or a skipped ARGUMENT named `level` is not the span's Level. The
        // blanked text contains the word in both, and a substring test passed both.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_level_field.rs",
            "#[tracing::instrument(name = \"forward\", skip_all, fields(level = %lvl))]\n\
             pub fn a_field_named_level() {}\n\n\
             #[instrument(skip(log_level))]\n\
             pub fn a_skipped_arg_named_level() {}\n\n\
             #[tracing::instrument(skip_all, level = \"debug\", fields(level = %lvl))]\n\
             pub fn levelled_and_a_field() {}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a field or skipped argument named level does not set the span's Level",
            &[ROW_LEVEL],
            ov,
            &[
                "2 finding(s)",
                "planted_level_field.rs:1",
                "planted_level_field.rs:4",
            ],
        ));

        // A HAND-ROLLED SPAN IS A SPAN (row 82 D2, ARCHITECT ruling 2026-10-20): `span!` and the
        // `*_span!` macros are read beside the attribute, and each one's level is checked against
        // `observability::HOTPATH_LEVEL`. An INFO span and a `span!` at TRACE are flagged, a
        // multi-line `span!` read to its first argument; a `span!` naming HOTPATH_LEVEL and a
        // `debug_span!` (HOTPATH_LEVEL's own level) are not.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_wrong_level_spans.rs",
            "pub fn f() {\n\
             \x20   let _a = tracing::info_span!(\"forward\");\n\
             \x20   let _b = tracing::span!(\n\
             \x20       tracing::Level::TRACE,\n\
             \x20       \"forward_once\"\n\
             \x20   );\n\
             \x20   let _c = tracing::span!(busbar_kernel::observability::HOTPATH_LEVEL, \"ok\");\n\
             \x20   let _d = tracing::debug_span!(\"ok\");\n\
             }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a hand-rolled span at a level other than HOTPATH_LEVEL is flagged",
            &[ROW_LEVEL],
            ov,
            &[
                "2 finding(s)",
                "planted_wrong_level_spans.rs:2",
                "planted_wrong_level_spans.rs:3",
            ],
        ));

        // ITEM 228: THE SUBJECT FLOOR. Every production span becomes a hand-rolled `span!`; the
        // file walk still clears 130, and the scan must still refuse to call the empty subject
        // clean.
        let mut ov = Overlay::new();
        let mut planted = 0usize;
        if let Ok(files) = cx.walk(
            &WalkSpec::new([SCAN_ROOT])
                .ext("rs")
                .exclude([EXCLUDE_TESTS_DIR]),
        ) {
            for f in &files {
                if !f
                    .text
                    .lines()
                    .any(|l| opens_instrument_attr(l) || !span_macros_in(l).is_empty())
                {
                    continue;
                }
                let text: String = f
                    .text
                    .lines()
                    .map(|l| {
                        if opens_instrument_attr(l) || !span_macros_in(l).is_empty() {
                            "// span removed".to_string()
                        } else {
                            l.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                ov.set(&f.rel, text);
                planted += 1;
            }
        }
        if planted == 0 {
            report.note_infra_failure(
                "tracing selftest: the base tree holds no span to remove, so the span-floor plant \
                 has nothing to take away"
                    .to_string(),
            );
        } else {
            report.push(prove_red(
                cx,
                self,
                "a tree whose spans all left clears the file floor and is still refused",
                &[ROW_SCAN_FLOOR, ROW_LEVEL],
                ov,
                &["span floor", "NOT a pass"],
            ));
        }

        // THE SCAN IS RECONCILED AGAINST THE TRACKED SET: one tracked file hidden from the walk
        // is refused, and the refusal NAMES it. No count, so no tree size turns it green.
        match coverage_plant(cx) {
            Ok((ov, rel)) => report.push(prove_red(
                cx,
                self,
                "a tracked file the crates walk did not read is refused by name",
                &[ROW_SCAN_FLOOR],
                ov,
                &["NOT scanned", rel.as_str()],
            )),
            Err(why) => report.note_infra_failure(format!("tracing selftest: {why}")),
        }

        // AN EMPTY WALK, on the RUN path. Every candidate file is removed from the overlay's view,
        // which is what a workspace restructure looks like from the scan's side.
        match cx.walk(&scan_spec()) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "an empty scan set is refused, not reported as a clean tree",
                    &[ROW_SCAN_FLOOR],
                    ov,
                    &["ZERO files"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "tracing selftest: the base tree's crates walk is unreadable ({e}), so the empty \
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Status;

    /// A temp tree of `SPAN_FLOOR + 3` `.rs` files under `crates/`, the first `SPAN_FLOOR` of them
    /// carrying a levelled span so the subject floor is met, and a context over it whose index is
    /// planted (a temp tree has no git index of its own) — every file but `untracked`.
    fn fixture(tag: &str, untracked: Option<&str>) -> (std::path::PathBuf, Ctx) {
        let root = std::env::temp_dir().join(format!(
            "xtask-tracing-coverage-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("a").join("src");
        let scratch = root.join(".fix").join("xtask");
        std::fs::create_dir_all(&src).expect("src dir creates");
        std::fs::create_dir_all(&scratch).expect("scratch dir creates");
        let mut index = Vec::new();
        for i in 0..SPAN_FLOOR + 3 {
            let text = if i < SPAN_FLOOR {
                "#[instrument(level = \"debug\")]\npub fn f() {}\n"
            } else {
                "pub fn f() {}\n"
            };
            std::fs::write(src.join(format!("f{i:05}.rs")), text).expect("seed");
            let rel = format!("crates/a/src/f{i:05}.rs");
            if Some(rel.as_str()) != untracked {
                index.push(rel);
            }
        }
        let mut ov = Overlay::new();
        ov.set_command(crate::ctx::INDEX_KEY, index.join("\n"));
        let cx = Ctx::at(&root, &scratch)
            .expect("ctx opens over the temp root")
            .with_overlay(ov);
        (root, cx)
    }

    fn coverage_row(cx: &Ctx) -> Row {
        TracingGate
            .run(cx)
            .rows
            .into_iter()
            .find(|r| r.id == ROW_SCAN_FLOOR)
            .expect("the scan-floor row is reported")
    }

    /// THE RED ARM: a tree whose walk reads exactly its index is green; the same tree with one
    /// span-free tracked file hidden from the walk is refused, and the refusal names the file.
    #[test]
    fn a_tracked_file_hidden_from_the_walk_is_refused_by_name() {
        let (root, cx) = fixture("hidden", None);
        let base = coverage_row(&cx);
        assert_eq!(base.status, Status::Pass, "{}", base.detail);
        let (ov, rel) = coverage_plant(&cx).expect("the coverage plant plants");
        assert_eq!(rel, format!("crates/a/src/f{:05}.rs", SPAN_FLOOR + 2));
        let planted = coverage_row(&cx.with_overlay(ov));
        assert_eq!(planted.status, Status::Fail, "{}", planted.detail);
        assert!(planted.detail.contains("NOT scanned"), "{}", planted.detail);
        assert!(planted.detail.contains(&rel), "{}", planted.detail);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE OTHER DIRECTION: a file the walk read that the index does not hold is refused by name.
    #[test]
    fn a_walked_file_nothing_tracks_is_refused_by_name() {
        let stray = "crates/a/src/f00000.rs";
        let (root, cx) = fixture("extra", Some(stray));
        let row = coverage_row(&cx);
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert!(row.detail.contains("NOT tracked"), "{}", row.detail);
        assert!(row.detail.contains(stray), "{}", row.detail);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The gate's whole selftest over the real tree: every case holds, the floor plant among them.
    #[test]
    fn the_tracing_selftest_holds_on_the_workspace() {
        let cx = Ctx::workspace().expect("workspace context");
        let report = TracingGate.selftest(&cx);
        if let Err(why) = crate::gates::verify_report(&TracingGate, &report) {
            panic!("tracing selftest failed:\n{}", why.join("\n"));
        }
    }
}
