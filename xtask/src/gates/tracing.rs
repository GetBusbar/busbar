//! `cargo xtask gate tracing` — EVERY SPAN IS BOUND TO AN EXPLICIT LEVEL, SET IN ONE PLACE. The
//! successor to `scripts/tracing-lint.sh`, rule for rule, plus the hand-written spans it never read.
//!
//! TWO KINDS OF SUBJECT (ARCHITECT RULING D1 2026-10-06, option (b)). A span is opened either by an
//! `#[instrument]` attribute or by hand, with a `span!` macro. Both are subjects of the one rule and
//! both count toward the subject floor. A hand-written span names its level as the `span!` macro's
//! level argument, and that argument must be `observability::HOTPATH_LEVEL` (by any path): a
//! `debug_span!`/`info_span!`/… sets its level through the macro's name, and a `span!` handed
//! `Level::DEBUG` hard-codes it, and either is a level picked somewhere other than the one place.
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

/// THE SUBJECT FLOOR (item 228). The file floor above proves the walk opened the crates; it says
/// nothing about whether the thing this gate judges is still there. "Every span has a level" is as
/// vacuous over zero SPANS as over zero files, and the files-to-spans ratio is ~150:1, so every span
/// could leave the tree with the file floor untouched. Armed at 5 (arrival.rs 3, ingress/mod.rs 2);
/// since ARCHITECT RULING D1 2026-10-06 a hand-written `span!` counts as a subject too, and the tree
/// holds 7 (the plane's arrival reader's five `#[instrument]`s, the request span the composition
/// root opens and the kernel's degraded-attempt span). Like the file floor it has no override, and
/// lowering it is a reviewable source edit that says which span went where.
const SPAN_FLOOR: usize = 5;

/// The `tracing` macros that open a span by hand. `span!` takes its level as an argument; every
/// other one names its level in the macro's own name.
const SPAN_MACROS: &[&str] = &[
    "span",
    "trace_span",
    "debug_span",
    "info_span",
    "warn_span",
    "error_span",
];

/// The one place a hand-written span's level may come from: the hot-path level constant, by any
/// path (`HOTPATH_LEVEL`, `observability::HOTPATH_LEVEL`, `busbar_kernel::observability::…`).
const ONE_PLACE: &str = "HOTPATH_LEVEL";

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

/// A hand-written span whose level is not the one place's: the macro that names its own level, or
/// the `span!` level argument that is not [`ONE_PLACE`].
fn finding_hand_level(rel: &str, line: usize, how: &str) -> String {
    format!(
        "{rel}:{line}: hand-written span {how} — open it with `tracing::span!(observability::\
         HOTPATH_LEVEL, …)` so its level is set in the one place"
    )
}

fn finding_hand_unclosed(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: hand-written span macro never closes — its parens do not balance before the \
         end of the file, so this span AND EVERY LATER SPAN IN THIS FILE went unchecked"
    )
}

const CLEAN: &str = "the scan cleared its floor and named nothing";

/// One file's findings: the level-less spans and the attribute that never closed.
#[derive(Debug, Default)]
struct Findings {
    /// How many spans the scan read, `#[instrument]` and hand-written — the subject count
    /// [`SPAN_FLOOR`] judges.
    spans: usize,
    /// How many of [`Self::spans`] were hand-written.
    hand: usize,
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

/// Where a hand-written span macro is invoked in BLANKED code, at or after `from`: the char index
/// of its opening paren and the macro's name. Only `tracing`'s own macros count: a bare name (the
/// macro imported) or one reached through `tracing::`; `other::span!` and `my_span!` are not spans.
fn next_span_macro(code: &[char], from: usize) -> Option<(usize, &'static str)> {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut i = from;
    while i + 5 <= code.len() {
        if code[i..i + 5] != ['s', 'p', 'a', 'n', '!'] {
            i += 1;
            continue;
        }
        let bang = i + 4;
        let mut start = i;
        while start > 0 && ident(code[start - 1]) {
            start -= 1;
        }
        let name: String = code[start..bang].iter().collect();
        let Some(name) = SPAN_MACROS.iter().copied().find(|m| *m == name) else {
            i += 5;
            continue;
        };
        // What stands before the name: nothing that continues a path, or `tracing::`.
        let before: String = code[..start].iter().collect();
        let before = before.trim_end();
        let pathed = before.ends_with("::");
        let tracing_path = before
            .strip_suffix("::")
            .map(str::trim_end)
            .is_some_and(|p| {
                p.strip_suffix("tracing")
                    .is_some_and(|q| !q.ends_with(|c: char| ident(c)))
            });
        if pathed && !tracing_path {
            i += 5;
            continue;
        }
        let mut open = bang + 1;
        while open < code.len() && code[open].is_whitespace() {
            open += 1;
        }
        if code.get(open) == Some(&'(') {
            return Some((open, name));
        }
        i += 5;
    }
    None
}

/// The top-level arguments of a balanced `( … )` group in blanked code starting at its `(`.
fn top_level_args(group: &str) -> Vec<String> {
    let mut depth = 0usize;
    let mut args: Vec<String> = vec![String::new()];
    for c in group.chars() {
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
    args
}

/// A complete hand-written span macro's verdict: `None` when its level is the one place's, else how
/// it is set instead.
fn hand_span_level(name: &str, group: &str) -> Option<String> {
    if name != "span" {
        return Some(format!("`{name}!` sets its level through the macro's name"));
    }
    let args = top_level_args(group);
    let level = args
        .iter()
        .map(|a| a.trim())
        .find(|a| !a.starts_with("target:") && !a.starts_with("parent:"))
        .unwrap_or("");
    let is_path = !level.is_empty()
        && level
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c.is_whitespace());
    let last = level.rsplit("::").next().unwrap_or("").trim();
    if is_path && last == ONE_PLACE {
        None
    } else {
        Some(format!(
            "`span!` hard-codes its level `{}`",
            level.split_whitespace().collect::<Vec<_>>().join(" ")
        ))
    }
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
    // A hand-written span macro still open at the end of a line: its line, its name and its
    // blanked text from its `(`.
    let mut hand: Option<(usize, &'static str, String)> = None;

    for (i, line) in text.lines().enumerate() {
        let is_comment = line.trim_start().starts_with("//");
        // A paren inside a STRING LITERAL or a COMMENT is text, not structure. The state is carried
        // so a `fields(…)` list interrupted by a multi-line literal is still read as one attribute.
        let nostr = scan::blank_code(line, &mut lex);
        scan_hand_spans(rel, i + 1, &nostr, &mut hand, &mut out);

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
    if let Some((line, _, _)) = hand {
        out.unclosed.push(finding_hand_unclosed(rel, line));
    }
    out
}

/// One blanked line's hand-written span macros: the one carried in from earlier lines first, then
/// each one this line opens, every complete one judged and counted.
fn scan_hand_spans(
    rel: &str,
    line_no: usize,
    nostr: &str,
    open: &mut Option<(usize, &'static str, String)>,
    out: &mut Findings,
) {
    if open.is_none() && !nostr.contains("span!") {
        return;
    }
    let chars: Vec<char> = nostr.chars().collect();
    let mut at = 0usize;
    loop {
        let (start, name, mut group, from) = match open.take() {
            Some((start, name, mut group)) => {
                group.push('\n');
                (start, name, group, 0)
            }
            None => match next_span_macro(&chars, at) {
                Some((paren, name)) => (line_no, name, String::new(), paren),
                None => return,
            },
        };
        let mut depth = group.matches('(').count() - group.matches(')').count();
        let mut closed_at = None;
        for (k, c) in chars.iter().enumerate().skip(from) {
            group.push(*c);
            match c {
                '(' => depth += 1,
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closed_at = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(k) = closed_at else {
            *open = Some((start, name, group));
            return;
        };
        out.spans += 1;
        out.hand += 1;
        if let Some(how) = hand_span_level(name, &group) {
            out.level.push(finding_hand_level(rel, start, &how));
        }
        at = k + 1;
    }
}

/// The finding rows, built from offender lists — the ONE constructor `run` and the legacy
/// translator both call.
fn row_level(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_LEVEL,
            "every #[instrument] carries an explicit level= and every hand-written span the \
             hot-path level",
            CLEAN,
        );
    }
    Row::fail(
        ROW_LEVEL,
        "a span's level is not set in the one place",
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
        let mut spans = 0usize;
        let mut hand = 0usize;
        for f in &files {
            let found = scan_file(&f.rel_str(), &f.text);
            spans += found.spans;
            hand += found.hand;
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
                        "{} files walked but only {spans} span(s) read ({hand} hand-written), below \
                         the span floor of {SPAN_FLOOR}. A span that left the tree took the subject \
                         with it: the floor is never lowered to meet the tree.",
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
                "the crates walk cleared its floor",
                format!(
                    "{} files, {spans} span(s), {hand} of them hand-written (floors {SCAN_FLOOR} / \
                     {SPAN_FLOOR}); {CLEAN}",
                    files.len()
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

        // ARCHITECT RULING D1 2026-10-06: A HAND-WRITTEN SPAN WITH A HARD-CODED LEVEL IS REFUSED.
        // The two kernel spans this ruling deleted were `debug_span!`s; a `span!` handed a literal
        // Level is the same level picked outside the one place, and so is one whose level argument
        // sits on the next line. The hot-path level by any path (and behind a `target:`) is clean;
        // a `debug_span!` inside a string, another crate's `span!` and a macro whose name merely
        // ends in `span` are not spans. Exactly three findings, and which three is the point.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_hand_spans.rs",
            "pub fn hard_coded() {\n\
             \x20   let a = tracing::debug_span!(\"forward\", request_id = tracing::field::Empty);\n\
             \x20   let b = tracing::span!(tracing::Level::DEBUG, \"forward_once\", lane = 1);\n\
             \x20   let c = span!(\n\
             \x20       Level::INFO,\n\
             \x20       \"multi_line\"\n\
             \x20   );\n\
             \x20   let d = tracing::span!(HOTPATH_LEVEL, \"one_place\");\n\
             \x20   let e = ::tracing::span!(target: \"t\",\x20\
             crate::observability::HOTPATH_LEVEL, \"x\");\n\
             \x20   let f = \"tracing::debug_span!(\\\"in_a_string\\\")\";\n\
             \x20   let g = other::span!(Level::DEBUG, \"not_tracing\");\n\
             \x20   let h = my_span!(Level::DEBUG);\n\
             }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a hand-written span with a hard-coded level is refused",
            &[ROW_LEVEL],
            ov,
            &[
                "3 finding(s)",
                "planted_hand_spans.rs:2: hand-written span `debug_span!`",
                "planted_hand_spans.rs:3: hand-written span `span!` hard-codes its level \
                 `tracing::Level::DEBUG`",
                "planted_hand_spans.rs:4: hand-written span `span!` hard-codes its level \
                 `Level::INFO`",
            ],
        ));

        // ITEM 228: THE SUBJECT FLOOR. Every production span leaves the tree (an `#[instrument]`
        // line becomes a comment, a hand-written `span!` stops being one); the file walk still
        // clears 130, and the scan must still refuse to call the empty subject clean.
        let mut ov = Overlay::new();
        let mut planted = 0usize;
        if let Ok(files) = cx.walk(
            &WalkSpec::new([SCAN_ROOT])
                .ext("rs")
                .exclude([EXCLUDE_TESTS_DIR]),
        ) {
            for f in &files {
                if !f.text.lines().any(opens_instrument_attr)
                    && scan_file(&f.rel_str(), &f.text).hand == 0
                {
                    continue;
                }
                let text: String = f
                    .text
                    .lines()
                    .map(|l| {
                        if opens_instrument_attr(l) {
                            "// span removed".to_string()
                        } else {
                            l.replace("span!", "spam!")
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
                "tracing selftest: the base tree holds no #[instrument] span to remove, so the \
                 span-floor plant has nothing to take away"
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
