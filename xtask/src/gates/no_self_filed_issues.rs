//! `cargo xtask gate no-self-filed-issues` — THE REPOSITORY DOES NOT FILE ISSUES AGAINST ITSELF.
//! The successor to `scripts/no-self-filed-issues-lint.sh`, rule for rule.
//!
//! `verify-deploy.yml` used to open an issue when a published release was broken, and it did so at
//! least once. Three things were wrong with it. A self-filed issue is INDISTINGUISHABLE from a
//! user's: it lands in the queue a human triages wearing the same clothes as a real report, on the
//! one channel whose whole value is signal. It LEFT THE RUN GREEN — the filing step began `set +e`
//! and ended on an `echo`, so a broken release produced a green check and an issue nobody was paged
//! by. And it created STATE THAT COULD GO STALE: a long-lived mutable object outside the run that
//! produced it needs a second job to close it, a label to deduplicate it, and a rule about which
//! cron is allowed to have an opinion — all of which existed only because the notification was an
//! issue rather than a red square.
//!
//! Three rows:
//!
//! * `no-self-filed-issues:discovery-floor` — the workflow set was found. A discovery step that
//!   finds nothing passes everything.
//! * `no-self-filed-issues:no-issue-write` — no workflow invokes an issue-writing operation.
//! * `no-self-filed-issues:no-issues-permission` — no workflow requests `issues: write`. This is
//!   the belt to the braces above: even if a filing call is smuggled past the pattern list, without
//!   the token scope it fails on the API rather than quietly succeeding.
//!
//! COMMENTS ARE STRIPPED BEFORE MATCHING, so the workflows may — and do — explain in prose why the
//! filing was removed without the explanation tripping the check that removed it. Naive on purpose
//! about `#` inside quotes: a false POSITIVE here is a loud, fixable lint failure, where tolerating
//! comments would be a false NEGATIVE, and this rule's whole point is failing closed.
//!
//! A SHELL CONTINUATION IS ONE COMMAND, so it is joined into one line before matching. The matcher
//! was written as if a command could not span two lines, and the ordinary block-scalar form put the
//! verb on one line and the `/issues` endpoint on the next and scanned CLEAN. Claim (B) is no
//! backstop against that either: a call carrying a PAT from `secrets.*` never consults the workflow
//! `permissions:` block at all.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;

pub const ROW_FLOOR: &str = "no-self-filed-issues:discovery-floor";
pub const ROW_WRITE: &str = "no-self-filed-issues:no-issue-write";
pub const ROW_PERM: &str = "no-self-filed-issues:no-issues-permission";

const WF_DIR: &str = ".github/workflows";

/// A discovery step that finds nothing passes everything. Twenty-odd workflows today; the floor is
/// the shell's, a `const` with no environment override.
const DISCOVERY_FLOOR: usize = 5;

const CLEAN: &str = "the scan cleared its floor and named nothing";

/// The offender unit is the FILE, not the line: the shell reports `FAIL: <path>` per claim and its
/// line numbers are indices into a temporary stripped-and-joined copy, which no second
/// implementation could reproduce and which names nothing a reader can open.
fn row_write(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_WRITE,
            "no workflow files or mutates a GitHub issue",
            CLEAN,
        );
    }
    Row::fail(
        ROW_WRITE,
        "a workflow files or mutates a GitHub issue",
        format!(
            "{} workflow(s): {} — make the check RED instead: write the findings to \
             $GITHUB_STEP_SUMMARY, emit ::error:: annotations, and exit 1",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

fn row_perm(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(ROW_PERM, "no workflow requests `issues: write`", CLEAN);
    }
    Row::fail(
        ROW_PERM,
        "a workflow requests `issues: write`",
        format!(
            "{} workflow(s): {} — without the token scope a smuggled filing call fails on the API \
             rather than quietly succeeding",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

/// Strip full-line and trailing `#` comments, then JOIN backslash continuations — in that order,
/// which is the order that matters: joining first would resurrect a comment whose prose happened to
/// end in a backslash, and the shell's own fixture pins exactly that.
fn strip_and_join(text: &str) -> String {
    let mut kept: Vec<String> = Vec::new();
    for raw in text.lines() {
        let t = raw.trim_start();
        if t.starts_with('#') {
            kept.push(String::new());
            continue;
        }
        // ` #<no quote or apostrophe to the end of line>` is a trailing comment.
        kept.push(strip_trailing_comment(raw));
    }
    let mut out = String::new();
    let mut pending = String::new();
    for line in kept {
        let joined = match line.strip_suffix('\\') {
            Some(head) => {
                pending.push_str(head);
                continue;
            }
            None => line,
        };
        if pending.is_empty() {
            out.push_str(&joined);
        } else {
            out.push_str(&pending);
            out.push_str(joined.trim_start());
            pending.clear();
        }
        out.push('\n');
    }
    if !pending.is_empty() {
        out.push_str(&pending);
        out.push('\n');
    }
    out
}

/// The shell's `sed -e 's/[[:space:]]#[^"'"'"']*$//'`: a `#` preceded by whitespace whose tail
/// carries neither a `"` nor a `'` is prose.
fn strip_trailing_comment(line: &str) -> String {
    let bytes: Vec<char> = line.chars().collect();
    for i in 1..bytes.len() {
        if bytes[i] != '#' || !bytes[i - 1].is_whitespace() {
            continue;
        }
        if bytes[i..].iter().any(|c| *c == '"' || *c == '\'') {
            continue;
        }
        return bytes[..i - 1].iter().collect();
    }
    line.to_string()
}

/// Whitespace between tokens is "one or more", never a single literal space: `gh  issue  create`
/// is the same command as `gh issue create` and must read the same way. Returns the byte offset
/// just past the match, so a caller can keep scanning the rest of the line.
fn match_words(hay: &str, words: &[&str]) -> Option<usize> {
    let chars: Vec<char> = hay.chars().collect();
    'start: for start in 0..chars.len() {
        // The first word must begin at an identifier boundary, so `foogh issue create` is not a hit.
        if start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
            continue;
        }
        let mut i = start;
        for (w, word) in words.iter().enumerate() {
            if w > 0 {
                let before = i;
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }
                if i == before {
                    continue 'start;
                }
            }
            let wc: Vec<char> = word.chars().collect();
            if i + wc.len() > chars.len() || chars[i..i + wc.len()] != wc[..] {
                continue 'start;
            }
            i += wc.len();
        }
        return Some(i);
    }
    None
}

/// (A) The issue-writing operations, one alternative per line of the shell's `ISSUE_WRITE_RE`.
fn writes_an_issue(line: &str) -> bool {
    for verb in ["create", "edit", "close", "comment", "reopen"] {
        if match_words(line, &["gh", "issue", verb]).is_some() {
            return true;
        }
    }
    if match_words(line, &["gh", "label", "create"]).is_some() {
        return true;
    }
    for call in [
        "issues.create",
        "issues.update",
        "issues.createComment",
        "issues.addLabels",
    ] {
        if line.contains(call) {
            return true;
        }
    }
    // A POST — however it is spelled — reaching an `/issues` endpoint, with no `|` between the two.
    // The pipe bound is the shell's: past a pipe the POST is feeding something else's stdin.
    let posts: [&[&str]; 3] = [&["POST"], &["--method", "POST"], &["-X", "POST"]];
    for spelling in posts {
        if let Some(end) = match_words(line, spelling) {
            let tail: String = line.chars().skip(end).collect();
            if let Some(i) = tail.find("/issues") {
                if !tail[..i].contains('|') {
                    return true;
                }
            }
        }
    }
    if let Some(end) = match_words(line, &["gh", "api"]) {
        let tail: String = line.chars().skip(end).collect();
        if let Some(i) = tail.find("/issues") {
            if !tail[..i].contains('|') {
                return true;
            }
        }
    }
    false
}

/// (B) `issues:` followed by optional whitespace and `write`.
fn requests_issues_write(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find("issues:") {
        let tail = rest[i + "issues:".len()..].trim_start();
        if tail.starts_with("write") {
            return true;
        }
        rest = &rest[i + "issues:".len()..];
    }
    false
}

pub struct NoSelfFiledIssuesGate;

impl Gate for NoSelfFiledIssuesGate {
    fn name(&self) -> &'static str {
        "no-self-filed-issues"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_FLOOR.to_string(),
            ROW_WRITE.to_string(),
            ROW_PERM.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // `find "$WF_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \)`. The walk has
        // no depth control, so the depth is imposed here: a path with a further `/` under the
        // directory is a nested file the shell never saw.
        let files = match cx.walk(&WalkSpec::new([WF_DIR])) {
            Ok(f) => f,
            Err(e) => {
                return Verdict::of(vec![
                    Row::fail(
                        ROW_FLOOR,
                        "the workflow directory could not be read",
                        e.to_string(),
                    ),
                    Row::fail(
                        ROW_WRITE,
                        "the workflow scan did not run",
                        "broken discovery reports a clean tree".to_string(),
                    ),
                    Row::fail(
                        ROW_PERM,
                        "the workflow scan did not run",
                        "broken discovery reports a clean tree".to_string(),
                    ),
                ]);
            }
        };
        let files: Vec<_> = files
            .into_iter()
            .filter(|f| {
                let rel = f.rel_str();
                let Some(base) = rel.strip_prefix(&format!("{WF_DIR}/")) else {
                    return false;
                };
                !base.contains('/') && (base.ends_with(".yml") || base.ends_with(".yaml"))
            })
            .collect();

        if files.len() < DISCOVERY_FLOOR {
            return Verdict::of(vec![
                Row::fail(
                    ROW_FLOOR,
                    "workflow discovery found too few files",
                    format!(
                        "found only {} workflow file(s) (floor {DISCOVERY_FLOOR}). Discovery is \
                         broken, and broken discovery reports a clean tree.",
                        files.len()
                    ),
                ),
                Row::fail(
                    ROW_WRITE,
                    "the workflow scan did not run",
                    "broken discovery reports a clean tree".to_string(),
                ),
                Row::fail(
                    ROW_PERM,
                    "the workflow scan did not run",
                    "broken discovery reports a clean tree".to_string(),
                ),
            ]);
        }

        let mut writes = Vec::new();
        let mut perms = Vec::new();
        for f in &files {
            let text = strip_and_join(&f.text);
            if text.lines().any(writes_an_issue) {
                writes.push(f.rel_str());
            }
            if text.lines().any(requests_issues_write) {
                perms.push(f.rel_str());
            }
        }
        writes.sort();
        perms.sort();

        Verdict::of(vec![
            Row::pass(ROW_FLOOR, "workflow discovery cleared its floor", CLEAN),
            row_write(&writes),
            row_perm(&perms),
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
            "no workflow files an issue or asks for the scope to",
            &[ROW_FLOOR, ROW_WRITE, ROW_PERM],
        ));

        // The verb is BUILT rather than written, so this gate's own source does not carry the
        // needle it hunts.
        let filing = format!("{} {} {}", "gh", "issue", "create");

        report.push(prove_red(
            cx,
            self,
            "a workflow that files an issue is flagged",
            &[ROW_WRITE],
            planted(&format!(
                "name: files\njobs:\n  alert:\n    steps:\n      - run: {filing} --title \"broken\"\n"
            )),
            &["planted-files-issue.yml"],
        ));

        // `gh  issue  create` is the same command. Whitespace between tokens is one-or-more.
        report.push(prove_red(
            cx,
            self,
            "extra whitespace between the tokens is the same command",
            &[ROW_WRITE],
            planted(&format!(
                "name: spaced\njobs:\n  alert:\n    steps:\n      - run: {} \n",
                filing.replace(' ', "  ")
            )),
            &["planted-files-issue.yml"],
        ));

        // THE INSTRUMENT FOR THE FIX THIS PORT INHERITS. A shell continuation is ONE command: the
        // verb on one line and the endpoint on the next scanned clean, and claim (B) is no
        // backstop because a PAT from `secrets.*` never consults `permissions:` at all.
        report.push(prove_red(
            cx,
            self,
            "a filing call continued over two lines is one command",
            &[ROW_WRITE],
            planted(
                "name: continued\npermissions:\n  contents: read\njobs:\n  alert:\n    steps:\n\
                 \x20     - run: |\n          curl -X POST -H \"Authorization: token $T\" \\\n\
                 \x20           \"https://api.github.com/repos/$R/issues\" -d '{\"title\":\"b\"}'\n",
            ),
            &["planted-files-issue.yml"],
        ));

        report.push(prove_red(
            cx,
            self,
            "a workflow that asks for the issues scope is flagged",
            &[ROW_PERM],
            planted(
                "name: grants\npermissions:\n  contents: read\n  issues: write\njobs:\n  alert:\n\
                 \x20   steps:\n      - run: echo hi\n",
            ),
            &["planted-files-issue.yml"],
        ));

        // A COMMENT-ONLY MENTION IS PROSE — the workflows explain the ban, and a lint its own
        // explanation fails is a lint people learn to skip. And a continuation INSIDE prose is
        // still prose: joining lines must not resurrect a comment.
        let ov = planted(&format!(
            "name: comment-only\n# it used to run `{filing}` and request `issues: write`, and it\n\
             # used to curl -X POST \\\n#   against the /issues endpoint. It does not any more.\n\
             permissions:\n  contents: read   # no issues: write here either\njobs:\n  alert:\n\
             \x20   steps:\n      - run: exit 1   # never `{filing}`\n"
        ));
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "prose about the ban, continued or not, does not trip the ban",
            &[ROW_WRITE, ROW_PERM],
        ));

        // THE FLOOR, on the RUN path. Discovery that finds nothing passes everything.
        match cx.walk(&WalkSpec::new([WF_DIR])) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a workflow set below its floor is refused, not reported as a clean tree",
                    &[ROW_FLOOR],
                    ov,
                    &["floor"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "no-self-filed-issues selftest: the workflow directory is unreadable ({e}), so the \
                 floor plant has nothing to empty"
            )),
        }

        report
    }
}

fn planted(body: &str) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(format!("{WF_DIR}/planted-files-issue.yml"), body);
    ov
}

/// Drop the SGR escapes the shell's `red()`/`grn()` wrap their lines in. A translator that read
/// them as part of the path would find no offender at all and report the tree clean.
fn decolour(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for c in chars.by_ref() {
            if c == 'm' {
                break;
            }
        }
    }
    out
}

/// Read the shell gate's own output into the same three rows. Its verdicts are per file and per
/// claim; nothing here re-scans the tree.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut writes = Vec::new();
    let mut perms = Vec::new();
    let mut floor_broken = None;
    let mut ran = false;

    for raw in run.lines() {
        let t = decolour(raw);
        let t = t.trim();
        if t.contains("(floor 5)") || t.contains("Discovery is broken") {
            floor_broken = Some(t.to_string());
            continue;
        }
        if let Some(rest) = t.strip_prefix("FAIL: ") {
            if let Some(path) = rest.strip_suffix(" files or mutates a GitHub issue") {
                writes.push(path.to_string());
                ran = true;
            } else if let Some(path) = rest.strip_suffix(" requests `issues: write`") {
                perms.push(path.to_string());
                ran = true;
            } else {
                return Err(format!(
                    "the legacy translator does not recognise the finding `{t}`. An unclassified \
                     finding dropped on the floor is how a rewrite is proven faithful to a script \
                     nobody read."
                ));
            }
            continue;
        }
        if t.contains("workflow file(s) clean") || t.contains("workflow file(s) file issues") {
            ran = true;
        }
    }

    if floor_broken.is_none() && !ran {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no verdict line, no \
             findings. Silence read as a clean tree is the exact defect this gate exists for.",
            run.argv.join(" ")
        ));
    }

    if let Some(why) = floor_broken {
        return Ok(vec![
            Row::fail(ROW_FLOOR, "workflow discovery found too few files", why),
            Row::fail(
                ROW_WRITE,
                "the workflow scan did not run",
                "broken discovery reports a clean tree".to_string(),
            ),
            Row::fail(
                ROW_PERM,
                "the workflow scan did not run",
                "broken discovery reports a clean tree".to_string(),
            ),
        ]);
    }

    writes.sort();
    perms.sort();
    Ok(vec![
        Row::pass(ROW_FLOOR, "workflow discovery cleared its floor", CLEAN),
        row_write(&writes),
        row_perm(&perms),
    ])
}
