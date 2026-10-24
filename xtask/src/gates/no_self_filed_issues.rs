//! `cargo xtask gate no-self-filed-issues` — THE REPOSITORY DOES NOT FILE ISSUES AGAINST ITSELF.
//! The successor to `scripts/no-self-filed-issues-lint.sh`, rule for rule.
//!
//! the removed `verify-deploy.yml` used to open an issue when a published release was broken, and it did so at
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

/// The other files that RUN: ModernCI's moves (`.ci/*.yaml`), the pre-push hook, `bin/`, and the
/// release/gate shell under `scripts/`. A filing call in any of them files an issue exactly as a
/// workflow does, so each is read with the same patterns. A root that resolves to nothing is an
/// error from the walk, never a clean pass.
const CI_DIR: &str = ".ci";
const HOOKS_DIR: &str = ".githooks";
const BIN_DIR: &str = "bin";
const SCRIPTS_DIR: &str = "scripts";

/// A discovery step that finds nothing passes everything. The floor is the workflow count, a `const`
/// with no environment override: the four reusable `plugin-*.yml` workflows the plugin repos call.
/// It was the shell's 5 while `promote.yml` (the busbar-release hop) stood; that file is deleted
/// (OWNER 2026-10-12, "ModernCI only": busbar's moves are judged from `.ci/*.yaml`), so 5 would
/// read the honest tree as broken discovery.
const DISCOVERY_FLOOR: usize = 4;

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

/// The verbs of `gh issue` that change an issue. Every one is a write; `list`, `view` and `status` are not.
const GH_ISSUE_WRITES: [&str; 12] = [
    "create", "edit", "close", "comment", "reopen", "delete", "transfer", "pin", "unpin", "lock",
    "unlock", "develop",
];

/// The `issues.<method>` prefixes of the REST client (`github.rest.issues.`, `octokit.issues.`)
/// that mutate. A read (`issues.get`, `issues.list`) is not a hit.
const ISSUE_METHOD_PREFIXES: [&str; 8] = [
    "create", "update", "add", "remove", "set", "delete", "lock", "unlock",
];

/// The GraphQL mutations that change an issue.
const ISSUE_MUTATIONS: [&str; 6] = [
    "createIssue",
    "updateIssue",
    "closeIssue",
    "reopenIssue",
    "deleteIssue",
    "transferIssue",
];

/// A request carrying one of these is not a GET, whatever it names: an explicit mutating method, or
/// a body flag (`gh api` and `curl` both turn a body into a POST).
fn request_mutates(segment: &str) -> bool {
    let words: Vec<&str> = segment
        .split(|c: char| c.is_whitespace() || c == '=' || c == '"' || c == '\'')
        .filter(|w| !w.is_empty())
        .collect();
    let mut previous = "";
    for w in &words {
        let upper = w.to_ascii_uppercase();
        let method = matches!(upper.as_str(), "POST" | "PATCH" | "PUT" | "DELETE");
        if method && matches!(previous, "-X" | "--method" | "--request") {
            return true;
        }
        // `-XPATCH`, the glued short form.
        if let Some(rest) = upper.strip_prefix("-X") {
            if matches!(rest, "POST" | "PATCH" | "PUT" | "DELETE") {
                return true;
            }
        }
        if matches!(
            *w,
            "-d" | "--data"
                | "--data-raw"
                | "--data-binary"
                | "--data-urlencode"
                | "--json"
                | "-F"
                | "--field"
                | "--raw-field"
                | "--input"
        ) {
            return true;
        }
        previous = *w;
    }
    false
}

/// A client command (`gh api`, `curl`, `wget`) whose request, up to the first pipe, reaches an
/// `/issues` endpoint with a mutating method or a body. Past a pipe the request is feeding
/// something else's stdin — the shell's bound.
fn mutating_issue_request(line: &str) -> bool {
    for client in [&["curl"][..], &["wget"][..]] {
        let mut from = 0;
        let chars: Vec<char> = line.chars().collect();
        while let Some(end) = match_words(&chars[from..].iter().collect::<String>(), client) {
            let tail: String = chars[from + end..].iter().collect();
            let segment = tail.split('|').next().unwrap_or("");
            if segment.contains("/issues") && request_mutates(segment) {
                return true;
            }
            from += end;
            if from >= chars.len() {
                break;
            }
        }
    }
    // The shell's own shapes: a POST however spelled reaching `/issues`, and ANY `gh api` call to
    // an `/issues` endpoint (a read of the queue is not what this repository's runners do either).
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

/// `<client>.issues.<write method>` or `.issues.<write method>(`: the REST client calls.
fn issue_client_write(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find("issues.") {
        let after = &rest[i + "issues.".len()..];
        if ISSUE_METHOD_PREFIXES.iter().any(|p| after.starts_with(p)) {
            return true;
        }
        rest = after;
    }
    false
}

/// A step that USES an action whose name says it writes issues (`peter-evans/create-issue-from-file`,
/// `actions-ecosystem/action-create-issue`, `JasonEtco/create-an-issue`, `dacbd/create-issue-action`).
fn uses_an_issue_action(line: &str) -> bool {
    let t: String = line.chars().filter(|c| *c != '"' && *c != '\'').collect();
    let Some(i) = t.find("uses:") else {
        return false;
    };
    let action = t[i + "uses:".len()..].trim().to_ascii_lowercase();
    let action = action.split('@').next().unwrap_or("");
    action.contains("issue")
}

/// (A) The issue-writing operations, one alternative per line of the shell's `ISSUE_WRITE_RE`, and
/// then the spellings the shell never listed: every mutating `gh issue` verb, every mutating REST
/// client method, a GraphQL issue mutation, a non-GET request to `/issues` (POST, PATCH, PUT,
/// DELETE, or any body), and a `uses:` of an issue action.
fn writes_an_issue(line: &str) -> bool {
    for verb in GH_ISSUE_WRITES {
        if match_words(line, &["gh", "issue", verb]).is_some() {
            return true;
        }
    }
    for verb in ["create", "edit", "delete"] {
        if match_words(line, &["gh", "label", verb]).is_some() {
            return true;
        }
    }
    if issue_client_write(line) {
        return true;
    }
    if ISSUE_MUTATIONS.iter().any(|m| line.contains(m)) {
        return true;
    }
    if uses_an_issue_action(line) {
        return true;
    }
    mutating_issue_request(line)
}

/// The text with quotes removed and the spaces around a `:` collapsed, so `"issues": "write"`,
/// `issues : write` and `{issues: write}` all read as `issues:write`.
fn flatten_yaml(line: &str) -> String {
    let unquoted: String = line.chars().filter(|c| *c != '"' && *c != '\'').collect();
    let mut out = String::new();
    let mut chars = unquoted.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            // Drop whitespace that sits against a colon on either side.
            if out.ends_with(':') {
                continue;
            }
            let mut ahead = chars.clone();
            while ahead.peek().is_some_and(|n| n.is_whitespace()) {
                ahead.next();
            }
            if ahead.peek() == Some(&':') {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// (B) A token scope that lets the run write issues: `issues: write`, or `permissions: write-all`
/// (every scope, this one included).
fn requests_issues_write(line: &str) -> bool {
    let flat = flatten_yaml(line);
    let mut rest = flat.as_str();
    while let Some(i) = rest.find("issues:") {
        let boundary = i == 0 || !rest[..i].ends_with(|c: char| c.is_alphanumeric() || c == '_');
        if boundary && rest[i + "issues:".len()..].starts_with("write") {
            return true;
        }
        rest = &rest[i + "issues:".len()..];
    }
    let mut rest = flat.as_str();
    while let Some(i) = rest.find("permissions:") {
        if rest[i + "permissions:".len()..].starts_with("write-all") {
            return true;
        }
        rest = &rest[i + "permissions:".len()..];
    }
    false
}

fn unreadable(what: &str, why: String) -> Verdict {
    Verdict::of(vec![
        Row::fail(ROW_FLOOR, what, why),
        Row::fail(
            ROW_WRITE,
            "the runner-file scan did not run",
            "broken discovery reports a clean tree".to_string(),
        ),
        Row::fail(
            ROW_PERM,
            "the runner-file scan did not run",
            "broken discovery reports a clean tree".to_string(),
        ),
    ])
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
        let workflows = match cx.walk(&WalkSpec::new([WF_DIR])) {
            Ok(f) => f,
            Err(e) => return unreadable("the workflow directory could not be read", e.to_string()),
        };
        let workflows: Vec<_> = workflows
            .into_iter()
            .filter(|f| {
                let rel = f.rel_str();
                let Some(base) = rel.strip_prefix(&format!("{WF_DIR}/")) else {
                    return false;
                };
                !base.contains('/') && (base.ends_with(".yml") || base.ends_with(".yaml"))
            })
            .collect();
        let mut files = workflows;
        let floor_count = files.len();
        let others = [
            WalkSpec::new([CI_DIR]).ext("yaml"),
            WalkSpec::new([CI_DIR]).ext("yml").allow_empty(),
            WalkSpec::new([HOOKS_DIR]),
            WalkSpec::new([BIN_DIR]),
            WalkSpec::new([SCRIPTS_DIR]).ext("sh"),
        ];
        for spec in &others {
            match cx.walk(spec) {
                Ok(more) => files.extend(more),
                Err(e) => return unreadable("a runner file set could not be read", e.to_string()),
            }
        }

        if floor_count < DISCOVERY_FLOOR {
            return Verdict::of(vec![
                Row::fail(
                    ROW_FLOOR,
                    "workflow discovery found too few files",
                    format!(
                        "found only {} workflow file(s) (floor {DISCOVERY_FLOOR}). Discovery is \
                         broken, and broken discovery reports a clean tree.",
                        floor_count
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

        // THE RUNNER FILES BEYOND THE WORKFLOWS. A filing call in a ModernCI move, the pre-push
        // hook, `bin/` or a gate script files an issue exactly as a workflow does.
        for (path, body) in [
            (
                format!("{CI_DIR}/planted-files-issue.yaml"),
                format!("name: files\nsteps:\n  - run: {filing} --title b\n"),
            ),
            (
                format!("{HOOKS_DIR}/planted-files-issue"),
                format!("#!/usr/bin/env bash\n{filing} --title b\n"),
            ),
            (
                format!("{BIN_DIR}/planted-files-issue"),
                format!("#!/usr/bin/env bash\n{filing} --title b\n"),
            ),
            (
                format!("{SCRIPTS_DIR}/planted-files-issue.sh"),
                format!("#!/usr/bin/env bash\n{filing} --title b\n"),
            ),
        ] {
            report.push(prove_red(
                cx,
                self,
                format!("a filing call in `{path}` is flagged"),
                &[ROW_WRITE],
                planted_at(&path, &body),
                &["planted-files-issue"],
            ));
        }

        // THE SPELLINGS THE FIRST PATTERN LIST NEVER HAD.
        let patch = format!(
            "curl -X {} -H \"A: t\" https://api.github.com/repos/o/r/issues/1",
            "PATCH"
        );
        let create_issue = format!("{}{}", "github.rest.issues.", "create({})");
        let graphql = format!(
            "gh api graphql -f query='mutation {{ {}(input: {{}}) {{ id }} }}'",
            "createIssue"
        );
        let lock = format!("gh {} {} 12", "issue", "lock");
        let body_post = "gh api repos/o/r/issues -f title=b".to_string();
        let action = format!("uses: peter-evans/{}-from-file@v5", "create-issue");
        for (what, step) in [
            ("a PATCH to an issues endpoint", patch),
            ("a REST client issues write", create_issue),
            ("a GraphQL issue mutation", graphql),
            ("a `gh issue` verb outside create/edit", lock),
            ("a body-carrying gh api call to issues", body_post),
            ("a `uses:` of an issue action", action),
        ] {
            let yaml = if step.starts_with("uses:") {
                format!("name: x\njobs:\n  a:\n    steps:\n      - {step}\n")
            } else {
                format!("name: x\njobs:\n  a:\n    steps:\n      - run: {step}\n")
            };
            report.push(prove_red(
                cx,
                self,
                format!("{what} is flagged"),
                &[ROW_WRITE],
                planted(&yaml),
                &["planted-files-issue.yml"],
            ));
        }

        for (what, perms) in [
            ("`permissions: write-all`", "permissions: write-all\n"),
            (
                "a flow-mapping `issues: write`",
                "permissions: { issues: write }\n",
            ),
            (
                "a quoted `\"issues\": \"write\"`",
                "permissions:\n  \"issues\": \"write\"\n",
            ),
        ] {
            report.push(prove_red(
                cx,
                self,
                format!("{what} is the issues scope"),
                &[ROW_PERM],
                planted(&format!(
                    "name: grants\n{perms}jobs:\n  a:\n    steps:\n      - run: echo hi\n"
                )),
                &["planted-files-issue.yml"],
            ));
        }

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
    planted_at(&format!("{WF_DIR}/planted-files-issue.yml"), body)
}

fn planted_at(path: &str, body: &str) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(path, body);
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
