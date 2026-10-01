//! THE WORKFLOW-RULES GATE. The rules that outlived the release workflows.
//!
//! This gate was `release-order`: "nothing may be tagged until it has been verified from the
//! consumer side", enforced over the SHAPE OF busbar's own release workflows (`release.yml`,
//! `release-stage.yml`, `docker.yml`, `verify-deploy.yml`). Those workflows are deleted: busbar has
//! one pipeline workflow, `promote.yml`, and the release engine lives in busbar-release. The rules
//! that were ABOUT those files (the staged-verification graph, the draft flag, the red-branch gate,
//! the first gate's run list) went with them, rows and code together.
//!
//! Four rules were never about one file. They are bans over EVERY workflow and composite action
//! that remains (`promote.yml` and the reusable `plugin-*.yml` workflows the plugin repos call),
//! and each has a specific observed failure behind it:
//!
//! * **R1 — no workflow is triggered by a version tag.** A tag is the OUTPUT of a verified release,
//!   never its trigger.
//! * **R11 — no workflow pushes a commit to a release branch.** `qa` and `main` move only by a
//!   fast-forward of a green sha.
//! * **R14 — every third-party action runs from a commit sha** with its tag as a trailing comment,
//!   because an action that can be force-moved under a name we already trust runs with our tokens.
//! * **R15 — every attestation verify names the workflow that signed**, not just the repository.
//!
//! **The parser stays deliberately small, and here that is a correctness argument rather than a
//! dependency one.** The rules are assertions about what a human WROTE (a trailing `# tag` comment
//! on a pin; a `v*` trigger in either of YAML's two sequence spellings), and a general YAML parser
//! normalises exactly that away. This crate also carries no regex dependency, so every pattern is
//! spelled out as explicit scanning, each with its own unit test.
//!
//! **The structural mutations are the selftest.** Each mutation is a real regression written the
//! way it would actually arrive, applied to an overlay of a real workflow, and the gate must go RED
//! naming that rule. A mutation that CHANGES NOTHING is itself a failure: the anchor it edits has
//! moved and the rule is no longer being proven.

use std::collections::BTreeSet;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

const WORKFLOWS: &str = ".github/workflows";
/// composite action's `runs.steps` has exactly the same `uses:` shape and the same third-party-code
/// exposure, and a repo that grows one is a repo where "every `uses:` in the tree is a sha" would
/// otherwise quietly stop being true the day the first `action.yml` lands.
const ACTIONS_DIR: &str = ".github/actions";

/// The floor under the workflow discovery. A scan that finds nothing satisfies every ban, and a
/// tree with fewer workflows than this has lost its subject, not been cleaned: `promote.yml` plus
/// the four reusable `plugin-*.yml` workflows.
const MIN_WORKFLOWS: usize = 5;

/// The rule ids, which are also the ledger row ids.
const RULES: &[&str] = &["R1", "R11", "R14", "R15"];

// -------------------------------------------------------------------------------------------
// THE SMALL PARSER
// -------------------------------------------------------------------------------------------

/// Blank out comment lines. Every rule here is about CODE; these workflows are heavily commented
/// and a rule that matched its own prose would be unfixable without deleting the explanation.
pub fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| {
            if l.trim_start().starts_with('#') {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text of a top-level `name:` block — its header line plus every indented line under it.
pub fn top_level_block(text: &str, name: &str) -> String {
    let header = format!("{name}:");
    let mut out: Vec<&str> = Vec::new();
    let mut grab = false;
    for line in text.lines() {
        if line.starts_with(&header) {
            grab = true;
            out.push(line);
            continue;
        }
        if grab {
            if line.trim().is_empty() || line.starts_with(' ') || line.starts_with('\t') {
                out.push(line);
            } else {
                break;
            }
        }
    }
    out.join("\n")
}

/// The action reference of a `uses:` line and its trailing tag comment, in either of YAML's two
/// spellings of a step:
///
/// * block: `^\s*(?:-\s+)?uses:\s*(\S+)\s*(#.*)?$`;
/// * flow: `- { uses: <ref>, with: { ... } } # <tag>` — a step written as ONE mapping on one line,
///   the compact spelling a workflow that is only a bootstrap is written in. The comment is what
///   follows the closing brace.
///
/// A rule that read only the block spelling could be switched off by reformatting the step, and a
/// rule a formatting choice can switch off is not a rule.
fn parse_uses(line: &str) -> Option<(String, Option<String>)> {
    let t = line.trim_start();
    let t = t.strip_prefix("- ").map(str::trim_start).unwrap_or(t);
    if t.starts_with('{') {
        return parse_uses_flow(t);
    }
    let rest = t.strip_prefix("uses:")?;
    let rest = rest.trim_start();
    let (reference, tail) = match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], rest[i..].trim()),
        None => (rest, ""),
    };
    if reference.is_empty() {
        return None;
    }
    let comment = if tail.starts_with('#') {
        Some(tail.to_string())
    } else if tail.is_empty() {
        None
    } else {
        // Trailing content that is not a comment is not the shape this rule reads.
        return None;
    };
    Some((reference.to_string(), comment))
}

/// The flow-mapping half of [`parse_uses`]: `{ ..., uses: <ref>, ... } # <tag>`.
fn parse_uses_flow(t: &str) -> Option<(String, Option<String>)> {
    let mut from = 0usize;
    let value = loop {
        let at = from + t[from..].find("uses:")?;
        from = at + "uses:".len();
        let before = t[..at].trim_end();
        if before.ends_with('{') || before.ends_with(',') {
            let rest = t[from..].trim_start();
            let end = rest
                .find(|c: char| c.is_whitespace() || c == ',' || c == '}')
                .unwrap_or(rest.len());
            break &rest[..end];
        }
    };
    if value.is_empty() {
        return None;
    }
    let tail = t.rfind('}').map(|i| t[i + 1..].trim()).unwrap_or("");
    let comment = if tail.starts_with('#') {
        Some(tail.to_string())
    } else if tail.is_empty() {
        None
    } else {
        return None;
    };
    Some((value.to_string(), comment))
}

fn is_sha40(s: &str) -> bool {
    s.len() == 40
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// A shell STATEMENT, not a mention. These workflows quote the user-facing command in prose and in
/// error strings; only an invocation at the head of a statement (optionally behind `if`/`!`) is a
/// real check whose flags matter.
fn is_attestation_verify_statement(line: &str) -> bool {
    let mut t = line.trim_start_matches([' ', '\t']);
    if let Some(r) = t.strip_prefix("if ") {
        t = r.trim_start_matches([' ', '\t']);
    }
    if let Some(r) = t.strip_prefix('!') {
        t = r.trim_start_matches([' ', '\t']);
    }
    let Some(rest) = t.strip_prefix("gh attestation verify") else {
        return false;
    };
    rest.is_empty() || rest.starts_with(|c: char| !c.is_alphanumeric() && c != '_')
}

/// `--signer-workflow[= \t]+["']?([^\s"';&|)]+)`. The value stops at shell punctuation: a flag
/// followed by the shell's statement separator is not a workflow path ending in a semicolon.
fn signer_value(cmd: &str) -> Option<String> {
    let i = cmd.find("--signer-workflow")?;
    let rest = &cmd[i + "--signer-workflow".len()..];
    let rest = rest.trim_start_matches(['=', ' ', '\t']);
    let rest = rest.trim_start_matches(['"', '\'']);
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '&' | '|' | ')'))
        .unwrap_or(rest.len());
    let v = &rest[..end];
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// `\bkey\s*:\s*` at the head of a trimmed line, returning what follows.
fn after_key<'a>(trimmed: &'a str, key: &str) -> Option<&'a str> {
    let rest = trimmed.strip_prefix(key)?;
    let rest = rest.trim_start();
    rest.strip_prefix(':')
}

/// A `v*` tag trigger, in BOTH of YAML's sequence spellings.
///
/// The original test saw only the block form. The flow form (`tags: ["v*"]`) is ordinary,
/// idiomatic YAML that the runner treats identically, and it is what a maintainer writes when
/// compressing a trigger block — so the root rule of this whole design could be reinstated in the
/// shorter of two spellings with the lint staying green. A rule a formatting choice can switch off
/// is not a rule.
fn has_v_star_tag_trigger(on_block: &str) -> bool {
    for line in on_block.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix('-') {
            let r = rest.trim_start().trim_start_matches(['"', '\'']);
            if r.starts_with("v*") {
                return true;
            }
        }
        if let Some(rest) = after_key(t, "tags") {
            let r = rest.trim_start();
            let r = r.strip_prefix('[').unwrap_or(r);
            let r = r.trim_start().trim_start_matches(['"', '\'']);
            if r.starts_with("v*") {
                return true;
            }
        }
    }
    false
}

/// Every `git push` command line in a workflow.
fn git_push_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| contains_git_push(l))
        .map(|l| l.trim().to_string())
        .collect()
}

/// `\bgit\s+(?:-C\s+\S+\s+)?push\b`.
fn contains_git_push(line: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = line[from..].find("git ") {
        let i = from + rel;
        let before_ok = i == 0 || {
            let c = line.as_bytes()[i - 1] as char;
            !c.is_alphanumeric() && c != '_' && c != '-'
        };
        from = i + 4;
        if !before_ok {
            continue;
        }
        let mut rest = line[i + 4..].trim_start();
        if let Some(r) = rest.strip_prefix("-C ") {
            let r = r.trim_start();
            let cut = r.find(char::is_whitespace).unwrap_or(r.len());
            rest = r[cut..].trim_start();
        }
        if rest
            .strip_prefix("push")
            .map(|t| t.is_empty() || t.starts_with(|c: char| !c.is_alphanumeric() && c != '_'))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// THE DESTINATION IS WHAT MATTERS, AND THE SOURCE SIDE IS NOT ALWAYS `HEAD`.
///
/// This only ever looked for `HEAD:<dst>`, so `git push origin main:main` — the exact form the
/// promote script documents, and the one a workflow copies when it wants to fast-forward a release
/// branch — matched neither that test nor the bare-branch one below. A push straight to a protected
/// branch from a workflow was therefore invisible in its most likely spelling. Read the whole
/// refspec instead: `[+]<src>:<dst>`, any src.
fn refspec_destination(cmd: &str) -> Option<String> {
    let bytes = cmd.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if !(c.is_whitespace() || c == '"' || c == '\'') {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < bytes.len() && bytes[j] == b'+' {
            j += 1;
        }
        let src_start = j;
        while j < bytes.len() {
            let c = bytes[j] as char;
            if c.is_whitespace() || c == '"' || c == '\'' || c == ':' {
                break;
            }
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' || j == src_start {
            i += 1;
            continue;
        }
        let mut k = j + 1;
        let dst_start = k;
        while k < bytes.len() {
            let c = bytes[k] as char;
            if c.is_whitespace() || c == '"' || c == '\'' {
                break;
            }
            k += 1;
        }
        if k == dst_start {
            i += 1;
            continue;
        }
        let dst = &cmd[dst_start..k];
        let dst = dst.strip_prefix("refs/heads/").unwrap_or(dst);
        return Some(dst.to_string());
    }
    None
}

/// A BARE `git push origin main` with no refspec. The word-boundary guard keeps this from firing on
/// `main:main`, which the refspec test above owns, and on a branch merely named `main-docs`.
fn pushes_bare_release_branch(cmd: &str) -> bool {
    let Some(i) = cmd.find("origin ") else {
        return false;
    };
    let rest = cmd[i + "origin ".len()..].trim_start();
    let rest = rest.trim_start_matches(['"', '\'', '+']);
    let rest = rest.strip_prefix("refs/heads/").unwrap_or(rest);
    for branch in ["main", "qa"] {
        if let Some(tail) = rest.strip_prefix(branch) {
            let ok = tail.is_empty()
                || !tail.starts_with(|c: char| {
                    c.is_alphanumeric() || c == '_' || c == ':' || c == '/' || c == '-'
                });
            if ok {
                return true;
            }
        }
    }
    false
}

/// True when there is an actual composite-action manifest to scan, either on disk or planted by a
/// selftest overlay. Mirrors `Ctx::list`'s own `overlay_adds_it` test: `.github/actions` need not
/// exist in the real tree today (it does not) for a plant UNDER it to be a legitimate root, exactly
/// as a plant into any other not-yet-existing directory is (see `Ctx::list`'s own comment on this).
fn has_composite_actions(cx: &Ctx) -> bool {
    if cx.exists(ACTIONS_DIR) {
        return true;
    }
    let prefix = format!("{ACTIONS_DIR}/");
    cx.overlay()
        .map(|ov| ov.paths().any(|p| p.to_string_lossy().starts_with(&prefix)))
        .unwrap_or(false)
}

/// Every composite-action manifest (`action.yml` / `action.yaml`, at any depth under
/// `.github/actions`) as `(relative path, text)`. Empty, not an error, when there is nothing to
/// scan — unlike `workflow_names`'s floor, a repo with zero composite actions today is not a repo
/// that lost its subject.
fn action_manifests(cx: &Ctx) -> Result<Vec<(String, String)>, String> {
    if !has_composite_actions(cx) {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    // TWO SPELLINGS, ONE SCOPE. `yml` and `yaml` are the same manifest under two names, and a
    // repository that spells every one of them `yml` legitimately has zero `yaml` — so each
    // individual walk declares that zero is a real answer FOR IT. What must not be empty is the
    // UNION, and that is checked below rather than per-extension: a `.github/actions` that exists
    // and holds no manifest at all is a scope this rule is reading nothing of, and zero is the
    // passing answer to every ban.
    for ext in ["yml", "yaml"] {
        let files = cx
            .walk(&WalkSpec::new([ACTIONS_DIR]).ext(ext).allow_empty())
            .map_err(|e| e.to_string())?;
        for f in files {
            let rel = f.rel_str();
            if rel.rsplit('/').next() == Some(&format!("action.{ext}")) {
                out.push((rel, f.text));
            }
        }
    }
    if out.is_empty() {
        return Err(format!(
            "{ACTIONS_DIR} is present and holds no `action.yml`/`action.yaml` at any depth. A \
             composite-action directory with no manifest in it is a scope this rule reads nothing \
             of, and nothing read is not a clean pin set. Remove the directory, or add the manifest \
             it exists for."
        ));
    }
    Ok(out)
}

/// One finding, carrying the rule id that owns it so the row set is derived from the findings
/// rather than restated beside them.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub message: String,
}

impl Finding {
    fn new(rule: &'static str, message: impl Into<String>) -> Finding {
        Finding {
            rule,
            message: message.into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct WorkflowRulesGate;

/// The workflow file names, sorted, with the discovery floor applied. A directory listing that
/// silently drops a missing root is what makes "scanned nothing" indistinguishable from "found
/// nothing", and every rule here is a ban.
fn workflow_names(cx: &Ctx) -> Result<Vec<String>, String> {
    let files = cx
        .walk(
            &WalkSpec::new([WORKFLOWS])
                .exclude([".json"])
                .min_files(MIN_WORKFLOWS),
        )
        .map_err(|e| e.to_string())?;
    let mut out: Vec<String> = files
        .iter()
        .map(|f| f.rel_str())
        .filter(|p| p.ends_with(".yml") || p.ends_with(".yaml"))
        .filter_map(|p| p.strip_prefix(&format!("{WORKFLOWS}/")).map(str::to_string))
        .filter(|n| !n.contains('/'))
        .collect();
    out.sort();
    if out.len() < MIN_WORKFLOWS {
        return Err(format!(
            "{WORKFLOWS} yielded {} workflow file(s), under its floor of {MIN_WORKFLOWS}. Every \
             rule in this gate is a ban, and a scan that found nothing satisfies all of them.",
            out.len()
        ));
    }
    Ok(out)
}

pub fn check(cx: &Ctx) -> Result<Vec<Finding>, String> {
    let mut bad: Vec<Finding> = Vec::new();
    let names = workflow_names(cx)?;
    let read = |n: &str| -> Option<String> {
        let p = format!("{WORKFLOWS}/{n}");
        if cx.exists(&p) {
            cx.read(&p).ok()
        } else {
            None
        }
    };

    // R14. EVERY THIRD-PARTY ACTION RUNS FROM A COMMIT SHA, AND A TAG IS NOT A SHA.
    //
    // The dependabot config states this as a rule, at length, and nothing checked it. Every `uses:`
    // in the tree really is a 40-hex sha today, and reverting any one of them to a tag was proven
    // green against every lint in the structure job — a rule written down in a config file's
    // comment and enforced nowhere survives exactly as long as nobody is in a hurry. The scopes
    // that note names are why this is a pipeline rule and not a style rule: an action that can
    // be force-moved under a name we already trust can push an image and mint an attestation, which
    // is to say it can put a user-facing name on bytes nothing in this repository ever built.
    //
    // SCOPE: EVERY WORKFLOW, PLUS EVERY COMPOSITE ACTION. `workflow_names` covers the former; the
    // latter is `action_manifests` (`.github/actions/**/action.yml`), added because a composite
    // action's `runs.steps` carries the identical `uses:` shape and the identical exposure — CI
    // secrets and, on the promote path, `packages`/`id-token`/`attestations` write. There is no
    // `.github/actions` in this tree today, so that half scans zero files and costs nothing; the
    // day one is added, this rule already covers it rather than needing to be told to.
    //
    // The independently-resolved SHA behind every pin below, re-checked against upstream rather
    // than trusted from whatever a scanner suggested, is `docs/ci/actions-pins.md`.
    //
    // LOCAL `uses:` IS EXEMPT, AND ONLY LOCAL. A `./` reference resolves inside this repository at
    // the caller's own commit; there is no third party and nothing to force-move. A `docker://`
    // reference is exempt for the same reason a SHA is required everywhere else: it names an image
    // by DIGEST, not by a movable ref, so it is already the thing this rule wants and is judged
    // instead by the digest-pin rule over `services:` images.
    //
    // THE TRAILING TAG COMMENT IS PART OF THE PIN: without it Dependabot cannot tell what the sha
    // stands for and silently stops updating it, so the pin rots into a permanently stale,
    // unpatched version.
    let mut targets: Vec<(String, String)> = names
        .iter()
        .map(|n| (n.clone(), read(n).unwrap_or_default()))
        .collect();
    targets.extend(action_manifests(cx)?);
    for (name, raw) in &targets {
        let text = strip_comments(raw);
        for line in text.lines() {
            let Some((reference, comment)) = parse_uses(line) else {
                continue;
            };
            if reference.starts_with("./") || reference.starts_with("docker://") {
                continue;
            }
            let Some((_, at)) = reference.rsplit_once('@') else {
                bad.push(Finding::new(
                    "R14",
                    format!(
                        "{name}: `uses: {reference}` names no ref at all, so it runs whatever the \
                         default branch holds today."
                    ),
                ));
                continue;
            };
            if !is_sha40(at) {
                bad.push(Finding::new(
                    "R14",
                    format!(
                    "{name}: `uses: {reference}` is pinned to '{at}', which is a ref the action's \
                     owner can force-move, not a commit. Our runners hold \
                     packages/id-token/attestations write; the bytes that run must be the bytes \
                     that were reviewed. Pin the sha and keep the tag as a trailing comment so \
                     Dependabot can still bump it."
                ),
                ));
            } else if comment.is_none() {
                bad.push(Finding::new(
                    "R14",
                    format!(
                    "{name}: `uses: {reference}` is a bare sha with no trailing `# <tag>` comment. \
                     Dependabot reads that comment to learn which version the sha stands for; \
                     without it the pin stops being updated and rots into a stale, unpatched \
                     version."
                ),
                ));
            }
        }
    }

    // R15. EVERY ATTESTATION VERIFY NAMES THE WORKFLOW THAT SIGNED, NOT JUST THE REPOSITORY.
    //
    // Asking only which REPOSITORY attested is an org-scoped check being read as a pipeline check.
    // Every workflow in this repository that can be given the attestation scopes answers it equally
    // well — including a workflow added by a pull request, running on a branch, that built an image
    // nothing here staged and pushed it under a staging name. The promote would find a verifying
    // attestation on that tag, conclude the bytes are ours, and mint a user-facing version over
    // them. The gap between those two questions is the whole promote.
    //
    // THE SIGNER IS THE REUSABLE WORKFLOW, NEVER ITS CALLER, because the signing certificate's
    // subject is the file holding the job that requested the token, not whatever called it. Naming
    // the workflow a human would call "the stager" makes every verify FAIL and every promote
    // refuse: a silent-looking one-word error with the whole release path behind it.
    //
    // SO THE ALLOWED SET IS DERIVED FROM THE TREE, NOT RESTATED HERE.
    let mut signers: BTreeSet<String> = BTreeSet::new();
    for name in &names {
        if strip_comments(&read(name).unwrap_or_default())
            .contains("actions/attest-build-provenance")
        {
            signers.insert(format!("GetBusbar/busbar/{WORKFLOWS}/{name}"));
        }
    }
    let signer_list = signers.iter().cloned().collect::<Vec<_>>().join(", ");
    for name in &names {
        let text = strip_comments(&read(name).unwrap_or_default());
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !is_attestation_verify_statement(line) {
                continue;
            }
            // Follow backslash continuations so a flag on the next line still counts.
            let mut cmd = (*line).to_string();
            let mut j = i;
            while cmd.trim_end().ends_with('\\') && j + 1 < lines.len() {
                j += 1;
                cmd.push('\n');
                cmd.push_str(lines[j]);
            }
            match signer_value(&cmd) {
                None => {
                    bad.push(Finding::new(
                        "R15",
                        format!(
                    "{name}:{}: `gh attestation verify` runs without --signer-workflow, so it \
                     accepts an attestation minted by ANY workflow in this repository -- a branch \
                     workflow that pushed its own bytes under a staging name passes it. Pin the \
                     signer to the reusable workflow that actually attests ({}).",
                    i + 1,
                    if signer_list.is_empty() { "none found in the tree" } else { &signer_list }
                ),
                    ))
                }
                Some(v) if !signers.is_empty() && !signers.contains(&v) => {
                    bad.push(Finding::new(
                        "R15",
                        format!(
                            "{name}:{}: --signer-workflow names '{v}', which does not run \
                         actions/attest-build-provenance in this tree. The signer is the reusable \
                         workflow the attest step lives in, NOT the workflow that calls it -- \
                         naming the caller fails every verify and blocks every promote. Expected \
                         one of: {signer_list}.",
                            i + 1
                        ),
                    ));
                }
                Some(_) => {}
            }
        }
    }

    // R1. NO WORKFLOW MAY BE TRIGGERED BY A VERSION TAG.
    // This is the root of the old order. If a tag push causes a build, then the tag has to exist
    // before the build, and the name is public before anything has verified it. Under the new order
    // a tag is an OUTPUT of a green release, so nothing may key off one.
    for name in &names {
        let text = strip_comments(&read(name).unwrap_or_default());
        if has_v_star_tag_trigger(&top_level_block(&text, "on")) {
            bad.push(Finding::new(
                "R1",
                format!(
                "{name} is triggered by a `v*` tag push. A tag must be the RESULT of a verified \
                 release, never its trigger: keying a build off a tag means the version name is \
                 public before one consumer check has run against it, which is how a release \
                 shipped five of seven assets under a name that could not be taken back."
            ),
            ));
        }
    }

    // R11. NO WORKFLOW MAY PUSH A COMMIT TO A RELEASE BRANCH.
    //
    // A documentation-refresh job once ended by committing back to whichever release branch it ran
    // on. Those branches are protected, so the push is REJECTED there: the job fails, the run
    // concludes failure, and the staging workflow's first gate refuses to stage. Had it instead
    // SUCCEEDED it would have been worse: a new HEAD on a release branch for which no run of any
    // required workflow exists, so the record resolution refuses that sha permanently and there is
    // no release at all.
    //
    // The rule is therefore about the REFSPEC, not about intent: a branch destination that is a
    // release branch, or a VARIABLE (which is how the destination silently became the release
    // branch in the first place), is a violation. Publishing to a fixed, unprotected branch is
    // fine, and so is pushing a tag - the promote must still be able to push the version tag, which
    // is the one user-facing name this whole gate exists to sequence.
    for name in &names {
        let text = strip_comments(&read(name).unwrap_or_default());
        for cmd in git_push_lines(&text) {
            if let Some(dest) = refspec_destination(&cmd) {
                if dest.starts_with('$') || dest == "main" || dest == "qa" {
                    bad.push(Finding::new(
                        "R11",
                        format!(
                        "{name} pushes a commit to `{dest}` (`{cmd}`). Never push to a release \
                         branch from a workflow: qa and main are protected, so the push is \
                         rejected and the run goes red, which stops the release; and if it landed \
                         it would mint a release-branch HEAD that no required run covers, which \
                         resolve-staged refuses forever. Publish to an unprotected branch or \
                         upload an artifact."
                    ),
                    ));
                }
            }
            if pushes_bare_release_branch(&cmd) {
                bad.push(Finding::new(
                    "R11",
                    format!(
                    "{name} pushes directly to a release branch (`{cmd}`). Release branches move \
                     only by a human fast-forward of a green sha; a workflow that writes to them \
                     can create a HEAD nothing has verified."
                ),
                ));
            }
        }
    }

    Ok(bad)
}

/// Is every ban's input read? Used by both the run and the selftest.
fn owed_all() -> Vec<&'static str> {
    RULES.to_vec()
}

fn rule_title(rule: &str) -> &'static str {
    match rule {
        "R1" => "no workflow is triggered by a version tag",
        "R11" => "no workflow pushes a commit to a release branch",
        "R14" => "every third-party action runs from a commit sha",
        "R15" => "every attestation verify names the workflow that signed",
        _ => "workflow rule",
    }
}

impl Gate for WorkflowRulesGate {
    fn name(&self) -> &'static str {
        "workflow-rules"
    }

    fn owed(&self) -> Vec<String> {
        RULES.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows: Vec<Row> = Vec::new();
        match check(cx) {
            Err(e) => {
                // The tree could not be READ. Every rule is a ban, so reporting them individually
                // as passes over a scan that did not happen is the one answer this gate must
                // never give: one FAIL row per rule, naming the reason.
                for rule in RULES {
                    rows.push(Row::fail(*rule, "the workflow scan did not run", e.clone()));
                }
            }
            Ok(bad) => {
                for rule in RULES {
                    let hits: Vec<&Finding> = bad.iter().filter(|f| f.rule == *rule).collect();
                    if hits.is_empty() {
                        rows.push(Row::pass(*rule, rule_title(rule), "no violation"));
                    } else {
                        rows.push(Row::fail(
                            *rule,
                            rule_title(rule),
                            hits.iter()
                                .map(|f| f.message.clone())
                                .collect::<Vec<_>>()
                                .join(" | "),
                        ));
                    }
                }
            }
        }
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the unmutated tree is green, so every RED below means something",
            &owed_all(),
        ));
        for m in mutations() {
            report.push(m.case(cx, self));
        }
        report
    }
}

// -------------------------------------------------------------------------------------------
// THE STRUCTURAL MUTATIONS, AS SELFTEST CASES.
//
// Each one is a real regression written the way it would actually arrive. A mutation is applied to
// an OVERLAY of the real workflow, never to the tree, so the fixtures cannot drift from the file
// they are about and the plants cannot stack.
//
// A MUTATION THAT CHANGES NOTHING IS A FAILURE, NOT A SKIP. If the anchor a mutation edits has
// moved, the rule stops being proven while the selftest keeps printing a line about it. The anchors
// below are therefore chosen to be structural (`steps:`, the `on:` block) wherever a literal would
// do.
// -------------------------------------------------------------------------------------------

struct Mutation {
    label: &'static str,
    file: &'static str,
    rule: &'static str,
    apply: fn(&str) -> String,
    /// The mutation CREATES the file rather than editing it: no remaining workflow runs
    /// `gh attestation verify`, so the only violation R15 can be shown is a workflow that does.
    creates: bool,
}

/// A case whose answer needs no gate run: the plant could not be made, so the rule is UNPROVEN
/// here rather than passing. Same `expected` and `covers` as the red case it stands in for, so the
/// report reads exactly as it did when this was a `prove_red` with its verdict overwritten.
fn skipped<'a>(name: String, rule: &str) -> crate::gates::CasePlan<'a> {
    crate::gates::Case {
        name,
        covers: vec![rule.to_string()],
        expected: crate::gates::Expect::Red { naming: Vec::new() },
        got: crate::gates::Expect::Skipped,
    }
    .into()
}

impl Mutation {
    fn case<'a>(&self, cx: &'a Ctx, gate: &'a dyn Gate) -> crate::gates::CasePlan<'a> {
        let rel = format!("{WORKFLOWS}/{}", self.file);
        if self.creates {
            if cx.exists(&rel) {
                // SKIPPED without running the gate: the case's answer is already known, and a
                // plan that ran the whole gate in order to throw the verdict away was a whole
                // tree scan spent on a case that proves nothing either way.
                return skipped(
                    format!(
                        "{}: the file this mutation plants already exists, so planting it proves \
                         nothing",
                        self.label
                    ),
                    self.rule,
                );
            }
            let mut ov = Overlay::new();
            ov.set(&rel, (self.apply)(""));
            return prove_red(cx, gate, self.label, &[self.rule], ov, &[self.rule]);
        }
        let original = match cx.read(&rel) {
            Ok(t) => t,
            Err(e) => {
                return skipped(format!("{}: {e}", self.label), self.rule);
            }
        };
        let mutated = (self.apply)(&original);
        if mutated == original {
            // Reported as a case that did not do what it expected, which fails the report — a
            // mutation that edits nothing produces no RED and proves no rule.
            return skipped(
                format!(
                    "{}: the anchor this mutation edits has moved, so the rule is no longer proven",
                    self.label
                ),
                self.rule,
            );
        }
        let mut ov = Overlay::new();
        ov.set(&rel, mutated);
        prove_red(cx, gate, self.label, &[self.rule], ov, &[self.rule])
    }
}

fn replace_once(t: &str, from: &str, to: &str) -> String {
    t.replacen(from, to, 1)
}

fn mutations() -> Vec<Mutation> {
    vec![
        Mutation {
            // THE REGRESSION AS IT WOULD ACTUALLY ARRIVE: the verify is written the way the docs
            // and every README write it -- subject plus repository -- and it passes, on real
            // attested bytes, every time anyone tests it. It only fails to be a pipeline check on
            // the day someone else's workflow attests something.
            label: "R15 an attestation check runs without --signer-workflow",
            file: "zz-planted-verify.yml",
            rule: "R15",
            apply: |_| {
                "jobs:\n  v:\n    steps:\n      - run: |\n          gh attestation verify ./x --repo GetBusbar/busbar\n"
                    .to_string()
            },
            creates: true,
        },
        Mutation {
            // The subtler half: the flag is present and names a workflow that does not run the
            // attest step. The signer is the reusable workflow the attest step lives in, so this
            // spelling fails every verify -- green to read, red only in production.
            label: "R15 the signer is named as a workflow that does not attest",
            file: "zz-planted-verify.yml",
            rule: "R15",
            apply: |_| {
                "jobs:\n  v:\n    steps:\n      - run: |\n          gh attestation verify ./x --repo GetBusbar/busbar --signer-workflow GetBusbar/busbar/.github/workflows/promote.yml\n"
                    .to_string()
            },
            creates: true,
        },
        Mutation {
            // THE REGRESSION AS IT WOULD ACTUALLY ARRIVE: someone copies a snippet out of an
            // action's README, which is always written with the tag, and nothing anywhere notices.
            label: "R14 an action reverts from a sha to a force-movable tag",
            file: "plugin-ci.yml",
            rule: "R14",
            apply: |t| retag_first_pin(t, false),
            creates: false,
        },
        Mutation {
            // The quieter half. The sha stays a sha, so it still looks pinned; the tag comment
            // goes, so Dependabot stops bumping it and the pin rots in place.
            label: "R14 a pin loses the trailing tag comment Dependabot reads",
            file: "plugin-ci.yml",
            rule: "R14",
            apply: |t| retag_first_pin(t, true),
            creates: false,
        },
        Mutation {
            // THE SAME TWO REGRESSIONS IN THE FLOW SPELLING the pipeline workflow itself is
            // written in: a step as one `{ uses: ..., with: ... }` mapping.
            label: "R14 a flow-style action reverts from a sha to a force-movable tag",
            file: "promote.yml",
            rule: "R14",
            apply: |t| retag_first_pin(t, false),
            creates: false,
        },
        Mutation {
            label: "R14 a flow-style pin loses the trailing tag comment Dependabot reads",
            file: "promote.yml",
            rule: "R14",
            apply: |t| retag_first_pin(t, true),
            creates: false,
        },
        Mutation {
            label: "R1 a v* tag trigger comes back",
            file: "promote.yml",
            rule: "R1",
            apply: |t| {
                replace_once(
                    t,
                    "on: pull_request\n",
                    "on:\n  push:\n    tags:\n      - \"v*\"\n",
                )
            },
            creates: false,
        },
        Mutation {
            // THE SAME RULE, IN THE OTHER YAML SPELLING. The block form above was caught; the flow
            // form is ordinary YAML the runner treats identically.
            label: "R1 a v* tag trigger comes back as a FLOW sequence",
            file: "promote.yml",
            rule: "R1",
            apply: |t| {
                replace_once(
                    t,
                    "on: pull_request\n",
                    "on:\n  push:\n    tags: [\"v*\"]\n",
                )
            },
            creates: false,
        },
        Mutation {
            // The refspec form a promote script documents, which the `HEAD:<dst>` test and the
            // no-refspec test both walked past. THE ANCHOR IS `steps:`, NOT A `uses:` LINE: a
            // structural feature of every job cannot be renamed by a pin bump or a formatting pass.
            label: "R11 a workflow pushes a refspec straight to main",
            file: "promote.yml",
            rule: "R11",
            apply: |t| {
                replace_once(
                    t,
                    "    steps:\n",
                    "    steps:\n      - run: git push origin main:main\n",
                )
            },
            creates: false,
        },
    ]
}

/// The R14 mutations both target the FIRST fully-pinned third-party action in the file, found by
/// shape rather than by a literal sha. A literal would rot the day that action is bumped, and a
/// mutation that edits nothing proves nothing.
fn retag_first_pin(t: &str, drop_comment_only: bool) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut done = false;
    for line in t.lines() {
        if done {
            out.push(line.to_string());
            continue;
        }
        let Some((reference, comment)) = parse_uses(line) else {
            out.push(line.to_string());
            continue;
        };
        let Some((repo, at)) = reference.rsplit_once('@') else {
            out.push(line.to_string());
            continue;
        };
        if reference.starts_with("./") || !is_sha40(at) || comment.is_none() {
            out.push(line.to_string());
            continue;
        }
        let comment = comment.unwrap_or_default();
        let tag = comment.trim_start_matches('#').trim();
        let replacement = if line.contains('{') {
            // Flow spelling: the pin sits inside the mapping and the comment follows the brace.
            if drop_comment_only {
                line.rfind('}')
                    .map(|i| line[..=i].to_string())
                    .unwrap_or_else(|| line.to_string())
            } else {
                line.replace(&format!("@{at}"), &format!("@{tag}"))
            }
        } else if drop_comment_only {
            line.replace(&format!(" {comment}"), "")
        } else {
            line.replace(&format!("{repo}@{at} {comment}"), &format!("{repo}@{tag}"))
        };
        out.push(replacement);
        done = true;
    }
    let mut s = out.join("\n");
    if t.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[cfg(test)]
#[path = "tests/workflow_rules_tests.rs"]
mod tests;
