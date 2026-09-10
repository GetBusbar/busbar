//! THE RELEASE-ORDER GATE. Nothing may be tagged until it has been verified from the consumer side.
//!
//! busbar's release used to mint the version name FIRST: landing on main pushed `vX.Y.Z`, that tag
//! push fired both the release and the image workflow, and everything was built and published under
//! a name that already existed in public. Consumer verification, however thorough, therefore ran
//! after the fact and could only report damage. One release shipped that way with five of seven
//! assets, its container version tag never built at all while the docs told users to pin it, and
//! putting it right meant deleting the release and the tag and re-cutting. Docker Hub has TAG
//! IMMUTABILITY enabled on the published repository, so a broken version is permanent.
//!
//! The order is now build -> stage under a throwaway name -> verify from the consumer side ->
//! promote. That order lives in the SHAPE OF THE WORKFLOW GRAPH, and a workflow graph is edited by
//! people in a hurry during an incident. Every rule below is a way the old order could come back by
//! accident, and each one has a specific observed failure behind it.
//!
//! Three things this port keeps that a clean-room rewrite would lose:
//!
//! * **The parser stays deliberately small, and here that is not a dependency argument but a
//!   correctness one.** The rules need three facts — which top-level block a line is in, which job
//!   it is in, and each job's `needs:` — and indentation gives all three. A general YAML parser
//!   normalises the document, and several of these rules are assertions about what a human WROTE
//!   (a trailing `# tag` comment on a pin; `--draft` as a whole token; a `v*` trigger in either of
//!   YAML's two sequence spellings). This crate also carries no regex dependency, so every pattern
//!   below is spelled out as explicit scanning — which is why each one has its own unit test.
//!
//! * **The signer set is DERIVED FROM THE TREE, never restated.** The workflows allowed to be named
//!   by `--signer-workflow` are exactly the ones that run the attest action. A hand-kept list would
//!   go stale the day the attest step moves files, and it would go stale in the direction that
//!   breaks releases.
//!
//! * **The structural mutations are the selftest.** Each mutation is a real regression written the
//!   way it would actually arrive, applied to an overlay of the real workflow, and the gate must go
//!   RED naming that rule. A mutation that CHANGES NOTHING is itself a failure: it means the anchor
//!   it edits has moved and the rule is no longer being proven. That refusal is load-bearing — a
//!   pin bump once silently emptied one mutation and left a rule unproven behind a standing red.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};

const WORKFLOWS: &str = ".github/workflows";

/// The jobs allowed to create a user-facing name. Everything here must be downstream of the staged
/// consumer verification.
const PROMOTE_JOBS: &[&str] = &["promote-image", "promote-release"];
/// In the stage workflow; gates the record being written.
const VERIFY_GATE: &str = "verify-staged";
/// In the release workflow; gates the promote jobs.
const RESOLVE_GATE: &str = "resolve-staged";

/// The floor under the workflow discovery. `find`-style discovery that yields nothing reads exactly
/// like a tree with no violations, and every rule below is a ban — zero inputs satisfies all of
/// them. The real tree carries well over twenty workflows; a scan that finds fewer than this many
/// has lost its subject, not been cleaned.
const MIN_WORKFLOWS: usize = 12;

/// The rule ids, which are also the ledger row ids. They are the prefixes the legacy lint already
/// printed, so a row means the same thing before and after the conversion. There is deliberately no
/// `R13`: the legacy rule table never had one, and inventing one to close the gap would make the
/// row set disagree with every message anybody has read.
const RULES: &[&str] = &[
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R14", "R15",
];

/// The graph proof is an owed row of its own, not a second invocation. "A failure leaves nothing
/// public" is a claim about job-scheduling semantics applied to this particular graph, and a design
/// nobody has watched fail is not a design. Running it on the same push as the rules means the
/// claim cannot fall out of CI by losing one call site.
const PROVE_ROW: &str = "PROVE";

/// The jobs whose execution creates something a user can see. If any of these runs after a failure
/// upstream of it, the design is broken.
fn public_jobs() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "promote-image",
            "mints the container version tag and moves the moving pointer (immutable, cannot be \
             undone)",
        ),
        (
            "promote-release",
            "pushes the git tag and publishes the release",
        ),
        (
            "notify-downstream",
            "tells every downstream repo a release happened",
        ),
    ]
}

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

/// Job id -> that job's text, for every two-space-indented key under `jobs:`.
pub fn jobs(text: &str) -> BTreeMap<String, String> {
    let block = top_level_block(text, "jobs");
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    let mut cur: Option<String> = None;
    let mut buf: Vec<String> = Vec::new();
    for line in block.lines().skip(1) {
        if let Some(id) = job_key(line) {
            if let Some(name) = cur.take() {
                found.insert(name, buf.join("\n"));
            }
            cur = Some(id);
            buf = vec![line.to_string()];
        } else if cur.is_some() {
            buf.push(line.to_string());
        }
    }
    if let Some(name) = cur {
        found.insert(name, buf.join("\n"));
    }
    found
}

/// `^  ([A-Za-z0-9_-]+):\s*$` — a job header and nothing else. The trailing-content test is what
/// keeps `  name: something` inside a step from opening a job.
fn job_key(line: &str) -> Option<String> {
    let rest = line.strip_prefix("  ")?;
    if rest.starts_with(' ') {
        return None;
    }
    let (id, tail) = rest.split_once(':')?;
    if !tail.trim().is_empty() || id.is_empty() {
        return None;
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some(id.to_string())
}

/// The job ids a job depends on, from either `needs: a` or `needs: [a, b]`.
pub fn needs_of(job_text: &str) -> Vec<String> {
    for line in job_text.lines() {
        let Some(rest) = line.strip_prefix("    needs:") else {
            continue;
        };
        if line.starts_with("     ") {
            continue;
        }
        let mut raw = rest.trim();
        if raw.starts_with('[') {
            raw = raw.trim_matches(['[', ']']);
        }
        return raw
            .split(',')
            .map(|p| p.trim().trim_matches(['\'', '"']).to_string())
            .filter(|p| !p.is_empty())
            .collect();
    }
    Vec::new()
}

/// Is `target` anywhere upstream of `start` in the needs graph?
pub fn depends_on(all: &BTreeMap<String, String>, start: &str, target: &str) -> bool {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = needs_of(all.get(start).map(String::as_str).unwrap_or(""));
    while let Some(j) = stack.pop() {
        if j == target {
            return true;
        }
        if !seen.insert(j.clone()) {
            continue;
        }
        stack.extend(needs_of(all.get(&j).map(String::as_str).unwrap_or("")));
    }
    false
}

// -------------------------------------------------------------------------------------------
// PATTERN HELPERS. One function per shell/regex idiom, each with its own unit test, because the
// crate carries no regex dependency and a hand-rolled scanner that is wrong is a gate that is
// green for the wrong reason.
// -------------------------------------------------------------------------------------------

/// `^\s*(?:-\s+)?uses:\s*(\S+)\s*(#.*)?$` — the action reference and its trailing tag comment.
fn parse_uses(line: &str) -> Option<(String, Option<String>)> {
    let t = line.trim_start();
    let t = t.strip_prefix("- ").map(str::trim_start).unwrap_or(t);
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

/// `(?<![=\w])--draft(?![=\w])` — the flag as a WHOLE TOKEN.
///
/// An earlier revision of this rule searched a whole file for `--draft`. The promote step runs
/// `gh release edit --draft=false`, which contains that substring, so deleting the real `--draft`
/// flag from the create call left the rule GREEN. The mutation test is what found it.
fn has_draft_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find("--draft") {
        let i = from + rel;
        let end = i + "--draft".len();
        let before_ok = i == 0 || {
            let c = bytes[i - 1] as char;
            c != '=' && !c.is_alphanumeric() && c != '_'
        };
        let after_ok = end >= bytes.len() || {
            let c = bytes[end] as char;
            c != '=' && !c.is_alphanumeric() && c != '_'
        };
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
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

/// `\bkey\s*:\s*` at the head of a trimmed line, returning what follows.
fn after_key<'a>(trimmed: &'a str, key: &str) -> Option<&'a str> {
    let rest = trimmed.strip_prefix(key)?;
    let rest = rest.trim_start();
    rest.strip_prefix(':')
}

/// `^\s+<key>:` — an indented key, anywhere in a block.
fn has_indented_key(text: &str, key: &str) -> bool {
    text.lines().any(|l| {
        (l.starts_with(' ') || l.starts_with('\t'))
            && l.trim_start().starts_with(&format!("{key}:"))
    })
}

/// `inputs.<token>\b` — the token being READ, as opposed to declared.
fn reads_input(text: &str, token: &str) -> bool {
    let needle = format!("inputs.{token}");
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(&needle) {
        let i = from + rel;
        let end = i + needle.len();
        let boundary = end >= text.len() || {
            let c = text.as_bytes()[end] as char;
            !c.is_alphanumeric() && c != '_'
        };
        if boundary {
            return true;
        }
        from = end;
    }
    false
}

/// `^\s+continue-on-error:\s*true`.
fn has_continue_on_error_true(text: &str) -> bool {
    text.lines().any(|l| {
        (l.starts_with(' ') || l.starts_with('\t'))
            && l.trim_start()
                .strip_prefix("continue-on-error:")
                .map(|v| v.trim() == "true")
                .unwrap_or(false)
    })
}

/// `^\s*uses:\s*\./\.github/workflows/docker\.yml\s*$` — a job that CALLS the local reusable
/// workflow.
///
/// READ THE WIRING, NOT THE MENTION. The two rules that use this used to ask whether a job passes
/// an input to the image workflow by testing whether the job text contained that file's name at
/// all — true of any job that names the file in a comment or inside a shell string. That substring
/// search standing in for a structural one mistook the promote-time attestation check for a
/// rebuild, because the flag that names WHO SIGNED the staged image names the same file.
fn calls_docker_workflow(job_text: &str) -> bool {
    job_text.lines().any(|l| {
        let t = l.trim_start();
        after_key(t, "uses")
            .map(|v| v.trim() == "./.github/workflows/docker.yml")
            .unwrap_or(false)
    })
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

/// `\.conclusion\s*==\s*"success"`.
fn asserts_conclusion_success(text: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(".conclusion") {
        let i = from + rel;
        from = i + ".conclusion".len();
        let rest = text[from..].trim_start();
        let Some(rest) = rest.strip_prefix("==") else {
            continue;
        };
        if rest.trim_start().starts_with("\"success\"") {
            return true;
        }
    }
    false
}

// -------------------------------------------------------------------------------------------
// THE GATE
// -------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ReleaseOrderGate;

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

    let release = read("release.yml");
    let stage = read("release-stage.yml");
    let docker = read("docker.yml");
    let verify = read("verify-deploy.yml");

    // R14. EVERY THIRD-PARTY ACTION RUNS FROM A COMMIT SHA, AND A TAG IS NOT A SHA.
    //
    // The dependabot config states this as a rule, at length, and nothing checked it. Every `uses:`
    // in the tree really is a 40-hex sha today, and reverting any one of them to a tag was proven
    // green against every lint in the structure job — a rule written down in a config file's
    // comment and enforced nowhere survives exactly as long as nobody is in a hurry. The scopes
    // that note names are why this is a release-order rule and not a style rule: an action that can
    // be force-moved under a name we already trust can push an image and mint an attestation, which
    // is to say it can put a user-facing name on bytes nothing in this repository ever built.
    //
    // LOCAL `uses:` IS EXEMPT, AND ONLY LOCAL. A `./` reference resolves inside this repository at
    // the caller's own commit; there is no third party and nothing to force-move.
    //
    // THE TRAILING TAG COMMENT IS PART OF THE PIN: without it Dependabot cannot tell what the sha
    // stands for and silently stops updating it, so the pin rots into a permanently stale,
    // unpatched version.
    for name in &names {
        let text = strip_comments(&read(name).unwrap_or_default());
        for line in text.lines() {
            let Some((reference, comment)) = parse_uses(line) else {
                continue;
            };
            if reference.starts_with("./") {
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

    // R2. THE TAG-ON-MAIN WORKFLOW MUST NOT COME BACK.
    // It read the manifest on a main push and pushed the tag immediately. Its version read and its
    // idempotency guard now live in the release workflow's `plan` job, which computes the same tag
    // but does not push it until the promote.
    if cx.exists(format!("{WORKFLOWS}/tag-on-main.yml")) {
        bad.push(Finding::new(
            "R2",
            format!(
            "{WORKFLOWS}/tag-on-main.yml exists again. That workflow pushed the version tag the \
             moment a commit landed on main, before anything was built - the exact order this \
             design removes. release.yml's `plan` job owns the version read now, and its \
             `promote-release` job owns pushing the tag, after verification."
        ),
        ));
    }

    let Some(release) = release else {
        bad.push(Finding::new(
            "R0",
            format!("{WORKFLOWS}/release.yml is missing."),
        ));
        return Ok(bad);
    };
    let rel = strip_comments(&release);
    let rjobs = jobs(&rel);

    let Some(stage) = stage else {
        bad.push(Finding::new(
            "R0",
            format!(
            "{WORKFLOWS}/release-stage.yml is missing. Without the qa staging workflow there is \
             nothing that builds and verifies release bytes, and release.yml (promote-only by \
             design) would have nothing honest to promote."
        ),
        ));
        return Ok(bad);
    };
    let stg = strip_comments(&stage);
    let sjobs = jobs(&stg);

    // R3. THE RELEASE MUST BE CREATED AS A DRAFT.
    // A draft has real, downloadable assets but does not resolve as the latest release, is not
    // listed, and materialises no git tag. That is what makes it safe to build against and safe to
    // abandon. Tag verification is called out because it is the flag the old flow used and it
    // CANNOT work here: there is no tag to verify.
    let draft_job = sjobs.get("draft").cloned().unwrap_or_default();
    if !has_draft_token(&draft_job) {
        bad.push(Finding::new(
            "R3",
            "release-stage.yml creates a GitHub Release without `--draft`. A non-draft release is \
             immediately listed and immediately resolves as the latest release, so the version is \
             public before verification - and publishing also materialises the git tag. On the qa \
             branch that would publish EVERY iteration.",
        ));
    }
    for (label, body) in [("release.yml", &rel), ("release-stage.yml", &stg)] {
        if body.contains("--verify-tag") {
            bad.push(Finding::new(
                "R3",
                format!(
                "{label} still passes `--verify-tag`. Under this design no tag exists when the \
                 release is created; the draft is anchored with `--target <sha>` instead."
            ),
            ));
        }
    }

    // R4. EVERY PROMOTE MUST BE DOWNSTREAM OF THE STAGED CONSUMER VERIFICATION.
    // This is the rule the whole restructure exists to state, and the graph is where that
    // dependency lives - there is no other place to assert it.
    for j in PROMOTE_JOBS {
        if !rjobs.contains_key(*j) {
            bad.push(Finding::new(
                "R4",
                format!("release.yml has no `{j}` job; the promote step is missing."),
            ));
        } else if !depends_on(&rjobs, j, RESOLVE_GATE) {
            bad.push(Finding::new(
                "R4",
                format!(
                "release.yml's `{j}` job does not depend, even transitively, on `{RESOLVE_GATE}`. \
                 Under the qa/main split the record re-verification IS the promote's gate: \
                 skipping it means minting a user-facing name over a digest nothing re-proved \
                 (absent, stale, or contradicted by the registry), which is the entire defect this \
                 design removes."
            ),
            ));
        }
    }
    // The other half of the same seam: the RECORD may only be written after the staged consumer
    // verification passed. A record written unconditionally would let the promote ship bytes whose
    // verification failed, with every check downstream still green.
    if !sjobs.contains_key("record-staged") {
        bad.push(Finding::new(
            "R4",
            "release-stage.yml has no `record-staged` job. Without the record there is no seam: \
             release.yml's resolve-staged would refuse every promote (fail-closed, but \
             permanently), or someone will 'fix' that by rebuilding on main.",
        ));
    } else if !depends_on(&sjobs, "record-staged", VERIFY_GATE) {
        bad.push(Finding::new(
            "R4",
            format!(
                "release-stage.yml's `record-staged` job does not depend, even transitively, on \
             `{VERIFY_GATE}`. The record is the promote's only input, so writing it before the \
             staged consumer verification passed publishes-by-proxy: main would happily retag a \
             digest whose verification failed."
            ),
        ));
    }

    // R5. THE STAGED VERIFICATION MUST ACTUALLY BE IN STAGING MODE, AGAINST THE STAGED IMAGE.
    // Calling the verification workflow without the staging stage would run the public sweep
    // against an unpublished version: it would fail on channels correctly still pointing at the
    // previous release, and the natural "fix" is to delete the gate. Omitting the image reference
    // is worse and quieter - the image checks would fall back to the PUBLISHED pin and go green on
    // the PREVIOUS release while claiming to have verified this one.
    let vs = sjobs.get(VERIFY_GATE).cloned().unwrap_or_default();
    if vs.is_empty() {
        bad.push(Finding::new("R5", format!(
            "release-stage.yml has no `{VERIFY_GATE}` job. The staged consumer verification is what \
             the recorded digest's credibility rests on; without it the record certifies an \
             unverified build."
        )));
    } else {
        if !vs.contains("stage: staging") {
            bad.push(Finding::new(
                "R5",
                format!(
                    "release-stage.yml's `{VERIFY_GATE}` job does not pass `stage: staging` to \
                 verify-deploy.yml. The public sweep asserts downstream channels that only move \
                 after publication, so it cannot be the pre-promote gate."
                ),
            ));
        }
        if !vs.contains("image_ref:") {
            bad.push(Finding::new(
                "R5",
                format!(
                "release-stage.yml's `{VERIFY_GATE}` job does not pass `image_ref`. Without it the \
                 image checks verify the PUBLISHED pin - the previous release - and pass while \
                 proving nothing about the artifact being cut."
            ),
            ));
        }
    }

    // R6. THE FAN-OUT MUST NOT FIRE BEFORE THE RELEASE IS REAL.
    // The fan-out tells every downstream repo to go and consume this release. Firing it off the
    // build jobs means telling nineteen repos to consume something that may never be promoted.
    if rjobs.contains_key("notify-downstream")
        && !depends_on(&rjobs, "notify-downstream", "promote-release")
    {
        bad.push(Finding::new(
            "R6",
            "release.yml's `notify-downstream` job does not depend on `promote-release`. The \
             fan-out would announce a release that is not published, so every downstream repo \
             would chase a version that does not exist yet or may never exist.",
        ));
    }

    // R7. THE IMAGE WORKFLOW MUST NOT EMIT A VERSION TAG FROM A BUILD.
    // A semver tag gated on an input is the exact shape that let a bare dispatch publish only a
    // throwaway name while a human believed a release had been rebuilt, and it is also the shape
    // that publishes the version straight out of a build. The moving pointer as a raw tag in the
    // build's tag block is the same defect for the pointer. Both names are created by the promote
    // job now, from bytes that have already been verified.
    match docker {
        None => bad.push(Finding::new(
            "R0",
            format!("{WORKFLOWS}/docker.yml is missing."),
        )),
        Some(docker) => {
            let dtext = strip_comments(&docker);
            let djobs = jobs(&dtext);
            let build_side: String = djobs
                .iter()
                .filter(|(j, _)| j.as_str() != "promote")
                .map(|(_, t)| t.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if build_side.contains("type=semver") {
                bad.push(Finding::new(
                    "R7",
                    "docker.yml emits `type=semver` from a build job. A build must never decide, \
                     on its own, that a version exists: that tag is immutable on the registry and \
                     cannot be taken back. Only the `promote` job may create `X.Y.Z`, from an \
                     already-verified digest.",
                ));
            }
            if build_side.contains("type=raw,value=latest") {
                bad.push(Finding::new(
                    "R7",
                    "docker.yml emits `latest` from a build job. `latest` is what a bare pull \
                     reads, so moving it from a build publishes an unverified image to every user \
                     who does not pin. Only the `promote` job may move it.",
                ));
            }
            if !djobs.contains_key("promote") {
                bad.push(Finding::new(
                    "R7",
                    "docker.yml has no `promote` job. The manifest-only retag is the primitive \
                     that lets `X.Y.Z` be the EXACT digest verification pulled and ran, rather \
                     than a second build that ought to match it.",
                ));
            }
        }
    }

    // R9. NOTHING IS RELEASED FROM A RED COMMIT, AND THERE IS NO WAY AROUND IT.
    //
    // The owner's decision was that nothing should ever be released red, nor ignored, and that
    // there is no permission for a logged human override. A sibling repository published a version
    // with red CI where the red sat on a list headed "known, tracked, not blocking", which is
    // ignoring with paperwork. So the gate must exist, everything must be downstream of it, and the
    // escape hatch must not exist - a waiver IS the permission-to-ignore mechanism.
    if !rjobs.contains_key("branch-green") {
        bad.push(Finding::new(
            "R9",
            "release.yml has no `branch-green` job. Nothing may be cut from a red commit, and the \
             gate cannot be a convention: it has to be a job every other job is downstream of.",
        ));
    } else {
        for j in PROMOTE_JOBS.iter().copied().chain([RESOLVE_GATE]) {
            if rjobs.contains_key(j) && !depends_on(&rjobs, j, "branch-green") {
                bad.push(Finding::new(
                    "R9",
                    format!(
                    "release.yml's `{j}` job is not downstream of `branch-green`, so it would run \
                     on a red commit."
                ),
                ));
            }
        }
    }
    // The stage workflow carries its own gate, and the expensive build must sit behind it for the
    // same reason the promote sits behind the release workflow's: nothing is built from a
    // known-red commit.
    if !sjobs.contains_key("branch-green") {
        bad.push(Finding::new(
            "R9",
            "release-stage.yml has no `branch-green` job. The staging build would run on a commit \
             already known red, spending the full PGO pipeline on bytes that cannot ship.",
        ));
    } else {
        for j in ["gate", "targets"] {
            if sjobs.contains_key(j) && !depends_on(&sjobs, j, "branch-green") {
                bad.push(Finding::new(
                    "R9",
                    format!(
                        "release-stage.yml's `{j}` job is not downstream of `branch-green`, so it \
                     would run on a red commit."
                    ),
                ));
            }
        }
    }
    // THE ABSENCE OF AN ESCAPE HATCH IS ITSELF THE RULE. These are the names such a hatch arrives
    // under; naming them here means adding one is a build failure with a message that explains why,
    // rather than a plausible-looking input nobody questions. Scoped to the trigger block (where an
    // input would be DECLARED) and to input READS, not to the file's prose: the refusal messages in
    // the gate say the words "no waiver" and "no bypass" out loud, on purpose, and a rule that
    // forbade the explanation of itself would be unfixable.
    const HATCHES: &[&str] = &[
        "override_red_ci",
        "allow_red",
        "force_release",
        "skip_ci_check",
        "ignore_red",
        "red_waiver",
        "release_waiver",
        "bypass_ci",
    ];
    for (label, body) in [("release.yml", &rel), ("release-stage.yml", &stg)] {
        let trigger_block = top_level_block(body, "on");
        for token in HATCHES {
            if has_indented_key(&trigger_block, token) || reads_input(body, token) {
                bad.push(Finding::new(
                    "R9",
                    format!(
                        "{label} declares or reads a `{token}` input. There is NO bypass of the \
                     red-branch gate: no override input, no force flag, no waiver, no exception \
                     list. That absence is the feature - a waiver IS the permission-to-ignore \
                     mechanism, and permission-to-ignore is what shipped a red release. If a check \
                     should not block a release, change or delete the CHECK."
                    ),
                ));
            }
        }
    }
    // Letting the gate continue on error is the silent version of the same thing: the job goes red,
    // the release carries on, and nothing downstream can tell.
    for (label, jb) in [("release.yml", &rjobs), ("release-stage.yml", &sjobs)] {
        if has_continue_on_error_true(jb.get("branch-green").map(String::as_str).unwrap_or("")) {
            bad.push(Finding::new(
                "R9",
                format!(
                    "{label}'s `branch-green` job sets `continue-on-error: true`, which turns the \
                 red-branch gate into a decoration: it reports red and the run proceeds anyway."
                ),
            ));
        }
    }

    // R10. MAIN NEVER REBUILDS, QA NEVER NAMES.
    // This is the split's own invariant, and the one an incident is most likely to erode: "just
    // rebuild it on main real quick" reintroduces the exact promoted-bytes-are-not-the-verified-
    // bytes defect the split was asked for, and a promote path in the stage workflow would mint
    // names on every qa iteration.
    for (marker, why) in [
        ("build-artifact.yml", "calls the binary build workflow"),
        ("pgo-build", "runs the PGO build script"),
        ("docker/build-push-action", "builds and pushes an image"),
        ("cargo build", "compiles"),
    ] {
        if rel.contains(marker) {
            bad.push(Finding::new(
                "R10",
                format!(
                "release.yml contains `{marker}` ({why}). release.yml is PROMOTE-ONLY: every byte \
                 it names must have been built, verified and recorded by release-stage.yml on \
                 `qa`. A build here ships bytes that are not what was QA'd - the exact defect the \
                 split removes. Build on qa; promote the record."
            ),
            ));
        }
    }
    for (j, jt) in &rjobs {
        let jt = strip_comments(jt);
        if calls_docker_workflow(&jt) && has_indented_key(&jt, "staging_tag") {
            bad.push(Finding::new(
                "R10",
                format!(
                "release.yml's `{j}` job passes `staging_tag:` to docker.yml, i.e. it asks for a \
                 fresh image BUILD on the main push. Main never rebuilds: the promote consumes the \
                 digest release-stage.yml recorded on qa."
            ),
            ));
        }
    }
    for (j, jt) in &sjobs {
        let jt = strip_comments(jt);
        if calls_docker_workflow(&jt) && has_indented_key(&jt, "promote_to") {
            bad.push(Finding::new(
                "R10",
                format!(
                    "release-stage.yml's `{j}` job passes `promote_to:` to docker.yml. The stage \
                 workflow must never mint `X.Y.Z`/`latest`: it runs on EVERY qa iteration, and \
                 only release.yml's promote (behind resolve-staged) may name bytes."
                ),
            ));
        }
    }
    if stg.contains("--draft=false") {
        bad.push(Finding::new(
            "R10",
            "release-stage.yml publishes the draft (`--draft=false`). Publishing is naming; it \
             belongs to release.yml's promote-release, after the record is re-proved.",
        ));
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

    // R12. THE FIRST GATE MUST NOT COLLAPSE THE RUN LIST TO ONE RUN PER WORKFLOW NAME.
    //
    // Keeping exactly one element per workflow name, over an API that returns runs newest-first,
    // means the NEWEST run of each name wins. A main push's own completion spawns a second run of
    // the qa workflow on the same sha whose jobs all skip, and a skip was counted green -- so a
    // genuinely red two-hour soak was replaced, at promote time, by an empty run of the same name.
    // Every run on the sha must be judged, and a required workflow must be selected by the branch
    // it ran on and required to have concluded success.
    //
    // EVERY JOB THAT FILTERS THE RUN LIST FOR THIS SHA, NOT JUST THE ONES THAT DID SO ON THE DAY
    // THIS RULE WAS WRITTEN. Hard-coding two job names is the exact drift this gate exists to stop
    // one level up: a third job added later that reads the run list would not be discovered and
    // could reintroduce the collapse in a place nobody is looking. So the check is over every job
    // whose body actually reads the run list for this commit, discovered by that shape.
    const RUN_LIST_MARKERS: &[&str] = &[".workflow_runs[]", "actions/runs?head_sha="];
    for (name, body) in &rjobs {
        if !RUN_LIST_MARKERS.iter().any(|m| body.contains(m)) {
            continue;
        }
        if body.contains("unique_by") {
            bad.push(Finding::new(
                "R12",
                format!(
                "release.yml's `{name}` job collapses the run list with `unique_by`. That keeps \
                 only the NEWEST run per workflow name, and a main push spawns a second, \
                 all-skipped qa run on the same sha - so a red qa soak reads green and the release \
                 promotes over it. Judge every run on the sha."
            ),
            ));
        }
    }
    let bg = rjobs.get("branch-green").cloned().unwrap_or_default();
    let promote_recheck = rjobs.get("promote-release").cloned().unwrap_or_default();
    if !bg.is_empty() {
        if !has_indented_key(&bg, "PROMOTE_SOURCE_BRANCH") {
            bad.push(Finding::new(
                "R12",
                "release.yml's `branch-green` job no longer selects the required workflow runs by \
                 the branch they ran on (`PROMOTE_SOURCE_BRANCH`). main's HEAD IS the qa commit, \
                 so both the qa-push run that carries the verdict and the main-push re-run that \
                 carries nothing are present on the sha; without the branch selection the empty \
                 one can satisfy the gate.",
            ));
        }
        // A REQUIRED WORKFLOW'S skipped/neutral CONCLUSION MUST NOT COUNT AS GREEN. Elsewhere in
        // this same gate a skip is correctly treated as green for an INCIDENTAL workflow -- but a
        // workflow named as required is being asked "did the soak actually run", and a skip answers
        // "no", not "yes, and it was fine".
        if !asserts_conclusion_success(&bg) {
            bad.push(Finding::new(
                "R12",
                "release.yml's `branch-green` job no longer asserts SUCCESS (as opposed to merely \
                 non-red) for each required workflow. Without that explicit check, \
                 `skipped`/`neutral` -- correctly green for an incidental workflow -- would also \
                 read as green for a REQUIRED one, so a qa gate that never ran on this commit \
                 could still reach promote-release looking green.",
            ));
        }
    }
    if !promote_recheck.is_empty() {
        let guarded = depends_on(&rjobs, "promote-release", "branch-green")
            || promote_recheck.contains("REQUIRED_WORKFLOWS");
        if !guarded {
            bad.push(Finding::new(
                "R12",
                "`promote-release` is no longer downstream of `branch-green` and does not assert \
                 REQUIRED_WORKFLOWS success itself. Its own red-check treats `skipped`/`neutral` \
                 as green for every name, which is only safe because `branch-green` already proved \
                 each required workflow concluded SUCCESS before promote-release could run; break \
                 that ordering and a required workflow's skip stops being caught at promote time \
                 too.",
            ));
        }
    }

    // R8. THE VERIFICATION WORKFLOW MUST STILL OFFER THE STAGING CONTRACT.
    // The release's gate is a call into that file. If the inputs go away the call breaks loudly,
    // but a rename that keeps the call syntactically valid while changing what it means would not,
    // so both halves of the contract are asserted here.
    match verify {
        None => bad.push(Finding::new(
            "R0",
            format!("{WORKFLOWS}/verify-deploy.yml is missing."),
        )),
        Some(verify) => {
            let v = strip_comments(&verify);
            for inp in ["stage:", "image_ref:"] {
                if !v.contains(inp) {
                    bad.push(Finding::new(
                        "R8",
                        format!(
                        "verify-deploy.yml no longer declares a `{}` input, so release.yml cannot \
                         run it as the pre-promote gate.",
                        inp.trim_end_matches(':')
                    ),
                    ));
                }
            }
        }
    }

    Ok(bad)
}

// -------------------------------------------------------------------------------------------
// THE GRAPH PROOF: WATCH THE DESIGN FAIL.
//
// The semantics reproduced here are the runner's own: a job runs when every job in its `needs:` has
// SUCCEEDED; a `needs:` on a failed or skipped job SKIPS the dependent, UNLESS the dependent carries
// a forgiving condition, in which case it runs anyway and must judge for itself. That last clause is
// not a detail: it is exactly what let one release's asset verification keep running after the build
// matrix went red, and it is exactly what must NOT appear on a promote job.
// -------------------------------------------------------------------------------------------

/// Job id -> `success` | `failure` | `skipped`, with `failed` forced to fail.
pub fn simulate(all: &BTreeMap<String, String>, failed: &str) -> BTreeMap<String, String> {
    let order: Vec<String> = all.keys().cloned().collect();
    let mut result: BTreeMap<String, String> = BTreeMap::new();
    for _ in 0..order.len() + 2 {
        for j in &order {
            if result.contains_key(j) {
                continue;
            }
            let body = &all[j];
            let deps = needs_of(body);
            if deps
                .iter()
                .any(|d| all.contains_key(d) && !result.contains_key(d))
            {
                continue;
            }
            let cond = if_block(body);
            let forgiving = cond.contains("always()") || cond.contains("!cancelled()");
            let upstream_bad = deps.iter().any(|d| {
                all.contains_key(d) && result.get(d).map(String::as_str) != Some("success")
            });
            let verdict = if upstream_bad && !forgiving {
                "skipped"
            } else if j == failed {
                "failure"
            } else if upstream_bad {
                // It runs, but a guard job whose upstream is broken is expected to REPORT the
                // breakage, i.e. go red itself.
                //
                // DELIBERATELY PESSIMISTIC. A job may carry a forgiving condition AND a further
                // clause that would really skip it, and this does not model that second clause. It
                // therefore reports such a job as RUNNING when the runner would skip it.
                // Over-reporting is the safe direction for a proof about what stays private: it can
                // only ever accuse the design of publishing too much, never excuse it.
                "failure"
            } else {
                "success"
            };
            result.insert(j.clone(), verdict.to_string());
        }
    }
    result
}

/// `^    if:.*(?:\n      .*)*` — the job-level condition and its continuation lines.
fn if_block(job_text: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut in_if = false;
    for line in job_text.lines() {
        if let Some(rest) = line.strip_prefix("    if:") {
            if !line.starts_with("     ") {
                in_if = true;
                out.push(rest);
                continue;
            }
        }
        if in_if {
            if line.starts_with("      ") {
                out.push(line);
            } else {
                in_if = false;
            }
        }
    }
    out.join(" ")
}

pub fn prove(cx: &Ctx) -> Result<Vec<String>, String> {
    let text = strip_comments(&cx.read(format!("{WORKFLOWS}/release.yml"))?);
    let all = jobs(&text);
    let mut broken: Vec<String> = Vec::new();
    for failed in ["branch-green", RESOLVE_GATE] {
        if !all.contains_key(failed) {
            broken.push(format!(
                "the graph proof cannot run: no job named `{failed}`. A proof over a graph that \
                 does not contain its own failure point proves nothing."
            ));
            continue;
        }
        let res = simulate(&all, failed);
        let ran_public: Vec<&str> = public_jobs()
            .into_iter()
            .filter(|(j, _)| res.get(*j).map(String::as_str) == Some("success"))
            .map(|(j, _)| j)
            .collect();
        if !ran_public.is_empty() {
            broken.push(format!(
                "if `{failed}` FAILS these public-name jobs still run: {}. A failure before the \
                 promote must leave NOTHING public.",
                ran_public.join(", ")
            ));
        }
    }
    Ok(broken)
}

impl Gate for ReleaseOrderGate {
    fn name(&self) -> &'static str {
        "release-order"
    }

    fn owed(&self) -> Vec<String> {
        RULES
            .iter()
            .map(|s| (*s).to_string())
            .chain([PROVE_ROW.to_string()])
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows: Vec<Row> = Vec::new();
        match check(cx) {
            Err(e) => {
                // The tree could not be READ. Every rule below is a ban, so reporting them
                // individually as passes over a scan that did not happen is the one answer this
                // gate must never give: one FAIL row per rule, naming the reason.
                for rule in RULES {
                    rows.push(Row::fail(*rule, "the workflow scan did not run", e.clone()));
                }
                rows.push(Row::fail(PROVE_ROW, "the workflow scan did not run", e));
                return Verdict::of(rows);
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
        match prove(cx) {
            Ok(broken) if broken.is_empty() => rows.push(Row::pass(
                PROVE_ROW,
                "at every failure point, nothing public runs",
                "no git tag, no listed release, no container version tag, no fan-out",
            )),
            Ok(broken) => rows.push(Row::fail(
                PROVE_ROW,
                "a failure somewhere in this graph still publishes",
                broken.join(" | "),
            )),
            Err(e) => rows.push(Row::fail(PROVE_ROW, "the graph proof could not be run", e)),
        }
        Verdict::of(rows)
    }

    /// THE SAME MUTATIONS, DRIVEN THROUGH BOTH IMPLEMENTATIONS.
    ///
    /// The legacy lint reads a tree on disk and takes a root, so each probe materializes the
    /// overlaid workflow directory into scratch and points the Python at it. Comparing on the real
    /// tree alone would compare one green against another; comparing on a violation the legacy
    /// script is known to catch is what proves the Rust caught the same thing for the same reason.
    ///
    /// The graph-proof probe is deliberately absent: the legacy script answers that question under
    /// a different flag, and a probe whose two sides are asking different questions is not a parity
    /// probe.
    fn parity_probes(&self, cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        let names = workflow_names(cx).unwrap_or_default();
        let materialize: Vec<String> = names
            .iter()
            .map(|n| format!("{WORKFLOWS}/{n}"))
            .collect::<Vec<_>>();
        let mut out = Vec::new();
        for m in mutations() {
            if m.rule == PROVE_ROW {
                continue;
            }
            let rel = format!("{WORKFLOWS}/{}", m.file);
            let mut ov = Overlay::new();
            let mut touched = materialize.clone();
            if m.creates {
                if cx.exists(&rel) {
                    continue;
                }
                ov.set(&rel, (m.apply)(""));
                touched.push(rel);
            } else {
                let Ok(original) = cx.read(&rel) else {
                    continue;
                };
                let mutated = (m.apply)(&original);
                if mutated == original {
                    continue;
                }
                ov.set(&rel, mutated);
            }
            out.push(crate::gates::ParityProbe {
                label: m.label.to_string(),
                overlay: ov,
                materialize: touched,
                expect_rule: Some(m.rule.to_string()),
                legacy_names: None,
                divergence: None,
            });
        }
        out
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

        // R0 — THE WORKFLOWS THIS GATE READS. Every mutation above EDITS a workflow; not one takes
        // a workflow away, so the rule that refuses a missing file was carried by the whole-tree
        // green alone and could have been deleted with `cargo xtask selftest` still passing. It is
        // the rule the rest of the gate rests on: a release.yml that is not there ends the scan,
        // and eight rules then report "no violation" over a scan that never happened.
        let mut ov = Overlay::new();
        ov.remove(format!("{WORKFLOWS}/release.yml"));
        report.push(prove_rows_red(
            cx,
            self,
            "the release workflow is gone, so the rules below it judged nothing",
            &["R0"],
            ov,
            &["release.yml is missing"],
        ));

        report
    }
}

fn owed_all() -> Vec<&'static str> {
    RULES.iter().copied().chain([PROVE_ROW]).collect()
}

fn rule_title(rule: &str) -> &'static str {
    match rule {
        "R0" => "the workflows this gate reads all exist",
        "R1" => "no workflow is triggered by a version tag",
        "R2" => "the tag-on-main workflow has not come back",
        "R3" => "the release is created as a draft",
        "R4" => "every promote is downstream of the staged consumer verification",
        "R5" => "the staged verification runs in staging mode against the staged image",
        "R6" => "the fan-out does not fire before the release is real",
        "R7" => "the image workflow emits no version tag from a build",
        "R8" => "the verification workflow still offers the staging contract",
        "R9" => "nothing is released from a red commit, and there is no way around it",
        "R10" => "main never rebuilds, qa never names",
        "R11" => "no workflow pushes a commit to a release branch",
        "R12" => "the first gate judges every run on the sha",
        "R14" => "every third-party action runs from a commit sha",
        "R15" => "every attestation verify names the workflow that signed",
        _ => "release-order rule",
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
// moved, the rule stops being proven while the selftest keeps printing a line about it -- which is
// exactly what happened when a pin bump removed a literal one mutation spliced itself in front of,
// leaving a rule unproven behind a standing red that said nothing about release order. The anchors
// below are therefore chosen to be structural (`steps:`, a `needs:` list) wherever a literal would
// do.
// -------------------------------------------------------------------------------------------

struct Mutation {
    label: &'static str,
    file: &'static str,
    rule: &'static str,
    apply: fn(&str) -> String,
    /// The mutation CREATES the file rather than editing it. Exactly one rule asserts a file's
    /// ABSENCE, so the only violation that exists for it is the file coming back.
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

/// Drop the first line whose trimmed form starts with `prefix`.
fn drop_line_starting(t: &str, prefix: &str) -> String {
    let mut done = false;
    t.lines()
        .filter(|l| {
            if !done && l.trim_start().starts_with(prefix) {
                done = true;
                return false;
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn mutations() -> Vec<Mutation> {
    vec![
        Mutation {
            // THE REGRESSION AS IT WOULD ACTUALLY ARRIVE: the verify is written the way the docs
            // and every README write it -- subject plus repository -- and it passes, on real
            // attested bytes, every time anyone tests it. It only fails to be a pipeline check on
            // the day someone else's workflow attests something. Proven on the PROMOTE, which is
            // the invocation standing between a staging tag and a user-facing version number.
            label: "R15 the promote's attestation check drops --signer-workflow",
            file: "release.yml",
            rule: "R15",
            apply: |t| drop_line_starting(t, "--signer-workflow "),
            creates: false,
        },
        Mutation {
            // The subtler half, and the one a careful reviewer produces: the flag is present and
            // names the workflow a human would call "the stager". The signer is the reusable
            // workflow the attest step lives in, so this spelling fails every verify and refuses
            // every promote -- green to read, red only in production.
            label: "R15 the signer is named as the CALLER instead of the attesting workflow",
            file: "release.yml",
            rule: "R15",
            apply: |t| {
                replace_once(
                    t,
                    "--signer-workflow GetBusbar/busbar/.github/workflows/docker.yml",
                    "--signer-workflow GetBusbar/busbar/.github/workflows/release-stage.yml",
                )
            },
            creates: false,
        },
        Mutation {
            // THE REGRESSION AS IT WOULD ACTUALLY ARRIVE: someone copies a snippet out of an
            // action's README, which is always written with the tag, and nothing anywhere notices.
            label: "R14 an action reverts from a sha to a force-movable tag",
            file: "docker.yml",
            rule: "R14",
            apply: |t| retag_first_pin(t, false),
            creates: false,
        },
        Mutation {
            // The quieter half. The sha stays a sha, so it still looks pinned; the tag comment
            // goes, so Dependabot stops bumping it and the pin rots in place.
            label: "R14 a pin loses the trailing tag comment Dependabot reads",
            file: "docker.yml",
            rule: "R14",
            apply: |t| retag_first_pin(t, true),
            creates: false,
        },
        Mutation {
            label: "R1 a v* tag trigger comes back",
            file: "release.yml",
            rule: "R1",
            apply: |t| {
                replace_once(
                    t,
                    "  push:\n    branches: [main]",
                    "  push:\n    tags:\n      - \"v*\"",
                )
            },
            creates: false,
        },
        Mutation {
            // THE SAME RULE, IN THE OTHER YAML SPELLING. The block form above was caught; this
            // flow form was not, and the runner treats the two identically.
            label: "R1 a v* tag trigger comes back as a FLOW sequence",
            file: "release.yml",
            rule: "R1",
            apply: |t| {
                replace_once(
                    t,
                    "  push:\n    branches: [main]",
                    "  push:\n    tags: [\"v*\"]",
                )
            },
            creates: false,
        },
        Mutation {
            // The refspec form the promote script documents, which the `HEAD:<dst>` test and the
            // no-refspec test both walked past. THE ANCHOR IS `steps:`, NOT A `uses:` LINE, AND
            // THAT IS THE POINT: a structural feature of every job in every workflow cannot be
            // renamed by a pin bump, an action major, or a formatting pass.
            label: "R11 a workflow pushes a refspec straight to main",
            file: "release.yml",
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
        Mutation {
            label: "R3 the release is created without --draft",
            file: "release-stage.yml",
            rule: "R3",
            apply: |t| drop_line_starting(t, "--draft"),
            creates: false,
        },
        Mutation {
            label: "R4 promote-image stops depending on the staged-record verification",
            file: "release.yml",
            rule: "R4",
            apply: |t| replace_once(t, "needs: [plan, resolve-staged]", "needs: [plan]"),
            creates: false,
        },
        Mutation {
            label: "R4 the staged record stops being gated on the staged verification",
            file: "release-stage.yml",
            rule: "R4",
            apply: |t| {
                replace_once(
                    t,
                    "needs: [plan, stage-image, verify-staged]",
                    "needs: [plan, stage-image]",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R5 the gate stops passing stage: staging",
            file: "release-stage.yml",
            rule: "R5",
            apply: |t| replace_once(t, "      stage: staging\n", ""),
            creates: false,
        },
        Mutation {
            label: "R5 the gate stops passing image_ref",
            file: "release-stage.yml",
            rule: "R5",
            apply: |t| drop_line_starting(t, "image_ref:"),
            creates: false,
        },
        Mutation {
            label: "R6 the fan-out is re-hung off the record resolution instead of the promote",
            file: "release.yml",
            rule: "R6",
            apply: |t| {
                replace_once(
                    t,
                    "  notify-downstream:\n    needs: [plan, promote-release]",
                    "  notify-downstream:\n    needs: [plan, resolve-staged]",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R7 a semver tag reappears in the image build",
            file: "docker.yml",
            rule: "R7",
            apply: |t| {
                replace_once(
                    t,
                    "            type=raw,value=test,enable=",
                    "            type=semver,pattern={{version}},value=v1.2.3\n            \
                     type=raw,value=test,enable=",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R7 the moving pointer reappears in the image build",
            file: "docker.yml",
            rule: "R7",
            apply: |t| {
                replace_once(
                    t,
                    "            type=raw,value=test,enable=",
                    "            type=raw,value=latest\n            type=raw,value=test,enable=",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R9 the red-branch gate is removed from the promote workflow",
            file: "release.yml",
            rule: "R9",
            apply: |t| replace_once(t, "  branch-green:\n", "  branch-yellow:\n"),
            creates: false,
        },
        Mutation {
            label: "R9 the record resolution stops depending on the red-branch gate",
            file: "release.yml",
            rule: "R9",
            apply: |t| {
                replace_once(
                    t,
                    "    needs: [plan, branch-green]\n    runs-on: ubuntu-latest\n    outputs:",
                    "    needs: [plan]\n    runs-on: ubuntu-latest\n    outputs:",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R9 the staging build stops depending on the red-branch gate",
            file: "release-stage.yml",
            rule: "R9",
            apply: |t| {
                replace_once(
                    t,
                    "    needs: [plan, branch-green]\n    runs-on: ubuntu-latest\n    services:",
                    "    needs: [plan]\n    runs-on: ubuntu-latest\n    services:",
                )
            },
            creates: false,
        },
        Mutation {
            // Inserted INTO the existing inputs block, not as a second `inputs:` key -- a mutation
            // that produced invalid YAML would go red for the wrong reason and prove nothing.
            label: "R9 an override input is added to bypass a red branch",
            file: "release.yml",
            rule: "R9",
            apply: |t| {
                replace_once(
                    t,
                    "      release_tag:\n",
                    "      override_red_ci:\n        description: reason\n      release_tag:\n",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R10 a fresh image build sneaks back into the main promote",
            file: "release.yml",
            rule: "R10",
            apply: |t| {
                replace_once(
                    t,
                    "      promote_to: ${{ needs['resolve-staged'].outputs.promote_version }}",
                    "      staging_tag: staging-oops\n      promote_to: ${{ \
                     needs['resolve-staged'].outputs.promote_version }}",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R10 a promote sneaks into the qa staging workflow",
            file: "release-stage.yml",
            rule: "R10",
            apply: |t| {
                replace_once(
                    t,
                    "      staging_tag: ${{ needs.plan.outputs.staging_tag }}",
                    "      promote_to: 9.9.9\n      staging_tag: ${{ \
                     needs.plan.outputs.staging_tag }}",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R12 the first gate goes back to keeping one run per workflow name",
            file: "release.yml",
            rule: "R12",
            apply: |t| {
                replace_once(
                    t,
                    "                | map({name, status, conclusion, event",
                    "                | unique_by(.name)\n                | map({name, status, \
                     conclusion, event",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R12 the first gate stops selecting the required runs by the branch they ran on",
            file: "release.yml",
            rule: "R12",
            apply: |t| drop_line_starting(t, "PROMOTE_SOURCE_BRANCH:"),
            creates: false,
        },
        Mutation {
            label: "R12 the first gate stops requiring SUCCESS for a required workflow",
            file: "release.yml",
            rule: "R12",
            apply: |t| {
                replace_once(
                    t,
                    r#"[.[] | select(.conclusion == "success")] | length"#,
                    "length",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R11 the proof-manifest job commits back to the branch it ran on",
            file: "ci.yml",
            rule: "R11",
            apply: |t| {
                replace_once(
                    t,
                    r#"git -C "$pub" push origin "HEAD:refs/heads/proof-manifests""#,
                    r#"git push origin "HEAD:${VERSION}""#,
                )
            },
            creates: false,
        },
        Mutation {
            label: "R11 a workflow pushes straight to main",
            file: "ci.yml",
            rule: "R11",
            apply: |t| {
                replace_once(
                    t,
                    r#"git -C "$pub" push origin "HEAD:refs/heads/proof-manifests""#,
                    "git push origin main",
                )
            },
            creates: false,
        },
        Mutation {
            label: "R8 the verification workflow drops the staging inputs",
            file: "verify-deploy.yml",
            rule: "R8",
            apply: |t| replace_once(t, "      image_ref:", "      unrelated_input:"),
            creates: false,
        },
        Mutation {
            // R2 asserts a FILE'S ABSENCE, so the mutation is creating it. `Overlay::set` on a path
            // the tree does not hold is exactly that.
            label: "R2 the tag-on-main workflow comes back",
            file: "tag-on-main.yml",
            rule: "R2",
            apply: |_| "name: tag-on-main\n".to_string(),
            creates: true,
        },
        Mutation {
            // THE GRAPH PROOF ITSELF MUST BE ABLE TO GO RED, and the way it goes red is the way
            // the old order actually worked: a promote that is not downstream of the gate runs
            // whatever the gate concluded. This overlaps the graph rules on purpose -- the point of
            // the proof is that it is a second, independent reading of the same edge, so a rule
            // deleted by hand does not take the evidence with it.
            label: "PROVE the promote stops depending on the record resolution",
            file: "release.yml",
            rule: PROVE_ROW,
            apply: |t| replace_once(t, "needs: [plan, resolve-staged]", "needs: [plan]"),
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
        let replacement = if drop_comment_only {
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
mod tests {
    use super::*;

    #[test]
    fn draft_flag_is_matched_as_a_whole_token() {
        // The defect this rule was rewritten for: `--draft=false` in the promote satisfied a
        // substring search for `--draft` in the create call.
        assert!(has_draft_token("gh release create --draft --target x"));
        assert!(!has_draft_token("gh release edit --draft=false"));
        assert!(!has_draft_token("gh release edit --drafty"));
    }

    #[test]
    fn both_yaml_spellings_of_a_tag_trigger_are_caught() {
        assert!(has_v_star_tag_trigger(
            "on:\n  push:\n    tags:\n      - \"v*\"\n"
        ));
        assert!(has_v_star_tag_trigger("on:\n  push:\n    tags: [\"v*\"]\n"));
        assert!(has_v_star_tag_trigger("on:\n  push:\n    tags: v*\n"));
        assert!(!has_v_star_tag_trigger(
            "on:\n  push:\n    branches: [main]\n"
        ));
    }

    #[test]
    fn a_refspec_destination_is_read_from_either_side() {
        assert_eq!(
            refspec_destination("git push origin main:main").as_deref(),
            Some("main")
        );
        assert_eq!(
            refspec_destination("git push origin \"HEAD:refs/heads/proof-manifests\"").as_deref(),
            Some("proof-manifests")
        );
        assert_eq!(
            refspec_destination("git push origin \"HEAD:${VERSION}\"").as_deref(),
            Some("${VERSION}")
        );
    }

    #[test]
    fn a_bare_release_branch_push_is_caught_but_a_lookalike_is_not() {
        assert!(pushes_bare_release_branch("git push origin main"));
        assert!(pushes_bare_release_branch("git push origin qa"));
        assert!(!pushes_bare_release_branch("git push origin main-docs"));
        assert!(!pushes_bare_release_branch("git push origin main:main"));
    }

    #[test]
    fn git_push_is_found_through_a_dash_c() {
        assert!(contains_git_push("run: git push origin x"));
        assert!(contains_git_push("git -C \"$pub\" push origin y"));
        assert!(!contains_git_push("echo pushing"));
        assert!(!contains_git_push("legit pushback"));
    }

    #[test]
    fn only_a_statement_counts_as_an_attestation_verify() {
        assert!(is_attestation_verify_statement("  gh attestation verify x"));
        assert!(is_attestation_verify_statement(
            "  if ! gh attestation verify x; then"
        ));
        assert!(!is_attestation_verify_statement(
            "  echo 'run gh attestation verify yourself'"
        ));
    }

    #[test]
    fn a_signer_value_stops_at_shell_punctuation() {
        assert_eq!(
            signer_value("gh attestation verify x --signer-workflow a/b.yml; then").as_deref(),
            Some("a/b.yml")
        );
        assert_eq!(
            signer_value("--signer-workflow=\"a/b.yml\"").as_deref(),
            Some("a/b.yml")
        );
        assert_eq!(signer_value("gh attestation verify x --repo o/r"), None);
    }

    #[test]
    fn a_pin_is_a_forty_hex_sha_and_nothing_else() {
        assert!(is_sha40("398d4b0eeef1380460a10c8013a76f728fb906ac"));
        assert!(!is_sha40("v3"));
        assert!(!is_sha40("398D4B0EEEF1380460A10C8013A76F728FB906AC"));
    }

    #[test]
    fn a_uses_line_yields_its_reference_and_its_trailing_tag_comment() {
        assert_eq!(
            parse_uses("      - uses: actions/checkout@abc # v7"),
            Some(("actions/checkout@abc".into(), Some("# v7".into())))
        );
        assert_eq!(
            parse_uses("      uses: ./.github/workflows/docker.yml"),
            Some(("./.github/workflows/docker.yml".into(), None))
        );
        assert_eq!(parse_uses("      run: cargo test"), None);
    }

    #[test]
    fn jobs_and_needs_come_out_of_indentation_alone() {
        let text = "\
name: x
jobs:
  a:
    runs-on: ubuntu-latest
  b:
    needs: [a]
    steps:
      - name: b:
        run: true
  c:
    needs: b
";
        let j = jobs(text);
        assert_eq!(
            j.keys().cloned().collect::<Vec<_>>(),
            vec!["a".to_string(), "b".into(), "c".into()]
        );
        assert_eq!(needs_of(&j["b"]), vec!["a".to_string()]);
        assert!(depends_on(&j, "c", "a"));
        assert!(!depends_on(&j, "a", "c"));
    }

    #[test]
    fn a_forgiving_condition_makes_a_job_run_over_a_failed_upstream() {
        let mut all = BTreeMap::new();
        all.insert("gate".to_string(), "  gate:\n".to_string());
        all.insert(
            "promote".to_string(),
            "  promote:\n    needs: [gate]\n".to_string(),
        );
        assert_eq!(simulate(&all, "gate")["promote"], "skipped");

        all.insert(
            "promote".to_string(),
            "  promote:\n    needs: [gate]\n    if: always()\n".to_string(),
        );
        // Forgiving, so it runs -- and a guard whose upstream is broken is expected to go red
        // itself rather than report success.
        assert_eq!(simulate(&all, "gate")["promote"], "failure");
    }

    #[test]
    fn the_gate_is_green_over_the_real_tree() {
        let cx = Ctx::workspace().expect("workspace context");
        let verdict = crate::gates::execute(&ReleaseOrderGate, &cx);
        assert!(
            !verdict.red,
            "release-order is RED over the real tree: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn every_rule_and_the_graph_proof_are_proven_able_to_go_red() {
        let cx = Ctx::workspace().expect("workspace context");
        let gate = ReleaseOrderGate;
        let report = gate.selftest(&cx);
        crate::gates::verify_report(&gate, &report).expect("every rule proven RED");
    }
}
