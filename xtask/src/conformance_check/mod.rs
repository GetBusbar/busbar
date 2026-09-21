//! `cargo xtask conformance check` — the TURNSTILE-FACING per-suite conformance admission command.
//!
//! This is the one command the release pipeline's `busbar-release-turnstile` shells to as a
//! `CommandCheck` (`CONFORMANCE-GATES-PLAN.md` §1.3: turnstile drives everything as local
//! subprocesses over a busbar checkout, never GitHub check-runs). It answers exactly one question
//! per invocation — "is this suite a fresh green, right now, on this commit" — and answers it
//! deny-safe: every error path (missing manifest, unparseable manifest, unregistered suite id,
//! missing/absent verdict commit, a non-pass status, a stale pass) is a REFUSAL, never a silent 0.
//!
//! It is deliberately READ-ONLY over `conformance/manifest.json` and `conformance/verdicts/*.json`.
//! The gate that WRITES the manifest is `cargo xtask gate conformance-sync --write`
//! ([`crate::gates::conformance_sync`]); this command only loads what that gate already produced
//! and reconciled, so there is exactly one reader of the manifest schema
//! (`conformance/manifest.schema.json`) and one writer, never two disagreeing parsers.
//!
//! ## The MUST set
//!
//! `--musts` (and its alias `--suite all`) is the single call the turnstile board makes to fold
//! every registered suite into one admit/deny fact. The MUST set is not a new registry field: the
//! owner's final, superseding ruling is that **every suite in the registry is a dev-green MUST** —
//! `CONFORMANCE-MATRIX-RULING.md` lines 107-116 ("OWNER RE-SCOPE ... Supersedes all earlier
//! 'post-G / gates-at-promotion' framing ... Dev-green now REQUIRES: ALL MUST suites GREEN: MCP,
//! A2A (already), + WebSocket/Autobahn, HTTP2/h2spec, TLS/testssl, SLSA-verifier, OIDF OAuth2
//! self-hosted run, FAPI2 suite green, jev suite. LLM x6 + voice x2 already green."), which
//! enumerates exactly the 17 suites `conformance/registry.toml` carries today (a2a, mcp, the 6 llm-*
//! planes, the 2 voice-* planes, fapi2, h2, jev, oidf-oauth2, slsa-verifier, tls, ws). So `--musts`
//! is "every suite the manifest carries", not a filtered subset — adding a suite to the registry
//! auto-adds it to the MUST set, exactly the P4 "sixth platform auto-owes six rows" shape
//! (`CONFORMANCE-SYNC-DESIGN.md` §7) the sibling gate already relies on.
//!
//! ## Freshness (`CONFORMANCE-SYNC-DESIGN.md` §5.2)
//!
//! A suite is admitted iff its manifest row is `status:"pass"` AND its `commit` equals the
//! candidate sha — `--sha`, defaulting to `git rev-parse HEAD` of this checkout. A pass whose
//! `commit` does not match is a pass carried over from an older sha and is refused, never rendered
//! green here even though the manifest still shows `status:"pass"` (the manifest's own `freshness`
//! row polices the SAME rule at generation time; this command re-checks it at admission time
//! against the CANDIDATE sha, which may differ from the manifest's recorded `commit` when the
//! manifest predates the sha under test).

mod selftest;

use serde_json::Value;

use crate::ctx::Ctx;
use crate::gates;
use crate::ledger::{Row, Verdict};

/// Where the manifest lives when `--manifest` names nothing else.
pub const DEFAULT_MANIFEST_PATH: &str = "conformance/manifest.json";

const USAGE: &str = "\
usage:
  cargo xtask conformance check --suite <id> [--sha <sha>] [--manifest <path>] [--format=tsv]
  cargo xtask conformance check --musts       [--sha <sha>] [--manifest <path>] [--format=tsv]
  cargo xtask conformance check --suite all   [--sha <sha>] [--manifest <path>] [--format=tsv]
  cargo xtask conformance check --selftest";

/// One resolved manifest row, as this command reads it. Deliberately narrower than
/// [`crate::gates::conformance_sync::render::Suite`] — this command does not touch the registry,
/// tier ceilings or claim strings; it only asks "pass, and about this commit".
#[derive(Debug, Clone)]
struct SuiteEntry {
    suite: String,
    status: String,
    commit: Option<String>,
    reason: Option<String>,
}

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("check") => check_cmd(cx, &args[1..]),
        Some(other) => {
            eprintln!("xtask conformance: unknown subcommand `{other}`");
            eprintln!("{USAGE}");
            2
        }
        None => {
            eprintln!("xtask conformance: no subcommand named");
            eprintln!("{USAGE}");
            2
        }
    }
}

fn check_cmd(cx: &Ctx, args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--selftest") {
        return selftest::run(cx);
    }

    let tsv = args.iter().any(|a| a == "--format=tsv");
    let musts = args.iter().any(|a| a == "--musts");
    let suite = flag(args, "--suite");
    let manifest_path =
        flag(args, "--manifest").unwrap_or_else(|| DEFAULT_MANIFEST_PATH.to_string());
    let sha_flag = flag(args, "--sha");

    let want_musts = musts || suite.as_deref() == Some("all");
    if musts && suite.is_some() && suite.as_deref() != Some("all") {
        eprintln!(
            "xtask conformance check: --musts and --suite <id> name two different questions — \
             pass one or the other, not both."
        );
        eprintln!("{USAGE}");
        return 2;
    }
    if !want_musts && suite.is_none() {
        eprintln!(
            "xtask conformance check: no `--suite <id>` or `--musts` given — nothing to admit."
        );
        eprintln!("{USAGE}");
        return 2;
    }

    let sha = match sha_flag {
        Some(s) => s,
        None => match resolve_head(cx) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "xtask conformance check: could not resolve the candidate sha from `git rev-parse \
                     HEAD` and no --sha was given: {e}"
                );
                return 3;
            }
        },
    };

    let verdict = if want_musts {
        Verdict::of(check_musts(cx, &manifest_path, &sha))
    } else {
        Verdict::of(vec![check_one_suite(
            cx,
            &manifest_path,
            suite.as_deref().unwrap_or_default(),
            &sha,
        )])
    };

    if tsv {
        gates::print_rows_tsv(&verdict.rows);
    } else {
        gates::print_verdict("conformance-check", &verdict);
    }
    i32::from(verdict.red)
}

/// `--flag value` or `--flag=value`, whichever form was written.
fn flag(args: &[String], name: &str) -> Option<String> {
    let eq = format!("{name}=");
    for (i, a) in args.iter().enumerate() {
        if let Some(v) = a.strip_prefix(&eq) {
            return Some(v.to_string());
        }
        if a == name {
            return args.get(i + 1).cloned();
        }
    }
    None
}

fn resolve_head(cx: &Ctx) -> Result<String, String> {
    cx.git(&["rev-parse", "HEAD"]).map(|s| s.trim().to_string())
}

/// Load and validate the manifest's `suites` array. Every error here is deny-safe: the caller turns
/// `Err` into a single FAIL row, never a pass.
fn load_manifest(cx: &Ctx, path: &str) -> Result<Vec<SuiteEntry>, String> {
    let text = read_manifest_text(cx, path).map_err(|e| format!("{path}: {e}"))?;
    let v: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{path}: not valid JSON, so no suite in it can be trusted: {e}"))?;
    let arr = v.get("suites").and_then(Value::as_array).ok_or_else(|| {
        format!("{path}: no `suites` array — this does not read as a conformance manifest")
    })?;
    let mut out = Vec::new();
    for s in arr {
        let suite = s
            .get("suite")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{path}: a suite entry has no `suite` id"))?
            .to_string();
        let status = s
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("not-run")
            .to_string();
        let commit = s.get("commit").and_then(Value::as_str).map(str::to_string);
        let reason = s.get("reason").and_then(Value::as_str).map(str::to_string);
        out.push(SuiteEntry {
            suite,
            status,
            commit,
            reason,
        });
    }
    if out.is_empty() {
        return Err(format!(
            "{path}: the `suites` array is empty — an empty manifest admits nothing"
        ));
    }
    Ok(out)
}

/// `--manifest` may name an absolute path (a downloaded artifact copy outside the checkout); a
/// relative path is read through [`Ctx::read`] so the selftest's overlay still applies.
fn read_manifest_text(cx: &Ctx, path: &str) -> Result<String, String> {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        std::fs::read_to_string(p).map_err(|e| e.to_string())
    } else {
        cx.read(path)
    }
}

fn short(sha: &str) -> String {
    sha.chars().take(12).collect()
}

/// One suite's admission fact: `status:"pass"` AND `commit == sha`, or a refusal that names why.
fn admit(entry: &SuiteEntry, sha: &str) -> Row {
    let id = format!("conformance-check:{}", entry.suite);
    if entry.status != "pass" {
        return Row::fail(
            id,
            format!("suite `{}` is not a fresh pass", entry.suite),
            format!(
                "manifest status is `{}`, not `pass`{} — a suite that has not passed cannot be \
                 admitted.",
                entry.status,
                entry
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default()
            ),
        );
    }
    match &entry.commit {
        None => Row::fail(
            id,
            format!("suite `{}` pass carries no commit", entry.suite),
            "a pass with no recorded commit cannot be proven fresh — deny-safe.".to_string(),
        ),
        Some(c) if c == sha => Row::pass(
            id,
            format!("suite `{}` is a fresh pass", entry.suite),
            format!(
                "manifest status pass, commit {} matches candidate sha {}",
                short(c),
                short(sha)
            ),
        ),
        Some(c) => Row::fail(
            id,
            format!("suite `{}` pass is STALE", entry.suite),
            format!(
                "verdict commit {} does not equal the candidate sha {} — a pass carried over from \
                 an older sha is refused (CONFORMANCE-SYNC-DESIGN.md §5.2: 'a pass is honoured only \
                 if its commit == the release sha'). Re-run the suite on this sha.",
                short(c),
                short(sha)
            ),
        ),
    }
}

/// The single-suite arm. Resolves `id` against the manifest — not the registry — because the
/// manifest is drift-gated to set-equal the registry (`conformance:coverage`), so an id absent from
/// the manifest is either unregistered or the tree is already red for a reason this command is not
/// the one to re-diagnose; either way, deny.
fn check_one_suite(cx: &Ctx, manifest_path: &str, id: &str, sha: &str) -> Row {
    let entries = match load_manifest(cx, manifest_path) {
        Ok(e) => e,
        Err(why) => {
            return Row::fail(
                "conformance-check:manifest",
                "the manifest could not be loaded",
                why,
            )
        }
    };
    match entries.iter().find(|e| e.suite == id) {
        Some(e) => admit(e, sha),
        None => {
            let known: Vec<&str> = entries.iter().map(|e| e.suite.as_str()).collect();
            Row::fail(
                format!("conformance-check:{id}"),
                format!("`{id}` is not a registered suite"),
                format!(
                    "{manifest_path} carries no suite `{id}`. Refusing rather than silently passing \
                     an unknown name. Registered suites: {}",
                    known.join(", ")
                ),
            )
        }
    }
}

/// The `--musts` arm: every suite the manifest carries is a MUST (see module docs). One row per
/// suite so a caller can see exactly which MUST suite(s) are not fresh-pass.
fn check_musts(cx: &Ctx, manifest_path: &str, sha: &str) -> Vec<Row> {
    let entries = match load_manifest(cx, manifest_path) {
        Ok(e) => e,
        Err(why) => {
            return vec![Row::fail(
                "conformance-check:manifest",
                "the manifest could not be loaded",
                why,
            )]
        }
    };
    entries.iter().map(|e| admit(e, sha)).collect()
}
