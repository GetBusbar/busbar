//! `cargo xtask conformance check` — the CI-FACING per-suite conformance admission command.
//!
//! This is the one command the pipeline shells to: ModernCI's `conformance` check on the
//! `dev` -> `qa` move (`.ci/dev.yaml`) runs it over a busbar checkout, as a local subprocess, never
//! a GitHub check-run. It answers exactly one question
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
//! `--musts` (and its alias `--suite all`) is the single call the `conformance` check makes to fold
//! every registered suite into one admit/deny fact. The MUST set is not a new registry field: the
//! owner's final, superseding ruling is that **every suite in the registry is a dev-green MUST**
//! (the owner's conformance-matrix re-scope: dev-green requires every MUST suite green, naming MCP,
//! A2A, WebSocket/Autobahn, HTTP2/h2spec, TLS/testssl, SLSA-verifier, the self-hosted OIDF OAuth2
//! run, FAPI2, jev and the language-model and voice suites), which enumerates the suites
//! `conformance/registry.toml` carries (a2a, mcp, the 6 llm-* suites, the 2 voice-* suites, fapi2,
//! h2, jev, oidf-oauth2, slsa-verifier, tls, ws, and the suites added since).
//! So `--musts` is "every suite the REGISTRY carries", not a filtered subset and not whatever the
//! manifest happens to hold: the registry is the denominator, a registered suite missing from the
//! manifest is refused and a manifest row the registry does not name is refused (Law 8: "An
//! instrument declares the set it measures over"). It has two FLOORS, both read through
//! [`crate::gates::conformance_sync::render::parse_registry`], and a registry that breaks either
//! denies `--musts` outright: every plane `qa/construction.toml` `[gate.plugin_kinds].plane` ships
//! owes at least one registered suite (`plane = "<key>"`), and the registered ids are exactly the
//! armed set (`SUITE_FLOOR`, Law 9: a floor only rises), so deleting any suite's block, one that
//! judges no plane included, cannot shrink the MUST set. Adding a suite to the registry adds it to
//! the MUST set, and arms it in the same commit.
//!
//! A manifest read from the checkout is also held to the verdict files it renders: a pass row is
//! admitted only if `conformance/verdicts/<suite>.json` exists, judges that suite, is `armed`, says
//! `pass` and is about the candidate sha. A suite id the manifest names twice is a refusal of the
//! whole manifest, so an earlier pass row can never outrank a later fail row.
//!
//! ## Freshness
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
  cargo xtask conformance check --selftest
  cargo xtask conformance record --suite <id>|--all [--recording <dir>] [--out <dir>]";

/// One resolved manifest row, as this command reads it. Deliberately narrower than
/// [`crate::gates::conformance_sync::render::Suite`] — this command reads only the registry's suite
/// ids (the `--musts` denominator), never tier ceilings or claim strings; per row it only asks
/// "pass, and about this commit".
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
        // The PRODUCER of the verdicts this command and `gate conformance-sync` read.
        Some("record") => crate::conformance_record::main(cx, &args[1..]),
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
    // A SUITE ID APPEARS ONCE. Resolving by `find` would let an earlier pass row beat a later fail
    // row for the same suite, so a manifest that names a suite twice admits nothing at all.
    let mut seen = std::collections::BTreeSet::new();
    for e in &out {
        if !seen.insert(e.suite.as_str()) {
            return Err(format!(
                "{path}: suite `{}` appears more than once — which row is the verdict cannot be \
                 told, so no suite in this manifest can be trusted",
                e.suite
            ));
        }
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

/// Where a suite's verdict artifact lives in the checkout.
fn verdict_path(suite: &str) -> String {
    format!(
        "{}/{suite}.json",
        gates::conformance_sync::render::VERDICT_DIR
    )
}

/// WHAT THE VERDICT ARTIFACT SAYS AGAINST THE MANIFEST ROW, or the reason it does not back it.
///
/// The manifest is a render of the verdicts, so a pass in it is only as good as the verdict under
/// it: that verdict must judge this suite, be ARMED (an unarmed rig did not judge), say `pass`, and
/// be about the candidate sha. A manifest read from the checkout (a relative `--manifest`) is held
/// to its verdicts; an absolute `--manifest` is a downloaded copy whose verdicts are not in this
/// checkout, so it is held to its own row alone.
fn verdict_refusal(cx: &Ctx, suite: &str, sha: &str) -> Option<String> {
    let path = verdict_path(suite);
    let text = match cx.read(&path) {
        Ok(t) => t,
        Err(e) => {
            return Some(format!(
                "the manifest says pass but {path} cannot be read ({e}): a pass with no verdict \
                 artifact under it is not evidence"
            ))
        }
    };
    let v: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return Some(format!("{path} is not valid JSON ({e})")),
    };
    let field = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default();
    if field("suite") != suite {
        return Some(format!(
            "{path} judges suite `{}`, not `{suite}`",
            field("suite")
        ));
    }
    if v.get("armed").and_then(Value::as_bool) != Some(true) {
        return Some(format!(
            "{path} is not armed: a rig that did not judge cannot back a pass"
        ));
    }
    if field("status") != "pass" {
        return Some(format!(
            "{path} says status `{}`, not `pass`, whatever the manifest row says",
            field("status")
        ));
    }
    if field("commit") != sha {
        return Some(format!(
            "{path} is about commit {}, not the candidate sha {}",
            short(field("commit")),
            short(sha)
        ));
    }
    None
}

/// One suite's admission fact: `status:"pass"` AND `commit == sha` (AND, for a manifest read from
/// the checkout, an armed passing verdict at that sha under it), or a refusal that names why.
fn admit(cx: &Ctx, manifest_path: &str, entry: &SuiteEntry, sha: &str) -> Row {
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
        Some(c) if c == sha => {
            if !std::path::Path::new(manifest_path).is_absolute() {
                if let Some(why) = verdict_refusal(cx, &entry.suite, sha) {
                    return Row::fail(
                        id,
                        format!("suite `{}` pass is not backed by its verdict", entry.suite),
                        why,
                    );
                }
            }
            Row::pass(
                id,
                format!("suite `{}` is a fresh pass", entry.suite),
                format!(
                    "manifest status pass, commit {} matches candidate sha {}",
                    short(c),
                    short(sha)
                ),
            )
        }
        Some(c) => Row::fail(
            id,
            format!("suite `{}` pass is STALE", entry.suite),
            format!(
                "verdict commit {} does not equal the candidate sha {} — a pass carried over from \
                 an older sha is refused: a pass is honoured only if its commit is the candidate \
                 sha. Re-run the suite on this sha.",
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
        Some(e) => admit(cx, manifest_path, e, sha),
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

/// The `--musts` arm: every suite the REGISTRY carries is a MUST (see module docs), and the
/// registry, not the manifest, is the denominator. One row per registered suite so a caller can see
/// exactly which MUST suite(s) are not fresh-pass: a registered suite the manifest does not carry is
/// a refusal, never a smaller set, and a manifest row the registry does not name is refused rather
/// than counted. The registry is read first: a registry that leaves a shipped plane with no suite
/// (the derived floor, [`crate::gates::conformance_sync::render::plane_roster`]) or drops an armed
/// suite (`SUITE_FLOOR`) denies the whole set, so the MUST set can never be made smaller.
fn check_musts(cx: &Ctx, manifest_path: &str, sha: &str) -> Vec<Row> {
    let registered: Vec<String> = match gates::conformance_sync::render::parse_registry(cx) {
        Ok(suites) => suites.into_iter().map(|s| s.id).collect(),
        Err(why) => {
            return vec![Row::fail(
                "conformance-check:registry",
                "the MUST set could not be derived from the registry",
                why,
            )]
        }
    };
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
    let mut rows: Vec<Row> = registered
        .iter()
        .map(|id| match entries.iter().find(|e| &e.suite == id) {
            Some(e) => admit(cx, manifest_path, e, sha),
            None => Row::fail(
                format!("conformance-check:{id}"),
                format!("MUST suite `{id}` is absent from the manifest"),
                format!(
                    "{} registers `{id}`, and every registered suite is a MUST; {manifest_path} \
                     carries no row for it, so it cannot be admitted. A manifest with a suite \
                     dropped admits nothing on the rest.",
                    gates::conformance_sync::render::REGISTRY_PATH
                ),
            ),
        })
        .collect();
    rows.extend(
        entries
            .iter()
            .filter(|e| !registered.contains(&e.suite))
            .map(|e| {
                Row::fail(
                    format!("conformance-check:{}", e.suite),
                    format!("`{}` is not a registered suite", e.suite),
                    format!(
                        "{manifest_path} carries `{}`, which {} does not register: a row nobody \
                         owes is refused rather than counted toward the MUST set. Registered \
                         suites: {}",
                        e.suite,
                        gates::conformance_sync::render::REGISTRY_PATH,
                        registered.join(", ")
                    ),
                )
            }),
    );
    rows
}
