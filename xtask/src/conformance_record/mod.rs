//! `cargo xtask conformance record` — the PRODUCER of `conformance/verdicts/<id>.json`.
//!
//! ARCHITECT ruling 2026-10-02 (W): `conformance:freshness` admits an armed pass only when its
//! `commit` equals `git rev-parse HEAD` of the judged checkout, and nothing produced such a file —
//! the committed verdicts were hand-stamped. This command is that producer. It runs each rig under
//! `testing/{llm,mcp,voice,ws,jev}-conformance` as the subprocess CI ran it, reads the rig's OWN
//! judgement (its exit codes and its report), and writes one `busbar.conformance.verdict/1` file per
//! registered suite that rig judges. Every suite the registry carries has a rig — the registry IS
//! the MUST set — so `--all` produces every verdict: llm x6, mcp, voice x2 and ws drive the rigs
//! under `testing/`; a2a drives its two instruments and its subject; h2 (h2spec), tls (testssl),
//! slsa-verifier and oidf-oauth2 + fapi2 (the self-hosted OIDF suite) drive the upstream tools
//! against a busbar built from this checkout; jev judges the decisions plane's battery and its
//! served bytes in Rust.
//!
//! THE THREE RULES THIS FILE EXISTS TO HOLD.
//!
//! * `commit` is resolved HERE, by `git rev-parse HEAD` of the checkout the rigs ran in, at write
//!   time. It is never a flag and never read from a rig's output (the ws parser and the jev rig
//!   each write a commit of their own; both are ignored). A HEAD that moved while the rigs ran, or a
//!   checkout whose tracked files differ from HEAD, judges something HEAD does not name, so every
//!   verdict of that run is `not-run`.
//! * A pass is written only for a rig that JUDGED: [`render_verdict`] refuses `pass` without
//!   `armed`, `armed` with `not-run`, and a `fail`/`not-run` with no reason. A rig that cannot run
//!   (a missing toolchain, no `--recording` for llm, a red self-test or control) is `not-run` with
//!   the reason, never a pass.
//! * A `fail` verdict is DATA, not an error: exit 0 means every targeted verdict was written,
//!   whatever its status. Exit 3 means at least one could not be written (no HEAD, an unreadable
//!   registry, an unwritable file, an incoherent outcome). Exit 2 is an argument error. These are
//!   the codes `cli.rs` documents for every xtask command.

mod a2a;
mod h2;
mod jev;
mod oidf;
mod rigs;
mod slsa;
mod subject;
mod tls;
mod upstream;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::ctx::Ctx;
use crate::gates::conformance_sync::render::{self, Suite};
use crate::gitp;

pub use a2a::{discriminates, governance_observed, NEGATIVE_PAIRS};
pub use h2::{decide_h2, junit_cases, Case, CaseResult, H2Run};
pub use jev::{decide_jev, is_jev_refusal, judge_jev_ledger, tests_passed, JevRun, REPORTED_UNITS};
pub use oidf::{
    decide_oidf, es256_jwk, module_results, oidf_plan_config, oidf_subject_config,
    rsa_jwk_from_pkcs8, OidfClient, OidfRun, RESOURCE_PATH as OIDF_RESOURCE_PATH,
    SUITES as OIDF_SUITES,
};
pub use rigs::{
    decide_legs, decide_llm, decide_voice, decide_ws, rig_for, Inputs, LlmRun, VoiceRun, WsRun,
    LLM_DIALECTS,
};
pub use slsa::{decide_slsa, provenance_commit, SlsaRun};
pub use subject::b64url;
pub use tls::{decide_tls, TlsRun};

/// The schema id every verdict carries (`conformance/verdicts/verdict.schema.json`, `title`).
pub const SCHEMA_ID: &str = "busbar.conformance.verdict/1";

const USAGE: &str = "\
usage:
  cargo xtask conformance record --suite <id> [--recording <dir>] [--slsa-artifact <file>
                                             --slsa-provenance <file>] [--out <dir>]
  cargo xtask conformance record --all        [the same flags]
    --recording  the oracle's candidate recording the llm rig judges (testing/shadow-oracle record
                 output); without it every llm-* verdict is not-run
    --slsa-artifact, --slsa-provenance
                 a busbar artifact built from HEAD and its SLSA provenance, minted by a trusted CI
                 builder; without both the slsa-verifier verdict is not-run
    --out        where <id>.json is written (default conformance/verdicts; relative to the checkout)
  exit: 0 every targeted verdict written (pass, fail or not-run), 2 bad arguments,
        3 a verdict could not be written";

/// A verdict's status, the schema's `status` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    NotRun,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::NotRun => "not-run",
        }
    }
}

/// What a rig decided about one suite, before it is stamped with a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    /// The rig judged busbar. `false` ⇒ the status can only be `not-run`.
    pub armed: bool,
    pub reason: Option<String>,
    /// The rig's own report, as a path relative to the checkout where it lies inside it.
    pub evidence: Option<String>,
}

impl Outcome {
    pub fn pass(evidence: impl Into<String>) -> Outcome {
        Outcome {
            status: Status::Pass,
            armed: true,
            reason: None,
            evidence: Some(evidence.into()),
        }
    }

    pub fn fail(reason: impl Into<String>, evidence: impl Into<String>) -> Outcome {
        Outcome {
            status: Status::Fail,
            armed: true,
            reason: Some(reason.into()),
            evidence: Some(evidence.into()),
        }
    }

    pub fn not_run(reason: impl Into<String>) -> Outcome {
        Outcome {
            status: Status::NotRun,
            armed: false,
            reason: Some(reason.into()),
            evidence: None,
        }
    }
}

/// `git rev-parse HEAD` of `root`. The ONE source of a verdict's `commit`.
pub fn head_commit(root: &Path) -> Result<String, String> {
    let sha = gitp::git(root, &["rev-parse", "--verify", "HEAD"])
        .map_err(|e| format!("`git rev-parse HEAD` failed: {e}"))?;
    let sha = sha.trim().to_string();
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "`git rev-parse HEAD` answered `{sha}`, not a sha — no verdict can name it"
        ));
    }
    Ok(sha)
}

/// Now, UTC, as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = crate::gates::changelog::civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        (s / 60) % 60,
        s % 60
    )
}

/// The verdict file's bytes, in the committed files' field order. Refuses an incoherent outcome
/// rather than writing it: a pass the rig did not judge, an armed not-run, a red with no reason.
pub fn render_verdict(
    suite: &Suite,
    outcome: &Outcome,
    commit: &str,
    generated_at: &str,
) -> Result<String, String> {
    let id = &suite.id;
    match (outcome.status, outcome.armed) {
        (Status::Pass, false) => {
            return Err(format!(
                "`{id}`: refusing to write `pass` for a rig that did not judge (armed=false)"
            ))
        }
        (Status::NotRun, true) => {
            return Err(format!(
            "`{id}`: refusing to write an armed `not-run` — a rig that judged has a pass or a fail"
        ))
        }
        _ => {}
    }
    let reason = outcome.reason.as_deref().filter(|r| !r.trim().is_empty());
    if outcome.status != Status::Pass && reason.is_none() {
        return Err(format!(
            "`{id}`: refusing to write `{}` with no reason",
            outcome.status.as_str()
        ));
    }
    if commit.trim().is_empty() {
        return Err(format!(
            "`{id}`: refusing to write a verdict with no commit"
        ));
    }
    let q = |s: &str| serde_json::to_string(s).expect("a str always serializes");
    let mut fields: Vec<(&str, String)> = vec![
        ("schema", q(SCHEMA_ID)),
        ("suite", q(id)),
        ("standard", q(&suite.standard)),
        ("plan", q(&suite.plan)),
        ("status", q(outcome.status.as_str())),
        ("armed", outcome.armed.to_string()),
        ("commit", q(commit)),
    ];
    if let Some(ev) = outcome.evidence.as_deref().filter(|e| !e.is_empty()) {
        fields.push(("evidence", q(ev)));
    }
    fields.push(("generated_at", q(generated_at)));
    if let Some(r) = reason {
        fields.push(("reason", q(r)));
    }
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("  \"{k}\": {v}"))
        .collect();
    Ok(format!("{{\n{}\n}}\n", body.join(",\n")))
}

/// Stamp `outcome` with `root`'s HEAD and now, and write `<out_dir>/<suite>.json`.
pub fn write_verdict(
    root: &Path,
    out_dir: &Path,
    suite: &Suite,
    outcome: &Outcome,
) -> Result<PathBuf, String> {
    let commit = head_commit(root)?;
    let text = render_verdict(suite, outcome, &commit, &utc_now())?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let path = out_dir.join(format!("{}.json", suite.id));
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// `--flag value` or `--flag=value`.
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

fn usage_error(msg: &str) -> i32 {
    eprintln!("xtask conformance record: {msg}");
    eprintln!("{USAGE}");
    2
}

fn absolute(root: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

/// Tracked files that differ from HEAD, outside the verdict directories this run writes. A
/// non-empty answer means HEAD does not name the tree the rigs would judge.
fn tracked_drift(root: &Path, out_dir: &Path) -> Result<Vec<String>, String> {
    let out_rel = out_dir
        .strip_prefix(root)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"));
    let text = gitp::git(root, &["status", "--porcelain", "--untracked-files=no"])?;
    Ok(text
        .lines()
        .filter_map(|l| l.get(3..))
        .map(str::to_string)
        .filter(|p| {
            !p.starts_with(&format!("{}/", render::VERDICT_DIR))
                && out_rel
                    .as_deref()
                    .is_none_or(|o| o.is_empty() || !p.starts_with(&format!("{o}/")))
        })
        .collect())
}

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    const KNOWN: &[&str] = &[
        "--suite",
        "--all",
        "--recording",
        "--slsa-artifact",
        "--slsa-provenance",
        "--out",
    ];
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let name = a.split('=').next().unwrap_or(a);
        if !KNOWN.contains(&name) {
            return usage_error(&format!(
                "unknown argument `{a}` (the commit is never an argument: it is this checkout's HEAD)"
            ));
        }
        i += if a.contains('=') || name == "--all" {
            1
        } else {
            2
        };
    }
    let all = args.iter().any(|a| a == "--all");
    let one = flag(args, "--suite");
    let target = match (all, one) {
        (true, Some(_)) => return usage_error("--suite and --all are two different requests"),
        (false, None) => return usage_error("name a suite (--suite <id>) or --all"),
        (true, None) => None,
        (false, Some(id)) => Some(id),
    };

    let root = cx.root().to_path_buf();
    let suites = match render::parse_registry(cx) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask conformance record: the registry could not be read: {e}");
            return 3;
        }
    };
    let selected: Vec<&Suite> = match &target {
        None => suites
            .iter()
            .filter(|s| rigs::rig_for(&s.id).is_some())
            .collect(),
        Some(id) => match suites.iter().find(|s| &s.id == id) {
            None => {
                let known: Vec<&str> = suites.iter().map(|s| s.id.as_str()).collect();
                return usage_error(&format!(
                    "`{id}` is not a registered suite (registered: {})",
                    known.join(", ")
                ));
            }
            Some(s) if rigs::rig_for(&s.id).is_none() => {
                return usage_error(&format!(
                    "`{id}` is registered but no rig judges it; a registered suite is a MUST and \
                     needs one"
                ));
            }
            Some(s) => vec![s],
        },
    };

    let out_dir = absolute(
        &root,
        &flag(args, "--out").unwrap_or_else(|| render::VERDICT_DIR.to_string()),
    );
    let inputs = rigs::Inputs {
        recording: flag(args, "--recording").map(|r| absolute(&root, &r)),
        slsa_artifact: flag(args, "--slsa-artifact").map(|r| absolute(&root, &r)),
        slsa_provenance: flag(args, "--slsa-provenance").map(|r| absolute(&root, &r)),
    };

    let start_head = match head_commit(&root) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("xtask conformance record: no verdict can be written: {e}");
            return 3;
        }
    };
    let blocked = match tracked_drift(&root, &out_dir) {
        Ok(d) if d.is_empty() => None,
        Ok(d) => Some(format!(
            "the checkout's tracked files differ from HEAD {} ({}), so HEAD does not name what \
             would be judged",
            &start_head[..12],
            d.join(", ")
        )),
        Err(e) => Some(format!(
            "`git status` failed, so the judged tree is unknown: {e}"
        )),
    };

    // One run per rig, however many of its suites were asked for.
    let mut by_rig: BTreeMap<rigs::Rig, Vec<&Suite>> = BTreeMap::new();
    for s in selected {
        if let Some(r) = rigs::rig_for(&s.id) {
            by_rig.entry(r).or_default().push(s);
        }
    }
    let runner = rigs::Runner::new(&root, &inputs);
    let mut unwritten = 0;
    for (rig, suites) in by_rig {
        let outcomes = match &blocked {
            Some(why) => suites
                .iter()
                .map(|s| (s.id.clone(), Outcome::not_run(why.clone())))
                .collect(),
            None => runner.run(rig),
        };
        let moved = match head_commit(&root) {
            Ok(h) if h == start_head => None,
            Ok(h) => Some(format!(
                "HEAD moved from {} to {} while the rig ran; the judgement names neither",
                &start_head[..12],
                &h[..12]
            )),
            Err(e) => Some(e),
        };
        for s in suites {
            let outcome = match (&moved, outcomes.get(&s.id)) {
                (Some(why), _) => Outcome::not_run(why.clone()),
                (None, Some(o)) => o.clone(),
                (None, None) => Outcome::not_run(format!(
                    "the {} rig returned no outcome for `{}`",
                    rig.name(),
                    s.id
                )),
            };
            match write_verdict(&root, &out_dir, s, &outcome) {
                Ok(p) => println!(
                    "conformance record: {:<22} {:<7} {}{}",
                    s.id,
                    outcome.status.as_str(),
                    p.display(),
                    outcome
                        .reason
                        .as_deref()
                        .map(|r| format!("\n    {r}"))
                        .unwrap_or_default()
                ),
                Err(e) => {
                    unwritten += 1;
                    eprintln!("conformance record: {}: NOT WRITTEN: {e}", s.id);
                }
            }
        }
    }
    if unwritten > 0 {
        eprintln!("conformance record: {unwritten} verdict(s) could not be written");
        3
    } else {
        0
    }
}
