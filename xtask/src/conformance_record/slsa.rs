//! THE slsa-verifier RIG — SLSA provenance (v1.0) verified by `slsa-verifier`, the SLSA project's
//! own verifier, over a busbar artifact built from THIS checkout and its provenance.
//!
//! WHAT IT VERIFIES: `slsa-verifier verify-artifact <artifact> --provenance-path <provenance>
//! --source-uri github.com/GetBusbar/busbar --print-provenance`. slsa-verifier checks the
//! signature chain, the trusted builder and that the provenance's subject digest is the artifact's.
//! This rig adds the one thing slsa-verifier is not told: the provenance's SOURCE COMMIT must be
//! this checkout's HEAD. A valid provenance for another commit is a fail, because the verdict is
//! stamped with HEAD and would otherwise vouch for bytes HEAD did not build.
//!
//! WHERE THE ARTIFACT COMES FROM is not this rig's to decide: provenance is minted by a trusted
//! builder in CI (keyless, OIDC), never on a developer box. The caller hands both files in with
//! `--slsa-artifact` and `--slsa-provenance`; with neither, the suite is `not-run` and says so.
//! Which job mints them at the predev/dev hop is an open ARCHITECT/owner question (lane handoff
//! CONFORMANCE-RIGS.md).

use serde_json::Value;

use super::rigs::{rc, Rig, Runner};
use super::Outcome;

/// The repository whose provenance is accepted.
pub const SOURCE_URI: &str = "github.com/GetBusbar/busbar";
/// slsa-verifier, when the runner has no binary on PATH: `go run` at this pinned release.
pub const VERIFIER_MODULE: &str =
    "github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1";

/// What the rig measured.
#[derive(Debug, Clone)]
pub struct SlsaRun {
    /// `Err` = the inputs were not handed in, and which.
    pub inputs: Result<(), String>,
    pub exit: Option<i32>,
    /// slsa-verifier's output: the verified provenance statement (`--print-provenance`) and its
    /// own PASSED/FAILED line.
    pub output: String,
    pub head: String,
    pub evidence: String,
}

/// The source commit an in-toto SLSA statement names: v1.0
/// `predicate.buildDefinition.resolvedDependencies[].digest.gitCommit`, or v0.2
/// `predicate.invocation.configSource.digest.sha1`.
pub fn provenance_commit(statement: &Value) -> Option<String> {
    let p = statement.get("predicate")?;
    if let Some(deps) = p
        .pointer("/buildDefinition/resolvedDependencies")
        .and_then(Value::as_array)
    {
        if let Some(c) = deps
            .iter()
            .find_map(|d| d.pointer("/digest/gitCommit").and_then(Value::as_str))
        {
            return Some(c.to_string());
        }
    }
    p.pointer("/invocation/configSource/digest/sha1")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The first JSON object in `text` that parses as an in-toto statement.
fn statement_in(text: &str) -> Option<Value> {
    text.lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .find(|v| v.get("predicate").is_some())
}

pub fn decide_slsa(run: &SlsaRun) -> Outcome {
    if let Err(why) = &run.inputs {
        return Outcome::not_run(why.clone());
    }
    let Some(code) = run.exit else {
        return Outcome::not_run("slsa-verifier did not run to an exit");
    };
    let last = run
        .output
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .to_string();
    if code != 0 {
        return Outcome::fail(
            format!(
                "slsa-verifier refused the provenance ({}): {last}",
                rc(Some(code))
            ),
            run.evidence.clone(),
        );
    }
    let Some(statement) = statement_in(&run.output) else {
        return Outcome::fail(
            "slsa-verifier passed but printed no provenance statement, so its source commit cannot \
             be held to HEAD",
            run.evidence.clone(),
        );
    };
    match provenance_commit(&statement) {
        Some(c) if c.eq_ignore_ascii_case(&run.head) => Outcome::pass(run.evidence.clone()),
        Some(c) => Outcome::fail(
            format!(
                "the provenance is valid but names source commit {c}, not HEAD {}",
                run.head
            ),
            run.evidence.clone(),
        ),
        None => Outcome::fail(
            "the verified provenance names no source commit",
            run.evidence.clone(),
        ),
    }
}

impl Runner {
    pub(super) fn run_slsa(&self) -> Outcome {
        let rig = Rig::Slsa;
        let dir = self.work_dir(rig);
        let head = super::head_commit(&self.root).unwrap_or_default();
        let mut run = SlsaRun {
            inputs: Ok(()),
            exit: None,
            output: String::new(),
            head,
            evidence: self.rel(&dir.join("verify.log")),
        };
        let (artifact, provenance) = match (
            self.inputs.slsa_artifact.as_deref(),
            self.inputs.slsa_provenance.as_deref(),
        ) {
            (Some(a), Some(p)) if a.is_file() && p.is_file() => (a, p),
            (a, p) => {
                run.inputs = Err(format!(
                    "no attested artifact of HEAD was handed in (--slsa-artifact {}, \
                     --slsa-provenance {}): provenance is minted by a trusted CI builder, and no \
                     job of this run minted one",
                    a.map_or("absent".to_string(), |x| x.display().to_string()),
                    p.map_or("absent".to_string(), |x| x.display().to_string()),
                ));
                return decide_slsa(&run);
            }
        };
        let tool: Vec<String> = if super::rigs::on_path("slsa-verifier") {
            vec!["slsa-verifier".into()]
        } else if super::rigs::on_path("go") {
            vec!["go".into(), "run".into(), VERIFIER_MODULE.into()]
        } else {
            return Outcome::not_run(
                "the slsa-verifier rig cannot run here: neither slsa-verifier nor go is on PATH",
            );
        };
        let mut argv = tool;
        argv.extend([
            "verify-artifact".to_string(),
            artifact.to_string_lossy().into_owned(),
            "--provenance-path".to_string(),
            provenance.to_string_lossy().into_owned(),
            "--source-uri".to_string(),
            SOURCE_URI.to_string(),
            "--print-provenance".to_string(),
        ]);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        run.exit = self.leg(rig, "verify", &argv, None, &[]);
        run.output = self.log_text(rig, "verify");
        decide_slsa(&run)
    }
}
