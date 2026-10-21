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
//! builder (keyless, OIDC), never on a developer box and never under a key of our own. The SIGNER
//! is GetBusbar/busbar's own GitHub Actions workflow `slsa-dev-provenance` on each push to `dev`
//! (ARCHITECT rulings 2026-10-17, option A1, and 2026-10-20): slsa-github-generator's generic
//! generator over the `busbar` it builds at that commit. The HAND-OFF is that run's own artifacts
//! ([`hand_off`]): `busbar-linux-<arch>` holding `busbar-linux-<arch>-<sha>`, and
//! `busbar-slsa-provenance` holding `busbar-linux-<sha>.intoto.jsonl` (one statement naming both
//! binaries). No release and no other repository is involved.
//!
//! The rig finds the `slsa-dev-provenance` run whose head_sha is HEAD ([`run_state`]); while it is
//! queued or in progress it waits, polling every [`RUN_POLL_SECS`] seconds for at most
//! [`RUN_WAIT_CAP_SECS`] ([`next_step`]); then it downloads the two artifacts (zip) and extracts
//! the pair ([`artifact_urls`]). The download needs a token with actions:read on GetBusbar/busbar
//! even though the repository is public ([`token_from`]: `BUSBAR_RELEASE_TOKEN`, else `GH_TOKEN`,
//! else `GITHUB_TOKEN`). The caller may instead hand both files in with `--slsa-artifact` and
//! `--slsa-provenance`. No token, no run for HEAD, a run that did not succeed, a missing or expired
//! artifact, or a run still unfinished at the cap: the suite is `not-run` and says which. Never a
//! pass, never a fallback.

use serde_json::Value;

use super::rigs::{rc, Rig, Runner};
use super::Outcome;

/// The repository whose provenance is accepted.
pub const SOURCE_URI: &str = "github.com/GetBusbar/busbar";
/// The branch whose builds are attested: the generator runs on each push to it.
pub const SOURCE_BRANCH: &str = "dev";
/// The repository whose Actions run signs dev's builds, and the workflow file that does it.
pub const SIGNER_REPO: &str = "GetBusbar/busbar";
pub const SIGNER_WORKFLOW: &str = "slsa-dev-provenance.yml";
/// The run artifact holding the signed provenance (`.github/workflows/slsa-dev-provenance.yml`,
/// job `hand-off`).
pub const PROVENANCE_ARTIFACT: &str = "busbar-slsa-provenance";
/// How often the rig asks again while HEAD's run is queued or in progress, and the most it waits
/// in all: 60 seconds, 60 minutes (the run builds two release binaries; the `conformance` check
/// reaches this rig hours after the push that started it, so the wait is the exception).
pub const RUN_POLL_SECS: u64 = 60;
pub const RUN_WAIT_CAP_SECS: u64 = 60 * 60;
/// The environment the token is read from, in order (as `bin/oracle` reads it).
pub const TOKEN_VARS: [&str; 3] = ["BUSBAR_RELEASE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];
/// What the token must be able to do.
pub const TOKEN_NEED: &str = "a token with actions:read on GetBusbar/busbar";

/// THE NAMES the `slsa-dev-provenance` run hands HEAD's build off under, for `arch` (`x86_64`,
/// `aarch64`): each artifact and the one file the rig takes out of its zip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandOff {
    pub binary_artifact: String,
    pub binary_file: String,
    pub provenance_artifact: String,
    pub provenance_file: String,
}

#[must_use]
pub fn hand_off(arch: &str, head: &str) -> HandOff {
    HandOff {
        binary_artifact: format!("busbar-linux-{arch}"),
        binary_file: format!("busbar-linux-{arch}-{head}"),
        provenance_artifact: PROVENANCE_ARTIFACT.to_string(),
        provenance_file: format!("busbar-linux-{head}.intoto.jsonl"),
    }
}

/// The token and the variable it came from: the first of [`TOKEN_VARS`] `lookup` finds non-empty.
///
/// # Errors
/// None is set: the reason names the token the rig needs.
pub fn token_from(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(&'static str, String), String> {
    TOKEN_VARS
        .iter()
        .find_map(|k| lookup(k).filter(|v| !v.is_empty()).map(|v| (*k, v)))
        .ok_or_else(|| {
            format!(
                "no token to download HEAD's attested build from the {SIGNER_WORKFLOW} run's \
                 artifacts: set {} to {TOKEN_NEED} (artifact downloads need one even on a public \
                 repository)",
                TOKEN_VARS.join(", ")
            )
        })
}

/// Where HEAD's `slsa-dev-provenance` run stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunState {
    /// A run for HEAD succeeded: its id.
    Ready(u64),
    /// A run for HEAD is not finished: its id and status (`queued`, `in_progress`, ...).
    Pending(u64, String),
    /// No run for HEAD can hand a build off, and why.
    Refused(String),
}

/// HEAD's run, read from the API's `workflow_runs` list (newest first). A successful run wins; else
/// an unfinished one is waited for; else the newest run's conclusion is the reason.
#[must_use]
pub fn run_state(runs: &Value, head: &str) -> RunState {
    let mine: Vec<&Value> = runs
        .get("workflow_runs")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter(|r| {
                    r.get("head_sha")
                        .and_then(Value::as_str)
                        .is_some_and(|h| h.eq_ignore_ascii_case(head))
                })
                .collect()
        })
        .unwrap_or_default();
    let id = |r: &Value| r.get("id").and_then(Value::as_u64).unwrap_or(0);
    let field = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    if let Some(r) = mine
        .iter()
        .find(|r| field(r, "status") == "completed" && field(r, "conclusion") == "success")
    {
        return RunState::Ready(id(r));
    }
    if let Some(r) = mine.iter().find(|r| field(r, "status") != "completed") {
        return RunState::Pending(id(r), field(r, "status"));
    }
    match mine.first() {
        None => RunState::Refused(format!(
            "{SIGNER_REPO} has no {SIGNER_WORKFLOW} run for HEAD {head}: the workflow signs each \
             push to dev, so HEAD's build is unattested"
        )),
        Some(r) => RunState::Refused(format!(
            "{SIGNER_REPO}'s {SIGNER_WORKFLOW} run {} for HEAD {head} concluded `{}`, so it handed \
             off no attested build",
            id(r),
            field(r, "conclusion")
        )),
    }
}

/// The API's answer to one request, read as the rig's reason when it is not a 2xx. 401 and 403 are
/// the token's: it is absent from the request or lacks Actions: read on GetBusbar/busbar (ModernCI
/// hands the `conformance` check BUSBAR_RELEASE_TOKEN alone, and that scope is the owner's to
/// grant), never a pass.
///
/// # Errors
/// Any status outside 200..=299, with the reason.
pub fn http_answer(code: u16, token_var: &str, what: &str) -> Result<(), String> {
    match code {
        200..=299 => Ok(()),
        401 | 403 => Err(format!(
            "the GitHub API refused {what} with HTTP {code}: the token in {token_var} lacks \
             Actions: read on GetBusbar/busbar ({TOKEN_NEED} is needed), so HEAD's attested build \
             cannot be fetched"
        )),
        0 => Err(format!("{what}: no HTTP answer")),
        c => Err(format!("the GitHub API answered {what} with HTTP {c}")),
    }
}

/// What the rig does next with HEAD's run, `waited` seconds into its wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Fetch(u64),
    Wait,
    Stop(String),
}

#[must_use]
pub fn next_step(state: RunState, waited: u64, head: &str) -> Step {
    match state {
        RunState::Ready(id) => Step::Fetch(id),
        RunState::Pending(_, _) if waited < RUN_WAIT_CAP_SECS => Step::Wait,
        RunState::Pending(id, status) => Step::Stop(format!(
            "{SIGNER_REPO}'s {SIGNER_WORKFLOW} run {id} for HEAD {head} was still `{status}` after \
             the rig's {}-minute wait (polled every {RUN_POLL_SECS}s): no attested build to verify",
            RUN_WAIT_CAP_SECS / 60
        )),
        RunState::Refused(why) => Step::Stop(why),
    }
}

/// The download urls of the two artifacts [`HandOff`] names, read from run `run_id`'s artifact
/// list.
///
/// # Errors
/// An artifact is absent from the run, or expired (past its retention-days).
pub fn artifact_urls(
    list: &Value,
    want: &HandOff,
    run_id: u64,
) -> Result<(String, String), String> {
    let all = list
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let url = |name: &str| -> Result<String, String> {
        let a = all
            .iter()
            .find(|a| a.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| {
                format!(
                    "{SIGNER_REPO}'s {SIGNER_WORKFLOW} run {run_id} has no artifact `{name}`, so \
                     HEAD's attested build cannot be fetched"
                )
            })?;
        if a.get("expired").and_then(Value::as_bool).unwrap_or(false) {
            return Err(format!(
                "{SIGNER_REPO}'s {SIGNER_WORKFLOW} run {run_id} artifact `{name}` has expired \
                 (past its retention-days), so HEAD's attested build cannot be fetched"
            ));
        }
        a.get("archive_download_url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                format!("{SIGNER_WORKFLOW} run {run_id} artifact `{name}` names no download url")
            })
    };
    Ok((url(&want.binary_artifact)?, url(&want.provenance_artifact)?))
}
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
        let fetched;
        let (artifact, provenance) = match (
            self.inputs.slsa_artifact.as_deref(),
            self.inputs.slsa_provenance.as_deref(),
        ) {
            (Some(a), Some(p)) if a.is_file() && p.is_file() => (a, p),
            (None, None) => match self.fetch_run_artifacts(&dir, &run.head) {
                Ok(pair) => {
                    fetched = pair;
                    (fetched.0.as_path(), fetched.1.as_path())
                }
                Err(why) => {
                    run.inputs = Err(why);
                    return decide_slsa(&run);
                }
            },
            (a, p) => {
                run.inputs = Err(format!(
                    "an attested artifact was handed in by half (--slsa-artifact {}, \
                     --slsa-provenance {}): both, or neither and the rig fetches HEAD's from \
                     {SIGNER_REPO}'s {SIGNER_WORKFLOW} run",
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
            "--source-branch".to_string(),
            SOURCE_BRANCH.to_string(),
            "--print-provenance".to_string(),
        ]);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        run.exit = self.leg(rig, "verify", &argv, None, &[]);
        run.output = self.log_text(rig, "verify");
        decide_slsa(&run)
    }
}

impl Runner {
    /// HEAD's attested build from its `slsa-dev-provenance` run: the run found through the API
    /// ([`run_state`]), waited for while unfinished ([`next_step`]), and the two artifacts
    /// [`hand_off`] names downloaded as zips into `dir` and the pair extracted. The token
    /// ([`token_from`]) is handed to curl in a header file, never on its command line; curl does not
    /// carry it across the redirect to the artifact store.
    ///
    /// # Errors
    /// Every way there is no attested pair for HEAD: the suite is not-run, with this text.
    fn fetch_run_artifacts(
        &self,
        dir: &std::path::Path,
        head: &str,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
        use std::process::{Command, Stdio};
        let (token_var, token) = token_from(|k| std::env::var(k).ok())?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let header = dir.join(".auth-header");
        std::fs::write(&header, format!("Authorization: Bearer {token}\n"))
            .map_err(|e| format!("{}: {e}", header.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&header, std::fs::Permissions::from_mode(0o600));
        }
        let auth = format!("@{}", header.display());
        // One request: the body to `to`, the HTTP status read back (`-w`), held to [`http_answer`].
        // No `-f`, so a 401/403 is told apart from every other refusal.
        let fetch = |url: &str, accept: &str, to: &std::path::Path, what: &str| {
            let out = Command::new("curl")
                .args(["-sSL", "--retry", "3", "-H", &auth, "-H", accept])
                .args(["-w", "%{http_code}", "-o"])
                .arg(to)
                .arg(url)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("curl could not run: {e}"))?;
            let code: u16 = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);
            if code == 0 && !out.status.success() {
                return Err(format!(
                    "{what}: curl {} ({})",
                    rc(out.status.code()),
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            http_answer(code, token_var, what)
        };
        let api = |path: &str| -> Result<Value, String> {
            let to = dir.join("api.json");
            fetch(
                &format!("https://api.github.com/repos/{SIGNER_REPO}/{path}"),
                "Accept: application/vnd.github+json",
                &to,
                &format!("`{path}`"),
            )?;
            let body = std::fs::read(&to).map_err(|e| format!("{}: {e}", to.display()))?;
            serde_json::from_slice(&body)
                .map_err(|e| format!("the GitHub API's `{path}` did not read as JSON: {e}"))
        };
        let result = (|| {
            let started = std::time::Instant::now();
            let run_id = loop {
                let runs = api(&format!(
                    "actions/workflows/{SIGNER_WORKFLOW}/runs?head_sha={head}&per_page=100"
                ))?;
                let waited = started.elapsed().as_secs();
                match next_step(run_state(&runs, head), waited, head) {
                    Step::Fetch(id) => break id,
                    Step::Stop(why) => return Err(why),
                    Step::Wait => {
                        let left = RUN_WAIT_CAP_SECS.saturating_sub(waited);
                        std::thread::sleep(std::time::Duration::from_secs(
                            RUN_POLL_SECS.min(left.max(1)),
                        ));
                    }
                }
            };
            let want = hand_off(std::env::consts::ARCH, head);
            let list = api(&format!("actions/runs/{run_id}/artifacts?per_page=100"))?;
            let (url_bin, url_prov) = artifact_urls(&list, &want, run_id)?;
            let mut got = Vec::new();
            for (url, artifact, file) in [
                (&url_bin, &want.binary_artifact, &want.binary_file),
                (&url_prov, &want.provenance_artifact, &want.provenance_file),
            ] {
                let zip = dir.join(format!("{artifact}.zip"));
                fetch(
                    url,
                    "Accept: application/vnd.github+json",
                    &zip,
                    &format!("the download of run {run_id}'s artifact `{artifact}`"),
                )?;
                let to = dir.join(file);
                extract_member(&zip, file, &to).map_err(|e| {
                    format!("{SIGNER_WORKFLOW} run {run_id} artifact `{artifact}`: {e}")
                })?;
                got.push(to);
            }
            let prov = got.pop().unwrap_or_default();
            let art = got.pop().unwrap_or_default();
            Ok((art, prov))
        })();
        let _ = std::fs::remove_file(&header);
        result
    }
}

/// Takes exactly the member `name` out of the artifact zip `zip` into `to`, with python3's zipfile
/// (`-I`: nothing from the working directory is imported; the `conformance` check's backend has
/// python3). Only the named member is read, so no path inside the zip chooses where a file lands.
///
/// # Errors
/// The zip does not hold `name`, or python3 cannot read it.
fn extract_member(zip: &std::path::Path, name: &str, to: &std::path::Path) -> Result<(), String> {
    const READ: &str = concat!(
        "import sys, zipfile\n",
        "z = zipfile.ZipFile(sys.argv[1]); names = z.namelist()\n",
        "if sys.argv[2] not in names: ",
        "sys.exit('the zip holds no ' + sys.argv[2] + ' (it holds ' + ', '.join(names) + ')')\n",
        "open(sys.argv[3], 'wb').write(z.read(sys.argv[2]))\n",
    );
    let out = std::process::Command::new("python3")
        .args(["-I", "-c", READ])
        .arg(zip)
        .arg(name)
        .arg(to)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("python3 could not run to read the zip: {e}"))?;
    if out.status.success() && to.is_file() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
