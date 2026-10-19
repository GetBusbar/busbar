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
//! builder (keyless, OIDC), never on a developer box and never under a key of our own. The trusted
//! builder is GetBusbar/busbar's own GitHub Actions run on each push to `dev` (ARCHITECT ruling
//! 2026-10-17, option A1): slsa-github-generator's generic generator over the `busbar` it builds
//! at that commit, published to busbar-release's `dev-bin` release as
//! `busbar-linux-<arch>-<sha>` and `busbar-linux-<arch>-<sha>.intoto.jsonl` ([`dev_bin_assets`]).
//! The rig fetches the pair for HEAD (the release token, `BUSBAR_RELEASE_TOKEN`) unless the
//! caller hands both files in with `--slsa-artifact` and `--slsa-provenance`. When `dev-bin` holds
//! no pair for HEAD yet, the suite is `not-run` and says so: never a pass, never a fallback.

use serde_json::Value;

use super::rigs::{rc, Rig, Runner};
use super::Outcome;

/// The repository whose provenance is accepted.
pub const SOURCE_URI: &str = "github.com/GetBusbar/busbar";
/// The branch whose builds are attested: the generator runs on each push to it.
pub const SOURCE_BRANCH: &str = "dev";
/// Where the attested builds are published: busbar-release's `dev-bin` release.
pub const DEV_BIN_REPO: &str = "GetBusbar/busbar-release";
pub const DEV_BIN_TAG: &str = "dev-bin";

/// THE PAIR `dev-bin` holds for the build of `head` on `arch` (`x86_64`, `aarch64`): the binary
/// and its in-toto SLSA provenance, named as the generator workflow publishes them.
#[must_use]
pub fn dev_bin_assets(arch: &str, head: &str) -> (String, String) {
    let artifact = format!("busbar-linux-{arch}-{head}");
    let provenance = format!("{artifact}.intoto.jsonl");
    (artifact, provenance)
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

/// Write `contents` to `path`, then restrict it to its owner.
pub fn write_secret_file(path: &std::path::Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
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
            (None, None) => match self.fetch_dev_bin(&dir, &run.head) {
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
                     {DEV_BIN_REPO}'s {DEV_BIN_TAG} release",
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
    /// HEAD's attested build from `dev-bin`: the release's asset list read through the API with the
    /// release token (`BUSBAR_RELEASE_TOKEN`, else `GH_TOKEN` / `GITHUB_TOKEN`, as `bin/oracle`
    /// reads it), and the pair [`dev_bin_assets`] names downloaded into `dir`. The token is handed
    /// to curl in a header file, never on its command line.
    ///
    /// # Errors
    /// The release cannot be read, or holds no pair for HEAD on this architecture (the generator
    /// has not published it yet): the suite is not-run, with this text.
    fn fetch_dev_bin(
        &self,
        dir: &std::path::Path,
        head: &str,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
        use std::process::{Command, Stdio};
        let token = ["BUSBAR_RELEASE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .ok_or_else(|| {
                format!(
                    "no release token (BUSBAR_RELEASE_TOKEN) to read {DEV_BIN_REPO}'s \
                     {DEV_BIN_TAG} release, so HEAD's attested build cannot be fetched"
                )
            })?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let header = dir.join(".auth-header");
        write_secret_file(&header, &format!("Authorization: Bearer {token}\n"))
            .map_err(|e| format!("{}: {e}", header.display()))?;
        let auth = format!("@{}", header.display());
        let curl = |args: &[&str]| -> Result<Vec<u8>, String> {
            let out = Command::new("curl")
                .args(["-fsSL", "--retry", "3", "-H", &auth])
                .args(args)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("curl could not run: {e}"))?;
            if out.status.success() {
                Ok(out.stdout)
            } else {
                Err(format!(
                    "curl {} ({})",
                    rc(out.status.code()),
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        };
        let result = (|| {
            let release: Value = serde_json::from_slice(&curl(&[
                "-H",
                "Accept: application/vnd.github+json",
                &format!("https://api.github.com/repos/{DEV_BIN_REPO}/releases/tags/{DEV_BIN_TAG}"),
            ])?)
            .map_err(|e| format!("the {DEV_BIN_TAG} release did not read as JSON: {e}"))?;
            let id = release
                .get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("the {DEV_BIN_TAG} release names no id"))?;
            let (want_a, want_p) = dev_bin_assets(std::env::consts::ARCH, head);
            let (mut url_a, mut url_p) = (None, None);
            for page in 1.. {
                let assets: Value = serde_json::from_slice(&curl(&[
                    "-H",
                    "Accept: application/vnd.github+json",
                    &format!(
                        "https://api.github.com/repos/{DEV_BIN_REPO}/releases/{id}/assets?per_page=100&page={page}"
                    ),
                ])?)
                .map_err(|e| format!("the {DEV_BIN_TAG} asset list did not read as JSON: {e}"))?;
                let list = assets.as_array().cloned().unwrap_or_default();
                for a in &list {
                    let name = a.get("name").and_then(Value::as_str).unwrap_or("");
                    let url = a.get("url").and_then(Value::as_str).map(str::to_string);
                    if name == want_a {
                        url_a = url;
                    } else if name == want_p {
                        url_p = url;
                    }
                }
                if list.len() < 100 || (url_a.is_some() && url_p.is_some()) {
                    break;
                }
            }
            let (Some(url_a), Some(url_p)) = (url_a, url_p) else {
                return Err(format!(
                    "{DEV_BIN_REPO}'s {DEV_BIN_TAG} release holds no attested build of HEAD {head} \
                     for {} yet (`{want_a}` and `{want_p}`): the provenance workflow has not \
                     published it",
                    std::env::consts::ARCH
                ));
            };
            let (art, prov) = (dir.join(&want_a), dir.join(&want_p));
            for (url, to) in [(&url_a, &art), (&url_p, &prov)] {
                let to_s = to.to_string_lossy().into_owned();
                curl(&["-H", "Accept: application/octet-stream", "-o", &to_s, url])?;
            }
            Ok((art, prov))
        })();
        let _ = std::fs::remove_file(&header);
        result
    }
}

#[cfg(all(test, unix))]
mod secret_file_tests {
    use super::write_secret_file;
    use std::os::unix::fs::PermissionsExt;

    /// The token's file is a fresh inode created 0600, never bytes poured into an inode that an
    /// earlier, looser file (and any other name linked to it) already holds.
    #[test]
    fn the_token_file_is_created_0600_and_never_written_into_an_existing_inode() {
        let dir = std::env::temp_dir().join(format!("xtask-slsa-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let header = dir.join(".auth-header");
        let alias = dir.join("alias");
        std::fs::write(&header, "stale").unwrap();
        std::fs::set_permissions(&header, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::hard_link(&header, &alias).unwrap();

        write_secret_file(&header, "Authorization: Bearer t0ken\n").unwrap();

        let mode = std::fs::metadata(&header).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::read_to_string(&header).unwrap(),
            "Authorization: Bearer t0ken\n"
        );
        assert_eq!(
            std::fs::read_to_string(&alias).unwrap(),
            "stale",
            "the token must not reach an inode another name already holds"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
