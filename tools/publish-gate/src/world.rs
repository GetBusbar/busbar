// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The outside world: subprocesses, temporary files, and the read-only lookups (GitHub, the
//! registries, ModernCI) and the pinned scanners the rules consult. Each lookup is a trait so a
//! test harness can answer it; the CLI only ever constructs the real ones.

use crate::py::{self, os_err, Kind, PyErr, Value, R};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// What a finished subprocess left behind (`subprocess.CompletedProcess`).
pub struct Out {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Out {
    pub fn stdout_str(&self) -> R<String> {
        py::decode_utf8(&self.stdout)
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

fn status_code(s: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = s.signal() {
            return -sig;
        }
    }
    s.code().unwrap_or(-1)
}

fn spawn_err(e: &std::io::Error, program: &str) -> PyErr {
    os_err(e, Some(Path::new(program)))
}

/// Run `cmd` with captured output (`subprocess.run(cmd, input=stdin, capture_output=True)`).
/// Without `stdin` the child shares ours. `check` turns a non-zero exit into "cannot run".
pub fn run(cmd: &[String], stdin: Option<&[u8]>, check: bool) -> R<Out> {
    run_in(cmd, stdin, check, None, None)
}

pub fn run_in(
    cmd: &[String],
    stdin: Option<&[u8]>,
    check: bool,
    cwd: Option<&Path>,
    env: Option<&[(String, String)]>,
) -> R<Out> {
    let mut c = Command::new(&cmd[0]);
    c.args(&cmd[1..]);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    if let Some(vars) = env {
        c.env_clear();
        for (k, v) in vars {
            c.env(k, v);
        }
    }
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    c.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    let mut child = c.spawn().map_err(|e| spawn_err(&e, &cmd[0]))?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("stdin is piped");
        let data = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        });
        let out = child
            .wait_with_output()
            .map_err(|e| spawn_err(&e, &cmd[0]))?;
        let _ = writer.join();
        return finish(cmd, out, check);
    }
    let out = child
        .wait_with_output()
        .map_err(|e| spawn_err(&e, &cmd[0]))?;
    finish(cmd, out, check)
}

fn finish(cmd: &[String], out: std::process::Output, check: bool) -> R<Out> {
    let o = Out {
        code: status_code(out.status),
        stdout: out.stdout,
        stderr: out.stderr,
    };
    if check && o.code != 0 {
        return Err(PyErr::cannot_run(format!(
            "{} failed: {}",
            cmd.join(" "),
            py::strip(&o.stderr_lossy())
        )));
    }
    Ok(o)
}

/// `shutil.which(name)`.
pub fn which(name: &str) -> Option<String> {
    if name.contains('/') {
        return executable(Path::new(name)).then(|| name.to_string());
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let cand = dir.join(name);
        if executable(&cand) {
            return Some(py::disp(&cand));
        }
    }
    None
}

fn executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The full path of a tool a rule needs, or "cannot run".
pub fn tool(name: &str) -> R<String> {
    which(name).ok_or_else(|| {
        PyErr::cannot_run(format!(
            "`{name}` is not on PATH; this rule cannot run without it"
        ))
    })
}

// ── temporary files ─────────────────────────────────────────────────────────────────────────────

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn tmp_root() -> PathBuf {
    std::env::var_os("TMPDIR")
        .filter(|x| !x.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn token() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{}:{}:{}", std::process::id(), t, n);
    py::sha256_hex(seed.as_bytes())[..12].to_string()
}

/// 32 hex characters, unique to this process and moment (a container or file name).
pub fn mkstemp_token() -> String {
    let mut s = String::new();
    while s.len() < 32 {
        s.push_str(&token());
    }
    s.truncate(32);
    s
}

/// `tempfile.mkstemp(suffix=...)`: a new, empty, owner-only file.
pub fn mkstemp(prefix: &str, suffix: &str) -> R<PathBuf> {
    mkstemp_at(&tmp_root(), prefix, suffix)
}

/// A new, empty, owner-only file in `dir`.
pub fn mkstemp_in(dir: &Path) -> R<PathBuf> {
    mkstemp_at(dir, "tmp", "")
}

fn mkstemp_at(root: &Path, prefix: &str, suffix: &str) -> R<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    for _ in 0..100 {
        let p = root.join(format!("{prefix}{}{suffix}", token()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
        {
            Ok(_) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(os_err(&e, Some(&p))),
        }
    }
    Err(PyErr::new(
        Kind::Os("FileExistsError"),
        "No usable temporary file name found",
    ))
}

/// `tempfile.mkdtemp(prefix=...)`: a new, owner-only directory.
pub fn mkdtemp(prefix: &str) -> R<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let root = tmp_root();
    for _ in 0..100 {
        let p = root.join(format!("{prefix}{}", token()));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(_) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(os_err(&e, Some(&p))),
        }
    }
    Err(PyErr::new(
        Kind::Os("FileExistsError"),
        "No usable temporary directory name found",
    ))
}

/// A temporary directory removed when dropped (`tempfile.TemporaryDirectory`).
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> R<TempDir> {
        mkdtemp(prefix).map(TempDir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── the lookups ─────────────────────────────────────────────────────────────────────────────────

/// Read-only GitHub and registry lookups.
pub trait Net {
    fn release_exists(&self, repo: &str, tag: &str) -> R<bool>;
    fn release_published(&self, repo: &str, tag: &str) -> R<bool>;
    fn registry_digest(&self, reference: &str) -> R<Option<String>>;
    /// The repository GitHub serves for `org/name` (a renamed repo redirects), or `None`.
    fn repo_full_name(&self, repo: &str) -> R<Option<String>>;
    /// The object `refs/tags/<tag>` names on GitHub (the tag object for an annotated tag).
    fn remote_tag(&self, repo: &str, tag: &str) -> R<Option<String>>;
    fn repo_file(&self, repo: &str, path: &str, reference: &str) -> R<String>;
}

pub struct RealNet;

fn s(x: &str) -> String {
    x.to_string()
}

fn lower_err(o: &Out) -> String {
    o.stderr_lossy().to_lowercase()
}

impl Net for RealNet {
    fn release_exists(&self, repo: &str, tag: &str) -> R<bool> {
        let gh = tool("gh")?;
        let p = run(
            &[
                gh,
                s("release"),
                s("view"),
                s(tag),
                s("-R"),
                s(repo),
                s("--json"),
                s("tagName"),
            ],
            None,
            false,
        )?;
        if p.code == 0 {
            return Ok(true);
        }
        let err = lower_err(&p);
        if err.contains("not found") || err.contains("release not found") {
            return Ok(false);
        }
        Err(PyErr::cannot_run(format!(
            "gh release view {tag} -R {repo}: {}",
            py::strip(&err)
        )))
    }

    fn release_published(&self, repo: &str, tag: &str) -> R<bool> {
        let gh = tool("gh")?;
        let p = run(
            &[
                gh,
                s("release"),
                s("view"),
                s(tag),
                s("-R"),
                s(repo),
                s("--json"),
                s("isDraft"),
                s("-q"),
                s(".isDraft"),
            ],
            None,
            false,
        )?;
        if p.code == 0 {
            return Ok(py::strip(&p.stdout_str()?) == "false");
        }
        let err = lower_err(&p);
        if err.contains("not found") {
            return Ok(false);
        }
        Err(PyErr::cannot_run(format!(
            "gh release view {tag} -R {repo}: {}",
            py::strip(&err)
        )))
    }

    fn registry_digest(&self, reference: &str) -> R<Option<String>> {
        let skopeo = tool("skopeo")?;
        let p = run(
            &[
                skopeo,
                s("inspect"),
                s("--raw"),
                format!("docker://{reference}"),
            ],
            None,
            false,
        )?;
        if p.code == 0 {
            return Ok(Some(format!("sha256:{}", py::sha256_hex(&p.stdout))));
        }
        let err = lower_err(&p);
        if err.contains("manifest unknown")
            || err.contains("not found")
            || err.contains("name unknown")
        {
            return Ok(None);
        }
        Err(PyErr::cannot_run(format!(
            "skopeo inspect {reference}: {}",
            py::strip(&err)
        )))
    }

    fn repo_full_name(&self, repo: &str) -> R<Option<String>> {
        let gh = tool("gh")?;
        let p = run(
            &[
                gh,
                s("api"),
                format!("repos/{repo}"),
                s("-q"),
                s(".full_name"),
            ],
            None,
            false,
        )?;
        if p.code == 0 {
            let v = py::strip(&p.stdout_str()?).to_string();
            return Ok(if v.is_empty() { None } else { Some(v) });
        }
        let err = lower_err(&p);
        if err.contains("not found") || err.contains("404") {
            return Ok(None);
        }
        Err(PyErr::cannot_run(format!(
            "gh api repos/{repo}: {}",
            py::strip(&err)
        )))
    }

    fn remote_tag(&self, repo: &str, tag: &str) -> R<Option<String>> {
        let p = run(
            &[
                s("git"),
                s("ls-remote"),
                format!("https://github.com/{repo}.git"),
                format!("refs/tags/{tag}"),
            ],
            None,
            false,
        )?;
        if p.code != 0 {
            return Err(PyErr::cannot_run(format!(
                "git ls-remote {repo} {tag}: {}",
                py::strip(&p.stderr_lossy())
            )));
        }
        for line in py::splitlines(&p.stdout_str()?) {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 2 {
                return Err(unpack_err(2, parts.len()));
            }
            if parts[1] == format!("refs/tags/{tag}") {
                return Ok(Some(parts[0].to_string()));
            }
        }
        Ok(None)
    }

    fn repo_file(&self, repo: &str, path: &str, reference: &str) -> R<String> {
        let gh = tool("gh")?;
        let p = run(
            &[
                gh,
                s("api"),
                format!("repos/{repo}/contents/{path}?ref={reference}"),
                s("-q"),
                s(".content"),
            ],
            None,
            false,
        )?;
        if p.code != 0 {
            return Err(PyErr::cannot_run(format!(
                "gh api {repo}/{path}@{reference}: {}",
                py::strip(&p.stderr_lossy())
            )));
        }
        py::decode_utf8(&b64decode(&p.stdout)?)
    }
}

/// `base64.b64decode(data)`: characters outside the alphabet are discarded.
pub fn b64decode(data: &[u8]) -> R<Vec<u8>> {
    use base64::engine::{general_purpose, DecodePaddingMode, GeneralPurposeConfig};
    use base64::Engine;
    let kept: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/' || *c == b'=')
        .collect();
    let body: Vec<u8> = kept.iter().copied().take_while(|c| *c != b'=').collect();
    if body.len() % 4 == 1 {
        return Err(PyErr::new(
            Kind::ValueNamed("Error"),
            format!(
                "Invalid base64-encoded string: number of data characters ({}) cannot be 1 more than a multiple of 4",
                body.len()
            ),
        ));
    }
    let pads = kept.len() - body.len();
    if !body.len().is_multiple_of(4) && (body.len() % 4) + pads < 4 {
        return Err(PyErr::new(Kind::ValueNamed("Error"), "Incorrect padding"));
    }
    let engine = general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    engine
        .decode(&body)
        .map_err(|e| PyErr::new(Kind::ValueNamed("Error"), e.to_string()))
}

/// `a, b = xs` failing.
pub fn unpack_err(want: usize, got: usize) -> PyErr {
    if got < want {
        PyErr::value(format!(
            "not enough values to unpack (expected {want}, got {got})"
        ))
    } else {
        PyErr::value(format!(
            "too many values to unpack (expected {want}, got {got})"
        ))
    }
}

/// ModernCI and the forge, as G-C reads them.
pub trait ModernCI {
    /// The commit `refs/heads/dev` names for `repo` on the configured forge.
    fn dev_head(&self, repo: &str) -> R<String>;
}

pub struct RealModernCI {
    /// The owner's clone, whose `origin` names the forge when no server is configured.
    pub root: PathBuf,
}

fn cg_cannot_run(msg: String) -> PyErr {
    PyErr::new(Kind::CgCannotRun, msg)
}

impl ModernCI for RealModernCI {
    fn dev_head(&self, repo: &str) -> R<String> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let server = match env("CI_SERVER_URL").or_else(|| env("BUSBAR_GIT_SERVER_URL")) {
            Some(s) => s,
            None => {
                let origin = run_in(
                    &[s("git"), s("remote"), s("get-url"), s("origin")],
                    None,
                    false,
                    Some(&self.root),
                    None,
                )?;
                let remote = py::strip(&origin.stdout_lossy_text()).to_string();
                if origin.code != 0 || remote.is_empty() {
                    return Err(cg_cannot_run(
                        "set BUSBAR_GIT_SERVER_URL or configure the origin remote".into(),
                    ));
                }
                if remote.contains("://") {
                    let mut parts: Vec<&str> = remote.rsplitn(3, '/').collect();
                    parts.reverse();
                    parts[0].to_string()
                } else if let Some((host, _)) = remote.split_once(':') {
                    format!("{host}:")
                } else {
                    return Err(cg_cannot_run(
                        "origin must use HTTPS/SSH or set BUSBAR_GIT_SERVER_URL".into(),
                    ));
                }
            }
        };
        let sep = if server.ends_with(':') { "" } else { "/" };
        let remote = format!("{}{sep}{repo}.git", server.trim_end_matches('/'));
        let p = run(
            &[s("git"), s("ls-remote"), remote, s("refs/heads/dev")],
            None,
            false,
        )?;
        let out = p.stdout_lossy_text();
        let re = regex::Regex::new(r"^([0-9a-f]{40})\s").expect("static regex");
        match re.captures(&out) {
            Some(m) if p.code == 0 => Ok(m[1].to_string()),
            _ => {
                let err = p.stderr_lossy();
                let why = py::strip(&err);
                Err(cg_cannot_run(format!(
                    "git ls-remote {repo} dev: {}",
                    if why.is_empty() { "no dev branch" } else { why }
                )))
            }
        }
    }
}

impl Out {
    fn stdout_lossy_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// The pinned, network-disabled scanners G-S runs over the actual release bytes.
pub trait Security {
    fn scan_candidate(&self, trusted: &Path, candidate: &Path, platforms: &[String]) -> R<Value>;
    fn scan_plugin_candidate(
        &self,
        trusted: &Path,
        directory: &Path,
        names: &[String],
        repository: &str,
        version: &str,
        source: &str,
    ) -> R<Value>;
}
