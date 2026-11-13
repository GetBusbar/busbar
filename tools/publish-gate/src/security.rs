// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! G-S: the exact release SBOM set and every declared OCI platform are scanned before anything is
//! signed, in pinned, digest-checked scanner images with no network, no credentials and read-only
//! mounts. Any failure is one error; the gate reports it without the scanner's text (reports can
//! carry secrets or source snippets).
//!
//! The evidence shape is the one `scripts/security/artifacts.py` writes
//! (`busbar.artifact-security/1`, `busbar.plugin-security/1`), so release-evidence.json and
//! plugin-security.json keep their schema.

use crate::conformance::{epoch, now_epoch};
use crate::py::{self, dict, Dict, PyErr, Value, R};
use crate::world::{self, Security, TempDir};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fail(msg: &str) -> PyErr {
    PyErr::value(msg)
}

fn require(ok: bool, msg: &str) -> R<()> {
    if ok {
        Ok(())
    } else {
        Err(fail(msg))
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> R<()> {
    for p in py::iterdir(dir)? {
        out.push(p.clone());
        let m = std::fs::symlink_metadata(&p).map_err(|e| py::os_err(&e, Some(&p)))?;
        if m.is_dir() {
            walk(&p, out)?;
        }
    }
    Ok(())
}

/// `artifacts.candidate_inventory`: `{relative path: sha256}` of every candidate file.
pub fn candidate_inventory(candidate: &Path) -> R<Dict> {
    let mut dirs = vec!["artifacts", "sboms", "internal", "plugins", "oci"];
    if py::exists(&candidate.join("closures")) {
        dirs.push("closures");
    }
    let mut rows: Vec<(String, Value)> = Vec::new();
    for d in dirs {
        let root = candidate.join(d);
        require(
            py::is_dir(&root) && !py::is_symlink(&root),
            "candidate directory missing or symlinked",
        )?;
        let mut paths = Vec::new();
        walk(&root, &mut paths)?;
        paths.sort();
        for p in paths {
            require(!py::is_symlink(&p), "symlink in release candidate")?;
            if py::is_file(&p) {
                let rel = p
                    .strip_prefix(candidate)
                    .map(|r| r.to_string_lossy().into_owned())
                    .unwrap_or_default();
                rows.push((rel, Value::Str(py::sha256_file(&p)?)));
            }
        }
    }
    require(!rows.is_empty(), "empty release candidate")?;
    Ok(Dict(rows))
}

fn uid_gid() -> (u32, u32) {
    // SAFETY: getuid and getgid take no arguments, cannot fail and touch no memory.
    unsafe { (libc::getuid(), libc::getgid()) }
}

fn run_timed(mut c: Command, timeout: Duration) -> R<i32> {
    let mut child = c.spawn().map_err(|e| py::os_err(&e, None))?;
    let start = Instant::now();
    loop {
        if let Some(s) = child.try_wait().map_err(|e| py::os_err(&e, None))? {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = s.signal() {
                    return Ok(-sig);
                }
            }
            return Ok(s.code().unwrap_or(-1));
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(PyErr::new(
                py::Kind::Subprocess("TimeoutExpired"),
                "scanner timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One container step's result: exit code, report bytes, stderr digest.
type Step = (i32, Vec<u8>, String);

pub struct Scanner {
    pub policy: PathBuf,
    work: PathBuf,
    tools: Dict,
    env: Vec<(String, String)>,
    cache: PathBuf,
    pub steps: Vec<Value>,
}

impl Scanner {
    pub fn new(trusted: &Path, work: &Path) -> R<Scanner> {
        let policy = trusted.join("ci/security");
        let tools = py::loads(&py::read_text(&policy.join("tools.json"))?)?;
        let tools = tools
            .as_dict()
            .cloned()
            .ok_or_else(|| fail("tools.json is not an object"))?;
        let pinned = Regex::new(r"^[a-z0-9./:-]+@sha256:[0-9a-f]{64}$").expect("static regex");
        for name in ["trivy", "semgrep"] {
            let v = tools.get(name).ok_or_else(|| PyErr::key(name))?;
            let s = v
                .as_str()
                .ok_or_else(|| PyErr::type_err("expected string"))?;
            require(pinned.is_match(s), "scanner image must be digest pinned")?;
        }
        let home = work.join("scanner-home");
        std::fs::create_dir(&home).map_err(|e| py::os_err(&e, Some(&home)))?;
        let path = std::env::var("PATH").map_err(|_| PyErr::key("PATH"))?;
        let home_s = py::disp(&home);
        let env = vec![
            ("PATH".to_string(), path),
            ("HOME".to_string(), home_s.clone()),
            ("DOCKER_CONFIG".to_string(), home_s),
        ];
        let cache = work.join("database");
        std::fs::create_dir(&cache).map_err(|e| py::os_err(&e, Some(&cache)))?;
        Ok(Scanner {
            policy,
            work: work.to_path_buf(),
            tools,
            env,
            cache,
            steps: Vec::new(),
        })
    }

    fn image(&self, tool: &str) -> R<String> {
        Ok(self
            .tools
            .get(tool)
            .and_then(Value::as_str)
            .ok_or_else(|| PyErr::key(tool))?
            .to_string())
    }

    fn docker(&self) -> Command {
        let mut c = Command::new("docker");
        c.args(["--host", "unix:///var/run/docker.sock"]);
        c.env_clear();
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }

    fn container(
        &self,
        tool: &str,
        argv: &[String],
        mounts: &[(PathBuf, &str, bool)],
        network: &str,
    ) -> R<Step> {
        let name = format!("busbar-scan-{}", world::mkstemp_token());
        let (uid, gid) = uid_gid();
        let mut c = self.docker();
        c.args([
            "run",
            "--rm",
            "--name",
            &name,
            "--pull=never",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            &format!("--network={network}"),
            "--pids-limit=256",
            "--memory=3g",
            "--cpus=2",
            "--user",
            &format!("{uid}:{gid}"),
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
            "-e",
            "HOME=/tmp",
            "--workdir",
            "/tmp",
            "--entrypoint",
            tool,
        ]);
        for (source, target, writable) in mounts {
            let src = py::disp(source);
            require(!src.contains(','), "comma in mount source")?;
            let ro = if *writable { "" } else { ",readonly" };
            c.args(["--mount", &format!("type=bind,src={src},dst={target}{ro}")]);
        }
        c.arg(self.image(tool)?);
        c.args(argv);
        let out_path = world::mkstemp_in(&self.work)?;
        let err_path = world::mkstemp_in(&self.work)?;
        let result = (|| -> R<Step> {
            let out = std::fs::File::create(&out_path).map_err(|e| py::os_err(&e, None))?;
            let err = std::fs::File::create(&err_path).map_err(|e| py::os_err(&e, None))?;
            c.stdout(out).stderr(err).stdin(Stdio::inherit());
            let code = run_timed(c, Duration::from_secs(1200))?;
            let data = py::read_bytes(&out_path)?;
            require(
                data.len() <= 128 * 1024 * 1024,
                "scanner report exceeds limit",
            )?;
            let stderr_hash = py::sha256_file(&err_path)?;
            Ok((code, data, stderr_hash))
        })();
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&err_path);
        let mut rm = self.docker();
        rm.args(["rm", "-f", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let removed = run_timed(rm, Duration::from_secs(30));
        let step = result?;
        removed?;
        Ok(step)
    }

    fn prepare_image(&self, tool: &str) -> R<()> {
        let image = self.image(tool)?;
        let inspect = || -> R<(i32, Vec<u8>)> {
            let mut c = self.docker();
            c.args([
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                &image,
            ]);
            let out_path = world::mkstemp_in(&self.work)?;
            let f = std::fs::File::create(&out_path).map_err(|e| py::os_err(&e, None))?;
            c.stdout(f).stderr(Stdio::null()).stdin(Stdio::inherit());
            let code = run_timed(c, Duration::from_secs(30));
            let data = py::read_bytes(&out_path);
            let _ = std::fs::remove_file(&out_path);
            Ok((code?, data?))
        };
        let (mut code, mut stdout) = inspect()?;
        if code != 0 {
            let mut pull = self.docker();
            pull.args(["pull", &image])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let rc = run_timed(pull, Duration::from_secs(600))?;
            if rc != 0 {
                return Err(PyErr::new(
                    py::Kind::Subprocess("CalledProcessError"),
                    "docker pull failed",
                ));
            }
            (code, stdout) = inspect()?;
        }
        require(code == 0, "pinned scanner image unavailable")?;
        let refs = py::loads_bytes(&stdout)?;
        let expected = image.split_once('@').map(|x| x.1).unwrap_or("");
        let ok = refs.as_list().is_some_and(|l| {
            l.iter().any(|r| {
                r.as_str()
                    .is_some_and(|s| s.rsplit_once('@').map(|x| x.1).unwrap_or(s) == expected)
            })
        });
        require(ok, "scanner image digest differs from policy")
    }

    pub fn prepare(&self) -> R<Value> {
        for tool in ["trivy", "semgrep"] {
            self.prepare_image(tool)?;
        }
        let argv: Vec<String> = [
            "image",
            "--download-db-only",
            "--disable-telemetry",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (code, _, _) = self.container(
            "trivy",
            &argv,
            &[(self.cache.clone(), "/cache", true)],
            "bridge",
        )?;
        require(code == 0, "vulnerability database download failed")?;
        let max_age = self
            .tools
            .get("database_max_age_hours")
            .cloned()
            .ok_or_else(|| PyErr::key("database_max_age_hours"))?;
        database_identity(&self.cache, &max_age, now_epoch())
    }

    /// A `dependencies` scan of `name` with trivy; any finding or failure refuses.
    pub fn scan(&mut self, name: &str, source: &Path, argv: &[String]) -> R<()> {
        let mounts = [
            (source.to_path_buf(), "/input", false),
            (self.policy.clone(), "/policy", false),
            (self.cache.clone(), "/cache", false),
        ];
        let (code, data, stderr_hash) = self.container("trivy", argv, &mounts, "none")?;
        let mut row = dict([
            ("name", Value::from(name)),
            ("tool_image", Value::Str(self.image("trivy")?)),
            ("exit_code", Value::from(code as i64)),
            ("status", Value::from("fail")),
            ("report_sha256", Value::Str(py::sha256_hex(&data))),
            ("stderr_sha256", Value::Str(stderr_hash)),
        ]);
        let judged = (|| -> R<usize> {
            let report = py::loads_bytes(&data)?;
            inspect_report(&report)
        })();
        let outcome = match judged {
            Ok(count) => {
                row.insert("findings", Value::from(count));
                row.insert("diagnostics", Value::List(Vec::new()));
                row.insert("diagnostics_omitted", Value::from(count));
                if code == 0 && count == 0 {
                    row.insert("status", Value::from("pass"));
                    Ok(())
                } else {
                    Err(())
                }
            }
            Err(_) => Err(()),
        };
        self.steps.push(Value::Dict(row));
        outcome.map_err(|_| fail(&format!("security scan refused: {name}")))
    }

    pub fn trivy(mode: &str, extra: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = vec![
            mode.into(),
            "--config".into(),
            "/policy/trivy.yaml".into(),
            "--ignorefile".into(),
            "/policy/trivy.ignore".into(),
        ];
        if mode != "sbom" {
            v.push("--secret-config".into());
            v.push("/policy/trivy-secret.yaml".into());
        }
        for s in [
            "--disable-telemetry",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
            "--cache-backend",
            "memory",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
        ] {
            v.push(s.into());
        }
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    pub fn policy_files(&self) -> R<Dict> {
        let mut files = py::iterdir(&self.policy)?;
        files.sort();
        let mut out = Dict::new();
        for p in files {
            if py::is_file(&p) {
                out.insert(py::name(&p), Value::Str(py::sha256_file(&p)?));
            }
        }
        Ok(out)
    }
}

/// `scan.inspect_report('dependencies', report)`: the finding count of a complete report.
fn inspect_report(report: &Value) -> R<usize> {
    let d = report
        .as_dict()
        .ok_or_else(|| fail("scanner report is not an object"))?;
    let schema = d.get("SchemaVersion").cloned().unwrap_or(Value::Null);
    require(
        py::py_eq(&schema, &Value::Int("2".into())),
        "unsupported vulnerability/secret report",
    )?;
    let results = match d.get("Results") {
        None => Vec::new(),
        Some(Value::List(v)) => v.clone(),
        Some(_) => return Err(fail("invalid scanner results")),
    };
    let mut count = 0;
    for row in &results {
        let r = row
            .as_dict()
            .ok_or_else(|| fail("invalid scanner result"))?;
        match r.get("Vulnerabilities") {
            None => {}
            Some(v) if !v.truthy() => {}
            Some(Value::List(v)) => count += v.len(),
            Some(_) => return Err(fail("invalid scanner findings")),
        }
    }
    Ok(count)
}

/// `datetime.fromisoformat` for the timestamps trivy writes, as UTC seconds; `None` without an
/// offset.
fn iso_utc(s: &str) -> R<Option<i64>> {
    let re = Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?(Z|[+-]\d{2}:?\d{2}(?::?\d{2}(?:\.\d+)?)?)?$",
    )
    .expect("static regex");
    let m = re
        .captures(s)
        .ok_or_else(|| fail(&format!("Invalid isoformat string: {}", py::repr_str(s))))?;
    let n = |i: usize| -> i64 {
        m.get(i)
            .map(|x| x.as_str().parse().unwrap_or(0))
            .unwrap_or(0)
    };
    let (y, mo, d, h, mi, sec) = (n(1), n(2), n(3), n(4), n(5), n(6));
    require(
        (1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && sec < 60,
        "Invalid isoformat string",
    )?;
    let base = epoch(y, mo, d, h, mi, sec);
    let Some(tz) = m.get(8).map(|x| x.as_str()) else {
        return Ok(None);
    };
    if tz == "Z" {
        return Ok(Some(base));
    }
    let sign = if tz.starts_with('-') { -1 } else { 1 };
    let digits: String = tz[1..].chars().filter(|c| c.is_ascii_digit()).collect();
    let oh: i64 = digits[0..2].parse().unwrap_or(0);
    let om: i64 = digits[2..4].parse().unwrap_or(0);
    Ok(Some(base - sign * (oh * 3600 + om * 60)))
}

fn database_identity(cache: &Path, max_age: &Value, now: i64) -> R<Value> {
    let metadata = py::loads(&py::read_text(&cache.join("db/metadata.json"))?)?;
    let updated_s = metadata.item_str("UpdatedAt")?.to_string();
    let updated = iso_utc(&updated_s.replace('Z', "+00:00"))?;
    let hours = match max_age {
        Value::Int(_) | Value::Bool(_) => max_age.as_int().map(|x| x as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
    .ok_or_else(|| PyErr::type_err("unsupported type for timedelta hours component"))?;
    let Some(updated) = updated else {
        return Err(fail("vulnerability database is stale or future-dated"));
    };
    let age = (now - updated) as f64;
    require(
        age >= 0.0 && age <= hours * 3600.0,
        "vulnerability database is stale or future-dated",
    )?;
    Ok(Value::Dict(dict([
        ("updated_at", Value::Str(updated_s)),
        (
            "sha256",
            Value::Str(py::sha256_file(&cache.join("db/trivy.db"))?),
        ),
        (
            "metadata_sha256",
            Value::Str(py::sha256_file(&cache.join("db/metadata.json"))?),
        ),
    ])))
}

/// `artifacts.scan_candidate`.
pub fn scan_candidate(trusted: &Path, candidate: &Path, platforms: &[String]) -> R<Value> {
    let before = candidate_inventory(candidate)?;
    let mut sboms: Vec<String> = before
        .keys()
        .filter(|n| n.starts_with("sboms/") && n.ends_with(".cdx.json"))
        .cloned()
        .collect();
    sboms.sort();
    require(
        !sboms.is_empty() && !platforms.is_empty() && before.contains("oci/busbar.oci.tar"),
        "release scan subjects missing",
    )?;
    let temporary = TempDir::new("busbar-artifact-scans-")?;
    let mut scanner = Scanner::new(trusted, &temporary.0)?;
    let database = scanner.prepare()?;
    let mut failures: Vec<String> = Vec::new();
    for sbom in &sboms {
        let document = py::loads(&py::read_text(&candidate.join(sbom))?)?;
        let d = document
            .as_dict()
            .ok_or_else(|| PyErr::new(py::Kind::Attribute, "not an object"))?;
        require(
            py::eq_str(d.get("bomFormat"), "CycloneDX")
                && d.get("components").map(Value::truthy).unwrap_or(false),
            "empty or unsupported SBOM",
        )?;
        let input = format!("/input/{sbom}");
        if let Err(e) = scanner.scan(sbom, candidate, &Scanner::trivy("sbom", &[&input])) {
            failures.push(e.msg);
        }
    }
    let mut plats: Vec<String> = platforms.to_vec();
    plats.sort();
    plats.dedup();
    for platform in &plats {
        require(
            platform == "linux/amd64" || platform == "linux/arm64",
            "unsupported release image platform",
        )?;
        let argv = Scanner::trivy(
            "image",
            &[
                "--platform",
                platform,
                "--input",
                "/input/oci/busbar.oci.tar",
            ],
        );
        if let Err(e) = scanner.scan(&format!("image:{platform}"), candidate, &argv) {
            failures.push(e.msg);
        }
    }
    require(
        py::py_eq(
            &Value::Dict(candidate_inventory(candidate)?),
            &Value::Dict(before.clone()),
        ),
        "candidate changed during security scans",
    )?;
    require(failures.is_empty(), &failures.join("; "))?;
    let policy_files = scanner.policy_files()?;
    Ok(Value::Dict(dict([
        ("schema", Value::from("busbar.artifact-security/1")),
        ("status", Value::from("pass")),
        ("subjects", Value::Dict(before)),
        ("database", database),
        ("steps", Value::List(std::mem::take(&mut scanner.steps))),
        ("policy_files", Value::Dict(policy_files)),
    ])))
}

/// `artifacts.plugin_inventory`: one digest-bound SBOM for each expected plugin archive.
pub fn plugin_inventory(
    directory: &Path,
    names: &[String],
    repository: &str,
    version: &str,
    source: &str,
) -> R<Dict> {
    require(
        py::is_dir(directory) && !py::is_symlink(directory),
        "invalid plugin candidate directory",
    )?;
    let manifest = directory.join("security-sboms.json");
    require(
        py::is_file(&manifest) && !py::is_symlink(&manifest),
        "plugin SBOM inventory required",
    )?;
    let document = py::loads(&py::read_text(&manifest)?)?;
    let doc = document
        .as_dict()
        .ok_or_else(|| PyErr::new(py::Kind::Attribute, "not an object"))?;
    require(
        py::eq_str(doc.get("schema"), "busbar.plugin-sboms/1")
            && py::eq_str(doc.get("repository"), repository)
            && py::eq_str(doc.get("version"), version)
            && py::eq_str(doc.get("source"), source),
        "plugin SBOM source binding differs",
    )?;
    let rows = match doc.get("subjects") {
        Some(Value::List(v)) if v.len() == names.len() && !names.is_empty() => v.clone(),
        _ => return Err(fail("plugin SBOM subjects incomplete")),
    };
    let short = repository
        .rsplit_once('/')
        .map(|x| x.1)
        .unwrap_or(repository);
    let mut subjects = Dict::new();
    let mut used: Vec<String> = Vec::new();
    for row in &rows {
        let r = row
            .as_dict()
            .ok_or_else(|| fail("invalid plugin SBOM subject"))?;
        let name = r.get("artifact").and_then(Value::as_str);
        let Some(name) = name.filter(|n| names.iter().any(|x| x == n) && !subjects.contains(n))
        else {
            return Err(fail("duplicate or unexpected plugin artifact"));
        };
        let sbom = r.get("sbom").and_then(Value::as_str);
        let Some(sbom) = sbom.filter(|s| {
            py::name(Path::new(s)) == *s && s.ends_with(".cdx.json") && !used.iter().any(|u| u == s)
        }) else {
            return Err(fail("invalid or reused plugin SBOM"));
        };
        for (filename, expected) in [
            (name, r.get("artifact_sha256")),
            (sbom, r.get("sbom_sha256")),
        ] {
            let path = directory.join(filename);
            let ok = py::is_file(&path)
                && !py::is_symlink(&path)
                && py::eq_str(expected, &py::sha256_file(&path)?);
            require(ok, "plugin artifact/SBOM bytes differ")?;
        }
        let bom = py::loads(&py::read_text(&directory.join(sbom))?)?;
        let b = bom
            .as_dict()
            .ok_or_else(|| PyErr::new(py::Kind::Attribute, "not an object"))?;
        let component = b
            .get("metadata")
            .and_then(Value::as_dict)
            .and_then(|m| m.get("component"))
            .and_then(Value::as_dict);
        let ok = py::eq_str(b.get("bomFormat"), "CycloneDX")
            && b.get("components").map(Value::truthy).unwrap_or(false)
            && component.is_some_and(|c| {
                py::eq_str(c.get("name"), short) && py::eq_str(c.get("version"), version)
            });
        require(ok, "plugin SBOM identity or inventory missing")?;
        subjects.insert(
            name,
            Value::Dict(dict([
                (
                    "artifact_sha256",
                    r.get("artifact_sha256").cloned().unwrap_or(Value::Null),
                ),
                ("sbom", Value::from(sbom)),
                (
                    "sbom_sha256",
                    r.get("sbom_sha256").cloned().unwrap_or(Value::Null),
                ),
            ])),
        );
        used.push(sbom.to_string());
    }
    let mut have: Vec<&String> = subjects.keys().collect();
    let mut want: Vec<&String> = names.iter().collect();
    have.sort();
    want.sort();
    want.dedup();
    require(have == want, "plugin SBOM artifact set differs")?;
    Ok(subjects)
}

/// `artifacts.scan_plugin_candidate`.
pub fn scan_plugin_candidate(
    trusted: &Path,
    directory: &Path,
    names: &[String],
    repository: &str,
    version: &str,
    source: &str,
) -> R<Value> {
    let subjects = plugin_inventory(directory, names, repository, version, source)?;
    let manifest_hash = py::sha256_file(&directory.join("security-sboms.json"))?;
    let temporary = TempDir::new("busbar-plugin-scans-")?;
    let mut scanner = Scanner::new(trusted, &temporary.0)?;
    let database = scanner.prepare()?;
    for row in subjects.values() {
        let sbom = row
            .as_dict()
            .and_then(|r| r.get("sbom"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let input = format!("/input/{sbom}");
        scanner.scan(&sbom, directory, &Scanner::trivy("sbom", &[&input]))?;
    }
    let again = plugin_inventory(directory, names, repository, version, source)?;
    require(
        py::py_eq(&Value::Dict(again), &Value::Dict(subjects.clone()))
            && py::sha256_file(&directory.join("security-sboms.json"))? == manifest_hash,
        "plugin candidate changed during security scans",
    )?;
    let policy_files = scanner.policy_files()?;
    Ok(Value::Dict(dict([
        ("schema", Value::from("busbar.plugin-security/1")),
        ("status", Value::from("pass")),
        ("repository", Value::from(repository)),
        ("version", Value::from(version)),
        ("source", Value::from(source)),
        ("subjects", Value::Dict(subjects)),
        ("database", database),
        ("inventory_sha256", Value::Str(manifest_hash)),
        ("steps", Value::List(std::mem::take(&mut scanner.steps))),
        ("policy_files", Value::Dict(policy_files)),
    ])))
}

/// The real scanners.
pub struct RealSecurity;

impl Security for RealSecurity {
    fn scan_candidate(&self, trusted: &Path, candidate: &Path, platforms: &[String]) -> R<Value> {
        scan_candidate(trusted, candidate, platforms)
    }
    fn scan_plugin_candidate(
        &self,
        trusted: &Path,
        directory: &Path,
        names: &[String],
        repository: &str,
        version: &str,
        source: &str,
    ) -> R<Value> {
        scan_plugin_candidate(trusted, directory, names, repository, version, source)
    }
}
