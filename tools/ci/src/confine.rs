//! Explicit candidate execution boundary; controller code never enters its mounts.
//!
//! The `Execution` contract of scripts/architecture/native_confinement.py as the
//! architecture controller uses it: `from_context`, per-invocation Docker
//! containers (create, inspect, attach, state, removal, confirmed absence),
//! observations with the same keys and digests, and the two-isolate compiler
//! pool. The step runner keeps its Python implementation for its own steps
//! until it is ported; both write identical observation rows. Missing images,
//! weakened runtimes or failed disposal refuse; there is no host fallback.
use crate::isolation;
use crate::json::{self, Value, object};
use crate::pathx::{self, io, text};
use crate::proc::{self, Result, require};
use crate::py;
use crate::sha256;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub type Env = BTreeMap<String, String>;

/// Error text of a cancelled compiler case (`CancelledError`).
pub const CANCELLED: &str = "compiler pool cancelled";

/// A finished candidate command (`subprocess.CompletedProcess`).
#[derive(Clone, Debug, Default)]
pub struct Done {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn digest(path: &Path) -> Result<String> {
    Ok(sha256::hex(&pathx::read(path)?))
}

/// `(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()`.
pub fn canonical(value: &Value) -> Vec<u8> {
    json::encoded(value)
}

fn canonical_sha(value: &Value) -> String {
    sha256::hex(&canonical(value))
}

/// The process environment as `os.environ` sees it.
pub fn process_env() -> Env {
    std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

pub fn checked_directory(value: &Path) -> Result<PathBuf> {
    let path = value.to_path_buf();
    require(
        path.is_absolute()
            && path.is_dir()
            && !pathx::is_symlink(&path)
            && path == pathx::resolve(&path)
            && pathx::norm(&path).components().count() > 2,
        "unsafe execution root",
    )?;
    require(!text(&path).contains(','), "unsupported mount path")?;
    Ok(pathx::norm(&path))
}

fn mkdir_exist_ok(path: &Path, mode: u32) -> Result<()> {
    match pathx::mkdir(path, mode) {
        Ok(()) => Ok(()),
        Err(_) if path.is_dir() => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn writable_directory(root: &Path, parts: &[&str]) -> Result<PathBuf> {
    let mut current = checked_directory(root)?;
    for part in parts {
        require(
            !matches!(*part, "" | "." | "..") && !part.contains('/'),
            "invalid writable directory component",
        )?;
        current = current.join(part);
        require(!pathx::is_symlink(&current), "indirect writable directory")?;
        mkdir_exist_ok(&current, 0o777)?;
        checked_directory(&current)?;
    }
    Ok(current)
}

fn image_reference(value: &str) -> bool {
    let digest = match value.split_once('@') {
        Some((prefix, rest)) => {
            if prefix.is_empty()
                || !prefix
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"./:_-".contains(&c))
            {
                return false;
            }
            rest
        }
        None => value,
    };
    digest
        .strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

fn unix_endpoint(value: &str) -> bool {
    value
        .strip_prefix("unix:///")
        .is_some_and(|rest| !rest.is_empty() && !rest.chars().any(|c| c == ',' || py_space(c)))
}

/// `str.isspace()` / regex `\s` for str patterns.
pub fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn test_endpoint_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("BUSBAR_TEST_") else {
        return false;
    };
    ["_URL", "_ADDR", "_FIXTURE"].iter().any(|suffix| {
        rest.len() > suffix.len()
            && rest.ends_with(suffix)
            && rest
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
    })
}

fn github_mapping(value: &str) -> bool {
    value
        .strip_prefix("https://github.com/GetBusbar/")
        .is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        })
}

/// `PurePosixPath.as_uri()`.
fn file_uri(path: &Path) -> String {
    let mut out = String::from("file://");
    for byte in text(path).bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~/".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `int(text)` for the Git mapping count.
fn py_int(value: &str) -> Result<i64> {
    let trimmed = value.trim_matches(py_space);
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    let valid = !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.bytes().all(|c| c.is_ascii_digit() || c == b'_');
    let parsed = valid
        .then(|| trimmed.replace('_', "").parse::<i64>().ok())
        .flatten();
    parsed.ok_or_else(|| {
        format!(
            "invalid literal for int() with base 10: {}",
            py::repr_str(value)
        )
    })
}

pub type Client = Arc<dyn Fn(&[String], bool) -> Result<(i32, String)> + Send + Sync>;
pub type PrepareWritable = Arc<dyn Fn(&Value, &[PathBuf], u64, u64) -> Result<Value> + Send + Sync>;
pub type Userns = Arc<dyn Fn(&Value, &Value, Option<&Value>) -> Result<Value> + Send + Sync>;

/// Host-kernel contracts. Production uses the real Docker client and Linux
/// checks; unit tests substitute them as the Python tests patch them.
#[derive(Clone, Default)]
pub struct Hooks {
    pub client: Option<Client>,
    pub prepare_writable: Option<PrepareWritable>,
    pub userns: Option<Userns>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Roots {
    pub checkout: PathBuf,
    pub candidate: PathBuf,
    pub trusted: PathBuf,
    pub harness: PathBuf,
}

impl Roots {
    pub fn all(&self) -> [(&'static str, &PathBuf); 4] {
        [
            ("checkout", &self.checkout),
            ("candidate", &self.candidate),
            ("trusted", &self.trusted),
            ("harness", &self.harness),
        ]
    }
}

struct Attach<'a> {
    at: usize,
    name: &'a str,
    args: &'a [String],
    mounts: &'a [(PathBuf, PathBuf, bool)],
    fixture_hosts: &'a [String],
    resources: &'a Value,
    daemon: &'a Value,
    isolation: &'a Value,
    user: String,
}

#[derive(Clone)]
pub struct Execution {
    pub config: Value,
    pub control: PathBuf,
    pub roots: Roots,
    docker: Vec<String>,
    client_env: Vec<(String, String)>,
    fixture_directory: PathBuf,
    fixture_map: PathBuf,
    pub extra_readonly: Vec<PathBuf>,
    pub observations: Vec<Value>,
    conformance_mounts: Vec<(PathBuf, PathBuf)>,
    conformance_inputs_manifest: Option<PathBuf>,
    dependency_seed: Option<PathBuf>,
    dependency_seed_sha256: Value,
    resource_slice: Option<Value>,
    compiler_readonly: bool,
    prepared_git: Option<PathBuf>,
    readonly_candidate_inputs: Option<PathBuf>,
    pub hooks: Hooks,
}

const CONFIG_KEYS: [&str; 13] = [
    "schema",
    "docker",
    "docker_sha256",
    "docker_host",
    "image",
    "runtime",
    "uid",
    "gid",
    "python",
    "environment",
    "resources",
    "isolation",
    "collector",
];

const ALLOWED_ENV: &[&str] = &[
    "CI",
    "LANG",
    "LC_ALL",
    "RUSTUP_TOOLCHAIN",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_JOBS",
    "CARGO_TERM_COLOR",
    "CARGO_PROFILE_DEV_DEBUG",
    "CARGO_PROFILE_TEST_DEBUG",
    "CARGO_NET_GIT_FETCH_WITH_CLI",
    "TMPDIR",
    "MODERNCI_CACHE_DIR",
    "XDG_CACHE_HOME",
    "GIT_TERMINAL_PROMPT",
    "CI_SERVER_HOST",
    "CI_JOB_URL",
    "CI_JOB_ID",
    "CI_PIPELINE_ID",
    "CI_PROJECT_PATH",
    "CONFORMANCE_OUT",
    "CONFORMANCE_TIMEOUT_SECONDS",
    "VALKEY_URL",
    "BUSBAR_V4_TRANSPORT_URL",
    "BUSBAR_V4_TEST_TMP",
    "BUSBAR_VALKEY_SERVER",
    "BUSBAR_CHECKOUT",
    "BUSBAR_ADMISSION_CORE_REVISION",
    "BUSBAR_SDK_CHECKOUT",
    "BUSBAR_SDK_REVISION",
    "BUSBAR_SCAFFOLD_OUTPUT",
    "BUSBAR_PIN",
    "BUSBAR_TEST_TMP_ROOT",
    "BUSBAR_TEST_VAULT_TOKEN",
    "BUSBAR_TEST_MYSQL_ROOT_PASSWORD",
    "BUSBAR_ARCHITECTURE_SOURCES",
    "BUSBAR_ARCHITECTURE_POLICY_SOURCES",
    "BUSBAR_ARCHITECTURE_GENERATED_DIRS",
    "BUSBAR_C_ABI_SOURCES",
    "BUSBAR_C_ABI_LIBRARY",
    "BUSBAR_PLUGIN_CDYLIB",
    "BUSBAR_BIN",
    "TSAN_OPTIONS",
];

const TMPFS: &str = "rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777";

fn int(value: &Value) -> Option<i128> {
    value.is_int().then(|| value.as_int()).flatten()
}

fn str_map(value: &Value) -> Option<Vec<(String, String)>> {
    value
        .as_object()?
        .iter()
        .map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect()
}

impl Execution {
    pub fn new(config: Value, roots: &Value, control: &Path, hooks: Hooks) -> Result<Execution> {
        require(
            config.has_keys(&CONFIG_KEYS),
            "unknown isolation configuration",
        )?;
        require(
            config.at("schema").as_str() == Some("busbar.native-confinement/2"),
            "unknown isolation schema",
        )?;
        let docker = config.at("docker").as_str().unwrap_or("").to_owned();
        require(
            Path::new(&docker).is_absolute()
                && digest(Path::new(&docker))?.as_str()
                    == config.at("docker_sha256").as_str().unwrap_or("\0"),
            "Docker client is not the pinned executable",
        )?;
        let docker_host = config.at("docker_host").as_str().unwrap_or("").to_owned();
        require(
            unix_endpoint(&docker_host),
            "local Unix Docker endpoint required",
        )?;
        require(
            config.at("image").as_str().is_some_and(image_reference),
            "immutable toolchain image required",
        )?;
        require(
            matches!(config.at("runtime").as_str(), Some("runc" | "runsc")),
            "unsupported candidate runtime",
        )?;
        require(
            int(config.at("uid")).is_some_and(|v| v > 0)
                && int(config.at("gid")).is_some_and(|v| v > 0),
            "candidate must use a nonroot identity",
        )?;
        require(
            config
                .at("python")
                .as_str()
                .is_some_and(|p| Path::new(p).is_absolute()),
            "pinned-image Python path required",
        )?;
        let environment = str_map(config.at("environment"));
        require(
            environment.as_ref().is_some_and(|env| {
                env.iter().all(|(k, _)| {
                    [
                        "PATH",
                        "CARGO_HOME",
                        "RUSTUP_HOME",
                        "GOROOT",
                        "RUSTC",
                        "RUSTDOC",
                    ]
                    .contains(&k.as_str())
                }) && env.iter().any(|(k, _)| k == "PATH")
            }),
            "unexpected toolchain environment",
        )?;
        isolation::validate_configuration(config.at("isolation"))?;
        let collector = config.at("collector");
        let isolation = config.at("isolation");
        let mapped = |key: &str, id: &str| -> Option<i128> {
            Some(int(isolation.at(key).index(1))? + int(config.at(id))?)
        };
        require(
            (collector.has_keys(&["docker_host", "uid", "gid"])
                || collector.has_keys(&["docker_host", "uid", "gid", "image"]))
                && collector
                    .get("image")
                    .unwrap_or(config.at("image"))
                    .as_str()
                    .is_some_and(image_reference)
                && collector
                    .at("docker_host")
                    .as_str()
                    .is_some_and(unix_endpoint)
                && py::eq(
                    collector.at("uid"),
                    &mapped("uid_map", "uid").map_or(Value::Null, Value::int),
                )
                && py::eq(
                    collector.at("gid"),
                    &mapped("gid_map", "gid").map_or(Value::Null, Value::int),
                ),
            "invalid protected dependency collector identity",
        )?;
        let resources = config.at("resources");
        let resource = |key: &str| int(resources.at(key));
        require(
            resources.has_keys(&["cpus", "memory_bytes", "pids"])
                && ["cpus", "memory_bytes", "pids"]
                    .iter()
                    .all(|k| resource(k).is_some_and(|v| v > 0))
                && resource("cpus").unwrap_or(0) <= 64
                && resource("memory_bytes").unwrap_or(0) <= 256 << 30
                && resource("pids").unwrap_or(0) <= 65536,
            "invalid confinement resource caps",
        )?;
        let control = checked_directory(control)?;
        require(
            roots.has_keys(&["checkout", "candidate", "trusted", "harness"]),
            "unexpected execution roots",
        )?;
        let root = |key: &str| -> Result<PathBuf> {
            checked_directory(Path::new(
                roots.at(key).as_str().ok_or("unsafe execution root")?,
            ))
        };
        let roots = Roots {
            checkout: root("checkout")?,
            candidate: root("candidate")?,
            trusted: root("trusted")?,
            harness: root("harness")?,
        };
        for writable in [&roots.checkout, &roots.candidate] {
            require(
                !control.starts_with(writable),
                "controller is beneath candidate access",
            )?;
        }
        for readonly in [&roots.trusted, &roots.harness] {
            require(
                !control.starts_with(readonly),
                "controller is exposed through readonly root",
            )?;
            for writable in [&roots.checkout, &roots.candidate] {
                require(
                    !readonly.starts_with(writable) && !writable.starts_with(readonly),
                    "trusted source overlaps candidate roots",
                )?;
            }
        }
        require(
            !roots.candidate.starts_with(&roots.checkout)
                && !roots.checkout.starts_with(&roots.candidate),
            "candidate roots overlap",
        )?;
        let omitted = [
            roots.checkout.join(".git"),
            roots.checkout.join("target"),
            roots.checkout.join("dist/default/target"),
        ];
        let mut pending = vec![roots.checkout.clone()];
        while let Some(directory) = pending.pop() {
            let Ok(entries) = fs::read_dir(&directory) else {
                continue; // os.walk ignores unreadable directories
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    continue;
                };
                require(
                    !metadata.file_type().is_symlink(),
                    "candidate source contains symlinks",
                )?;
                if metadata.is_dir() && !omitted.contains(&path) {
                    pending.push(path);
                }
            }
        }
        let resolved_docker = pathx::resolve(Path::new(&docker));
        require(
            !resolved_docker.starts_with(&roots.checkout)
                && !resolved_docker.starts_with(&roots.candidate),
            "Docker client is candidate writable",
        )?;
        let candidate_writable =
            |path: &Path| path.starts_with(&roots.candidate) || path.starts_with(&roots.checkout);
        for (key, value) in environment.unwrap_or_default() {
            if key == "PATH" {
                require(
                    value.split(':').all(|part| {
                        let path = Path::new(if part.is_empty() { "." } else { part });
                        path.is_absolute() && !path.starts_with("/tmp") && !candidate_writable(path)
                    }),
                    "relative or candidate writable tool search path",
                )?;
                continue;
            }
            let path = Path::new(if value.is_empty() { "." } else { &value });
            require(
                path.is_absolute() && !path.starts_with("/tmp") && !candidate_writable(path),
                "toolchain or Cargo seed path is candidate writable",
            )?;
        }
        let client_home = control.join("docker-client");
        mkdir_exist_ok(&client_home, 0o700)?;
        let client_env = vec![
            ("PATH".to_owned(), "/bin:/usr/bin".to_owned()),
            ("HOME".to_owned(), text(&client_home)),
            ("DOCKER_CONFIG".to_owned(), text(&client_home)),
        ];
        let fixture_directory = control.join("fixture-sockets");
        mkdir_exist_ok(&fixture_directory, 0o755)?;
        let fixture_map = control.join("fixture-map.json");
        if !fixture_map.exists() {
            pathx::write(&fixture_map, b"[]\n")?;
        }
        Ok(Execution {
            docker: vec![docker, "--host".into(), docker_host],
            config,
            control,
            roots,
            client_env,
            fixture_directory,
            fixture_map,
            extra_readonly: Vec::new(),
            observations: Vec::new(),
            conformance_mounts: Vec::new(),
            conformance_inputs_manifest: None,
            dependency_seed: None,
            dependency_seed_sha256: Value::Null,
            resource_slice: None,
            compiler_readonly: false,
            prepared_git: None,
            readonly_candidate_inputs: None,
            hooks,
        })
    }

    pub fn from_context(path: &Path, expected: &str, hooks: Hooks) -> Result<Execution> {
        require(
            digest(path)? == expected,
            "controller execution context digest differs",
        )?;
        let data = py::loads(pathx::read_text(path)?.as_bytes()).map_err(|e| e.message)?;
        let mut execution = Execution::new(
            data.get("configuration")
                .cloned()
                .ok_or("KeyError: 'configuration'")?,
            data.get("roots").ok_or("KeyError: 'roots'")?,
            Path::new(
                data.get("control")
                    .and_then(Value::as_str)
                    .ok_or("KeyError: 'control'")?,
            ),
            hooks,
        )?;
        for value in data.at("extra_readonly").as_array().unwrap_or(&[]) {
            execution
                .extra_readonly
                .push(checked_directory(Path::new(value.as_str().unwrap_or("")))?);
        }
        for row in data.at("conformance_mounts").as_array().unwrap_or(&[]) {
            execution.conformance_mounts.push((
                PathBuf::from(row.index(0).as_str().unwrap_or("")),
                PathBuf::from(row.index(1).as_str().unwrap_or("")),
            ));
        }
        if let Some(manifest) = data
            .at("conformance_inputs_manifest")
            .as_str()
            .filter(|m| !m.is_empty())
        {
            execution.conformance_inputs_manifest = Some(PathBuf::from(manifest));
        }
        if !matches!(data.at("dependency_seed"), Value::Null) {
            execution.dependency_seed = Some(checked_directory(Path::new(
                data.at("dependency_seed").as_str().unwrap_or(""),
            ))?);
            execution.dependency_seed_sha256 = data.at("dependency_seed_sha256").clone();
        }
        Ok(execution)
    }

    fn client(&self, argv: &[String], capture: bool) -> Result<(i32, String)> {
        if let Some(client) = &self.hooks.client {
            return client(argv, capture);
        }
        let mut command = self.docker.clone();
        command.extend(argv.iter().cloned());
        let output = proc::run(
            &command,
            &proc::Options {
                env: self.client_env.clone(),
                capture: true,
                timeout: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        )?;
        let stdout = if capture {
            pathx::text_mode(&output.stdout)?
        } else {
            String::new()
        };
        Ok((pathx::returncode(output.status), stdout))
    }

    /// Expose source history without GitLab clone credentials, hooks or host config.
    pub fn sanitize_git(&mut self) -> Result<PathBuf> {
        if let Some(prepared) = &self.prepared_git {
            return checked_directory(prepared);
        }
        let source = self.roots.checkout.join(".git");
        require(
            source.is_dir() && !pathx::is_symlink(&source),
            "CI checkout must have a regular Git directory",
        )?;
        require(
            fs::symlink_metadata(source.join("objects/info/alternates")).is_err()
                && !source.join("objects/info/alternates").exists(),
            "external Git object store",
        )?;
        let destination = self.control.join("candidate-git");
        if !destination.exists() {
            pathx::mkdir(&destination, 0o777)?;
            for name in ["objects", "refs", "HEAD", "packed-refs", "shallow", "index"] {
                let path = source.join(name);
                if !path.exists() {
                    continue;
                }
                require(!pathx::is_symlink(&path), "indirect Git metadata")?;
                if path.is_dir() {
                    require(
                        !pathx::rglob(&path, "*")
                            .iter()
                            .any(|p| pathx::is_symlink(p)),
                        "indirect Git objects",
                    )?;
                    pathx::copytree(&path, &destination.join(name))?;
                } else {
                    pathx::copyfile(&path, &destination.join(name))?;
                }
            }
            pathx::write(
                &destination.join("config"),
                "[core]\nrepositoryformatversion = 0\nbare = false\n",
            )?;
        }
        Ok(destination)
    }

    fn inputs_root(&self) -> &Path {
        self.readonly_candidate_inputs
            .as_deref()
            .unwrap_or(&self.roots.candidate)
    }

    pub fn environment(&self, env: &Env) -> Result<Env> {
        let allowed = |key: &str| ALLOWED_ENV.contains(&key) || test_endpoint_key(key);
        let mut result: Env = env
            .iter()
            .filter(|(k, _)| allowed(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let count = py_int(env.get("GIT_CONFIG_COUNT").map_or("0", String::as_str))?;
        require((0..=1000).contains(&count), "invalid Git mapping count")?;
        result.insert("GIT_CONFIG_COUNT".into(), count.to_string());
        let prefix = format!(
            "url.{}/",
            file_uri(&self.inputs_root().join("canonical-inputs"))
        );
        for index in 0..count {
            let key_name = format!("GIT_CONFIG_KEY_{index}");
            let value_name = format!("GIT_CONFIG_VALUE_{index}");
            let key = env
                .get(&key_name)
                .ok_or_else(|| format!("KeyError: '{key_name}'"))?;
            let value = env
                .get(&value_name)
                .ok_or_else(|| format!("KeyError: '{value_name}'"))?;
            require(
                key.starts_with(&prefix) && key.ends_with(".insteadOf") && github_mapping(value),
                "unexpected Git setting in candidate environment",
            )?;
            result.insert(key_name, key.clone());
            result.insert(value_name, value.clone());
        }
        let mut git_roots = vec![self.roots.checkout.clone(), self.roots.trusted.clone()];
        for relative in ["host", "sdk", "c-witness"] {
            let path = self.inputs_root().join(relative);
            if path.exists() {
                git_roots.push(checked_directory(&path)?);
            }
        }
        let mut count = count;
        for path in git_roots {
            result.insert(format!("GIT_CONFIG_KEY_{count}"), "safe.directory".into());
            result.insert(format!("GIT_CONFIG_VALUE_{count}"), text(&path));
            count += 1;
        }
        result.insert("GIT_CONFIG_COUNT".into(), count.to_string());
        for (key, value) in str_map(self.config.at("environment")).unwrap_or_default() {
            result.insert(key, value);
        }
        if self.conformance_inputs_manifest.is_some() {
            result.insert(
                "BUSBAR_CONFORMANCE_INPUTS".into(),
                "/__busbar_conformance_inputs.json".into(),
            );
        }
        if self.dependency_seed.is_some() {
            result.insert("CARGO_HOME".into(), "/__busbar_job_seed".into());
        }
        result.insert("HOME".into(), text(&self.roots.candidate.join("home")));
        result.insert("GIT_CONFIG_GLOBAL".into(), "/dev/null".into());
        result.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        result.insert("CARGO_NET_OFFLINE".into(), "true".into());
        result.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
        writable_directory(&self.roots.candidate, &["home"])?;
        Ok(result)
    }

    pub fn cargo_environment(&self, argv: &[String], env: &Env) -> Result<Env> {
        let mut result = self.environment(env)?;
        if let Some(index) = argv.iter().position(|a| a == "--manifest-path") {
            let value = argv
                .get(index + 1)
                .ok_or("IndexError: list index out of range")?;
            let manifest = pathx::resolve(Path::new(value));
            if manifest.starts_with(&self.roots.harness) {
                // Stable since Cargo 1.97: trusted harness directories stay read-only.
                let name = format!(
                    "{}-{}",
                    sha256::hex(text(&manifest).as_bytes()),
                    pathx::uuid4()
                );
                let location =
                    writable_directory(&self.roots.candidate, &["harness-locks", &name])?;
                let lock = location.join("Cargo.lock");
                require(!pathx::is_symlink(&lock), "indirect harness lockfile")?;
                let original = manifest
                    .parent()
                    .unwrap_or(Path::new("/"))
                    .join("Cargo.lock");
                if !lock.exists() && original.is_file() {
                    pathx::copyfile(&original, &lock)?;
                }
                require(!pathx::is_symlink(&lock), "indirect harness lockfile")?;
                result.insert("CARGO_RESOLVER_LOCKFILE_PATH".into(), text(&lock));
                let fresh = self
                    .roots
                    .candidate
                    .join(format!("harness-target-{}", pathx::uuid4()));
                pathx::mkdir(&fresh, 0o777)?;
                result.insert("CARGO_TARGET_DIR".into(), text(&fresh));
                for key in [
                    "RUSTFLAGS",
                    "RUSTDOCFLAGS",
                    "RUSTC_WRAPPER",
                    "RUSTC_WORKSPACE_WRAPPER",
                ] {
                    result.insert(key.into(), String::new());
                }
            }
        }
        Ok(result)
    }

    fn prepare_command(&self, argv: Vec<String>, cwd: &Path) -> Result<Vec<String>> {
        if argv.len() < 2 || argv[0] != "cargo" || argv[1] != "vet" {
            return Ok(argv);
        }
        require(
            !argv.iter().any(|a| a == "--store-path"),
            "candidate-selected vet store is forbidden",
        )?;
        let mut manifest = cwd.join("Cargo.toml");
        if let Some(index) = argv.iter().position(|a| a == "--manifest-path") {
            manifest = PathBuf::from(
                argv.get(index + 1)
                    .ok_or("IndexError: list index out of range")?,
            );
            if !manifest.is_absolute() {
                manifest = cwd.join(manifest);
            }
        }
        let store = manifest
            .parent()
            .unwrap_or(Path::new("/"))
            .join("supply-chain");
        require(
            store.is_dir()
                && !pathx::is_symlink(&store)
                && !pathx::rglob(&store, "*")
                    .iter()
                    .any(|p| pathx::is_symlink(p)),
            "missing or indirect vet policy store",
        )?;
        let destination = self
            .roots
            .candidate
            .join(format!("vet-store-{}", pathx::uuid4()));
        pathx::copytree(&store, &destination)?;
        let mut argv = argv;
        argv.extend(["--store-path".into(), text(&destination)]);
        Ok(argv)
    }

    fn mounts(&mut self) -> Result<Vec<(PathBuf, PathBuf, bool)>> {
        let roots = self.roots.clone();
        let target = roots.checkout.join("target");
        if !self.compiler_readonly {
            mkdir_exist_ok(&target, 0o777)?;
            checked_directory(&target)?;
        }
        let mut mounts = vec![
            (roots.checkout.clone(), roots.checkout.clone(), false),
            (roots.candidate.clone(), roots.candidate.clone(), true),
            (roots.trusted.clone(), roots.trusted.clone(), false),
            (roots.harness.clone(), roots.harness.clone(), false),
            (self.sanitize_git()?, roots.checkout.join(".git"), false),
            (
                self.fixture_directory.clone(),
                PathBuf::from("/__busbar_fixtures"),
                false,
            ),
            (
                self.fixture_map.clone(),
                PathBuf::from("/__busbar_fixture_map.json"),
                false,
            ),
            (
                roots
                    .trusted
                    .join("scripts/architecture/confinement_entry.py"),
                PathBuf::from("/__busbar_entry.py"),
                false,
            ),
        ];
        if !self.compiler_readonly {
            mounts.push((target.clone(), target, true));
        }
        for relative in ["canonical-inputs", "host", "sdk", "c-witness"] {
            let path = self.inputs_root().join(relative);
            if path.exists() {
                mounts.push((checked_directory(&path)?, path, false));
            }
        }
        let nested = roots.checkout.join("dist/default/target");
        if nested.parent().is_some_and(Path::is_dir) && !self.compiler_readonly {
            mkdir_exist_ok(&nested, 0o777)?;
            checked_directory(&nested)?;
            mounts.push((nested.clone(), nested, true));
        }
        for path in &self.extra_readonly {
            mounts.push((checked_directory(path)?, path.clone(), false));
        }
        for (source, target) in &self.conformance_mounts {
            mounts.push((source.clone(), target.clone(), false));
        }
        if let Some(seed) = &self.dependency_seed {
            mounts.push((seed.clone(), PathBuf::from("/__busbar_job_seed"), false));
        }
        Ok(mounts)
    }

    /// One disposable candidate container around `body`, which receives the
    /// attach command and the Docker client environment.
    pub fn invocation<T>(
        &mut self,
        argv: &[String],
        cwd: &Path,
        env: &Env,
        discard_harness_target: bool,
        body: impl FnOnce(&[String], &[(String, String)]) -> Result<T>,
    ) -> Result<T> {
        require(
            argv.first().is_some_and(|a| !a.starts_with('-')),
            "missing candidate executable",
        )?;
        if discard_harness_target {
            let manifest = argv
                .iter()
                .position(|a| a == "--manifest-path")
                .and_then(|i| argv.get(i + 1));
            require(
                argv[0] == "cargo"
                    && manifest.is_some_and(|m| {
                        pathx::resolve(Path::new(m)).starts_with(&self.roots.harness)
                    }),
                "disposable target requires a trusted harness manifest",
            )?;
        }
        let cwd = pathx::resolve(cwd);
        require(
            self.roots
                .all()
                .iter()
                .any(|(_, root)| cwd.starts_with(root)),
            "candidate cwd escapes execution roots",
        )?;
        let argv = self.prepare_command(argv.to_vec(), &cwd)?;
        let name = format!("busbar-candidate-{}", pathx::uuid4());
        let aggregate = self.config.at("resources").clone();
        let resources = self
            .resource_slice
            .clone()
            .unwrap_or_else(|| aggregate.clone());
        if self.resource_slice.is_some() {
            let keys = ["cpus", "memory_bytes", "pids"];
            require(
                self.compiler_readonly
                    && resources.has_keys(&keys)
                    && keys.iter().all(|k| {
                        int(resources.at(k)).is_some_and(|v| {
                            v > 0 && int(aggregate.at(k)).is_some_and(|a| v * 2 <= a)
                        })
                    }),
                "compiler slices exceed the aggregate resource budget",
            )?;
        }
        let mounts = self.mounts()?;
        let fixture_hosts: Vec<String> = {
            let mut hosts = Vec::new();
            let has = |target: &str| {
                self.conformance_mounts
                    .iter()
                    .any(|(_, t)| t == Path::new(target))
            };
            if has("/opt/busbar-conformance/oidf") {
                hosts.extend([
                    "localhost.emobix.co.uk:127.0.0.1".to_owned(),
                    "busbar.oidf.test:127.0.0.1".to_owned(),
                ]);
            }
            if has("/opt/busbar-conformance/a2a-tools") {
                hosts.extend([
                    "example.com:104.20.23.154".to_owned(),
                    "example.com:172.66.147.243".to_owned(),
                ]);
            }
            hosts
        };
        let number = |key: &str| int(resources.at(key)).unwrap_or(0);
        let uid = int(self.config.at("uid")).unwrap_or(0);
        let gid = int(self.config.at("gid")).unwrap_or(0);
        let runtime = self.config.at("runtime").as_str().unwrap_or("").to_owned();
        let mut args: Vec<String> = [
            "create",
            "--name",
            &name,
            "--pull=never",
            "--read-only",
            "--network=none",
            "--runtime",
            &runtime,
            "--user",
            &format!("{uid}:{gid}"),
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--ipc=private",
            "--cgroupns=private",
            &format!("--pids-limit={}", number("pids")),
            &format!("--memory={}", number("memory_bytes")),
            &format!("--memory-swap={}", number("memory_bytes")),
            &format!("--cpus={}", number("cpus")),
            "--init",
            "--workdir",
            &text(&cwd),
            "--tmpfs",
            &format!("/tmp:{TMPFS}"),
            "--shm-size=64m",
            "--entrypoint",
            "/usr/bin/env",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        for alias in &fixture_hosts {
            args.extend(["--add-host".to_owned(), alias.clone()]);
        }
        for (source, destination, writable) in &mounts {
            require(
                !text(source).contains(',') && !text(destination).contains(','),
                "unsupported bind path",
            )?;
            args.push("--mount".into());
            args.push(format!(
                "type=bind,src={},dst={}{}",
                text(source),
                text(destination),
                if *writable { "" } else { ",readonly" }
            ));
        }
        let mut safe_env = self.cargo_environment(&argv, env)?;
        let mut disposable_target = None;
        if discard_harness_target {
            let target = PathBuf::from(
                safe_env
                    .get("CARGO_TARGET_DIR")
                    .cloned()
                    .unwrap_or_default(),
            );
            let valid_name = target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .and_then(|n| n.strip_prefix("harness-target-").map(str::to_owned))
                .is_some_and(|hex| {
                    hex.len() == 32 && hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
                });
            require(
                target.parent() == Some(self.roots.candidate.as_path())
                    && valid_name
                    && !pathx::is_symlink(&target),
                "invalid disposable harness target",
            )?;
            disposable_target = Some(target);
        }
        let mut cargo_home = None;
        if safe_env.get("CARGO_HOME").is_some_and(|v| !v.is_empty()) {
            // Stable dependency paths preserve Cargo target fingerprints. The
            // contents remain fresh for every invocation and are removed below.
            let home = self.roots.candidate.join("cargo-home-invocation");
            pathx::mkdir(&home, 0o700)?;
            safe_env.insert("BUSBAR_INVOCATION_CARGO_HOME".into(), text(&home));
            cargo_home = Some(home);
        }
        let isolation = self.config.at("isolation").clone();
        let writable: Vec<PathBuf> = mounts.iter().filter(|m| m.2).map(|m| m.0.clone()).collect();
        let mut storage = match &self.hooks.prepare_writable {
            Some(hook) => hook(&isolation, &writable, uid as u64, gid as u64)?,
            None => isolation::prepare_writable(&isolation, &writable, uid as u64, gid as u64)?,
        };
        let (code, info) = self.client(
            &["info".into(), "--format".into(), "{{json .}}".into()],
            true,
        )?;
        require(code == 0, "candidate daemon identity unavailable")?;
        let daemon = py::loads(info.as_bytes()).map_err(|e| e.message)?;
        let user_namespace = self.userns(&isolation, &daemon, None)?;
        safe_env.insert(
            "BUSBAR_EXPECTED_UID_MAP".into(),
            json::dumps(isolation.at("uid_map"), false),
        );
        safe_env.insert(
            "BUSBAR_EXPECTED_GID_MAP".into(),
            json::dumps(isolation.at("gid_map"), false),
        );
        storage.set("tmp_bytes", Value::int(1i64 << 30));
        storage.set("tmp_inodes", Value::int(65536));
        storage.set("shm_bytes", Value::int(64i64 << 20));
        args.push(self.config.at("image").as_str().unwrap_or("").to_owned());
        args.push("-i".into());
        args.extend(safe_env.iter().map(|(k, v)| format!("{k}={v}")));
        args.push(self.config.at("python").as_str().unwrap_or("").to_owned());
        args.extend(["-I", "-B", "/__busbar_entry.py", "--"].map(String::from));
        args.extend(argv.iter().cloned());
        let argv_value = Value::Array(argv.iter().map(|a| Value::str(a.clone())).collect());
        let env_value = Value::Object(
            safe_env
                .iter()
                .map(|(k, v)| (k.clone(), Value::str(v.clone())))
                .collect(),
        );
        let mut observation = object([
            ("name", Value::str(name.clone())),
            ("image", self.config.at("image").clone()),
            ("runtime", self.config.at("runtime").clone()),
            ("candidate_uid", self.config.at("uid").clone()),
            ("disposed", false.into()),
            ("command_sha256", canonical_sha(&argv_value).into()),
            ("environment_sha256", canonical_sha(&env_value).into()),
            ("working_directory", text(&cwd).into()),
            (
                "docker_client_sha256",
                self.config.at("docker_sha256").clone(),
            ),
            ("configuration_sha256", canonical_sha(&self.config).into()),
            ("resources", resources.clone()),
            (
                "dependency_seed_sha256",
                self.dependency_seed_sha256.clone(),
            ),
            ("storage", storage),
            ("user_namespace", user_namespace),
            (
                "fixture_hosts",
                Value::Array(
                    fixture_hosts
                        .iter()
                        .map(|h| Value::str(h.clone()))
                        .collect(),
                ),
            ),
        ]);
        if self.resource_slice.is_some() {
            observation.set("aggregate_resources", aggregate.clone());
            observation.set("compiler_pool_width", Value::int(2));
        }
        self.observations.push(observation);
        let at = self.observations.len() - 1;
        let attach = Attach {
            at,
            name: &name,
            args: &args,
            mounts: &mounts,
            fixture_hosts: &fixture_hosts,
            resources: &resources,
            daemon: &daemon,
            isolation: &isolation,
            user: format!("{uid}:{gid}"),
        };
        let outcome = self.attach(&attach, body);
        let cleanup = self.dispose(
            at,
            &name,
            disposable_target.as_deref(),
            cargo_home.as_deref(),
        );
        match cleanup {
            Err(error) => Err(error),
            Ok(()) => outcome,
        }
    }

    fn userns(
        &self,
        isolation: &Value,
        daemon: &Value,
        inspected: Option<&Value>,
    ) -> Result<Value> {
        match &self.hooks.userns {
            Some(hook) => hook(isolation, daemon, inspected),
            None => match inspected {
                None => isolation::validate_userns(isolation, daemon),
                Some(actual) => isolation::validate_userns_inspected(isolation, daemon, actual),
            },
        }
    }

    fn attach<T>(
        &mut self,
        a: &Attach,
        body: impl FnOnce(&[String], &[(String, String)]) -> Result<T>,
    ) -> Result<T> {
        let number = |resources: &Value, key: &str| int(resources.at(key)).unwrap_or(0);
        let (code, _) = self.client(a.args, true)?;
        require(code == 0, "candidate container creation failed")?;
        let (code, inspection) = self.client(&["inspect".into(), a.name.to_owned()], true)?;
        require(code == 0, "candidate inspection failed")?;
        let actual = py::loads(inspection.as_bytes()).map_err(|e| e.message)?;
        let actual = actual.index(0).clone();
        self.userns(a.isolation, a.daemon, Some(&actual))?;
        let host = actual.at("HostConfig");
        let empty = |v: &Value| !py::truthy(v);
        let extra_hosts = match host.get("ExtraHosts") {
            Some(v) if py::truthy(v) => v.clone(),
            _ => Value::Array(Vec::new()),
        };
        let expected_hosts = Value::Array(
            a.fixture_hosts
                .iter()
                .map(|h| Value::str(h.clone()))
                .collect(),
        );
        let tmpfs = object([("/tmp", TMPFS.into())]);
        require(
            host.at("NetworkMode").as_str() == Some("none")
                && matches!(host.at("ReadonlyRootfs"), Value::Bool(true))
                && matches!(host.at("Privileged"), Value::Bool(false))
                && matches!(host.at("PidMode").as_str(), Some("" | "private"))
                && host.at("IpcMode").as_str() == Some("private")
                && host.at("CgroupnsMode").as_str() == Some("private")
                && py::eq(host.at("Runtime"), self.config.at("runtime"))
                && actual.at("Config").at("User").as_str() == Some(a.user.as_str())
                && py::eq(host.at("CapDrop"), &Value::Array(vec!["ALL".into()]))
                && host.get("CapAdd").is_none_or(empty)
                && py::eq(host.at("PidsLimit"), a.resources.at("pids"))
                && py::eq(host.at("Memory"), a.resources.at("memory_bytes"))
                && py::eq(
                    host.at("NanoCpus"),
                    &Value::int(number(a.resources, "cpus") * 1_000_000_000),
                )
                && host.get("Devices").is_none_or(empty)
                && host.get("DeviceRequests").is_none_or(empty)
                && py::eq(&extra_hosts, &expected_hosts)
                && host
                    .get("ShmSize")
                    .is_some_and(|v| py::eq(v, &Value::int(64i64 << 20)))
                && host.get("Tmpfs").is_some_and(|v| py::eq(v, &tmpfs)),
            "runtime weakened candidate isolation",
        )?;
        let swap_bound = isolation::validate_swap_bound(
            a.daemon,
            host,
            number(a.resources, "memory_bytes") as u64,
        )?;
        let expected: Vec<(String, String, bool)> = {
            let mut rows: Vec<_> = a
                .mounts
                .iter()
                .map(|(s, d, w)| (text(s), text(d), *w))
                .collect();
            rows.sort();
            rows.dedup();
            rows
        };
        let mounts_list = actual.at("Mounts").as_array().unwrap_or(&[]);
        require(
            mounts_list
                .iter()
                .all(|m| matches!(m.at("Type").as_str(), Some("bind" | "tmpfs"))),
            "unexpected image volume",
        )?;
        let mut observed: Vec<(String, String, bool)> = Vec::new();
        for m in mounts_list
            .iter()
            .filter(|m| m.at("Type").as_str() == Some("bind"))
        {
            let row = (
                m.at("Source").as_str().unwrap_or("\0").to_owned(),
                m.at("Destination").as_str().unwrap_or("\0").to_owned(),
                m.at("RW").as_bool().unwrap_or(false),
            );
            require(
                m.at("RW").as_bool().is_some(),
                "runtime candidate mounts differ",
            )?;
            observed.push(row);
        }
        observed.sort();
        observed.dedup();
        require(observed == expected, "runtime candidate mounts differ")?;
        require(
            host.at("SecurityOpt").as_array().is_some_and(|rows| {
                rows.iter().any(|v| {
                    matches!(
                        v.as_str(),
                        Some("no-new-privileges" | "no-new-privileges:true")
                    )
                })
            }),
            "runtime permits privilege gain",
        )?;
        let mounts_value = Value::Array(
            expected
                .iter()
                .map(|(s, d, w)| {
                    Value::Array(vec![s.clone().into(), d.clone().into(), (*w).into()])
                })
                .collect(),
        );
        let row = &mut self.observations[a.at];
        row.set("container_id", actual.at("Id").clone());
        row.set("image_id", actual.at("Image").clone());
        row.set("network", "none".into());
        row.set("inspected", true.into());
        row.set("mounts_sha256", canonical_sha(&mounts_value).into());
        row.set("security_options", host.at("SecurityOpt").clone());
        row.set("swap_bound", swap_bound);
        let mut command = self.docker.clone();
        command.extend(["start".into(), "--attach".into(), a.name.to_owned()]);
        body(&command, &self.client_env)
    }

    fn dispose(
        &mut self,
        at: usize,
        name: &str,
        disposable_target: Option<&Path>,
        cargo_home: Option<&Path>,
    ) -> Result<()> {
        // Read process state from the engine before deleting the container.
        // These controller observations are still not an independent host attestation.
        let mut state_error = false;
        if self.observations[at].at("inspected").truthy() {
            let state = (|| -> Result<Value> {
                let (code, text) = self.client(
                    &[
                        "inspect".into(),
                        "--format".into(),
                        "{{json .State}}".into(),
                        name.into(),
                    ],
                    true,
                )?;
                require(code == 0, "candidate process state unavailable")?;
                let actual = py::loads(text.as_bytes()).map_err(|e| e.message)?;
                let keys = [
                    "Status",
                    "Running",
                    "ExitCode",
                    "OOMKilled",
                    "Error",
                    "StartedAt",
                    "FinishedAt",
                ];
                Ok(Value::Object(
                    keys.iter()
                        .map(|k| ((*k).to_owned(), actual.at(k).clone()))
                        .collect(),
                ))
            })();
            match state {
                Ok(value) => self.observations[at].set("state_before_disposal", value),
                Err(error) => {
                    state_error = true;
                    let kind = if error.contains("unavailable") {
                        "ValueError"
                    } else {
                        "JSONDecodeError"
                    };
                    self.observations[at].set("state_observation_error", kind.into());
                }
            }
        }
        let removed = self
            .client(&["rm".into(), "--force".into(), name.into()], false)?
            .0;
        let (code, listing) = self.client(
            &[
                "container".into(),
                "ls".into(),
                "--all".into(),
                "--quiet".into(),
                "--filter".into(),
                format!("name=^/{name}$"),
            ],
            true,
        )?;
        let inspected = self.observations[at].at("inspected").truthy();
        require(
            code == 0 && listing.trim_matches(py_space).is_empty() && (removed == 0 || !inspected),
            "candidate disposal was not confirmed",
        )?;
        self.observations[at].set("disposed", true.into());
        if let Some(target) = disposable_target {
            // The container is gone before touching candidate-owned artifacts.
            // Unlink a replaced top-level symlink instead of following it.
            if pathx::is_symlink(target) {
                io(fs::remove_file(target), target)?;
            } else if target.exists() {
                pathx::rmtree(target)?;
            }
            self.observations[at].set("harness_target_removed", true.into());
            self.observations[at].set(
                "harness_target_path_sha256",
                sha256::hex(text(target).as_bytes()).into(),
            );
        }
        if let Some(home) = cargo_home {
            if pathx::is_symlink(home) {
                io(fs::remove_file(home), home)?;
            } else if home.exists() {
                pathx::rmtree(home)?;
            }
            self.observations[at].set("private_cargo_cache_removed", true.into());
        }
        if self.observations[at].get("swap_bound").is_some() {
            let mut proof = self.observations[at].at("swap_bound").clone();
            isolation::recheck_swap_bound(&mut proof)?;
            self.observations[at].set("swap_bound", proof);
        }
        require(!state_error, "candidate process state observation failed")
    }

    pub fn compiler_pool(&mut self) -> Result<CompilerPool<'_>> {
        CompilerPool::new(self)
    }
}

/// Spawn a client command in this process group, as `subprocess` does.
pub fn spawn(
    argv: &[String],
    env: Option<&[(String, String)]>,
    cwd: Option<&Path>,
    capture_stdout: bool,
    capture_stderr: bool,
    cancel: Option<&dyn Fn() -> bool>,
) -> Result<(i32, Vec<u8>, Vec<u8>, bool)> {
    let (program, args) = argv.split_first().ok_or("missing candidate executable")?;
    let mut command = Command::new(program);
    command.args(args);
    if let Some(env) = env {
        command.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdin(Stdio::inherit());
    if capture_stdout {
        command.stdout(Stdio::piped());
    }
    if capture_stderr {
        command.stderr(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|e| pathx::os_error(&e, Some(Path::new(program))))?;
    let reader = |stream: Option<Box<dyn Read + Send>>| {
        stream.map(|mut stream| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let _ = stream.read_to_end(&mut out);
                out
            })
        })
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let mut cancelled = false;
    let status = match cancel {
        None => child.wait().map_err(|e| e.to_string())?,
        Some(stop) => loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if stop() {
                let _ = child.kill();
                cancelled = true;
                break child.wait().map_err(|e| e.to_string())?;
            }
            std::thread::sleep(Duration::from_millis(50));
        },
    };
    let stdout = out
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = err
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    Ok((pathx::returncode(status), stdout, stderr, cancelled))
}

/// Two compiler isolates sharing only readonly inputs and an aggregate quota.
///
/// Each case owns its Execution, observations, home, lockfile, cache and target.
/// The callback validates its result so failure cancels other work before
/// another case starts. No successful receipt survives an error.
pub struct CompilerPool<'a> {
    execution: &'a mut Execution,
    resources: Value,
    cancel: Arc<AtomicBool>,
    used: bool,
}

/// One compiler case's private isolate.
pub struct Slot {
    pub execution: Execution,
    cancel: Arc<AtomicBool>,
}

impl Slot {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst) || proc::interrupted().is_some()
    }

    /// `CompilerPool.run`: one confined compiler command, cancellable.
    pub fn run(&mut self, argv: &[String], cwd: &Path) -> Result<Done> {
        if self.cancelled() {
            return Err(CANCELLED.into());
        }
        let mut env = process_env();
        for (key, value) in [
            ("TMPDIR", "/tmp"),
            ("BUSBAR_TEST_TMP_ROOT", "/tmp/tests"),
            ("XDG_CACHE_HOME", "/tmp/cache"),
            ("MODERNCI_CACHE_DIR", "/tmp/cache"),
            ("CARGO_BUILD_JOBS", "2"),
        ] {
            env.insert(key.into(), value.into());
        }
        let cancel = self.cancel.clone();
        self.execution
            .invocation(argv, cwd, &env, true, |command, client_env| {
                let stop = || cancel.load(Ordering::SeqCst) || proc::interrupted().is_some();
                if stop() {
                    return Err(CANCELLED.into());
                }
                let (code, stdout, stderr, cancelled) =
                    spawn(command, Some(client_env), None, true, true, Some(&stop))?;
                if cancelled {
                    return Err(CANCELLED.into());
                }
                Ok(Done {
                    code,
                    stdout: pathx::text_mode(&stdout)?,
                    stderr: pathx::text_mode(&stderr)?,
                })
            })
    }
}

impl<'a> CompilerPool<'a> {
    pub fn new(execution: &'a mut Execution) -> Result<CompilerPool<'a>> {
        let resources = execution.config.at("resources").clone();
        let value = |key: &str| int(resources.at(key)).unwrap_or(0);
        require(
            value("cpus") >= 4 && value("memory_bytes") >= 6 << 30 && value("pids") >= 2,
            "compiler pool requires the measured resource budget",
        )?;
        // Deliberately cap the pool at the measured 4 CPU / 6 GiB even on larger
        // runners. Container memory includes its tmpfs and shared memory charges.
        let slice = object([
            ("cpus", Value::int(2)),
            ("memory_bytes", Value::int(3i64 << 30)),
            ("pids", Value::int(value("pids") / 2)),
        ]);
        Ok(CompilerPool {
            execution,
            resources: slice,
            cancel: Arc::new(AtomicBool::new(false)),
            used: false,
        })
    }

    /// Run every case on at most two isolates, in submission order; observations
    /// merge in case order; the first non-cancellation failure is reported.
    pub fn map<C: Sync, R: Send>(
        &mut self,
        cases: &[C],
        function: &(dyn Fn(&mut Slot, usize, &C) -> Result<R> + Sync),
    ) -> Result<Vec<R>> {
        require(!self.used, "compiler pool cannot be reused")?;
        self.used = true;
        let prepared_git = self.execution.sanitize_git()?;
        let parent = self.execution.clone();
        let resources = self.resources.clone();
        let cancel = self.cancel.clone();
        let next = std::sync::Mutex::new(0usize);
        type Outcome<R> = (Result<R>, Vec<Value>);
        let outcomes: std::sync::Mutex<BTreeMap<usize, Outcome<R>>> = Default::default();
        proc::install_signal_handlers();
        let invoke = |index: usize, case: &C| -> Outcome<R> {
            if cancel.load(Ordering::SeqCst) || proc::interrupted().is_some() {
                cancel.store(true, Ordering::SeqCst);
                return (Err(CANCELLED.into()), Vec::new());
            }
            let base = parent
                .roots
                .candidate
                .parent()
                .unwrap_or(Path::new("/"))
                .join(format!("compiler-isolate-{}", pathx::uuid4()));
            let prepare = || -> Result<Execution> {
                pathx::mkdir(&base, 0o755)?;
                let (candidate, control) = (base.join("candidate"), base.join("control"));
                pathx::mkdir(&candidate, 0o755)?;
                pathx::mkdir(&control, 0o700)?;
                let mut child = parent.clone();
                child.roots.candidate = candidate;
                child.control = control.clone();
                child.observations = Vec::new();
                child.resource_slice = Some(resources.clone());
                child.compiler_readonly = true;
                child.prepared_git = Some(prepared_git.clone());
                child.readonly_candidate_inputs = Some(parent.roots.candidate.clone());
                // Compiler checks receive no service capabilities or mutable parent
                // candidate mount. Their source is the readonly core checkout.
                child.fixture_directory = control.join("fixture-sockets");
                pathx::mkdir(&child.fixture_directory, 0o755)?;
                child.fixture_map = control.join("fixture-map.json");
                pathx::write(&child.fixture_map, "[]\n")?;
                Ok(child)
            };
            let mut slot = match prepare() {
                Ok(child) => Slot {
                    execution: child,
                    cancel: cancel.clone(),
                },
                Err(error) => {
                    cancel.store(true, Ordering::SeqCst);
                    return (Err(error), Vec::new());
                }
            };
            let mut result = function(&mut slot, index, case);
            if result.is_err() {
                cancel.store(true, Ordering::SeqCst);
            }
            let mut rows = std::mem::take(&mut slot.execution.observations);
            for row in &mut rows {
                row.set("compiler_case_index", Value::int(index as i64));
            }
            // Never delete artifacts while a container could still hold
            // them. A failed disposal retains the entire private root.
            if rows.iter().all(|row| row.at("disposed").truthy())
                && let Err(error) = pathx::rmtree(&base)
            {
                cancel.store(true, Ordering::SeqCst);
                result = Err(error);
            }
            (result, rows)
        };
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    loop {
                        let index = {
                            let mut next = next.lock().unwrap();
                            let index = *next;
                            *next += 1;
                            index
                        };
                        let Some(case) = cases.get(index) else {
                            break;
                        };
                        let outcome = invoke(index, case);
                        outcomes.lock().unwrap().insert(index, outcome);
                    }
                });
            }
        });
        proc::restore_default_signals();
        let outcomes = outcomes.into_inner().unwrap();
        let mut results = Vec::new();
        let mut errors = Vec::new();
        for (_, (result, rows)) in outcomes {
            self.execution.observations.extend(rows);
            match result {
                Ok(value) => results.push(value),
                Err(error) => errors.push(error),
            }
        }
        if let Some(signal) = proc::interrupted() {
            return Err(format!("compiler pool interrupted by signal {signal}"));
        }
        if !errors.is_empty() {
            let first = errors
                .iter()
                .find(|e| *e != CANCELLED)
                .unwrap_or(&errors[0]);
            return Err(first.clone());
        }
        Ok(results)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The Python `Fixture`: four roots, a control directory and a confinement
    /// configuration whose Docker client is `/bin/echo`.
    pub struct Fixture {
        pub base: PathBuf,
        pub roots: Roots,
        pub control: PathBuf,
        pub config: Value,
    }

    impl Fixture {
        pub fn new() -> Fixture {
            let base =
                pathx::resolve(&std::env::temp_dir().join(format!("confine-{}", pathx::uuid4())));
            let roots = Roots {
                checkout: base.join("checkout"),
                candidate: base.join("candidate"),
                trusted: base.join("trusted"),
                harness: base.join("harness"),
            };
            let control = base.join("control");
            fs::create_dir_all(&base).unwrap();
            for (_, path) in roots.all() {
                fs::create_dir(path).unwrap();
            }
            fs::create_dir(&control).unwrap();
            fs::create_dir(roots.checkout.join(".git")).unwrap();
            fs::write(
                roots.checkout.join(".git/config"),
                "url=https://secret-token@example.invalid/repo",
            )
            .unwrap();
            let config = json::parse(
                format!(
                    r#"{{"schema": "busbar.native-confinement/2", "docker": "/bin/echo",
                "docker_sha256": "{}", "docker_host": "unix:///var/run/docker.sock",
                "image": "python@sha256:{}", "runtime": "runc", "uid": 1000, "gid": 1000,
                "python": "/usr/local/bin/python3", "environment": {{"PATH": "/usr/local/bin:/usr/bin:/bin"}},
                "resources": {{"cpus": 2, "memory_bytes": 2147483648, "pids": 256}},
                "collector": {{"docker_host": "unix:///var/run/docker.sock", "uid": 525288, "gid": 525288}},
                "isolation": {{"storage_kind": "tmpfs", "storage_reserve_bytes": 0,
                  "storage_root": "{}", "storage_bytes": 67108864, "storage_inodes": 4096,
                  "uid_map": [0, 524288, 65536], "gid_map": [0, 524288, 65536]}}}}"#,
                    digest(Path::new("/bin/echo")).unwrap(),
                    "a".repeat(64),
                    text(&base)
                )
                .as_bytes(),
            )
            .unwrap();
            Fixture {
                base,
                roots,
                control,
                config,
            }
        }

        pub fn roots_value(&self) -> Value {
            Value::Object(
                self.roots
                    .all()
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), text(v).into()))
                    .collect(),
            )
        }

        pub fn execution(&self, hooks: Hooks) -> Execution {
            Execution::new(
                self.config.clone(),
                &self.roots_value(),
                &self.control,
                hooks,
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    /// The fake engine of the former test_compiler_parallel.py and test_compiler_storage.py.
    pub struct Engine {
        pub calls: Mutex<Vec<Vec<String>>>,
        pub created: Mutex<BTreeMap<String, Vec<String>>>,
        pub removed: Mutex<Vec<String>>,
        pub targets: Mutex<Vec<PathBuf>>,
        pub mismatch: Mutex<Option<&'static str>>,
        pub fail_disposal: AtomicBool,
        pub memory: i64,
    }

    impl Engine {
        pub fn new(memory: i64) -> Arc<Engine> {
            Arc::new(Engine {
                calls: Default::default(),
                created: Default::default(),
                removed: Default::default(),
                targets: Default::default(),
                mismatch: Mutex::new(None),
                fail_disposal: AtomicBool::new(false),
                memory,
            })
        }

        pub fn hooks(self: &Arc<Engine>) -> Hooks {
            let engine = self.clone();
            Hooks {
                client: Some(Arc::new(move |argv: &[String], _| Ok(engine.client(argv)))),
                prepare_writable: Some(Arc::new(|config: &Value, _: &[PathBuf], _, _| {
                    Ok(object([
                        ("root", config.at("storage_root").clone()),
                        ("bytes", config.at("storage_bytes").clone()),
                    ]))
                })),
                userns: Some(Arc::new(|_: &Value, _: &Value, _: Option<&Value>| {
                    Ok(object([]))
                })),
            }
        }

        fn client(&self, argv: &[String]) -> (i32, String) {
            self.calls.lock().unwrap().push(argv.to_vec());
            let mut payload = String::new();
            let mut code = 0;
            match argv[0].as_str() {
                "create" => {
                    let name = argv[argv.iter().position(|a| a == "--name").unwrap() + 1].clone();
                    if let Some(target) = argv
                        .iter()
                        .find_map(|a| a.strip_prefix("CARGO_TARGET_DIR="))
                    {
                        let target = PathBuf::from(target);
                        let _ = fs::write(target.join("artifact"), b"compiler output");
                        self.targets.lock().unwrap().push(target);
                    }
                    self.created.lock().unwrap().insert(name, argv.to_vec());
                }
                "info" => {
                    payload = r#"{"SecurityOptions": ["name=userns"], "SwapLimit": true}"#.into()
                }
                "inspect" if argv[1] == "--format" => payload =
                    r#"{"Status": "exited", "Running": false, "ExitCode": 0, "OOMKilled": false}"#
                        .into(),
                "inspect" => {
                    let args = self.created.lock().unwrap()[&argv[1]].clone();
                    let values: BTreeMap<String, String> = args
                        .iter()
                        .filter_map(|a| a.strip_prefix("--").and_then(|a| a.split_once('=')))
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect();
                    let mut mounts = Vec::new();
                    for (i, value) in args.iter().enumerate() {
                        if value == "--mount" {
                            let fields: BTreeMap<&str, &str> = args[i + 1]
                                .split(',')
                                .map(|p| p.split_once('=').unwrap_or((p, "")))
                                .collect();
                            mounts.push(format!(
                                r#"{{"Type": "{}", "Source": "{}", "Destination": "{}", "RW": {}}}"#,
                                fields["type"],
                                fields["src"],
                                fields["dst"],
                                !fields.contains_key("readonly")
                            ));
                        }
                    }
                    let mut numbers: BTreeMap<&str, i64> = [
                        ("PidsLimit", values["pids-limit"].parse::<i64>().unwrap()),
                        ("Memory", values["memory"].parse().unwrap()),
                        ("MemorySwap", values["memory-swap"].parse().unwrap()),
                        (
                            "NanoCpus",
                            values["cpus"].parse::<i64>().unwrap() * 1_000_000_000,
                        ),
                    ]
                    .into_iter()
                    .collect();
                    if self.memory > 0 {
                        numbers.insert("Memory", self.memory);
                        numbers.insert("MemorySwap", self.memory);
                    }
                    if let Some(field) = *self.mismatch.lock().unwrap() {
                        *numbers.get_mut(field).unwrap() += 1;
                    }
                    payload = format!(
                        r#"[{{"Id": "{}", "Image": "python@sha256:{}", "Config": {{"User": "1000:1000"}},
                        "Mounts": [{}], "HostConfig": {{"NetworkMode": "none", "ReadonlyRootfs": true,
                        "Privileged": false, "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private",
                        "Runtime": "runc", "CapDrop": ["ALL"], "CapAdd": [], "PidsLimit": {}, "Memory": {},
                        "MemorySwap": {}, "NanoCpus": {}, "Devices": [], "DeviceRequests": [], "ExtraHosts": [],
                        "ShmSize": 67108864, "Tmpfs": {{"/tmp": "{TMPFS}"}},
                        "SecurityOpt": ["no-new-privileges"]}}}}]"#,
                        argv[1],
                        "a".repeat(64),
                        mounts.join(", "),
                        numbers["PidsLimit"],
                        numbers["Memory"],
                        numbers["MemorySwap"],
                        numbers["NanoCpus"],
                    );
                }
                "rm" => {
                    // HarnessStorage (serial) only: artifacts outlive container removal.
                    if self.memory > 0
                        && let Some(last) = self.targets.lock().unwrap().last()
                    {
                        assert!(
                            last.exists(),
                            "artifacts must exist until container removal"
                        );
                    }
                    self.removed
                        .lock()
                        .unwrap()
                        .push(argv.last().unwrap().clone());
                }
                "container" if self.fail_disposal.load(Ordering::SeqCst) => code = 1,
                _ => {}
            }
            (code, payload)
        }
    }

    fn harness_argv(fixture: &Fixture) -> Vec<String> {
        let manifest = fixture.roots.harness.join("Cargo.toml");
        fs::write(&manifest, "[workspace]\n").unwrap();
        ["cargo", "check", "--manifest-path", &text(&manifest)]
            .map(String::from)
            .to_vec()
    }

    // test_compiler_storage.HarnessStorage

    #[test]
    fn completed_cases_have_unique_targets_and_reclaim_each_one() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        let mut execution = fixture.execution(engine.hooks());
        let argv = harness_argv(&fixture);
        for _ in 0..3 {
            execution
                .invocation(&argv, &fixture.roots.checkout, &Env::new(), true, |_, _| {
                    assert!(engine.targets.lock().unwrap().last().unwrap().exists());
                    Ok(())
                })
                .unwrap();
            let target = engine.targets.lock().unwrap().last().unwrap().clone();
            assert!(!target.exists());
            let row = execution.observations.last().unwrap();
            assert!(row.at("disposed").truthy() && row.at("harness_target_removed").truthy());
            assert_eq!(
                row.at("harness_target_path_sha256").as_str().unwrap(),
                sha256::hex(text(&target).as_bytes())
            );
        }
        let targets = engine.targets.lock().unwrap().clone();
        assert_eq!(
            targets
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn default_retains_generated_build_output() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        let mut execution = fixture.execution(engine.hooks());
        let argv = harness_argv(&fixture);
        execution
            .invocation(
                &argv,
                &fixture.roots.checkout,
                &Env::new(),
                false,
                |_, _| Ok(()),
            )
            .unwrap();
        assert!(
            engine
                .targets
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .join("artifact")
                .exists()
        );
        assert!(
            execution
                .observations
                .last()
                .unwrap()
                .get("harness_target_removed")
                .is_none()
        );
    }

    #[test]
    fn process_error_still_reclaims_after_confirmed_disposal() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        let mut execution = fixture.execution(engine.hooks());
        let argv = harness_argv(&fixture);
        let result: Result<()> =
            execution.invocation(&argv, &fixture.roots.checkout, &Env::new(), true, |_, _| {
                Err(pathx::called_process_error(&argv, 1))
            });
        assert!(result.unwrap_err().contains("non-zero exit status 1"));
        assert!(!engine.targets.lock().unwrap().last().unwrap().exists());
    }

    #[test]
    fn daemon_loss_retains_artifacts_and_refuses_disposal_claim() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        engine.fail_disposal.store(true, Ordering::SeqCst);
        let mut execution = fixture.execution(engine.hooks());
        let argv = harness_argv(&fixture);
        let error = execution
            .invocation(&argv, &fixture.roots.checkout, &Env::new(), true, |_, _| {
                Ok(())
            })
            .unwrap_err();
        assert!(error.contains("disposal"));
        assert!(engine.targets.lock().unwrap().last().unwrap().exists());
        let row = execution.observations.last().unwrap();
        assert!(!row.at("disposed").truthy());
        assert!(row.get("harness_target_removed").is_none());
    }

    #[test]
    fn replaced_target_symlink_does_not_delete_its_destination() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        let mut execution = fixture.execution(engine.hooks());
        let argv = harness_argv(&fixture);
        let sentinel = fixture.control.join("preserve");
        fs::write(&sentinel, "controller evidence").unwrap();
        let control = fixture.control.clone();
        execution
            .invocation(&argv, &fixture.roots.checkout, &Env::new(), true, |_, _| {
                let target = engine.targets.lock().unwrap().last().unwrap().clone();
                fs::remove_dir_all(&target).unwrap();
                std::os::unix::fs::symlink(&control, &target).unwrap();
                Ok(())
            })
            .unwrap();
        let target = engine.targets.lock().unwrap().last().unwrap().clone();
        assert!(!pathx::is_symlink(&target));
        assert_eq!(
            fs::read_to_string(&sentinel).unwrap(),
            "controller evidence"
        );
    }

    #[test]
    fn candidate_manifest_cannot_request_target_disposal() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        let mut execution = fixture.execution(engine.hooks());
        let mut argv = harness_argv(&fixture);
        *argv.last_mut().unwrap() = text(&fixture.roots.checkout.join("Cargo.toml"));
        let error = execution
            .invocation(
                &argv,
                &fixture.roots.checkout,
                &Env::new(),
                true,
                |_, _| -> Result<()> { panic!("candidate manifest accepted") },
            )
            .unwrap_err();
        assert!(error.contains("trusted harness"));
        assert!(engine.created.lock().unwrap().is_empty());
    }

    #[test]
    fn candidate_symlinks_cannot_redirect_controller_harness_preparation() {
        let fixture = Fixture::new();
        let execution = fixture.execution(Hooks::default());
        let argv = harness_argv(&fixture);
        std::os::unix::fs::symlink(
            &fixture.control,
            fixture.roots.candidate.join("harness-locks"),
        )
        .unwrap();
        let before: Vec<_> = fs::read_dir(&fixture.control)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        let error = execution.cargo_environment(&argv, &Env::new()).unwrap_err();
        assert!(error.contains("indirect writable"));
        let after: Vec<_> = fs::read_dir(&fixture.control)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(before.len(), after.len());
    }

    #[test]
    fn requires_pinned_client_image_nonroot_and_private_roots() {
        let fixture = Fixture::new();
        for (key, value) in [
            ("docker_sha256", Value::str("0".repeat(64))),
            ("image", Value::str("python:latest")),
            ("uid", Value::int(0)),
            ("runtime", Value::str("untrusted")),
            ("docker_host", Value::str("tcp://host:2375")),
        ] {
            let mut config = fixture.config.clone();
            config.set(key, value);
            assert!(
                Execution::new(
                    config,
                    &fixture.roots_value(),
                    &fixture.control,
                    Hooks::default()
                )
                .is_err()
            );
        }
        let mut roots = fixture.roots_value();
        roots.set(
            "candidate",
            text(&fixture.roots.checkout.join("nested")).into(),
        );
        fs::create_dir(fixture.roots.checkout.join("nested")).unwrap();
        assert!(
            Execution::new(
                fixture.config.clone(),
                &roots,
                &fixture.control,
                Hooks::default()
            )
            .is_err()
        );
    }

    #[test]
    fn context_round_trip_and_digest_binding() {
        let fixture = Fixture::new();
        let generated = fixture.roots.candidate.join("generated/x");
        fs::create_dir_all(&generated).unwrap();
        let context = object([
            ("configuration", fixture.config.clone()),
            ("roots", fixture.roots_value()),
            ("control", text(&fixture.control).into()),
            (
                "extra_readonly",
                Value::Array(vec![text(&generated).into()]),
            ),
            ("conformance_mounts", Value::Array(vec![])),
            ("conformance_inputs_manifest", Value::Null),
            ("dependency_seed", Value::Null),
            ("dependency_seed_sha256", Value::Null),
        ]);
        let path = fixture.control.join("execution-context.json");
        fs::write(&path, canonical(&context)).unwrap();
        let expected = digest(&path).unwrap();
        let execution = Execution::from_context(&path, &expected, Hooks::default()).unwrap();
        assert_eq!(execution.roots, fixture.roots);
        assert!(py::eq(&execution.config, &fixture.config));
        assert_eq!(execution.extra_readonly, vec![generated]);
        assert!(Execution::from_context(&path, &"0".repeat(64), Hooks::default()).is_err());
    }

    // test_compiler_parallel.ParallelCompiler

    fn pool_fixture() -> (Fixture, Arc<Engine>, Execution, Vec<String>) {
        let mut fixture = Fixture::new();
        fixture.config.set(
            "resources",
            object([
                ("cpus", Value::int(4)),
                ("memory_bytes", Value::int(6i64 << 30)),
                ("pids", Value::int(256)),
            ]),
        );
        let engine = Engine::new(0);
        let execution = fixture.execution(engine.hooks());
        let argv = harness_argv(&fixture);
        (fixture, engine, execution, argv)
    }

    fn isolates(fixture: &Fixture) -> usize {
        fs::read_dir(&fixture.base)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("compiler-isolate-")
            })
            .count()
    }

    #[test]
    fn two_isolates_enforce_aggregate_limits_and_merge_in_case_order() {
        let (fixture, engine, mut parent, argv) = pool_fixture();
        let barrier = std::sync::Barrier::new(2);
        let harness = fixture.roots.harness.clone();
        let writable = Mutex::new(Vec::new());
        let results = parent
            .compiler_pool()
            .unwrap()
            .map(&[0usize, 1], &|slot: &mut Slot, _, index: &usize| {
                writable
                    .lock()
                    .unwrap()
                    .push(slot.execution.roots.candidate.clone());
                slot.execution
                    .invocation(&argv, &harness, &Env::new(), true, |_, _| {
                        barrier.wait();
                        if *index == 0 {
                            std::thread::sleep(Duration::from_millis(30));
                        }
                        Ok(*index)
                    })
            })
            .unwrap();
        assert_eq!(results, vec![0, 1]);
        let rows = &parent.observations;
        let indices: Vec<_> = rows
            .iter()
            .map(|r| r.at("compiler_case_index").as_u64().unwrap())
            .collect();
        assert_eq!(indices, vec![0, 1]);
        assert_eq!(engine.removed.lock().unwrap().len(), 2);
        assert_eq!(
            writable
                .lock()
                .unwrap()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
        assert_eq!(isolates(&fixture), 0);
        for key in ["cpus", "memory_bytes", "pids"] {
            let total: u64 = rows
                .iter()
                .map(|r| r.at("resources").at(key).as_u64().unwrap())
                .sum();
            assert!(total <= fixture.config.at("resources").at(key).as_u64().unwrap());
        }
        for row in rows {
            assert_eq!(
                row.at("configuration_sha256").as_str().unwrap(),
                canonical_sha(&fixture.config)
            );
            assert!(py::eq(
                row.at("aggregate_resources"),
                fixture.config.at("resources")
            ));
            assert_eq!(
                json::dumps(row.at("resources"), false),
                r#"{"cpus": 2, "memory_bytes": 3221225472, "pids": 128}"#
            );
            assert_eq!(
                row.at("storage").at("root").as_str().unwrap(),
                text(&fixture.base)
            );
            assert_eq!(row.at("storage").at("tmp_bytes").as_u64(), Some(1 << 30));
            assert_eq!(row.at("storage").at("shm_bytes").as_u64(), Some(64 << 20));
            assert_eq!(
                row.at("swap_bound").at("effective_swap_bytes").as_u64(),
                Some(0)
            );
            assert!(row.at("disposed").truthy() && row.at("harness_target_removed").truthy());
        }
    }

    #[test]
    fn engine_limit_mismatch_refuses_and_disposes() {
        for field in ["PidsLimit", "Memory", "NanoCpus", "MemorySwap"] {
            let (fixture, engine, mut parent, argv) = pool_fixture();
            *engine.mismatch.lock().unwrap() = Some(field);
            let harness = fixture.roots.harness.clone();
            let result =
                parent
                    .compiler_pool()
                    .unwrap()
                    .map(&[0usize], &|slot: &mut Slot, _, _| {
                        slot.execution.invocation(
                            &argv,
                            &harness,
                            &Env::new(),
                            true,
                            |_, _| -> Result<()> { panic!("weakened engine limits were accepted") },
                        )
                    });
            assert!(result.is_err(), "{field}");
            assert!(parent.observations.last().unwrap().at("disposed").truthy());
            assert_eq!(isolates(&fixture), 0);
        }
    }

    #[test]
    fn unconfirmed_disposal_retains_private_artifacts_and_fails() {
        let (fixture, engine, mut parent, argv) = pool_fixture();
        engine.fail_disposal.store(true, Ordering::SeqCst);
        let harness = fixture.roots.harness.clone();
        let error = parent
            .compiler_pool()
            .unwrap()
            .map(&[0usize], &|slot: &mut Slot, _, _| {
                slot.execution
                    .invocation(&argv, &harness, &Env::new(), true, |_, _| Ok(()))
            })
            .unwrap_err();
        assert!(error.contains("disposal"));
        assert_eq!(isolates(&fixture), 1);
        assert!(!parent.observations.last().unwrap().at("disposed").truthy());
    }

    #[test]
    fn case_failure_cancels_and_reaps_other_attach_process() {
        let (fixture, _engine, mut parent, _) = pool_fixture();
        let ready = fixture.base.join("ready");
        let disposed = Mutex::new(0);
        let mut pool = parent.compiler_pool().unwrap();
        let cancel = pool.cancel.clone();
        let error = pool
            .map(&[0usize, 1, 2, 3], &|slot: &mut Slot,
                                       index,
                                       _|
             -> Result<Option<i32>> {
                if index == 0 {
                    let script = format!("echo $$ > {}; exec sleep 60", text(&ready));
                    let argv = ["/bin/sh", "-c", &script].map(String::from);
                    let stop = || slot.cancel.load(Ordering::SeqCst);
                    let (_, _, _, cancelled) = spawn(&argv, None, None, true, true, Some(&stop))?;
                    *disposed.lock().unwrap() += 1;
                    return if cancelled {
                        Err(CANCELLED.into())
                    } else {
                        Ok(None)
                    };
                }
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !ready.exists() && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(ready.exists(), "attach client never started");
                std::thread::sleep(Duration::from_millis(50));
                Err("wrong compiler diagnostic".into())
            })
            .unwrap_err();
        assert_eq!(error, "wrong compiler diagnostic");
        assert!(cancel.load(Ordering::SeqCst));
        let pid: i32 = fs::read_to_string(&ready).unwrap().trim().parse().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            std::process::Command::new("/bin/kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| !s.success())
        );
        assert_eq!(*disposed.lock().unwrap(), 1);
        assert_eq!(isolates(&fixture), 0);
    }

    #[test]
    fn insufficient_budget_refuses_without_creating_isolates() {
        let (fixture, engine, mut parent, _) = pool_fixture();
        for (cpus, memory) in [(2, 6i64 << 30), (4, 5i64 << 30)] {
            parent.config.set(
                "resources",
                object([
                    ("cpus", Value::int(cpus)),
                    ("memory_bytes", Value::int(memory)),
                    ("pids", Value::int(256)),
                ]),
            );
            let error = CompilerPool::new(&mut parent).err().unwrap();
            assert!(error.contains("resource budget"));
        }
        assert!(engine.created.lock().unwrap().is_empty());
        drop(fixture);
    }
}
