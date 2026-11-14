//! Explicit candidate execution boundary (former `native_confinement.Execution`
//! and its `CompilerPool`), the one implementation both controller commands use.
//!
//! `native-qualify` constructs it from the protected configuration and writes
//! the digest-bound execution context; `architecture` reloads that context
//! (`from_context`) and runs its candidate commands and the two-isolate
//! compiler pool through the same per-invocation container lifecycle (create,
//! inspect, attach, state, removal, confirmed absence). Controller code never
//! enters its mounts; missing images, unsupported fixtures, weakened runtimes
//! or failed disposal refuse, with no host fallback. The context bytes and the
//! observation rows keep the former schema exactly.
use crate::isolation;
use crate::json::{self, Value, object};
use crate::native::pysteps;
use crate::native::sp::{
    self, Dict, Error, Io, Kind, R, Spec, at, key_error, need_value as require, value_error,
};
use crate::proc;
use crate::sha256;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub fn digest(path: &Path) -> R<String> {
    sha256::file(path).map_err(|e| {
        let error = std::fs::File::open(path).err();
        match error {
            Some(error) => sp::os_error(&error, Some(path)),
            None => value_error(e),
        }
    })
}

/// Each invocation's private Cargo home, at one path in every job (the same
/// value as `native_dep_cache.CARGO_HOME_PATH` and `confinement_entry`).
pub const INVOCATION_CARGO_HOME: &str = "/__busbar_cargo_home";

/// `canonical(value)`: sorted compact JSON plus newline.
pub fn canonical(value: &Value) -> Vec<u8> {
    json::encoded(value)
}

pub fn sha_canonical(value: &Value) -> String {
    sha256::hex(&canonical(value))
}

/// `checked_directory(value)`.
pub fn checked_directory(path: &Path) -> R<PathBuf> {
    require(
        path.is_absolute()
            && path.is_dir()
            && !sp::is_symlink(path)
            && path == sp::resolve(path)
            && path.components().count() > 2,
        "unsafe execution root",
    )?;
    require(!sp::text(path).contains(','), "unsupported mount path")?;
    Ok(path.to_owned())
}

/// `writable_directory(root, *parts)`.
pub fn writable_directory(root: &Path, parts: &[&str]) -> R<PathBuf> {
    let mut current = checked_directory(root)?;
    for part in parts {
        require(
            !matches!(*part, "" | "." | "..") && !part.contains('/'),
            "invalid writable directory component",
        )?;
        current = current.join(part);
        require(!sp::is_symlink(&current), "indirect writable directory")?;
        sp::mkdir(&current, 0o777, true)?;
        checked_directory(&current)?;
    }
    Ok(current)
}

fn image_reference(value: &str) -> bool {
    let digest = |text: &str| {
        text.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    };
    match value.rsplit_once('@') {
        Some((name, rest)) => {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"./:_-".contains(&c))
                && digest(rest)
        }
        None => digest(value),
    }
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

/// An environment mapping as the architecture checks build it.
pub type Env = BTreeMap<String, String>;

/// The process environment as `os.environ` sees it.
pub fn process_env() -> Env {
    Dict::environ().0.into_iter().collect()
}

pub type Client = Arc<dyn Fn(&[String], bool) -> R<(i32, Vec<u8>)> + Send + Sync>;
pub type PrepareWritable = Arc<dyn Fn(&Value, &[PathBuf], u64, u64) -> R<Value> + Send + Sync>;
pub type Userns = Arc<dyn Fn(&Value, &Value, Option<&Value>) -> R<Value> + Send + Sync>;

/// Host-kernel contracts. Production uses the real Docker client and Linux
/// checks; unit tests substitute them as the former Python tests patched them.
#[derive(Clone, Default)]
pub struct Hooks {
    pub client: Option<Client>,
    pub prepare_writable: Option<PrepareWritable>,
    pub userns: Option<Userns>,
}

fn positive_int(value: &Value) -> Option<i128> {
    value.as_int().filter(|v| *v > 0)
}

fn is_relative_to(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// The four candidate-visible roots, in their former insertion order.
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

/// A custom seccomp profile execution (`tsan_linux29_probe.ProfileExecution`).
#[derive(Clone, Debug)]
pub struct Profile {
    pub path: PathBuf,
    pub sha256: String,
    pub data: Value,
}

/// The fixed C unit command restriction (`native_sanitizer.CUnitExecution`).
#[derive(Clone, Debug)]
pub struct Restriction {
    pub command: Vec<String>,
}

#[derive(Clone)]
pub struct Execution {
    pub config: Value,
    pub control: PathBuf,
    pub roots: Roots,
    /// `Path(native_confinement.__file__).with_name('confinement_entry.py')`.
    pub entry: PathBuf,
    pub docker: Vec<String>,
    pub client_env: Vec<(String, String)>,
    pub fixture_directory: PathBuf,
    pub fixture_map: PathBuf,
    pub extra_readonly: Vec<PathBuf>,
    pub observations: Vec<Value>,
    pub product_inputs: Dict,
    pub oracle_inputs: Dict,
    pub conformance_capabilities: Option<PathBuf>,
    pub conformance_mounts: Vec<(PathBuf, PathBuf)>,
    pub conformance_inputs_manifest: Option<PathBuf>,
    pub dependency_seed: Option<PathBuf>,
    pub dependency_seed_sha256: Option<String>,
    /// Controller-owned trusted prebuilt product images (native/images.rs),
    /// mounted read-only for the product-inputs step only.
    pub product_images: Option<PathBuf>,
    pub profile: Option<Profile>,
    pub restriction: Option<Restriction>,
    /// Compiler-pool isolate state (`resource_slice`, `compiler_readonly`,
    /// `prepared_git`, `readonly_candidate_inputs`); unset outside the pool.
    pub resource_slice: Option<Value>,
    pub compiler_readonly: bool,
    pub prepared_git: Option<PathBuf>,
    pub readonly_candidate_inputs: Option<PathBuf>,
    /// The next invocation is a vendored-source harness check
    /// (`invocation(..., vendored_sources=True)`): an empty private Cargo home.
    pub vendored_sources: bool,
    pub hooks: Hooks,
}

/// One live candidate container; [`Execution::dispose`] must always follow.
pub struct Invocation {
    pub name: String,
    pub command: Vec<String>,
    pub observation: usize,
    inspected: bool,
    disposable_target: Option<PathBuf>,
    cargo_home: Option<PathBuf>,
}

impl Execution {
    pub fn new(config: Value, roots: Roots, control: &Path, entry: PathBuf) -> R<Execution> {
        require(
            config.has_keys(&[
                "schema",
                "docker",
                "docker_sha256",
                "docker_host",
                "image",
                "runtime",
                "uid",
                "gid",
                pysteps::INTERPRETER_KEY,
                "environment",
                "resources",
                "isolation",
                "collector",
            ]),
            "unknown isolation configuration",
        )?;
        require(
            config.at("schema").as_str() == Some("busbar.native-confinement/2"),
            "unknown isolation schema",
        )?;
        let docker = config.at("docker").as_str().unwrap_or("").to_owned();
        require(
            Path::new(&docker).is_absolute()
                && digest(Path::new(&docker))?
                    == config.at("docker_sha256").as_str().unwrap_or("-"),
            "Docker client is not the pinned executable",
        )?;
        require(
            unix_endpoint(config.at("docker_host").as_str().unwrap_or("")),
            "local Unix Docker endpoint required",
        )?;
        require(
            image_reference(config.at("image").as_str().unwrap_or("")),
            "immutable toolchain image required",
        )?;
        require(
            matches!(config.at("runtime").as_str(), Some("runc" | "runsc")),
            "unsupported candidate runtime",
        )?;
        require(
            positive_int(config.at("uid")).is_some() && positive_int(config.at("gid")).is_some(),
            "candidate must use a nonroot identity",
        )?;
        require(
            Path::new(config.at(pysteps::INTERPRETER_KEY).as_str().unwrap_or("")).is_absolute(),
            "pinned-image Python path required",
        )?;
        let environment = config.at("environment");
        let allowed = [
            "PATH",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "GOROOT",
            "RUSTC",
            "RUSTDOC",
        ];
        require(
            environment.as_object().is_some_and(|rows| {
                rows.iter()
                    .all(|(k, v)| allowed.contains(&k.as_str()) && v.as_str().is_some())
                    && rows.iter().any(|(k, _)| k == "PATH")
            }),
            "unexpected toolchain environment",
        )?;
        isolation::validate_configuration(config.at("isolation")).map_err(sp::from_text)?;
        let collector = config.at("collector");
        let isolation = config.at("isolation");
        let mapped = |map: &str, id: &str| {
            isolation
                .at(map)
                .index(1)
                .as_int()
                .zip(config.at(id).as_int())
                .map(|(a, b)| a + b)
        };
        require(
            collector.is_object()
                && (collector.has_keys(&["docker_host", "uid", "gid"])
                    || collector.has_keys(&["docker_host", "uid", "gid", "image"]))
                && image_reference(
                    collector
                        .get("image")
                        .unwrap_or(config.at("image"))
                        .as_str()
                        .unwrap_or(""),
                )
                && unix_endpoint(collector.at("docker_host").as_str().unwrap_or(""))
                && collector.at("uid").as_int().is_some()
                && collector.at("uid").as_int() == mapped("uid_map", "uid")
                && collector.at("gid").as_int() == mapped("gid_map", "gid"),
            "invalid protected dependency collector identity",
        )?;
        let resources = config.at("resources");
        require(
            resources.has_keys(&["cpus", "memory_bytes", "pids"])
                && ["cpus", "memory_bytes", "pids"]
                    .iter()
                    .all(|k| positive_int(resources.at(k)).is_some())
                && resources.at("cpus").as_int() <= Some(64)
                && resources.at("memory_bytes").as_int() <= Some(256 << 30)
                && resources.at("pids").as_int() <= Some(65536),
            "invalid confinement resource caps",
        )?;
        let control = checked_directory(control)?;
        let roots = Roots {
            checkout: checked_directory(&roots.checkout)?,
            candidate: checked_directory(&roots.candidate)?,
            trusted: checked_directory(&roots.trusted)?,
            harness: checked_directory(&roots.harness)?,
        };
        for root in [&roots.checkout, &roots.candidate] {
            require(
                !is_relative_to(&control, root),
                "controller is beneath candidate access",
            )?;
        }
        for root in [&roots.trusted, &roots.harness] {
            require(
                !is_relative_to(&control, root),
                "controller is exposed through readonly root",
            )?;
            for writable in [&roots.checkout, &roots.candidate] {
                require(
                    !is_relative_to(root, writable) && !is_relative_to(writable, root),
                    "trusted source overlaps candidate roots",
                )?;
            }
        }
        require(
            !is_relative_to(&roots.candidate, &roots.checkout)
                && !is_relative_to(&roots.checkout, &roots.candidate),
            "candidate roots overlap",
        )?;
        source_without_links(&roots.checkout)?;
        let resolved_docker = sp::resolve(Path::new(&docker));
        require(
            !is_relative_to(&resolved_docker, &roots.checkout)
                && !is_relative_to(&resolved_docker, &roots.candidate),
            "Docker client is candidate writable",
        )?;
        let writable = |path: &Path| {
            is_relative_to(path, &roots.candidate) || is_relative_to(path, &roots.checkout)
        };
        for (key, value) in environment.as_object().into_iter().flatten() {
            let value = value.as_str().unwrap_or("");
            if key == "PATH" {
                require(
                    value.split(':').all(|part| {
                        let part = Path::new(part);
                        part.is_absolute()
                            && !is_relative_to(part, Path::new("/tmp"))
                            && !writable(part)
                    }),
                    "relative or candidate writable tool search path",
                )?;
                continue;
            }
            let path = Path::new(value);
            require(
                path.is_absolute() && !is_relative_to(path, Path::new("/tmp")) && !writable(path),
                "toolchain or Cargo seed path is candidate writable",
            )?;
        }
        let client_home = control.join("docker-client");
        sp::mkdir(&client_home, 0o700, true)?;
        let fixture_directory = control.join("fixture-sockets");
        sp::mkdir(&fixture_directory, 0o755, true)?;
        let fixture_map = control.join("fixture-map.json");
        if !fixture_map.exists() {
            sp::write(&fixture_map, b"[]\n")?;
        }
        let docker_host = config.at("docker_host").as_str().unwrap_or("").to_owned();
        let home = sp::text(&client_home);
        Ok(Execution {
            docker: vec![docker, "--host".into(), docker_host],
            client_env: vec![
                ("PATH".into(), "/bin:/usr/bin".into()),
                ("HOME".into(), home.clone()),
                ("DOCKER_CONFIG".into(), home),
            ],
            fixture_directory,
            fixture_map,
            config,
            control,
            roots,
            entry,
            extra_readonly: Vec::new(),
            observations: Vec::new(),
            product_inputs: Dict::default(),
            oracle_inputs: Dict::default(),
            conformance_capabilities: None,
            conformance_mounts: Vec::new(),
            conformance_inputs_manifest: None,
            dependency_seed: None,
            dependency_seed_sha256: None,
            product_images: None,
            profile: None,
            restriction: None,
            resource_slice: None,
            compiler_readonly: false,
            prepared_git: None,
            readonly_candidate_inputs: None,
            vendored_sources: false,
            hooks: Hooks::default(),
        })
    }

    /// `Execution.from_context(path, expected)`: the digest-bound context the
    /// step runner wrote, reloaded by the architecture command.
    pub fn from_context(path: &Path, expected: &str, hooks: Hooks) -> R<Execution> {
        require(
            digest(path)? == expected,
            "controller execution context digest differs",
        )?;
        let data = sp::read_json(path)?;
        let roots = at(&data, "roots")?;
        require(
            roots.has_keys(&["checkout", "candidate", "trusted", "harness"]),
            "unexpected execution roots",
        )?;
        let root = |key: &str| PathBuf::from(roots.at(key).as_str().unwrap_or(""));
        let roots = Roots {
            checkout: root("checkout"),
            candidate: root("candidate"),
            trusted: root("trusted"),
            harness: root("harness"),
        };
        // `Path(native_confinement.__file__).with_name('confinement_entry.py')`:
        // the policy checkout's own entry, as the step runner mounts it.
        let entry = roots
            .trusted
            .join("scripts/architecture/confinement_entry.py");
        let control = PathBuf::from(at(&data, "control")?.as_str().unwrap_or(""));
        let mut execution =
            Execution::new(at(&data, "configuration")?.clone(), roots, &control, entry)?;
        execution.hooks = hooks;
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
            execution.dependency_seed_sha256 = Some(
                at(&data, "dependency_seed_sha256")?
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
            );
        }
        Ok(execution)
    }

    /// `readonly_candidate_inputs or roots['candidate']`.
    fn inputs_root(&self) -> &Path {
        self.readonly_candidate_inputs
            .as_deref()
            .unwrap_or(&self.roots.candidate)
    }

    /// One `_client` call, through the test hook when one is installed.
    fn raw_client(&self, args: &[String], capture: bool) -> R<sp::Done> {
        if let Some(client) = &self.hooks.client {
            let (code, stdout) = client(args, capture)?;
            let mut argv = self.docker.clone();
            argv.extend(args.iter().cloned());
            return Ok(sp::Done {
                argv,
                code,
                stdout,
                stderr: Vec::new(),
            });
        }
        let spec = self.client_spec(args)?;
        sp::run(if capture {
            spec.capture()
        } else {
            spec.quiet()
        })
    }

    fn userns(&self, isolation: &Value, daemon: &Value, inspected: Option<&Value>) -> R<Value> {
        if let Some(hook) = &self.hooks.userns {
            return hook(isolation, daemon, inspected);
        }
        match inspected {
            None => isolation::validate_userns(isolation, daemon),
            Some(actual) => isolation::validate_userns_inspected(isolation, daemon, actual),
        }
        .map_err(sp::from_text)
    }

    pub fn uid(&self) -> i128 {
        self.config.at("uid").as_int().unwrap_or(0)
    }
    pub fn gid(&self) -> i128 {
        self.config.at("gid").as_int().unwrap_or(0)
    }
    pub fn mapped_uid(&self) -> i128 {
        self.config
            .at("isolation")
            .at("uid_map")
            .index(1)
            .as_int()
            .unwrap_or(0)
            + self.uid()
    }
    pub fn image(&self) -> &str {
        self.config.at("image").as_str().unwrap_or("")
    }
    pub fn python(&self) -> &str {
        self.config
            .at(pysteps::INTERPRETER_KEY)
            .as_str()
            .unwrap_or("")
    }
    pub fn docker_host(&self) -> &str {
        self.config.at("docker_host").as_str().unwrap_or("")
    }

    /// `write_context()`: the digest-bound context the architecture step reads.
    pub fn write_context(&self) -> R<(PathBuf, String)> {
        let path = self.control.join("execution-context.json");
        let texts =
            |paths: &[PathBuf]| Value::Array(paths.iter().map(|p| sp::text(p).into()).collect());
        let optional = |value: &Option<PathBuf>| match value {
            Some(path) => Value::from(sp::text(path)),
            None => Value::Null,
        };
        let context = object([
            ("configuration", self.config.clone()),
            (
                "roots",
                Value::Object(
                    self.roots
                        .all()
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), sp::text(v).into()))
                        .collect(),
                ),
            ),
            ("control", sp::text(&self.control).into()),
            ("extra_readonly", texts(&self.extra_readonly)),
            (
                "conformance_mounts",
                Value::Array(
                    self.conformance_mounts
                        .iter()
                        .map(|(s, t)| Value::Array(vec![sp::text(s).into(), sp::text(t).into()]))
                        .collect(),
                ),
            ),
            (
                "conformance_inputs_manifest",
                optional(&self.conformance_inputs_manifest),
            ),
            ("dependency_seed", optional(&self.dependency_seed)),
            (
                "dependency_seed_sha256",
                self.dependency_seed_sha256
                    .clone()
                    .map_or(Value::Null, Value::from),
            ),
        ]);
        sp::write(&path, canonical(&context))?;
        let expected = digest(&path)?;
        Ok((path, expected))
    }

    /// The candidate daemon client invocation (`_client`), 60 s by default.
    pub fn client_spec(&self, args: &[String]) -> R<Spec> {
        let mut args = args.to_vec();
        if let Some(profile) = &self.profile
            && args.first().map(String::as_str) == Some("create")
        {
            require(
                digest(&profile.path)? == profile.sha256,
                "profile changed before launch",
            )?;
            args.splice(
                1..1,
                [
                    "--security-opt".to_owned(),
                    format!("seccomp={}", sp::text(&profile.path)),
                ],
            );
        }
        let mut argv = self.docker.clone();
        argv.extend(args);
        Ok(Spec::new(argv).env(&self.client_env).timeout(60))
    }

    /// `_client(args, capture_output=True, text=True)`.
    pub fn client(&self, args: &[String]) -> R<sp::Done> {
        let done = self.raw_client(args, true)?;
        self.check_profile_inspect(args, &done)?;
        Ok(done)
    }

    /// A custom profile must be retained exactly by the runtime.
    pub fn check_profile_inspect(&self, args: &[String], done: &sp::Done) -> R<()> {
        let Some(profile) = &self.profile else {
            return Ok(());
        };
        if args.first().map(String::as_str) != Some("inspect")
            || args.iter().any(|a| a == "--format")
            || done.code != 0
        {
            return Ok(());
        }
        let rows = sp::loads(&done.stdout)?;
        let options = at(at(rows.index(0), "HostConfig")?, "SecurityOpt")?;
        let options = options.as_array().unwrap_or(&[]);
        let policies: Vec<&str> = options
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|v| v.strip_prefix("seccomp="))
            .collect();
        require(
            policies.len() == 1 && sp::loads(policies[0].as_bytes())? == profile.data,
            "runtime did not retain the exact local seccomp profile",
        )?;
        require(options.len() == 2, "unexpected additional security option")
    }

    /// `collector_client(args, ...)`: only trusted fetch code uses the network daemon.
    pub fn collector_spec(&self, args: &[String]) -> Spec {
        let mut argv = vec![
            self.docker[0].clone(),
            "--host".into(),
            self.config
                .at("collector")
                .at("docker_host")
                .as_str()
                .unwrap_or("")
                .into(),
        ];
        argv.extend(args.iter().cloned());
        Spec::new(argv).env(&self.client_env).timeout(60)
    }

    /// `sanitize_git()`: source history without clone credentials, hooks or host config.
    pub fn sanitize_git(&self) -> R<PathBuf> {
        if let Some(prepared) = &self.prepared_git {
            return checked_directory(prepared);
        }
        let source = self.roots.checkout.join(".git");
        require(
            source.is_dir() && !sp::is_symlink(&source),
            "CI checkout must have a regular Git directory",
        )?;
        require(
            !source.join("objects/info/alternates").exists(),
            "external Git object store",
        )?;
        let destination = self.control.join("candidate-git");
        if !destination.exists() {
            sp::mkdir(&destination, 0o777, false)?;
            for name in ["objects", "refs", "HEAD", "packed-refs", "shallow", "index"] {
                let path = source.join(name);
                if !path.exists() {
                    continue;
                }
                require(!sp::is_symlink(&path), "indirect Git metadata")?;
                if path.is_dir() {
                    require(
                        !sp::rglob(&path).iter().any(|p| sp::is_symlink(p)),
                        "indirect Git objects",
                    )?;
                    sp::copytree(&path, &destination.join(name))?;
                } else {
                    std::fs::copy(&path, destination.join(name)).at(&path)?;
                }
            }
            sp::write(
                &destination.join("config"),
                "[core]\nrepositoryformatversion = 0\nbare = false\n",
            )?;
        }
        Ok(destination)
    }

    /// `register_generated(path)`: a bounded readonly generated project.
    pub fn register_generated(&mut self, path: &Path) -> R<()> {
        let root = checked_directory(path)?;
        require(
            is_relative_to(&root, &self.roots.candidate.join("generated")),
            "generated project escapes its registered output root",
        )?;
        let mut total = 0u64;
        for entry in sp::rglob(&root) {
            use std::os::unix::fs::MetadataExt;
            let info = std::fs::symlink_metadata(&entry).at(&entry)?;
            let kind = info.file_type();
            require(
                kind.is_dir() || kind.is_file(),
                "generated project contains indirect or special files",
            )?;
            if kind.is_file() {
                total += info.len();
                require(
                    info.nlink() == 1 && info.len() <= 16 << 20 && total <= 128 << 20,
                    "generated source exceeds its collection bounds",
                )?;
            }
            require(
                !entry
                    .strip_prefix(&root)
                    .unwrap_or(&entry)
                    .components()
                    .any(|c| c.as_os_str() == ".git"),
                "generated projects must not supply Git control metadata",
            )?;
        }
        self.extra_readonly.push(root);
        Ok(())
    }

    /// `set_conformance_capabilities(manifest, repository, source, expected)`.
    pub fn set_conformance_capabilities(
        &mut self,
        manifest: Option<&Path>,
        repository: &str,
        source: &str,
        expected: Option<&str>,
    ) -> R<String> {
        let data = match manifest {
            None => object([
                ("schema", "busbar.conformance.capabilities/1".into()),
                ("repo", repository.into()),
                ("source", source.into()),
                ("toolchain_ready", false.into()),
                ("suites", Value::Object(Vec::new())),
            ]),
            Some(manifest) => {
                require(
                    expected.is_some_and(|e| !e.is_empty())
                        && digest(manifest)? == expected.unwrap_or(""),
                    "protected conformance capabilities digest differs",
                )?;
                let resolved = sp::resolve(manifest);
                require(
                    !sp::is_symlink(manifest)
                        && !is_relative_to(&resolved, &self.roots.checkout)
                        && !is_relative_to(&resolved, &self.roots.candidate),
                    "candidate supplied conformance capabilities",
                )?;
                sp::read_json(manifest)?
            }
        };
        require(
            data.has_keys(&["schema", "repo", "source", "toolchain_ready", "suites"])
                && data.at("schema").as_str() == Some("busbar.conformance.capabilities/1")
                && data.at("repo").as_str() == Some(repository)
                && data.at("source").as_str() == Some(source)
                && data.at("toolchain_ready").as_bool().is_some()
                && data.at("suites").is_object(),
            "conformance capability identity or schema differs",
        )?;
        for (name, row) in data.at("suites").as_object().into_iter().flatten() {
            let mut chars = name.chars();
            let reason = row.get("reason");
            require(
                chars
                    .next()
                    .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && row.is_object()
                    && row
                        .keys()
                        .iter()
                        .all(|k| matches!(*k, "available" | "reason"))
                    && row.at("available").as_bool().is_some()
                    && reason.is_none_or(|r| r.as_str().is_some_and(|t| t.chars().count() <= 2000)),
                "invalid conformance suite capability",
            )?;
        }
        let path = self.control.join("conformance-capabilities.json");
        sp::write(&path, canonical(&data))?;
        sp::chmod(&path, 0o444)?;
        self.conformance_capabilities = Some(path.clone());
        digest(&path)
    }

    /// `environment(env)`: the allowlisted candidate environment.
    pub fn environment(&self, env: &Dict) -> R<BTreeMap<String, String>> {
        const ALLOWED: &[&str] = &[
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
            "CARGO_INCREMENTAL",
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
        let fixture_key = |key: &str| {
            key.strip_prefix("BUSBAR_TEST_").is_some_and(|rest| {
                ["_URL", "_ADDR", "_FIXTURE"].iter().any(|suffix| {
                    rest.len() > suffix.len()
                        && rest.ends_with(suffix)
                        && rest[..rest.len() - suffix.len()]
                            .bytes()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                })
            })
        };
        let mut result: BTreeMap<String, String> = env
            .0
            .iter()
            .filter(|(k, _)| ALLOWED.contains(&k.as_str()) || fixture_key(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, value) in self
            .product_inputs
            .0
            .iter()
            .chain(self.oracle_inputs.0.iter())
        {
            if let Some(actual) = env.get(key) {
                require(actual == value, "registered product input was overridden")?;
                result.insert(key.clone(), value.clone());
            }
        }
        let mut count = sp::py_int(env.get("GIT_CONFIG_COUNT").unwrap_or("0"))?;
        require((0..=1000).contains(&count), "invalid Git mapping count")?;
        result.insert("GIT_CONFIG_COUNT".into(), count.to_string());
        let inputs = self.inputs_root();
        let prefix = format!("url.{}/", sp::as_uri(&inputs.join("canonical-inputs")));
        for index in 0..count {
            let key = env
                .get(&format!("GIT_CONFIG_KEY_{index}"))
                .ok_or_else(|| key_error(&format!("GIT_CONFIG_KEY_{index}")))?;
            let value = env
                .get(&format!("GIT_CONFIG_VALUE_{index}"))
                .ok_or_else(|| key_error(&format!("GIT_CONFIG_VALUE_{index}")))?;
            let repository = value.strip_prefix("https://github.com/GetBusbar/");
            require(
                key.starts_with(&prefix)
                    && key.ends_with(".insteadOf")
                    && repository.is_some_and(|r| {
                        !r.is_empty()
                            && r.bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                    }),
                "unexpected Git setting in candidate environment",
            )?;
            result.insert(format!("GIT_CONFIG_KEY_{index}"), key.to_owned());
            result.insert(format!("GIT_CONFIG_VALUE_{index}"), value.to_owned());
        }
        let mut git_roots = vec![self.roots.checkout.clone(), self.roots.trusted.clone()];
        for relative in ["host", "sdk", "c-witness"] {
            let path = inputs.join(relative);
            if path.exists() {
                git_roots.push(checked_directory(&path)?);
            }
        }
        for path in git_roots {
            result.insert(format!("GIT_CONFIG_KEY_{count}"), "safe.directory".into());
            result.insert(format!("GIT_CONFIG_VALUE_{count}"), sp::text(&path));
            count += 1;
        }
        result.insert("GIT_CONFIG_COUNT".into(), count.to_string());
        for (key, value) in self
            .config
            .at("environment")
            .as_object()
            .into_iter()
            .flatten()
        {
            result.insert(key.clone(), value.as_str().unwrap_or("").to_owned());
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
        if let Some(capabilities) = &self.conformance_capabilities {
            result.insert(
                "CONFORMANCE_CAPABILITIES".into(),
                "/__busbar_conformance_capabilities.json".into(),
            );
            let identity = sp::read_json(capabilities)?;
            let repo = at(&identity, "repo")?;
            result.insert("MODERNCI_REPO".into(), crate::py::str(repo));
        }
        result.insert("HOME".into(), sp::text(&self.roots.candidate.join("home")));
        result.insert("GIT_CONFIG_GLOBAL".into(), "/dev/null".into());
        result.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        result.insert("CARGO_NET_OFFLINE".into(), "true".into());
        result.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
        writable_directory(&self.roots.candidate, &["home"])?;
        Ok(result)
    }

    /// `cargo_environment(argv, env)`: trusted harness manifests keep their
    /// sources read-only, with a private lockfile and fresh target.
    pub fn cargo_environment(&self, argv: &[String], env: &Dict) -> R<BTreeMap<String, String>> {
        let mut result = self.environment(env)?;
        if let Some(index) = argv.iter().position(|a| a == "--manifest-path") {
            let manifest = sp::resolve(Path::new(
                argv.get(index + 1)
                    .ok_or_else(|| value_error("list index out of range"))?,
            ));
            if is_relative_to(&manifest, &self.roots.harness) {
                let label = format!(
                    "{}-{}",
                    sha256::hex(sp::text(&manifest).as_bytes()),
                    sp::uuid_hex()
                );
                let location =
                    writable_directory(&self.roots.candidate, &["harness-locks", &label])?;
                let lock = location.join("Cargo.lock");
                require(!sp::is_symlink(&lock), "indirect harness lockfile")?;
                let original = manifest
                    .parent()
                    .unwrap_or(Path::new("/"))
                    .join("Cargo.lock");
                if !lock.exists() && original.is_file() {
                    std::fs::copy(&original, &lock).at(&original)?;
                }
                require(!sp::is_symlink(&lock), "indirect harness lockfile")?;
                result.insert("CARGO_RESOLVER_LOCKFILE_PATH".into(), sp::text(&lock));
                let fresh = self
                    .roots
                    .candidate
                    .join(format!("harness-target-{}", sp::uuid_hex()));
                sp::mkdir(&fresh, 0o777, false)?;
                result.insert("CARGO_TARGET_DIR".into(), sp::text(&fresh));
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

    /// `prepare_command(argv, cwd)`: cargo-vet receives a fresh policy store copy.
    pub fn prepare_command(&self, argv: Vec<String>, cwd: &Path) -> R<Vec<String>> {
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
                    .ok_or_else(|| value_error("list index out of range"))?,
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
                && !sp::is_symlink(&store)
                && !sp::rglob(&store).iter().any(|p| sp::is_symlink(p)),
            "missing or indirect vet policy store",
        )?;
        let destination = self
            .roots
            .candidate
            .join(format!("vet-store-{}", sp::uuid_hex()));
        sp::copytree(&store, &destination)?;
        let mut argv = argv;
        argv.push("--store-path".into());
        argv.push(sp::text(&destination));
        Ok(argv)
    }

    /// Enter one candidate container (`invocation(...)`'s body up to `yield`).
    /// A failure after the container is named disposes it before returning.
    pub fn invocation(
        &mut self,
        argv: &[String],
        cwd: &Path,
        env: &Dict,
        discard_harness_target: bool,
    ) -> R<Invocation> {
        if let Some(restriction) = &self.restriction {
            require(
                argv == restriction.command.as_slice(),
                "sanitizer profile is restricted to the fixed C unit command",
            )?;
            require(
                sp::resolve(cwd) == self.roots.checkout,
                "sanitizer cwd differs from the qualified checkout",
            )?;
            require(
                env.get("TSAN_OPTIONS") == Some("halt_on_error=1"),
                "sanitizer error handling differs",
            )?;
        }
        require(
            argv.first().is_some_and(|a| !a.starts_with('-')),
            "missing candidate executable",
        )?;
        // A vendored-source compiler check reads every dependency from the
        // controller's read-only vendor directory, never from the job seed.
        let vendored_sources = std::mem::take(&mut self.vendored_sources);
        require(
            !vendored_sources
                || (discard_harness_target
                    && argv.len() >= 2
                    && argv[0] == "cargo"
                    && argv[1] == "check"
                    && argv.iter().any(|a| a == "--config")),
            "an empty Cargo cache requires a vendored harness compiler check",
        )?;
        if discard_harness_target {
            let index = argv.iter().position(|a| a == "--manifest-path");
            require(
                argv[0] == "cargo"
                    && index.is_some_and(|i| {
                        i + 1 < argv.len()
                            && is_relative_to(
                                &sp::resolve(Path::new(&argv[i + 1])),
                                &self.roots.harness,
                            )
                    }),
                "disposable target requires a trusted harness manifest",
            )?;
        }
        let cwd = sp::resolve(cwd);
        require(
            self.roots
                .all()
                .iter()
                .any(|(_, root)| is_relative_to(&cwd, root)),
            "candidate cwd escapes execution roots",
        )?;
        let argv = self.prepare_command(argv.to_vec(), &cwd)?;
        let name = format!("busbar-candidate-{}", sp::uuid_hex());
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
                        let value = resources.at(k);
                        value.is_int()
                            && value.as_int().is_some_and(|v| {
                                v > 0
                                    && aggregate
                                        .at(k)
                                        .as_int()
                                        .is_some_and(|a| v * COMPILER_POOL_WIDTH as i128 <= a)
                            })
                    }),
                "compiler slices exceed the aggregate resource budget",
            )?;
        }
        let target = self.roots.checkout.join("target");
        if !self.compiler_readonly {
            sp::mkdir(&target, 0o777, true)?;
            checked_directory(&target)?;
        }
        let checkout = self.roots.checkout.clone();
        let mut mounts: Vec<(PathBuf, PathBuf, bool)> = vec![
            (checkout.clone(), checkout.clone(), false),
            (
                self.roots.candidate.clone(),
                self.roots.candidate.clone(),
                true,
            ),
            (
                self.roots.trusted.clone(),
                self.roots.trusted.clone(),
                false,
            ),
            (
                self.roots.harness.clone(),
                self.roots.harness.clone(),
                false,
            ),
            (self.sanitize_git()?, checkout.join(".git"), false),
            (
                self.fixture_directory.clone(),
                "/__busbar_fixtures".into(),
                false,
            ),
            (
                self.fixture_map.clone(),
                "/__busbar_fixture_map.json".into(),
                false,
            ),
            (self.entry.clone(), "/__busbar_entry.py".into(), false),
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
        let nested = checkout.join("dist/default/target");
        if nested.parent().is_some_and(Path::is_dir) && !self.compiler_readonly {
            sp::mkdir(&nested, 0o777, true)?;
            checked_directory(&nested)?;
            mounts.push((nested.clone(), nested, true));
        }
        for path in &self.extra_readonly {
            mounts.push((checked_directory(path)?, path.clone(), false));
        }
        for (source, target) in &self.conformance_mounts {
            mounts.push((source.clone(), target.clone(), false));
        }
        if let Some(capabilities) = &self.conformance_capabilities {
            mounts.push((
                capabilities.clone(),
                "/__busbar_conformance_capabilities.json".into(),
                false,
            ));
        }
        if let Some(seed) = &self.dependency_seed {
            mounts.push((seed.clone(), "/__busbar_job_seed".into(), false));
        }
        if let Some(images) = &self.product_images {
            mounts.push((
                checked_directory(images)?,
                crate::native::images::MOUNT.into(),
                false,
            ));
        }
        let mounted = |target: &str| {
            self.conformance_mounts
                .iter()
                .any(|(_, t)| t == Path::new(target))
        };
        let mut fixture_hosts: Vec<String> = if mounted("/opt/busbar-conformance/oidf") {
            sp::strings(&[
                "localhost.emobix.co.uk:127.0.0.1",
                "busbar.oidf.test:127.0.0.1",
            ])
        } else {
            Vec::new()
        };
        if mounted("/opt/busbar-conformance/a2a-tools") {
            fixture_hosts.extend(sp::strings(&[
                "example.com:104.20.23.154",
                "example.com:172.66.147.243",
            ]));
        }
        let int = |key: &str| resources.at(key).as_int().unwrap_or(0);
        let mut args = sp::strings(&["create", "--name"]);
        args.push(name.clone());
        args.extend(sp::strings(&[
            "--pull=never",
            "--read-only",
            "--network=none",
            "--runtime",
        ]));
        args.push(self.config.at("runtime").as_str().unwrap_or("").into());
        args.push("--user".into());
        args.push(format!("{}:{}", self.uid(), self.gid()));
        args.extend(sp::strings(&[
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--ipc=private",
            "--cgroupns=private",
        ]));
        args.push(format!("--pids-limit={}", int("pids")));
        args.push(format!("--memory={}", int("memory_bytes")));
        args.push(format!("--memory-swap={}", int("memory_bytes")));
        args.push(format!("--cpus={}", int("cpus")));
        args.extend(sp::strings(&["--init", "--workdir"]));
        args.push(sp::text(&cwd));
        args.extend(sp::strings(&[
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777",
            "--shm-size=64m",
            "--entrypoint",
            "/usr/bin/env",
        ]));
        for alias in &fixture_hosts {
            args.push("--add-host".into());
            args.push(alias.clone());
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
            let name = target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            require(
                target.parent() == Some(self.roots.candidate.as_path())
                    && name.strip_prefix("harness-target-").is_some_and(|hex| {
                        hex.len() == 32
                            && hex
                                .bytes()
                                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    })
                    && !sp::is_symlink(&target),
                "invalid disposable harness target",
            )?;
            disposable_target = Some(target);
        }
        let mut cargo_home = None;
        if safe_env.get("CARGO_HOME").is_some_and(|v| !v.is_empty()) {
            // One fixed in-container path, independent of the job directory, so
            // registry/Git unit fingerprints are portable between jobs.
            let path = self.roots.candidate.join("cargo-home-invocation");
            sp::mkdir(&path, 0o700, false)?;
            mounts.push((path.clone(), INVOCATION_CARGO_HOME.into(), true));
            safe_env.insert(
                "BUSBAR_INVOCATION_CARGO_HOME".into(),
                INVOCATION_CARGO_HOME.into(),
            );
            if vendored_sources {
                // Still private, writable and removed on disposal; only the
                // copy of the job seed it would never read is skipped.
                safe_env.insert("BUSBAR_INVOCATION_CARGO_HOME_EMPTY".into(), "1".into());
            }
            cargo_home = Some(path);
        }
        for (source, destination, writable) in &mounts {
            require(
                !sp::text(source).contains(',') && !sp::text(destination).contains(','),
                "unsupported bind path",
            )?;
            args.push("--mount".into());
            args.push(format!(
                "type=bind,src={},dst={}{}",
                sp::text(source),
                sp::text(destination),
                if *writable { "" } else { ",readonly" }
            ));
        }
        let isolation = self.config.at("isolation").clone();
        let writable: Vec<PathBuf> = mounts.iter().filter(|m| m.2).map(|m| m.0.clone()).collect();
        let (uid, gid) = (self.uid() as u64, self.gid() as u64);
        let mut storage = match &self.hooks.prepare_writable {
            Some(hook) => hook(&isolation, &writable, uid, gid)?,
            None => isolation::prepare_writable(&isolation, &writable, uid, gid)
                .map_err(sp::from_text)?,
        };
        let daemon_result = self.client(&sp::strings(&["info", "--format", "{{json .}}"]))?;
        require(
            daemon_result.code == 0,
            "candidate daemon identity unavailable",
        )?;
        let daemon = sp::loads(&daemon_result.stdout)?;
        let user_namespace = self.userns(&isolation, &daemon, None)?;
        safe_env.insert(
            "BUSBAR_EXPECTED_UID_MAP".into(),
            json::dumps(isolation.at("uid_map"), false),
        );
        safe_env.insert(
            "BUSBAR_EXPECTED_GID_MAP".into(),
            json::dumps(isolation.at("gid_map"), false),
        );
        storage.set("tmp_bytes", (1u64 << 30).into());
        storage.set("tmp_inodes", 65536u64.into());
        storage.set("shm_bytes", (64u64 << 20).into());
        args.push(self.image().into());
        args.push("-i".into());
        args.extend(safe_env.iter().map(|(k, v)| format!("{k}={v}")));
        args.push(self.python().into());
        args.extend(sp::strings(&["-I", "-B", "/__busbar_entry.py", "--"]));
        args.extend(argv.iter().cloned());
        let env_value = Value::Object(
            safe_env
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
                .collect(),
        );
        let mut observation = object([
            ("name", name.as_str().into()),
            ("image", self.image().into()),
            ("runtime", self.config.at("runtime").clone()),
            ("candidate_uid", self.config.at("uid").clone()),
            ("disposed", false.into()),
            (
                "command_sha256",
                sha_canonical(&Value::Array(
                    argv.iter().map(|a| a.as_str().into()).collect(),
                ))
                .into(),
            ),
            ("environment_sha256", sha_canonical(&env_value).into()),
            ("working_directory", sp::text(&cwd).into()),
            (
                "docker_client_sha256",
                self.config.at("docker_sha256").clone(),
            ),
            ("configuration_sha256", sha_canonical(&self.config).into()),
            ("resources", resources.clone()),
            (
                "dependency_seed_sha256",
                self.dependency_seed_sha256
                    .clone()
                    .map_or(Value::Null, Value::from),
            ),
            ("storage", storage),
            ("user_namespace", user_namespace),
            (
                "fixture_hosts",
                Value::Array(fixture_hosts.iter().map(|h| h.as_str().into()).collect()),
            ),
        ]);
        if self.resource_slice.is_some() {
            observation.set("aggregate_resources", aggregate.clone());
            observation.set("compiler_pool_width", (COMPILER_POOL_WIDTH as u64).into());
        }
        self.observations.push(observation);
        let mut invocation = Invocation {
            name: name.clone(),
            command: Vec::new(),
            observation: self.observations.len() - 1,
            inspected: false,
            disposable_target,
            cargo_home,
        };
        match self.start(
            &mut invocation,
            &args,
            &daemon,
            &mounts,
            &fixture_hosts,
            &resources,
        ) {
            Ok(()) => {
                let mut command = self.docker.clone();
                command.extend(sp::strings(&["start", "--attach"]));
                command.push(name);
                invocation.command = command;
                if let Some(profile) = &self.profile
                    && self.restriction.is_some()
                {
                    let row = &mut self.observations[invocation.observation];
                    row.set("sanitizer_profile_sha256", profile.sha256.as_str().into());
                    row.set("sanitizer_scope", "c-unit-tsan".into());
                }
                Ok(invocation)
            }
            Err(error) => Err(self.dispose(invocation).err().unwrap_or(error)),
        }
    }

    fn start(
        &mut self,
        invocation: &mut Invocation,
        args: &[String],
        daemon: &Value,
        mounts: &[(PathBuf, PathBuf, bool)],
        fixture_hosts: &[String],
        resources: &Value,
    ) -> R<()> {
        let created = self.client(args)?;
        require(created.code == 0, "candidate container creation failed")?;
        let inspection = self.client(&["inspect".to_owned(), invocation.name.clone()])?;
        require(inspection.code == 0, "candidate inspection failed")?;
        let rows = sp::loads(&inspection.stdout)?;
        let actual = rows
            .as_array()
            .and_then(|r| r.first())
            .ok_or_else(|| Error::new(Kind::Value, "list index out of range"))?
            .clone();
        let isolation = self.config.at("isolation").clone();
        self.userns(&isolation, daemon, Some(&actual))?;
        let host = at(&actual, "HostConfig")?;
        let field = |key: &str| at(host, key);
        let int = |key: &str| resources.at(key).as_int().unwrap_or(0);
        let expected_hosts =
            Value::Array(fixture_hosts.iter().map(|h| h.as_str().into()).collect());
        let extra_hosts = match host.get("ExtraHosts") {
            Some(v) if v.truthy() => v.clone(),
            _ => Value::Array(Vec::new()),
        };
        let user = format!("{}:{}", self.uid(), self.gid());
        let ok = field("NetworkMode")?.as_str() == Some("none")
            && field("ReadonlyRootfs")?.as_bool() == Some(true)
            && field("Privileged")?.as_bool() == Some(false)
            && matches!(field("PidMode")?.as_str(), Some("" | "private"))
            && field("IpcMode")?.as_str() == Some("private")
            && field("CgroupnsMode")?.as_str() == Some("private")
            && field("Runtime")? == self.config.at("runtime")
            && at(at(&actual, "Config")?, "User")?.as_str() == Some(user.as_str())
            && *field("CapDrop")? == Value::Array(vec!["ALL".into()])
            && !host.at("CapAdd").truthy()
            && field("PidsLimit")?.as_int() == Some(int("pids"))
            && field("Memory")?.as_int() == Some(int("memory_bytes"))
            && field("NanoCpus")?.as_int() == Some(int("cpus") * 1_000_000_000)
            && !host.at("Devices").truthy()
            && !host.at("DeviceRequests").truthy()
            && extra_hosts == expected_hosts
            && host.at("ShmSize").as_int() == Some(64 << 20)
            && *host.at("Tmpfs")
                == object([(
                    "/tmp",
                    "rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777".into(),
                )]);
        require(ok, "runtime weakened candidate isolation")?;
        let memory = int("memory_bytes") as u64;
        let swap_bound =
            isolation::validate_swap_bound(daemon, host, memory).map_err(sp::from_text)?;
        let mut expected: Vec<(String, String, bool)> = mounts
            .iter()
            .map(|(s, d, w)| (sp::text(s), sp::text(d), *w))
            .collect();
        expected.sort();
        expected.dedup();
        let rows = at(&actual, "Mounts")?.as_array().unwrap_or(&[]).to_vec();
        let mut observed = Vec::new();
        for row in &rows {
            if at(row, "Type")?.as_str() == Some("bind") {
                observed.push((
                    at(row, "Source")?.as_str().unwrap_or("").to_owned(),
                    at(row, "Destination")?.as_str().unwrap_or("").to_owned(),
                    at(row, "RW")?.as_bool().unwrap_or(false),
                ));
            }
        }
        observed.sort();
        observed.dedup();
        require(
            rows.iter()
                .all(|m| matches!(m.at("Type").as_str(), Some("bind" | "tmpfs"))),
            "unexpected image volume",
        )?;
        require(observed == expected, "runtime candidate mounts differ")?;
        let options = field("SecurityOpt")?;
        require(
            options.as_array().is_some_and(|rows| {
                rows.iter().any(|v| {
                    matches!(
                        v.as_str(),
                        Some("no-new-privileges" | "no-new-privileges:true")
                    )
                })
            }),
            "runtime permits privilege gain",
        )?;
        let sorted = Value::Array(
            expected
                .iter()
                .map(|(s, d, w)| {
                    Value::Array(vec![s.as_str().into(), d.as_str().into(), (*w).into()])
                })
                .collect(),
        );
        let security = options.clone();
        let row = &mut self.observations[invocation.observation];
        row.set("container_id", at(&actual, "Id")?.clone());
        row.set("image_id", at(&actual, "Image")?.clone());
        row.set("network", "none".into());
        row.set("inspected", true.into());
        row.set("mounts_sha256", sha_canonical(&sorted).into());
        row.set("security_options", security);
        row.set("swap_bound", swap_bound);
        invocation.inspected = true;
        Ok(())
    }

    /// The invocation's `finally`: observe state, remove, confirm absence, then
    /// remove disposable controller-created candidate directories.
    pub fn dispose(&mut self, invocation: Invocation) -> R<()> {
        let name = invocation.name.clone();
        let index = invocation.observation;
        let mut state_error = None;
        if invocation.inspected {
            let observed = (|| -> R<Value> {
                let state = self.client(&sp::strings(&[
                    "inspect",
                    "--format",
                    "{{json .State}}",
                    &name,
                ]))?;
                require(state.code == 0, "candidate process state unavailable")?;
                let actual = sp::loads(&state.stdout)?;
                Ok(Value::Object(
                    [
                        "Status",
                        "Running",
                        "ExitCode",
                        "OOMKilled",
                        "Error",
                        "StartedAt",
                        "FinishedAt",
                    ]
                    .iter()
                    .map(|k| ((*k).to_owned(), actual.at(k).clone()))
                    .collect(),
                ))
            })();
            match observed {
                Ok(state) => self.observations[index].set("state_before_disposal", state),
                Err(error) if error.kind == Kind::Interrupted => return Err(error),
                Err(error) => {
                    let class = match error.kind {
                        Kind::Timeout => "TimeoutExpired",
                        Kind::Os => "OSError",
                        Kind::Key => "KeyError",
                        _ if error.message.contains(": line ") => "JSONDecodeError",
                        _ => "ValueError",
                    };
                    self.observations[index].set("state_observation_error", class.into());
                    state_error = Some(error);
                }
            }
        }
        let removed = self.raw_client(&sp::strings(&["rm", "--force", &name]), false)?;
        let filter = format!("name=^/{name}$");
        let absent = self.client(&sp::strings(&[
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            &filter,
        ]))?;
        require(
            absent.code == 0
                && absent.text().trim().is_empty()
                && (removed.code == 0 || !invocation.inspected),
            "candidate disposal was not confirmed",
        )?;
        self.observations[index].set("disposed", true.into());
        if let Some(target) = &invocation.disposable_target {
            if sp::is_symlink(target) {
                std::fs::remove_file(target).at(target)?;
            } else if target.exists() {
                sp::rmtree(target)?;
            }
            self.observations[index].set("harness_target_removed", true.into());
            self.observations[index].set(
                "harness_target_path_sha256",
                sha256::hex(sp::text(target).as_bytes()).into(),
            );
        }
        if let Some(home) = &invocation.cargo_home {
            if sp::is_symlink(home) {
                std::fs::remove_file(home).at(home)?;
            } else if home.exists() {
                sp::rmtree(home)?;
            }
            self.observations[index].set("private_cargo_cache_removed", true.into());
        }
        if let Some(proof) = self.observations[index].get_mut("swap_bound") {
            isolation::recheck_swap_bound(proof).map_err(sp::from_text)?;
        }
        match state_error {
            Some(_) => Err(value_error("candidate process state observation failed")),
            None => Ok(()),
        }
    }

    /// `run(argv, cwd=..., env=..., capture_output=True, text=True, timeout=...)`.
    pub fn run_captured(
        &mut self,
        argv: &[String],
        cwd: &Path,
        env: &Dict,
        timeout: u64,
    ) -> R<sp::Done> {
        let invocation = self.invocation(argv, cwd, env, false)?;
        let spec = Spec::new(invocation.command.clone())
            .env(&self.client_env)
            .capture()
            .timeout(timeout);
        let result = sp::run(spec);
        // The invocation's `finally`: a disposal failure replaces the result.
        self.dispose(invocation)?;
        result
    }

    /// `check_output(argv, cwd=..., env=..., text=True)`.
    pub fn check_output(&mut self, argv: &[String], cwd: &Path, env: &Dict) -> R<String> {
        let invocation = self.invocation(argv, cwd, env, false)?;
        let mut spec = Spec::new(invocation.command.clone()).env(&self.client_env);
        spec.stdout = sp::Output::Capture;
        let result = sp::run(spec).and_then(sp::Done::checked);
        self.dispose(invocation)?;
        Ok(result?.text())
    }

    /// `with invocation(argv, cwd, env) as (command, client_env, _): body`.
    /// A disposal failure replaces the body's outcome, as the former `finally`.
    pub fn invocation_with<T>(
        &mut self,
        argv: &[String],
        cwd: &Path,
        env: &Dict,
        discard_harness_target: bool,
        body: impl FnOnce(&[String], &[(String, String)]) -> R<T>,
    ) -> R<T> {
        let invocation = self.invocation(argv, cwd, env, discard_harness_target)?;
        let outcome = body(&invocation.command, &self.client_env);
        self.dispose(invocation)?;
        outcome
    }

    pub fn compiler_pool(&mut self) -> R<CompilerPool<'_>> {
        CompilerPool::new(self)
    }
}

/// Error text of a cancelled compiler case (`CancelledError`).
pub const CANCELLED: &str = "compiler pool cancelled";

fn cancelled() -> Error {
    value_error(CANCELLED)
}

/// A finished architecture candidate command (`subprocess.CompletedProcess`
/// with text-mode streams).
#[derive(Clone, Debug, Default)]
pub struct Done {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Spawn a command in this process group, as `subprocess` does; `cancel` is
/// polled and kills the attach client (its container is removed by disposal).
pub fn spawn(
    argv: &[String],
    env: Option<&[(String, String)]>,
    cwd: Option<&Path>,
    capture_stdout: bool,
    capture_stderr: bool,
    cancel: Option<&dyn Fn() -> bool>,
) -> R<(i32, Vec<u8>, Vec<u8>, bool)> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| value_error("missing candidate executable"))?;
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
        .map_err(|e| sp::os_error(&e, Some(Path::new(program))))?;
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
    let wait_error = |e: std::io::Error| sp::os_error(&e, None);
    let mut was_cancelled = false;
    let status = match cancel {
        None => child.wait().map_err(wait_error)?,
        Some(stop) => loop {
            if let Some(status) = child.try_wait().map_err(wait_error)? {
                break status;
            }
            if stop() {
                let _ = child.kill();
                was_cancelled = true;
                break child.wait().map_err(wait_error)?;
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
    Ok((sp::returncode(status), stdout, stderr, was_cancelled))
}

fn text_mode(data: &[u8]) -> R<String> {
    crate::pathx::text_mode(data).map_err(sp::from_text)
}

/// Job 6131: each seeded witness case ran 20-30 s inside its container with
/// 2 CPUs, of which one rustc checks the case's own crate; the remainder was
/// the private copy of the whole job Cargo seed, which vendored cases never
/// read. Four 1 CPU / 1.5 GiB isolates keep the same 4 CPU / 6 GiB aggregate.
pub const COMPILER_POOL_WIDTH: usize = 4;
/// CPUs (and Cargo jobs) of one isolate: the measured 4 CPU aggregate split.
pub const COMPILER_POOL_JOBS: usize = 4 / COMPILER_POOL_WIDTH;

/// Compiler isolates sharing only readonly inputs and an aggregate quota.
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
    pub fn run(&mut self, argv: &[String], cwd: &Path, vendored_sources: bool) -> R<Done> {
        if self.cancelled() {
            return Err(cancelled());
        }
        let mut env = Dict::environ();
        for (key, value) in [
            ("TMPDIR", "/tmp"),
            ("BUSBAR_TEST_TMP_ROOT", "/tmp/tests"),
            ("XDG_CACHE_HOME", "/tmp/cache"),
            ("MODERNCI_CACHE_DIR", "/tmp/cache"),
            ("CARGO_BUILD_JOBS", COMPILER_POOL_JOBS.to_string().as_str()),
        ] {
            env.set(key, value);
        }
        let cancel = self.cancel.clone();
        self.execution.vendored_sources = vendored_sources;
        self.execution
            .invocation_with(argv, cwd, &env, true, |command, client_env| {
                let stop = || cancel.load(Ordering::SeqCst) || proc::interrupted().is_some();
                if stop() {
                    return Err(cancelled());
                }
                let (code, stdout, stderr, was_cancelled) =
                    spawn(command, Some(client_env), None, true, true, Some(&stop))?;
                if was_cancelled {
                    return Err(cancelled());
                }
                Ok(Done {
                    code,
                    stdout: text_mode(&stdout)?,
                    stderr: text_mode(&stderr)?,
                })
            })
    }
}

impl<'a> CompilerPool<'a> {
    pub fn new(execution: &'a mut Execution) -> R<CompilerPool<'a>> {
        let resources = execution.config.at("resources").clone();
        let value = |key: &str| resources.at(key).as_int().unwrap_or(0);
        require(
            value("cpus") >= 4 && value("memory_bytes") >= 6 << 30 && value("pids") >= 2,
            "compiler pool requires the measured resource budget",
        )?;
        // Deliberately cap the pool at the measured 4 CPU / 6 GiB even on larger
        // runners. Container memory includes its tmpfs and shared memory charges.
        let width = COMPILER_POOL_WIDTH as i128;
        let slice = object([
            ("cpus", Value::int(COMPILER_POOL_JOBS as i128)),
            ("memory_bytes", Value::int((6i128 << 30) / width)),
            ("pids", Value::int(value("pids") / width)),
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
    pub fn map<C: Sync, T: Send>(
        &mut self,
        cases: &[C],
        function: &(dyn Fn(&mut Slot, usize, &C) -> R<T> + Sync),
    ) -> R<Vec<T>> {
        require(!self.used, "compiler pool cannot be reused")?;
        self.used = true;
        let prepared_git = self.execution.sanitize_git()?;
        let parent = self.execution.clone();
        let resources = self.resources.clone();
        let cancel = self.cancel.clone();
        let next = std::sync::Mutex::new(0usize);
        type Outcome<T> = (R<T>, Vec<Value>);
        let outcomes: std::sync::Mutex<BTreeMap<usize, Outcome<T>>> = Default::default();
        proc::install_signal_handlers();
        let invoke = |index: usize, case: &C| -> Outcome<T> {
            if cancel.load(Ordering::SeqCst) || proc::interrupted().is_some() {
                cancel.store(true, Ordering::SeqCst);
                return (Err(cancelled()), Vec::new());
            }
            let base = parent
                .roots
                .candidate
                .parent()
                .unwrap_or(Path::new("/"))
                .join(format!("compiler-isolate-{}", sp::uuid_hex()));
            let prepare = || -> R<Execution> {
                sp::mkdir(&base, 0o755, false)?;
                let (candidate, control) = (base.join("candidate"), base.join("control"));
                sp::mkdir(&candidate, 0o755, false)?;
                sp::mkdir(&control, 0o700, false)?;
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
                sp::mkdir(&child.fixture_directory, 0o755, false)?;
                child.fixture_map = control.join("fixture-map.json");
                sp::write(&child.fixture_map, "[]\n")?;
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
                row.set("compiler_case_index", (index as u64).into());
            }
            // Never delete artifacts while a container could still hold
            // them. A failed disposal retains the entire private root.
            if rows.iter().all(|row| row.at("disposed").truthy())
                && let Err(error) = sp::rmtree(&base)
            {
                cancel.store(true, Ordering::SeqCst);
                result = Err(error);
            }
            (result, rows)
        };
        std::thread::scope(|scope| {
            for _ in 0..COMPILER_POOL_WIDTH {
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
            return Err(Error::new(
                Kind::Os,
                format!("compiler pool interrupted by signal {signal}"),
            ));
        }
        if !errors.is_empty() {
            let first = errors
                .iter()
                .position(|e| e.message != CANCELLED)
                .unwrap_or(0);
            return Err(errors.swap_remove(first));
        }
        Ok(results)
    }
}

/// `os.walk(checkout)` refusing links outside Git/target directories.
fn source_without_links(root: &Path) -> R<()> {
    let omitted = [
        root.join(".git"),
        root.join("target"),
        root.join("dist/default/target"),
    ];
    fn walk(directory: &Path, omitted: &[PathBuf]) -> R<()> {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return Ok(());
        };
        let mut subdirectories = Vec::new();
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            require(!sp::is_symlink(&path), "candidate source contains symlinks")?;
            if path.is_dir() && !omitted.contains(&path) {
                subdirectories.push(path);
            }
        }
        for path in subdirectories {
            walk(&path, omitted)?;
        }
        Ok(())
    }
    walk(root, &omitted)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn config(docker: &Path, storage: &Path) -> Value {
        let sha = sha256::file(docker).unwrap();
        crate::json::parse(
            format!(
                r#"{{"schema":"busbar.native-confinement/2","docker":"{}","docker_sha256":"{sha}",
                "docker_host":"unix:///var/run/docker.sock","image":"sha256:{}","runtime":"runc",
                "uid":1000,"gid":1000,"python":"/usr/bin/python3","environment":{{"PATH":"/usr/local/cargo/bin:/usr/bin:/bin"}},
                "resources":{{"cpus":4,"memory_bytes":6442450944,"pids":4096}},
                "isolation":{{"storage_kind":"tmpfs","storage_root":"{}","storage_bytes":1073741824,
                "storage_inodes":100000,"storage_reserve_bytes":0,"uid_map":[0,524288,65536],"gid_map":[0,524288,65536]}},
                "collector":{{"docker_host":"unix:///var/run/docker.sock","uid":525288,"gid":525288}}}}"#,
                docker.display(),
                "a".repeat(64),
                storage.display()
            )
            .as_bytes(),
        )
        .unwrap()
    }

    pub struct Fixture {
        pub base: PathBuf,
        pub roots: Roots,
        pub control: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    pub fn fixture(label: &str) -> Fixture {
        let base = sp::resolve(&std::env::temp_dir())
            .join(format!("busbar-ci-confine-{label}-{}", sp::uuid_hex()));
        let roots = Roots {
            checkout: base.join("checkout"),
            candidate: base.join("candidate"),
            trusted: base.join("trusted"),
            harness: base.join("harness"),
        };
        for path in [
            &roots.checkout,
            &roots.candidate,
            &roots.trusted,
            &roots.harness,
        ] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::create_dir_all(roots.checkout.join(".git/objects")).unwrap();
        std::fs::write(roots.checkout.join(".git/HEAD"), "ref: refs/heads/dev\n").unwrap();
        let control = base.join("control");
        std::fs::create_dir_all(&control).unwrap();
        Fixture {
            base,
            roots,
            control,
        }
    }

    fn execution(f: &Fixture) -> Execution {
        Execution::new(
            config(Path::new("/bin/echo"), &f.base.join("storage")),
            f.roots.clone(),
            &f.control,
            f.roots
                .trusted
                .join("scripts/architecture/confinement_entry.py"),
        )
        .unwrap()
    }

    #[test]
    fn requires_pinned_client_image_nonroot_and_private_roots() {
        let f = fixture("refuse");
        let base = config(Path::new("/bin/echo"), &f.base.join("storage"));
        let cases: [(&str, Value, &str); 6] = [
            (
                "docker_sha256",
                "0".repeat(64).into(),
                "Docker client is not the pinned executable",
            ),
            (
                "docker_host",
                "tcp://host:2375".into(),
                "local Unix Docker endpoint required",
            ),
            (
                "image",
                "rust:latest".into(),
                "immutable toolchain image required",
            ),
            ("uid", 0u64.into(), "candidate must use a nonroot identity"),
            ("runtime", "kata".into(), "unsupported candidate runtime"),
            (
                "python",
                "python3".into(),
                "pinned-image Python path required",
            ),
        ];
        for (key, value, message) in cases {
            let mut config = base.clone();
            config.set(key, value);
            let error = Execution::new(config, f.roots.clone(), &f.control, PathBuf::from("/x"))
                .err()
                .unwrap();
            assert_eq!(error.message, message, "{key}");
        }
        let overlapping = Roots {
            candidate: f.roots.checkout.join("inner"),
            ..f.roots.clone()
        };
        std::fs::create_dir_all(&overlapping.candidate).unwrap();
        assert_eq!(
            Execution::new(base.clone(), overlapping, &f.control, PathBuf::from("/x"))
                .err()
                .unwrap()
                .message,
            "candidate roots overlap"
        );
        std::os::unix::fs::symlink("/etc", f.roots.checkout.join("link")).unwrap();
        assert_eq!(
            Execution::new(base, f.roots.clone(), &f.control, PathBuf::from("/x"))
                .err()
                .unwrap()
                .message,
            "candidate source contains symlinks"
        );
    }

    #[test]
    fn context_is_digest_bound_and_sorted() {
        let f = fixture("context");
        let mut execution = execution(&f);
        execution.extra_readonly.push(f.roots.harness.clone());
        execution.dependency_seed_sha256 = Some("b".repeat(64));
        let (path, expected) = execution.write_context().unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(sha256::hex(&data), expected);
        let text = String::from_utf8(data).unwrap();
        assert!(text.starts_with("{\"configuration\":{\"collector\":"));
        assert!(text.contains("\"conformance_inputs_manifest\":null,\"conformance_mounts\":[]"));
        assert!(text.ends_with(&("\"dependency_seed_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"extra_readonly\":[\"".to_owned() + &sp::text(&f.roots.harness) + "\"],\"roots\":{\"candidate\":\"" + &sp::text(&f.roots.candidate) + "\",\"checkout\":\"" + &sp::text(&f.roots.checkout) + "\",\"harness\":\"" + &sp::text(&f.roots.harness) + "\",\"trusted\":\"" + &sp::text(&f.roots.trusted) + "\"}}\n")));
    }

    #[test]
    fn environment_is_allowlisted_and_git_auth_cannot_cross() {
        let f = fixture("environment");
        let execution = execution(&f);
        let mut env = Dict::default();
        for (k, v) in [
            ("CI", "1"),
            ("CI_JOB_TOKEN", "secret"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("BUSBAR_TEST_POSTGRES_URL", "postgres://127.0.0.1:1/x"),
            ("BUSBAR_TEST__URL", "x"),
        ] {
            env.set(k, v);
        }
        let result = execution.environment(&env).unwrap();
        assert!(result.contains_key("CI") && result.contains_key("BUSBAR_TEST_POSTGRES_URL"));
        assert!(
            !result.contains_key("CI_JOB_TOKEN") && !result.contains_key("AWS_SECRET_ACCESS_KEY")
        );
        assert!(!result.contains_key("BUSBAR_TEST__URL"));
        assert_eq!(result["GIT_CONFIG_COUNT"], "2");
        assert_eq!(result["GIT_CONFIG_KEY_0"], "safe.directory");
        assert_eq!(result["GIT_CONFIG_VALUE_1"], sp::text(&f.roots.trusted));
        assert_eq!(result["CARGO_NET_OFFLINE"], "true");
        env.set("GIT_CONFIG_COUNT", "1");
        env.set("GIT_CONFIG_KEY_0", "http.https://git.example/.extraheader");
        env.set("GIT_CONFIG_VALUE_0", "Authorization: Basic x");
        assert_eq!(
            execution.environment(&env).unwrap_err().message,
            "unexpected Git setting in candidate environment"
        );
        let mut overridden = Execution { ..execution };
        overridden.product_inputs.set("BUSBAR_PLUGIN_CDYLIB", "/a");
        env.set("GIT_CONFIG_COUNT", "0");
        env.set("BUSBAR_PLUGIN_CDYLIB", "/b");
        assert_eq!(
            overridden.environment(&env).unwrap_err().message,
            "registered product input was overridden"
        );
    }

    #[test]
    fn conformance_manifest_is_controller_pinned() {
        let f = fixture("capabilities");
        let mut execution = execution(&f);
        let digest = execution
            .set_conformance_capabilities(None, "GetBusbar/busbar", &"c".repeat(40), None)
            .unwrap();
        let path = f.control.join("conformance-capabilities.json");
        assert_eq!(sha256::file(&path).unwrap(), digest);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!(
                "{{\"repo\":\"GetBusbar/busbar\",\"schema\":\"busbar.conformance.capabilities/1\",\"source\":\"{}\",\"suites\":{{}},\"toolchain_ready\":false}}\n",
                "c".repeat(40)
            )
        );
        let candidate = f.roots.candidate.join("caps.json");
        std::fs::write(&candidate, "{}").unwrap();
        let sha = sha256::file(&candidate).unwrap();
        assert_eq!(
            execution
                .set_conformance_capabilities(Some(&candidate), "GetBusbar/busbar", "x", Some(&sha))
                .unwrap_err()
                .message,
            "candidate supplied conformance capabilities"
        );
    }

    #[test]
    fn image_references_are_immutable() {
        assert!(image_reference(&format!("sha256:{}", "a".repeat(64))));
        assert!(image_reference(&format!(
            "mirror.gcr.io/library/rust:1@sha256:{}",
            "a".repeat(64)
        )));
        assert!(!image_reference("rust:latest"));
        assert!(!image_reference(&format!(
            "UPPER@sha256:{}",
            "a".repeat(64)
        )));
        assert!(unix_endpoint("unix:///var/run/docker.sock"));
        assert!(!unix_endpoint("unix:///a b"));
    }
}

/// The former `test_compiler_storage.py` / `test_compiler_parallel.py` and the
/// architecture context cases: invocation lifecycle against a fake engine.
#[cfg(test)]
pub mod lifecycle_tests {
    use super::*;
    use crate::native::sp::text;
    use crate::py;
    use std::fs;
    use std::sync::Mutex;

    const TMPFS: &str = "rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777";

    fn no_env() -> Dict {
        Dict::default()
    }

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
                sp::resolve(&std::env::temp_dir()).join(format!("confine-{}", sp::uuid_hex()));
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
            let mut execution = Execution::new(
                self.config.clone(),
                self.roots.clone(),
                &self.control,
                self.roots
                    .trusted
                    .join("scripts/architecture/confinement_entry.py"),
            )
            .unwrap();
            execution.hooks = hooks;
            execution
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
                client: Some(Arc::new(move |argv: &[String], _| {
                    let (code, payload) = engine.client(argv);
                    Ok((code, payload.into_bytes()))
                })),
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
                .invocation_with(&argv, &fixture.roots.checkout, &no_env(), true, |_, _| {
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
    fn empty_cargo_home_only_for_vendored_harness_checks() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        let mut execution = fixture.execution(engine.hooks());
        let mut vendored = harness_argv(&fixture);
        vendored.extend(["--config".into(), "/v.toml".into()]);
        let mut build = vendored.clone();
        build[1] = "build".into();
        for (argv, discard) in [
            (vendored.clone(), false),
            (harness_argv(&fixture), true),
            (build, true),
        ] {
            execution.vendored_sources = true;
            let error = execution
                .invocation_with(
                    &argv,
                    &fixture.roots.checkout,
                    &no_env(),
                    discard,
                    |_, _| -> R<()> { panic!("unvendored command skipped the seed copy") },
                )
                .unwrap_err();
            assert!(error.message.contains("vendored harness compiler check"));
            assert!(!execution.vendored_sources, "the request is consumed");
        }
        execution.vendored_sources = true;
        execution
            .invocation_with(
                &vendored,
                &fixture.roots.checkout,
                &no_env(),
                true,
                |_, _| Ok(()),
            )
            .unwrap();
    }

    #[test]
    fn default_retains_generated_build_output() {
        let fixture = Fixture::new();
        let engine = Engine::new(2 << 30);
        let mut execution = fixture.execution(engine.hooks());
        let argv = harness_argv(&fixture);
        execution
            .invocation_with(&argv, &fixture.roots.checkout, &no_env(), false, |_, _| {
                Ok(())
            })
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
        let result: R<()> =
            execution.invocation_with(&argv, &fixture.roots.checkout, &no_env(), true, |_, _| {
                Err(sp::from_text(crate::pathx::called_process_error(&argv, 1)))
            });
        assert!(
            result
                .unwrap_err()
                .message
                .contains("non-zero exit status 1")
        );
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
            .invocation_with(&argv, &fixture.roots.checkout, &no_env(), true, |_, _| {
                Ok(())
            })
            .unwrap_err();
        assert!(error.message.contains("disposal"));
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
            .invocation_with(&argv, &fixture.roots.checkout, &no_env(), true, |_, _| {
                let target = engine.targets.lock().unwrap().last().unwrap().clone();
                fs::remove_dir_all(&target).unwrap();
                std::os::unix::fs::symlink(&control, &target).unwrap();
                Ok(())
            })
            .unwrap();
        let target = engine.targets.lock().unwrap().last().unwrap().clone();
        assert!(!sp::is_symlink(&target));
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
            .invocation_with(
                &argv,
                &fixture.roots.checkout,
                &no_env(),
                true,
                |_, _| -> R<()> { panic!("candidate manifest accepted") },
            )
            .unwrap_err();
        assert!(error.message.contains("trusted harness"));
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
        let error = execution.cargo_environment(&argv, &no_env()).unwrap_err();
        assert!(error.message.contains("indirect writable"));
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
                    fixture.roots.clone(),
                    &fixture.control,
                    PathBuf::from("/entry.py")
                )
                .is_err()
            );
        }
        let mut roots = fixture.roots.clone();
        roots.candidate = fixture.roots.checkout.join("nested");
        fs::create_dir(fixture.roots.checkout.join("nested")).unwrap();
        assert!(
            Execution::new(
                fixture.config.clone(),
                roots,
                &fixture.control,
                PathBuf::from("/entry.py")
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
                    .invocation_with(&argv, &harness, &no_env(), true, |_, _| {
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
                sha_canonical(&fixture.config)
            );
            assert!(py::eq(
                row.at("aggregate_resources"),
                fixture.config.at("resources")
            ));
            assert_eq!(
                json::dumps(row.at("resources"), false),
                r#"{"cpus": 1, "memory_bytes": 1610612736, "pids": 64}"#
            );
            assert_eq!(row.at("compiler_pool_width").as_int(), Some(4));
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
                        slot.execution.invocation_with(
                            &argv,
                            &harness,
                            &no_env(),
                            true,
                            |_, _| -> R<()> { panic!("weakened engine limits were accepted") },
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
                    .invocation_with(&argv, &harness, &no_env(), true, |_, _| Ok(()))
            })
            .unwrap_err();
        assert!(error.message.contains("disposal"));
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
             -> R<Option<i32>> {
                if index == 0 {
                    let script = format!("echo $$ > {}; exec sleep 60", text(&ready));
                    let argv = ["/bin/sh", "-c", &script].map(String::from);
                    let stop = || slot.cancel.load(Ordering::SeqCst);
                    let (_, _, _, was_cancelled) =
                        spawn(&argv, None, None, true, true, Some(&stop))?;
                    *disposed.lock().unwrap() += 1;
                    return if was_cancelled {
                        Err(cancelled())
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
                Err(value_error("wrong compiler diagnostic"))
            })
            .unwrap_err();
        assert_eq!(error.message, "wrong compiler diagnostic");
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
            assert!(error.message.contains("resource budget"));
        }
        assert!(engine.created.lock().unwrap().is_empty());
        drop(fixture);
    }
}
