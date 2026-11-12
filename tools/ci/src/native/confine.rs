//! Explicit candidate execution boundary (former `native_confinement.Execution`).
//! Controller code never enters its mounts; missing images, unsupported
//! fixtures or failed disposal refuse, with no host fallback. The execution
//! context it writes is read by the architecture step (`check.py`), so its
//! bytes and the observations it appends keep the former schema exactly.
use super::pysteps;
use super::sp::{
    self, Dict, Error, Io, Kind, R, Spec, at, key_error, need_value as require, value_error,
};
use crate::isolation;
use crate::json::{self, Value, object};
use crate::sha256;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn digest(path: &Path) -> R<String> {
    sha256::file(path).map_err(|e| {
        let error = std::fs::File::open(path).err();
        match error {
            Some(error) => sp::os_error(&error, Some(path)),
            None => value_error(e),
        }
    })
}

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
    value.strip_prefix("unix:///").is_some_and(|rest| {
        !rest.is_empty() && !rest.chars().any(|c| c.is_whitespace() || c == ',')
    })
}

fn positive_int(value: &Value) -> Option<i128> {
    value.as_int().filter(|v| *v > 0)
}

fn is_relative_to(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// The four candidate-visible roots, in their former insertion order.
#[derive(Clone, Debug)]
pub struct Roots {
    pub checkout: PathBuf,
    pub candidate: PathBuf,
    pub trusted: PathBuf,
    pub harness: PathBuf,
}

impl Roots {
    fn all(&self) -> [(&'static str, &PathBuf); 4] {
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
    pub profile: Option<Profile>,
    pub restriction: Option<Restriction>,
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
            profile: None,
            restriction: None,
        })
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
        let done = sp::run(self.client_spec(args)?.capture())?;
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
        let inputs = &self.roots.candidate;
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
        let resources = self.config.at("resources").clone();
        let target = self.roots.checkout.join("target");
        sp::mkdir(&target, 0o777, true)?;
        checked_directory(&target)?;
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
            (target.clone(), target, true),
        ];
        for relative in ["canonical-inputs", "host", "sdk", "c-witness"] {
            let path = self.roots.candidate.join(relative);
            if path.exists() {
                mounts.push((checked_directory(&path)?, path, false));
            }
        }
        let nested = checkout.join("dist/default/target");
        if nested.parent().is_some_and(Path::is_dir) {
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
            let path = self.roots.candidate.join("cargo-home-invocation");
            sp::mkdir(&path, 0o700, false)?;
            safe_env.insert("BUSBAR_INVOCATION_CARGO_HOME".into(), sp::text(&path));
            cargo_home = Some(path);
        }
        let isolation = self.config.at("isolation").clone();
        let writable: Vec<PathBuf> = mounts.iter().filter(|m| m.2).map(|m| m.0.clone()).collect();
        let mut storage = isolation::prepare_writable(
            &isolation,
            &writable,
            self.uid() as u64,
            self.gid() as u64,
        )
        .map_err(sp::from_text)?;
        let daemon_result = self.client(&sp::strings(&["info", "--format", "{{json .}}"]))?;
        require(
            daemon_result.code == 0,
            "candidate daemon identity unavailable",
        )?;
        let daemon = sp::loads(&daemon_result.stdout)?;
        let user_namespace =
            isolation::validate_userns(&isolation, &daemon).map_err(sp::from_text)?;
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
        let observation = object([
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
        self.observations.push(observation);
        let mut invocation = Invocation {
            name: name.clone(),
            command: Vec::new(),
            observation: self.observations.len() - 1,
            inspected: false,
            disposable_target,
            cargo_home,
        };
        match self.start(&mut invocation, &args, &daemon, &mounts, &fixture_hosts) {
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
        isolation::validate_userns_inspected(&isolation, daemon, &actual).map_err(sp::from_text)?;
        let host = at(&actual, "HostConfig")?;
        let resources = self.config.at("resources");
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
        let removed = sp::run(
            self.client_spec(&sp::strings(&["rm", "--force", &name]))?
                .quiet(),
        )?;
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
        let disposed = self.dispose(invocation);
        let done = result?;
        disposed?;
        Ok(done)
    }

    /// `check_output(argv, cwd=..., env=..., text=True)`.
    pub fn check_output(&mut self, argv: &[String], cwd: &Path, env: &Dict) -> R<String> {
        let invocation = self.invocation(argv, cwd, env, false)?;
        let mut spec = Spec::new(invocation.command.clone()).env(&self.client_env);
        spec.stdout = sp::Output::Capture;
        let result = sp::run(spec).and_then(sp::Done::checked);
        let disposed = self.dispose(invocation);
        let done = result?;
        disposed?;
        Ok(done.text())
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
