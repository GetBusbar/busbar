//! `busbar-ci native-qualify`: the trusted native admission step runner
//! (former `scripts/architecture/native.py` and the `native_*` modules it
//! imported). Full suites run only inside a GitLab job.
//!
//! The project setting chooses this binary's immutable checkout. Candidate
//! code supplies the product, never the policy, compiler witnesses, command
//! list or merge credential. The step list, argv, `receipt.json` bytes,
//! evidence layout and refusal messages are those of the former runner; the
//! only Python left on this path is named in [`pysteps`].
pub mod capabilities;
pub mod cinputs;
pub mod depcache;

pub mod fixtures;
pub mod junit;
pub mod oracle;
pub mod peers;
pub mod plugins;

pub mod pysteps;
pub mod release;
pub mod resources;
pub mod sanitizer;
pub mod seed;
pub mod sources;
pub mod sp;
pub mod staged;

use crate::confine::{self, Execution, Roots, digest};
use crate::json::{self, Value, object};
use crate::product;
use crate::sha256;
use sp::{Dict, Io, Kind, R, Spec, at, key_error, need, violation};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const CORE: &str = "GetBusbar/busbar";

/// `native_scheduling(execution)`: rustc runs inside the candidate's CPU and
/// memory boundary, never the controller's CPU count.
pub fn native_scheduling(cpus: usize, resources: Option<&Value>) -> Value {
    let mut available = cpus as i128;
    let mut memory = None;
    if let Some(resources) = resources {
        available = available.min(resources.at("cpus").as_int().unwrap_or(available));
        memory = resources.at("memory_bytes").as_int();
    }
    let test_threads = available.clamp(1, 16).max(1);
    let per_slot: i128 = 6 << 30;
    let unoptimized_per_slot: i128 = 2 << 30;
    let jobs = |slot: i128| match memory {
        None => test_threads,
        Some(memory) => (memory / slot).min(test_threads).max(1),
    };
    object([
        ("build_jobs", Value::int(jobs(per_slot))),
        ("test_threads", Value::int(test_threads)),
        (
            "unoptimized_build_jobs",
            Value::int(jobs(unoptimized_per_slot)),
        ),
        (
            "candidate_memory_bytes",
            memory.map_or(Value::Null, Value::int),
        ),
        ("compiler_memory_bytes_per_slot", Value::int(per_slot)),
        (
            "unoptimized_compiler_memory_bytes_per_slot",
            Value::int(unoptimized_per_slot),
        ),
        (
            "memory_policy",
            "conservative-slot-budget-not-measured-peak-or-fit-guarantee".into(),
        ),
    ])
}

const OPTIMIZED_STEPS: [&str; 2] = ["bounded-loom", "final-binary"];

const UNOPTIMIZED_CARGO_COMMANDS: [&str; 6] =
    ["check", "clippy", "test", "nextest", "build", "doc"];

/// Controller-named core wrapper steps whose every compiler invocation is a
/// dev-profile `cargo build`: product-inputs runs the trusted
/// scripts/ci-product-inputs.sh (plugin cdylibs land in target/debug), and core
/// conformance runs the digest-pinned testing/conformance/run.sh, whose suites
/// build dist/default, the packer and the OIDC plugin unoptimized. Matched by
/// step name and the exact trusted script name, never by candidate input.
const UNOPTIMIZED_WRAPPER_STEPS: [(&str, &str); 2] = [
    ("product-inputs", "scripts/ci-product-inputs.sh"),
    ("core-native-conformance", "testing/conformance/run.sh"),
];

/// Only a visible unoptimized cargo command gets the wider budget. Wrapper
/// scripts may build optimized binaries inside (a plugin's runtime preparation
/// runs its LTO release build), so they keep the conservative slot budget like
/// every optimized step, except the named core wrappers above.
pub fn step_build_jobs(name: &str, argv: &[String], scheduling: &Value) -> Value {
    let mut unoptimized = argv.len() >= 2
        && argv[0] == "cargo"
        && UNOPTIMIZED_CARGO_COMMANDS.contains(&argv[1].as_str())
        && !argv.iter().any(|a| a == "--release")
        && !argv.iter().any(|a| a.starts_with("--profile"));
    if let Some((_, script)) = UNOPTIMIZED_WRAPPER_STEPS
        .iter()
        .find(|(step, _)| *step == name)
        && argv.len() == 2
        && argv[0] == "bash"
        && argv[1].ends_with(&format!("/{script}"))
    {
        unoptimized = true;
    }
    if OPTIMIZED_STEPS.contains(&name)
        || !unoptimized
        || scheduling.get("unoptimized_build_jobs").is_none()
    {
        return scheduling.at("build_jobs").clone();
    }
    scheduling.at("unoptimized_build_jobs").clone()
}

/// `evaluation_job(repository, conformance_only, external_conformance, policy)`.
pub fn evaluation_job(
    repository: &str,
    conformance_only: bool,
    external: bool,
    policy: &Value,
) -> R<Option<&'static str>> {
    if conformance_only && external {
        return Err(violation("evaluation modes are mutually exclusive"));
    }
    if conformance_only && repository == CORE {
        return Ok(Some("core-conformance"));
    }
    if external
        && native_settings(repository, policy)?
            .at("external_conformance")
            .truthy()
    {
        return Ok(Some("external-conformance"));
    }
    if conformance_only || external {
        return Err(violation(
            "no trusted evaluation command for this repository",
        ));
    }
    Ok(None)
}

pub fn requires_native_oracle(repository: &str, external: bool, policy: &Value) -> R<bool> {
    Ok(native_settings(repository, policy)?
        .at("native_oracle")
        .truthy()
        && !external)
}

/// `native_policy.native_settings`, raising Violation like the former module.
pub fn native_settings(repository: &str, policy: &Value) -> R<Value> {
    crate::policy::native_settings(repository, policy).map_err(|m| {
        if m.starts_with("native ") && m.ends_with(" requirement must be boolean") {
            let fixed = if m.contains("native_oracle") {
                "native oracle requirement must be boolean"
            } else {
                "native conformance requirement must be boolean"
            };
            violation(fixed)
        } else if m == "policy has no repositories" {
            key_error("repositories")
        } else {
            violation(m)
        }
    })
}

/// `git(root, *args)`: `git -c safe.directory=<root> -C <root> ...`, stripped.
pub fn git(root: &Path, args: &[&str]) -> R<String> {
    let mut argv = vec![
        "git".to_owned(),
        "-c".into(),
        format!("safe.directory={}", sp::text(&sp::resolve(root))),
        "-C".into(),
        sp::text(root),
    ];
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    let out = sp::check_output(Spec::new(argv))?;
    Ok(String::from_utf8_lossy(&out).trim().to_owned())
}

pub fn now() -> String {
    crate::retention::utc_now()
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn environ(key: &str) -> R<String> {
    std::env::var(key).map_err(|_| key_error(key))
}

/// `fetch_environment()`: the job token is used only by trusted source fetches.
pub fn fetch_environment() -> R<Dict> {
    let mut env = Dict::environ();
    let token = env
        .get("CI_JOB_TOKEN")
        .ok_or_else(|| key_error("CI_JOB_TOKEN"))?
        .to_owned();
    let server = env
        .get("CI_SERVER_URL")
        .ok_or_else(|| key_error("CI_SERVER_URL"))?
        .trim_end_matches('/')
        .to_owned();
    env.set("GIT_CONFIG_COUNT", "1");
    env.set("GIT_CONFIG_KEY_0", format!("http.{server}/.extraheader"));
    env.set(
        "GIT_CONFIG_VALUE_0",
        format!(
            "Authorization: Basic {}",
            base64(format!("gitlab-ci-token:{token}").as_bytes())
        ),
    );
    env.set("GIT_TERMINAL_PROMPT", "0");
    Ok(env)
}

pub fn server_url() -> R<String> {
    Ok(environ("CI_SERVER_URL")?.trim_end_matches('/').to_owned())
}

/// `checkout(repository, revision, destination)`: one shallow exact fetch.
pub fn checkout(repository: &str, revision: &str, destination: &Path) -> R<PathBuf> {
    sp::mkdirs(destination, false)?;
    let env = fetch_environment()?;
    let server = server_url()?;
    let dest = sp::text(destination);
    sp::check_call(Spec::new(sp::strings(&["git", "-C", &dest, "init", "-q"])))?;
    sp::check_call(
        Spec::new(sp::strings(&[
            "git",
            "-C",
            &dest,
            "fetch",
            "--depth",
            "1",
            &format!("{server}/{repository}.git"),
            revision,
        ]))
        .env(&env.pairs()),
    )?;
    sp::check_call(Spec::new(sp::strings(&[
        "git",
        "-C",
        &dest,
        "checkout",
        "--detach",
        "FETCH_HEAD",
    ])))?;
    if product::is_revision(revision) && git(destination, &["rev-parse", "HEAD"])? != revision {
        return Err(violation("fetched source revision mismatch"));
    }
    Ok(destination.to_owned())
}

/// `published_dev_target(repository, source)`.
fn published_dev_target(repository: &str, source: &str) -> R<String> {
    let remote = format!("{}/{repository}.git", server_url()?);
    let out = sp::check_output(
        Spec::new(sp::strings(&[
            "git",
            "ls-remote",
            &remote,
            "refs/heads/dev",
        ]))
        .env(&fetch_environment()?.pairs())
        .cwd(Path::new("/")),
    )?;
    let text = String::from_utf8_lossy(&out);
    let lines: Vec<&str> = text.lines().collect();
    need(
        lines.len() == 1
            && lines[0].split_whitespace().collect::<Vec<_>>() == [source, "refs/heads/dev"],
        "published dev moved; qualify its current revision",
    )?;
    Ok(source.to_owned())
}

pub const CORE_LINT_COMMANDS: [(&str, &[&str]); 3] = [
    (
        "root-clippy",
        &[
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    ),
    (
        "default-clippy",
        &[
            "cargo",
            "clippy",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    ),
    (
        "root-clippy-nodefault",
        &[
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--no-default-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    ),
];

/// Parsed command line (former argparse interface).
#[derive(Default, Debug)]
pub struct Args {
    pub trusted: PathBuf,
    pub checkout: PathBuf,
    pub work: PathBuf,
    pub confinement: Option<PathBuf>,
    pub confinement_sha256: Option<String>,
    pub conformance_capabilities: Option<PathBuf>,
    pub conformance_capabilities_sha256: Option<String>,
    pub conformance_inputs: Option<PathBuf>,
    pub conformance_inputs_sha256: Option<String>,
    pub fixture_inputs: Option<PathBuf>,
    pub fixture_inputs_sha256: Option<String>,
    pub conformance_only: bool,
    pub external_conformance: bool,
}

const USAGE: &str = "usage: busbar-ci native-qualify [-h] --trusted TRUSTED --checkout CHECKOUT --work WORK [--confinement CONFINEMENT] [--confinement-sha256 CONFINEMENT_SHA256] [--conformance-capabilities CONFORMANCE_CAPABILITIES] [--conformance-capabilities-sha256 CONFORMANCE_CAPABILITIES_SHA256] [--conformance-inputs CONFORMANCE_INPUTS] [--conformance-inputs-sha256 CONFORMANCE_INPUTS_SHA256] [--fixture-inputs FIXTURE_INPUTS] [--fixture-inputs-sha256 FIXTURE_INPUTS_SHA256] [--conformance-only | --external-conformance]";

const VALUED: [&str; 11] = [
    "--trusted",
    "--checkout",
    "--work",
    "--confinement",
    "--confinement-sha256",
    "--conformance-capabilities",
    "--conformance-capabilities-sha256",
    "--conformance-inputs",
    "--conformance-inputs-sha256",
    "--fixture-inputs",
    "--fixture-inputs-sha256",
];
const FLAGS: [&str; 2] = ["--conformance-only", "--external-conformance"];

/// argparse semantics: `--name VALUE`, `--name=VALUE`, unique prefixes, last wins.
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut flags: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-h" || arg == "--help" {
            return Err(String::new());
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        let all: Vec<&str> = VALUED.iter().chain(FLAGS.iter()).copied().collect();
        let matched: Vec<&str> = match all.iter().find(|o| **o == name) {
            Some(exact) => vec![*exact],
            None => all
                .iter()
                .copied()
                .filter(|o| name.len() > 2 && name.starts_with("--") && o.starts_with(name))
                .collect(),
        };
        let [option] = matched.as_slice() else {
            return Err(if matched.is_empty() {
                format!("unrecognized arguments: {arg}")
            } else {
                format!(
                    "ambiguous option: {name} could match {}",
                    matched.join(", ")
                )
            });
        };
        if FLAGS.contains(option) {
            if let Some(value) = inline {
                return Err(format!(
                    "argument {option}: ignored explicit argument '{value}'"
                ));
            }
            let other = if *option == FLAGS[0] {
                FLAGS[1]
            } else {
                FLAGS[0]
            };
            if flags.contains(&other) {
                return Err(format!(
                    "argument {option}: not allowed with argument {other}"
                ));
            }
            flags.push(option);
        } else {
            let value = match inline {
                Some(value) => value,
                None => {
                    index += 1;
                    match args.get(index) {
                        Some(value) if !value.starts_with('-') || value.len() == 1 => value.clone(),
                        _ => return Err(format!("argument {option}: expected one argument")),
                    }
                }
            };
            values.retain(|(k, _)| k != option);
            values.push(((*option).to_owned(), value));
        }
        index += 1;
    }
    let get = |name: &str| {
        values
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let missing: Vec<&str> = ["--trusted", "--checkout", "--work"]
        .into_iter()
        .filter(|k| get(k).is_none())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "the following arguments are required: {}",
            missing.join(", ")
        ));
    }
    let path = |name: &str| get(name).map(PathBuf::from);
    Ok(Args {
        trusted: path("--trusted").unwrap_or_default(),
        checkout: path("--checkout").unwrap_or_default(),
        work: path("--work").unwrap_or_default(),
        confinement: path("--confinement").filter(|p| !p.as_os_str().is_empty()),
        confinement_sha256: get("--confinement-sha256"),
        conformance_capabilities: path("--conformance-capabilities")
            .filter(|p| !p.as_os_str().is_empty()),
        conformance_capabilities_sha256: get("--conformance-capabilities-sha256"),
        conformance_inputs: path("--conformance-inputs").filter(|p| !p.as_os_str().is_empty()),
        conformance_inputs_sha256: get("--conformance-inputs-sha256"),
        fixture_inputs: path("--fixture-inputs").filter(|p| !p.as_os_str().is_empty()),
        fixture_inputs_sha256: get("--fixture-inputs-sha256"),
        conformance_only: flags.contains(&FLAGS[0]),
        external_conformance: flags.contains(&FLAGS[1]),
    })
}

fn nonempty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

/// `Policy(data)` constructor validation (the step runner reads `policy.data`).
fn validate_policy(data: &Value) -> R<()> {
    need(
        data.get("version").is_some_and(|v| v.equals_int(1)),
        "unsupported architecture policy",
    )?;
    for (_, entry) in at(data, "core")?.as_object().into_iter().flatten() {
        need(entry.is_object(), "core policy entries must be tables")?;
    }
    for (_, repo) in at(data, "repositories")?.as_object().into_iter().flatten() {
        for package in repo.at("packages").as_array().unwrap_or(&[]) {
            at(package, "role")?;
            at(package, "name")?;
        }
    }
    at(at(data, "assembly")?, "package")?;
    for host in data.at("test_hosts").as_array().unwrap_or(&[]) {
        if host.at("package").truthy() {
            at(host, "allows")?;
        }
    }
    Ok(())
}

pub struct Q {
    pub conformance_only: bool,
    pub external_conformance: bool,
    pub evaluation_only: bool,
    pub root: PathBuf,
    pub trusted: PathBuf,
    pub work: PathBuf,
    pub control: PathBuf,
    pub harness: PathBuf,
    pub evidence: PathBuf,
    pub execution: Option<Execution>,
    pub repository: String,
    pub policy: Value,
    pub receipt: Value,
    pub env: Dict,
    pub staged_fixtures: Vec<(String, PathBuf)>,
    host: Option<PathBuf>,
    sdk_checkout: Option<PathBuf>,
    /// (step index, observation index): `row['container']` is the live observation.
    containers: Vec<(usize, usize)>,
}

impl Q {
    pub fn new(args: &Args) -> R<Q> {
        let root = sp::resolve(&args.checkout);
        let trusted = sp::resolve(&args.trusted);
        let control = sp::resolve(&args.work);
        let Some(confinement) = &args.confinement else {
            if nonempty(&args.confinement_sha256).is_some() {
                return Err(violation("confinement digest requires its configuration"));
            }
            // The protected bootstrap always confines candidate execution; the
            // former unconfined development path has no CI caller.
            return Err(violation(
                "native qualification requires the protected confinement configuration",
            ));
        };
        let expected = nonempty(&args.confinement_sha256);
        if expected.is_none() || digest(confinement)? != expected.unwrap_or("") {
            return Err(violation(
                "protected confinement configuration digest differs",
            ));
        }
        let work = control.join("candidate");
        sp::mkdir(&work, 0o700, false)?;
        let harness = control.join("harness");
        sp::mkdir(&harness, 0o700, false)?;
        // Controller-owned source is bind-mounted read-only, but the
        // remapped compiler must be able to traverse its mount root.
        sp::chmod(&harness, 0o755)?;
        let config = sp::read_json(confinement)?;
        let roots = Roots {
            checkout: root.clone(),
            candidate: work.clone(),
            trusted: trusted.clone(),
            harness: harness.clone(),
        };
        let entry = trusted.join("scripts/architecture/confinement_entry.py");
        let execution = Some(Execution::new(config, roots, &control, entry)?);
        let evidence = control.join("evidence");
        sp::mkdir(&evidence, 0o777, false)?;
        let repository = environ("CI_PROJECT_PATH")?;
        let policy_path = trusted.join("ci/architecture.toml");
        let policy = product::toml(&sp::read(&policy_path)?)?;
        validate_policy(&policy)?;
        let source = git(&root, &["rev-parse", "HEAD"])?;
        let receipt = object([
            ("schema", "busbar.protected-native-admission/1".into()),
            ("status", "running".into()),
            ("started_at", now().into()),
            ("repository", repository.as_str().into()),
            ("source", source.as_str().into()),
            (
                "source_tree",
                git(&root, &["rev-parse", "HEAD^{tree}"])?.into(),
            ),
            (
                "policy_revision",
                git(&trusted, &["rev-parse", "HEAD"])?.into(),
            ),
            ("policy_sha256", digest(&policy_path)?.into()),
            ("config_uri", environ("CI_CONFIG_REF_URI")?.into()),
            ("pipeline_id", environ("CI_PIPELINE_ID")?.into()),
            ("job_id", environ("CI_JOB_ID")?.into()),
            ("job_url", environ("CI_JOB_URL")?.into()),
            ("steps", Value::Array(Vec::new())),
        ]);
        let mut q = Q {
            conformance_only: args.conformance_only,
            external_conformance: args.external_conformance,
            evaluation_only: args.conformance_only || args.external_conformance,
            root,
            trusted,
            work,
            control,
            harness,
            evidence,
            execution,
            repository,
            policy,
            receipt,
            env: Dict::default(),
            staged_fixtures: Vec::new(),
            host: None,
            sdk_checkout: None,
            containers: Vec::new(),
        };
        // A fresh job VM does not separate candidate code from this controller.
        // This development receipt must never substitute for independent host
        // observation required by the protected release producer.
        q.receipt.set(
            "execution_boundary",
            object([
                ("mode", "docker-confined".into()),
                ("isolated", false.into()),
                ("release_eligible", false.into()),
                ("confinement_configured", true.into()),
                (
                    "approved_configuration_sha256",
                    args.confinement_sha256
                        .clone()
                        .map_or(Value::Null, Value::from),
                ),
                ("observations", Value::Array(Vec::new())),
                ("observer", "protected-controller".into()),
                (
                    "limitation",
                    "development execution evidence; not a release-producer attestation".into(),
                ),
            ]),
        );
        let capability_path = args.conformance_capabilities.clone();
        let capability_digest = nonempty(&args.conformance_capabilities_sha256).map(str::to_owned);
        if capability_path.is_some() != capability_digest.is_some() {
            return Err(violation(
                "conformance capabilities require an independently approved digest",
            ));
        }
        let repository = q.repository.clone();
        let execution = q.execution.as_mut().unwrap();
        let capabilities = execution.set_conformance_capabilities(
            capability_path.as_deref(),
            &repository,
            &source,
            capability_digest.as_deref(),
        )?;
        q.receipt
            .set("conformance_capabilities_sha256", capabilities.into());
        if q.evaluation_only {
            let expected = evaluation_job(
                &q.repository,
                q.conformance_only,
                q.external_conformance,
                &q.policy,
            )?;
            let job = std::env::var("CI_JOB_NAME").ok();
            let source = std::env::var("CI_PIPELINE_SOURCE").ok();
            if job.as_deref() != expected
                || !matches!(
                    source.as_deref(),
                    Some("api" | "merge_request_event" | "push")
                )
            {
                return Err(violation(
                    "conformance requires its trusted job and pipeline source",
                ));
            }
            // This receipt supplements, and never replaces, native qualification.
            q.receipt
                .set("schema", "busbar.protected-conformance/1".into());
        }
        if source != environ("CI_COMMIT_SHA")? {
            return Err(violation("candidate checkout is not the pipeline commit"));
        }
        let tools_path = args.conformance_inputs.clone();
        let tools_digest = nonempty(&args.conformance_inputs_sha256).map(str::to_owned);
        if tools_path.is_some() || tools_digest.is_some() {
            let (Some(path), Some(expected)) = (&tools_path, &tools_digest) else {
                return Err(violation(
                    "conformance instruments require confined execution and a protected plan digest",
                ));
            };
            cinputs::stage(&mut q, path, expected)?;
        }
        let fixture_path = args.fixture_inputs.clone();
        let fixture_digest = nonempty(&args.fixture_inputs_sha256).map(str::to_owned);
        if fixture_path.is_some() != fixture_digest.is_some() {
            return Err(violation(
                "staged fixture inputs require confinement and a protected digest",
            ));
        }
        if let (Some(path), Some(expected)) = (&fixture_path, &fixture_digest) {
            q.staged_fixtures = staged::stage(&mut q, path, expected)?;
        }
        if !git(&q.root, &["status", "--porcelain"])?.is_empty() {
            return Err(violation(
                "candidate checkout is dirty before qualification",
            ));
        }
        let pipeline = environ("CI_PIPELINE_SOURCE")?;
        if pipeline == "merge_request_event" {
            if environ("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")? != "dev"
                || environ("CI_MERGE_REQUEST_SOURCE_PROJECT_ID")? != environ("CI_PROJECT_ID")?
            {
                return Err(violation(
                    "qualification requires a same-project candidate targeting dev",
                ));
            }
            let remote = format!("{}/{}.git", server_url()?, q.repository);
            let line = sp::check_output(
                Spec::new(sp::strings(&[
                    "git",
                    "ls-remote",
                    &remote,
                    "refs/heads/dev",
                ]))
                .env(&fetch_environment()?.pairs())
                .cwd(Path::new("/")),
            )?;
            let line = String::from_utf8_lossy(&line).into_owned();
            let target = line
                .split_whitespace()
                .next()
                .ok_or_else(|| sp::Error::new(Kind::Value, "list index out of range"))?
                .to_owned();
            need(
                product::is_revision(&target),
                "target branch revision is unavailable",
            )?;
            sp::check_call(
                Spec::new(sp::strings(&[
                    "git",
                    "-C",
                    &sp::text(&q.root),
                    "fetch",
                    "--no-tags",
                    &remote,
                    &target,
                ]))
                .env(&fetch_environment()?.pairs()),
            )?;
            let ancestor = sp::run(Spec::new(sp::strings(&[
                "git",
                "-C",
                &sp::text(&q.root),
                "merge-base",
                "--is-ancestor",
                &target,
                &source,
            ])))?;
            if ancestor.code != 0 {
                return Err(violation(
                    "candidate must be rebased on current dev and qualified again",
                ));
            }
            q.receipt.set("target_revision", target.into());
        } else if matches!(pipeline.as_str(), "push" | "api")
            && std::env::var("CI_COMMIT_BRANCH").ok().as_deref() == Some("dev")
        {
            let target = if pipeline == "api" {
                published_dev_target(&q.repository, &source)?
            } else {
                source.clone()
            };
            q.receipt.set("target_revision", target.into());
            // Server-provided; consumers require a protected dev ref for push/api credit.
            q.receipt.set(
                "commit_ref_protected",
                (std::env::var("CI_COMMIT_REF_PROTECTED").ok().as_deref() == Some("true")).into(),
            );
        } else if q.evaluation_only && pipeline == "api" {
            q.receipt.set("target_revision", Value::Null);
        } else {
            return Err(violation(
                "qualification requires a dev MR or published dev commit",
            ));
        }
        // Build/test children receive no project tokens, cloud credentials or
        // merge/settings credentials. The short-lived job token is used only by
        // the trusted source fetcher.
        let keep = [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "LANG",
            "LC_ALL",
            "CARGO_HOME",
            "RUSTUP_HOME",
        ];
        q.env = Dict(
            Dict::environ()
                .0
                .into_iter()
                .filter(|(k, _)| keep.contains(&k.as_str()))
                .collect(),
        );
        let cpus = std::thread::available_parallelism().map_or(4, usize::from);
        let cpus = host_cpu_count().unwrap_or(cpus);
        let scheduling =
            native_scheduling(cpus, q.execution.as_ref().map(|e| e.config.at("resources")));
        q.receipt.set("native_scheduling", scheduling.clone());
        let work_text = |relative: &str| sp::text(&q.work.join(relative));
        let updates = [
            ("CI", "1".to_owned()),
            ("RUSTUP_TOOLCHAIN", "1.98.0".to_owned()),
            ("CARGO_TARGET_DIR", work_text("target")),
            ("RUSTC_WRAPPER", String::new()),
            ("RUSTC_WORKSPACE_WRAPPER", String::new()),
            // Every job starts from an empty target directory, so incremental
            // query caches are written and never read; release is already
            // non-incremental.
            ("CARGO_INCREMENTAL", "0".to_owned()),
            ("CARGO_PROFILE_DEV_DEBUG", "0".to_owned()),
            ("CARGO_PROFILE_TEST_DEBUG", "0".to_owned()),
            (
                "CARGO_BUILD_JOBS",
                crate::py::str(scheduling.at("build_jobs")),
            ),
            ("CARGO_TERM_COLOR", "never".to_owned()),
            ("TMPDIR", work_text("tmp")),
            ("BUSBAR_TEST_TMP_ROOT", work_text("tmp/tests")),
            ("MODERNCI_CACHE_DIR", work_text("cache")),
            ("XDG_CACHE_HOME", work_text("cache")),
            ("PYTHONDONTWRITEBYTECODE", "1".to_owned()),
            ("CARGO_NET_GIT_FETCH_WITH_CLI", "true".to_owned()),
            ("GIT_TERMINAL_PROMPT", "0".to_owned()),
        ];
        for (key, value) in updates {
            q.env.set(key, value);
        }
        q.env.set("CI_SERVER_HOST", environ("CI_SERVER_HOST")?);
        // Evidence links name the real native job; these fields contain no credentials.
        for key in ["CI_JOB_URL", "CI_JOB_ID", "CI_PIPELINE_ID"] {
            if let Ok(value) = std::env::var(key) {
                q.env.set(key, value);
            }
        }
        // Runner umasks can permit group/world writes. Custody requires a
        // private temporary directory, independent of the checkout permissions.
        sp::mkdir(&q.work.join("tmp"), 0o700, false)?;
        q.save()?;
        Ok(q)
    }

    pub fn execution(&mut self) -> &mut Execution {
        self.execution.as_mut().expect("confined execution")
    }

    pub fn job_id(&self) -> String {
        self.receipt.at("job_id").as_str().unwrap_or("").to_owned()
    }

    pub fn source(&self) -> String {
        self.receipt.at("source").as_str().unwrap_or("").to_owned()
    }

    fn materialized(&self, value: &Value, step: Option<usize>) -> Value {
        let mut row = value.clone();
        if let (Some(step), Some(execution)) = (step, &self.execution) {
            for (s, o) in &self.containers {
                if *s == step
                    && let Some(observation) = execution.observations.get(*o)
                {
                    row.set("container", observation.clone());
                }
            }
        }
        row
    }

    /// The receipt as the former runner held it: container observations and
    /// the execution boundary's observation list are live references.
    fn rendered(&self) -> Value {
        let mut receipt = self.receipt.clone();
        if let Some(Value::Array(rows)) = receipt.get_mut("steps") {
            for (index, row) in rows.iter_mut().enumerate() {
                *row = self.materialized(row, Some(index));
            }
        }
        if let (Some(execution), Some(boundary)) =
            (&self.execution, receipt.get_mut("execution_boundary"))
        {
            boundary.set("observations", Value::Array(execution.observations.clone()));
        }
        receipt
    }

    pub fn save(&mut self) -> R<()> {
        if let Some(execution) = &self.execution
            && self.receipt.get("execution_boundary").is_some()
        {
            let configuration = confine::sha_canonical(&execution.config);
            let rows = &execution.observations;
            if rows
                .iter()
                .any(|row| row.at("configuration_sha256").as_str() != Some(configuration.as_str()))
            {
                return Err(violation(
                    "execution configuration differs from retained observations",
                ));
            }
            // Approval binds the original input bytes; observations bind the
            // canonical runtime after measured, protected instrument additions.
            let isolated = !rows.is_empty()
                && rows.iter().all(|row| {
                    row.at("inspected").truthy()
                        && row.at("disposed").truthy()
                        && row.at("storage").truthy()
                        && row.at("user_namespace").truthy()
                });
            let boundary = self.receipt.get_mut("execution_boundary").unwrap();
            boundary.set("configuration_sha256", configuration.into());
            boundary.set("isolated", isolated.into());
        }
        let text = json::dumps_indent(&self.rendered()) + "\n";
        sp::write(&self.evidence.join("receipt.json"), text)
    }

    /// `with q.preparation(name): body` — preparation cost kept apart from checks.
    pub fn preparation(&mut self, name: &str, body: impl FnOnce(&mut Q) -> R<()>) -> R<()> {
        let row = object([
            ("name", name.into()),
            ("started_at", now().into()),
            ("status", "running".into()),
        ]);
        if self.receipt.get("preparation").is_none() {
            self.receipt.set("preparation", Value::Array(Vec::new()));
        }
        let index = {
            let Some(Value::Array(rows)) = self.receipt.get_mut("preparation") else {
                unreachable!()
            };
            rows.push(row);
            rows.len() - 1
        };
        let started = Instant::now();
        self.save()?;
        self.print_preparation(index);
        let result = body(self);
        let status = if result.is_ok() { "pass" } else { "fail" };
        {
            let Some(Value::Array(rows)) = self.receipt.get_mut("preparation") else {
                unreachable!()
            };
            rows[index].set("status", status.into());
            rows[index].set("finished_at", now().into());
            rows[index].set(
                "elapsed_seconds",
                sp::round_float(started.elapsed().as_secs_f64(), 3),
            );
        }
        self.save()?;
        self.print_preparation(index);
        result
    }

    fn print_preparation(&self, index: usize) {
        let row = self.receipt.at("preparation").index(index).clone();
        println!(
            "{}",
            json::dumps(&object([("native_preparation", row)]), false)
        );
    }

    pub fn run(&mut self, name: &str, argv: Vec<String>) -> R<PathBuf> {
        self.step(name, argv, None, 3600, false)
    }
    pub fn run_in(&mut self, name: &str, argv: Vec<String>, cwd: &Path) -> R<PathBuf> {
        self.step(name, argv, Some(cwd), 3600, false)
    }
    pub fn run_timeout(&mut self, name: &str, argv: Vec<String>, timeout: u64) -> R<PathBuf> {
        self.step(name, argv, None, timeout, false)
    }
    pub fn run_controller(&mut self, name: &str, argv: Vec<String>) -> R<PathBuf> {
        self.step(name, argv, None, 3600, true)
    }
    pub fn run_controller_in(
        &mut self,
        name: &str,
        argv: Vec<String>,
        cwd: &Path,
        timeout: u64,
    ) -> R<PathBuf> {
        self.step(name, argv, Some(cwd), timeout, true)
    }

    fn row_mut(&mut self, index: usize) -> &mut Value {
        let Some(Value::Array(rows)) = self.receipt.get_mut("steps") else {
            unreachable!()
        };
        &mut rows[index]
    }

    /// `_run(name, argv, cwd, timeout, controller)`: one hashed, observed step.
    pub fn step(
        &mut self,
        name: &str,
        argv: Vec<String>,
        cwd: Option<&Path>,
        timeout: u64,
        controller: bool,
    ) -> R<PathBuf> {
        let confined = !controller && self.execution.is_some();
        let mut argv = argv;
        if confined && argv.len() >= 2 && argv[0] == "cargo" && argv[1] == "deny" {
            argv.insert(2, "--frozen".into());
        }
        if confined && argv.len() >= 2 && argv[0] == "cargo" && argv[1] == "vet" {
            argv.splice(2..2, ["--locked".to_owned(), "--frozen".to_owned()]);
        }
        let cwd = cwd.map(Path::to_owned).unwrap_or_else(|| self.root.clone());
        let row = object([
            ("name", name.into()),
            (
                "argv",
                Value::Array(argv.iter().map(|a| a.as_str().into()).collect()),
            ),
            ("status", "running".into()),
            ("started_at", now().into()),
            (
                "authority",
                if controller {
                    "controller"
                } else {
                    "candidate"
                }
                .into(),
            ),
        ]);
        let index = {
            let Some(Value::Array(rows)) = self.receipt.get_mut("steps") else {
                unreachable!()
            };
            rows.push(row);
            rows.len() - 1
        };
        self.save()?;
        let nextest = argv.len() >= 3 && argv[..3] == ["cargo", "nextest", "run"];
        let mut junit = PathBuf::new();
        if nextest {
            let mut locate = sp::strings(&[
                "cargo",
                "locate-project",
                "--workspace",
                "--message-format",
                "plain",
            ]);
            if let Some(i) = argv.iter().position(|a| a == "--manifest-path") {
                locate.push("--manifest-path".into());
                locate.push(argv.get(i + 1).cloned().unwrap_or_default());
            }
            let env = self.env.clone();
            let located = if confined {
                self.execution().check_output(&locate, &cwd, &env)?
            } else {
                String::from_utf8_lossy(&sp::check_output(
                    Spec::new(locate).env(&env.pairs()).cwd(&cwd),
                )?)
                .into_owned()
            };
            let workspace = PathBuf::from(located.trim())
                .parent()
                .map(Path::to_owned)
                .unwrap_or_default();
            if confined && !(workspace.starts_with(&self.root) || workspace.starts_with(&self.work))
            {
                return Err(violation(
                    "candidate workspace report escapes writable output roots",
                ));
            }
            // Nextest's default store is workspace-relative, independent of
            // Cargo's target-dir. The distribution workspace has its own report.
            junit = workspace.join("target/nextest/default/native.xml");
            if confined
                && (sp::is_symlink(&junit)
                    || !sp::resolve(&junit).starts_with(sp::resolve(&workspace)))
            {
                return Err(violation("indirect candidate report path"));
            }
            match std::fs::remove_file(&junit) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(sp::os_error(&e, Some(&junit)));
                }
                _ => {}
            }
        }
        let stdout_path = self.evidence.join(format!("{name}.stdout"));
        let stderr_path = self.evidence.join(format!("{name}.stderr"));
        let out = File::create(&stdout_path).at(&stdout_path)?;
        let err = File::create(&stderr_path).at(&stderr_path)?;
        let mut child = None;
        let mut invocation = None;
        let mut command_argv = argv.clone();
        let setup = sp::deferred(|| {
            let mut environment = self.env.clone();
            if let Some(scheduling) = self.receipt.get("native_scheduling").cloned()
                && environment.contains("CARGO_BUILD_JOBS")
            {
                let jobs = step_build_jobs(name, &argv, &scheduling);
                environment.set("CARGO_BUILD_JOBS", crate::py::str(&jobs));
                self.row_mut(index).set("build_jobs", jobs);
            }
            let mut command = argv.clone();
            let mut env_pairs = environment.pairs();
            if confined {
                let entered = self
                    .execution()
                    .invocation(&argv, &cwd, &environment, false)?;
                command = entered.command.clone();
                env_pairs = self.execution().client_env.clone();
                self.row_mut(index).set("container", Value::Null);
                self.containers.push((index, entered.observation));
                invocation = Some(entered);
            } else if controller && let Some(execution) = &self.execution {
                let mut env = self.env.clone();
                env.set("DOCKER_HOST", execution.docker_host());
                env_pairs = env.pairs();
            }
            command_argv = command.clone();
            let mut spec = Spec::new(command).env(&env_pairs).cwd(&cwd);
            spec.stdout = sp::Output::File(out.try_clone().at(&stdout_path)?);
            spec.stderr = sp::Output::File(err.try_clone().at(&stderr_path)?);
            spec.new_session = true;
            child = Some(sp::spawn(&mut spec)?);
            Ok(())
        });
        drop(out);
        drop(err);
        let mut result: R<i32> = match setup {
            Err(error) => Err(error),
            Ok(()) => {
                let container = invocation
                    .as_ref()
                    .and_then(|i| {
                        self.execution
                            .as_ref()
                            .map(|e| e.observations[i.observation].clone())
                    })
                    .and_then(|o| {
                        o.get("container_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    });
                let mut observer = resources::StepObserver::new(name, container.as_deref());
                let waited = resources::wait_observed(
                    child.as_mut().unwrap(),
                    &command_argv,
                    timeout,
                    &mut observer,
                );
                self.row_mut(index).set("resources", observer.summary());
                waited
            }
        };
        if let Err(error) = &result {
            match error.kind {
                Kind::Timeout => {
                    let row = self.row_mut(index);
                    row.set("status", "timeout".into());
                    row.set("finished_at", now().into());
                    if let Err(saved) = self.save() {
                        result = Err(saved);
                    }
                }
                Kind::Interrupted => {
                    let signal = error.signal;
                    self.mark_interrupted(index, signal);
                    if let Err(saved) = self.save() {
                        result = Err(saved);
                    }
                }
                _ => {}
            }
        }
        // TERM gives nested conformance supervisors time to reap their own
        // independent sessions; KILL remains bounded for unresponsive commands.
        if let Some(process) = child.as_mut() {
            match sp::stop_process_group(process, Duration::from_secs(10)) {
                Ok(_) => {}
                Err(error) if error.kind == Kind::Interrupted => {
                    self.mark_interrupted(index, error.signal);
                    result = Err(error);
                    if let Err(saved) = self.save() {
                        result = Err(saved);
                    }
                }
                Err(error) => result = Err(error),
            }
        }
        if let Some(entered) = invocation.take() {
            let execution = self.execution.as_mut().unwrap();
            if let Err(error) = sp::deferred(|| execution.dispose(entered)) {
                result = Err(error);
            }
        }
        let code = result?;
        let row = self.row_mut(index);
        row.set("status", if code == 0 { "pass" } else { "fail" }.into());
        row.set("exit_code", Value::int(code));
        row.set("finished_at", now().into());
        let stdout_sha = digest(&stdout_path)?;
        let stderr_sha = digest(&stderr_path)?;
        let row = self.row_mut(index);
        row.set("stdout_sha256", stdout_sha.into());
        row.set("stderr_sha256", stderr_sha.into());
        if nextest && code == 0 {
            if !junit.is_file() {
                return Err(violation(
                    "nextest did not produce its current machine-readable report",
                ));
            }
            let collected = self.collect_output(
                &junit,
                &self.evidence.join(format!("{name}.xml")),
                64 << 20,
                false,
            )?;
            let sha = digest(&collected)?;
            self.row_mut(index).set("junit_sha256", sha.into());
            if let Err(error) = junit::validate_test_report(&collected) {
                let row = self.row_mut(index);
                row.set("status", "fail".into());
                row.set("exit_code", Value::int(1));
                self.save()?;
                return Err(error);
            }
        }
        self.save()?;
        let rendered = self.materialized(self.receipt.at("steps").index(index), Some(index));
        println!("{}", json::dumps(&rendered, false));
        if code != 0 {
            return Err(violation(format!("{name} failed; no automatic retry")));
        }
        Ok(stdout_path)
    }

    fn mark_interrupted(&mut self, index: usize, signal: i32) {
        let row = self.row_mut(index);
        row.set("status", "interrupted".into());
        row.set("signal", Value::int(signal));
        row.set("finished_at", now().into());
    }

    /// `candidate_output(q, source, limit)`: open each component without
    /// following links, even during rename races, and refuse mutation.
    pub fn with_candidate_output<T>(
        &self,
        source: &Path,
        limit: u64,
        compiler_output: bool,
        body: impl FnOnce(&mut File, &std::fs::Metadata) -> R<T>,
    ) -> R<T> {
        let root = sp::resolve(&self.root);
        let roots = [
            root.join("target"),
            root.join("dist/default/target"),
            sp::resolve(&self.work),
        ];
        if !source.is_absolute()
            || source != sp::abspath(source)
            || !roots.iter().any(|r| source.starts_with(r))
        {
            return Err(violation("collected output escapes candidate build roots"));
        }
        let mut descriptors = Vec::new();
        let outcome = (|| -> R<T> {
            use std::os::fd::FromRawFd;
            let mut parent = sp::openat(
                sp::AT_FDCWD,
                std::ffi::OsStr::new("/"),
                sp::flags::O_DIRECTORY,
            )?;
            descriptors.push(parent);
            let parts: Vec<_> = source
                .components()
                .skip(1)
                .map(|c| c.as_os_str().to_owned())
                .collect();
            let (name, directories) = parts
                .split_last()
                .ok_or_else(|| violation("collected output escapes candidate build roots"))?;
            for part in directories {
                parent = sp::openat(parent, part, sp::flags::O_DIRECTORY | sp::flags::O_NOFOLLOW)?;
                descriptors.push(parent);
            }
            let fd = sp::openat(parent, name, sp::flags::O_NOFOLLOW | sp::O_NONBLOCK)?;
            let mut stream = unsafe { File::from_raw_fd(fd) };
            let before = stream.metadata().map_err(|e| sp::os_error(&e, None))?;
            let owner = match &self.execution {
                Some(execution) => execution.mapped_uid() as u32,
                None => crate::proc::euid(),
            };
            let linked = compiler_output && before.uid() == owner && before.nlink() > 0;
            if !before.file_type().is_file()
                || before.len() > limit
                || (before.nlink() != 1 && !linked)
            {
                return Err(violation(
                    "candidate output is nonregular, linked or exceeds limit",
                ));
            }
            let value = body(&mut stream, &before)?;
            let after = stream.metadata().map_err(|e| sp::os_error(&e, None))?;
            let fields = |m: &std::fs::Metadata| {
                (
                    m.len(),
                    m.mtime(),
                    m.mtime_nsec(),
                    m.ctime(),
                    m.ctime_nsec(),
                    m.nlink(),
                )
            };
            if fields(&before) != fields(&after) {
                return Err(violation("candidate output changed during collection"));
            }
            Ok(value)
        })();
        for fd in descriptors.into_iter().rev() {
            sp::close(fd);
        }
        outcome.map_err(|error| {
            if error.kind == Kind::Os {
                violation(format!(
                    "missing or indirect candidate output: {}",
                    error.message
                ))
            } else {
                error
            }
        })
    }

    /// `collect_output(q, source, destination, limit)`: copy one regular
    /// candidate output after execution has ended; never follow links.
    pub fn collect_output(
        &mut self,
        source: &Path,
        destination: &Path,
        limit: u64,
        compiler_output: bool,
    ) -> R<PathBuf> {
        use std::io::{Read, Write};
        let mut created = false;
        let copied =
            self.with_candidate_output(source, limit, compiler_output, |stream, before| {
                let mut output = sp::create_new(destination)?;
                created = true;
                let mut remaining = limit as i128;
                let mut buffer = vec![0u8; 1 << 20];
                loop {
                    let want = (remaining + 1).min(1 << 20) as usize;
                    let n = stream
                        .read(&mut buffer[..want])
                        .map_err(|e| sp::os_error(&e, None))?;
                    if n == 0 {
                        break;
                    }
                    remaining -= n as i128;
                    if remaining < 0 {
                        return Err(violation("candidate output grew beyond limit"));
                    }
                    output
                        .write_all(&buffer[..n])
                        .map_err(|e| sp::os_error(&e, None))?;
                }
                if limit as i128 - remaining != before.len() as i128 {
                    return Err(violation("candidate output changed during collection"));
                }
                Ok((before.len(), before.nlink()))
            });
        let (bytes, links) = match copied {
            Ok(value) => value,
            Err(error) => {
                if created {
                    let _ = std::fs::remove_file(destination);
                }
                return Err(error);
            }
        };
        let row = object([
            ("source", sp::text(source).into()),
            ("destination", sp::text(destination).into()),
            ("sha256", digest(destination)?.into()),
            ("bytes", bytes.into()),
            ("regular_file", true.into()),
            ("single_link", true.into()),
            ("source_link_count", links.into()),
            ("compiler_output", compiler_output.into()),
            ("mutation_checked", true.into()),
        ]);
        if self.receipt.get("collected_outputs").is_none() {
            self.receipt
                .set("collected_outputs", Value::Array(Vec::new()));
        }
        if let Some(Value::Array(rows)) = self.receipt.get_mut("collected_outputs") {
            rows.push(row);
        }
        Ok(destination.to_owned())
    }

    pub fn host(&mut self) -> R<PathBuf> {
        if let Some(host) = &self.host {
            return Ok(host.clone());
        }
        let host = if self.repository == CORE {
            self.root.clone()
        } else {
            // Owner-controlled cohort input during an SDK cutover; ordinary
            // candidates cannot supply pipeline variable overrides.
            let revision =
                std::env::var("BUSBAR_ADMISSION_CORE_REVISION").unwrap_or_else(|_| "dev".into());
            let host = checkout(CORE, &revision, &self.work.join("host"))?;
            if self.repository != "GetBusbar/busbar-release" {
                let reference = sp::read_text(&self.root.join(".busbar-ref"))?;
                let sdk = reference
                    .split_whitespace()
                    .next()
                    .ok_or_else(|| sp::Error::new(Kind::Value, "list index out of range"))?
                    .to_owned();
                let pins = sp::read_json(&host.join("scripts/ci-product-pins.json"))?;
                if at(&pins, "sdk")?.as_str() != Some(sdk.as_str()) {
                    return Err(violation(
                        "assembled host and plugin SDK differ; submit a coherent cohort",
                    ));
                }
            }
            host
        };
        let revision = git(&host, &["rev-parse", "HEAD"])?;
        self.receipt.set("host_revision", revision.as_str().into());
        self.env.set("BUSBAR_CHECKOUT", sp::text(&host));
        self.env.set("BUSBAR_ADMISSION_CORE_REVISION", revision);
        self.save()?;
        self.host = Some(host.clone());
        Ok(host)
    }

    pub fn pins(&mut self) -> R<Value> {
        let host = self.host()?;
        sp::read_json(&host.join("scripts/ci-product-pins.json"))
    }

    pub fn sdk(&mut self) -> R<PathBuf> {
        if let Some(sdk) = &self.sdk_checkout {
            return Ok(sdk.clone());
        }
        let pin = sp::at_str(&self.pins()?, "sdk")?.to_owned();
        let sdk = checkout(CORE, &pin, &self.work.join("sdk"))?;
        self.receipt.set("sdk_revision", pin.into());
        self.save()?;
        self.sdk_checkout = Some(sdk.clone());
        Ok(sdk)
    }

    /// The digest-verified busbar-ci binary the bootstrap runs this step runner
    /// from (`BUSBAR_CI_CONTROLLER`): never a candidate path, and this process.
    pub fn controller(&self) -> R<String> {
        let value = std::env::var("BUSBAR_CI_CONTROLLER").unwrap_or_default();
        let path = Path::new(&value);
        let executable = std::fs::metadata(path).is_ok_and(|m| m.mode() & 0o111 != 0);
        let resolved = sp::resolve(path);
        let this = std::env::current_exe()
            .ok()
            .and_then(|exe| std::fs::metadata(exe).ok());
        let same = std::fs::metadata(path)
            .ok()
            .zip(this)
            .is_some_and(|(a, b)| (a.dev(), a.ino()) == (b.dev(), b.ino()));
        if value.is_empty()
            || !path.is_absolute()
            || sp::is_symlink(path)
            || !path.is_file()
            || !executable
            || !same
            || [&self.root, &self.work]
                .iter()
                .any(|root| resolved.starts_with(root))
        {
            return Err(violation("verified busbar-ci controller is unavailable"));
        }
        Ok(value)
    }

    /// The architecture step: this controller's `architecture` command.
    pub fn architecture(&mut self, sdk: Option<&Path>) -> R<()> {
        self.architecture_with(sdk, None)
    }

    pub fn architecture_with(&mut self, sdk: Option<&Path>, units: Option<&Path>) -> R<()> {
        let scratch = self.harness.join("architecture");
        let controller = self.controller()?;
        let (context, expected) = self.execution().write_context()?;
        let command = architecture_command(
            &controller,
            &self.trusted,
            &self.trusted.join("ci/architecture.toml"),
            &self.repository,
            &self.root,
            &scratch,
            &self.evidence.join("architecture.json"),
            sdk,
            Some((&context, &expected)),
        );
        let mut command = command;
        if let Some(units) = units {
            command.extend(["--dependency-units".into(), sp::text(units)]);
        }
        self.run_controller("architecture", command)?;
        let observed = sp::read_json(&self.evidence.join("architecture.json"))?;
        let rows = at(&observed, "candidate_execution")?
            .as_array()
            .unwrap_or(&[])
            .to_vec();
        self.execution().observations.extend(rows);
        self.save()
    }

    /// Fixed controller tests need neither subject dependencies nor witnesses.
    /// The controller's own suite runs first so a broken controller fails fast.
    /// It builds and runs inside the pinned toolchain image (offline, no
    /// network, trusted source read-only), before any candidate command, into
    /// a fresh target directory; the controller host needs no Rust toolchain.
    pub fn core_regressions(&mut self) -> R<()> {
        let trusted = self.trusted.clone();
        let target = self
            .work
            .join(format!("controller-tests-{}", sp::uuid_hex()));
        self.run_in(
            "architecture-regressions",
            controller_regressions(&trusted, &target),
            &trusted,
        )?;
        for (name, argv) in pysteps::regressions(&trusted) {
            self.run_controller_in(name, argv, &trusted, 3600)?;
        }
        Ok(())
    }

    pub fn core_formatting(&mut self) -> R<()> {
        self.run(
            "root-fmt",
            sp::strings(&["cargo", "fmt", "--all", "--check"]),
        )?;
        self.run(
            "default-fmt",
            sp::strings(&[
                "cargo",
                "fmt",
                "--manifest-path",
                "dist/default/Cargo.toml",
                "--all",
                "--check",
            ]),
        )?;
        Ok(())
    }

    pub fn core_compilation(&mut self) -> R<()> {
        for (name, command) in CORE_LINT_COMMANDS {
            self.run(name, sp::strings(command))?;
        }
        Ok(())
    }

    pub fn core(&mut self) -> R<()> {
        if dependency_units_producer(&self.repository) {
            return self.preparation("dependency-units-producer", depcache::produce);
        }
        self.core_compilation()?;
        self.architecture(None)?;
        let host = self.host()?;
        let sdk = sp::at_str(&self.pins()?, "sdk")?.to_owned();
        self.sdk()?;
        // A local assembly patch must not hide SDK source drift behind an old pin.
        self.run(
            "sdk-source-identity",
            sp::strings(&[
                "git",
                "diff",
                "--exit-code",
                &sdk,
                "HEAD",
                "--",
                "crates/busbar-contract/src",
                "crates/busbar-contract/include",
                "crates/busbar-contract/Cargo.toml",
            ]),
        )?;
        self.receipt.set("sdk_revision", sdk.as_str().into());
        let services = fixtures::Services::open(self, &host)?;
        let body = self.core_services(&host, &sdk);
        let closed = services.close(self);
        closed.and(body)
    }

    fn core_services(&mut self, host: &Path, sdk: &str) -> R<()> {
        let trusted = self.trusted.clone();
        let envfile = self.run(
            "product-inputs",
            vec![
                "bash".into(),
                sp::text(&trusted.join("scripts/ci-product-inputs.sh")),
            ],
        )?;
        let pins_path = host.join("scripts/ci-product-pins.json");
        let vector = sp::read_json(&pins_path)?;
        let host_revision = self
            .receipt
            .at("host_revision")
            .as_str()
            .unwrap_or("")
            .to_owned();
        let inputs = product::load_product_inputs(
            &envfile,
            &self.work,
            &self.policy,
            &vector,
            &host_revision,
        )?;
        self.execution().product_inputs = inputs.clone();
        self.env.update(&inputs);
        let mut sizes = Vec::new();
        for (key, value) in &self.env.0 {
            if key.starts_with("BUSBAR_")
                && (key.ends_with("_CDYLIB") || key.ends_with("_PLUGIN"))
                && Path::new(value).is_file()
            {
                let size = std::fs::metadata(value).at(Path::new(value))?.len();
                sizes.push((key.clone(), Value::from(size)));
            }
        }
        self.receipt
            .set("product_input_bytes", Value::Object(sizes));
        self.save()?;
        let vector = sp::read_json(&pins_path)?;
        let witness = at(&vector, "c_witness")?;
        if at(witness, "sdk")? != at(&vector, "sdk")? {
            return Err(violation("C witness and assembled SDK pins differ"));
        }
        let witness_repo = format!("GetBusbar/{}", sp::at_str(witness, "repo")?);
        let witness_commit = sp::at_str(witness, "commit")?.to_owned();
        let c_source = checkout(&witness_repo, &witness_commit, &self.work.join("c-witness"))?;
        let recipe = product::load_c_recipe(
            &self.policy,
            &witness_repo,
            &c_source,
            Some(&witness_commit),
        )?;
        let library = self.work.join(if cfg!(target_os = "macos") {
            "c-witness.dylib"
        } else {
            "c-witness.so"
        });
        let header = Path::new(product::PUBLIC_C_HEADER)
            .parent()
            .unwrap_or(Path::new(""));
        let mut build = sp::strings(&[
            "cc",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-shared",
            "-fPIC",
            "-fvisibility=hidden",
            "-I",
        ]);
        build.push(sp::text(&host.join(header)));
        for source in recipe.at("sources").as_array().unwrap_or(&[]) {
            build.push(sp::text(&c_source.join(source.as_str().unwrap_or(""))));
        }
        build.push("-o".into());
        build.push(sp::text(&library));
        self.run("c-witness-build", build)?;
        self.env.set(
            "BUSBAR_C_ABI_SOURCES",
            sp::text(&c_source.join(recipe.at("test-root").as_str().unwrap_or(""))),
        );
        self.env.set("BUSBAR_C_ABI_LIBRARY", sp::text(&library));
        let threads = crate::py::str(self.receipt.at("native_scheduling").at("test_threads"));
        let nextest_config = format!(
            "admission:{}",
            sp::text(&trusted.join("ci/native-nextest.toml"))
        );
        let nextest: Vec<String> = vec![
            "--no-fail-fast".into(),
            "--test-threads".into(),
            threads,
            "--tool-config-file".into(),
            nextest_config,
        ];
        let selected = "binary(mcp_stdio_serve) | binary(hook_parity_driver) | (package(busbar-default) & test(/^distribution::admin_cross_plane::/)) | (package(busbar-default) & test(/(serve_tests|secret_source|connector|boot)::/))";
        let features = "test-harness,transport-webrtc,openapi-schema";
        let final_build = sp::strings(&[
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--bin",
            "busbar",
        ]);
        let build_capture = self.work.join("final-build-capture");
        let with = |base: &[&str], tail: &[String]| {
            let mut argv = sp::strings(base);
            argv.extend(tail.iter().cloned());
            argv
        };
        let commands: Vec<(&str, Vec<String>)> = vec![
            (
                "workspace-doctests",
                sp::strings(&[
                    "cargo",
                    "test",
                    "--workspace",
                    "--doc",
                    "--locked",
                    "--no-fail-fast",
                ]),
            ),
            (
                "loader-witnesses",
                sp::strings(&[
                    "cargo",
                    "build",
                    "--locked",
                    "-p",
                    "busbar-plugin-loader",
                    "--examples",
                ]),
            ),
            (
                "root-runtime",
                with(
                    &["cargo", "nextest", "run", "--workspace", "--locked"],
                    &nextest,
                ),
            ),
            (
                "default-runtime",
                with(
                    &[
                        "cargo",
                        "nextest",
                        "run",
                        "--locked",
                        "--manifest-path",
                        "dist/default/Cargo.toml",
                        "--workspace",
                    ],
                    &nextest,
                ),
            ),
            (
                "selected-default",
                with(
                    &[
                        "cargo",
                        "nextest",
                        "run",
                        "--locked",
                        "--manifest-path",
                        "dist/default/Cargo.toml",
                        "--features",
                        features,
                        "-E",
                        selected,
                    ],
                    &nextest,
                ),
            ),
            (
                "selected-errors",
                with(
                    &[
                        "cargo",
                        "nextest",
                        "run",
                        "--locked",
                        "--manifest-path",
                        "dist/default/Cargo.toml",
                        "--features",
                        features,
                        "-E",
                        "test(keys_error_surface_is_byte_stable) | test(every_admin_error_surface_answers_its_declared_status)",
                    ],
                    &nextest,
                ),
            ),
            (
                "timing-admin",
                with(
                    &[
                        "cargo",
                        "nextest",
                        "run",
                        "--locked",
                        "-p",
                        "busbar-kernel",
                        "-p",
                        "busbar-core-admin",
                        "--features",
                        "busbar-kernel/timing,busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema",
                        "-E",
                        "binary(timing_smoke) | package(busbar-core-admin) | (package(busbar-kernel) & test(/timing::/))",
                    ],
                    &nextest,
                ),
            ),
            (
                "bounded-loom",
                sp::strings(&[
                    "cargo",
                    "test",
                    "--release",
                    "--locked",
                    "-p",
                    "busbar-kernel",
                    "--features",
                    "loom-model",
                    // The txn_loom models are kernel library unit tests; `--lib`
                    // runs the same two tests without 27 fat-LTO integration
                    // test links that matched none (see native.py).
                    "--lib",
                    "txn_loom",
                ]),
            ),
            (
                "dependency-policy",
                sp::strings(&["cargo", "deny", "check"]),
            ),
            ("dependency-vet", sp::strings(&["cargo", "vet"])),
            (
                "default-dependency-policy",
                sp::strings(&[
                    "cargo",
                    "deny",
                    "--manifest-path",
                    "dist/default/Cargo.toml",
                    "check",
                ]),
            ),
            (
                "final-binary",
                pysteps::development_artifact_capture(&trusted, &build_capture, &final_build),
            ),
        ];
        for (name, command) in commands {
            self.run(name, command)?;
        }
        self.run_in(
            "default-dependency-vet",
            sp::strings(&["cargo", "vet"]),
            &host.join("dist/default"),
        )?;
        let binary =
            PathBuf::from(self.env.get("CARGO_TARGET_DIR").unwrap_or("")).join("release/busbar");
        let collected =
            self.collect_output(&binary, &self.evidence.join("busbar"), 2 << 30, true)?;
        self.receipt
            .set("binary_sha256", digest(&collected)?.into());
        let artifact_evidence = self.evidence.join("development-artifact");
        sp::mkdirs(&artifact_evidence.join("build"), false)?;
        for name in [
            "cargo-metadata.json",
            "Cargo.lock",
            "cargo-messages.jsonl",
            "build-context.json",
        ] {
            self.collect_output(
                &build_capture.join(name),
                &artifact_evidence.join("build").join(name),
                64 << 20,
                false,
            )?;
        }
        let source = self.source();
        let policy = self
            .receipt
            .at("policy_revision")
            .as_str()
            .unwrap_or("")
            .to_owned();
        let finalize = pysteps::development_artifact_finalize(
            &trusted,
            &artifact_evidence,
            &collected,
            &source,
            &policy,
            sdk,
            &pins_path,
            &binary,
            &json::dumps(
                &Value::Array(final_build.iter().map(|a| a.as_str().into()).collect()),
                false,
            ),
            &digest(&trusted.join("ci/architecture-pipeline.yml"))?,
        );
        self.run_controller("development-artifact-evidence", finalize)?;
        self.receipt.set(
            "development_artifact",
            object([
                ("path", "development-artifact/receipt.json".into()),
                (
                    "sha256",
                    digest(&artifact_evidence.join("receipt.json"))?.into(),
                ),
                ("signed", false.into()),
                ("release_eligible", false.into()),
                ("supported_lifetime_retention_verified", false.into()),
            ]),
        );
        self.receipt
            .set("dependency_vector", sp::read_json(&pins_path)?);
        self.receipt
            .set("root_lock_sha256", digest(&host.join("Cargo.lock"))?.into());
        self.receipt.set(
            "distribution_lock_sha256",
            digest(&host.join("dist/default/Cargo.lock"))?.into(),
        );
        self.env.set("BUSBAR_BIN", sp::text(&binary));
        // Section 15 qualifies the native product and its boundary. Core's
        // separate certification launcher includes the unimplemented ModernCI
        // attestation producer; this cutover does not commission that project.
        Ok(())
    }

    pub fn plugin(&mut self) -> R<()> {
        let host = self.host()?;
        let reference = sp::read_text(&self.root.join(".busbar-ref"))?;
        let sdk_pin = reference
            .split_whitespace()
            .next()
            .ok_or_else(|| sp::Error::new(Kind::Value, "list index out of range"))?
            .to_owned();
        let sdk = self.sdk()?;
        self.receipt.set("sdk_revision", sdk_pin.into());
        let mut units = None;
        self.preparation("dependency-units", |q| {
            units = depcache::restore(q, None)?;
            depcache::install_job_target(q, units.as_deref())
        })?;
        let architecture = self.architecture_with(Some(&sdk), units.as_deref());
        depcache::discard(units.as_deref());
        architecture?;
        let services = fixtures::Services::open(self, &host)?;
        let body = plugins::qualify_plugin(self, &host, &sdk);
        let closed = services.close(self);
        closed.and(body)?;
        depcache::account(self)
    }

    /// `conformance(name)`: the owner roster under the protected inventory.
    pub fn conformance(&mut self, name: &str) -> R<()> {
        let required = conformance_rows(&self.repository, &self.policy, &self.trusted)?;
        validate_conformance_roster(&self.root, &required)?;
        if !required.is_empty() {
            let mut names: Vec<&str> = required.iter().map(|(n, _)| n.as_str()).collect();
            names.sort();
            self.receipt.set(
                "required_conformance_suites",
                Value::Array(names.into_iter().map(Value::from).collect()),
            );
        }
        if self
            .execution
            .as_ref()
            .is_some_and(|e| e.conformance_capabilities.is_none())
        {
            return Err(violation(
                "confined conformance requires controller-owned capability manifest",
            ));
        }
        let suites = self.root.join("testing/conformance/suites.tsv");
        let listed = suites.is_file()
            && sp::read_text(&suites)?
                .lines()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));
        if listed {
            for relative in [
                "testing/conformance/run.sh",
                "testing/conformance/capabilities.py",
            ] {
                let path = self.root.join(relative);
                if sp::is_symlink(&path)
                    || !path.is_file()
                    || digest(&path)? != digest(&self.trusted.join(relative))?
                {
                    return Err(violation(format!(
                        "confined conformance requires the published capability-aware controls: {relative}"
                    )));
                }
            }
            let command = vec![
                "bash".to_owned(),
                sp::text(&self.root.join("testing/conformance/run.sh")),
            ];
            let ran = self.run_timeout(name, command, 10800);
            // Failed and blocked evaluations are evidence too. Preserve their
            // actual verdicts without changing the command or job's failure.
            let copied = self.copy_conformance();
            copied?;
            ran?;
        }
        Ok(())
    }

    fn copy_conformance(&mut self) -> R<()> {
        let source = self.root.join("target/conformance");
        if sp::is_symlink(&source)
            || source.parent().is_some_and(sp::is_symlink)
            || !source.is_dir()
        {
            return Err(violation("missing conformance output"));
        }
        let destination = self.evidence.join("conformance");
        sp::mkdir(&destination, 0o777, true)?;
        let mut verdicts = sp::glob(&source.join("verdicts"), "*.json");
        sp::sort_paths(&mut verdicts);
        let mut relatives = vec!["invocation.json".to_owned()];
        relatives.extend(
            verdicts
                .iter()
                .map(|p| sp::text(p.strip_prefix(&source).unwrap_or(p))),
        );
        for relative in relatives {
            let path = source.join(&relative);
            if sp::is_symlink(&path) || path.parent().is_some_and(sp::is_symlink) || !path.is_file()
            {
                return Err(violation("missing or indirect conformance evidence"));
            }
            let out = destination.join(&relative);
            if let Some(parent) = out.parent() {
                sp::mkdir(parent, 0o777, true)?;
            }
            self.collect_output(&path, &out, 64 << 20, false)?;
        }
        // Preserve the external judge's diagnostic evidence, not its tool or
        // source trees, fixture credentials or candidate-selected paths.
        let patterns = [
            "h2/evidence/*.xml",
            "tls/evidence/*.json",
            "otlp/work/subject/traces.json",
            "otel-semconv-weaver/evidence/assessment.json",
            "otel-semconv-weaver/evidence/*-samples.json",
            "otel-semconv-weaver/evidence/*/live_check.json",
        ];
        let mut reports: Vec<PathBuf> =
            patterns.iter().flat_map(|p| sp::glob(&source, p)).collect();
        sp::sort_paths(&mut reports);
        reports.dedup();
        let mut total = 0usize;
        let mut retained: Vec<(String, Value)> = Vec::new();
        for path in reports {
            let (relative, payload) = self.bounded_report(&source, &path, &mut total)?;
            let out = destination.join(&relative);
            if let Some(parent) = out.parent() {
                sp::mkdirs(parent, true)?;
            }
            sp::write(&out, &payload)?;
            retained.push((sp::text(&relative), sha256::hex(&payload).into()));
        }
        // OIDF's raw exports and review HTML can carry generated credentials
        // and browser session tokens. Retain terminal results and page hashes.
        let record = source.join("oidf-run/record.json");
        if record.exists() || sp::is_symlink(&record) {
            let (_, payload) = self.bounded_report(&source, &record, &mut total)?;
            let raw = sp::loads(&payload)?;
            let mut summary = object([
                ("source_record_sha256", sha256::hex(&payload).into()),
                (
                    "scope",
                    "Terminal module outcomes and review page hashes; credential-bearing raw exports omitted".into(),
                ),
            ]);
            for leg in ["control", "negative", "subject"] {
                let Some(entry) = raw.get(leg).filter(|e| e.is_object()) else {
                    continue;
                };
                summary.set(leg, oidf_leg(entry)?);
            }
            let out = destination.join("oidf-module-results.json");
            sp::write(&out, crate::py::dumps_sorted_indent(&summary) + "\n")?;
            retained.push(("oidf-module-results.json".into(), digest(&out)?.into()));
        }
        self.receipt
            .set("conformance_diagnostics", Value::Object(retained));
        Ok(())
    }

    fn bounded_report(
        &self,
        source: &Path,
        path: &Path,
        total: &mut usize,
    ) -> R<(PathBuf, Vec<u8>)> {
        use std::io::Read;
        let relative = path.strip_prefix(source).unwrap_or(path).to_owned();
        // glob can traverse a symlink directory. Check every component
        // before reading anything, including the output root itself.
        let indirect = sp::self_and_parents(path)
            .iter()
            .filter(|p| *p == source || p.starts_with(source))
            .any(|p| sp::is_symlink(p));
        if indirect {
            return Err(violation("indirect conformance diagnostic evidence"));
        }
        let limit = 64u64 << 20;
        let payload = self.with_candidate_output(path, limit, false, |stream, before| {
            let mut payload = Vec::new();
            stream
                .take(limit + 1)
                .read_to_end(&mut payload)
                .map_err(|e| sp::os_error(&e, None))?;
            if payload.len() as u64 != before.len() {
                return Err(violation(
                    "conformance diagnostic changed during collection",
                ));
            }
            Ok(payload)
        })?;
        *total += payload.len();
        if payload.len() > 64 << 20 || *total > 256 << 20 {
            return Err(violation(
                "conformance diagnostic evidence exceeds its byte budget",
            ));
        }
        Ok((relative, payload))
    }

    /// `core_conformance()`: required core suites, retaining failures and
    /// release-input gaps.
    pub fn core_conformance(&mut self) -> R<()> {
        self.sdk()?;
        // The full applicable upstream mTLS signature roster contains
        // thousands of handshakes; the enclosing command keeps its 3 h bound.
        self.env.set("CONFORMANCE_TIMEOUT_SECONDS", "3600");
        let context = release::stage_context(&Dict::environ());
        self.receipt.set("conformance_stage", context.clone());
        let development = context.at("stage").as_str() == Some("dev");
        let mut failed = false;
        let mut engineering_report = self.evidence.join("release-engineering/result.json");
        match release::run_engineering(self) {
            Ok(report) => engineering_report = report,
            Err(error) if error.is_ordinary() => failed = true,
            Err(error) => return Err(error),
        }
        if let Err(conformance_error) = self.conformance("core-native-conformance") {
            let classified = (|| -> R<Value> {
                if conformance_error.message != "core-native-conformance failed; no automatic retry"
                {
                    return Err(conformance_error.clone());
                }
                if !development {
                    return Err(violation("release-stage conformance remains required"));
                }
                release::classify(self, &engineering_report)
            })();
            match classified {
                Ok(value) => self.receipt.set("development_conformance", value),
                Err(error) if error.is_ordinary() => {
                    self.receipt.set(
                        "development_conformance_error",
                        error.message.as_str().into(),
                    );
                    failed = true;
                }
                Err(error) => return Err(error),
            }
        }
        let out = self.work.join("sigstore");
        sp::mkdir(&out, 0o777, false)?;
        self.env.set("CONFORMANCE_OUT", sp::text(&out));
        // Coverage declares this artifact-readiness check at main. Development
        // records missing inputs honestly; supplied invalid evidence still fails.
        self.receipt.set(
            "sigstore_requirement",
            object([
                ("stage", context.at("stage").clone()),
                ("required_at", "main".into()),
                ("required", (!development).into()),
                ("missing_result", "not-run".into()),
            ]),
        );
        let command = pysteps::sigstore(&self.root, development);
        let observed = self.run("sigstore-release-evidence-observation", command);
        let destination = self.evidence.join("sigstore");
        let collected = (|| -> R<()> {
            sp::mkdir(&destination, 0o777, false)?;
            let mut paths: Vec<PathBuf> = std::fs::read_dir(&out)
                .at(&out)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .collect();
            sp::sort_paths(&mut paths);
            for path in paths {
                let name = path.file_name().unwrap_or_default().to_owned();
                self.collect_output(&path, &destination.join(name), 64 << 20, false)?;
            }
            Ok(())
        })();
        collected?;
        match observed {
            Ok(_) => {}
            Err(error) if error.kind == Kind::Violation => failed = true,
            Err(error) => return Err(error),
        }
        if failed {
            return Err(violation(
                "one or more conformance evaluations did not pass; inspect actual verdicts",
            ));
        }
        Ok(())
    }

    /// External judges need a fixed-destination confined network broker,
    /// which the protected confinement does not provide.
    pub fn external_endpoint_conformance(&mut self) -> R<()> {
        Err(violation(
            "external judges require a fixed-destination confined network broker",
        ))
    }

    pub fn finish(&mut self, status: &str, error: Option<&sp::Error>) -> R<()> {
        self.receipt.set("status", status.into());
        self.receipt.set("finished_at", now().into());
        if let Some(error) = error {
            self.receipt.set("error", error.message.as_str().into());
        }
        self.save()?;
        let destination = self.root.join("boundary-evidence");
        if destination.exists() || sp::is_symlink(&destination) {
            return Err(violation(
                "candidate supplied the evidence output directory",
            ));
        }
        sp::copytree(&self.evidence, &destination)
    }
}

/// The host's CPU count (`os.cpu_count()`), not the affinity-limited count.
fn host_cpu_count() -> Option<usize> {
    let text = std::fs::read_to_string("/sys/devices/system/cpu/online").ok()?;
    let mut count = 0;
    for range in text.trim().split(',') {
        match range.split_once('-') {
            Some((a, b)) => count += b.parse::<usize>().ok()? - a.parse::<usize>().ok()? + 1,
            None => {
                range.parse::<usize>().ok()?;
                count += 1;
            }
        }
    }
    (count > 0).then_some(count)
}

fn oidf_leg(entry: &Value) -> R<Value> {
    let identity = |t: &str| {
        (1..=240).contains(&t.chars().count())
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
    };
    let result = |t: &str| {
        t.chars().count() <= 40
            && t.chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c == '-')
    };
    let mut modules = Vec::new();
    for row in entry
        .get("modules")
        .and_then(Value::as_array)
        .unwrap_or(&[])
    {
        let ok = row.as_array().is_some_and(|r| {
            r.len() >= 3
                && r[0].as_str().is_some_and(identity)
                && r[1..3].iter().all(|v| v.as_str().is_some_and(result))
        });
        if !ok {
            return Err(violation("invalid OIDF terminal module identity/result"));
        }
        modules.push(Value::Array(row.as_array().unwrap()[..3].to_vec()));
    }
    let empty = Value::Object(Vec::new());
    let pages = entry.get("review_pages").unwrap_or(&empty);
    let pages_ok = pages.as_object().is_some_and(|rows| {
        rows.iter().all(|(name, hashes)| {
            identity(name)
                && hashes.as_array().is_some_and(|h| {
                    h.iter().all(|v| {
                        v.as_str().is_some_and(|t| {
                            t.len() == 64
                                && t.bytes()
                                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                        })
                    })
                })
        })
    });
    if !pages_ok {
        return Err(violation("invalid OIDF review page identity"));
    }
    let mut safe = object([
        ("modules", Value::Array(modules)),
        ("review_pages", pages.clone()),
    ]);
    if let Some(ok) = entry.get("ok").filter(|v| v.as_bool().is_some()) {
        safe.set("ok", ok.clone());
    }
    if let Some(exit) = entry.get("exit").filter(|v| v.is_int()) {
        safe.set("exit", exit.clone());
    }
    Ok(safe)
}

/// `conformance_rows(repository, policy, trusted)`: the approved coverage inventory.
pub fn conformance_rows(
    repository: &str,
    policy: &Value,
    trusted: &Path,
) -> R<Vec<(String, Value)>> {
    if !native_settings(repository, policy)?
        .at("required_conformance")
        .truthy()
    {
        return Ok(Vec::new());
    }
    let coverage = sp::read_json(&trusted.join("conformance/ci-coverage.json"))?;
    need(
        coverage.at("schema").as_str() == Some("busbar.conformance.ci-coverage/1"),
        "required conformance coverage schema differs",
    )?;
    let rows: Vec<(String, Value)> = at(&coverage, "suites")?
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, row)| row.at("repo").as_str() == Some(repository))
        .map(|(n, r)| (n.clone(), r.clone()))
        .collect();
    need(
        !rows.is_empty()
            && rows
                .iter()
                .all(|(_, row)| row.at("command").as_str().is_some_and(|c| !c.is_empty())),
        "required owner has no complete protected conformance inventory",
    )?;
    Ok(rows)
}

pub fn validate_conformance_roster(root: &Path, rows: &[(String, Value)]) -> R<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let roster = product::regular_under(&root.join("testing/conformance/suites.tsv"), root)?;
    let mut actual: Vec<(String, String)> = Vec::new();
    for line in sp::read_text(&roster)?.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.splitn(2, '\t').collect();
        if fields.len() != 2 || actual.iter().any(|(n, _)| n == fields[0]) {
            return Err(violation(
                "invalid or duplicate required conformance roster entry",
            ));
        }
        actual.push((fields[0].to_owned(), fields[1].to_owned()));
    }
    let differs = rows.iter().any(|(name, row)| {
        actual
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.as_str())
            != row.at("command").as_str()
    });
    need(
        !differs,
        "required conformance suite is missing or its command differs from protected coverage",
    )
}

fn source_checks(q: &mut Q) -> R<()> {
    if git(&q.root, &["rev-parse", "HEAD"])? != q.source() {
        return Err(violation("source revision changed during qualification"));
    }
    if !git(&q.root, &["diff", "HEAD", "--"])?.is_empty() {
        return Err(violation("tracked source changed during qualification"));
    }
    q.receipt.set("source_unchanged", true.into());
    let mut spec = Spec::new(sp::strings(&[
        "git",
        "-C",
        &sp::text(&q.root),
        "archive",
        "--format=tar",
        "HEAD",
    ]));
    spec.stdout = sp::Output::Capture;
    let mut child = sp::spawn(&mut spec)?;
    let mut hasher = sha256::Sha256::new();
    if let Some(mut stdout) = child.stdout.take() {
        use std::io::Read;
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            let n = stdout
                .read(&mut buffer)
                .map_err(|e| sp::os_error(&e, None))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
    }
    q.receipt.set("source_archive_sha256", hasher.hex().into());
    let status = child.wait().map_err(|e| sp::os_error(&e, None))?;
    if !status.success() {
        return Err(violation("could not bind the qualified source archive"));
    }
    Ok(())
}

/// Core's dependency-unit producer job (server-set job name; the bootstrap admits
/// only known job names) publishes plugin dependency units instead of qualifying.
pub fn dependency_units_producer(repository: &str) -> bool {
    repository == CORE
        && std::env::var("CI_JOB_NAME").is_ok_and(|j| depcache::producer_shard(&j).is_some())
}

fn body(args: &Args, slot: &mut Option<Q>) -> R<()> {
    *slot = Some(sp::deferred(|| Q::new(args))?);
    let q = slot.as_mut().unwrap();
    // Constructor validation establishes the immutable controller, exact
    // candidate and execution boundary before any regression command runs.
    let producer = dependency_units_producer(&q.repository);
    if q.repository == CORE && !q.evaluation_only && !producer {
        q.core_regressions()?;
        q.core_formatting()?;
    }
    if !producer && requires_native_oracle(&q.repository, args.external_conformance, &q.policy)? {
        q.preparation("oracle-inputs", oracle::prepare)?;
    }
    q.preparation("canonical-inputs", |q| {
        let host = q.host()?;
        sources::prepare(q, &host)
    })?;
    q.preparation("dependency-seed", seed::prepare)?;
    q.preparation("staged-fixtures", staged::collect_required)?;
    if args.conformance_capabilities.is_none() {
        q.preparation("conformance-capabilities", capabilities::prepare)?;
    }
    let mut evaluation_error = None;
    if args.external_conformance {
        if let Err(error) = q.external_endpoint_conformance() {
            if error.kind != Kind::Violation {
                return Err(error);
            }
            evaluation_error = Some(error);
        }
    } else if args.conformance_only {
        if let Err(error) = q.core_conformance() {
            if error.kind != Kind::Violation {
                return Err(error);
            }
            evaluation_error = Some(error);
        }
    } else if q.repository == CORE {
        q.core()?;
    } else if q.repository == "GetBusbar/busbar-release" {
        plugins::qualify_generator(q)?;
    } else if q.policy.at("repositories").get(&q.repository).is_some() {
        q.plugin()?;
    } else {
        return Err(violation("unclassified native project"));
    }
    source_checks(q)?;
    if let Some(error) = evaluation_error {
        return Err(error);
    }
    q.finish("pass", None)
}

pub fn qualify(args: &Args) -> R<()> {
    for key in [
        "CI_JOB_ID",
        "CI_PIPELINE_ID",
        "CI_PROJECT_PATH",
        "CI_CONFIG_REF_URI",
    ] {
        if std::env::var(key).map_or(true, |v| v.is_empty()) {
            return Err(violation(
                "full native qualification runs in GitLab CI only",
            ));
        }
    }
    let mut slot = None;
    let mut outcome = body(args, &mut slot);
    if let (Err(error), Some(q)) = (&outcome, slot.as_mut()) {
        let error = error.clone();
        outcome = Err(match q.finish("fail", Some(&error)) {
            Ok(()) => error,
            Err(finished) => finished,
        });
    }
    // Only the unique job workspace created by the trusted bootstrap is disposable.
    let work = match &slot {
        Some(q) => q.control.clone(),
        None => sp::resolve(&args.work),
    };
    let expected = format!(
        "boundary-{}-{}",
        environ("CI_PROJECT_ID")?,
        environ("CI_JOB_ID")?
    );
    if work
        .file_name()
        .is_some_and(|n| n.to_string_lossy() == expected)
    {
        sp::rmtree(&work)?;
    }
    outcome
}

/// `busbar-ci native-qualify ...`
pub fn main(args: &[String]) -> i32 {
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(message) if message.is_empty() => {
            println!("{USAGE}");
            return 0;
        }
        Err(message) => {
            eprintln!("{USAGE}\nbusbar-ci native-qualify: error: {message}");
            return 2;
        }
    };
    sp::install_interruptions();
    let outcome = qualify(&parsed);
    sp::restore_interruptions();
    match outcome {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("busbar-ci native-qualify: {}", error.message);
            1
        }
    }
}

/// `architecture-regressions`: the controller crate's own unit tests, built
/// offline from the trusted policy checkout's dependency-free `tools/ci`
/// (former Python controller suites, `unittest discover scripts/architecture`).
/// The trusted checkout stays read-only; the build lands in `target`.
pub fn controller_regressions(trusted: &Path, target: &Path) -> Vec<String> {
    vec![
        "cargo".into(),
        "test".into(),
        "--offline".into(),
        "--locked".into(),
        "--manifest-path".into(),
        sp::text(&trusted.join("tools/ci/Cargo.toml")),
        "--target-dir".into(),
        sp::text(target),
    ]
}

/// The architecture step argv (former `check.py`; `busbar-ci architecture`
/// keeps its CLI). argv[0] is the verified controller path.
#[allow(clippy::too_many_arguments)]
pub fn architecture_command(
    controller: &str,
    trusted: &Path,
    policy: &Path,
    repository: &str,
    checkout: &Path,
    scratch: &Path,
    output: &Path,
    sdk: Option<&Path>,
    context: Option<(&Path, &str)>,
) -> Vec<String> {
    let t = sp::text;
    let mut command = vec![
        controller.to_owned(),
        "architecture".into(),
        "--policy".into(),
        t(policy),
        "--repository".into(),
        repository.into(),
        "--checkout".into(),
        t(checkout),
        "--trusted".into(),
        t(trusted),
        "--scratch".into(),
        t(scratch),
        "--output".into(),
        t(output),
    ];
    if let Some(sdk) = sdk {
        command.extend(["--sdk".into(), t(sdk)]);
    }
    if let Some((path, digest)) = context {
        command.extend([
            "--execution-context".into(),
            t(path),
            "--execution-context-sha256".into(),
            digest.into(),
        ]);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduling_keeps_optimized_slot_budget() {
        let resources =
            crate::json::parse(br#"{"cpus": 4, "memory_bytes": 6442450944, "pids": 4096}"#)
                .unwrap();
        let scheduling = native_scheduling(32, Some(&resources));
        assert_eq!(
            json::dumps(&scheduling, false),
            "{\"build_jobs\": 1, \"test_threads\": 4, \"unoptimized_build_jobs\": 3, \"candidate_memory_bytes\": 6442450944, \"compiler_memory_bytes_per_slot\": 6442450944, \"unoptimized_compiler_memory_bytes_per_slot\": 2147483648, \"memory_policy\": \"conservative-slot-budget-not-measured-peak-or-fit-guarantee\"}"
        );
        let argv = sp::strings(&["cargo", "clippy"]);
        assert_eq!(
            step_build_jobs("root-clippy", &argv, &scheduling).as_int(),
            Some(3)
        );
        assert_eq!(
            step_build_jobs("final-binary", &argv, &scheduling).as_int(),
            Some(1)
        );
        let jobs = |name: &str, argv: &[&str]| {
            step_build_jobs(name, &sp::strings(argv), &scheduling).as_int()
        };
        assert_eq!(jobs("root-runtime", &["cargo", "nextest", "run"]), Some(3));
        assert_eq!(
            jobs(
                "product-inputs",
                &["bash", "/t/scripts/ci-product-inputs.sh"]
            ),
            Some(3)
        );
        assert_eq!(
            jobs(
                "core-native-conformance",
                &["bash", "/c/testing/conformance/run.sh"]
            ),
            Some(3)
        );
        for (name, argv) in [
            ("final-binary", &["python3", "x"][..]),
            ("product-inputs", &["bash", "x"]),
            (
                "product-inputs",
                &["bash", "-c", "/t/scripts/ci-product-inputs.sh"],
            ),
            ("core-native-conformance", &["bash", "/c/other.sh"]),
            (
                "plugin-conformance",
                &["bash", "/c/testing/conformance/run.sh"],
            ),
            (
                "plugin-runtime-prepare",
                &["bash", "-euo", "pipefail", "prepare.sh"],
            ),
            ("profiled", &["cargo", "build", "--profile", "dist"]),
            ("bounded-loom", &["cargo", "test", "--release"]),
            ("x", &["cargo", "test", "--release"]),
            ("other", &["cargo", "build", "--release"]),
        ] {
            assert_eq!(jobs(name, argv), Some(1), "{name}");
        }
        let legacy = crate::json::parse(br#"{"build_jobs": 1}"#).unwrap();
        assert_eq!(
            step_build_jobs("root-clippy", &[], &legacy).as_int(),
            Some(1)
        );
        let unconfined = native_scheduling(64, None);
        assert_eq!(unconfined.at("build_jobs").as_int(), Some(16));
        assert_eq!(unconfined.at("candidate_memory_bytes"), &Value::Null);
    }

    #[test]
    fn arguments_follow_argparse() {
        let args = parse_args(&sp::strings(&[
            "--trusted",
            "/t",
            "--checkout=/c",
            "--work",
            "/w",
            "--conformance-only",
        ]))
        .unwrap();
        assert_eq!(args.checkout, PathBuf::from("/c"));
        assert!(args.conformance_only);
        assert_eq!(
            parse_args(&sp::strings(&["--trusted", "/t"])).unwrap_err(),
            "the following arguments are required: --checkout, --work"
        );
        assert_eq!(
            parse_args(&sp::strings(&[
                "--trusted",
                "/t",
                "--checkout",
                "/c",
                "--work",
                "/w",
                "--conformance-only",
                "--external-conformance"
            ]))
            .unwrap_err(),
            "argument --external-conformance: not allowed with argument --conformance-only"
        );
        assert!(
            parse_args(&sp::strings(&["--conf", "x"]))
                .unwrap_err()
                .starts_with("ambiguous option")
        );
        assert_eq!(
            base64(b"gitlab-ci-token:abc"),
            "Z2l0bGFiLWNpLXRva2VuOmFiYw=="
        );
    }

    #[test]
    fn evaluation_jobs_are_exclusive() {
        let policy = crate::json::parse(br#"{"assembly": {"repository": "GetBusbar/busbar"}, "repositories": {"GetBusbar/x": {"native": {"external_conformance": "testing/conformance/x.sh"}}}}"#).unwrap();
        assert_eq!(
            evaluation_job(CORE, true, false, &policy).unwrap(),
            Some("core-conformance")
        );
        assert_eq!(
            evaluation_job("GetBusbar/x", false, true, &policy).unwrap(),
            Some("external-conformance")
        );
        assert_eq!(evaluation_job(CORE, false, false, &policy).unwrap(), None);
        assert_eq!(
            evaluation_job("GetBusbar/x", true, false, &policy)
                .unwrap_err()
                .message,
            "no trusted evaluation command for this repository"
        );
        assert_eq!(
            evaluation_job(CORE, true, true, &policy)
                .unwrap_err()
                .message,
            "evaluation modes are mutually exclusive"
        );
    }

    #[test]
    fn oidf_summary_keeps_only_terminal_identities() {
        let leg = crate::json::parse(br#"{"modules": [["oidcc-server", "PASSED", "FINISHED", "secret"]], "review_pages": {"p": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}, "ok": true, "exit": 0, "token": "x"}"#).unwrap();
        let safe = oidf_leg(&leg).unwrap();
        assert_eq!(
            json::dumps(&safe, false),
            "{\"modules\": [[\"oidcc-server\", \"PASSED\", \"FINISHED\"]], \"review_pages\": {\"p\": [\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}, \"ok\": true, \"exit\": 0}"
        );
        let bad = crate::json::parse(br#"{"modules": [["x y", "PASSED", "FINISHED"]]}"#).unwrap();
        assert_eq!(
            oidf_leg(&bad).unwrap_err().message,
            "invalid OIDF terminal module identity/result"
        );
    }
}
