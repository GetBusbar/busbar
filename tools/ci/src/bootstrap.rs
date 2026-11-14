//! Protected, fixed-source root controller on an existing one-use native worker.
//!
//! `native-bootstrap` runs as the runner user from the server-selected pipeline.
//! It downloads and verifies the public tool image, then starts one privileged
//! administrator entry from that image which copies this exact binary into a
//! root-only directory, checks its digest and executes `native-root` in the host
//! namespaces. Candidate commands never enter that container or receive its host
//! namespaces, socket, environment or credentials. `native-root` starts a
//! separate userns-remapped daemon (`native-daemon`) in private mount AND network
//! namespaces before any daemon process exists, prepares bounded job storage,
//! stages inputs and runs the step runner, then disposes everything and writes
//! `bootstrap.json` (schema `busbar.native-ci-root-bootstrap/1`, unchanged).
use crate::fetch;
use crate::images;
use crate::inputs::{self, HOST_DOCKER, base_env};
use crate::isolation;
use crate::json::{self, Value, object};
use crate::proc::{self, Options, Result, require, strings};
use crate::sha256;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

pub const PACKAGE: &str = "https://git.getbusbar.dev/api/v4/projects/3/packages/generic/busbar-native-public-tools/20261110-78dea35890609955/image.tar";
pub const ARCHIVE_SHA256: &str = "2b0ba52edc6f3bb198f2fcf9afc2c7edd75f3111f93f8b5afcbb3125eb813873";
pub const ARCHIVE_BYTES: u64 = 938926592;
pub const MANIFEST: &str = "78dea3589060995560aada47e190bf8d7c3f7d1e9ed6eb843ceffe5c13a81383";
pub const DOCKER: &str = "/usr/bin/docker";
pub const DOCKER_SHA256: &str = "7ed12b00293d64742419a6601ae97960a367a0ce97c88b06e3278cc0a409557b";
const GIT: &str = "/usr/bin/git";
const SUBID: u64 = 524288;
const SUBCOUNT: u64 = 65536;
const REMAP: &str = "busbar-ci-remap";
const ROOT: &str = "/srv/busbar-native-ci";
const STAGING: &str = "/var/lib/busbar-native";
const BUILDS: &str = "/home/fleeting/builds";
const ENTRY_PREFIX: &str = "/run/busbar-ci-root.";
const CI_KEYS: [&str; 16] = [
    "CI_JOB_ID",
    "CI_PIPELINE_ID",
    "CI_PROJECT_ID",
    "CI_PROJECT_PATH",
    "CI_JOB_NAME",
    "CI_JOB_URL",
    "CI_PIPELINE_SOURCE",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BRANCH",
    "CI_CONFIG_REF_URI",
    "CI_SERVER_HOST",
    "CI_SERVER_URL",
    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    "CI_MERGE_REQUEST_SOURCE_PROJECT_ID",
    "CI_JOB_TOKEN",
    "BUSBAR_ADMISSION_CORE_REVISION",
];
const JOBS: [&str; 4] = [
    "native-qualification",
    "core-conformance",
    "external-conformance",
    "native-isolation-diagnostic",
];

/// Verifies the copied controller in a root-only directory before executing it.
pub const ENTRY_SCRIPT: &str = "set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
d=$(mktemp -d /run/busbar-ci-root.XXXXXXXX)
if cp -- \"$1\" \"$d/busbar-ci\" && printf '%s  %s\\n' \"$2\" \"$d/busbar-ci\" | sha256sum -c - >/dev/null; then
  exec \"$d/busbar-ci\" native-root \"$d\"
fi
rm -rf -- \"$d\"
echo 'fixed controller differs from its verified digest' >&2
exit 1
";

pub type Env = BTreeMap<String, String>;

fn io<T>(value: std::io::Result<T>, context: &Path) -> Result<T> {
    value.map_err(|e| format!("{}: {e}", context.display()))
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn positive_integer(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('0') && value.bytes().all(|c| c.is_ascii_digit())
}

pub fn is_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn ci_environment(env: &Env) -> Result<Env> {
    let result: Env = env
        .iter()
        .filter(|(k, _)| CI_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let get = |key: &str| result.get(key).map(String::as_str).unwrap_or("");
    require(
        get("CI_SERVER_URL") == "https://git.getbusbar.dev"
            && get("CI_SERVER_HOST") == "git.getbusbar.dev",
        "unexpected CI authority",
    )?;
    for key in ["CI_JOB_ID", "CI_PIPELINE_ID", "CI_PROJECT_ID"] {
        require(positive_integer(get(key)), "invalid CI identity")?;
    }
    require(
        JOBS.contains(&get("CI_JOB_NAME")),
        "unrecognized protected bootstrap job",
    )?;
    let project = get("CI_PROJECT_PATH");
    let valid_project = ["GetBusbar/", "BusbarInc/"].iter().any(|owner| {
        project.strip_prefix(owner).is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
        })
    });
    require(valid_project, "invalid CI project")?;
    require(is_revision(get("CI_COMMIT_SHA")), "invalid source revision")?;
    require(
        !get("CI_JOB_TOKEN").is_empty(),
        "controller job token is missing",
    )?;
    let host = result.get("BUSBAR_ADMISSION_CORE_REVISION");
    require(
        host.is_none_or(|h| is_revision(h)),
        "protected host revision must be immutable",
    )?;
    require(
        project == "GetBusbar/busbar" || host.is_some(),
        "plugin qualification requires its protected immutable host revision",
    )?;
    Ok(result)
}

/// The trusted revision from the immutable server-selected configuration URI.
pub fn approved_revision(env: &Env) -> Result<String> {
    let uri = env
        .get("CI_CONFIG_REF_URI")
        .map(String::as_str)
        .unwrap_or("");
    let project = env.get("CI_PROJECT_PATH").map(String::as_str).unwrap_or("");
    let rest = uri.strip_prefix("https://").unwrap_or(uri);
    let prefix =
        format!("git.getbusbar.dev/{project}//ci/architecture-pipeline.yml@GetBusbar/busbar:");
    let revision = rest
        .strip_prefix(&prefix)
        .filter(|r| r.len() > 40 && r.is_char_boundary(40))
        .map(|r| r.split_at(40))
        .filter(|(sha, tail)| {
            is_revision(sha)
                && tail.strip_prefix("@refs/heads/").is_some_and(|branch| {
                    !branch.is_empty()
                        && !branch.chars().any(|c| c.is_whitespace() || c.is_control())
                })
        })
        .map(|(sha, _)| sha.to_owned());
    revision.ok_or_else(|| {
        "bootstrap must come from the immutable server-selected configuration".into()
    })
}

/// The one controller Git reader: exact `safe.directory`, no hooks/fsmonitor,
/// no global or system configuration. It reads stores owned by any UID.
pub fn git(path: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let text = path_text(path);
    let mut argv = strings(&[
        GIT,
        "-c",
        &format!("safe.directory={text}"),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-C",
        &text,
    ]);
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    let options = Options {
        env: base_env(),
        capture: true,
        timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    };
    let output = proc::run(&argv, &options)?;
    require(
        output.status.success(),
        &format!("git {} failed in {text}", args.first().unwrap_or(&"")),
    )?;
    Ok(output.stdout)
}

pub fn verify_trusted(path: &Path, revision: &str) -> Result<()> {
    require(
        isolation::exact_path(path) && path.is_dir(),
        "indirect trusted checkout",
    )?;
    require(
        String::from_utf8_lossy(&git(path, &["rev-parse", "HEAD"])?).trim() == revision,
        "trusted source revision differs",
    )?;
    require(
        git(path, &["diff", "--no-ext-diff", "HEAD", "--"])?.is_empty(),
        "trusted source has modifications",
    )?;
    require(
        git(path, &["ls-files", "--others", "--exclude-standard"])?.is_empty(),
        "untracked controller source",
    )?;
    Ok(())
}

fn docker(host: &str, args: &[&str]) -> Vec<String> {
    let mut argv = strings(&[DOCKER, "--host", host]);
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    argv
}

fn docker_json(host: &str, args: &[&str], env: &[(String, String)]) -> Result<Value> {
    let options = Options {
        env: env.to_vec(),
        capture: true,
        timeout: Some(Duration::from_secs(120)),
        ..Default::default()
    };
    json::parse(&proc::checked(&docker(host, args), &options)?.stdout)
}

fn import_failure(stderr: &[u8], status: &str, token: &str) -> String {
    format!(
        "offline image import failed ({status}): {}",
        fetch::redact(&String::from_utf8_lossy(stderr), token)
    )
}

/// Import the verified archive into a daemon and bind its identity.
fn load_tool_image(
    archive: &Path,
    endpoint: &str,
    env: &[(String, String)],
    token: &str,
) -> Result<String> {
    let metadata = images::tool_metadata(archive, MANIFEST)?;
    let options = Options {
        env: env.to_vec(),
        capture: true,
        timeout: Some(Duration::from_secs(300)),
        interruptible: true,
        ..Default::default()
    };
    let loaded = proc::run(
        &docker(endpoint, &["image", "load", "--input", &path_text(archive)]),
        &options,
    )?;
    require(
        loaded.status.success(),
        &import_failure(&loaded.stderr, &loaded.status.to_string(), token),
    )?;
    let name = images::loaded_names(&String::from_utf8_lossy(&loaded.stdout))?;
    let actual = docker_json(endpoint, &["image", "inspect", &name], env)?;
    images::verify_loaded(
        actual.index(0),
        &metadata.config,
        &allowed_ids(&metadata),
        "tool",
    )
}

fn allowed_ids(metadata: &images::ToolMetadata) -> Vec<String> {
    vec![
        format!("sha256:{MANIFEST}"),
        format!("sha256:{}", metadata.config_sha256),
    ]
}

pub fn entry_command(binary: &Path, expected: &str, image: &str, name: &str) -> Vec<String> {
    // No candidate entrypoint, shell, arbitrary command, environment or writable
    // source mount. Bare --wd selects target PID 1's cwd; --wd=/ would open the
    // old container root before namespace entry.
    strings(&[
        DOCKER,
        "--host",
        HOST_DOCKER,
        "run",
        "--name",
        name,
        "--pull=never",
        "--rm",
        "--interactive",
        "--privileged",
        "--userns=host",
        "--pid=host",
        "--network=none",
        "--entrypoint",
        "/usr/bin/nsenter",
        image,
        "--target",
        "1",
        "--mount",
        "--net",
        "--uts",
        "--ipc",
        "--cgroup",
        "--root",
        "--wd",
        "--no-fork",
        "/bin/sh",
        "-c",
        ENTRY_SCRIPT,
        "busbar-ci-entry",
        &path_text(binary),
        expected,
    ])
}

fn process_env() -> Env {
    std::env::vars().collect()
}

fn flag(args: &[String], name: &str) -> Result<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
        .ok_or_else(|| format!("bootstrap path {name} required"))
}

fn expected_work(env: &Env) -> PathBuf {
    Path::new(STAGING).join(format!(
        "boundary-{}-{}",
        env["CI_PROJECT_ID"], env["CI_JOB_ID"]
    ))
}

/// Kinds whose expensive bootstrap an authenticated equal-input original may replace.
pub const RETAINABLE: [&str; 2] = ["native-qualification", "core-conformance"];

/// The retention decision, made before any bootstrap download: true only after
/// this verified controller's own `retention` command (crate::retention, run as
/// a separate process with the job environment) authenticated an equal-input
/// successful original and wrote boundary-evidence/retained.json naming it.
/// Anything else runs fresh; evidence left behind without retaining fails the job.
fn retained(binary: &Path, checkout: &Path, revision: &str, job: &str) -> Result<bool> {
    if !RETAINABLE.contains(&job) {
        return Ok(false);
    }
    let output = checkout.join("boundary-evidence/retained.json");
    let argv = retention_command(binary, checkout, revision, &output);
    decide_retention(&argv, &output)
}

fn decide_retention(argv: &[String], output: &Path) -> Result<bool> {
    // Same inputs as the former in-YAML call: the job's own environment.
    let options = Options {
        env: std::env::vars().collect(),
        interruptible: true,
        ..Default::default()
    };
    let decided = proc::run(argv, &options)?.status.success();
    let regular = fs::symlink_metadata(output).is_ok_and(|m| m.file_type().is_file());
    if decided && regular {
        return Ok(true);
    }
    require(
        fs::symlink_metadata(output).is_err(),
        "retention decision left evidence without retaining",
    )?;
    Ok(false)
}

pub fn retention_command(
    binary: &Path,
    checkout: &Path,
    revision: &str,
    output: &Path,
) -> Vec<String> {
    vec![
        path_text(binary),
        "retention".into(),
        "--policy".into(),
        revision.into(),
        "--checkout".into(),
        path_text(checkout),
        "--output".into(),
        path_text(output),
    ]
}

fn outer(args: &[String]) -> Result<()> {
    proc::install_signal_handlers();
    let (trusted, checkout, work) = (
        flag(args, "--trusted")?,
        flag(args, "--checkout")?,
        flag(args, "--work")?,
    );
    let env = ci_environment(&process_env())?;
    let token = env["CI_JOB_TOKEN"].clone();
    let revision = approved_revision(&env)?;
    verify_trusted(&trusted, &revision)?;
    require(
        sha256::file(Path::new(DOCKER))? == DOCKER_SHA256,
        "native Docker client differs",
    )?;
    require(
        isolation::exact_path(&work)
            && work == expected_work(&env)
            && trusted == work.join("trusted"),
        "unexpected bootstrap staging root",
    )?;
    require(
        checkout.is_dir() && isolation::exact_path(&checkout) && checkout.starts_with(BUILDS),
        "unexpected runner checkout",
    )?;
    // The fixed controller must be the one the server-selected pipeline just
    // built from this trusted revision inside the job staging root.
    let binary = fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    require(
        binary.starts_with(&work) && !binary.starts_with(&trusted),
        "controller binary is outside the job staging root",
    )?;
    let binary_sha = sha256::file(&binary)?;
    if retained(&binary, &checkout, &revision, &env["CI_JOB_NAME"])? {
        return Ok(());
    }
    let archive = work.join("public-tools.tar");
    fetch::fetch(PACKAGE, &token, &archive, ARCHIVE_BYTES, ARCHIVE_SHA256)?;
    io(
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o444)),
        &archive,
    )?;
    let name = format!("busbar-root-controller-{}", env["CI_JOB_ID"]);
    let mut client_env = base_env();
    client_env.push(("HOME".into(), path_text(&work)));
    let docker_config = work.join("docker-client");
    client_env.push(("DOCKER_CONFIG".into(), path_text(&docker_config)));
    io(fs::create_dir(&docker_config), &docker_config)?;
    io(
        fs::set_permissions(&docker_config, fs::Permissions::from_mode(0o700)),
        &docker_config,
    )?;
    let result = (|| -> Result<()> {
        let image = load_tool_image(&archive, HOST_DOCKER, &client_env, &token)?;
        let environment = Value::Object(
            env.iter()
                .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
                .collect(),
        );
        let payload = object([
            ("environment", environment),
            ("trusted", path_text(&trusted).into()),
            ("checkout", path_text(&checkout).into()),
            ("work", path_text(&work).into()),
            ("archive", path_text(&archive).into()),
            ("revision", revision.as_str().into()),
            ("image", image.as_str().into()),
        ]);
        // The token crosses only stdin into the verified root controller. It is
        // absent from Docker's inspectable environment and every argument.
        let options = Options {
            env: client_env.clone(),
            stdin: Some(json::dumps(&payload, false).into_bytes()),
            interruptible: true,
            ..Default::default()
        };
        let status = proc::run(
            &entry_command(&binary, &binary_sha, &image, &name),
            &options,
        )?
        .status;
        require(
            status.success(),
            &format!("protected root controller failed ({status})"),
        )
    })();
    let quiet = Options {
        env: client_env.clone(),
        capture: true,
        timeout: Some(Duration::from_secs(45)),
        ..Default::default()
    };
    let _ = proc::run(
        &docker(HOST_DOCKER, &["stop", "--time", "30", &name]),
        &quiet,
    );
    let _ = proc::run(&docker(HOST_DOCKER, &["rm", "--force", &name]), &quiet);
    result
}

/// Create (root-owned, not group/other writable) parents; optionally require emptiness.
fn root_directory(path: &Path, fresh: bool) -> Result<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if !current.exists() && !current.is_symlink() {
            io(fs::create_dir(&current), &current)?;
            io(
                fs::set_permissions(&current, fs::Permissions::from_mode(0o755)),
                &current,
            )?;
        }
        let metadata = io(fs::symlink_metadata(&current), &current)?;
        require(
            metadata.file_type().is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "controller path is not root-owned",
        )?;
    }
    if fresh {
        require(
            io(fs::read_dir(path), path)?.next().is_none(),
            "controller workspace is not fresh",
        )?;
    }
    Ok(path.to_path_buf())
}

/// Remapped graphroot must be traversable, but never listable or writable.
fn job_directory(path: &Path) -> Result<PathBuf> {
    let control = root_directory(path, true)?;
    io(
        fs::set_permissions(&control, fs::Permissions::from_mode(0o711)),
        &control,
    )?;
    Ok(control)
}

/// `shutil.copytree` (mode and mtime preserved). With `links`, symbolic links
/// are recreated; otherwise any link refuses. Special files always refuse.
pub fn copy_tree(source: &Path, destination: &Path, links: bool, merge: bool) -> Result<()> {
    let metadata = io(fs::symlink_metadata(source), source)?;
    require(
        metadata.file_type().is_dir(),
        "copy source is not a directory",
    )?;
    if !(merge && destination.is_dir()) {
        io(fs::create_dir(destination), destination)?;
    }
    for entry in io(fs::read_dir(source), source)? {
        let entry = io(entry, source)?;
        let (from, to) = (entry.path(), destination.join(entry.file_name()));
        let kind = io(entry.file_type(), &from)?;
        if kind.is_symlink() {
            require(links, "indirect controller evidence")?;
            if merge && (to.exists() || to.is_symlink()) {
                io(fs::remove_file(&to), &to)?;
            }
            io(
                std::os::unix::fs::symlink(io(fs::read_link(&from), &from)?, &to),
                &to,
            )?;
            continue;
        }
        if kind.is_dir() {
            copy_tree(&from, &to, links, merge)?;
        } else if kind.is_file() {
            io(fs::copy(&from, &to), &to)?;
        } else {
            return Err(format!("{}: unsupported special file", from.display()));
        }
        let metadata = io(fs::symlink_metadata(&from), &from)?;
        if kind.is_file() {
            let file = io(fs::File::open(&to), &to)?;
            io(file.set_modified(io(metadata.modified(), &from)?), &to)?;
        }
    }
    let file = io(fs::File::open(destination), destination)?;
    io(
        file.set_modified(io(metadata.modified(), source)?),
        destination,
    )?;
    io(
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(metadata.mode() & 0o7777),
        ),
        destination,
    )
}

pub fn runtime_configuration(
    control: &Path,
    endpoint: &str,
    image: &str,
    diagnostic: bool,
) -> Value {
    let gib = 1u64 << 30;
    let mut isolation = object([
        (
            "storage_kind",
            if diagnostic { "tmpfs" } else { "loop-ext4" }.into(),
        ),
        ("storage_root", path_text(&control.join("store")).into()),
        (
            "storage_bytes",
            if diagnostic { 512u64 << 20 } else { 24 * gib }.into(),
        ),
        (
            "storage_inodes",
            if diagnostic { 65536u64 } else { 1048576 }.into(),
        ),
        (
            "storage_reserve_bytes",
            if diagnostic { 0 } else { 6 * gib }.into(),
        ),
        (
            "uid_map",
            vec![0u64.into(), SUBID.into(), SUBCOUNT.into()].into(),
        ),
        (
            "gid_map",
            vec![0u64.into(), SUBID.into(), SUBCOUNT.into()].into(),
        ),
    ]);
    if !diagnostic {
        isolation.set("storage_image", path_text(&control.join("job.ext4")).into());
    }
    object([
        ("schema", "busbar.native-confinement/2".into()),
        ("docker", DOCKER.into()),
        ("docker_sha256", DOCKER_SHA256.into()),
        ("docker_host", endpoint.into()),
        ("image", image.into()),
        ("runtime", "runc".into()),
        ("uid", 1001u64.into()),
        ("gid", 1002u64.into()),
        ("python", "/usr/bin/python3".into()),
        (
            "environment",
            object([
                (
                    "PATH",
                    "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin".into(),
                ),
                ("CARGO_HOME", "/opt/busbar-native/cargo-seed".into()),
                ("RUSTUP_HOME", "/usr/local/rustup".into()),
            ]),
        ),
        (
            "resources",
            object([
                ("cpus", if diagnostic { 2u64 } else { 4 }.into()),
                (
                    "memory_bytes",
                    if diagnostic { gib } else { 6 * gib }.into(),
                ),
                ("pids", if diagnostic { 256u64 } else { 1024 }.into()),
            ]),
        ),
        ("isolation", isolation),
        (
            "collector",
            object([
                ("docker_host", HOST_DOCKER.into()),
                ("image", image.into()),
                ("uid", (SUBID + 1001).into()),
                ("gid", (SUBID + 1002).into()),
            ]),
        ),
    ])
}

fn namespace_inode(path: &str) -> Result<u64> {
    Ok(fs::metadata(path)
        .map_err(|e| format!("{path}: {e}"))?
        .ino())
}

pub fn require_host_controller(euid: u32, inode: &dyn Fn(&str) -> Result<u64>) -> Result<()> {
    require(euid == 0, "controller must execute as host root")?;
    // The administrator bridge starts in Docker's private cgroup namespace.
    // Only the controller joins the host namespace; candidates and fixture
    // peers retain their private cgroup namespaces.
    for kind in ["mnt", "cgroup"] {
        require(
            inode(&format!("/proc/self/ns/{kind}"))? == inode(&format!("/proc/1/ns/{kind}"))?,
            &format!("controller must execute in the host {kind} namespace"),
        )?;
    }
    Ok(())
}

/// Validate existing subordinate rows and return the rows to append.
pub fn subordinate_rows(existing: &str) -> Result<()> {
    for line in existing.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        require(fields.len() == 3, "invalid subordinate identity file")?;
        let start: u64 = fields[1]
            .parse()
            .map_err(|_| "invalid subordinate identity file")?;
        let count: u64 = fields[2]
            .parse()
            .map_err(|_| "invalid subordinate identity file")?;
        require(
            fields[0] != REMAP && (start + count <= SUBID || start >= SUBID + SUBCOUNT),
            "protected subordinate range overlaps an existing mapping",
        )?;
    }
    Ok(())
}

fn appended(original: &Option<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(payload) = original {
        let mut trimmed = payload.as_slice();
        while trimmed.last() == Some(&b'\n') {
            trimmed = &trimmed[..trimmed.len() - 1];
        }
        out.extend(trimmed);
        if !payload.is_empty() {
            out.push(b'\n');
        }
    }
    out.extend(format!("{REMAP}:{SUBID}:{SUBCOUNT}\n").as_bytes());
    out
}

struct SubordinateIds {
    originals: Vec<(PathBuf, Option<Vec<u8>>)>,
    created: bool,
}

impl SubordinateIds {
    fn create() -> Result<Self> {
        let mut originals = Vec::new();
        for path in ["/etc/subuid", "/etc/subgid"] {
            let path = PathBuf::from(path);
            let payload = if path.exists() {
                Some(io(fs::read(&path), &path)?)
            } else {
                None
            };
            subordinate_rows(&String::from_utf8_lossy(payload.as_deref().unwrap_or(b"")))?;
            originals.push((path, payload));
        }
        let host = Options {
            env: base_env(),
            capture: true,
            timeout: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        require(
            !proc::run(&strings(&["getent", "passwd", REMAP]), &host)?
                .status
                .success(),
            "remapped controller identity already exists",
        )?;
        let mut guard = SubordinateIds {
            originals,
            created: false,
        };
        proc::checked(
            &strings(&[
                "/usr/sbin/useradd",
                "--system",
                "--user-group",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                REMAP,
            ]),
            &host,
        )?;
        guard.created = true;
        for (path, payload) in &guard.originals {
            io(fs::write(path, appended(payload)), path)?;
        }
        Ok(guard)
    }

    fn restore(mut self) -> Result<()> {
        let mut result = Ok(());
        if std::mem::take(&mut self.created) {
            let host = Options {
                env: base_env(),
                capture: true,
                timeout: Some(Duration::from_secs(60)),
                ..Default::default()
            };
            result = proc::checked(&strings(&["/usr/sbin/userdel", REMAP]), &host).map(|_| ());
        }
        for (path, payload) in &self.originals {
            let restored = match payload {
                None => fs::remove_file(path).or_else(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                }),
                Some(payload) => fs::write(path, payload),
            };
            if let Err(error) = restored {
                result = result.and(Err(format!("{}: {error}", path.display())));
            }
        }
        self.originals.clear();
        result
    }
}

impl Drop for SubordinateIds {
    fn drop(&mut self) {
        if self.created || !self.originals.is_empty() {
            let guard = SubordinateIds {
                originals: std::mem::take(&mut self.originals),
                created: self.created,
            };
            self.created = false;
            let _ = guard.restore();
        }
    }
}

/// Poll until `probe` succeeds, the supervisor exits, or the deadline passes.
pub fn wait_ready(
    deadline: Duration,
    interval: Duration,
    supervisor_alive: &mut dyn FnMut() -> bool,
    probe: &mut dyn FnMut() -> Option<Value>,
) -> Result<Value> {
    let start = Instant::now();
    while start.elapsed() < deadline {
        proc::check_interrupted()?;
        require(
            supervisor_alive(),
            "private daemon supervisor exited; see daemon.log",
        )?;
        if let Some(info) = probe() {
            return Ok(info);
        }
        std::thread::sleep(interval);
    }
    Err("private Docker daemon did not become ready".into())
}

/// Candidate disposal is confirmed only by an empty listing after removal;
/// before any workload a failed daemon cannot have accepted a candidate.
pub fn disposal_confirmed(remaining_after_removal: Option<bool>, workload_started: bool) -> bool {
    !workload_started || remaining_after_removal == Some(false)
}

pub fn receipt_status(success: bool, disposal: bool, mounted: bool) -> &'static str {
    if success && disposal && !mounted {
        "pass"
    } else {
        "failed"
    }
}

fn terminate(child: &mut Child, wait: Duration) -> Result<()> {
    if child.try_wait().map_err(|e| e.to_string())?.is_none() {
        proc::signal_process(child.id() as i32, proc::SIGTERM);
    }
    let start = Instant::now();
    while start.elapsed() < wait {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    proc::signal_process(child.id() as i32, proc::SIGKILL);
    let _ = child.wait();
    Err("private daemon supervisor did not stop in time".into())
}

/// Stream the host-verified image into the private daemon (classic overlay
/// store needs `docker save`'s manifest.json): no second archive or registry.
fn load_private_image(
    endpoint: &str,
    source_image: &str,
    metadata: &images::ToolMetadata,
    token: &str,
) -> Result<String> {
    require(
        allowed_ids(metadata).iter().any(|a| a == source_image),
        "unverified image selected for compatibility export",
    )?;
    let env = base_env();
    let producer_argv = docker(
        HOST_DOCKER,
        &["image", "save", "--platform", "linux/amd64", source_image],
    );
    let mut producer = proc::command(
        &producer_argv,
        &Options {
            env: env.clone(),
            ..Default::default()
        },
    )?
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|e| e.to_string())?;
    let stream = producer.stdout.take().unwrap();
    let consumer = (|| -> Result<std::process::Output> {
        let mut child = proc::command(
            &docker(endpoint, &["image", "load"]),
            &Options {
                env: env.clone(),
                ..Default::default()
            },
        )?
        .stdin(Stdio::from(stream))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
        let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let readers = (
            std::thread::spawn(move || {
                let mut b = Vec::new();
                let _ = (&mut out).take(1 << 20).read_to_end(&mut b);
                b
            }),
            std::thread::spawn(move || {
                let mut b = Vec::new();
                let _ = (&mut err).take(1 << 20).read_to_end(&mut b);
                b
            }),
        );
        let status = proc::supervise(
            &mut child,
            &Options {
                timeout: Some(Duration::from_secs(300)),
                interruptible: true,
                ..Default::default()
            },
            "docker image load",
        );
        let stdout = readers.0.join().unwrap_or_default();
        let stderr = readers.1.join().unwrap_or_default();
        Ok(std::process::Output {
            status: status?,
            stdout,
            stderr,
        })
    })();
    let exported = proc::supervise(
        &mut producer,
        &Options {
            timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        },
        "docker image save",
    );
    let loaded = consumer?;
    require(
        loaded.status.success(),
        &import_failure(&loaded.stderr, &loaded.status.to_string(), token),
    )?;
    require(
        exported?.success(),
        "verified tool image compatibility export failed",
    )?;
    let name = images::loaded_names(&String::from_utf8_lossy(&loaded.stdout))?;
    let actual = docker_json(endpoint, &["image", "inspect", &name], &env)?;
    images::verify_loaded(
        actual.index(0),
        &metadata.config,
        &allowed_ids(metadata),
        "tool",
    )
}

fn capacity(path: &Path) -> Result<u64> {
    Ok(proc::statvfs(path)?.available_bytes)
}

struct Root {
    env: Env,
    controller_env: Vec<(String, String)>,
    original_checkout: PathBuf,
    control: PathBuf,
    trusted: PathBuf,
    revision: String,
    image: String,
    metadata: images::ToolMetadata,
    self_binary: PathBuf,
}

fn root_main(args: &[String]) -> Result<()> {
    proc::install_signal_handlers();
    std::env::set_current_dir("/").map_err(|e| e.to_string())?;
    let entry = PathBuf::from(args.first().ok_or("controller entry directory required")?);
    require(
        path_text(&entry)
            .strip_prefix(ENTRY_PREFIX)
            .is_some_and(|s| s.len() == 8 && s.bytes().all(|c| c.is_ascii_alphanumeric())),
        "unexpected controller entry directory",
    )?;
    let self_binary = entry.join("busbar-ci");
    let result = (|| {
        require(
            fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?).ok()
                == Some(self_binary.clone()),
            "controller entry binary differs",
        )?;
        require_host_controller(proc::euid(), &namespace_inode)?;
        let mut raw = Vec::new();
        std::io::stdin()
            .take(1 << 20)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        root(json::parse(&raw)?, self_binary.clone())
    })();
    let _ = fs::remove_dir_all(&entry);
    result
}

fn root(payload: Value, self_binary: PathBuf) -> Result<()> {
    require(
        payload.has_keys(&[
            "environment",
            "trusted",
            "checkout",
            "work",
            "archive",
            "revision",
            "image",
        ]),
        "unknown root bootstrap input",
    )?;
    let given = payload
        .at("environment")
        .as_object()
        .ok_or("unapproved controller environment")?;
    let mut raw_env = Env::new();
    for (key, value) in given {
        require(
            CI_KEYS.contains(&key.as_str()),
            "unapproved controller environment",
        )?;
        raw_env.insert(
            key.clone(),
            value
                .as_str()
                .ok_or("unapproved controller environment")?
                .to_owned(),
        );
    }
    let env = ci_environment(&raw_env)?;
    let text = |key: &str| payload.at(key).as_str().unwrap_or("").to_owned();
    let revision = text("revision");
    require(
        approved_revision(&env)? == revision,
        "unapproved controller environment",
    )?;
    let (original_trusted, original_checkout) = (
        PathBuf::from(text("trusted")),
        PathBuf::from(text("checkout")),
    );
    verify_trusted(&original_trusted, &revision)?;
    let work = expected_work(&env);
    require(
        Path::new(&text("work")) == work
            && original_trusted == work.join("trusted")
            && Path::new(&text("archive")) == work.join("public-tools.tar")
            && isolation::exact_path(&original_checkout)
            && original_checkout.starts_with(BUILDS),
        "root bootstrap paths differ",
    )?;
    let image = text("image");
    require(
        image.strip_prefix("sha256:").is_some_and(images::is_digest),
        "unapproved tool image identity",
    )?;
    require(
        sha256::file(Path::new(DOCKER))? == DOCKER_SHA256,
        "administrator bootstrap inputs changed",
    )?;
    // Digest and metadata come from one pass over the same bytes: no 939 MB copy.
    let metadata = images::verified_tool_metadata(
        &work.join("public-tools.tar"),
        ARCHIVE_SHA256,
        ARCHIVE_BYTES,
        MANIFEST,
    )?;
    let control = job_directory(&Path::new(ROOT).join(format!("job-{}", env["CI_JOB_ID"])))?;
    let mut controller_env: BTreeMap<String, String> = base_env().into_iter().collect();
    controller_env.extend(env.clone());
    controller_env.insert("HOME".into(), path_text(&control.join("home")));
    controller_env.insert("PATH".into(), format!("/opt/cargo/bin:{}", proc::HOST_PATH));
    controller_env.insert("RUSTUP_HOME".into(), "/opt/rustup".into());
    controller_env.insert("CARGO_HOME".into(), path_text(&control.join("home/.cargo")));
    // The step runner launches this same digest-verified binary for its
    // controller-owned steps (`busbar-ci architecture`); never a candidate path.
    controller_env.insert("BUSBAR_CI_CONTROLLER".into(), path_text(&self_binary));
    let home = control.join("home");
    io(fs::create_dir(&home), &home)?;
    io(
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)),
        &home,
    )?;
    let trusted = control.join("trusted");
    copy_tree(&original_trusted, &trusted, true, false)?;
    // Published source is mounted read-only in candidate invocations.
    io(
        fs::set_permissions(&trusted, fs::Permissions::from_mode(0o755)),
        &trusted,
    )?;
    verify_trusted(&trusted, &revision)?;
    let state = Root {
        env,
        controller_env: controller_env.into_iter().collect(),
        original_checkout,
        control,
        trusted,
        revision,
        image,
        metadata,
        self_binary,
    };
    state.run()
}

impl Root {
    fn run(&self) -> Result<()> {
        let control = &self.control;
        let endpoint = format!("unix://{}", path_text(&control.join("docker.sock")));
        let diagnostic = self.env["CI_JOB_NAME"] == "native-isolation-diagnostic";
        let mut config = runtime_configuration(control, &endpoint, &self.image, diagnostic);
        let config_path = control.join("runtime.json");
        let write_config = |config: &Value| -> Result<String> {
            io(
                fs::write(&config_path, json::dumps(config, true) + "\n"),
                &config_path,
            )?;
            sha256::file(&config_path)
        };
        let runtime_sha = write_config(&config)?;
        let inputs_path = control.join("daemon-inputs.json");
        io(
            fs::write(
                &inputs_path,
                json::dumps(&object([("endpoint", endpoint.as_str().into())]), false),
            ),
            &inputs_path,
        )?;
        let evidence = control.join("evidence");
        io(fs::create_dir(&evidence), &evidence)?;
        io(
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700)),
            &evidence,
        )?;
        let mut receipt = object([
            ("schema", "busbar.native-ci-root-bootstrap/1".into()),
            ("policy_revision", self.revision.as_str().into()),
            ("image_manifest_sha256", MANIFEST.into()),
            ("archive_sha256", ARCHIVE_SHA256.into()),
            ("runtime_sha256", runtime_sha.into()),
            ("root_controller", true.into()),
            ("bootstrap_admin_entry_privileged", true.into()),
            ("candidate_privileged", false.into()),
            ("private_daemon_mount_and_network_namespaces", true.into()),
            ("status", "running".into()),
        ]);
        let mut supervisor: Option<Child> = None;
        let mut mounted = false;
        let mut success = false;
        let mut disposal = false;
        let outcome = self.contained(
            &mut config,
            &write_config,
            &config_path,
            &endpoint,
            &evidence,
            &mut receipt,
            &mut supervisor,
            &mut mounted,
            &mut success,
            &mut disposal,
        );
        receipt.set("status", receipt_status(success, disposal, mounted).into());
        receipt.set("candidate_containers_disposed", disposal.into());
        receipt.set("storage_disposed", (!mounted).into());
        let published = self.publish(&evidence, &receipt);
        let mut stopped = Ok(());
        if let Some(child) = supervisor.as_mut() {
            stopped = terminate(child, Duration::from_secs(70));
        }
        let removed = if mounted {
            Ok(())
        } else {
            fs::remove_dir_all(control).map_err(|e| e.to_string())
        };
        outcome.and(published).and(stopped).and(removed)
    }

    fn publish(&self, evidence: &Path, receipt: &Value) -> Result<()> {
        let path = evidence.join("bootstrap.json");
        io(fs::write(&path, json::dumps_indent(receipt) + "\n"), &path)?;
        let destination = self.original_checkout.join("boundary-evidence");
        require(
            !destination.exists() && !destination.is_symlink(),
            "candidate supplied artifact destination",
        )?;
        copy_tree(evidence, &destination, false, false)?;
        fn fix(path: &Path) -> Result<()> {
            let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            require(
                !metadata.file_type().is_symlink(),
                "indirect controller evidence",
            )?;
            let mode = if metadata.is_dir() { 0o755 } else { 0o644 };
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .map_err(|e| e.to_string())?;
            if metadata.is_dir() {
                for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
                    fix(&entry.map_err(|e| e.to_string())?.path())?;
                }
            }
            Ok(())
        }
        fix(&destination)
    }

    #[allow(clippy::too_many_arguments)]
    fn contained(
        &self,
        config: &mut Value,
        write_config: &dyn Fn(&Value) -> Result<String>,
        config_path: &Path,
        endpoint: &str,
        evidence: &Path,
        receipt: &mut Value,
        supervisor: &mut Option<Child>,
        mounted: &mut bool,
        success: &mut bool,
        disposal: &mut bool,
    ) -> Result<()> {
        let ids = SubordinateIds::create()?;
        let result = (|| -> Result<()> {
            receipt.set(
                "host_available_bytes_before_storage",
                capacity(&self.control)?.into(),
            );
            let isolation_config = config.at("isolation").clone();
            receipt.set("storage", isolation::prepare(&isolation_config)?);
            *mounted = true;
            let store = PathBuf::from(isolation_config.at("storage_root").as_str().unwrap());
            // Both candidate daemon and its containerd inherit this mounted root.
            let log_path = evidence.join("bootstrap-daemon.log");
            let log = io(fs::File::create(&log_path), &log_path)?;
            let unshare = proc::host_program("unshare")?;
            let argv = vec![
                unshare,
                "--mount".into(),
                "--net".into(),
                "--propagation".into(),
                "private".into(),
                path_text(&self.self_binary),
                "native-daemon".into(),
                path_text(&self.control),
            ];
            let child = proc::command(
                &argv,
                &Options {
                    env: base_env(),
                    ..Default::default()
                },
            )?
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log)
            .spawn()
            .map_err(|e| e.to_string())?;
            *supervisor = Some(child);
            let mut workload_started = false;
            let inner = self.workload(
                config,
                write_config,
                config_path,
                endpoint,
                evidence,
                receipt,
                supervisor,
                &store,
                &mut workload_started,
            );
            *success = inner.is_ok();
            // Disposal: remove every private-daemon container and confirm none remain.
            let quiet = Options {
                env: base_env(),
                capture: true,
                timeout: Some(Duration::from_secs(120)),
                ..Default::default()
            };
            let listing = proc::run(&docker(endpoint, &["ps", "--all", "--quiet"]), &quiet);
            let mut remaining = None;
            if let Some(listing) = listing.as_ref().ok().filter(|l| l.status.success()) {
                let ids: Vec<String> = String::from_utf8_lossy(&listing.stdout)
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect();
                let removed = ids.is_empty() || {
                    let mut argv = docker(endpoint, &["rm", "--force"]);
                    argv.extend(ids);
                    proc::checked(&argv, &quiet).is_ok()
                };
                if removed
                    && let Ok(after) =
                        proc::checked(&docker(endpoint, &["ps", "--all", "--quiet"]), &quiet)
                {
                    remaining = Some(!String::from_utf8_lossy(&after.stdout).trim().is_empty());
                }
            }
            *disposal = disposal_confirmed(remaining, workload_started);
            let disposed = require(*disposal, "candidate disposal could not be confirmed");
            let stopped = if disposed.is_ok() {
                let mut child = supervisor.take().unwrap();
                terminate(&mut child, Duration::from_secs(70))
            } else {
                Ok(())
            };
            let storage = if disposed.is_ok() && stopped.is_ok() {
                isolation::dispose(&isolation_config).map(|_| *mounted = false)
            } else {
                Ok(())
            };
            inner.and(disposed).and(stopped).and(storage)
        })();
        let restored = ids.restore();
        result.and(restored)
    }

    #[allow(clippy::too_many_arguments)]
    fn workload(
        &self,
        config: &mut Value,
        write_config: &dyn Fn(&Value) -> Result<String>,
        config_path: &Path,
        endpoint: &str,
        evidence: &Path,
        receipt: &mut Value,
        supervisor: &mut Option<Child>,
        store: &Path,
        workload_started: &mut bool,
    ) -> Result<()> {
        let token = self.env["CI_JOB_TOKEN"].clone();
        let env = base_env();
        let info = wait_ready(
            Duration::from_secs(60),
            Duration::from_millis(250),
            &mut || {
                supervisor
                    .as_mut()
                    .is_some_and(|c| matches!(c.try_wait(), Ok(None)))
            },
            &mut || {
                let options = Options {
                    env: env.clone(),
                    capture: true,
                    timeout: Some(Duration::from_secs(10)),
                    ..Default::default()
                };
                proc::run(
                    &docker(endpoint, &["info", "--format", "{{json .}}"]),
                    &options,
                )
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| json::parse(&o.stdout).ok())
            },
        )?;
        isolation::validate_userns(config.at("isolation"), &info)?;
        let candidate = load_private_image(endpoint, &self.image, &self.metadata, &token)?;
        config.set("image", candidate.as_str().into());
        // The administrator entry already imported and verified this image on
        // the host daemon; re-verify its execution identity instead of a third
        // 939 MB import.
        let host = docker_json(HOST_DOCKER, &["image", "inspect", &self.image], &env)?;
        let collector = images::verify_loaded(
            host.index(0),
            &self.metadata.config,
            &allowed_ids(&self.metadata),
            "tool",
        )?;
        require(
            collector == self.image,
            "administrator image identity changed",
        )?;
        config
            .get_mut("collector")
            .unwrap()
            .set("image", collector.as_str().into());
        let runtime_sha = write_config(config)?;
        receipt.set("runtime_sha256", runtime_sha.as_str().into());
        receipt.set("candidate_image_id", candidate.as_str().into());
        receipt.set("collector_image_id", collector.as_str().into());
        let reserve = config
            .at("isolation")
            .at("storage_reserve_bytes")
            .as_u64()
            .unwrap_or(0);
        let available = capacity(&self.control)?;
        receipt.set("host_available_bytes_after_image_import", available.into());
        require(
            available >= reserve,
            "public tooling import would consume the protected host disk reserve",
        )?;
        *workload_started = true;
        let python = "/usr/bin/python3".to_owned();
        let architecture = self.trusted.join("scripts/architecture");
        if self.env["CI_JOB_NAME"] == "native-isolation-diagnostic" {
            // Fixed-source diagnostic witnesses (Python unit tests and probes).
            let argv = vec![
                python,
                "-B".into(),
                path_text(&architecture.join("native_isolation_diagnostic.py")),
                "--trusted".into(),
                path_text(&self.trusted),
                "--config".into(),
                path_text(config_path),
                "--store".into(),
                path_text(store),
                "--evidence".into(),
                path_text(evidence),
            ];
            let options = Options {
                env: self.controller_env.clone(),
                cwd: Some(self.trusted.clone()),
                grace: Some(Duration::from_secs(10)),
                interruptible: true,
                ..Default::default()
            };
            let status = proc::run(&argv, &options)?.status;
            return require(
                status.success(),
                &format!("isolation diagnostic failed ({status})"),
            );
        }
        let services = inputs::stage_services(
            &self.trusted,
            DOCKER,
            &self.env["CI_PROJECT_PATH"],
            store,
            &token,
        )?;
        receipt.set("service_inputs", services);
        require(
            capacity(&self.control)? >= reserve,
            "service image imports would consume the protected host disk reserve",
        )?;
        let checkout = store.join("checkout");
        copy_tree(&self.original_checkout, &checkout, true, false)?;
        let work = store.join(format!(
            "boundary-{}-{}",
            self.env["CI_PROJECT_ID"], self.env["CI_JOB_ID"]
        ));
        io(fs::create_dir(&work), &work)?;
        let mut argv = vec![
            python,
            "-B".into(),
            path_text(&architecture.join("native.py")),
            "--trusted".into(),
            path_text(&self.trusted),
            "--checkout".into(),
            path_text(&checkout),
            "--work".into(),
            path_text(&work),
            "--confinement".into(),
            path_text(config_path),
            "--confinement-sha256".into(),
            sha256::file(config_path)?,
        ];
        let fetcher = |row: &Value, destination: &Path| {
            fetch::fetch(
                row.at("archive_url").as_str().unwrap_or(""),
                &token,
                destination,
                row.at("bytes").as_u64().unwrap_or(0),
                row.at("archive_sha256").as_str().unwrap_or(""),
            )
        };
        if let Some(judges) = inputs::stage_judges(
            &self.trusted,
            &self.env["CI_PROJECT_PATH"],
            &self.env["CI_JOB_NAME"],
            store,
            &fetcher,
        )? {
            argv.extend([
                "--conformance-inputs".into(),
                judges.at("manifest").as_str().unwrap().to_owned(),
                "--conformance-inputs-sha256".into(),
                judges.at("sha256").as_str().unwrap().to_owned(),
            ]);
            receipt.set("judge_inputs", judges);
        }
        match self.env["CI_JOB_NAME"].as_str() {
            "core-conformance" => argv.push("--conformance-only".into()),
            "external-conformance" => argv.push("--external-conformance".into()),
            _ => {}
        }
        let options = Options {
            env: self.controller_env.clone(),
            cwd: Some(self.trusted.clone()),
            grace: Some(Duration::from_secs(10)),
            interruptible: true,
            ..Default::default()
        };
        let ran = proc::run(&argv, &options).and_then(|o| {
            require(
                o.status.success(),
                &format!("step runner failed ({})", o.status),
            )
        });
        let produced = checkout.join("boundary-evidence");
        let copied = if fs::symlink_metadata(&produced).is_ok_and(|m| m.is_dir()) {
            copy_tree(&produced, evidence, false, true)
        } else {
            Ok(())
        };
        ran.and(copied)
    }
}

fn daemon_main(args: &[String]) -> Result<()> {
    proc::install_signal_handlers();
    require(proc::euid() == 0, "daemon supervisor requires root")?;
    for kind in ["mnt", "net"] {
        require(
            namespace_inode(&format!("/proc/self/ns/{kind}"))?
                != namespace_inode(&format!("/proc/1/ns/{kind}"))?,
            "secondary daemon requires private mount and network namespaces from startup",
        )?;
    }
    let control = PathBuf::from(args.first().ok_or("daemon control directory required")?);
    let inputs = json::parse(&io(fs::read(control.join("daemon-inputs.json")), &control)?)?;
    let endpoint = inputs
        .at("endpoint")
        .as_str()
        .ok_or("invalid daemon inputs")?
        .to_owned();
    let data = root_directory(&control.join("daemon"), false)?;
    let host = Options {
        env: base_env(),
        capture: true,
        timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };
    proc::checked(
        &[
            proc::host_program("ip")?,
            "link".into(),
            "set".into(),
            "lo".into(),
            "up".into(),
        ],
        &host,
    )?;
    let spawn = |argv: Vec<String>| -> Result<Child> {
        proc::command(
            &argv,
            &Options {
                env: base_env(),
                ..Default::default()
            },
        )?
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())
    };
    let mut processes: Vec<Child> = Vec::new();
    let result = (|| -> Result<()> {
        let at = |name: &str| path_text(&data.join(name));
        processes.push(spawn(vec![
            proc::host_program("containerd")?,
            "--address".into(),
            at("containerd.sock"),
            "--root".into(),
            at("containerd-root"),
            "--state".into(),
            at("containerd-state"),
            "--config".into(),
            "/dev/null".into(),
        ])?);
        let daemon = object([
            ("hosts", vec![Value::from(endpoint.as_str())].into()),
            ("data-root", at("data").into()),
            ("exec-root", at("exec").into()),
            ("pidfile", at("docker.pid").into()),
            ("containerd", at("containerd.sock").into()),
            ("userns-remap", format!("{REMAP}:{REMAP}").into()),
            ("storage-driver", "overlay2".into()),
            ("bridge", "none".into()),
            ("iptables", false.into()),
            ("ip6tables", false.into()),
            ("ip-forward", false.into()),
            ("ip-masq", false.into()),
            (
                "features",
                object([("containerd-snapshotter", false.into())]),
            ),
        ]);
        let path = data.join("daemon.json");
        io(fs::write(&path, json::dumps(&daemon, false)), &path)?;
        processes.push(spawn(vec![
            proc::host_program("dockerd")?,
            "--config-file".into(),
            path_text(&path),
        ])?);
        loop {
            proc::check_interrupted()?;
            for process in processes.iter_mut() {
                if process.try_wait().map_err(|e| e.to_string())?.is_some() {
                    return Err("private daemon exited unexpectedly".into());
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    })();
    for process in processes.iter_mut().rev() {
        if matches!(process.try_wait(), Ok(None)) {
            proc::signal_process(process.id() as i32, proc::SIGTERM);
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(30)
                && matches!(process.try_wait(), Ok(None))
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            if matches!(process.try_wait(), Ok(None)) {
                proc::signal_process(process.id() as i32, proc::SIGKILL);
                let _ = process.wait();
            }
        }
    }
    let _ = std::io::stderr().flush();
    result
}

pub fn main(command: &str, args: &[String]) -> Result<()> {
    match command {
        "native-bootstrap" => outer(args),
        "native-root" => root_main(args),
        "native-daemon" => daemon_main(args),
        _ => Err("unknown bootstrap mode".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_runs_the_verified_controller_and_retains_only_on_regular_evidence() {
        let argv = retention_command(
            Path::new("/var/lib/busbar-native/boundary-3-19/controller/busbar-ci"),
            Path::new("/home/fleeting/builds/x"),
            &"a".repeat(40),
            Path::new("/home/fleeting/builds/x/boundary-evidence/retained.json"),
        );
        assert_eq!(
            argv,
            strings(&[
                "/var/lib/busbar-native/boundary-3-19/controller/busbar-ci",
                "retention",
                "--policy",
                &"a".repeat(40),
                "--checkout",
                "/home/fleeting/builds/x",
                "--output",
                "/home/fleeting/builds/x/boundary-evidence/retained.json",
            ])
        );
        assert_eq!(RETAINABLE, ["native-qualification", "core-conformance"]);
        let root = std::env::temp_dir().join(format!("busbar-ci-retention-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let output = root.join("retained.json");
        let decide = |script: &str| {
            let _ = fs::remove_file(&output);
            let argv = strings(&["/bin/sh", "-c", script, "retention", &path_text(&output)]);
            decide_retention(&argv, &output)
        };
        // Retained: exit 0 with a regular evidence file.
        assert_eq!(decide("printf '{}' > \"$1\""), Ok(true));
        // Fresh: nonzero without evidence, or exit 0 without evidence.
        assert_eq!(decide("exit 1"), Ok(false));
        assert_eq!(decide("exit 0"), Ok(false));
        // Evidence without retaining, or a symlink, fails the job.
        assert!(decide("printf '{}' > \"$1\"; exit 1").is_err());
        assert!(decide("ln -s /etc/hosts \"$1\"").is_err());
        assert!(decide("mkdir \"$1\"").is_err());
        let _ = fs::remove_dir_all(&output);
        // Other kinds never consult retention.
        assert_eq!(
            retained(&root, &root, &"a".repeat(40), "native-isolation-diagnostic"),
            Ok(false)
        );
        fs::remove_dir_all(&root).unwrap();
    }

    fn environment() -> Env {
        [
            ("CI_SERVER_URL", "https://git.getbusbar.dev"),
            ("CI_SERVER_HOST", "git.getbusbar.dev"),
            ("CI_PROJECT_ID", "3"),
            ("CI_JOB_ID", "19"),
            ("CI_PIPELINE_ID", "11"),
            ("CI_PROJECT_PATH", "GetBusbar/busbar"),
            ("CI_JOB_NAME", "native-isolation-diagnostic"),
            ("CI_COMMIT_SHA", &"a".repeat(40)),
            ("CI_JOB_TOKEN", "fixture-token"),
            ("CI_CONFIG_REF_URI", &format!("git.getbusbar.dev/GetBusbar/busbar//ci/architecture-pipeline.yml@GetBusbar/busbar:{}@refs/heads/diagnostic", "b".repeat(40))),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
    }

    fn with(key: &str, value: &str) -> Env {
        let mut env = environment();
        env.insert(key.into(), value.into());
        env
    }

    #[test]
    fn configuration_identity_is_fixed_and_untrusted_environment_is_dropped() {
        let mut env = environment();
        for (k, v) in [
            ("LD_PRELOAD", "/candidate.so"),
            ("PYTHONPATH", "/candidate"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
        ] {
            env.insert(k.into(), v.into());
        }
        let selected = ci_environment(&env).unwrap();
        assert_eq!(approved_revision(&selected).unwrap(), "b".repeat(40));
        assert!(
            !selected.contains_key("LD_PRELOAD")
                && !selected.contains_key("PYTHONPATH")
                && !selected.contains_key("AWS_SECRET_ACCESS_KEY")
        );
        for (key, value) in [
            ("CI_JOB_NAME", "candidate-command"),
            ("CI_SERVER_URL", "https://attacker.invalid"),
            ("CI_JOB_ID", "../escape"),
            ("CI_JOB_ID", "019"),
            ("CI_PROJECT_PATH", "Other/project"),
            ("CI_COMMIT_SHA", "dev"),
            ("CI_JOB_TOKEN", ""),
        ] {
            assert!(ci_environment(&with(key, value)).is_err(), "{key}={value}");
        }
    }

    #[test]
    fn bad_configuration_uris_are_rejected() {
        let good = environment()["CI_CONFIG_REF_URI"].clone();
        let revision = |uri: &str, project: &str| {
            let mut env = with("CI_CONFIG_REF_URI", uri);
            env.insert("CI_PROJECT_PATH".into(), project.into());
            approved_revision(&env)
        };
        assert_eq!(revision(&good, "GetBusbar/busbar").unwrap(), "b".repeat(40));
        assert_eq!(
            revision(&format!("https://{good}"), "GetBusbar/busbar").unwrap(),
            "b".repeat(40)
        );
        let consumer = good.replace("GetBusbar/busbar//", "BusbarInc/busbar-auth-scim//");
        assert!(revision(&consumer, "BusbarInc/busbar-auth-scim").is_ok());
        for bad in [
            good.replace(&"b".repeat(40), "dev"),
            good.replace(&"b".repeat(40), &"b".repeat(39)),
            good.replace(&"b".repeat(40), &"B".repeat(40)),
            good.replace("@GetBusbar/busbar:", "@BusbarInc/other:"),
            good.replace("git.getbusbar.dev/", "other.example/"),
            good.replace("/ci/architecture-pipeline.yml", "/candidate.yml"),
            good.replace("@refs/heads/", "@refs/tags/"),
            good.replace("@refs/heads/diagnostic", "@refs/heads/"),
            format!("{good}\n"),
            format!("{good} x"),
            format!("http://{good}"),
        ] {
            assert!(revision(&bad, "GetBusbar/busbar").is_err(), "{bad}");
        }
        assert!(revision(&good, "GetBusbar/other").is_err());
    }

    #[test]
    fn plugin_host_binding_cannot_float_or_disappear() {
        let mut env = with("CI_PROJECT_PATH", "GetBusbar/busbar-plane-mcp");
        env.insert("CI_JOB_NAME".into(), "native-qualification".into());
        assert!(ci_environment(&env).unwrap_err().contains("immutable host"));
        env.insert("BUSBAR_ADMISSION_CORE_REVISION".into(), "dev".into());
        assert!(ci_environment(&env).unwrap_err().contains("immutable"));
        env.insert("BUSBAR_ADMISSION_CORE_REVISION".into(), "c".repeat(40));
        assert_eq!(
            ci_environment(&env).unwrap()["BUSBAR_ADMISSION_CORE_REVISION"],
            "c".repeat(40)
        );
    }

    #[test]
    fn privilege_is_only_the_verified_fixed_controller_entry() {
        let argv = entry_command(
            Path::new("/var/lib/busbar-native/boundary-3-19/controller/busbar-ci"),
            &"a".repeat(64),
            &format!("sha256:{}", "b".repeat(64)),
            "job-19",
        );
        let nsenter = argv.iter().position(|a| a == "/usr/bin/nsenter").unwrap();
        assert!(
            argv.contains(&"--privileged".to_owned())
                && argv.contains(&"--network=none".to_owned())
        );
        assert!(
            !argv.contains(&"--env".to_owned())
                && !argv[..nsenter]
                    .iter()
                    .any(|a| a == "--mount" || a.starts_with("-v"))
        );
        assert!(argv[nsenter..].contains(&"--cgroup".to_owned()));
        assert!(argv.contains(&"--wd".to_owned()) && !argv.contains(&"--wd=/".to_owned()));
        let joined = argv.join(" ");
        assert!(
            !joined.contains("CI_JOB_TOKEN")
                && !joined.contains("fixture-token")
                && !joined.contains("candidate")
        );
        assert!(ENTRY_SCRIPT.contains("sha256sum -c -") && ENTRY_SCRIPT.contains("native-root"));
    }

    #[test]
    fn entry_script_executes_only_a_matching_root_only_copy() {
        // Exercise the actual script with a substitute prefix and binary.
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("busbar-ci-entry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("fake");
        fs::write(&binary, "#!/bin/sh\necho \"ran $1 $2\"; ls \"$2\"\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let script = ENTRY_SCRIPT.replace(
            "/run/busbar-ci-root.",
            &format!("{}/entry.", root.display()),
        );
        let digest = sha256::file(&binary).unwrap();
        let sha_tool =
            if Path::new("/usr/bin/sha256sum").exists() || Path::new("/sbin/sha256sum").exists() {
                ""
            } else {
                "skip"
            };
        if sha_tool == "skip" {
            fs::remove_dir_all(&root).unwrap();
            return;
        }
        let run = |expected: &str| {
            std::process::Command::new("/bin/sh")
                .args(["-c", &script, "entry", binary.to_str().unwrap(), expected])
                .output()
                .unwrap()
        };
        let ok = run(&digest);
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let stdout = String::from_utf8_lossy(&ok.stdout);
        assert!(stdout.starts_with("ran native-root ") && stdout.contains("busbar-ci"));
        let bad = run(&"0".repeat(64));
        assert!(!bad.status.success());
        assert!(String::from_utf8_lossy(&bad.stderr).contains("differs"));
        let leftovers = fs::read_dir(&root)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("entry.")
            })
            .count();
        assert_eq!(
            leftovers, 1,
            "only the successful run leaves its directory (removed by native-root)"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn controller_refuses_a_private_mount_or_cgroup_namespace() {
        for changed in ["mnt", "cgroup"] {
            let inode = |path: &str| {
                Ok(if path == format!("/proc/self/ns/{changed}") {
                    2
                } else {
                    1
                })
            };
            assert!(
                require_host_controller(0, &inode)
                    .unwrap_err()
                    .contains(&format!("host {changed} namespace"))
            );
        }
        require_host_controller(0, &|_| Ok(1)).unwrap();
        assert!(
            require_host_controller(1001, &|_| Ok(1))
                .unwrap_err()
                .contains("host root")
        );
    }

    #[test]
    fn candidate_and_collector_identities_endpoints_and_storage_are_distinct() {
        let root = Path::new("/srv/busbar-native-ci/job-19");
        let config = runtime_configuration(
            root,
            "unix:///private.sock",
            &format!("image@sha256:{}", "a".repeat(64)),
            false,
        );
        let isolation = config.at("isolation");
        assert_eq!(isolation.at("storage_bytes").as_u64(), Some(24 << 30));
        assert_eq!(
            isolation.at("storage_reserve_bytes").as_u64(),
            Some(6 << 30)
        );
        assert_eq!(isolation.at("storage_kind").as_str(), Some("loop-ext4"));
        assert_ne!(
            config.at("docker_host"),
            config.at("collector").at("docker_host")
        );
        assert_eq!(
            config.at("collector").at("uid").as_u64(),
            Some(isolation.at("uid_map").index(1).as_u64().unwrap() + 1001)
        );
        assert_eq!(
            config.at("collector").at("gid").as_u64(),
            Some(isolation.at("gid_map").index(1).as_u64().unwrap() + 1002)
        );
        assert!(config.at("environment").get("CI_JOB_TOKEN").is_none());
        let diagnostic = runtime_configuration(root, "unix:///private.sock", "x", true);
        assert_eq!(
            diagnostic.at("isolation").at("storage_kind").as_str(),
            Some("tmpfs")
        );
        assert!(diagnostic.at("isolation").get("storage_image").is_none());
        isolation::validate_configuration(isolation).unwrap();
        // Python json.dumps(config, sort_keys=True) form, as before.
        assert!(json::dumps(&config, true).starts_with(
            "{\"collector\": {\"docker_host\": \"unix:///var/run/docker.sock\", \"gid\": 525290"
        ));
    }

    #[test]
    fn subordinate_ranges_cannot_overlap_and_are_appended_once() {
        subordinate_rows("ubuntu:100000:65536\nother:589824:65536\n").unwrap();
        assert!(subordinate_rows("ubuntu:500000:65536\n").is_err());
        assert!(subordinate_rows("busbar-ci-remap:1:1\n").is_err());
        assert!(subordinate_rows("broken\n").is_err());
        assert_eq!(appended(&None), b"busbar-ci-remap:524288:65536\n");
        assert_eq!(
            appended(&Some(b"a:1:2\n\n".to_vec())),
            b"a:1:2\nbusbar-ci-remap:524288:65536\n"
        );
        assert_eq!(
            appended(&Some(Vec::new())),
            b"busbar-ci-remap:524288:65536\n"
        );
    }

    #[test]
    fn missing_daemon_and_disposal_failures_fail_closed() {
        let ready = wait_ready(
            Duration::from_millis(100),
            Duration::from_millis(10),
            &mut || true,
            &mut || None,
        );
        assert!(ready.unwrap_err().contains("did not become ready"));
        let exited = wait_ready(
            Duration::from_secs(5),
            Duration::from_millis(10),
            &mut || false,
            &mut || None,
        );
        assert!(exited.unwrap_err().contains("supervisor exited"));
        let info = wait_ready(
            Duration::from_secs(5),
            Duration::from_millis(10),
            &mut || true,
            &mut || Some(Value::Null),
        );
        assert_eq!(info.unwrap(), Value::Null);
        assert!(disposal_confirmed(Some(false), true));
        assert!(!disposal_confirmed(Some(true), true), "containers remain");
        assert!(
            !disposal_confirmed(None, true),
            "daemon could not list or remove"
        );
        assert!(disposal_confirmed(None, false), "no workload ever started");
        assert_eq!(receipt_status(true, true, false), "pass");
        assert_eq!(receipt_status(true, false, false), "failed");
        assert_eq!(receipt_status(true, true, true), "failed");
        assert_eq!(receipt_status(false, true, false), "failed");
    }

    #[test]
    fn job_parent_allows_remapped_traversal_and_copies_preserve_links() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("busbar-ci-copy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let source = root.join("source");
        fs::create_dir_all(source.join("sub")).unwrap();
        fs::write(source.join("sub/file"), "x").unwrap();
        fs::set_permissions(source.join("sub/file"), fs::Permissions::from_mode(0o751)).unwrap();
        std::os::unix::fs::symlink("sub/file", source.join("link")).unwrap();
        copy_tree(&source, &root.join("copy"), true, false).unwrap();
        assert_eq!(
            fs::read_link(root.join("copy/link")).unwrap(),
            Path::new("sub/file")
        );
        assert_eq!(
            fs::metadata(root.join("copy/sub/file")).unwrap().mode() & 0o777,
            0o751
        );
        assert!(
            copy_tree(&source, &root.join("evidence"), false, false)
                .unwrap_err()
                .contains("indirect")
        );
        fs::create_dir(root.join("merge")).unwrap();
        fs::remove_file(source.join("link")).unwrap();
        copy_tree(&source, &root.join("merge"), false, true).unwrap();
        assert!(root.join("merge/sub/file").is_file());
        // Mode 0711 on the job directory; private children keep their own modes.
        if proc::euid() == 0 {
            // Every ancestor must be root-owned and not group/other writable,
            // which rules out sticky temporary directories.
            assert!(
                root_directory(&root.join("job"), true)
                    .unwrap_err()
                    .contains("root-owned")
            );
            let job = PathBuf::from(format!("/run/busbar-ci-test-{}/job", std::process::id()));
            job_directory(&job).unwrap();
            assert_eq!(fs::metadata(&job).unwrap().mode() & 0o777, 0o711);
            fs::create_dir(job.join("private")).unwrap();
            assert!(job_directory(&job).unwrap_err().contains("not fresh"));
            fs::remove_dir_all(job.parent().unwrap()).unwrap();
        } else {
            assert!(
                root_directory(&root.join("job"), true)
                    .unwrap_err()
                    .contains("root-owned")
            );
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn trusted_checkout_must_be_the_exact_clean_revision() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("busbar-ci-git-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let sh = |script: &str| {
            assert!(
                std::process::Command::new("/bin/sh")
                    .current_dir(&root)
                    .args(["-c", script])
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "{script}"
            );
        };
        sh(
            "git init -q . && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m one && echo a > f && git add f && git -c user.name=t -c user.email=t@t commit -q -m two",
        );
        let head = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).unwrap())
            .unwrap()
            .trim()
            .to_owned();
        if !Path::new(GIT).exists() {
            fs::remove_dir_all(&root).unwrap();
            return;
        }
        verify_trusted(&root, &head).unwrap();
        assert!(
            verify_trusted(&root, &"0".repeat(40))
                .unwrap_err()
                .contains("revision differs")
        );
        sh("echo b > f");
        assert!(
            verify_trusted(&root, &head)
                .unwrap_err()
                .contains("modifications")
        );
        sh("git checkout -q f && echo n > new");
        assert!(
            verify_trusted(&root, &head)
                .unwrap_err()
                .contains("untracked")
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
