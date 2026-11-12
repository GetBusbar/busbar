//! Trusted prebuilt plugin dependency units: produced once, restored read-only
//! (the Python controller's `native_dep_cache`, byte-compatible identities).
//!
//! Producer: core's protected dev push, after every qualification job. For each
//! product pinned in core's `scripts/ci-product-pins.json` it snapshots the
//! pinned manifest graph and lock with every Rust source replaced by an inert
//! stub, runs the exact plugin step commands and the architecture shipping probe
//! in the ordinary confinement, strips every path (workspace) unit and publishes
//! the remaining registry/Git units to core's generic package registry under a
//! content identity. No candidate code exists in that tree.
//!
//! Consumer: plugin native qualification computes the same identity from its
//! candidate lock. Absence, an identity mismatch, missing provenance or any
//! digest mismatch builds from scratch exactly as before. A hit is extracted
//! into a controller-only directory that no candidate invocation mounts; each
//! Cargo target gets a fresh writable copy. Cargo's own fingerprints still
//! rebuild every unit whose features, profile, flags or sources differ.
use super::Q;
use super::sp::{self, Dict, R};
use crate::confine;
use crate::fetch;
use crate::json::{self, Value, object};
use crate::sha256;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime};

pub const SCHEMA: &str = "busbar.plugin-dependency-units/1";
pub const PACKAGE: &str = "busbar-plugin-dependency-units";
pub const PROJECT_API: &str = "https://github.com/api/v4/projects/3";
pub const PRODUCER_JOB: &str = "plugin-dependency-units";
/// The producer runs as GitLab `parallel: PRODUCER_SHARDS`; the server names each
/// instance "plugin-dependency-units K/N". Every product belongs to exactly one
/// shard by a stable digest of its repository name (the same assignment as the
/// Python controller), so one product is only ever built by one shard index, and
/// each shard index has its own resource_group: consecutive dev pushes never
/// write one package file twice.
pub const PRODUCER_SHARDS: u64 = 8;

/// 0-based shard of a server-named producer job, or None for any other job.
pub fn producer_shard(job_name: &str) -> Option<u64> {
    let rest = job_name.strip_prefix(PRODUCER_JOB)?.strip_prefix(' ')?;
    let (index, total) = rest.split_once('/')?;
    if total != PRODUCER_SHARDS.to_string()
        || index.starts_with('0')
        || !index.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let index: u64 = index.parse().ok()?;
    (1..=PRODUCER_SHARDS).contains(&index).then(|| index - 1)
}

/// `int(sha256(repo).hexdigest(), 16) % PRODUCER_SHARDS`; the shard count
/// divides 256, so only the final digest byte decides it.
pub fn product_shard(repo: &str) -> u64 {
    let digest = sha256::hex(repo.as_bytes());
    u64::from_str_radix(&digest[62..], 16).expect("sha256 hex") % PRODUCER_SHARDS
}
/// Cargo fingerprints the absolute source path of every registry and Git unit;
/// every confined invocation's private Cargo home is mounted at this one path.
pub const CARGO_HOME_PATH: &str = confine::INVOCATION_CARGO_HOME;
pub const STUB: &[u8] = b"#![allow(dead_code)]\nfn main() {}\n";
pub const MANIFEST: &str = "manifest.json";
pub const MAX_MANIFEST_BYTES: u64 = 64 << 20;
pub const MAX_ARCHIVE_BYTES: u64 = 6 << 30;
const GZIP: &str = "/usr/bin/gzip";
/// Controller environment that reaches rustc or Cargo's unit identity; absent
/// keys are recorded as null so a later added flag changes the identity.
pub const COMPILE_ENV: [&str; 11] = [
    "RUSTUP_TOOLCHAIN",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_PROFILE_DEV_DEBUG",
    "CARGO_PROFILE_TEST_DEBUG",
    "CARGO_BUILD_TARGET",
    "CARGO_INCREMENTAL",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
];

/// A reason to build from scratch; never a qualification failure.
pub type Fallback = String;

fn unavailable<T>(message: impl Into<String>) -> Result<T, Fallback> {
    Err(message.into())
}

fn need(ok: bool, message: &str) -> Result<(), Fallback> {
    if ok { Ok(()) } else { unavailable(message) }
}

fn io<T>(value: std::io::Result<T>, path: &Path) -> Result<T, Fallback> {
    value.map_err(|e| format!("{}: {e}", path.display()))
}

/// The dependency-compiling plugin steps of `plugins::qualify_plugin`.
/// plugin-runtime is the build half of `cargo nextest run` (`cargo test --no-run`).
pub fn plugin_commands(wrapper: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        (
            "clippy",
            sp::strings(&[
                "cargo",
                "clippy",
                "--locked",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ]),
        ),
        (
            "native-library",
            sp::strings(&[
                "cargo",
                "build",
                "--locked",
                "-p",
                wrapper,
                "--all-features",
                "--lib",
            ]),
        ),
        (
            "plugin-runtime",
            sp::strings(&[
                "cargo",
                "test",
                "--locked",
                "--workspace",
                "--all-features",
                "--no-run",
            ]),
        ),
        (
            "plugin-doctests",
            sp::strings(&[
                "cargo",
                "test",
                "--locked",
                "--workspace",
                "--all-features",
                "--doc",
                "--no-fail-fast",
            ]),
        ),
    ]
}

fn commands_value(wrapper: &str) -> Value {
    Value::Array(
        plugin_commands(wrapper)
            .into_iter()
            .map(|(name, argv)| {
                Value::Array(vec![
                    name.into(),
                    Value::Array(argv.into_iter().map(Value::from).collect()),
                ])
            })
            .collect(),
    )
}

/// Everything outside the manifests that decides a dependency unit's bytes.
pub fn identity(
    repository: &str,
    lock_sha256: &str,
    image: &str,
    env: &Dict,
    wrapper: &str,
) -> Value {
    let environment = COMPILE_ENV
        .iter()
        .map(|k| ((*k).to_owned(), env.get(k).map_or(Value::Null, Value::from)))
        .collect();
    object([
        ("schema", SCHEMA.into()),
        ("repository", repository.into()),
        ("lock_sha256", lock_sha256.into()),
        ("image", image.into()),
        ("target", "x86_64-unknown-linux-gnu".into()),
        ("cargo_home", CARGO_HOME_PATH.into()),
        ("environment", Value::Object(environment)),
        (
            "commands_sha256",
            sha256::hex(&json::encoded(&commands_value(wrapper))).into(),
        ),
        ("wrapper", wrapper.into()),
    ])
}

pub fn key(identity: &Value) -> String {
    sha256::hex(&json::encoded(identity))
}

/// Whether a target entry (`<name>-<16 hex>[.ext]`, optionally `lib`-prefixed)
/// belongs to one of `names`. Both the plain and `lib`-stripped stems count.
pub fn unit_matches(entry: &str, names: &std::collections::BTreeSet<String>) -> bool {
    let stem = entry.split('.').next().unwrap_or(entry);
    let base = stem
        .rsplit_once('-')
        .filter(|(_, h)| {
            h.len() == 16
                && h.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .map_or(stem, |(b, _)| b);
    names.contains(base) || base.strip_prefix("lib").is_some_and(|b| names.contains(b))
}

fn remove(path: &Path) -> Result<(), Fallback> {
    let meta = io(std::fs::symlink_metadata(path), path)?;
    if meta.is_dir() {
        io(std::fs::remove_dir_all(path), path)
    } else {
        io(std::fs::remove_file(path), path)
    }
}

fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>, Fallback> {
    let mut rows: Vec<PathBuf> = io(std::fs::read_dir(directory), directory)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    rows.sort();
    Ok(rows)
}

/// Remove every unit, output and cache of a path package; keep registry/Git units.
pub fn strip_path_units(target: &Path, path_packages: &[String]) -> Result<(), Fallback> {
    let mut names = std::collections::BTreeSet::new();
    for package in path_packages {
        names.insert(package.clone());
        names.insert(package.replace('-', "_"));
    }
    for name in [".rustc_info.json", "CACHEDIR.TAG", ".cargo-lock"] {
        let path = target.join(name);
        if std::fs::symlink_metadata(&path).is_ok() {
            remove(&path)?;
        }
    }
    for profile in sorted_entries(target)? {
        let meta = io(std::fs::symlink_metadata(&profile), &profile)?;
        if !meta.is_dir() {
            continue;
        }
        for entry in sorted_entries(&profile)? {
            let name = entry
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let meta = io(std::fs::symlink_metadata(&entry), &entry)?;
            if matches!(name.as_str(), ".fingerprint" | "deps" | "build") && meta.is_dir() {
                for unit in sorted_entries(&entry)? {
                    let unit_name = unit.file_name().unwrap_or_default().to_string_lossy();
                    if unit_matches(&unit_name, &names) {
                        remove(&unit)?;
                    }
                }
            } else {
                remove(&entry)?;
            }
        }
    }
    Ok(())
}

/// Regular files and directories only; sha256 of every file, sorted.
pub fn inventory(root: &Path) -> Result<BTreeMap<String, String>, Fallback> {
    fn walk(
        root: &Path,
        directory: &Path,
        out: &mut BTreeMap<String, String>,
    ) -> Result<(), Fallback> {
        for path in sorted_entries(directory)? {
            let meta = io(std::fs::symlink_metadata(&path), &path)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "inventory path escapes its root".to_owned())?
                .to_string_lossy()
                .into_owned();
            if meta.is_dir() {
                walk(root, &path, out)?;
            } else if meta.is_file() && meta.nlink() == 1 {
                out.insert(relative, sha256::file(&path)?);
            } else {
                return unavailable(format!(
                    "dependency units contain a non-regular entry: {relative}"
                ));
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn tar_header(name: &str, kind: u8, size: u64, mode: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let field = |block: &mut [u8; 512], offset: usize, width: usize, value: u64| {
        let text = format!("{:0w$o}\0", value, w = width - 1);
        block[offset..offset + width].copy_from_slice(text.as_bytes());
    };
    let header = |name: &str, kind: u8, size: u64, mode: u32| {
        let mut block = [0u8; 512];
        let bytes = name.as_bytes();
        block[..bytes.len().min(100)].copy_from_slice(&bytes[..bytes.len().min(100)]);
        field(&mut block, 100, 8, mode as u64);
        field(&mut block, 108, 8, 0);
        field(&mut block, 116, 8, 0);
        field(&mut block, 124, 12, size);
        field(&mut block, 136, 12, 0);
        block[148..156].copy_from_slice(b"        ");
        block[156] = kind;
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        let sum: u32 = block.iter().map(|b| *b as u32).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        block
    };
    if name.len() > 100 {
        // PAX extended header: "<len> path=<name>\n", length counting itself.
        let body = format!(" path={name}\n");
        let mut length = body.len() + 1;
        while format!("{length}{body}").len() != length {
            length += 1;
        }
        let record = format!("{length}{body}");
        out.extend_from_slice(&header("././@PaxHeader", b'x', record.len() as u64, 0o644));
        out.extend_from_slice(record.as_bytes());
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend_from_slice(&header(name, kind, size, mode));
    out
}

/// Deterministic gzip tar (sorted, fixed owner, time and mode) through `gzip -n`.
pub fn pack(root: &Path, archive: &Path) -> Result<BTreeMap<String, String>, Fallback> {
    let files = inventory(root)?;
    let output = io(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(archive),
        archive,
    )?;
    let mut child = io(
        Command::new(GZIP)
            .args(["-n", "-3", "-c"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(output)
            .spawn(),
        Path::new(GZIP),
    )?;
    let mut input = child.stdin.take().expect("gzip stdin");
    let mut directories = std::collections::BTreeSet::new();
    for name in files.keys() {
        let mut parent = Path::new(name).parent();
        while let Some(p) = parent.filter(|p| !p.as_os_str().is_empty()) {
            directories.insert(p.to_string_lossy().into_owned());
            parent = p.parent();
        }
    }
    let written: Result<(), Fallback> = (|| {
        for name in &directories {
            io(input.write_all(&tar_header(name, b'5', 0, 0o755)), archive)?;
        }
        for name in files.keys() {
            let path = root.join(name);
            let size = io(std::fs::metadata(&path), &path)?.len();
            io(
                input.write_all(&tar_header(name, b'0', size, 0o644)),
                archive,
            )?;
            let mut source = io(File::open(&path), &path)?;
            let copied = io(std::io::copy(&mut source, &mut input), &path)?;
            need(copied == size, "dependency unit changed while packing")?;
            let padding = (512 - size % 512) % 512;
            io(input.write_all(&vec![0u8; padding as usize]), archive)?;
        }
        io(input.write_all(&[0u8; 1024]), archive)
    })();
    drop(input);
    let status = io(child.wait(), Path::new(GZIP))?;
    written?;
    need(
        status.success(),
        "gzip failed while packing dependency units",
    )?;
    Ok(files)
}

/// Extract only regular files and directories at verified relative paths; every
/// file digest must equal the manifest inventory exactly.
pub fn unpack(
    archive: &Path,
    destination: &Path,
    expected: &BTreeMap<String, String>,
) -> Result<(), Fallback> {
    io(std::fs::create_dir(destination), destination)?;
    io(
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700)),
        destination,
    )?;
    let source = io(File::open(archive), archive)?;
    let mut child = io(
        Command::new(GZIP)
            .args(["-d", "-c"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(source)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn(),
        Path::new(GZIP),
    )?;
    let stdout = child.stdout.take().expect("gzip stdout");
    let mut reader = crate::tar::Reader::new(stdout);
    let mut seen = BTreeMap::new();
    let result: Result<(), Fallback> = (|| {
        while let Some(entry) = reader.next()? {
            let relative = Path::new(&entry.name);
            need(
                !entry.name.is_empty()
                    && !relative.is_absolute()
                    && relative
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "dependency archive path escapes its root",
            )?;
            let path = destination.join(relative);
            if entry.kind == b'5' {
                io(std::fs::create_dir_all(&path), &path)?;
                continue;
            }
            need(
                entry.is_file()
                    && expected.contains_key(&entry.name)
                    && !seen.contains_key(&entry.name),
                &format!("dependency archive entry is unexpected: {}", entry.name),
            )?;
            if let Some(parent) = path.parent() {
                io(std::fs::create_dir_all(parent), parent)?;
            }
            let mut output = io(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path),
                &path,
            )?;
            let mut hash = sha256::Sha256::new();
            let mut data = reader.data(entry.size);
            let mut buffer = vec![0u8; 1 << 20];
            loop {
                let n = io(data.read(&mut buffer), archive)?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
                io(output.write_all(&buffer[..n]), &path)?;
            }
            seen.insert(entry.name.clone(), hash.hex());
        }
        Ok(())
    })();
    drop(reader);
    let status = io(child.wait(), Path::new(GZIP))?;
    result?;
    need(status.success(), "dependency archive is not valid gzip")?;
    need(
        &seen == expected,
        "dependency archive inventory differs from its manifest",
    )
}

fn chmod_tree(root: &Path, file_mode: u32, dir_mode: u32) -> Result<(), Fallback> {
    for path in sorted_entries(root)? {
        let meta = io(std::fs::symlink_metadata(&path), &path)?;
        if meta.is_dir() {
            chmod_tree(&path, file_mode, dir_mode)?;
            io(
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(dir_mode)),
                &path,
            )?;
        } else if meta.is_file() {
            io(
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(file_mode)),
                &path,
            )?;
        }
    }
    Ok(())
}

/// Read-only bits as well; the real boundary is that no candidate mounts it.
pub fn seal(root: &Path) -> Result<(), Fallback> {
    chmod_tree(root, 0o444, 0o555)?;
    io(
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o555)),
        root,
    )
}

/// Remove a (possibly sealed) seed.
pub fn discard(seed: Option<&Path>) {
    if let Some(seed) = seed.filter(|s| s.exists()) {
        fn open(path: &Path) {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
            if let Ok(rows) = std::fs::read_dir(path) {
                for row in rows.flatten() {
                    if row.file_type().is_ok_and(|t| t.is_dir()) {
                        open(&row.path());
                    }
                }
            }
        }
        open(seed);
        let _ = std::fs::remove_dir_all(seed);
    }
}

/// A fresh writable target copy of the read-only seed. Every copied file gets
/// one current timestamp, so restored units postdate the job's freshly
/// collected (exact locked) sources and Cargo's mtime checks see one tree.
pub fn install(seed: &Path, destination: &Path, now: Option<SystemTime>) -> Result<(), Fallback> {
    need(
        std::fs::symlink_metadata(destination).is_err(),
        "dependency target destination already exists",
    )?;
    let stamp = now.unwrap_or_else(SystemTime::now);
    fn copy(source: &Path, destination: &Path, stamp: SystemTime) -> Result<(), Fallback> {
        io(std::fs::create_dir(destination), destination)?;
        io(
            std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755)),
            destination,
        )?;
        for path in sorted_entries(source)? {
            let meta = io(std::fs::symlink_metadata(&path), &path)?;
            let target = destination.join(path.file_name().unwrap_or_default());
            if meta.is_dir() {
                copy(&path, &target, stamp)?;
            } else if meta.is_file() {
                io(std::fs::copy(&path, &target), &path)?;
                // Cargo runs a restored build script again whenever its rerun-if
                // inputs differ; the sealed seed and the archive carry no mode bits.
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let mode = if build_script(&name) { 0o755 } else { 0o644 };
                io(
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)),
                    &target,
                )?;
                let file = io(
                    std::fs::OpenOptions::new().write(true).open(&target),
                    &target,
                )?;
                io(file.set_modified(stamp), &target)?;
            } else {
                return unavailable("dependency seed contains a non-regular entry");
            }
        }
        Ok(())
    }
    copy(seed, destination, stamp)
}

/// A compiled build script executable: build/<unit>/build-script-<name>[-<hash>].
pub fn build_script(name: &str) -> bool {
    (name.starts_with("build-script-") || name.starts_with("build_script_")) && !name.contains('.')
}

/// The controller-owned seed must lie outside every candidate-mounted root.
pub fn readonly_seed(path: &Path, roots: &confine::Roots) -> Result<PathBuf, Fallback> {
    let resolved = sp::resolve(path);
    need(
        std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()),
        "dependency seed is not a directory",
    )?;
    for (name, root) in [
        ("candidate", &roots.candidate),
        ("checkout", &roots.checkout),
        ("harness", &roots.harness),
        ("trusted", &roots.trusted),
    ] {
        let root = sp::resolve(root);
        need(
            !resolved.starts_with(&root) && !root.starts_with(&resolved),
            &format!("dependency seed is inside a candidate-mounted root: {name}"),
        )?;
    }
    Ok(resolved)
}

/// Non-member units Cargo compiled, from its own human status lines.
pub fn rebuilt_dependency_units(
    text: &str,
    members: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.len() == line.len() {
            continue;
        }
        let mut words = trimmed.split_whitespace();
        let (Some(verb), Some(name), Some(version)) = (words.next(), words.next(), words.next())
        else {
            continue;
        };
        if matches!(verb, "Compiling" | "Checking" | "Documenting")
            && let Some(version) = version.strip_prefix('v')
            && !members.contains(name)
        {
            rows.push(format!("{name} v{version}"));
        }
    }
    rows
}

// ---- GitLab generic package registry -------------------------------------------------

pub trait Registry {
    /// `Ok(None)` is HTTP 404: the file does not exist.
    fn read(&mut self, version: &str, name: &str, limit: u64) -> Result<Option<Vec<u8>>, Fallback>;
    fn json(&mut self, path: &str) -> Result<Value, Fallback>;
    fn download(
        &mut self,
        version: &str,
        name: &str,
        destination: &Path,
        size: u64,
        sha256: &str,
    ) -> Result<(), Fallback>;
    fn upload(&mut self, version: &str, name: &str, path: &Path) -> Result<(), Fallback>;
}

pub struct GitLab {
    pub token: String,
    /// Generic package name; dependency units unless a caller names another.
    pub package: &'static str,
}

impl GitLab {
    pub fn new(token: String) -> GitLab {
        GitLab {
            token,
            package: PACKAGE,
        }
    }
    fn file_url(&self, version: &str, name: &str) -> String {
        format!(
            "{PROJECT_API}/packages/generic/{}/{version}/{name}",
            self.package
        )
    }
    fn get(&self, url: &str, limit: u64) -> Result<Option<Vec<u8>>, Fallback> {
        match fetch::get(url, &format!("JOB-TOKEN:{}", self.token), limit)? {
            fetch::Got::Exceeded => unavailable("package registry response exceeds its bound"),
            fetch::Got::Done { code: 404, .. } => Ok(None),
            fetch::Got::Done {
                code: 200,
                exit: 0,
                body,
            } => Ok(Some(body)),
            fetch::Got::Done { code, .. } => {
                unavailable(format!("package registry refused GET (HTTP {code})"))
            }
        }
    }
}

impl Registry for GitLab {
    fn read(&mut self, version: &str, name: &str, limit: u64) -> Result<Option<Vec<u8>>, Fallback> {
        self.get(&self.file_url(version, name), limit)
    }
    fn json(&mut self, path: &str) -> Result<Value, Fallback> {
        let body = self
            .get(&format!("{PROJECT_API}{path}"), MAX_MANIFEST_BYTES)?
            .ok_or("package registry API path is absent")?;
        json::parse(&body)
    }
    fn download(
        &mut self,
        version: &str,
        name: &str,
        destination: &Path,
        size: u64,
        sha256: &str,
    ) -> Result<(), Fallback> {
        fetch::fetch(
            &self.file_url(version, name),
            &self.token,
            destination,
            size,
            sha256,
        )
    }
    fn upload(&mut self, version: &str, name: &str, path: &Path) -> Result<(), Fallback> {
        // The credential reaches curl only through its stdin configuration.
        let mut config = fetch::curl_config(
            &(self.file_url(version, name) + "?select=package_file"),
            &self.token,
        )?;
        config.push_str(&format!(
            "upload-file = \"{}\"\nmax-time = 1800\n",
            sp::text(path)
        ));
        let mut child = io(
            Command::new(fetch::CURL)
                .args(["--disable", "--config", "-"])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn(),
            Path::new(fetch::CURL),
        )?;
        let _ = child
            .stdin
            .take()
            .expect("curl stdin")
            .write_all(config.as_bytes());
        let mut stderr = String::new();
        let _ = child
            .stderr
            .take()
            .expect("curl stderr")
            .take(1 << 20)
            .read_to_string(&mut stderr);
        let _ = io(child.wait(), Path::new(fetch::CURL))?;
        let (code, _) = fetch::status(&stderr).map_err(|e| fetch::redact(&e, &self.token))?;
        need(
            (200..300).contains(&code),
            &format!("package upload refused (HTTP {code})"),
        )
    }
}

/// Only files written once by core's protected dev push producer pipeline.
pub fn provenance(
    registry: &mut dyn Registry,
    version: &str,
    manifest: &Value,
) -> Result<Value, Fallback> {
    provenance_in(registry, PACKAGE, version, manifest)
}

/// `provenance` for any generic package core's producer writes.
pub fn provenance_in(
    registry: &mut dyn Registry,
    package: &str,
    version: &str,
    manifest: &Value,
) -> Result<Value, Fallback> {
    let packages = registry.json(&format!(
        "/packages?package_type=generic&package_name={package}&package_version={version}"
    ))?;
    let matching: Vec<&Value> = packages
        .as_array()
        .unwrap_or(&[])
        .iter()
        .filter(|p| {
            p.at("name").as_str() == Some(package) && p.at("version").as_str() == Some(version)
        })
        .collect();
    need(
        matching.len() == 1,
        "dependency package is absent or ambiguous",
    )?;
    let id = matching[0]
        .at("id")
        .as_int()
        .ok_or("dependency package has no id")?;
    let producer = manifest.at("producer");
    let pipeline_id = producer
        .at("pipeline_id")
        .as_int()
        .ok_or("dependency producer has no pipeline")?;
    let commit = producer.at("commit").as_str().unwrap_or("");
    let files = registry.json(&format!("/packages/{id}/package_files?per_page=100"))?;
    let archive = manifest.at("archive");
    let expected = [
        (MANIFEST, None),
        (
            archive.at("name").as_str().unwrap_or(""),
            archive.at("sha256").as_str(),
        ),
    ];
    for (name, digest) in expected {
        let rows: Vec<&Value> = files
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter(|row| row.at("file_name").as_str() == Some(name))
            .collect();
        need(
            rows.len() == 1,
            &format!("dependency package file is absent or duplicated: {name}"),
        )?;
        let pipelines = rows[0].at("pipelines").as_array().unwrap_or(&[]);
        need(
            pipelines.len() == 1 && pipelines[0].at("id").as_int() == Some(pipeline_id),
            "dependency package file was not written by its producer pipeline",
        )?;
        let source = pipelines[0].at("source");
        need(
            pipelines[0].at("ref").as_str() == Some("dev")
                && pipelines[0].at("sha").as_str() == Some(commit)
                && (source.as_str() == Some("push") || *source == Value::Null),
            "dependency producer pipeline is not a protected dev push",
        )?;
        if let Some(digest) = digest {
            need(
                rows[0].at("file_sha256").as_str() == Some(digest),
                "registry digest differs from the dependency manifest",
            )?;
        }
    }
    Ok(object([
        ("package_id", Value::int(id)),
        ("pipeline_id", Value::int(pipeline_id)),
        ("commit", commit.into()),
    ]))
}

// ---- consumer ------------------------------------------------------------------------

pub fn wrapper_package(policy: &Value, repository: &str) -> Result<String, Fallback> {
    let rows: Vec<String> = policy
        .at("repositories")
        .at(repository)
        .at("packages")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .filter(|p| matches!(p.at("role").as_str(), Some("wrapper" | "combined")))
        .filter_map(|p| p.at("name").as_str().map(str::to_owned))
        .collect();
    need(
        rows.len() == 1,
        "dependency units need exactly one declared plugin export package",
    )?;
    Ok(rows[0].clone())
}

fn files_of(manifest: &Value) -> Result<BTreeMap<String, String>, Fallback> {
    let mut out = BTreeMap::new();
    for (name, digest) in manifest
        .at("files")
        .as_object()
        .ok_or("dependency manifest has no files")?
    {
        out.insert(
            name.clone(),
            digest.as_str().ok_or("invalid file digest")?.to_owned(),
        );
    }
    Ok(out)
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn restore_inner(
    q: &mut Q,
    registry: &mut dyn Registry,
    record: &mut Value,
    seed: &Path,
    download: &Path,
) -> Result<Option<PathBuf>, Fallback> {
    let wrapper = wrapper_package(&q.policy, &q.repository)?;
    let lock = q.root.join("Cargo.lock");
    need(
        std::fs::symlink_metadata(&lock).is_ok_and(|m| m.is_file()),
        "candidate has no regular Cargo.lock",
    )?;
    let image = q
        .execution()
        .config
        .at("image")
        .as_str()
        .unwrap_or("")
        .to_owned();
    let wanted = identity(
        &q.repository,
        &sha256::file(&lock)?,
        &image,
        &q.env,
        &wrapper,
    );
    let version = key(&wanted);
    record.set("key", version.clone().into());
    let Some(data) = registry.read(&version, MANIFEST, MAX_MANIFEST_BYTES)? else {
        return Ok(None);
    };
    let manifest = json::parse(&data)?;
    need(
        manifest.at("schema").as_str() == Some(SCHEMA)
            && manifest.at("key").as_str() == Some(version.as_str())
            && json::encoded(manifest.at("identity")) == json::encoded(&wanted),
        "dependency manifest identity differs",
    )?;
    let archive = manifest.at("archive");
    let sha = archive.at("sha256").as_str().unwrap_or("").to_owned();
    let bytes = archive.at("bytes").as_u64().unwrap_or(0);
    need(
        bytes > 0
            && bytes <= MAX_ARCHIVE_BYTES
            && hex64(&sha)
            && archive.at("name").as_str() == Some(format!("units-{sha}.tar.gz").as_str()),
        "dependency manifest archive is invalid",
    )?;
    record.set("provenance", provenance(registry, &version, &manifest)?);
    let started = Instant::now();
    registry.download(
        &version,
        &format!("units-{sha}.tar.gz"),
        download,
        bytes,
        &sha,
    )?;
    let files = files_of(&manifest)?;
    unpack(download, seed, &files)?;
    seal(seed)?;
    record.set("status", "hit".into());
    record.set("archive_sha256", sha.into());
    record.set("archive_bytes", bytes.into());
    record.set("files", (files.len() as u64).into());
    record.set(
        "restore_seconds",
        sp::round_float(started.elapsed().as_secs_f64(), 3),
    );
    record.set(
        "product_commit",
        manifest.at("product").at("commit").clone(),
    );
    let roots = q.execution().roots.clone();
    readonly_seed(seed, &roots).map(Some)
}

/// A verified read-only seed directory, or None to build from scratch.
pub fn restore(q: &mut Q, registry: Option<&mut dyn Registry>) -> R<Option<PathBuf>> {
    let mut record = object([("status", "miss".into())]);
    let c_plugin = q
        .policy
        .at("repositories")
        .at(&q.repository)
        .at("language")
        .as_str()
        == Some("c");
    if q.execution.is_none() || c_plugin {
        record.set("status", "not-applicable".into());
        q.receipt.set("dependency_units", record);
        q.save()?;
        return Ok(None);
    }
    let seed = q.control.join("dependency-units");
    let download = q.control.join("dependency-units.tar.gz");
    let mut owned;
    let registry: &mut dyn Registry = match registry {
        Some(registry) => registry,
        None => {
            owned = GitLab::new(std::env::var("CI_JOB_TOKEN").unwrap_or_default());
            &mut owned
        }
    };
    let outcome = restore_inner(q, registry, &mut record, &seed, &download);
    let _ = std::fs::remove_file(&download);
    let result = match outcome {
        Ok(found) => found,
        Err(reason) => {
            record.set("status", "fallback".into());
            record.set(
                "reason",
                reason.chars().take(500).collect::<String>().into(),
            );
            discard(Some(&seed));
            None
        }
    };
    q.receipt.set("dependency_units", record);
    q.save()?;
    Ok(result)
}

/// The job's shared CARGO_TARGET_DIR starts as a private copy of the seed.
pub fn install_job_target(q: &mut Q, seed: Option<&Path>) -> R<()> {
    let Some(seed) = seed else { return Ok(()) };
    let target = PathBuf::from(q.env.get("CARGO_TARGET_DIR").unwrap_or(""));
    install(seed, &target, None).map_err(sp::from_text)?;
    if let Some(record) = q.receipt.get_mut("dependency_units") {
        record.set("job_target", true.into());
    }
    q.save()
}

/// Record how many dependency units each step still compiled.
pub fn account(q: &mut Q) -> R<()> {
    let metadata = q.evidence.join("metadata.stdout");
    if q.receipt.get("dependency_units").is_none() || !metadata.is_file() {
        return Ok(());
    }
    let parsed = sp::read_json(&metadata)?;
    let mut members: std::collections::BTreeSet<String> = parsed
        .at("packages")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .filter(|p| *p.at("source") == Value::Null)
        .filter_map(|p| p.at("name").as_str().map(str::to_owned))
        .collect();
    members.insert("architecture-shipping-probe".into());
    let mut counts = Vec::new();
    for name in [
        "architecture",
        "clippy",
        "native-library",
        "plugin-runtime",
        "plugin-doctests",
    ] {
        let path = q.evidence.join(format!("{name}.stderr"));
        if path.is_file() {
            let text = String::from_utf8_lossy(&sp::read(&path)?).into_owned();
            counts.push((
                name.to_owned(),
                (rebuilt_dependency_units(&text, &members).len() as u64).into(),
            ));
        }
    }
    if let Some(record) = q.receipt.get_mut("dependency_units") {
        record.set("dependency_units_rebuilt", Value::Object(counts));
    }
    q.save()
}

// ---- producer ------------------------------------------------------------------------

/// Exact manifest graph and lock; every Rust file becomes an inert stub,
/// except `[patch]` path crates that registry dependencies compile against
/// (their own units are still stripped before upload).
pub fn stub_workspace(source: &Path, destination: &Path, revision: Option<&str>) -> R<()> {
    let kept = super::seed::manifest_snapshot(source, destination, revision, true)?;
    for path in sp::rglob(destination) {
        let relative = path.strip_prefix(destination).unwrap_or(&path);
        if path.extension().is_some_and(|e| e == "rs")
            && path.is_file()
            && !kept.iter().any(|prefix| relative.starts_with(prefix))
        {
            sp::write(&path, STUB)?;
        }
    }
    Ok(())
}

/// Paths plus manifest/lock bytes: the producer input, recorded for audit.
pub fn manifest_graph_sha256(root: &Path) -> R<String> {
    let mut rows = Vec::new();
    let mut paths: Vec<PathBuf> = sp::rglob(root)
        .into_iter()
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    for path in paths {
        let relative = sp::text(path.strip_prefix(root).unwrap_or(&path));
        let name = path.file_name().unwrap_or_default();
        let data = if name == "Cargo.toml" || name == "Cargo.lock" {
            sp::read(&path)?
        } else {
            Vec::new()
        };
        rows.push(Value::Array(vec![
            relative.into(),
            sha256::hex(&data).into(),
        ]));
    }
    Ok(sha256::hex(&json::encoded(&Value::Array(rows))))
}

fn produce_product(q: &mut Q, product: &Value, registry: &mut dyn Registry) -> R<Value> {
    let repo = sp::at_str(product, "repo")?.to_owned();
    let commit = sp::at_str(product, "commit")?.to_owned();
    let lock_sha256 = sp::at_str(product, "lock_sha256")?.to_owned();
    let repository = format!("GetBusbar/{repo}");
    let wrapper = wrapper_package(&q.policy, &repository).map_err(sp::from_text)?;
    if Some(wrapper.as_str()) != product.at("package").as_str() {
        return Err(sp::violation("pinned product package differs from policy"));
    }
    let image = q
        .execution()
        .config
        .at("image")
        .as_str()
        .unwrap_or("")
        .to_owned();
    let wanted = identity(&repository, &lock_sha256, &image, &q.env, &wrapper);
    let version = key(&wanted);
    let mut row = object([
        ("repo", repo.as_str().into()),
        ("commit", commit.as_str().into()),
        ("key", version.as_str().into()),
    ]);
    if registry
        .read(&version, MANIFEST, MAX_MANIFEST_BYTES)
        .map_err(sp::from_text)?
        .is_some()
    {
        row.set("status", "present".into());
        return Ok(row);
    }
    let source = q.work.join("canonical-inputs").join(&repo);
    let base = q.work.join("dependency-units").join(&repo);
    let stub = base.join("stub");
    sp::mkdirs(&base, true)?;
    stub_workspace(&source, &stub, Some(&commit))?;
    if sha256::file(&stub.join("Cargo.lock")).map_err(sp::from_text)? != lock_sha256 {
        return Err(sp::violation("pinned product lock differs from its vector"));
    }
    let graph = manifest_graph_sha256(&stub)?;
    let metadata = sp::read_json(&q.run_in(
        &format!("dependency-units-{repo}-metadata"),
        sp::strings(&["cargo", "metadata", "--locked", "--format-version", "1"]),
        &stub,
    )?)?;
    let target = base.join("target");
    let previous = q.env.get("CARGO_TARGET_DIR").unwrap_or("").to_owned();
    q.env.set("CARGO_TARGET_DIR", sp::text(&target));
    let built = (|| -> R<()> {
        for (name, argv) in plugin_commands(&wrapper) {
            q.run_in(&format!("dependency-units-{repo}-{name}"), argv, &stub)?;
        }
        // The architecture shipping probe, generated from the same manifests.
        let scratch = q.harness.join(format!("dependency-units-{repo}"));
        let policy =
            crate::architecture::graph::Policy::new(q.policy.clone()).map_err(sp::from_text)?;
        let entries: Vec<(String, Value)> = policy
            .packages
            .iter()
            .filter(|(_, e)| e.at("repository").as_str() == Some(repository.as_str()))
            .cloned()
            .collect();
        let log = crate::architecture::Log::default();
        let mut ctx = crate::architecture::Ctx {
            engine: Some(q.execution() as &mut dyn crate::architecture::Engine),
            evidence: None,
            log: &log,
            ci_host: std::env::var("CI_SERVER_HOST").ok(),
        };
        crate::architecture::graph::resolve_shipping(&mut ctx, &stub, &entries, &scratch, false)
            .map_err(sp::from_text)?;
        q.run_in(
            &format!("dependency-units-{repo}-architecture"),
            vec![
                "cargo".into(),
                "build".into(),
                "--manifest-path".into(),
                sp::text(&scratch.join("shipping-probe/Cargo.toml")),
                "--target-dir".into(),
                sp::text(&target),
            ],
            &stub,
        )?;
        Ok(())
    })();
    q.env.set("CARGO_TARGET_DIR", previous);
    built?;
    let mut members: Vec<String> = metadata
        .at("packages")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .filter(|p| *p.at("source") == Value::Null)
        .filter_map(|p| p.at("name").as_str().map(str::to_owned))
        .collect();
    members.push("architecture-shipping-probe".into());
    let parent = q.control.join("dependency-units-out");
    sp::mkdirs(&parent, true)?;
    let owned = parent.join(&repo);
    crate::architecture::witness::copy_candidate_tree(&target, &owned).map_err(|e| match e {
        crate::architecture::witness::SeedError::Fallback(m, _)
        | crate::architecture::witness::SeedError::Fatal(m) => sp::runtime(m),
    })?;
    sp::rmtree(&base)?;
    strip_path_units(&owned, &members).map_err(sp::from_text)?;
    let archive_tmp = parent.join(format!("{repo}.tar.gz"));
    let files = pack(&owned, &archive_tmp).map_err(sp::from_text)?;
    let digest = sha256::file(&archive_tmp).map_err(sp::from_text)?;
    let bytes = std::fs::metadata(&archive_tmp)
        .map_err(|e| sp::runtime(e.to_string()))?
        .len();
    let name = format!("units-{digest}.tar.gz");
    let manifest = object([
        ("schema", SCHEMA.into()),
        ("key", version.as_str().into()),
        ("identity", wanted),
        (
            "archive",
            object([
                ("name", name.as_str().into()),
                ("sha256", digest.as_str().into()),
                ("bytes", bytes.into()),
            ]),
        ),
        (
            "files",
            Value::Object(
                files
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().into()))
                    .collect(),
            ),
        ),
        (
            "product",
            object([
                ("repo", repo.as_str().into()),
                ("commit", commit.as_str().into()),
                ("lock_sha256", lock_sha256.as_str().into()),
                ("manifest_graph_sha256", graph.into()),
            ]),
        ),
        (
            "producer",
            object([
                (
                    "pipeline_id",
                    Value::int(sp::py_int(
                        &std::env::var("CI_PIPELINE_ID").unwrap_or_default(),
                    )?),
                ),
                (
                    "job_id",
                    Value::int(sp::py_int(&std::env::var("CI_JOB_ID").unwrap_or_default())?),
                ),
                (
                    "commit",
                    std::env::var("CI_COMMIT_SHA").unwrap_or_default().into(),
                ),
                (
                    "ref",
                    std::env::var("CI_COMMIT_BRANCH").unwrap_or_default().into(),
                ),
            ]),
        ),
    ]);
    let manifest_path = parent.join(format!("{repo}.manifest.json"));
    sp::write(&manifest_path, json::encoded(&manifest))?;
    // The archive first; the manifest is the commit marker consumers look for.
    registry
        .upload(&version, &name, &archive_tmp)
        .map_err(sp::from_text)?;
    registry
        .upload(&version, MANIFEST, &manifest_path)
        .map_err(sp::from_text)?;
    row.set("status", "published".into());
    row.set("archive_bytes", bytes.into());
    row.set("files", (files.len() as u64).into());
    sp::rmtree(&owned)?;
    let _ = std::fs::remove_file(&archive_tmp);
    let _ = std::fs::remove_file(&manifest_path);
    Ok(row)
}

/// Core dev push only: publish missing dependency units for this shard's pinned products.
/// The YAML rule admits only core's dev push pipelines; GitLab restricts pushes
/// to protected dev; consumers re-check the writing pipeline's ref.
pub fn produce(q: &mut Q) -> R<()> {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let shard = producer_shard(&env("CI_JOB_NAME"));
    if !(q.repository == "GetBusbar/busbar"
        && shard.is_some()
        && env("CI_PIPELINE_SOURCE") == "push"
        && env("CI_COMMIT_BRANCH") == "dev"
        && q.execution.is_some())
    {
        return Err(sp::violation(
            "dependency units are produced only by the protected core dev push producer",
        ));
    }
    // This receipt is producer evidence only; it never stands for qualification.
    q.receipt
        .set("schema", "busbar.plugin-dependency-units-producer/1".into());
    let mut registry = GitLab::new(env("CI_JOB_TOKEN"));
    let vector = sp::read_json(&q.root.join("scripts/ci-product-pins.json"))?;
    let shard = shard.unwrap_or_default();
    let rows = produce_units(q, shard, &vector, &mut |q, product| {
        produce_product(q, product, &mut registry)
    })?;
    // The same shard's products also publish their core product-inputs test
    // image (images.rs), built with the consumer's exact recipe.
    let shard_products: Vec<Value> = vector
        .at("products")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .filter(|p| product_shard(p.at("repo").as_str().unwrap_or("")) == shard)
        .cloned()
        .collect();
    if let Err(error) = super::images::produce(q, &shard_products, None) {
        if error.kind == sp::Kind::Interrupted {
            return Err(error);
        }
        // Images are an optimisation; never block the dependency units.
        q.receipt.set(
            "product_images_produced",
            Value::Array(vec![object([
                ("status", "failed".into()),
                (
                    "reason",
                    error.message.chars().take(500).collect::<String>().into(),
                ),
            ])]),
        );
        q.save()?;
    }
    // Every product (and the shard's images) is attempted first; a fill that
    // published nothing must not pass.
    failed_units(&rows)
}

/// This shard's dependency units, one row per Rust product; one product's
/// failure never blocks the others. Each row is recorded as it lands.
fn produce_units(
    q: &mut Q,
    shard: u64,
    vector: &Value,
    build: &mut dyn FnMut(&mut Q, &Value) -> R<Value>,
) -> R<Vec<Value>> {
    let mut rows = Vec::new();
    q.receipt.set(
        "dependency_units_shard",
        object([("index", shard.into()), ("total", PRODUCER_SHARDS.into())]),
    );
    for product in vector.at("products").as_array().unwrap_or(&[]).to_vec() {
        let repo = product.at("repo").as_str().unwrap_or("");
        if product_shard(repo) != shard {
            continue;
        }
        let repository = format!("GetBusbar/{repo}");
        let entry = q.policy.at("repositories").at(&repository);
        if *entry == Value::Null || entry.at("language").as_str() == Some("c") {
            continue;
        }
        let row = match build(q, &product) {
            Ok(row) => row,
            Err(error) if error.kind != sp::Kind::Interrupted => object([
                ("repo", product.at("repo").clone()),
                ("status", "failed".into()),
                (
                    "reason",
                    error.message.chars().take(500).collect::<String>().into(),
                ),
            ]),
            Err(error) => return Err(error),
        };
        rows.push(row);
        q.receipt
            .set("dependency_units_produced", Value::Array(rows.clone()));
        q.save()?;
    }
    Ok(rows)
}

/// A producer whose any product failed fails the job, naming every failure.
fn failed_units(rows: &[Value]) -> R<()> {
    let failed: Vec<&str> = rows
        .iter()
        .filter(|row| row.at("status").as_str() == Some("failed"))
        .map(|row| row.at("repo").as_str().unwrap_or(""))
        .collect();
    if failed.is_empty() {
        return Ok(());
    }
    Err(sp::violation(format!(
        "dependency units failed for {}",
        failed.join(", ")
    )))
}

#[cfg(test)]
mod tests;
