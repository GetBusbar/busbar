//! A per-job offline Cargo seed collected before candidate code runs (former
//! `native_seed`). The transient collector sees exact manifest graphs, inert
//! source placeholders and exact local Git objects, never executable
//! candidate source, host sockets, tokens or other jobs' caches.
use super::sp::{self, Io, R, Spec, at, need, value_error, violation};
use super::{Q, git};
use crate::isolation;
use crate::json::{self, Value, object};
use crate::sha256;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// `toolchain/prepare.GIT.fullmatch(source)`: (url, rev, fragment).
pub fn git_source(source: &str) -> Option<(String, String, String)> {
    let rest = source.strip_prefix("git+")?;
    let (url, query) = rest.split_once("?rev=")?;
    let path = url.strip_prefix("https://github.com/")?;
    let (owner, name) = path.split_once('/')?;
    let class = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    };
    let (rev, fragment) = query.split_once('#')?;
    (class(owner)
        && class(name)
        && crate::product::is_revision(rev)
        && crate::product::is_revision(fragment))
    .then(|| (url.to_owned(), rev.to_owned(), fragment.to_owned()))
}

/// `toolchain/prepare.packages(lock)`: sorted unique package identities.
pub fn packages(lock: &Value) -> R<Vec<Value>> {
    let mut rows: Vec<&Value> = lock
        .at("package")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .collect();
    rows.extend(lock.at("patch").at("unused").as_array().unwrap_or(&[]));
    let mut result: Vec<Value> = Vec::new();
    for row in rows {
        let Some(source) = row.get("source").and_then(Value::as_str) else {
            continue;
        };
        let name = sp::at_str(row, "name")?;
        let version = sp::at_str(row, "version")?;
        need_value(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                && version.bytes().next().is_some_and(|c| c.is_ascii_digit())
                && version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".+-".contains(&c)),
            "invalid Cargo package identity",
        )?;
        if source == REGISTRY {
            let checksum = row.at("checksum").as_str().unwrap_or("");
            need_value(
                checksum.len() == 64
                    && checksum
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "registry checksum required",
            )?;
        } else {
            need_value(
                git_source(source).is_some_and(|(_, rev, fragment)| rev == fragment),
                "unsupported or unpinned Git source",
            )?;
        }
        let identity = Value::Object(
            ["name", "version", "source", "checksum"]
                .iter()
                .filter_map(|k| row.get(k).map(|v| ((*k).to_owned(), v.clone())))
                .collect(),
        );
        if !result.contains(&identity) {
            result.push(identity);
        }
    }
    let key = |v: &Value| {
        (
            v.at("name").as_str().unwrap_or("").to_owned(),
            v.at("version").as_str().unwrap_or("").to_owned(),
            v.at("source").as_str().unwrap_or("").to_owned(),
        )
    };
    result.sort_by_key(key);
    Ok(result)
}

fn need_value(ok: bool, message: &str) -> R<()> {
    sp::need_value(ok, message)
}

/// `manifest_snapshot(source, destination, revision)`: Cargo's graph without
/// executing or staging candidate source code.
pub fn manifest_snapshot(source: &Path, destination: &Path, revision: Option<&str>) -> R<()> {
    sp::mkdirs(destination, false)?;
    let mut paths: Vec<PathBuf> = Vec::new();
    match revision {
        None => {
            fn walk(root: &Path, directory: &Path, paths: &mut Vec<PathBuf>) -> R<()> {
                let Ok(entries) = std::fs::read_dir(directory) else {
                    return Ok(());
                };
                let mut subdirectories = Vec::new();
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    let name = entry.file_name();
                    if path.is_dir() {
                        let pruned = [".git", ".cargo", "target", "node_modules", "__pycache__"]
                            .iter()
                            .any(|n| name == *n);
                        if !pruned && !sp::is_symlink(&path) {
                            subdirectories.push(path);
                        }
                        continue;
                    }
                    if sp::is_symlink(&path) {
                        return Err(violation("indirect manifest graph input"));
                    }
                    paths.push(path.strip_prefix(root).unwrap_or(&path).to_owned());
                }
                for path in subdirectories {
                    walk(root, &path, paths)?;
                }
                Ok(())
            }
            walk(source, source, &mut paths)?;
        }
        Some(revision) => {
            let output = sp::check_output(Spec::new(sp::strings(&[
                "git",
                "-C",
                &sp::text(source),
                "ls-tree",
                "-r",
                "-z",
                revision,
            ])))?;
            for row in output.split(|b| *b == 0).filter(|r| !r.is_empty()) {
                let tab = row.iter().position(|b| *b == b'\t').ok_or_else(|| {
                    value_error("not enough values to unpack (expected 2, got 1)")
                })?;
                let header: Vec<&[u8]> = row[..tab]
                    .split(|b| b.is_ascii_whitespace())
                    .filter(|f| !f.is_empty())
                    .collect();
                let [mode, kind, _] = header.as_slice() else {
                    return Err(value_error("not enough values to unpack (expected 3)"));
                };
                if *kind != b"blob" || !(*mode == b"100644" || *mode == b"100755") {
                    return Err(violation("indirect manifest graph object"));
                }
                use std::os::unix::ffi::OsStrExt;
                let relative = PathBuf::from(std::ffi::OsStr::from_bytes(&row[tab + 1..]));
                if !relative.components().any(|c| {
                    [".git", ".cargo", "target", "node_modules"]
                        .iter()
                        .any(|n| c.as_os_str() == *n)
                }) {
                    paths.push(relative);
                }
            }
        }
    }
    for relative in paths {
        if relative.is_absolute() || relative.components().any(|c| c.as_os_str() == "..") {
            return Err(violation("manifest graph path escapes source"));
        }
        let target = destination.join(&relative);
        if let Some(parent) = target.parent() {
            sp::mkdirs(parent, true)?;
        }
        let name = relative.file_name().unwrap_or_default();
        let data = if name == "Cargo.toml" || name == "Cargo.lock" {
            match revision {
                None => sp::read(&source.join(&relative))?,
                Some(revision) => sp::check_output(Spec::new(sp::strings(&[
                    "git",
                    "-C",
                    &sp::text(source),
                    "show",
                    &format!("{revision}:{}", sp::text(&relative)),
                ])))?,
            }
        } else {
            Vec::new()
        };
        sp::write(&target, data)?;
    }
    Ok(())
}

struct LockInput {
    data: Vec<u8>,
    source: PathBuf,
    revision: Option<String>,
    relative: String,
}

/// `lock_inputs(q, host, sdk, canonical, vector)`.
fn lock_inputs(
    q: &Q,
    host: &Path,
    sdk: &Path,
    canonical: &Path,
    vector: &Value,
) -> R<Vec<(String, LockInput)>> {
    let mut locks: Vec<(String, LockInput)> = Vec::new();
    for (label, directory, relative) in super::sources::subject_locks(&q.root, host, sdk) {
        let path = directory.join(relative);
        if path.is_file() {
            let parent = Path::new(relative)
                .parent()
                .map(sp::text)
                .unwrap_or_default();
            locks.push((
                label.to_owned(),
                LockInput {
                    data: sp::read(&path)?,
                    source: directory.to_owned(),
                    revision: None,
                    relative: if parent.is_empty() {
                        ".".into()
                    } else {
                        parent
                    },
                },
            ));
        }
    }
    for product in super::sources::standalone_products(&q.repository, q.evaluation_only, vector)? {
        let repo = sp::at_str(&product, "repo")?;
        let commit = sp::at_str(&product, "commit")?;
        let data = sp::check_output(Spec::new(sp::strings(&[
            "git",
            "-C",
            &sp::text(&canonical.join(repo)),
            "show",
            &format!("{commit}:Cargo.lock"),
        ])))?;
        need(
            sha256::hex(&data) == sp::at_str(&product, "lock_sha256")?,
            "job seed product lock differs from admitted vector",
        )?;
        let label = format!("product-{repo}");
        locks.retain(|(l, _)| *l != label);
        locks.push((
            label,
            LockInput {
                data,
                source: canonical.join(repo),
                revision: Some(commit.to_owned()),
                relative: ".".into(),
            },
        ));
    }
    need(!locks.is_empty(), "job dependency seed has no exact locks")?;
    locks.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(locks)
}

pub fn prepare(q: &mut Q) -> R<()> {
    let root = q.control.join("dependency-collector");
    sp::mkdir(&root, 0o700, false)?;
    let context = root.join("inputs");
    let output = root.join("output");
    sp::mkdir(&context, 0o777, false)?;
    sp::mkdir(&output, 0o777, false)?;
    sp::mkdir(&context.join("seed-payload"), 0o777, false)?;
    let host = q.host()?;
    let sdk = q.sdk()?;
    let pins_path = host.join("scripts/ci-product-pins.json");
    let vector = sp::read_json(&pins_path)?;
    let canonical = q.work.join("canonical-inputs");
    let locks = lock_inputs(q, &host, &sdk, &canonical, &vector)?;
    let vector_sha = sha256::hex(&sp::read(&pins_path)?);
    let toolchain_sha = sha256::hex(&sp::read(&host.join("rust-toolchain.toml"))?);
    let mut lock_digests: Vec<(String, Value)> = Vec::new();
    let mut expected_packages: Vec<(String, Value)> = Vec::new();
    // Insertion-ordered: the receipt keeps discovery order.
    let mut git_revisions: Vec<(String, BTreeSet<String>)> = Vec::new();
    for (index, (label, input)) in locks.iter().enumerate() {
        let lock = crate::product::toml(&input.data)?;
        let rows = packages(&lock)?;
        let destination = context.join("locks").join(index.to_string());
        manifest_snapshot(&input.source, &destination, input.revision.as_deref())?;
        let name = if input.relative == "." {
            index.to_string()
        } else {
            format!("{index}/{}", input.relative)
        };
        let directory = context.join("locks").join(&name);
        need(
            directory.join("Cargo.toml").is_file(),
            "job seed input has no exact Cargo manifest",
        )?;
        sp::write(&directory.join("Cargo.lock"), &input.data)?;
        lock_digests.push((label.clone(), sha256::hex(&input.data).into()));
        for row in &rows {
            let source = row.at("source").as_str().unwrap_or("");
            if source != REGISTRY {
                let (url, rev, _) = git_source(source)
                    .ok_or_else(|| value_error("unsupported or unpinned Git source"))?;
                match git_revisions.iter_mut().find(|(u, _)| *u == url) {
                    Some((_, revisions)) => {
                        revisions.insert(rev);
                    }
                    None => git_revisions.push((url, BTreeSet::from([rev]))),
                }
            }
        }
        expected_packages.push((name, Value::Array(rows)));
    }
    let mut git_paths: Vec<(String, Value)> = Vec::new();
    let mut sorted_git = git_revisions.clone();
    sorted_git.sort_by(|a, b| a.0.cmp(&b.0));
    for (index, (url, revisions)) in sorted_git.iter().enumerate() {
        let destination = context.join("git").join(index.to_string());
        sp::mkdir(&context.join("git"), 0o777, true)?;
        sp::check_call(Spec::new(sp::strings(&[
            "git",
            "init",
            "--bare",
            "--quiet",
            &sp::text(&destination),
        ])))?;
        let name = url.rsplit('/').next().unwrap_or("");
        let name = name.strip_suffix(".git").unwrap_or(name);
        let known = canonical.join(name);
        let remote = if url.starts_with("https://github.com/GetBusbar/") && known.is_dir() {
            sp::text(&known)
        } else {
            // No job token or credential helper reaches public GitHub fetches;
            // the lock parser permits only exact GitHub commit URLs.
            url.clone()
        };
        let environment: Vec<(String, String)> = [
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("HOME", sp::text(&root)),
            ("GIT_TERMINAL_PROMPT", "0".to_owned()),
            ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
            ("GIT_CONFIG_GLOBAL", "/dev/null".to_owned()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        for revision in revisions {
            sp::check_call(
                Spec::new(sp::strings(&[
                    "git",
                    "-c",
                    "credential.helper=",
                    "-C",
                    &sp::text(&destination),
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth",
                    "1",
                    &remote,
                    &format!("{revision}:refs/heads/input-{revision}"),
                ]))
                .env(&environment)
                .timeout(300),
            )?;
            need(
                git(
                    &destination,
                    &["rev-parse", &format!("refs/heads/input-{revision}")],
                )? == *revision,
                "job seed Git revision differs",
            )?;
        }
        sp::write(
            &destination.join("config"),
            "[core]\nrepositoryformatversion=0\nbare=true\n",
        )?;
        let _ = std::fs::remove_dir_all(destination.join("hooks"));
        let _ = std::fs::remove_file(destination.join("FETCH_HEAD"));
        git_paths.push((url.clone(), format!("/inputs/git/{index}").into()));
    }
    let binding = object([
        ("schema", "busbar.native-job-seed/1".into()),
        ("repository", q.repository.as_str().into()),
        ("source", q.source().into()),
        ("vector_sha256", vector_sha.as_str().into()),
        ("locks", Value::Object(lock_digests.clone())),
        (
            "git",
            Value::Object(
                git_revisions
                    .iter()
                    .map(|(url, revisions)| {
                        (
                            url.clone(),
                            Value::Array(revisions.iter().map(|r| r.as_str().into()).collect()),
                        )
                    })
                    .collect(),
            ),
        ),
    ]);
    let plan_sha = sha256::hex(json::dumps(&binding, true).as_bytes());
    let recipe = object([
        ("schema", "busbar.native-seed-recipe/1".into()),
        ("rust", "1.98.0".into()),
        ("vector_sha256", vector_sha.into()),
        ("toolchain_sha256", toolchain_sha.into()),
        ("locks", Value::Object(lock_digests)),
        ("expected_packages", Value::Object(expected_packages)),
        ("git", Value::Object(git_paths)),
        ("native_tools", Value::Object(Vec::new())),
        ("advisory_db", Value::Null),
        ("copy_image_advisories", true.into()),
        ("exact_manifest_graphs", true.into()),
        ("plan_sha256", plan_sha.as_str().into()),
    ]);
    sp::write(
        &context.join("recipe.json"),
        json::dumps(&recipe, true) + "\n",
    )?;
    for name in ["seed.py", "prepare.py"] {
        let from = q.trusted.join("scripts/architecture/toolchain").join(name);
        std::fs::copy(&from, context.join(name)).at(&from)?;
    }
    let execution = q.execution.as_ref().unwrap();
    let config = execution.config.clone();
    let storage = isolation::prepare_writable(
        config.at("isolation"),
        &[context.clone(), output.clone()],
        execution.uid() as u64,
        execution.gid() as u64,
    )
    .map_err(sp::from_text)?;
    let collector = |args: &[&str]| sp::run(execution.collector_spec(&sp::strings(args)).capture());
    let daemon = collector(&["info", "--format", "{{json .}}"])?;
    need(
        daemon.code == 0,
        "dependency collector daemon identity unavailable",
    )?;
    let daemon = sp::loads(&daemon.stdout)?;
    let remapped = daemon
        .at("SecurityOptions")
        .as_array()
        .is_some_and(|rows| rows.iter().any(|v| v.as_str() == Some("name=userns")));
    need(
        !remapped,
        "trusted collector endpoint must be the separate unremapped daemon",
    )?;
    let collector_config = config.at("collector");
    let user = format!(
        "{}:{}",
        crate::py::str(collector_config.at("uid")),
        crate::py::str(collector_config.at("gid"))
    );
    let namespace = object([
        ("mode", "host".into()),
        ("uid", collector_config.at("uid").clone()),
        ("gid", collector_config.at("gid").clone()),
        ("scope", "trusted fetch only; no candidate execution".into()),
    ]);
    let name = format!("busbar-job-seed-{}", sp::uuid_hex());
    let resources = config.at("resources");
    let collected = (|| -> R<()> {
        let image = collector_config
            .get("image")
            .unwrap_or(config.at("image"))
            .as_str()
            .unwrap_or("")
            .to_owned();
        let args: Vec<String> = vec![
            "create".into(),
            "--name".into(),
            name.clone(),
            "--pull=never".into(),
            "--read-only".into(),
            "--network=bridge".into(),
            "--runtime".into(),
            config.at("runtime").as_str().unwrap_or("").into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--userns=host".into(),
            "--user".into(),
            user.clone(),
            format!("--memory={}", crate::py::str(resources.at("memory_bytes"))),
            format!("--cpus={}", crate::py::str(resources.at("cpus"))),
            format!("--pids-limit={}", crate::py::str(resources.at("pids"))),
            "--init".into(),
            "--tmpfs".into(),
            "/tmp:rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777".into(),
            "--shm-size=64m".into(),
            "--mount".into(),
            format!("type=bind,src={},dst=/inputs", sp::text(&context)),
            "--mount".into(),
            format!(
                "type=bind,src={},dst=/__busbar_collected",
                sp::text(&output)
            ),
            "--entrypoint".into(),
            "/usr/bin/env".into(),
            image,
            "-i".into(),
            "PATH=/usr/local/cargo/bin:/usr/bin:/bin".into(),
            "BUSBAR_NATIVE_SEED_ROOT=/__busbar_collected".into(),
            config
                .at(super::pysteps::INTERPRETER_KEY)
                .as_str()
                .unwrap_or("")
                .into(),
            "-I".into(),
            "-B".into(),
            "/inputs/seed.py".into(),
        ];
        let created = sp::run(execution.collector_spec(&args).capture())?;
        need(
            created.code == 0,
            "private dependency collector container creation failed",
        )?;
        let inspected = collector(&["inspect", &name])?;
        need(
            inspected.code == 0,
            "trusted collector inspection unavailable",
        )?;
        let rows = sp::loads(&inspected.stdout)?;
        let actual = rows
            .as_array()
            .and_then(|r| r.first())
            .ok_or_else(|| value_error("list index out of range"))?;
        let settings = at(actual, "HostConfig")?;
        let ok = at(settings, "NetworkMode")?.as_str() == Some("bridge")
            && at(settings, "ReadonlyRootfs")?.truthy()
            && !at(settings, "Privileged")?.truthy()
            && settings.at("UsernsMode").as_str() == Some("host")
            && *at(settings, "CapDrop")? == Value::Array(vec!["ALL".into()])
            && !settings.at("CapAdd").truthy()
            && at(settings, "Memory")? == resources.at("memory_bytes")
            && at(settings, "PidsLimit")? == resources.at("pids")
            && at(at(actual, "Config")?, "User")?.as_str() == Some(user.as_str());
        need(ok, "trusted dependency collector controls differ")?;
        let mut observed: Vec<(String, String, bool)> = Vec::new();
        for mount in at(actual, "Mounts")?.as_array().unwrap_or(&[]) {
            if at(mount, "Type")?.as_str() == Some("bind") {
                observed.push((
                    at(mount, "Source")?.as_str().unwrap_or("").into(),
                    at(mount, "Destination")?.as_str().unwrap_or("").into(),
                    at(mount, "RW")?.truthy(),
                ));
            }
        }
        observed.sort();
        observed.dedup();
        let mut expected = vec![
            (sp::text(&context), "/inputs".to_owned(), true),
            (sp::text(&output), "/__busbar_collected".to_owned(), true),
        ];
        expected.sort();
        need(
            observed == expected,
            "trusted dependency collector mounts differ",
        )?;
        let out_path = q.evidence.join("dependency-seed.stdout");
        let err_path = q.evidence.join("dependency-seed.stderr");
        let mut spec = execution.collector_spec(&sp::strings(&["start", "--attach", &name]));
        spec.timeout = Some((1800.0, "1800".into()));
        spec.stdout = sp::Output::File(std::fs::File::create(&out_path).at(&out_path)?);
        spec.stderr = sp::Output::File(std::fs::File::create(&err_path).at(&err_path)?);
        let started = sp::run(spec)?;
        need(
            started.code == 0,
            "private dependency collection failed; no candidate network fallback",
        )
    })();
    let removed = (|| -> R<()> {
        collector(&["rm", "--force", &name])?;
        let filter = format!("name=^/{name}$");
        let absent = collector(&["container", "ls", "--all", "--quiet", "--filter", &filter])?;
        need(
            absent.code == 0 && absent.text().trim().is_empty(),
            "private dependency collector disposal was not confirmed",
        )
    })();
    removed?;
    collected?;
    let seed_path = output.join("seed.json");
    let seed = sp::read_json(&seed_path)?;
    need(
        at(&seed, "plan_sha256")?.as_str() == Some(plan_sha.as_str())
            && at(&seed, "packages")? == recipe.at("expected_packages"),
        "private dependency seed binding differs",
    )?;
    let directory = output.join("cargo-seed");
    let mut actual: Vec<(String, Value)> = Vec::new();
    for path in sp::rglob(&directory) {
        let info = std::fs::symlink_metadata(&path).at(&path)?;
        if info.is_dir() {
            continue;
        }
        need(
            info.file_type().is_file() && info.nlink() == 1,
            "private dependency seed contains indirect or special files",
        )?;
        let relative = sp::text(path.strip_prefix(&directory).unwrap_or(&path));
        actual.push((relative, crate::confine::digest(&path)?.into()));
    }
    need(
        Value::Object(actual) == *at(&seed, "files")?,
        "private dependency seed file inventory differs",
    )?;
    let manifest_sha = sha256::hex(&sp::read(&seed_path)?);
    let execution = q.execution();
    execution.dependency_seed = Some(directory);
    execution.dependency_seed_sha256 = Some(manifest_sha.clone());
    let mut record = binding;
    record.set("manifest_sha256", manifest_sha.into());
    record.set("collector_disposed", true.into());
    record.set("shared_image", false.into());
    record.set("storage", storage);
    record.set("user_namespace", namespace);
    q.receipt.set("dependency_seed", record);
    q.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_packages_are_exact_sorted_and_unique() {
        let a = "a".repeat(40);
        let sum = "c".repeat(64);
        let lock = crate::json::parse(
            format!(
                r#"{{"package": [
                {{"name": "zeta", "version": "1.0.0", "source": "{REGISTRY}", "checksum": "{sum}"}},
                {{"name": "alpha", "version": "0.1.0", "source": "git+https://github.com/x/y?rev={a}#{a}"}},
                {{"name": "local", "version": "0.1.0"}},
                {{"name": "zeta", "version": "1.0.0", "source": "{REGISTRY}", "checksum": "{sum}"}}]}}"#
            )
            .as_bytes(),
        )
        .unwrap();
        let rows = packages(&lock).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].at("name").as_str(), Some("alpha"));
        let unpinned = crate::json::parse(
            br#"{"package": [{"name": "x", "version": "1.0.0", "source": "git+https://github.com/x/y?branch=main#abc"}]}"#,
        )
        .unwrap();
        assert_eq!(
            packages(&unpinned).unwrap_err().message,
            "unsupported or unpinned Git source"
        );
        let unsummed = crate::json::parse(
            format!(
                r#"{{"package": [{{"name": "x", "version": "1.0.0", "source": "{REGISTRY}"}}]}}"#
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            packages(&unsummed).unwrap_err().message,
            "registry checksum required"
        );
    }

    #[test]
    fn manifest_snapshot_keeps_only_graph_bytes() {
        let base =
            sp::resolve(&std::env::temp_dir()).join(format!("busbar-ci-seed-{}", sp::uuid_hex()));
        let source = base.join("source");
        std::fs::create_dir_all(source.join("src")).unwrap();
        std::fs::create_dir_all(source.join("target/debug")).unwrap();
        std::fs::write(source.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::write(source.join("src/lib.rs"), "secret code").unwrap();
        std::fs::write(source.join("target/debug/out"), "x").unwrap();
        manifest_snapshot(&source, &base.join("out"), None).unwrap();
        assert_eq!(
            std::fs::read(base.join("out/Cargo.toml")).unwrap(),
            b"[package]\nname = \"x\"\n"
        );
        assert_eq!(std::fs::read(base.join("out/src/lib.rs")).unwrap(), b"");
        assert!(!base.join("out/target").exists());
        std::os::unix::fs::symlink("/etc/passwd", source.join("link")).unwrap();
        assert_eq!(
            manifest_snapshot(&source, &base.join("out2"), None)
                .unwrap_err()
                .message,
            "indirect manifest graph input"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
