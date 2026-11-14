//! Protected job inputs staged by the root controller before the step runner:
//! pinned fixture-service images and conformance judge instruments.
use crate::confined;
use crate::fetch;
use crate::images;
use crate::json::{self, Value, object};
use crate::policy;
use crate::proc::{self, Result, require};
use crate::sha256;
use crate::tar;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

pub const HOST_DOCKER: &str = "unix:///var/run/docker.sock";

pub fn base_env() -> Vec<(String, String)> {
    [
        ("PATH", proc::HOST_PATH),
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("LC_ALL", "C.UTF-8"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect()
}

fn mkdir_private(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

pub fn stage_services(
    trusted: &Path,
    docker: &str,
    repository: &str,
    store: &Path,
    token: &str,
) -> Result<Value> {
    let rows = policy::service_selection(trusted, repository)?;
    let mut receipts = Value::Object(Vec::new());
    if rows.is_empty() {
        return Ok(receipts);
    }
    let root = store.join("service-inputs");
    mkdir_private(&root)?;
    // Service names come from the protected policy; they are still confined to `root`.
    let confined_root = confined::Root::new(&root)?;
    for row in &rows {
        proc::check_interrupted()?;
        let archive = confined_root.resolve(Path::new(&format!("{}.tar", row.name)))?;
        let result = (|| -> Result<()> {
            fetch::fetch(
                &row.archive_url,
                token,
                &archive,
                row.bytes,
                &row.archive_sha256,
            )?;
            let config = images::service_metadata(&archive, row)?;
            let archive_text = archive.to_string_lossy().into_owned();
            let load = proc::strings(&[
                docker,
                "--host",
                HOST_DOCKER,
                "image",
                "load",
                "--platform",
                "linux/amd64",
                "--input",
                &archive_text,
            ]);
            let options = proc::Options {
                env: base_env(),
                capture: true,
                timeout: Some(Duration::from_secs(300)),
                interruptible: true,
                ..Default::default()
            };
            let loaded = proc::run(&load, &options)?;
            require(
                loaded.status.success(),
                &format!(
                    "{}: offline image import failed ({}): {}",
                    row.name,
                    loaded.status,
                    fetch::redact(&String::from_utf8_lossy(&loaded.stderr), token)
                ),
            )?;
            let mut env = base_env();
            env.push(("DOCKER_API_VERSION".into(), "1.49".into()));
            let inspect = proc::strings(&[
                docker,
                "--host",
                HOST_DOCKER,
                "image",
                "inspect",
                "--platform",
                "linux/amd64",
                &row.reference,
            ]);
            let output = proc::checked(
                &inspect,
                &proc::Options {
                    env,
                    capture: true,
                    timeout: Some(Duration::from_secs(60)),
                    ..Default::default()
                },
            )?;
            let actual = json::parse(&output.stdout)?;
            images::verify_service_import(actual.index(0), row, &config)
        })();
        let _ = fs::remove_file(&archive);
        result?;
        receipts.set(
            &row.name,
            object([
                ("reference", row.reference.as_str().into()),
                ("archive_sha256", row.archive_sha256.as_str().into()),
                ("manifest_sha256", row.manifest_sha256.as_str().into()),
                ("config_sha256", row.config_sha256.as_str().into()),
                ("platform", "linux/amd64".into()),
                ("candidate_execution", false.into()),
            ]),
        );
    }
    Ok(receipts)
}

fn safe_member(name: &str) -> bool {
    !name.starts_with('/')
        && Path::new(name)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && name.split('/').all(|p| !matches!(p, "" | "." | ".."))
        && (name == "manifest.json" || name.starts_with("bundles/"))
}

/// Extract only bounded regular files from a verified gzip tar stream.
pub fn unpack(source: impl Read, output: &Path, manifest_sha256: &str) -> Result<PathBuf> {
    fs::create_dir_all(output.parent().ok_or("invalid judge output")?)
        .map_err(|e| e.to_string())?;
    mkdir_private(output)?;
    let result = (|| -> Result<PathBuf> {
        // Member names are archive data: every write is confined to `output` (zip-slip).
        let destination = confined::Root::new(output)?;
        let mut reader = tar::Reader::new(source);
        let mut seen: std::collections::BTreeSet<String> = Default::default();
        let mut total = 0u64;
        while let Some(entry) = reader.next()? {
            proc::check_interrupted()?;
            require(
                entry.is_file()
                    && safe_member(&entry.name)
                    && !seen.contains(&entry.name)
                    && seen.len() < 400_000,
                "unsafe conformance archive member",
            )?;
            let limit = if entry.name == "manifest.json" {
                16 << 20
            } else {
                512 << 20
            };
            total += entry.size;
            require(
                entry.size <= limit && total <= (4 << 30) + (16 << 20),
                "conformance archive exceeds byte budget",
            )?;
            let mut file = destination.create_new(Path::new(&entry.name), 0o600)?;
            let copied = std::io::copy(&mut reader.data(entry.size), &mut file)
                .map_err(|e| e.to_string())?;
            require(copied == entry.size, "truncated conformance archive member")?;
            file.set_permissions(fs::Permissions::from_mode(entry.mode & 0o555))
                .map_err(|e| e.to_string())?;
            seen.insert(entry.name);
        }
        reader.finish()?;
        let manifest = destination.resolve(Path::new("manifest.json"))?;
        let metadata =
            fs::symlink_metadata(&manifest).map_err(|_| "portable conformance manifest differs")?;
        require(
            metadata.file_type().is_file() && metadata.len() <= 16 << 20,
            "portable conformance manifest differs",
        )?;
        require(
            sha256::file(&manifest)? == manifest_sha256,
            "portable conformance manifest differs",
        )?;
        Ok(manifest)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

fn gunzip_unpack(archive: &Path, output: &Path, manifest_sha256: &str) -> Result<PathBuf> {
    let gzip = proc::host_program("gzip")?;
    let options = proc::Options {
        env: base_env(),
        ..Default::default()
    };
    let mut command = proc::command(
        &[
            gzip,
            "-dc".into(),
            "--".into(),
            archive.to_string_lossy().into_owned(),
        ],
        &options,
    )?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().unwrap();
    let result = unpack(stdout, output, manifest_sha256);
    if result.is_err() {
        proc::signal_process(-(child.id() as i32), proc::SIGKILL);
    }
    let status = proc::supervise(
        &mut child,
        &proc::Options {
            timeout: Some(Duration::from_secs(60)),
            ..Default::default()
        },
        "gzip",
    );
    let manifest = result?;
    require(
        status?.success(),
        "conformance archive is not a valid gzip stream",
    )?;
    Ok(manifest)
}

fn tree_bytes(path: &Path) -> Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            total += tree_bytes(&entry.path())?;
        } else if kind.is_file() {
            total += entry.metadata().map_err(|e| e.to_string())?.len();
        }
    }
    Ok(total)
}

pub type Fetcher<'a> = dyn Fn(&Value, &Path) -> Result<()> + 'a;

/// Returns `None` when this job stages no judges.
pub fn stage_judges(
    trusted: &Path,
    repository: &str,
    job: &str,
    store: &Path,
    fetcher: &Fetcher,
) -> Result<Option<Value>> {
    let plan_path = trusted.join("ci/native-judge-inputs.json");
    let plan = json::parse(&fs::read(&plan_path).map_err(|e| e.to_string())?)?;
    let owners = policy::judge_selection(&plan, repository, job)?;
    if owners.is_empty() {
        return Ok(None);
    }
    let private = store.join("judge-inputs");
    mkdir_private(&private)?;
    // Owner names come from the protected plan; they are still confined to `private`.
    let private_root = confined::Root::new(&private)?;
    let schema = "busbar.native-conformance-inputs/1";
    let mut bundles_out = Value::Object(Vec::new());
    let mut retained = Vec::new();
    for owner in &owners {
        let row = plan.at("owners").at(owner);
        let archive = private_root.resolve(Path::new(&format!("{owner}.tar.gz")))?;
        fetcher(row, &archive)?;
        let unpacked = private_root.resolve(Path::new(owner.as_str()))?;
        gunzip_unpack(
            &archive,
            &unpacked,
            row.at("portable_manifest_sha256").as_str().unwrap(),
        )?;
        fs::remove_file(&archive).map_err(|e| e.to_string())?;
        // The manifest is an archive member: read back only through the confined root.
        let unpacked_root = confined::Root::new(&unpacked)?;
        let mut portable_bytes = Vec::new();
        unpacked_root
            .open(Path::new("manifest.json"))?
            .read_to_end(&mut portable_bytes)
            .map_err(|e| e.to_string())?;
        let portable = json::parse(&portable_bytes)?;
        let mut names: Vec<&str> = portable.at("bundles").keys();
        names.sort();
        let mut wanted: Vec<&str> = row
            .at("bundles")
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        wanted.sort();
        require(
            portable.has_keys(&["schema", "bundles"])
                && portable.at("schema").as_str() == Some(schema)
                && names == wanted,
            "published judge bundle set differs",
        )?;
        let mut actual_bytes = 0;
        for (name, bundle) in portable.at("bundles").as_object().unwrap() {
            require(
                bundles_out.get(name).is_none()
                    && bundle.at("path").as_str() == Some(&format!("bundles/{name}")),
                "portable judge path or ownership differs",
            )?;
            // Bundle names are manifest (archive) data: confined to the unpacked tree.
            let source = unpacked_root.resolve(Path::new(&format!("bundles/{name}")))?;
            actual_bytes += if source.is_dir() {
                tree_bytes(&source)?
            } else {
                0
            };
            let mut bundle = bundle.clone();
            bundle.set("path", source.to_string_lossy().as_ref().into());
            bundles_out.set(name, bundle);
        }
        let expected = row.at("expanded_bytes").as_u64().unwrap();
        require(
            actual_bytes == expected,
            &format!(
                "expanded judge size differs for {owner} ({owner}.tar.gz): expected {expected}, actual {actual_bytes}"
            ),
        )?;
        retained.push(object([
            ("owner", owner.as_str().into()),
            ("archive_sha256", row.at("archive_sha256").clone()),
            (
                "portable_manifest_sha256",
                row.at("portable_manifest_sha256").clone(),
            ),
            ("expanded_bytes", actual_bytes.into()),
            ("bundles", row.at("bundles").clone()),
        ]));
    }
    let merged = object([("schema", schema.into()), ("bundles", bundles_out)]);
    let manifest = private.join("combined.json");
    fs::write(&manifest, json::dumps(&merged, true) + "\n").map_err(|e| e.to_string())?;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o444)).map_err(|e| e.to_string())?;
    Ok(Some(object([
        ("manifest", manifest.to_string_lossy().as_ref().into()),
        ("sha256", sha256::file(&manifest)?.into()),
        ("protected_plan_sha256", sha256::file(&plan_path)?.into()),
        ("archives", Value::Array(retained)),
        ("suite_verdict", "not implied by input staging".into()),
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tar::tests::archive;

    #[test]
    fn judge_staging_binds_verified_archive_and_keeps_it_outside_candidate_roots() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("busbar-ci-judges-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (trusted, store) = (root.join("trusted"), root.join("store"));
        fs::create_dir_all(trusted.join("ci")).unwrap();
        fs::create_dir_all(&store).unwrap();
        let content = b"fixed external instrument";
        let digest = sha256::hex(content);
        let raw = format!(
            "{{\"bundles\": {{\"mcp-tools\": {{\"files\": {{\"tool\": {{\"executable\": false, \"sha256\": \"{digest}\"}}}}, \"path\": \"bundles/mcp-tools\", \"provenance\": [{{\"sha256\": \"{digest}\", \"uri\": \"https://example.invalid/pinned\"}}]}}}}, \"schema\": \"busbar.native-conformance-inputs/1\"}}\n"
        );
        let tarball = archive(&[
            ("manifest.json", raw.as_bytes()),
            ("bundles/mcp-tools/tool", content),
        ]);
        let gz = root.join("input.tar.gz");
        fs::write(root.join("input.tar"), &tarball).unwrap();
        assert!(
            std::process::Command::new("gzip")
                .arg("-kn")
                .arg(root.join("input.tar"))
                .status()
                .unwrap()
                .success()
        );
        let checksum = sha256::file(&gz).unwrap();
        let plan = |expanded: usize| {
            format!(
                "{{\"schema\": \"busbar.native-judge-inputs/1\", \"owners\": {{\"mcp\": {{\"archive_url\": \"https://git.getbusbar.dev/api/v4/projects/3/packages/generic/busbar-native-conformance-mcp/20261111-{checksum}/mcp.tar.gz\", \"archive_sha256\": \"{checksum}\", \"portable_manifest_sha256\": \"{}\", \"bytes\": {}, \"expanded_bytes\": {expanded}, \"bundles\": [\"mcp-tools\"]}}}}, \"repositories\": {{\"GetBusbar/busbar-plane-mcp\": [\"mcp\"]}}}}",
                sha256::hex(raw.as_bytes()),
                fs::metadata(&gz).unwrap().len()
            )
        };
        let fetched = |row: &Value, destination: &Path| -> Result<()> {
            assert_eq!(row.at("archive_sha256").as_str(), Some(checksum.as_str()));
            fs::copy(&gz, destination)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        fs::write(
            trusted.join("ci/native-judge-inputs.json"),
            plan(content.len() + raw.len()),
        )
        .unwrap();
        let error = stage_judges(
            &trusted,
            "GetBusbar/busbar-plane-mcp",
            "native-qualification",
            &store,
            &fetched,
        )
        .unwrap_err();
        assert_eq!(
            error,
            format!(
                "expanded judge size differs for mcp (mcp.tar.gz): expected {}, actual {}",
                content.len() + raw.len(),
                content.len()
            )
        );
        fs::remove_dir_all(store.join("judge-inputs")).unwrap();
        fs::write(
            trusted.join("ci/native-judge-inputs.json"),
            plan(content.len()),
        )
        .unwrap();
        let result = stage_judges(
            &trusted,
            "GetBusbar/busbar-plane-mcp",
            "native-qualification",
            &store,
            &fetched,
        )
        .unwrap()
        .unwrap();
        let combined =
            json::parse(&fs::read(result.at("manifest").as_str().unwrap()).unwrap()).unwrap();
        let bundle = PathBuf::from(
            combined
                .at("bundles")
                .at("mcp-tools")
                .at("path")
                .as_str()
                .unwrap(),
        );
        assert!(bundle.starts_with(store.join("judge-inputs")));
        assert_eq!(fs::read(bundle.join("tool")).unwrap(), content);
        assert!(!store.join("judge-inputs/mcp.tar.gz").exists());
        assert_eq!(
            result.at("sha256").as_str().unwrap(),
            sha256::file(Path::new(result.at("manifest").as_str().unwrap())).unwrap()
        );
        assert_eq!(
            result.at("suite_verdict").as_str(),
            Some("not implied by input staging")
        );
        assert!(
            stage_judges(
                &trusted,
                "GetBusbar/busbar",
                "native-qualification",
                &store,
                &fetched
            )
            .unwrap()
            .is_none()
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unpack_refuses_unsafe_members_and_wrong_manifest() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("busbar-ci-unpack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let manifest = b"{}";
        let digest = sha256::hex(manifest);
        for (index, name) in [
            "../escape",
            "/abs",
            "other/file",
            "bundles/../x",
            "bundles//x",
        ]
        .iter()
        .enumerate()
        {
            let bytes = archive(&[("manifest.json", manifest), (name, b"x")]);
            let output = root.join(format!("o{index}"));
            assert!(unpack(&bytes[..], &output, &digest).is_err(), "{name}");
            assert!(!output.exists());
        }
        let bytes = archive(&[("manifest.json", manifest), ("manifest.json", manifest)]);
        assert!(unpack(&bytes[..], &root.join("dup"), &digest).is_err());
        let bytes = archive(&[("manifest.json", manifest)]);
        assert!(unpack(&bytes[..], &root.join("wrong"), &"0".repeat(64)).is_err());
        let mut directory = crate::tar::tests::header("bundles/d/", b'5', 0, 0o755);
        directory.extend([0u8; 1024]);
        assert!(unpack(&directory[..], &root.join("dir"), &digest).is_err());
        unpack(&bytes[..], &root.join("ok"), &digest).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
}
