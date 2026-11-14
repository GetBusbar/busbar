//! Offline OCI archive metadata and loaded-image execution identity checks.
use crate::json::{self, Value, object};
use crate::proc::{Result, require};
use crate::sha256::{self, Sha256};
use crate::tar;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

const METADATA_LIMIT: u64 = 1 << 20;

pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Verified blobs of the tool image: (manifest, config JSON, config digest).
#[derive(Debug)]
pub struct ToolMetadata {
    pub config: Value,
    pub config_sha256: String,
}

fn blob(raw: Option<Vec<u8>>, checksum: &str) -> Result<Value> {
    let raw = raw.ok_or("invalid tool image metadata")?;
    require(
        sha256::hex(&raw) == checksum,
        "tool image metadata digest differs",
    )?;
    json::parse(&raw)
}

fn tool_from(
    mut lookup: impl FnMut(&str) -> Result<Option<Vec<u8>>>,
    manifest_sha: &str,
) -> Result<ToolMetadata> {
    let manifest = blob(lookup(manifest_sha)?, manifest_sha)?;
    let config_sha = manifest
        .at("config")
        .at("digest")
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:").or(Some(d)))
        .filter(|d| is_digest(d))
        .ok_or("invalid tool image metadata")?
        .to_owned();
    let config = blob(lookup(&config_sha)?, &config_sha)?;
    require(
        config.at("architecture").as_str() == Some("amd64")
            && config.at("os").as_str() == Some("linux"),
        "tool image platform differs",
    )?;
    Ok(ToolMetadata {
        config,
        config_sha256: config_sha,
    })
}

/// Seek-based metadata read of an archive this process just downloaded.
pub fn tool_metadata(archive: &Path, manifest_sha: &str) -> Result<ToolMetadata> {
    let members = tar::index(archive)?;
    tool_from(
        |checksum| {
            tar::read_member(
                archive,
                &members,
                &format!("blobs/sha256/{checksum}"),
                METADATA_LIMIT,
            )
        },
        manifest_sha,
    )
}

/// One pass over an archive written by another principal: the archive digest
/// and the metadata are taken from the same bytes, so no copy is needed.
pub fn verified_tool_metadata(
    archive: &Path,
    archive_sha: &str,
    bytes: u64,
    manifest_sha: &str,
) -> Result<ToolMetadata> {
    struct Hashing<R> {
        inner: R,
        hash: Sha256,
        count: u64,
    }
    impl<R: Read> Read for Hashing<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buffer)?;
            self.hash.update(&buffer[..n]);
            self.count += n as u64;
            Ok(n)
        }
    }
    let file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let mut reader = tar::Reader::new(Hashing {
        inner: std::io::BufReader::with_capacity(1 << 20, file),
        hash: Sha256::new(),
        count: 0,
    });
    let mut small: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut retained = 0u64;
    while let Some(entry) = reader.next()? {
        if let Some(checksum) = entry.name.strip_prefix("blobs/sha256/")
            && entry.is_file()
            && entry.size < METADATA_LIMIT
            && retained + entry.size <= 64 << 20
        {
            let mut data = Vec::new();
            reader
                .data(entry.size)
                .read_to_end(&mut data)
                .map_err(|e| e.to_string())?;
            retained += entry.size;
            small.insert(checksum.to_owned(), data);
        }
    }
    // Trailing bytes after the end-of-archive marker are part of the pinned file.
    let Hashing { hash, count, .. } = reader.finish()?;
    require(
        count == bytes && hash.hex() == archive_sha,
        "administrator bootstrap inputs changed",
    )?;
    tool_from(|checksum| Ok(small.get(checksum).cloned()), manifest_sha)
}

/// Loaded image identity bound to the verified execution bytes.
pub fn verify_loaded(
    actual: &Value,
    config: &Value,
    allowed: &[String],
    what: &str,
) -> Result<String> {
    let id = actual.at("Id").as_str().unwrap_or("");
    require(
        allowed.iter().any(|a| a == id),
        &format!("loaded {what} identity differs"),
    )?;
    let rootfs = object([
        ("Type", config.at("rootfs").at("type").clone()),
        ("Layers", config.at("rootfs").at("diff_ids").clone()),
    ]);
    let wanted = config
        .at("config")
        .as_object()
        .ok_or("invalid image config")?;
    let actual_config = actual.at("Config");
    require(
        actual.at("Os") == config.at("os")
            && actual.at("Architecture") == config.at("architecture")
            && *actual.at("RootFS") == rootfs
            && wanted
                .iter()
                .all(|(key, value)| actual_config.at(key) == value),
        &format!("loaded {what} execution content differs"),
    )?;
    Ok(id.to_owned())
}

/// `Loaded image: x` / `Loaded image ID: sha256:...` lines from `docker image load`.
pub fn loaded_names(stdout: &str) -> Result<String> {
    let names: Vec<&str> = stdout
        .lines()
        .filter_map(|line| {
            line.strip_prefix("Loaded image ID: ")
                .or_else(|| line.strip_prefix("Loaded image: "))
        })
        .collect();
    require(
        names.len() == 1 && !names[0].is_empty(),
        "tool archive must import exactly one image",
    )?;
    Ok(names[0].to_owned())
}

/// Protected service archive row (`ci/native-service-images.json`).
pub struct ServiceRow {
    pub name: String,
    pub reference: String,
    pub archive_url: String,
    pub archive_sha256: String,
    pub bytes: u64,
    pub manifest_sha256: String,
    pub config_sha256: String,
}

impl ServiceRow {
    pub fn index_digest(&self) -> &str {
        self.reference
            .rsplit_once("@sha256:")
            .map(|(_, d)| d)
            .unwrap_or("")
    }
}

pub fn service_metadata(archive: &Path, row: &ServiceRow) -> Result<Value> {
    let members = tar::index(archive)?;
    let member = |checksum: &str| -> Result<&(u64, tar::Entry)> {
        members
            .get(&format!("blobs/sha256/{checksum}"))
            .ok_or_else(|| format!("service archive is missing pinned content: {checksum}"))
    };
    let blob = |checksum: &str| -> Result<Value> {
        let (_, entry) = member(checksum)?;
        require(
            entry.is_file() && entry.size < METADATA_LIMIT,
            "invalid service OCI metadata",
        )?;
        let raw = tar::read_member(
            archive,
            &members,
            &format!("blobs/sha256/{checksum}"),
            METADATA_LIMIT,
        )?
        .unwrap();
        require(
            sha256::hex(&raw) == checksum,
            "service OCI metadata digest differs",
        )?;
        json::parse(&raw)
    };
    let index = blob(row.index_digest())?;
    let manifests = index
        .at("manifests")
        .as_array()
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    let selected: Vec<_> = manifests
        .iter()
        .filter(|item| {
            item.at("platform").at("os").as_str() == Some("linux")
                && item.at("platform").at("architecture").as_str() == Some("amd64")
        })
        .collect();
    require(
        selected.len() == 1
            && selected[0].at("digest").as_str()
                == Some(&format!("sha256:{}", row.manifest_sha256)),
        "service platform is not anchored to the catalog index",
    )?;
    // Docker 29.1's platform import also requires unknown-platform attestation
    // content referenced by the original immutable index.
    for descriptor in &manifests {
        if descriptor.at("platform").at("architecture").as_str() != Some("unknown") {
            continue;
        }
        require(
            descriptor
                .at("annotations")
                .at("vnd.docker.reference.type")
                .as_str()
                == Some("attestation-manifest"),
            "unknown service index artifact",
        )?;
        let digest = descriptor.at("digest").as_str().unwrap_or("");
        let attestation = blob(digest.strip_prefix("sha256:").unwrap_or(digest))?;
        let mut contents = vec![attestation.at("config").clone()];
        contents.extend(
            attestation
                .at("layers")
                .as_array()
                .map(<[_]>::to_vec)
                .unwrap_or_default(),
        );
        for content in contents {
            let digest = content.at("digest").as_str().unwrap_or("");
            let checksum = digest.strip_prefix("sha256:").unwrap_or(digest);
            require(is_digest(checksum), "invalid service attestation digest")?;
            let (offset, entry) = member(checksum)?;
            require(
                entry.is_file()
                    && Some(entry.size) == content.at("size").as_u64()
                    && entry.size <= 64 << 20,
                "invalid service attestation content size",
            )?;
            let mut file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
            std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(*offset))
                .map_err(|e| e.to_string())?;
            let mut hash = Sha256::new();
            let mut buffer = vec![0u8; 1 << 16];
            let mut left = entry.size;
            while left > 0 {
                let n = file
                    .read(&mut buffer[..left.min(1 << 16) as usize])
                    .map_err(|e| e.to_string())?;
                require(n > 0, "truncated service attestation content")?;
                hash.update(&buffer[..n]);
                left -= n as u64;
            }
            require(
                hash.hex() == checksum,
                "service attestation content digest differs",
            )?;
        }
    }
    let manifest = blob(&row.manifest_sha256)?;
    require(
        manifest.at("config").at("digest").as_str()
            == Some(&format!("sha256:{}", row.config_sha256)),
        "service config identity differs",
    )?;
    let config = blob(&row.config_sha256)?;
    require(
        config.at("os").as_str() == Some("linux")
            && config.at("architecture").as_str() == Some("amd64"),
        "service config platform differs",
    )?;
    Ok(config)
}

fn config_matches(actual: &Value, expected: &Value) -> bool {
    expected.as_object().is_some_and(|rows| {
        rows.iter().all(|(key, value)| {
            if actual.at(key) == value {
                return true;
            }
            // Old Docker builders recorded their build-container parent in Image.
            // Current engines erase this non-runtime bookkeeping field on inspect.
            key == "Image"
                && value
                    .as_str()
                    .and_then(|v| v.strip_prefix("sha256:"))
                    .is_some_and(is_digest)
                && actual.at(key).as_str() == Some("")
        })
    })
}

pub fn verify_service_import(actual: &Value, row: &ServiceRow, config: &Value) -> Result<()> {
    let index = format!("sha256:{}", row.index_digest());
    require(
        actual.at("RepoDigests").as_array().is_some_and(|rows| {
            rows.iter().any(|v| {
                v.as_str()
                    .is_some_and(|s| s.ends_with(&format!("@{index}")))
            })
        }),
        "loaded service has lost its catalog index identity",
    )?;
    let id = actual.at("Id").as_str().unwrap_or("");
    require(
        id == index || id == format!("sha256:{}", row.manifest_sha256),
        "loaded service immutable manifest identity differs",
    )?;
    let rootfs = object([
        ("Type", config.at("rootfs").at("type").clone()),
        ("Layers", config.at("rootfs").at("diff_ids").clone()),
    ]);
    require(
        actual.at("Os").as_str() == Some("linux")
            && actual.at("Architecture").as_str() == Some("amd64")
            && *actual.at("RootFS") == rootfs
            && config_matches(actual.at("Config"), config.at("config")),
        "loaded service execution bytes differ",
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tar::tests::archive;

    pub fn write(name: &str, members: &[(String, Vec<u8>)]) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("busbar-ci-images-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("image.tar");
        let refs: Vec<(&str, &[u8])> = members
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        std::fs::write(&path, archive(&refs)).unwrap();
        path
    }

    fn blob(value: &str) -> (String, Vec<u8>) {
        (sha256::hex(value.as_bytes()), value.as_bytes().to_vec())
    }

    #[test]
    fn offline_import_checks_execution_bytes() {
        let config_raw = r#"{"architecture": "amd64", "os": "linux", "config": {"Cmd": ["fixed"], "Env": ["PATH=/bin"]}, "rootfs": {"type": "layers", "diff_ids": ["sha256:aaaa"]}}"#;
        let (config_sha, config_bytes) = blob(config_raw);
        let (manifest_sha, manifest_bytes) = blob(&format!(
            r#"{{"config": {{"digest": "sha256:{config_sha}"}}}}"#
        ));
        let path = write(
            "tool",
            &[
                (format!("blobs/sha256/{config_sha}"), config_bytes),
                (format!("blobs/sha256/{manifest_sha}"), manifest_bytes),
            ],
        );
        let metadata = tool_metadata(&path, &manifest_sha).unwrap();
        assert_eq!(metadata.config_sha256, config_sha);
        let archive_sha = sha256::file(&path).unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        let verified = verified_tool_metadata(&path, &archive_sha, size, &manifest_sha).unwrap();
        assert_eq!(verified.config, metadata.config);
        // Image digest mismatch: archive pin, byte count and manifest pin.
        assert!(verified_tool_metadata(&path, &"0".repeat(64), size, &manifest_sha).is_err());
        assert!(verified_tool_metadata(&path, &archive_sha, size + 1, &manifest_sha).is_err());
        assert!(tool_metadata(&path, &"f".repeat(64)).is_err());

        let allowed = vec![
            format!("sha256:{manifest_sha}"),
            format!("sha256:{config_sha}"),
        ];
        let mut actual = json::parse(
            format!(r#"{{"Id": "sha256:{config_sha}", "Config": {{"Env": ["PATH=/bin"], "Cmd": ["fixed"], "Labels": null}}, "Os": "linux", "Architecture": "amd64", "RootFS": {{"Type": "layers", "Layers": ["sha256:aaaa"]}}}}"#).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_loaded(&actual, &metadata.config, &allowed, "tool").unwrap(),
            format!("sha256:{config_sha}")
        );
        actual.set(
            "RootFS",
            json::parse(br#"{"Type": "layers", "Layers": ["sha256:ffff"]}"#).unwrap(),
        );
        assert!(
            verify_loaded(&actual, &metadata.config, &allowed, "tool")
                .unwrap_err()
                .contains("execution content")
        );
        actual.set("Id", format!("sha256:{}", "f".repeat(64)).into());
        assert!(
            verify_loaded(&actual, &metadata.config, &allowed, "tool")
                .unwrap_err()
                .contains("identity")
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();

        assert_eq!(
            loaded_names("Loaded image: fixed:tag\n").unwrap(),
            "fixed:tag"
        );
        assert_eq!(
            loaded_names("Loaded image ID: sha256:ab\n").unwrap(),
            "sha256:ab"
        );
        assert!(loaded_names("Loaded image: a\nLoaded image: b\n").is_err());
        assert!(loaded_names("").is_err());
    }

    #[test]
    fn only_erased_legacy_build_parent_is_normalized() {
        let image = format!("sha256:{}", "a".repeat(64));
        let expected = json::parse(
            format!(r#"{{"Image": "{image}", "User": "", "WorkingDir": "", "Cmd": ["fixed"], "Env": ["PATH=/bin"]}}"#).as_bytes(),
        )
        .unwrap();
        let mut actual = expected.clone();
        actual.set("Image", "".into());
        assert!(config_matches(&actual, &expected));
        for (key, value) in [
            ("User", Value::from("1001")),
            ("WorkingDir", "/changed".into()),
            ("Cmd", vec![Value::from("changed")].into()),
            ("Env", vec![Value::from("PATH=/candidate")].into()),
            ("Image", format!("sha256:{}", "b".repeat(64)).into()),
        ] {
            let mut changed = actual.clone();
            changed.set(key, value);
            assert!(!config_matches(&changed, &expected), "{key}");
        }
        let parse = |t: &str| json::parse(t.as_bytes()).unwrap();
        assert!(!config_matches(
            &parse(r#"{"Image": ""}"#),
            &parse(r#"{"Image": "floating:tag"}"#)
        ));
        assert!(!config_matches(
            &parse("{}"),
            &parse(&format!(r#"{{"Image": "{image}"}}"#))
        ));
        assert!(!config_matches(
            &parse(r#"{"Image": null}"#),
            &parse(&format!(r#"{{"Image": "{image}"}}"#))
        ));
    }

    #[test]
    fn required_index_attestation_closure_is_checked_before_import() {
        let (config_sha, config_bytes) = blob(r#"{"os": "linux", "architecture": "amd64"}"#);
        let (manifest_sha, manifest_bytes) = blob(&format!(
            r#"{{"config": {{"digest": "sha256:{config_sha}"}}}}"#
        ));
        let (evidence_sha, evidence_bytes) = blob(r#"{"attestation": "pinned external metadata"}"#);
        let (attest_sha, attest_bytes) = blob(&format!(
            r#"{{"config": {{"digest": "sha256:{config_sha}", "size": {}}}, "layers": [{{"digest": "sha256:{evidence_sha}", "size": {}}}]}}"#,
            config_bytes.len(),
            evidence_bytes.len()
        ));
        let (index_sha, index_bytes) = blob(&format!(
            r#"{{"manifests": [{{"digest": "sha256:{manifest_sha}", "platform": {{"os": "linux", "architecture": "amd64"}}}}, {{"digest": "sha256:{attest_sha}", "platform": {{"os": "unknown", "architecture": "unknown"}}, "annotations": {{"vnd.docker.reference.type": "attestation-manifest"}}}}]}}"#
        ));
        let row = ServiceRow {
            name: "fixture".into(),
            reference: format!("fixture@sha256:{index_sha}"),
            archive_url: String::new(),
            archive_sha256: String::new(),
            bytes: 0,
            manifest_sha256: manifest_sha.clone(),
            config_sha256: config_sha.clone(),
        };
        for (missing, corrupt) in [(true, false), (false, true), (false, false)] {
            let mut members = vec![
                (config_sha.clone(), config_bytes.clone()),
                (manifest_sha.clone(), manifest_bytes.clone()),
                (attest_sha.clone(), attest_bytes.clone()),
                (index_sha.clone(), index_bytes.clone()),
            ];
            if !missing {
                let data = if corrupt {
                    vec![b'x'; evidence_bytes.len()]
                } else {
                    evidence_bytes.clone()
                };
                members.push((evidence_sha.clone(), data));
            }
            let members: Vec<_> = members
                .into_iter()
                .map(|(sha, d)| (format!("blobs/sha256/{sha}"), d))
                .collect();
            let path = write(&format!("closure-{missing}-{corrupt}"), &members);
            let result = service_metadata(&path, &row);
            match (missing, corrupt) {
                (true, _) => assert!(result.unwrap_err().contains("missing pinned content")),
                (_, true) => assert!(result.unwrap_err().contains("content digest differs")),
                _ => assert_eq!(result.unwrap().at("os").as_str(), Some("linux")),
            }
            std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn service_platform_membership_and_loaded_content_are_verified() {
        let config_raw = r#"{"os": "linux", "architecture": "amd64", "config": {"Cmd": ["fixed"], "Image": "sha256:1111111111111111111111111111111111111111111111111111111111111111"}, "rootfs": {"type": "layers", "diff_ids": ["sha256:aaaa"]}}"#;
        let (config_sha, config_bytes) = blob(config_raw);
        let (manifest_sha, manifest_bytes) = blob(&format!(
            r#"{{"config": {{"digest": "sha256:{config_sha}"}}}}"#
        ));
        let (layer_sha, layer_bytes) = blob("attestation layer");
        let (attest_sha, attest_bytes) = blob(&format!(
            r#"{{"config": {{"digest": "sha256:{layer_sha}", "size": {}}}, "layers": []}}"#,
            layer_bytes.len()
        ));
        let (index_sha, index_bytes) = blob(&format!(
            r#"{{"manifests": [{{"digest": "sha256:{manifest_sha}", "platform": {{"os": "linux", "architecture": "amd64"}}}}, {{"digest": "sha256:{attest_sha}", "platform": {{"os": "unknown", "architecture": "unknown"}}, "annotations": {{"vnd.docker.reference.type": "attestation-manifest"}}}}]}}"#
        ));
        let members: Vec<(String, Vec<u8>)> = [
            (config_sha.clone(), config_bytes),
            (manifest_sha.clone(), manifest_bytes),
            (layer_sha.clone(), layer_bytes),
            (attest_sha, attest_bytes),
            (index_sha.clone(), index_bytes),
        ]
        .into_iter()
        .map(|(sha, data)| (format!("blobs/sha256/{sha}"), data))
        .collect();
        let path = write("service", &members);
        let row = ServiceRow {
            name: "fixture".into(),
            reference: format!("fixture@sha256:{index_sha}"),
            archive_url: String::new(),
            archive_sha256: String::new(),
            bytes: 0,
            manifest_sha256: manifest_sha.clone(),
            config_sha256: config_sha.clone(),
        };
        let config = service_metadata(&path, &row).unwrap();
        assert_eq!(config.at("os").as_str(), Some("linux"));
        let wrong = ServiceRow {
            manifest_sha256: "f".repeat(64),
            ..row
        };
        assert!(
            service_metadata(&path, &wrong)
                .unwrap_err()
                .contains("anchored")
        );
        let row = ServiceRow {
            manifest_sha256: manifest_sha.clone(),
            ..wrong
        };
        let truncated: Vec<_> = members
            .iter()
            .filter(|(n, _)| !n.contains(&layer_sha))
            .cloned()
            .collect();
        let missing = write("service-missing", &truncated);
        assert!(
            service_metadata(&missing, &row)
                .unwrap_err()
                .contains("missing pinned content")
        );

        let mut actual = json::parse(
            format!(r#"{{"Id": "sha256:{manifest_sha}", "RepoDigests": ["{}"], "Os": "linux", "Architecture": "amd64", "Config": {{"Cmd": ["fixed"], "Image": ""}}, "RootFS": {{"Type": "layers", "Layers": ["sha256:aaaa"]}}}}"#, row.reference).as_bytes(),
        )
        .unwrap();
        verify_service_import(&actual, &row, &config).unwrap();
        let mut arm = actual.clone();
        arm.set("Architecture", "arm64".into());
        assert!(
            verify_service_import(&arm, &row, &config)
                .unwrap_err()
                .contains("execution")
        );
        actual.set(
            "RepoDigests",
            vec![Value::from(format!("fixture@sha256:{manifest_sha}"))].into(),
        );
        assert!(
            verify_service_import(&actual, &row, &config)
                .unwrap_err()
                .contains("catalog")
        );
        for dir in [path.parent().unwrap(), missing.parent().unwrap()] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
