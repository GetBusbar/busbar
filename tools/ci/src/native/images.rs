//! Trusted prebuilt product test images: the pinned plugin cdylibs of core's
//! product-inputs step (the Python controller's `native_product_images`,
//! byte-compatible identities and registry layout).
//!
//! Producer: the core dev push dependency-unit shard that owns a product runs
//! `product_artifacts.py --image-only <repo>` (the consumer's exact
//! `image_argv()`, cwd and shared-target layout) in the ordinary confinement
//! and publishes the image under a key over every build input.
//!
//! Consumer: core native qualification computes the same key per planned
//! product, requires a protected dev-push producer and verified digests, and
//! stages hits read-only for the product-inputs step only; the trusted script
//! re-verifies and copies each image to Cargo's output path, building every
//! other product as before. The candidate packer is never prebuilt. After the
//! step each restored image must be byte-identical at its bound path.
use super::Q;
use super::depcache::{self, Fallback, GitLab, Registry};
use super::sp::{self, R};
use crate::json::{self, Value, object};
use crate::sha256;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const SCHEMA: &str = "busbar.product-test-image/1";
pub const PACKAGE: &str = "busbar-product-test-images";
pub const MAX_IMAGE_BYTES: u64 = 512 << 20;
pub const MOUNT: &str = "/__busbar_product_images";
const TARGET: &str = "x86_64-unknown-linux-gnu";
const WORKERS: usize = 8;

fn unavailable<T>(message: impl Into<String>) -> Result<T, Fallback> {
    Err(message.into())
}

fn need(ok: bool, message: &str) -> Result<(), Fallback> {
    if ok { Ok(()) } else { unavailable(message) }
}

fn optional_digest(path: &Path) -> Result<Value, Fallback> {
    match std::fs::symlink_metadata(path) {
        Err(_) => Ok(Value::Null),
        Ok(meta) if meta.is_file() => Ok(sha256::file(path)?.into()),
        Ok(_) => unavailable(format!("indirect Cargo configuration: {}", sp::text(path))),
    }
}

/// Digests of every Cargo configuration file cargo discovers from `root`;
/// any `.cargo` above it is unexpected on the controller layout: a miss.
pub fn cargo_configuration(root: &Path) -> Result<Value, Fallback> {
    let mut rows = Vec::new();
    for relative in [".cargo/config.toml", ".cargo/config"] {
        rows.push((relative.to_owned(), optional_digest(&root.join(relative))?));
    }
    let resolved = sp::resolve(root);
    for parent in resolved.ancestors().skip(1) {
        if std::fs::symlink_metadata(parent.join(".cargo")).is_ok() {
            return unavailable("Cargo configuration above the build root");
        }
    }
    Ok(Value::Object(rows))
}

/// The trusted recipe: product_artifacts.py and the product-inputs wrapper.
pub fn builder_sha256(trusted: &Path) -> Result<String, Fallback> {
    let mut rows = Vec::new();
    for relative in [
        "scripts/architecture/product_artifacts.py",
        "scripts/ci-product-inputs.sh",
    ] {
        let path = trusted.join(relative);
        let digest = if path.is_file() {
            sha256::file(&path)?.into()
        } else {
            Value::Null
        };
        rows.push(Value::Array(vec![relative.into(), digest]));
    }
    Ok(depcache::key(&Value::Array(rows)))
}

fn seed_configuration(q: &mut Q) -> Result<Value, Fallback> {
    match q.execution.as_ref().and_then(|e| e.dependency_seed.clone()) {
        None => Ok(Value::Null),
        Some(seed) => {
            let path = seed.join("config.toml");
            if path.is_file() {
                Ok(sha256::file(&path)?.into())
            } else {
                Ok(Value::Null)
            }
        }
    }
}

/// Everything outside the product commit that decides the image bytes.
pub fn identity(q: &mut Q, row: &Value, sdk: &str) -> Result<Value, Fallback> {
    let mut environment: Vec<(String, Value)> = depcache::COMPILE_ENV
        .iter()
        .map(|k| {
            (
                (*k).to_owned(),
                q.env.get(k).map_or(Value::Null, Value::from),
            )
        })
        .collect();
    environment.push((
        "CI".to_owned(),
        q.env.get("CI").map_or(Value::Null, Value::from),
    ));
    let field = |name: &str| row.at(name).as_str().unwrap_or("").to_owned();
    let image = q
        .execution()
        .config
        .at("image")
        .as_str()
        .unwrap_or("")
        .to_owned();
    Ok(object([
        ("schema", SCHEMA.into()),
        ("repository", format!("GetBusbar/{}", field("repo")).into()),
        ("commit", field("commit").into()),
        ("package", field("package").into()),
        ("image_name", field("image").into()),
        ("lock_sha256", field("lock_sha256").into()),
        ("sdk", sdk.into()),
        ("image", image.into()),
        ("target", TARGET.into()),
        ("cargo_home", depcache::CARGO_HOME_PATH.into()),
        ("cargo_home_config_sha256", seed_configuration(q)?),
        ("environment", Value::Object(environment)),
        ("cargo_configuration", cargo_configuration(&q.root)?),
        ("builder_sha256", builder_sha256(&q.trusted)?.into()),
    ]))
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// One product's lookup; `Ok(None)` is an absent image (build as before).
fn restore_one(
    registry: &mut dyn Registry,
    row: &Value,
    wanted: &Value,
    staging: &Path,
    record: &mut Value,
) -> Result<Option<Value>, Fallback> {
    let repo = row.at("repo").as_str().unwrap_or("");
    let image_name = row.at("image").as_str().unwrap_or("");
    let version = depcache::key(wanted);
    record.set("key", version.as_str().into());
    let Some(data) = registry.read(&version, depcache::MANIFEST, depcache::MAX_MANIFEST_BYTES)?
    else {
        return Ok(None);
    };
    let manifest = json::parse(&data)?;
    need(
        manifest.at("schema").as_str() == Some(SCHEMA)
            && manifest.at("key").as_str() == Some(version.as_str())
            && json::encoded(manifest.at("identity")) == json::encoded(wanted),
        "image manifest identity differs",
    )?;
    let archive = manifest.at("archive");
    let image = manifest.at("image");
    let sha = archive.at("sha256").as_str().unwrap_or("").to_owned();
    let bytes = archive.at("bytes").as_u64().unwrap_or(0);
    let image_sha = image.at("sha256").as_str().unwrap_or("").to_owned();
    let files = manifest.at("files");
    need(
        bytes > 0
            && bytes <= MAX_IMAGE_BYTES
            && hex64(&sha)
            && hex64(&image_sha)
            && archive.at("name").as_str() == Some(format!("image-{sha}.tar.gz").as_str())
            && files.as_object().is_some_and(|f| f.len() == 1)
            && files.at(image_name).as_str() == Some(image_sha.as_str()),
        "image manifest archive is invalid",
    )?;
    record.set(
        "provenance",
        depcache::provenance_in(registry, PACKAGE, &version, &manifest)?,
    );
    let download = staging.join(format!("{repo}.tar.gz"));
    let destination = staging.join(repo);
    let fetched = registry
        .download(
            &version,
            &format!("image-{sha}.tar.gz"),
            &download,
            bytes,
            &sha,
        )
        .and_then(|()| {
            let expected = [(image_name.to_owned(), image_sha.clone())]
                .into_iter()
                .collect();
            depcache::unpack(&download, &destination, &expected)
        });
    let _ = std::fs::remove_file(&download);
    fetched?;
    need(
        sha256::file(&destination.join(image_name))? == image_sha,
        "image digest differs from its manifest",
    )?;
    record.set("status", "hit".into());
    record.set("sha256", image_sha.as_str().into());
    record.set("bytes", image.at("bytes").clone());
    Ok(Some(object([
        ("commit", row.at("commit").clone()),
        ("image", image_name.into()),
        ("lock_sha256", row.at("lock_sha256").clone()),
        ("file", format!("{repo}/{image_name}").into()),
        ("sha256", image_sha.into()),
        ("key", version.into()),
    ])))
}

/// Stage verified images read-only for product-inputs; return their index.
/// `registry: None` uses one GitLab client per concurrent lookup.
pub fn restore(
    q: &mut Q,
    vector: &Value,
    revision: &str,
    registry: Option<&mut dyn Registry>,
) -> R<Value> {
    let mut record = object([
        ("status", "not-applicable".into()),
        ("products", Value::Object(Vec::new())),
    ]);
    if q.execution.is_none() {
        q.receipt.set("product_images", record);
        q.save()?;
        return Ok(Value::Object(Vec::new()));
    }
    let started = Instant::now();
    let staging = q.control.join("product-images");
    let sdk = vector.at("sdk").as_str().unwrap_or("").to_owned();
    let prepared = (|| -> R<Vec<(Value, Value)>> {
        let planned = crate::product::canonical_images(&q.work, &q.policy, vector, revision)?;
        let mut rows = Vec::new();
        for (row, _) in planned {
            let wanted = identity(q, &row, &sdk).map_err(sp::from_text);
            rows.push((row, wanted?));
        }
        sp::mkdir(&staging, 0o700, false)?;
        Ok(rows)
    })();
    let rows = match prepared {
        Ok(rows) => rows,
        Err(error) if error.kind != sp::Kind::Interrupted => {
            record.set("status", "fallback".into());
            record.set(
                "reason",
                error.message.chars().take(500).collect::<String>().into(),
            );
            discard(q);
            q.receipt.set("product_images", record);
            q.save()?;
            return Ok(Value::Object(Vec::new()));
        }
        Err(error) => return Err(error),
    };
    let lookup = |registry: &mut dyn Registry, row: &Value, wanted: &Value| {
        let mut result = object([("status", "miss".into())]);
        match restore_one(registry, row, wanted, &staging, &mut result) {
            Ok(entry) => (result, entry),
            Err(reason) => {
                result.set("status", "fallback".into());
                result.set(
                    "reason",
                    reason.chars().take(500).collect::<String>().into(),
                );
                let repo = row.at("repo").as_str().unwrap_or("");
                if !repo.is_empty() {
                    let _ = sp::rmtree(&staging.join(repo));
                }
                (result, None)
            }
        }
    };
    let results: Vec<(Value, Option<Value>)> = match registry {
        Some(registry) => rows
            .iter()
            .map(|(row, wanted)| lookup(registry, row, wanted))
            .collect(),
        None => {
            let token = std::env::var("CI_JOB_TOKEN").unwrap_or_default();
            let mut results = Vec::new();
            for chunk in rows.chunks(WORKERS.max(1)) {
                let partial: Vec<(Value, Option<Value>)> = std::thread::scope(|scope| {
                    let handles: Vec<_> = chunk
                        .iter()
                        .map(|(row, wanted)| {
                            let token = token.clone();
                            let lookup = &lookup;
                            scope.spawn(move || {
                                let mut client = GitLab {
                                    token,
                                    package: PACKAGE,
                                };
                                lookup(&mut client, row, wanted)
                            })
                        })
                        .collect();
                    handles
                        .into_iter()
                        .map(|h| {
                            h.join()
                                .unwrap_or_else(|_| (object([("status", "fallback".into())]), None))
                        })
                        .collect()
                });
                results.extend(partial);
            }
            results
        }
    };
    let mut index = Vec::new();
    let mut products = Vec::new();
    for ((row, _), (result, entry)) in rows.iter().zip(results) {
        let repo = row.at("repo").as_str().unwrap_or("").to_owned();
        products.push((repo.clone(), result));
        if let Some(entry) = entry {
            index.push((repo, entry));
        }
    }
    let hits = index.len();
    let index = Value::Object(index);
    record.set("products", Value::Object(products));
    let staged = sp::write(&staging.join("index.json"), json::encoded(&index))
        .and_then(|()| depcache::seal(&staging).map_err(sp::from_text))
        .and_then(|()| {
            let roots = q.execution().roots.clone();
            depcache::readonly_seed(&staging, &roots).map_err(sp::from_text)
        });
    let index = match staged {
        Ok(path) => {
            q.execution().product_images = Some(path);
            let status = if hits == rows.len() && !rows.is_empty() {
                "hit"
            } else if hits > 0 {
                "partial"
            } else {
                "miss"
            };
            record.set("status", status.into());
            index
        }
        Err(error) => {
            record.set("status", "fallback".into());
            record.set(
                "reason",
                error.message.chars().take(500).collect::<String>().into(),
            );
            discard(q);
            Value::Object(Vec::new())
        }
    };
    record.set(
        "restore_seconds",
        sp::round_float(started.elapsed().as_secs_f64(), 3),
    );
    q.receipt.set("product_images", record);
    q.save()?;
    Ok(index)
}

/// Every restored image must still be the trusted bytes at its bound path.
pub fn verify(q: &mut Q, index: &Value, vector: &Value, revision: &str) -> R<()> {
    let Some(entries) = index.as_object() else {
        return Ok(());
    };
    if entries.is_empty() {
        return Ok(());
    }
    let planned = crate::product::canonical_images(&q.work, &q.policy, vector, revision)?;
    for (repo, entry) in entries {
        let path = planned
            .iter()
            .find(|(row, _)| row.at("repo").as_str() == Some(repo.as_str()))
            .map(|(_, path)| path.clone())
            .ok_or_else(|| sp::violation("restored product image has no planned path"))?;
        let actual = q.with_candidate_output(&path, MAX_IMAGE_BYTES, true, |stream, _| {
            use std::io::Read;
            let mut data = Vec::new();
            stream
                .read_to_end(&mut data)
                .map_err(|e| sp::os_error(&e, None))?;
            Ok(sha256::hex(&data))
        })?;
        if Some(actual.as_str()) != entry.at("sha256").as_str() {
            return Err(sp::violation(format!(
                "restored product image changed during product preparation: {repo}"
            )));
        }
        if let Some(row) = q
            .receipt
            .get_mut("product_images")
            .and_then(|products| products.get_mut("products"))
            .and_then(|p| p.get_mut(repo))
        {
            row.set("verified_after_step", true.into());
        }
    }
    q.save()
}

pub fn discard(q: &mut Q) {
    if let Some(execution) = q.execution.as_mut() {
        execution.product_images = None;
    }
    let staging = q.control.join("product-images");
    if staging.exists() {
        depcache::discard(Some(&staging));
    }
}

// ---- producer ------------------------------------------------------------------------

fn produce_image(q: &mut Q, row: &Value, sdk: &str, registry: &mut dyn Registry) -> R<Value> {
    let repo = sp::at_str(row, "repo")?.to_owned();
    let image_name = sp::at_str(row, "image")?.to_owned();
    let wanted = identity(q, row, sdk).map_err(sp::from_text)?;
    let version = depcache::key(&wanted);
    let mut result = object([
        ("repo", repo.as_str().into()),
        ("commit", row.at("commit").clone()),
        ("key", version.as_str().into()),
        ("kind", "image".into()),
    ]);
    if registry
        .read(&version, depcache::MANIFEST, depcache::MAX_MANIFEST_BYTES)
        .map_err(sp::from_text)?
        .is_some()
    {
        result.set("status", "present".into());
        return Ok(result);
    }
    // One shard-wide target, like the consumer's shared CARGO_TARGET_DIR.
    let target = q.work.join("product-images-target");
    let cache = q.env.get("MODERNCI_CACHE_DIR").unwrap_or("").to_owned();
    let root = q.root.clone();
    let argv = super::pysteps::product_image(&q.trusted, &root, &target, &cache, &repo);
    let stdout = q.run_in(&format!("product-image-{repo}"), argv, &root)?;
    let built = PathBuf::from(sp::read_text(&stdout)?.trim());
    if built.file_name().and_then(|n| n.to_str()) != Some(image_name.as_str())
        || built.parent() != Some(target.join("debug").as_path())
    {
        return Err(sp::violation(
            "producer image path differs from the consumer binding",
        ));
    }
    let owned = q.control.join("product-images-out").join(&repo);
    let _ = sp::rmtree(&owned);
    sp::mkdirs(&owned, false)?;
    let image_path = owned.join(&image_name);
    q.collect_output(&built, &image_path, MAX_IMAGE_BYTES, true)?;
    let image_sha = sha256::file(&image_path).map_err(sp::from_text)?;
    let image_bytes = std::fs::metadata(&image_path)
        .map_err(|e| sp::os_error(&e, Some(&image_path)))?
        .len();
    let parent = owned.parent().unwrap_or(Path::new("/")).to_owned();
    let archive_tmp = parent.join(format!("{repo}.tar.gz"));
    let files = depcache::pack(&owned, &archive_tmp).map_err(sp::from_text)?;
    let digest = sha256::file(&archive_tmp).map_err(sp::from_text)?;
    let bytes = std::fs::metadata(&archive_tmp)
        .map_err(|e| sp::os_error(&e, Some(&archive_tmp)))?
        .len();
    let name = format!("image-{digest}.tar.gz");
    let env = |k: &str| std::env::var(k).unwrap_or_default();
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
            "image",
            object([
                ("sha256", image_sha.as_str().into()),
                ("bytes", image_bytes.into()),
            ]),
        ),
        (
            "product",
            object([
                ("repo", repo.as_str().into()),
                ("commit", row.at("commit").clone()),
            ]),
        ),
        (
            "producer",
            object([
                (
                    "pipeline_id",
                    Value::int(sp::py_int(&env("CI_PIPELINE_ID"))?),
                ),
                ("job_id", Value::int(sp::py_int(&env("CI_JOB_ID"))?)),
                ("commit", env("CI_COMMIT_SHA").into()),
                ("ref", env("CI_COMMIT_BRANCH").into()),
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
        .upload(&version, depcache::MANIFEST, &manifest_path)
        .map_err(sp::from_text)?;
    result.set("status", "published".into());
    result.set("sha256", image_sha.into());
    result.set("bytes", image_bytes.into());
    sp::rmtree(&owned)?;
    let _ = std::fs::remove_file(&archive_tmp);
    let _ = std::fs::remove_file(&manifest_path);
    Ok(result)
}

/// Called by the dependency-unit producer for its shard's products only.
pub fn produce(q: &mut Q, rows: &[Value], registry: Option<&mut dyn Registry>) -> R<()> {
    let mut owned;
    let registry: &mut dyn Registry = match registry {
        Some(registry) => registry,
        None => {
            owned = GitLab {
                token: std::env::var("CI_JOB_TOKEN").unwrap_or_default(),
                package: PACKAGE,
            };
            &mut owned
        }
    };
    let vector = sp::read_json(&q.root.join("scripts/ci-product-pins.json"))?;
    let sdk = vector.at("sdk").as_str().unwrap_or("").to_owned();
    let source = q.receipt.at("source").as_str().unwrap_or("").to_owned();
    let declared: Vec<String> =
        crate::product::canonical_images(&q.work, &q.policy, &vector, &source)?
            .into_iter()
            .filter_map(|(row, _)| row.at("repo").as_str().map(str::to_owned))
            .collect();
    let mut results = Vec::new();
    for row in rows {
        let repo = row.at("repo").as_str().unwrap_or("");
        if !declared.iter().any(|d| d == repo) {
            continue;
        }
        let result = match produce_image(q, row, &sdk, registry) {
            Ok(result) => result,
            Err(error) if error.kind != sp::Kind::Interrupted => object([
                ("repo", repo.into()),
                ("kind", "image".into()),
                ("status", "failed".into()),
                (
                    "reason",
                    error.message.chars().take(500).collect::<String>().into(),
                ),
            ]),
            Err(error) => return Err(error),
        };
        results.push(result);
        q.receipt
            .set("product_images_produced", Value::Array(results.clone()));
        q.save()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestor_cargo_configuration_is_a_miss_and_absent_files_are_null() {
        let base = std::env::temp_dir().join(format!("busbar-images-{}", std::process::id()));
        let root = base.join("plain/root");
        std::fs::create_dir_all(&root).unwrap();
        let value = cargo_configuration(&root).unwrap();
        assert_eq!(value.at(".cargo/config.toml"), &Value::Null);
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        std::fs::write(root.join(".cargo/config.toml"), b"[env]\n").unwrap();
        assert_eq!(
            cargo_configuration(&root)
                .unwrap()
                .at(".cargo/config.toml")
                .as_str(),
            Some(sha256::hex(b"[env]\n").as_str())
        );
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        assert!(cargo_configuration(&nested).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    struct Fake {
        files: std::collections::BTreeMap<(String, String), Vec<u8>>,
        pipeline_ref: &'static str,
    }

    impl Registry for Fake {
        fn read(&mut self, v: &str, n: &str, _: u64) -> Result<Option<Vec<u8>>, Fallback> {
            Ok(self.files.get(&(v.to_owned(), n.to_owned())).cloned())
        }
        fn json(&mut self, path: &str) -> Result<Value, Fallback> {
            if path.starts_with("/packages?") {
                let version = path.rsplit("package_version=").next().unwrap_or("");
                return json::parse(
                    format!(r#"[{{"id": 5, "name": "{PACKAGE}", "version": "{version}"}}]"#)
                        .as_bytes(),
                );
            }
            let rows: Vec<Value> = self
                .files
                .iter()
                .map(|((_, name), data)| {
                    object([
                        ("file_name", name.as_str().into()),
                        ("file_sha256", sha256::hex(data).into()),
                        (
                            "pipelines",
                            Value::Array(vec![object([
                                ("id", Value::int(77)),
                                ("ref", self.pipeline_ref.into()),
                                ("sha", "c".repeat(40).into()),
                                ("source", "push".into()),
                            ])]),
                        ),
                    ])
                })
                .collect();
            Ok(Value::Array(rows))
        }
        fn download(
            &mut self,
            v: &str,
            n: &str,
            destination: &Path,
            size: u64,
            sha: &str,
        ) -> Result<(), Fallback> {
            let data = self.files[&(v.to_owned(), n.to_owned())].clone();
            std::fs::write(destination, &data).map_err(|e| e.to_string())?;
            need(
                data.len() as u64 == size && sha256::hex(&data) == sha,
                "dependency archive digest differs from its manifest",
            )
        }
        fn upload(&mut self, _: &str, _: &str, _: &Path) -> Result<(), Fallback> {
            Ok(())
        }
    }

    fn published(base: &Path, wanted: &Value, row: &Value, pipeline_ref: &'static str) -> Fake {
        let owned = base.join("owned");
        std::fs::create_dir_all(&owned).unwrap();
        let name = row.at("image").as_str().unwrap();
        std::fs::write(owned.join(name), b"trusted image").unwrap();
        let archive = base.join("image.tar.gz");
        let files = depcache::pack(&owned, &archive).unwrap();
        let data = std::fs::read(&archive).unwrap();
        let sha = sha256::hex(&data);
        let version = depcache::key(wanted);
        let manifest = object([
            ("schema", SCHEMA.into()),
            ("key", version.as_str().into()),
            ("identity", wanted.clone()),
            (
                "archive",
                object([
                    ("name", format!("image-{sha}.tar.gz").into()),
                    ("sha256", sha.as_str().into()),
                    ("bytes", (data.len() as u64).into()),
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
                "image",
                object([
                    ("sha256", sha256::hex(b"trusted image").into()),
                    ("bytes", 13u64.into()),
                ]),
            ),
            (
                "producer",
                object([
                    ("pipeline_id", Value::int(77)),
                    ("commit", "c".repeat(40).into()),
                ]),
            ),
        ]);
        let mut fake = Fake {
            files: Default::default(),
            pipeline_ref,
        };
        fake.files
            .insert((version.clone(), format!("image-{sha}.tar.gz")), data);
        fake.files.insert(
            (version, depcache::MANIFEST.into()),
            json::encoded(&manifest),
        );
        fake
    }

    #[test]
    fn verified_hit_stages_the_image_and_doubt_builds() {
        let base = std::env::temp_dir().join(format!("busbar-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let row = object([
            ("repo", "busbar-hook-fixture".into()),
            ("commit", "d".repeat(40).into()),
            ("image", "libbusbar_hook_fixture_plugin.so".into()),
            ("lock_sha256", "e".repeat(64).into()),
        ]);
        let wanted = object([("schema", SCHEMA.into()), ("commit", "d".repeat(40).into())]);
        for (pipeline_ref, other, hit) in [
            ("dev", false, true),
            ("feature", false, false),
            ("dev", true, false),
        ] {
            let staging = base.join(format!("staging-{pipeline_ref}-{other}"));
            std::fs::create_dir_all(&staging).unwrap();
            let mut fake = published(
                &base.join(format!("p-{pipeline_ref}-{other}")),
                &wanted,
                &row,
                pipeline_ref,
            );
            let asked = if other {
                object([("schema", SCHEMA.into()), ("commit", "f".repeat(40).into())])
            } else {
                wanted.clone()
            };
            let mut record = object([("status", "miss".into())]);
            let entry = restore_one(&mut fake, &row, &asked, &staging, &mut record);
            if hit {
                let entry = entry.unwrap().unwrap();
                assert_eq!(
                    entry.at("sha256").as_str(),
                    Some(sha256::hex(b"trusted image").as_str())
                );
                assert_eq!(
                    std::fs::read(staging.join(entry.at("file").as_str().unwrap())).unwrap(),
                    b"trusted image"
                );
            } else {
                // A foreign pipeline is refused; a different identity is absent.
                assert!(matches!(entry, Err(_) | Ok(None)));
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn builder_digest_matches_the_python_canonical_form() {
        let base = std::env::temp_dir().join(format!("busbar-builder-{}", std::process::id()));
        std::fs::create_dir_all(base.join("scripts/architecture")).unwrap();
        std::fs::write(
            base.join("scripts/architecture/product_artifacts.py"),
            b"# builder\n",
        )
        .unwrap();
        let expected = sha256::hex(
            format!(
                "[[\"scripts/architecture/product_artifacts.py\",\"{}\"],[\"scripts/ci-product-inputs.sh\",null]]\n",
                sha256::hex(b"# builder\n")
            )
            .as_bytes(),
        );
        assert_eq!(builder_sha256(&base).unwrap(), expected);
        let _ = std::fs::remove_dir_all(&base);
    }
}
