//! The syn source checks (`crates/busbar-contract/tests/architecture_surface.rs`),
//! run as a small harness over the exact source inventory of this build.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value as Json};
use toml::{Table, Value};

use crate::policy::{self, Policy, CORE};
use crate::py::{self, Cmd};
use crate::refuse::{Result, Rule, Violation};

fn rust_files(root: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    // `Path.rglob('*.rs')`: follows directories, reports files (also symlinks).
    let mut entries: Vec<_> = std::fs::read_dir(root)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        } else if file_type.is_symlink() && path.is_dir() {
            // rglob does not descend into symlinked directories.
        }
    }
    Ok(())
}

/// `core_source_inventory`: every Rust file of every core member.
pub fn core_source_inventory(policy: &Policy, checkout: &Path) -> Result<Vec<String>> {
    let checkout = py::resolve(checkout);
    let mut paths = BTreeSet::new();
    for entry in policy.core().values() {
        let entry = entry.as_table().cloned().unwrap_or_default();
        let manifest = policy::manifest(&entry)?;
        let root = py::resolve(
            py::join(&checkout, manifest)
                .parent()
                .unwrap_or(Path::new("/")),
        );
        if !root.starts_with(&checkout) || !root.is_dir() {
            return Err(Violation::new(
                Rule::SourceRoots,
                format!("invalid core source root: {}", root.display()),
            ));
        }
        let mut files = Vec::new();
        rust_files(&root, &mut files).map_err(|e| py::os_error(&e, &root))?;
        let mut member = BTreeSet::new();
        for path in files {
            let resolved = py::resolve(&path);
            if !resolved.starts_with(&checkout) {
                return Err(Violation::new(
                    Rule::SourceRoots,
                    format!("core source escapes candidate checkout: {}", path.display()),
                ));
            }
            member.insert(py::s(&resolved));
        }
        if member.is_empty() {
            return Err(Violation::new(
                Rule::SourceRoots,
                format!("core member has no Rust sources: {}", root.display()),
            ));
        }
        paths.extend(member);
    }
    Ok(paths.into_iter().collect())
}

/// `core_target_roots`: the actual workspace targets of every core member.
pub fn core_target_roots(policy: &Policy, checkout: &Path, metadata: &Json) -> Result<Vec<String>> {
    let checkout = py::resolve(checkout);
    let mut roots = BTreeSet::new();
    let mut found = BTreeSet::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let name = package["name"].as_str().unwrap_or("");
        let Some(entry) = policy.core().get(name).and_then(Value::as_table) else {
            continue;
        };
        let expected = py::resolve(&py::join(&checkout, policy::manifest(entry)?));
        if py::resolve(Path::new(package["manifest_path"].as_str().unwrap_or(""))) != expected {
            return Err(Violation::new(
                Rule::SourceRoots,
                format!("core target metadata does not name its actual manifest: {name}"),
            ));
        }
        found.insert(name.to_string());
        for target in package["targets"].as_array().into_iter().flatten() {
            let path = py::resolve(Path::new(target["src_path"].as_str().unwrap_or("")));
            if !path.starts_with(&checkout) || !path.is_file() {
                return Err(Violation::new(
                    Rule::SourceRoots,
                    format!(
                        "core target source escapes or is missing: {}",
                        path.display()
                    ),
                ));
            }
            roots.insert(py::s(&path));
        }
    }
    let core: BTreeSet<String> = policy.core().keys().cloned().collect();
    if found != core {
        let missing: Vec<String> = core.difference(&found).cloned().collect();
        return Err(Violation::new(
            Rule::SourceRoots,
            format!(
                "missing actual core target metadata: {}",
                py::repr_list(&missing)
            ),
        ));
    }
    Ok(roots.into_iter().collect())
}

#[derive(Debug, serde::Serialize)]
pub struct SourceReceipt {
    pub source_roots: usize,
    pub core_source_files: usize,
    pub trusted_source_check: bool,
}

fn write_json(path: &Path, value: &Json) -> Result<()> {
    std::fs::write(path, value.to_string()).map_err(|e| py::os_error(&e, path))
}

/// The source-check harness manifest: syn, quote, proc-macro2 and serde_json
/// exactly as the trusted root workspace declares them.
fn harness_manifest(trusted: &Path) -> Result<Table> {
    let root = py::read_toml(&py::join(trusted, "Cargo.toml"))?;
    let deps = root
        .get("workspace")
        .and_then(Value::as_table)
        .and_then(|w| w.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let mut dev = Table::new();
    for name in ["syn", "quote", "proc-macro2", "serde_json"] {
        let mut cfg = match deps.get(name) {
            Some(Value::String(v)) => {
                let mut t = Table::new();
                t.insert("version".into(), Value::String(v.clone()));
                t
            }
            Some(Value::Table(t)) => t.clone(),
            _ => {
                return Err(Violation::new(
                    Rule::PolicyShape,
                    format!("trusted workspace does not declare {name}"),
                ))
            }
        };
        if name == "syn" {
            let mut features: BTreeSet<String> = cfg
                .get("features")
                .and_then(Value::as_array)
                .map(|f| {
                    f.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            features.insert("full".into());
            features.insert("visit".into());
            cfg.insert(
                "features".into(),
                Value::Array(features.into_iter().map(Value::String).collect()),
            );
        }
        dev.insert(name.to_string(), Value::Table(cfg));
    }
    let mut package = Table::new();
    package.insert(
        "name".into(),
        Value::String("architecture-source-check".into()),
    );
    package.insert("version".into(), Value::String("0.0.0".into()));
    package.insert("edition".into(), Value::String("2021".into()));
    let mut manifest = Table::new();
    manifest.insert("workspace".into(), Value::Table(Table::new()));
    manifest.insert("package".into(), Value::Table(package));
    manifest.insert("dev-dependencies".into(), Value::Table(dev));
    Ok(manifest)
}

/// `check_sources`.
pub fn check_sources(
    policy: &Policy,
    repository: &str,
    checkout: &Path,
    metadata: &Json,
    trusted: &Path,
    scratch: &Path,
) -> Result<SourceReceipt> {
    let mut roots: Vec<String> = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let Some(entry) = policy.get(package["name"].as_str().unwrap_or("")) else {
            continue;
        };
        let role = policy::role(entry);
        if policy::repository(entry) == repository
            && (role == "implementation" || role == "wrapper")
        {
            for target in package["targets"].as_array().into_iter().flatten() {
                let kinds = target["kind"].as_array().cloned().unwrap_or_default();
                if kinds
                    .iter()
                    .any(|k| matches!(k.as_str(), Some("lib" | "rlib" | "cdylib")))
                {
                    roots.push(target["src_path"].as_str().unwrap_or("").to_string());
                }
            }
        }
    }
    let is_core = repository == CORE;
    if !is_core && roots.is_empty() {
        return Err(Violation::new(
            Rule::SourceRoots,
            "no classified plugin source roots",
        ));
    }
    let harness = scratch.join("source-check");
    std::fs::create_dir_all(harness.join("tests")).map_err(|e| py::os_error(&e, &harness))?;
    let surface = py::join(
        trusted,
        "crates/busbar-contract/tests/architecture_surface.rs",
    );
    std::fs::write(
        harness.join("tests/architecture_surface.rs"),
        py::read_bytes(&surface)?,
    )
    .map_err(|e| py::os_error(&e, &harness))?;
    let manifest = toml::to_string(&harness_manifest(trusted)?)
        .map_err(|e| Violation::new(Rule::Parse, e.to_string()))?;
    std::fs::write(harness.join("Cargo.toml"), manifest).map_err(|e| py::os_error(&e, &harness))?;

    let mut env_set: Vec<(String, String)> = Vec::new();
    let unique_roots: BTreeSet<String> = roots.iter().cloned().collect();
    if !roots.is_empty() {
        let inventory = scratch.join("source-roots.json");
        write_json(&inventory, &json!(unique_roots.iter().collect::<Vec<_>>()))?;
        env_set.push(("BUSBAR_ARCHITECTURE_SOURCES".into(), py::s(&inventory)));
    }
    let mut mapping: BTreeMap<String, String> = BTreeMap::new();
    let mut crate_roots = Vec::new();
    let mut source_metadata = metadata.clone();
    if is_core {
        let text = Cmd::new([
            "cargo".to_string(),
            "metadata".into(),
            "--no-deps".into(),
            "--format-version".into(),
            "1".into(),
            "--manifest-path".into(),
            py::s(&py::join(checkout, "Cargo.toml")),
        ])
        .cwd(checkout)
        .output()?;
        source_metadata = serde_json::from_str(&text)
            .map_err(|e| Violation::new(Rule::Parse, format!("cargo metadata: {e}")))?;
        crate_roots = core_target_roots(policy, checkout, &source_metadata)?;
    }
    if !roots.is_empty() || is_core {
        let mut build = if is_core {
            vec![
                "cargo".to_string(),
                "check".into(),
                "--workspace".into(),
                "--manifest-path".into(),
                py::s(&py::join(checkout, "Cargo.toml")),
            ]
        } else {
            vec![
                "cargo".to_string(),
                "build".into(),
                "--manifest-path".into(),
                py::s(&scratch.join("shipping-probe/Cargo.toml")),
            ]
        };
        build.push("--message-format=json".into());
        eprintln!("busbar-arch: source materialization: {}", build[1]);
        let output = Cmd::new(build).cwd(checkout).output()?;
        for line in output.lines() {
            let row: Json = serde_json::from_str(line)
                .map_err(|e| Violation::new(Rule::Parse, e.to_string()))?;
            if row.get("reason").and_then(Json::as_str) != Some("build-script-executed") {
                continue;
            }
            for package in source_metadata["packages"].as_array().into_iter().flatten() {
                let name = package["name"].as_str().unwrap_or("");
                if package["id"] == row["package_id"] && policy.get(name).is_some() {
                    let manifest = Path::new(package["manifest_path"].as_str().unwrap_or(""));
                    mapping.insert(
                        py::s(manifest.parent().unwrap_or(Path::new("/"))),
                        row["out_dir"].as_str().unwrap_or("").to_string(),
                    );
                }
            }
        }
        let generated = scratch.join("generated-directories.json");
        write_json(&generated, &json!(mapping))?;
        env_set.push((
            "BUSBAR_ARCHITECTURE_GENERATED_DIRS".into(),
            py::s(&generated),
        ));
    }
    let mut core_files = 0;
    if is_core {
        let inventory = scratch.join("policy-sources.json");
        let raw_paths = core_source_inventory(policy, checkout)?;
        let mut paths: BTreeSet<String> = raw_paths.iter().cloned().collect();
        for output in mapping.values() {
            let mut files = Vec::new();
            let output = Path::new(output);
            if output.is_dir() {
                rust_files(output, &mut files).map_err(|e| py::os_error(&e, output))?;
            }
            for path in files {
                paths.insert(py::s(&py::resolve(&path)));
            }
        }
        let plugin_packages: BTreeSet<String> = policy
            .packages
            .iter()
            .filter(|(_, e)| {
                e.as_table()
                    .is_some_and(|e| matches!(policy::role(e), "implementation" | "wrapper"))
            })
            .map(|(name, _)| name.clone())
            .collect();
        let names: BTreeSet<String> = policy
            .repositories()
            .keys()
            .map(|r| {
                let name = r.split_once('/').map_or("", |(_, n)| n);
                name.splitn(3, '-').nth(2).unwrap_or("").to_string()
            })
            .collect();
        core_files = paths.len();
        write_json(
            &inventory,
            &json!({"paths": paths, "raw_paths": raw_paths, "roots": crate_roots,
                    "plugin_packages": plugin_packages, "names": names}),
        )?;
        env_set.push((
            "BUSBAR_ARCHITECTURE_POLICY_SOURCES".into(),
            py::s(&inventory),
        ));
    }
    let mut test = Cmd::new([
        "cargo".to_string(),
        "test".into(),
        "--manifest-path".into(),
        py::s(&harness.join("Cargo.toml")),
        "--test".into(),
        "architecture_surface".into(),
    ])
    .cwd(scratch);
    test.env_remove = [
        "BUSBAR_ARCHITECTURE_SOURCES",
        "BUSBAR_ARCHITECTURE_POLICY_SOURCES",
        "BUSBAR_ARCHITECTURE_GENERATED",
        "BUSBAR_ARCHITECTURE_GENERATED_DIRS",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    test.env_set = env_set;
    test.run()?;
    Ok(SourceReceipt {
        source_roots: unique_roots.len(),
        core_source_files: core_files,
        trusted_source_check: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_policy;

    #[test]
    fn sdk_nested_sources_tests_and_build_scripts_are_all_in_scope() {
        let dir = crate::tests::TempDir::new("inventory");
        let root = dir.path();
        let expected = [
            "crates/contract/src/lib.rs",
            "crates/contract/src/abi/sdk/hidden.rs",
            "crates/contract/tests/fixture.rs",
            "crates/contract/build.rs",
            "crates/kernel/src/lib.rs",
        ];
        for relative in expected {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "fn fixture() {}").unwrap();
        }
        let mut want: Vec<String> = expected
            .iter()
            .map(|p| py::s(&py::resolve(&root.join(p))))
            .collect();
        want.sort();
        assert_eq!(core_source_inventory(&test_policy(), root).unwrap(), want);
    }

    #[test]
    fn a_missing_core_member_is_not_silently_unchecked() {
        let dir = crate::tests::TempDir::new("inventory");
        let e = core_source_inventory(&test_policy(), dir.path()).unwrap_err();
        assert!(e.message.starts_with("invalid core source root"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_source_cannot_escape_the_candidate() {
        let dir = crate::tests::TempDir::new("inventory");
        let root = dir.path().join("candidate");
        for member in ["contract", "kernel"] {
            let path = root.join("crates").join(member).join("src");
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("lib.rs"), "fn fixture() {}").unwrap();
        }
        let outside = dir.path().join("outside.rs");
        std::fs::write(&outside, "fn fixture() {}").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("crates/contract/src/escape.rs")).unwrap();
        let e = core_source_inventory(&test_policy(), &root).unwrap_err();
        assert!(e.message.contains("escapes candidate"), "{e}");
    }

    #[test]
    fn actual_custom_binary_and_test_targets_are_retained() {
        let dir = crate::tests::TempDir::new("targets");
        let root = dir.path();
        let p = test_policy();
        let mut packages = Vec::new();
        let mut expected = Vec::new();
        for (name, entry) in p.core() {
            let manifest = root.join(entry["manifest"].as_str().unwrap());
            let mut targets = Vec::new();
            for relative in ["src/custom-binary.rs", "tests/custom-test.rs", "build.rs"] {
                let path = manifest.parent().unwrap().join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, "fn main() {}").unwrap();
                expected.push(py::s(&py::resolve(&path)));
                targets.push(json!({"src_path": py::s(&path)}));
            }
            packages
                .push(json!({"name": name, "manifest_path": py::s(&manifest), "targets": targets}));
        }
        expected.sort();
        assert_eq!(
            core_target_roots(&p, root, &json!({"packages": packages})).unwrap(),
            expected
        );
        packages[0]["manifest_path"] = json!(py::s(&root.join("resolution-stub/Cargo.toml")));
        let e = core_target_roots(&p, root, &json!({"packages": packages})).unwrap_err();
        assert!(e.message.contains("actual manifest"), "{e}");
    }

    #[test]
    fn missing_core_target_metadata_refuses() {
        let dir = crate::tests::TempDir::new("targets");
        let e =
            core_target_roots(&test_policy(), dir.path(), &json!({"packages": []})).unwrap_err();
        assert!(
            e.message.starts_with("missing actual core target metadata"),
            "{e}"
        );
    }
}
