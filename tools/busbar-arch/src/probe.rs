//! Shipping resolution: a disposable consumer manifest with no dev edges and no
//! workspace feature unification, resolved by `cargo metadata` against the
//! committed lock. Manifests are built as TOML values, never as text.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use toml::{Table, Value};

use crate::declared::{dependency, lock_packages};
use crate::policy::{self, Entry};
use crate::py::{self, Cmd};
use crate::refuse::{Result, Rule, Violation};

fn write(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).map_err(|e| py::os_error(&e, path))
}

fn mkdir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|e| py::os_error(&e, path))
}

fn table_of(pairs: Vec<(&str, Value)>) -> Table {
    let mut t = Table::new();
    for (k, v) in pairs {
        t.insert(k.to_string(), v);
    }
    t
}

fn render(manifest: &Table) -> Result<String> {
    toml::to_string(manifest)
        .map_err(|e| Violation::new(Rule::Parse, format!("cannot render probe manifest: {e}")))
}

fn package_table(name: Value, version: Value) -> Value {
    Value::Table(table_of(vec![
        ("name", name),
        ("version", version),
        ("edition", Value::String("2021".into())),
    ]))
}

const TEST_FEATURES: [&str; 2] = ["test-support", "test-seal"];

/// `binary_resolution_root`: Cargo ignores binary-only dependencies, so their
/// normal/build edges are resolved through a manifest with an empty library.
fn binary_resolution_root(checkout: &Path, entry: &Entry, probe: &Path) -> Result<PathBuf> {
    let original = py::join(checkout, policy::manifest(entry)?);
    let manifest = py::read_toml(&original)?;
    let original_dir = original.parent().unwrap_or(Path::new("/")).to_path_buf();
    let root_dir = if manifest.contains_key("workspace") {
        original_dir.clone()
    } else {
        checkout.to_path_buf()
    };
    let workspace = py::read_toml(&py::join(&root_dir, "Cargo.toml"))?
        .get("workspace")
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let package = manifest
        .get("package")
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let name = package
        .get("name")
        .cloned()
        .unwrap_or(Value::String(String::new()));
    let binary = probe.with_file_name(format!(
        "{}-{}",
        probe.file_name().unwrap_or_default().to_string_lossy(),
        name.as_str().unwrap_or("")
    ));
    mkdir(&binary.join("src"))?;
    write(
        &binary.join("src/lib.rs"),
        b"// Dependency resolution only; native CI builds the actual binary.\n",
    )?;
    let mut out = Table::new();
    out.insert("workspace".into(), Value::Table(Table::new()));
    out.insert(
        "package".into(),
        package_table(
            name,
            package
                .get("version")
                .cloned()
                .unwrap_or(Value::String(String::new())),
        ),
    );
    let mut groups: Vec<(Option<String>, Table)> = vec![(None, manifest.clone())];
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, tables) in targets {
            groups.push((
                Some(target.clone()),
                tables.as_table().cloned().unwrap_or_default(),
            ));
        }
    }
    let mut targets = Table::new();
    for (target, tables) in groups {
        let mut sections = Table::new();
        for section in ["dependencies", "build-dependencies"] {
            let mut rendered = Table::new();
            if let Some(deps) = tables.get(section).and_then(Value::as_table) {
                for (alias, value) in deps {
                    let (_, mut cfg) = dependency(alias, value, &workspace)?;
                    if let Some(path) = cfg.get("path").and_then(Value::as_str).map(str::to_string)
                    {
                        let inherited = value
                            .as_table()
                            .is_some_and(|t| policy::truthy(t.get("workspace")));
                        let base = if inherited { &root_dir } else { &original_dir };
                        cfg.insert(
                            "path".into(),
                            Value::String(py::s(&py::resolve(&py::join(base, path)))),
                        );
                    }
                    rendered.insert(alias.clone(), Value::Table(cfg));
                }
            }
            sections.insert(section.to_string(), Value::Table(rendered));
        }
        match target {
            None => {
                for (k, v) in sections {
                    out.insert(k, v);
                }
            }
            Some(target) => {
                targets.insert(target, Value::Table(sections));
            }
        }
    }
    if !targets.is_empty() {
        out.insert("target".into(), Value::Table(targets));
    }
    let mut features = Table::new();
    if let Some(declared) = manifest.get("features").and_then(Value::as_table) {
        for (name, values) in declared {
            if !TEST_FEATURES.contains(&name.as_str()) {
                features.insert(name.clone(), values.clone());
            }
        }
    }
    out.insert("features".into(), Value::Table(features));
    write(&binary.join("Cargo.toml"), render(&out)?.as_bytes())?;
    Ok(binary)
}

/// `resolve_shipping`: resolved metadata of the shipping (or assembly) roots.
pub fn resolve_shipping(
    checkout: &Path,
    entries: &[(String, &Entry)],
    scratch: &Path,
    assembly: bool,
) -> Result<Json> {
    let probe = scratch.join(if assembly {
        "assembly-probe"
    } else {
        "shipping-probe"
    });
    mkdir(&probe.join("src"))?;
    write(
        &probe.join("src/lib.rs"),
        b"// Admission-only resolution root.\n",
    )?;
    let mut dependencies = Table::new();
    let mut binary_roots: Vec<(String, String)> = Vec::new();
    for (index, (name, entry)) in entries.iter().enumerate() {
        let role = policy::role(entry);
        if role == "test_host" || (role == "assembly") != assembly {
            continue;
        }
        let manifest_path = py::join(checkout, policy::manifest(entry)?);
        let manifest = py::read_toml(&manifest_path)?;
        let features: BTreeSet<String> = manifest
            .get("features")
            .and_then(Value::as_table)
            .map(|f| {
                f.keys()
                    .filter(|k| !matches!(k.as_str(), "default" | "test-support" | "test-seal"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut directory = manifest_path
            .parent()
            .unwrap_or(Path::new("/"))
            .to_path_buf();
        if !manifest.contains_key("lib") && !directory.join("src/lib.rs").is_file() {
            directory = binary_resolution_root(checkout, entry, &probe)?;
            binary_roots.push((name.clone(), py::s(&py::resolve(&manifest_path))));
        }
        dependencies.insert(
            format!("root_{index}"),
            Value::Table(table_of(vec![
                ("package", Value::String(name.clone())),
                ("path", Value::String(py::s(&directory))),
                (
                    "features",
                    Value::Array(features.into_iter().map(Value::String).collect()),
                ),
            ])),
        );
    }
    let root_dir = if assembly {
        py::join(checkout, "dist/default")
    } else {
        checkout.to_path_buf()
    };
    let root = py::read_toml(&py::join(&root_dir, "Cargo.toml"))?;
    let mut manifest = Table::new();
    manifest.insert("workspace".into(), Value::Table(Table::new()));
    manifest.insert(
        "package".into(),
        package_table(
            Value::String("architecture-shipping-probe".into()),
            Value::String("0.0.0".into()),
        ),
    );
    manifest.insert("dependencies".into(), Value::Table(dependencies));
    if let Some(patches) = root.get("patch").and_then(Value::as_table) {
        let mut out = Table::new();
        for (source, table) in patches {
            let mut rendered = Table::new();
            for (name, cfg) in table.as_table().cloned().unwrap_or_default() {
                let mut cfg = cfg.as_table().cloned().unwrap_or_default();
                if let Some(path) = cfg.get("path").and_then(Value::as_str).map(str::to_string) {
                    cfg.insert(
                        "path".into(),
                        Value::String(py::s(&py::resolve(&py::join(&root_dir, path)))),
                    );
                }
                rendered.insert(name, Value::Table(cfg));
            }
            out.insert(source.clone(), Value::Table(rendered));
        }
        manifest.insert("patch".into(), Value::Table(out));
    }
    write(&probe.join("Cargo.toml"), render(&manifest)?.as_bytes())?;
    let committed = py::join(&root_dir, "Cargo.lock");
    if committed.is_file() {
        write(&probe.join("Cargo.lock"), &py::read_bytes(&committed)?)?;
    }
    let text = Cmd::new([
        "cargo".to_string(),
        "metadata".into(),
        "--format-version".into(),
        "1".into(),
        "--manifest-path".into(),
        py::s(&probe.join("Cargo.toml")),
    ])
    .cwd(scratch)
    .output()?;
    let mut metadata: Json = serde_json::from_str(&text)
        .map_err(|e| Violation::new(Rule::Parse, format!("cargo metadata: {e}")))?;
    if let Some(packages) = metadata.get_mut("packages").and_then(Json::as_array_mut) {
        for package in packages {
            let name = package["name"].as_str().unwrap_or("").to_string();
            if let Some((_, path)) = binary_roots.iter().find(|(n, _)| *n == name) {
                package["manifest_path"] = Json::String(path.clone());
            }
        }
    }
    if committed.is_file() {
        let lock = py::read_toml(&committed)?;
        let locked: BTreeSet<(String, String, Option<String>)> = lock_packages(&lock)
            .iter()
            .map(|p| {
                (
                    p.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    p.get("version")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    p.get("source").and_then(Value::as_str).map(str::to_string),
                )
            })
            .collect();
        for package in metadata["packages"].as_array().into_iter().flatten() {
            let Some(source) = package.get("source").and_then(Json::as_str) else {
                continue;
            };
            if source.is_empty() {
                continue;
            }
            let name = package["name"].as_str().unwrap_or("");
            let version = package["version"].as_str().unwrap_or("");
            if !locked.contains(&(
                name.to_string(),
                version.to_string(),
                Some(source.to_string()),
            )) {
                return Err(Violation::new(
                    Rule::LockDrift,
                    format!("shipping resolver drifted from committed lock: {name} {version}"),
                ));
            }
        }
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_only_root_retains_its_production_edges() {
        let dir = crate::tests::TempDir::new("probe");
        let root = dir.path();
        let directory = root.join("binary");
        std::fs::create_dir_all(directory.join("src")).unwrap();
        std::fs::write(directory.join("src/main.rs"), "fn main() {}").unwrap();
        std::fs::write(
            directory.join("Cargo.toml"),
            "[workspace]\n[package]\nname=\"product\"\nversion=\"0.0.0\"\n[dependencies]\nexternal={path=\"../external\"}\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("external/src")).unwrap();
        std::fs::write(root.join("external/src/lib.rs"), "").unwrap();
        std::fs::write(
            root.join("external/Cargo.toml"),
            "[package]\nname=\"external\"\nversion=\"0.0.0\"\n",
        )
        .unwrap();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        let entry: Entry = "manifest = \"binary/Cargo.toml\"\nrole = \"core\"\n"
            .parse()
            .unwrap();
        let entries = vec![("product".to_string(), &entry)];
        let metadata = resolve_shipping(root, &entries, &root.join("scratch"), false).unwrap();
        let product = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "product")
            .unwrap();
        assert_eq!(
            product["manifest_path"].as_str().unwrap(),
            py::s(&py::resolve(&directory.join("Cargo.toml")))
        );
        let node = metadata["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == product["id"])
            .unwrap();
        assert_eq!(node["deps"].as_array().unwrap().len(), 1);
        assert_eq!(node["deps"][0]["name"], "external");
    }
}
