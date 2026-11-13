//! Manifest declarations, including cfg-disabled, optional, build and dev tables
//! that the resolved graph would not show.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use toml::{Table, Value};

use crate::graph::{ci_server_host, git_repository};
use crate::policy::{self, Entry, Policy, CORE};
use crate::py;
use crate::refuse::{Result, Rule, Violation};

/// `dependency_tables`: (kind, table) for the top level and every target.
pub fn dependency_tables(manifest: &Table) -> Vec<(&'static str, Table)> {
    const SECTIONS: [(&str, &str); 3] = [
        ("dependencies", "normal"),
        ("build-dependencies", "build"),
        ("dev-dependencies", "dev"),
    ];
    let mut out = Vec::new();
    let section = |t: &Table, name: &str| {
        t.get(name)
            .and_then(Value::as_table)
            .cloned()
            .unwrap_or_default()
    };
    for (name, kind) in SECTIONS {
        out.push((kind, section(manifest, name)));
    }
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for target in targets.values() {
            let target = target.as_table().cloned().unwrap_or_default();
            for (name, kind) in SECTIONS {
                out.push((kind, section(&target, name)));
            }
        }
    }
    out
}

fn as_dependency(value: &Value) -> Table {
    match value {
        Value::String(version) => {
            let mut t = Table::new();
            t.insert("version".into(), Value::String(version.clone()));
            t
        }
        Value::Table(t) => t.clone(),
        _ => Table::new(),
    }
}

fn features(t: &Table) -> Vec<Value> {
    match t.get("features") {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
}

/// `dependency`: the actual package name and the effective declaration, with
/// workspace inheritance applied (features are additive).
pub fn dependency(alias: &str, value: &Value, workspace: &Table) -> Result<(String, Table)> {
    let mut value = as_dependency(value);
    let inherit = value
        .remove("workspace")
        .is_some_and(|w| policy::truthy(Some(&w)));
    if inherit {
        let inherited = workspace
            .get("dependencies")
            .and_then(Value::as_table)
            .and_then(|d| d.get(alias))
            .ok_or_else(|| {
                Violation::new(
                    Rule::UnresolvedWorkspaceDependency,
                    format!("unresolved workspace dependency {alias}"),
                )
            })?;
        let inherited = as_dependency(inherited);
        let mut merged_features = features(&inherited);
        merged_features.extend(features(&value));
        let mut merged = inherited;
        for (k, v) in value {
            merged.insert(k, v);
        }
        merged.insert("features".into(), Value::Array(merged_features));
        value = merged;
    }
    let name = value
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or(alias)
        .to_string();
    Ok((name, value))
}

fn feature_names(cfg: &Table) -> BTreeSet<String> {
    features(cfg)
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

fn intersects(a: &BTreeSet<String>, b: &[String]) -> bool {
    b.iter().any(|f| a.contains(f))
}

/// `check_substitutions`: `[patch]` and `[replace]` of first-party packages.
pub fn check_substitutions(
    manifest: &Table,
    directory: &Path,
    policy: &Policy,
    repository: &str,
    checkout: &Path,
) -> Result<()> {
    for replacement in ["patch", "replace"] {
        let Some(groups) = manifest.get(replacement).and_then(Value::as_table) else {
            continue;
        };
        let tables: Vec<&Table> = if replacement == "patch" {
            groups.values().filter_map(Value::as_table).collect()
        } else {
            vec![groups]
        };
        for table in tables {
            for (alias, cfg) in table {
                let cfg_table = cfg.as_table();
                let actual = cfg_table
                    .and_then(|t| t.get("package"))
                    .and_then(Value::as_str)
                    .unwrap_or(alias);
                let actual = actual.split(':').next().unwrap_or("");
                if policy.get(actual).is_some() || actual.starts_with("busbar-") {
                    let local_core = repository == CORE && policy.is_core(actual);
                    let path = cfg_table
                        .and_then(|t| t.get("path"))
                        .filter(|p| policy::truthy(Some(p)))
                        .and_then(Value::as_str);
                    let allowed = local_core
                        && path.is_some_and(|path| {
                            let entry = policy.get(actual).expect("core entry");
                            let manifest = policy::manifest(entry).unwrap_or("");
                            py::resolve(&py::join(&py::join(directory, path), "Cargo.toml"))
                                == py::resolve(&py::join(checkout, manifest))
                        })
                        && cfg_table
                            .is_some_and(|t| t.keys().all(|k| k == "path" || k == "package"));
                    if !allowed {
                        return Err(Violation::new(
                            Rule::FirstPartySubstitution,
                            format!("first-party {replacement} substitution: {actual}"),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// The external-source exemption for a git dependency.
fn external(policy: &Policy, actual: &str, git: &Option<(Option<String>, String)>) -> bool {
    git.as_ref().is_some_and(|id| {
        policy
            .external_sources()
            .iter()
            .any(|(n, r)| n == actual && *id == (Some("github.com".into()), r.clone()))
    })
}

fn first_party_git(git: &Option<(Option<String>, String)>) -> bool {
    git.as_ref().is_some_and(|(_, path)| {
        let owner = path.split('/').next().unwrap_or("");
        owner == "GetBusbar" || owner == "BusbarInc"
    })
}

/// Entries of one repository, in policy order.
pub fn repository_entries<'p>(policy: &'p Policy, repository: &str) -> Vec<(String, &'p Entry)> {
    policy
        .packages
        .iter()
        .filter_map(|(name, e)| e.as_table().map(|t| (name.clone(), t)))
        .filter(|(_, e)| policy::repository(e) == repository)
        .collect()
}

/// `check_declared`.
pub fn check_declared<'p>(
    policy: &'p Policy,
    repository: &str,
    checkout: &Path,
) -> Result<Vec<(String, &'p Entry)>> {
    let root = py::read_toml(&py::join(checkout, "Cargo.toml"))?;
    check_substitutions(&root, checkout, policy, repository, checkout)?;
    for config in [
        py::join(checkout, ".cargo/config"),
        py::join(checkout, ".cargo/config.toml"),
    ] {
        if config.is_file() {
            let data = py::read_toml(&config)?;
            if ["patch", "paths", "source"]
                .iter()
                .any(|k| data.contains_key(*k))
            {
                return Err(Violation::new(
                    Rule::CargoConfigSubstitution,
                    format!(
                        "candidate Cargo source substitution in {}",
                        config.display()
                    ),
                ));
            }
        }
    }
    let forbidden = policy.forbidden()?;
    let host = ci_server_host();
    let entries = repository_entries(policy, repository);
    let mut refs: BTreeSet<String> = BTreeSet::new();
    let mut expected_paths: BTreeSet<PathBuf> = BTreeSet::new();
    for (name, entry) in &entries {
        let relative = policy::manifest(entry)?;
        let path = py::join(checkout, relative);
        expected_paths.insert(py::resolve(&path));
        if let Some(generator) = entry
            .get("generated_by")
            .filter(|g| policy::truthy(Some(g)))
        {
            let generator = generator.as_str().unwrap_or("");
            if !py::join(checkout, generator).is_file() {
                return Err(Violation::new(
                    Rule::MissingGenerator,
                    format!("missing conformance generator: {generator}"),
                ));
            }
            continue;
        }
        if !path.is_file() {
            return Err(Violation::new(
                Rule::MissingManifest,
                format!("missing classified manifest: {relative}"),
            ));
        }
        let manifest = py::read_toml(&path)?;
        let package_name = manifest
            .get("package")
            .and_then(Value::as_table)
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str);
        if package_name != Some(name.as_str()) {
            return Err(Violation::new(
                Rule::PackageIdentity,
                format!("package identity changed at {}", path.display()),
            ));
        }
        let parent = path.parent().unwrap_or(Path::new("/")).to_path_buf();
        let (workspace, workspace_dir) = match manifest.get("workspace") {
            Some(ws) => (ws.as_table().cloned().unwrap_or_default(), parent.clone()),
            None => (
                root.get("workspace")
                    .and_then(Value::as_table)
                    .cloned()
                    .unwrap_or_default(),
                checkout.to_path_buf(),
            ),
        };
        for (kind, table) in dependency_tables(&manifest) {
            for (alias, value) in &table {
                let (actual, cfg) = dependency(alias, value, &workspace)?;
                let known = policy.get(&actual);
                let git_url = cfg
                    .get("git")
                    .filter(|g| policy::truthy(Some(g)))
                    .and_then(Value::as_str);
                let git = git_url.and_then(|g| git_repository(Some(&format!("git+{g}"))));
                let is_external = external(policy, &actual, &git);
                if known.is_none()
                    && !is_external
                    && (actual.starts_with("busbar-") || first_party_git(&git))
                {
                    return Err(Violation::new(
                        Rule::UnclassifiedFirstParty,
                        format!("unclassified declared first-party package: {actual}"),
                    ));
                }
                let Some(known) = known else { continue };
                let allowed = if kind == "dev" {
                    policy::dev_allows(entry)?
                } else {
                    policy::allows(entry)?
                };
                if !allowed.contains(&actual) {
                    return Err(Violation::new(
                        Rule::ForbiddenDeclaredEdge,
                        format!("forbidden declared {kind} edge: {name} -> {actual}"),
                    ));
                }
                if kind != "dev" && intersects(&feature_names(&cfg), &forbidden) {
                    return Err(Violation::new(
                        Rule::ShippingFeatureDeclaration,
                        format!("forbidden shipping feature declaration: {name} -> {actual}"),
                    ));
                }
                if git_url.is_some() {
                    let (git_host, git_path) = git.clone().unwrap_or((None, String::new()));
                    let host_ok = git_host.as_deref() == Some("github.com") || git_host == host;
                    if git_path != policy::repository(known) || !host_ok {
                        return Err(Violation::new(
                            Rule::DeclaredSourceMismatch,
                            format!("declared source mismatch: {name} -> {actual}"),
                        ));
                    }
                    let rev = cfg.get("rev").and_then(Value::as_str).unwrap_or("");
                    if !py::is_hex(rev, 40) || cfg.contains_key("branch") || cfg.contains_key("tag")
                    {
                        return Err(Violation::new(
                            Rule::MutableRevision,
                            format!(
                                "first-party dependency must have an immutable full revision: {actual}"
                            ),
                        ));
                    }
                    if policy.is_core(&actual) {
                        refs.insert(rev.to_string());
                    }
                } else if let Some(dep_path) = cfg.get("path") {
                    let inherited = value
                        .as_table()
                        .is_some_and(|t| policy::truthy(t.get("workspace")));
                    let base = if inherited { &workspace_dir } else { &parent };
                    let dep_path = dep_path.as_str().unwrap_or("");
                    let resolved = py::resolve(&py::join(&py::join(base, dep_path), "Cargo.toml"));
                    let same_repository = policy::repository(known) == repository;
                    if !same_repository
                        || resolved != py::resolve(&py::join(checkout, policy::manifest(known)?))
                    {
                        return Err(Violation::new(
                            Rule::CrossRepositoryPath,
                            format!("cross-repository path dependency: {name} -> {actual}"),
                        ));
                    }
                } else {
                    return Err(Violation::new(
                        Rule::RegistryFirstParty,
                        format!("first-party package cannot come from a registry: {actual}"),
                    ));
                }
            }
        }
        let role = policy::role(entry);
        if role == "implementation" || role == "wrapper" {
            let declared: BTreeSet<String> = manifest
                .get("features")
                .and_then(Value::as_table)
                .map(|f| f.keys().cloned().collect())
                .unwrap_or_default();
            if intersects(&declared, &forbidden) {
                return Err(Violation::new(
                    Rule::PluginTestFeature,
                    format!("plugin exposes a test authority feature: {name}"),
                ));
            }
        }
        check_substitutions(&manifest, &parent, policy, repository, checkout)?;
    }
    let members = root
        .get("workspace")
        .and_then(Value::as_table)
        .and_then(|w| w.get("members"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for member in members {
        let member = member.as_str().unwrap_or("");
        for path in glob_paths(checkout, &format!("{member}/Cargo.toml")) {
            if !expected_paths.contains(&py::resolve(&path)) {
                let relative = path.strip_prefix(checkout).unwrap_or(&path);
                return Err(Violation::new(
                    Rule::UnclassifiedMember,
                    format!("unclassified workspace member: {}", relative.display()),
                ));
            }
        }
    }
    if repository != CORE {
        let text = py::read_text(&py::join(checkout, ".busbar-ref"))?;
        let fields: Vec<&str> = text.split_whitespace().collect();
        if fields.len() != 2 || fields[1] != "1.6.0" {
            return Err(Violation::new(
                Rule::BusbarRef,
                "expected SDK revision and product 1.6.0 in .busbar-ref",
            ));
        }
        let pin = fields[0];
        if refs.len() != 1 || !refs.contains(pin) || !py::is_hex(pin, 40) {
            let refs: Vec<String> = refs.into_iter().collect();
            return Err(Violation::new(
                Rule::BusbarRef,
                format!(
                    "SDK manifest/.busbar-ref mismatch: {} vs {pin}",
                    py::repr_list(&refs)
                ),
            ));
        }
        let lock = py::read_toml(&py::join(checkout, "Cargo.lock"))?;
        let canonical = [
            Some((Some("github.com".to_string()), CORE.to_string())),
            Some((host.clone(), CORE.to_string())),
        ];
        for p in lock_packages(&lock) {
            let name = p.get("name").and_then(Value::as_str).unwrap_or("");
            if policy.is_core(name) {
                let source = p.get("source").and_then(Value::as_str).unwrap_or("");
                if !source.ends_with(&format!("#{pin}"))
                    || !canonical.contains(&git_repository(Some(source)))
                {
                    return Err(Violation::new(
                        Rule::BusbarRef,
                        format!("SDK lock source mismatch: {name}: {source}"),
                    ));
                }
            }
        }
    }
    Ok(entries)
}

pub fn lock_packages(lock: &Table) -> Vec<&Table> {
    lock.get("package")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(Value::as_table).collect())
        .unwrap_or_default()
}

/// `Path.glob(pattern)` relative to `base` (the base itself is never a pattern).
pub fn glob_paths(base: &Path, pattern: &str) -> Vec<PathBuf> {
    let full = format!(
        "{}/{}",
        glob::Pattern::escape(&base.to_string_lossy()),
        pattern
    );
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    match glob::glob_with(&full, options) {
        Ok(paths) => paths
            .filter_map(|p| p.ok())
            .map(|p| py::normalize(&p))
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_policy;

    struct Fixture {
        _dir: crate::tests::TempDir,
        root: PathBuf,
        sdk: String,
    }

    fn fixture() -> Fixture {
        let dir = crate::tests::TempDir::new("declared");
        let root = dir.path().to_path_buf();
        let pin = "a".repeat(40);
        let sdk = format!("git = \"https://github.com/GetBusbar/busbar\", rev = \"{pin}\"");
        std::fs::write(root.join(".busbar-ref"), format!("{pin} 1.6.0\n")).unwrap();
        std::fs::write(
            root.join("Cargo.lock"),
            format!("[[package]]\nname=\"busbar-contract\"\nversion=\"1.6.0\"\nsource=\"git+https://github.com/GetBusbar/busbar?rev={pin}#{pin}\""),
        )
        .unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            format!("[workspace]\nmembers=[\"auth-alpha\", \"auth-alpha-plugin\"]\n[workspace.dependencies]\nrenamed-sdk={{package=\"busbar-contract\", {sdk}}}\n"),
        )
        .unwrap();
        for (name, deps) in [
            (
                "auth-alpha",
                "[dependencies]\nrenamed-sdk={workspace=true}\n",
            ),
            (
                "auth-alpha-plugin",
                "[dependencies]\nbusbar-auth-alpha={path=\"../auth-alpha\"}\n",
            ),
        ] {
            std::fs::create_dir(root.join(name)).unwrap();
            std::fs::write(
                root.join(name).join("Cargo.toml"),
                format!("[package]\nname=\"busbar-{name}\"\nversion=\"1.6.0\"\n{deps}"),
            )
            .unwrap();
        }
        Fixture {
            _dir: dir,
            root,
            sdk,
        }
    }

    fn check(f: &Fixture) -> Result<usize> {
        let policy = test_policy();
        check_declared(&policy, "GetBusbar/busbar-auth-alpha", &f.root).map(|e| e.len())
    }

    fn append(path: &Path, text: &str) {
        let mut current = std::fs::read_to_string(path).unwrap();
        current.push_str(text);
        std::fs::write(path, current).unwrap();
    }

    #[test]
    fn exact_workspace_alias_and_wrapper_are_allowed() {
        assert_eq!(check(&fixture()).unwrap(), 2);
    }

    #[test]
    fn inactive_optional_target_build_alias_cannot_hide_a_sibling() {
        let f = fixture();
        append(
            &f.root.join("auth-alpha/Cargo.toml"),
            &format!("[target.'cfg(windows)'.build-dependencies]\nneutral={{package=\"busbar-store-beta\",optional=true,git=\"https://github.com/GetBusbar/busbar-store-beta\",rev=\"{}\"}}\n", "b".repeat(40)),
        );
        let e = check(&f).unwrap_err();
        assert_eq!(
            e.message,
            "forbidden declared build edge: busbar-auth-alpha -> busbar-store-beta"
        );
    }

    #[test]
    fn workspace_feature_alias_cannot_enable_test_authority() {
        let f = fixture();
        let path = f.root.join("auth-alpha/Cargo.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replace("workspace=true", "workspace=true, features=[\"test-seal\"]"),
        )
        .unwrap();
        assert_eq!(
            check(&f).unwrap_err().rule,
            Rule::ShippingFeatureDeclaration
        );
    }

    #[test]
    fn optional_foreign_target_build_alias_cannot_enable_test_authority() {
        let f = fixture();
        let path = f.root.join("auth-alpha/Cargo.toml");
        let original = std::fs::read_to_string(&path).unwrap();
        for feature in ["test-seal", "test-support"] {
            for table in [
                "dependencies",
                "target.'cfg(windows)'.dependencies",
                "target.'cfg(windows)'.build-dependencies",
            ] {
                let header = if table == "dependencies" {
                    "\n".to_string()
                } else {
                    format!("\n[{table}]\n")
                };
                std::fs::write(
                    &path,
                    format!("{original}{header}hidden-sdk={{package=\"busbar-contract\", optional=true, features=[\"{feature}\"], {}}}\n", f.sdk),
                )
                .unwrap();
                assert_eq!(
                    check(&f).unwrap_err().rule,
                    Rule::ShippingFeatureDeclaration
                );
            }
        }
        std::fs::write(&path, original).unwrap();
        assert_eq!(check(&f).unwrap(), 2);
    }

    #[test]
    fn root_patch_and_config_replacement_are_rejected() {
        let f = fixture();
        let path = f.root.join("Cargo.toml");
        let original = std::fs::read_to_string(&path).unwrap();
        append(
            &path,
            "[patch.'https://github.com/GetBusbar/busbar']\nbusbar-contract={path=\"replacement\"}\n",
        );
        assert_eq!(
            check(&f).unwrap_err().message,
            "first-party patch substitution: busbar-contract"
        );
        std::fs::write(&path, original).unwrap();
        std::fs::create_dir(f.root.join(".cargo")).unwrap();
        std::fs::write(
            f.root.join(".cargo/config.toml"),
            "paths=[\"replacement\"]\n",
        )
        .unwrap();
        assert_eq!(check(&f).unwrap_err().rule, Rule::CargoConfigSubstitution);
    }

    #[test]
    fn unclassified_workspace_member_fails_closed() {
        let f = fixture();
        let path = f.root.join("Cargo.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replace(
                "\"auth-alpha-plugin\"]",
                "\"auth-alpha-plugin\", \"extra\"]",
            ),
        )
        .unwrap();
        std::fs::create_dir(f.root.join("extra")).unwrap();
        std::fs::write(
            f.root.join("extra/Cargo.toml"),
            "[package]\nname=\"innocent\"\nversion=\"0.0.0\"\n",
        )
        .unwrap();
        assert_eq!(
            check(&f).unwrap_err().message,
            "unclassified workspace member: extra/Cargo.toml"
        );
    }

    #[test]
    fn busbar_ref_must_match_manifest_and_lock() {
        let f = fixture();
        std::fs::write(
            f.root.join(".busbar-ref"),
            format!("{} 1.6.0\n", "c".repeat(40)),
        )
        .unwrap();
        let e = check(&f).unwrap_err();
        assert_eq!(
            e.message,
            format!(
                "SDK manifest/.busbar-ref mismatch: ['{}'] vs {}",
                "a".repeat(40),
                "c".repeat(40)
            )
        );
        std::fs::write(f.root.join(".busbar-ref"), "x\n").unwrap();
        assert_eq!(
            check(&f).unwrap_err().message,
            "expected SDK revision and product 1.6.0 in .busbar-ref"
        );
    }

    #[test]
    fn mutable_first_party_revision_is_refused() {
        let f = fixture();
        let path = f.root.join("Cargo.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replace(&format!("rev = \"{}\"", "a".repeat(40)), "branch = \"dev\""),
        )
        .unwrap();
        assert_eq!(check(&f).unwrap_err().rule, Rule::MutableRevision);
    }

    #[test]
    fn workspace_aliases_preserve_package_and_additive_features() {
        let workspace: Table = "[dependencies]\nneutral = { package = \"busbar-contract\", features = [\"test-support\"] }\n".parse().unwrap();
        let value: Value =
            toml::from_str::<Table>("v = { workspace = true, features = [\"extra\"] }").unwrap()
                ["v"]
                .clone();
        let (name, cfg) = dependency("neutral", &value, &workspace).unwrap();
        assert_eq!(name, "busbar-contract");
        assert_eq!(
            feature_names(&cfg).into_iter().collect::<Vec<_>>(),
            ["extra", "test-support"]
        );
        assert_eq!(features(&cfg)[0].as_str(), Some("test-support"));
    }

    #[test]
    fn declared_optional_target_and_build_tables_are_all_visited() {
        let manifest: Table =
            "[target.'cfg(windows)'.build-dependencies]\nneutral = { optional = true }\n"
                .parse()
                .unwrap();
        let tables = dependency_tables(&manifest);
        assert!(tables
            .iter()
            .any(|(k, t)| *k == "build" && t.contains_key("neutral")));
    }
}
