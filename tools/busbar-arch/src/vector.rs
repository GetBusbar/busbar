//! The assembly vector (`scripts/ci-product-pins.json`) and the lock alignment of
//! the two core workspaces.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use toml::{Table, Value};

use crate::declared::{dependency, dependency_tables, lock_packages};
use crate::policy::{self, Entry, Policy, CORE, PUBLIC_C_HEADER};
use crate::py;
use crate::refuse::{Result, Rule, Violation};

fn json_str<'a>(row: &'a Json, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Json::as_str)
}

/// `vector_revisions`: repository -> pinned commit, for core and every product.
pub fn vector_revisions(policy: &Policy, vector: &Json) -> Result<HashMap<String, String>> {
    let sdk = json_str(vector, "sdk").unwrap_or("");
    if !py::is_hex(sdk, 40) {
        return Err(Violation::new(
            Rule::VectorSdk,
            "assembled SDK pin is not immutable",
        ));
    }
    let mut expected = BTreeSet::new();
    for (name, entry) in policy.repositories() {
        let entry = entry.as_table().cloned().unwrap_or_default();
        let private = entry.get("private").ok_or_else(|| {
            Violation::new(
                Rule::PolicyShape,
                format!("policy is missing 'private' for {name}"),
            )
        })?;
        if !policy::truthy(Some(private))
            && !policy::truthy(entry.get("standalone"))
            && entry.get("language").and_then(Value::as_str) != Some("c")
        {
            expected.insert(name.clone());
        }
    }
    let mut revisions = HashMap::new();
    revisions.insert(CORE.to_string(), sdk.to_string());
    let empty = Vec::new();
    for row in vector["products"].as_array().unwrap_or(&empty) {
        let repo = format!("GetBusbar/{}", json_str(row, "repo").unwrap_or(""));
        if !expected.contains(&repo) || revisions.contains_key(&repo) {
            return Err(Violation::new(
                Rule::VectorProduct,
                format!("unclassified or duplicate assembly product: {repo}"),
            ));
        }
        let entry = policy.repositories()[&repo]
            .as_table()
            .cloned()
            .unwrap_or_default();
        let wrappers: BTreeSet<String> = entry
            .get("packages")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_table)
                    .filter(|p| p.get("role").and_then(Value::as_str) == Some("wrapper"))
                    .filter_map(|p| p.get("name").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let url = json_str(row, "url").unwrap_or("");
        let commit = json_str(row, "commit").unwrap_or("");
        if !wrappers.contains(json_str(row, "package").unwrap_or("\u{0}"))
            || json_str(row, "kind") != entry.get("kind").and_then(Value::as_str)
            || url.strip_suffix(".git").unwrap_or(url) != format!("https://github.com/{repo}")
            || !py::is_hex(commit, 40)
            || !py::is_hex(json_str(row, "lock_sha256").unwrap_or(""), 64)
        {
            return Err(Violation::new(
                Rule::VectorProduct,
                format!("assembly product identity mismatch: {repo}"),
            ));
        }
        revisions.insert(repo, commit.to_string());
    }
    let mut want = expected.clone();
    want.insert(CORE.to_string());
    let have: BTreeSet<String> = revisions.keys().cloned().collect();
    if have != want {
        return Err(Violation::new(
            Rule::VectorIncomplete,
            "assembly product vector is incomplete",
        ));
    }
    let witness = &vector["c_witness"];
    let keys_ok = witness.as_object().is_some_and(|w| {
        ["repo", "url", "commit", "sdk"]
            .iter()
            .all(|k| w.contains_key(*k))
            && w.keys().all(|k| {
                ["repo", "url", "commit", "sdk", "kind", "language", "header"].contains(&k.as_str())
            })
            && w.values().all(Json::is_string)
    });
    if !keys_ok {
        return Err(Violation::new(
            Rule::CWitnessVector,
            "C witness vector has missing or unknown keys",
        ));
    }
    let repo = format!("GetBusbar/{}", json_str(witness, "repo").unwrap_or(""));
    let c_owner = policy
        .repositories()
        .get(&repo)
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let owner_kind = c_owner.get("kind").and_then(Value::as_str);
    let url = json_str(witness, "url").unwrap_or("");
    let mismatch = c_owner.get("language").and_then(Value::as_str) != Some("c")
        || policy::truthy(c_owner.get("private"))
        || json_str(witness, "sdk") != Some(sdk)
        || !py::is_hex(json_str(witness, "commit").unwrap_or(""), 40)
        || url.strip_suffix(".git").unwrap_or(url) != format!("https://github.com/{repo}")
        || json_str(witness, "language").unwrap_or("c") != "c"
        || witness.get("kind").map_or(owner_kind, Json::as_str) != owner_kind
        || json_str(witness, "header").unwrap_or(PUBLIC_C_HEADER) != PUBLIC_C_HEADER;
    if mismatch {
        return Err(Violation::new(
            Rule::CWitnessVector,
            "C witness source/SDK mismatch",
        ));
    }
    Ok(revisions)
}

#[derive(Debug, serde::Serialize)]
pub struct VectorReceipt {
    pub sdk_revision: String,
    pub products: usize,
    pub shared_core_packages: usize,
    pub vector_sha256: String,
}

/// `check_vector`.
pub fn check_vector(
    policy: &Policy,
    checkout: &Path,
    entries: &[(String, &Entry)],
) -> Result<VectorReceipt> {
    let pins = py::join(checkout, "scripts/ci-product-pins.json");
    let vector = py::read_json(&pins)?;
    let revisions = vector_revisions(policy, &vector)?;
    let root = py::read_toml(&py::join(checkout, "Cargo.toml"))?;
    let workspace = root
        .get("workspace")
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let mut manifests: Vec<PathBuf> = Vec::new();
    for (_, e) in entries {
        let path = py::join(checkout, policy::manifest(e)?);
        if !manifests.contains(&path) {
            manifests.push(path);
        }
    }
    let root_manifest = py::join(checkout, "Cargo.toml");
    if !manifests.contains(&root_manifest) {
        manifests.push(root_manifest);
    }
    for path in &manifests {
        let manifest = py::read_toml(path)?;
        let own_workspace = manifest
            .get("workspace")
            .and_then(Value::as_table)
            .cloned()
            .unwrap_or_else(|| workspace.clone());
        let mut tables = dependency_tables(&manifest);
        tables.push((
            "workspace",
            own_workspace
                .get("dependencies")
                .and_then(Value::as_table)
                .cloned()
                .unwrap_or_default(),
        ));
        for (_, table) in tables {
            for (alias, cfg) in &table {
                let (name, value) = dependency(alias, cfg, &own_workspace)?;
                let Some(known) = policy.get(&name) else {
                    continue;
                };
                if !policy::truthy(value.get("git")) {
                    continue;
                }
                let rev = value.get("rev").and_then(Value::as_str);
                if rev != revisions.get(policy::repository(known)).map(String::as_str) {
                    return Err(Violation::new(
                        Rule::AssemblyMismatch,
                        format!(
                            "assembly manifest/vector mismatch: {}: {name}",
                            path.display()
                        ),
                    ));
                }
            }
        }
    }
    let root_lock_path = py::join(checkout, "Cargo.lock");
    let dist_lock_path = py::join(checkout, "dist/default/Cargo.lock");
    for path in [&root_lock_path, &dist_lock_path] {
        for package in lock_packages(&py::read_toml(path)?) {
            let name = package.get("name").and_then(Value::as_str).unwrap_or("");
            let Some(known) = policy.get(name) else {
                continue;
            };
            let Some(source) = package.get("source").and_then(Value::as_str) else {
                continue;
            };
            if source.is_empty() {
                continue;
            }
            let revision = revisions
                .get(policy::repository(known))
                .map(String::as_str)
                .unwrap_or("unclassified");
            if !source.ends_with(&format!("#{revision}")) {
                return Err(Violation::new(
                    Rule::AssemblyMismatch,
                    format!("assembly lock/vector mismatch: {}: {name}", path.display()),
                ));
            }
        }
    }
    let shared = check_shared_core_resolution(
        &py::read_toml(&root_lock_path)?,
        &py::read_toml(&dist_lock_path)?,
    )?;
    let digest = Sha256::digest(py::read_bytes(&pins)?);
    Ok(VectorReceipt {
        sdk_revision: json_str(&vector, "sdk").unwrap_or("").to_string(),
        products: vector["products"].as_array().map_or(0, Vec::len),
        shared_core_packages: shared,
        vector_sha256: hex(&digest),
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

type Identity = (String, String, Option<String>);

struct LockGraph<'a> {
    by_name: HashMap<&'a str, Vec<&'a Table>>,
    paths: BTreeMap<String, &'a Table>,
}

fn field<'a>(row: &'a Table, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str)
}

impl<'a> LockGraph<'a> {
    fn new(lock: &'a Table) -> Self {
        let mut by_name: HashMap<&str, Vec<&Table>> = HashMap::new();
        let mut paths = BTreeMap::new();
        for package in lock_packages(lock) {
            let name = field(package, "name").unwrap_or("");
            by_name.entry(name).or_default().push(package);
            if package.get("source").is_none() {
                paths.insert(name.to_string(), package);
            }
        }
        LockGraph { by_name, paths }
    }

    fn resolve(&self, entry: &str) -> Result<&'a Table> {
        let mut parts = entry.split(' ');
        let name = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();
        let mut rows: Vec<&Table> = self.by_name.get(name).cloned().unwrap_or_default();
        if let Some(version) = rest.first() {
            rows.retain(|row| field(row, "version") == Some(*version));
        }
        if let Some(source) = rest.get(1) {
            rows.retain(|row| format!("({})", field(row, "source").unwrap_or("")) == *source);
        }
        if rows.len() != 1 {
            return Err(Violation::new(
                Rule::LockAlignment,
                format!("unresolvable lock dependency: {entry}"),
            ));
        }
        Ok(rows[0])
    }

    fn closure(&self, package: &'a Table) -> Result<BTreeSet<Identity>> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![package];
        while let Some(row) = stack.pop() {
            let identity = (
                field(row, "name").unwrap_or("").to_string(),
                field(row, "version").unwrap_or("").to_string(),
                field(row, "source").map(str::to_string),
            );
            if seen.insert(identity) {
                if let Some(Value::Array(deps)) = row.get("dependencies") {
                    for entry in deps.iter().filter_map(Value::as_str) {
                        stack.push(self.resolve(entry)?);
                    }
                }
            }
        }
        Ok(seen)
    }
}

/// `check_shared_core_resolution` (`busbar-arch lock-align`): every core path
/// crate dist/default links resolves exactly as in the root lock.
pub fn check_shared_core_resolution(root_lock: &Table, distribution_lock: &Table) -> Result<usize> {
    let root = LockGraph::new(root_lock);
    let distribution = LockGraph::new(distribution_lock);
    let shared: Vec<&String> = root
        .paths
        .keys()
        .filter(|name| distribution.paths.contains_key(*name))
        .collect();
    for name in &shared {
        let dist = distribution.closure(distribution.paths[*name])?;
        let base = root.closure(root.paths[*name])?;
        let extra: Vec<&Identity> = dist.difference(&base).collect();
        if !extra.is_empty() {
            let sample: Vec<String> = extra
                .iter()
                .take(5)
                .map(|(n, v, _)| format!("{n} {v}"))
                .collect();
            return Err(Violation::new(
                Rule::LockAlignment,
                format!(
                    "dist/default resolves core crate {name} differently from the root lock: {}",
                    sample.join(", ")
                ),
            ));
        }
    }
    Ok(shared.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_policy;
    use serde_json::json;

    type Mutation = Box<dyn Fn(&mut Json)>;

    fn vector_policy() -> Policy {
        let mut data = test_policy().data;
        let repos = data["repositories"].as_table_mut().unwrap();
        repos.remove("GetBusbar/busbar-store-beta");
        let alpha = repos["GetBusbar/busbar-auth-alpha"].as_table_mut().unwrap();
        alpha.insert("kind".into(), Value::String("auth".into()));
        alpha.insert("private".into(), Value::Boolean(false));
        let c: Table = "kind = \"secret\"\nprivate = false\nlanguage = \"c\"\n"
            .parse()
            .unwrap();
        repos.insert("GetBusbar/busbar-secret-c".into(), Value::Table(c));
        Policy::new(data).unwrap()
    }

    fn vector() -> Json {
        json!({"sdk": "a".repeat(40), "products": [{"repo": "busbar-auth-alpha", "kind": "auth",
            "package": "busbar-auth-alpha-plugin", "url": "https://github.com/GetBusbar/busbar-auth-alpha",
            "commit": "b".repeat(40), "lock_sha256": "c".repeat(64)}],
            "c_witness": {"repo": "busbar-secret-c", "sdk": "a".repeat(40), "commit": "d".repeat(40),
            "url": "https://github.com/GetBusbar/busbar-secret-c"}})
    }

    #[test]
    fn complete_vector_binds_sdk_product_and_c_witness() {
        let p = vector_policy();
        let revisions = vector_revisions(&p, &vector()).unwrap();
        assert_eq!(revisions["GetBusbar/busbar-auth-alpha"], "b".repeat(40));
        let mutations: Vec<(Rule, Mutation)> = vec![
            (
                Rule::VectorIncomplete,
                Box::new(|v| v["products"] = json!([])),
            ),
            (
                Rule::VectorProduct,
                Box::new(|v| {
                    let first = v["products"][0].clone();
                    v["products"].as_array_mut().unwrap().push(first);
                }),
            ),
            (
                Rule::VectorProduct,
                Box::new(|v| v["products"][0]["commit"] = json!("dev")),
            ),
            (
                Rule::VectorProduct,
                Box::new(|v| v["products"][0]["package"] = json!("busbar-auth-alpha")),
            ),
            (
                Rule::CWitnessVector,
                Box::new(|v| v["c_witness"]["sdk"] = json!("e".repeat(40))),
            ),
            (
                Rule::CWitnessVector,
                Box::new(|v| v["c_witness"]["extra"] = json!("x")),
            ),
            (Rule::VectorSdk, Box::new(|v| v["sdk"] = json!("dev"))),
        ];
        for (rule, mutate) in mutations {
            let mut changed = vector();
            mutate(&mut changed);
            assert_eq!(
                vector_revisions(&p, &changed).unwrap_err().rule,
                rule,
                "{changed}"
            );
        }
    }

    fn lock(text: &str) -> Table {
        text.parse().unwrap()
    }

    #[test]
    fn shared_core_crates_must_resolve_alike() {
        let root = lock(
            r#"
[[package]]
name = "busbar-kernel"
version = "1.6.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        );
        assert_eq!(check_shared_core_resolution(&root, &root).unwrap(), 1);
        let dist = lock(
            r#"
[[package]]
name = "busbar-kernel"
version = "1.6.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        );
        let e = check_shared_core_resolution(&root, &dist).unwrap_err();
        assert_eq!(
            e.message,
            "dist/default resolves core crate busbar-kernel differently from the root lock: serde 1.0.2"
        );
        let broken = lock("[[package]]\nname = \"busbar-kernel\"\nversion = \"1.6.0\"\ndependencies = [\"missing\"]\n");
        assert_eq!(
            check_shared_core_resolution(&broken, &broken)
                .unwrap_err()
                .message,
            "unresolvable lock dependency: missing"
        );
    }
}
