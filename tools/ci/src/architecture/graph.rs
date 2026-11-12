//! Policy classification, the resolved shipping graph, every declared edge
//! (including cfg-disabled optional/build tables), the assembly product
//! vector and the disposable shipping-resolution probes.
use super::{CORE, Call, Ctx, hex40, key, key_str, loads, read, strings};
use crate::json::{self, Value};
use crate::pathx::{self, join, text};
use crate::proc::{Result, require};
use crate::py;
use crate::sha256;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub use crate::product::PUBLIC_C_HEADER;

/// `(hostname, path)` of a `git+` source; hostname may be absent.
pub type GitIdentity = (Option<String>, String);

/// `urlsplit(url)` → (netloc, path).
fn urlsplit(url: &str) -> (String, String) {
    let cleaned: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.as_str();
    if let Some(colon) = rest.find(':') {
        let scheme = &rest[..colon];
        if scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            rest = &rest[colon + 1..];
        }
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..end].to_owned();
        rest = &after[end..];
    }
    let rest = rest.split('#').next().unwrap_or("");
    let path = rest.split('?').next().unwrap_or("");
    (netloc, path.to_owned())
}

fn hostname(netloc: &str) -> Option<String> {
    let host = netloc.rsplit('@').next().unwrap_or("");
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// Canonical owner/repository, retaining host and rejecting other source types.
pub fn git_repository(source: Option<&str>) -> Option<GitIdentity> {
    let source = source?.strip_prefix("git+")?;
    let (netloc, path) = urlsplit(source);
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    Some((hostname(&netloc), path.to_owned()))
}

fn identity(host: Option<&str>, repository: &str) -> GitIdentity {
    (host.map(str::to_owned), repository.to_owned())
}

fn owner(identity: &GitIdentity) -> &str {
    identity.1.split('/').next().unwrap_or("")
}

/// `dict(entry, **extra)`.
fn with(entry: &Value, extra: Vec<(&str, Value)>) -> Value {
    let mut value = entry.clone();
    for (k, v) in extra {
        value.set(k, v);
    }
    value
}

fn names(values: &Value) -> Vec<String> {
    values
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn contains(values: &Value, name: &str) -> bool {
    values
        .as_array()
        .is_some_and(|rows| rows.iter().any(|v| v.as_str() == Some(name)))
}

fn object_rows(value: &Value) -> &[(String, Value)] {
    value.as_object().map(Vec::as_slice).unwrap_or(&[])
}

pub struct Policy {
    pub data: Value,
    /// Every classified package in policy order (`dict` semantics).
    pub packages: Vec<(String, Value)>,
}

impl Policy {
    pub fn new(data: Value) -> Result<Policy> {
        require(
            data.get("version").is_some_and(|v| v.equals_int(1)),
            "unsupported architecture policy",
        )?;
        let mut policy = Policy {
            data: Value::Null,
            packages: Vec::new(),
        };
        for (name, entry) in object_rows(key(&data, "core")?) {
            policy.insert(
                name,
                with(
                    entry,
                    vec![("repository", CORE.into()), ("role", "core".into())],
                ),
            );
        }
        for (repository, repo) in object_rows(key(&data, "repositories")?) {
            let packages = repo.at("packages").as_array().unwrap_or(&[]);
            let mut own = Vec::new();
            for p in packages {
                if key_str(p, "role")? == "implementation" {
                    own.push(key(p, "name")?.clone());
                }
            }
            for p in packages {
                let mut allows = vec![Value::str("busbar-contract")];
                if key_str(p, "role")? == "wrapper" {
                    allows.extend(own.iter().cloned());
                }
                policy.insert(
                    key_str(p, "name")?,
                    with(
                        p,
                        vec![
                            ("repository", Value::str(repository.clone())),
                            ("allows", Value::Array(allows)),
                        ],
                    ),
                );
            }
        }
        let assembly = key(&data, "assembly")?;
        let allows = Value::Array(
            policy
                .packages
                .iter()
                .map(|(n, _)| Value::str(n.clone()))
                .collect(),
        );
        policy.insert(
            key_str(assembly, "package")?,
            with(
                assembly,
                vec![("role", "assembly".into()), ("allows", allows)],
            ),
        );
        for host in data.at("test_hosts").as_array().unwrap_or(&[]) {
            if py::truthy(host.at("package")) {
                let allows = key(host, "allows")?.clone();
                policy.insert(
                    key_str(host, "package")?,
                    with(
                        host,
                        vec![("role", "test_host".into()), ("dev_allows", allows)],
                    ),
                );
            }
        }
        policy.data = data;
        Ok(policy)
    }

    fn insert(&mut self, name: &str, entry: Value) {
        match self.packages.iter_mut().find(|(n, _)| n == name) {
            Some(row) => row.1 = entry,
            None => self.packages.push((name.to_owned(), entry)),
        }
    }

    pub fn package(&self, name: &str) -> Option<&Value> {
        self.packages
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e)
    }

    pub fn core(&self) -> &[(String, Value)] {
        object_rows(self.data.at("core"))
    }

    pub fn is_core(&self, name: &str) -> bool {
        self.data.at("core").get(name).is_some()
    }

    pub fn forbidden(&self) -> BTreeSet<String> {
        names(self.data.at("forbidden_shipping_features"))
            .into_iter()
            .collect()
    }

    fn external(&self, name: &str, identity: &GitIdentity) -> bool {
        self.data
            .at("external_sources")
            .as_array()
            .unwrap_or(&[])
            .iter()
            .any(|e| {
                e.at("name").as_str() == Some(name)
                    && *identity == identity_of("github.com", e.at("repository"))
            })
    }

    pub fn classify(
        &self,
        package: &Value,
        repository: &str,
        checkout: &Path,
        ci_host: Option<&str>,
    ) -> Result<Option<&Value>> {
        let name = key_str(package, "name")?;
        let source = package.at("source").as_str();
        let identity = git_repository(source);
        let Some(entry) = self.package(name) else {
            if identity.as_ref().is_some_and(|i| self.external(name, i)) {
                return Ok(None);
            }
            if name.starts_with("busbar-")
                || identity
                    .as_ref()
                    .is_some_and(|i| matches!(owner(i), "GetBusbar" | "BusbarInc"))
            {
                return Err(format!(
                    "unclassified first-party package: {name} ({})",
                    source.map_or("None".to_owned(), str::to_owned)
                ));
            }
            return Ok(None);
        };
        let entry_repository = key_str(entry, "repository")?;
        if source.is_some_and(|s| !s.is_empty()) {
            let expected_host = if entry_repository.starts_with("BusbarInc/") {
                ci_host
            } else {
                Some("github.com")
            };
            let identity = identity.unwrap_or((Some("\0".into()), "\0".into()));
            if identity != self::identity(expected_host, entry_repository)
                && identity != self::identity(ci_host, entry_repository)
            {
                return Err(format!(
                    "noncanonical source for {name}: {}",
                    source.unwrap_or("")
                ));
            }
        } else {
            let actual = pathx::resolve(Path::new(key_str(package, "manifest_path")?));
            let expected = pathx::resolve(&join(checkout, key_str(entry, "manifest")?));
            if !(entry_repository == repository && actual == expected) {
                return Err(format!(
                    "unapproved path/source substitution for {name}: {}",
                    text(&actual)
                ));
            }
        }
        Ok(Some(entry))
    }
}

fn identity_of(host: &str, repository: &Value) -> GitIdentity {
    (
        Some(host.to_owned()),
        repository.as_str().unwrap_or("\0").to_owned(),
    )
}

fn sorted_repr(values: &BTreeSet<String>) -> String {
    pathx::repr_list(&values.iter().cloned().collect::<Vec<_>>())
}

fn production_deps(node: &Value) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for edge in key(node, "deps")?.as_array().unwrap_or(&[]) {
        let kinds = key(edge, "dep_kinds")?.as_array().unwrap_or(&[]);
        if kinds.iter().any(|d| d.at("kind").as_str() != Some("dev")) {
            out.push(key_str(edge, "pkg")?.to_owned());
        }
    }
    Ok(out)
}

pub fn check_graph(
    metadata: &Value,
    policy: &Policy,
    repository: &str,
    checkout: &Path,
    ci_host: Option<&str>,
) -> Result<Value> {
    require(
        py::truthy(metadata.at("resolve")),
        "resolved cargo metadata is required; --no-deps is not evidence",
    )?;
    let mut packages: Vec<(String, &Value)> = Vec::new();
    for p in key(metadata, "packages")?.as_array().unwrap_or(&[]) {
        let id = key_str(p, "id")?.to_owned();
        match packages.iter_mut().find(|(i, _)| *i == id) {
            Some(row) => row.1 = p,
            None => packages.push((id, p)),
        }
    }
    let nodes: Vec<&Value> = key(key(metadata, "resolve")?, "nodes")?
        .as_array()
        .unwrap_or(&[])
        .iter()
        .collect();
    let node = |id: &str| {
        nodes
            .iter()
            .rev()
            .find(|n| n.at("id").as_str() == Some(id))
            .copied()
    };
    let mut roles: Vec<(String, Option<&Value>)> = Vec::new();
    for (id, p) in &packages {
        roles.push((
            id.clone(),
            policy.classify(p, repository, checkout, ci_host)?,
        ));
    }
    let role = |id: &str| -> Result<Option<&Value>> {
        roles
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, r)| *r)
            .ok_or_else(|| format!("KeyError: {}", py::repr_str(id)))
    };
    let package = |id: &str| packages.iter().find(|(i, _)| i == id).map(|(_, p)| *p);
    let forbidden = policy.forbidden();
    for (id, entry) in &roles {
        let Some(entry) = entry else {
            continue;
        };
        let name = key_str(package(id).unwrap(), "name")?;
        if entry.at("role").as_str() == Some("test_host") {
            return Err(format!("test host entered shipping graph: {name}"));
        }
        let features: BTreeSet<String> = node(id)
            .map(|n| names(n.at("features")))
            .unwrap_or_default()
            .into_iter()
            .filter(|f| forbidden.contains(f))
            .collect();
        if !features.is_empty() {
            return Err(format!(
                "shipping feature on {name}: {}",
                sorted_repr(&features)
            ));
        }
        // Traverse through external libraries, but compare each first-party hop to
        // the graph for the first-party package that actually owns that hop.
        let start = node(id).ok_or_else(|| format!("KeyError: {}", py::repr_str(id)))?;
        let mut pending = production_deps(start)?;
        let mut seen = BTreeSet::new();
        while let Some(target) = pending.pop() {
            if !seen.insert(target.clone()) {
                continue;
            }
            if role(&target)?.is_some() {
                let target_name = key_str(package(&target).unwrap(), "name")?;
                if !contains(entry.at("allows"), target_name) {
                    return Err(format!(
                        "forbidden production/build edge: {name} -> {target_name}"
                    ));
                }
                continue;
            }
            let next =
                node(&target).ok_or_else(|| format!("KeyError: {}", py::repr_str(&target)))?;
            pending.extend(production_deps(next)?);
        }
    }
    let core_sources: BTreeSet<String> = packages
        .iter()
        .filter(|(_, p)| p.at("name").as_str().is_some_and(|n| policy.is_core(n)))
        .filter_map(|(_, p)| {
            p.at("source")
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })
        .collect();
    if core_sources.len() > 1 {
        return Err(format!(
            "SDK source/revision mismatch: {}",
            sorted_repr(&core_sources)
        ));
    }
    Ok(Value::Object(vec![
        ("packages".into(), Value::int(packages.len() as i64)),
        (
            "classified".into(),
            Value::int(roles.iter().filter(|(_, r)| r.is_some()).count() as i64),
        ),
    ]))
}

/// Every dependency table, including target-specific ones: `(kind, table)`.
pub fn dependency_tables(manifest: &Value) -> Vec<(&'static str, &Value)> {
    static EMPTY: Value = Value::Object(Vec::new());
    let sections = [
        ("dependencies", "normal"),
        ("build-dependencies", "build"),
        ("dev-dependencies", "dev"),
    ];
    let mut out: Vec<(&'static str, &Value)> = sections
        .iter()
        .map(|(s, k)| (*k, manifest.get(s).unwrap_or(&EMPTY)))
        .collect();
    for (_, target) in object_rows(manifest.at("target")) {
        for (s, k) in sections {
            out.push((k, target.get(s).unwrap_or(&EMPTY)));
        }
    }
    out
}

fn as_table(value: &Value) -> Result<Value> {
    match value {
        Value::String(_) => Ok(Value::Object(vec![("version".into(), value.clone())])),
        Value::Object(_) => Ok(value.clone()),
        other => Err(format!(
            "TypeError: cannot convert dictionary update sequence element: {}",
            py::type_name(other)
        )),
    }
}

/// `(package name, effective dependency table)`, inheriting workspace entries.
pub fn dependency(alias: &str, value: &Value, workspace: &Value) -> Result<(String, Value)> {
    let mut value = as_table(value)?;
    let inherit = match &mut value {
        Value::Object(rows) => match rows.iter().position(|(k, _)| k == "workspace") {
            Some(index) => py::truthy(&rows.remove(index).1),
            None => false,
        },
        _ => false,
    };
    if inherit {
        let inherited = workspace
            .at("dependencies")
            .get(alias)
            .ok_or_else(|| format!("unresolved workspace dependency {alias}"))?;
        let inherited = as_table(inherited)?;
        let mut features = inherited
            .at("features")
            .as_array()
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        features.extend(
            value
                .at("features")
                .as_array()
                .map(<[_]>::to_vec)
                .unwrap_or_default(),
        );
        let mut merged = inherited;
        for (k, v) in object_rows(&value) {
            merged.set(k, v.clone());
        }
        merged.set("features", Value::Array(features));
        value = merged;
    }
    let name = match value.get("package") {
        Some(name) => name
            .as_str()
            .ok_or("TypeError: package is not a str")?
            .to_owned(),
        None => alias.to_owned(),
    };
    Ok((name, value))
}

fn check_substitutions(
    manifest: &Value,
    directory: &Path,
    policy: &Policy,
    repository: &str,
    checkout: &Path,
) -> Result<()> {
    for replacement in ["patch", "replace"] {
        let groups = manifest.at(replacement);
        let tables: Vec<&Value> = if replacement == "patch" {
            object_rows(groups).iter().map(|(_, t)| t).collect()
        } else {
            vec![groups]
        };
        for table in tables {
            for (alias, cfg) in object_rows(table) {
                let actual = if cfg.is_object() {
                    cfg.get("package").and_then(Value::as_str).unwrap_or(alias)
                } else {
                    alias
                };
                let actual = actual.split(':').next().unwrap_or("");
                if policy.package(actual).is_none() && !actual.starts_with("busbar-") {
                    continue;
                }
                // Core's own assembly uses its checked-out core, never a second SDK.
                let local_core = repository == CORE && policy.is_core(actual);
                let path = if cfg.is_object() {
                    cfg.get("path")
                } else {
                    None
                };
                let allowed = local_core
                    && path.is_some_and(py::truthy)
                    && {
                        let manifest = key_str(policy.package(actual).unwrap(), "manifest")?;
                        let path = path.and_then(Value::as_str).unwrap_or("");
                        pathx::resolve(&join(&join(directory, path), "Cargo.toml"))
                            == pathx::resolve(&join(checkout, manifest))
                    }
                    && cfg.keys().iter().all(|k| matches!(*k, "path" | "package"));
                if !allowed {
                    return Err(format!("first-party {replacement} substitution: {actual}"));
                }
            }
        }
    }
    Ok(())
}

/// Inspect all declarations, including cfg-disabled optional/build dependencies.
pub fn check_declared(
    policy: &Policy,
    repository: &str,
    checkout: &Path,
    ci_host: Option<&str>,
) -> Result<Vec<(String, Value)>> {
    let root = read(&join(checkout, "Cargo.toml"))?;
    check_substitutions(&root, checkout, policy, repository, checkout)?;
    // Cargo configuration can otherwise silently replace the checked manifest graph.
    for config in [
        join(checkout, ".cargo/config"),
        join(checkout, ".cargo/config.toml"),
    ] {
        if config.is_file() {
            let data = read(&config)?;
            if ["patch", "paths", "source"]
                .iter()
                .any(|k| data.get(k).is_some())
            {
                return Err(format!(
                    "candidate Cargo source substitution in {}",
                    text(&config)
                ));
            }
        }
    }
    let mut entries = Vec::new();
    for (name, entry) in &policy.packages {
        if key_str(entry, "repository")? == repository {
            entries.push((name.clone(), entry.clone()));
        }
    }
    let forbidden = policy.forbidden();
    let mut refs = BTreeSet::new();
    let mut expected_paths = BTreeSet::new();
    static EMPTY: Value = Value::Object(Vec::new());
    for (name, entry) in &entries {
        let path = join(checkout, key_str(entry, "manifest")?);
        expected_paths.insert(pathx::resolve(&path));
        if py::truthy(entry.at("generated_by")) {
            let generator = entry.at("generated_by").as_str().unwrap_or("");
            if !join(checkout, generator).is_file() {
                return Err(format!("missing conformance generator: {generator}"));
            }
            continue; // Generated host is verified separately by its native conformance job.
        }
        if !path.is_file() {
            return Err(format!(
                "missing classified manifest: {}",
                key_str(entry, "manifest")?
            ));
        }
        let manifest = read(&path)?;
        if manifest.at("package").at("name").as_str() != Some(name.as_str()) {
            return Err(format!("package identity changed at {}", text(&path)));
        }
        let parent = path.parent().unwrap_or(Path::new("/")).to_path_buf();
        let (workspace, workspace_dir) = match manifest.get("workspace") {
            Some(own) => (own, parent.clone()),
            None => (
                root.get("workspace").unwrap_or(&EMPTY),
                checkout.to_path_buf(),
            ),
        };
        for (kind, table) in dependency_tables(&manifest) {
            for (alias, value) in object_rows(table) {
                let (actual, cfg) = dependency(alias, value, workspace)?;
                let known = policy.package(&actual);
                let git = match cfg.get("git") {
                    Some(g) if py::truthy(g) => {
                        git_repository(Some(&format!("git+{}", g.as_str().unwrap_or(""))))
                    }
                    _ => None,
                };
                let external = git.as_ref().is_some_and(|g| policy.external(&actual, g));
                if known.is_none()
                    && !external
                    && (actual.starts_with("busbar-")
                        || git
                            .as_ref()
                            .is_some_and(|g| matches!(owner(g), "GetBusbar" | "BusbarInc")))
                {
                    return Err(format!(
                        "unclassified declared first-party package: {actual}"
                    ));
                }
                let Some(known) = known.filter(|k| py::truthy(k)) else {
                    continue;
                };
                let allows = key(entry, "allows")?;
                let allowed = if kind == "dev" {
                    entry.get("dev_allows").unwrap_or(allows)
                } else {
                    allows
                };
                if !contains(allowed, &actual) {
                    return Err(format!(
                        "forbidden declared {kind} edge: {name} -> {actual}"
                    ));
                }
                if kind != "dev"
                    && names(cfg.at("features"))
                        .iter()
                        .any(|f| forbidden.contains(f))
                {
                    return Err(format!(
                        "forbidden shipping feature declaration: {name} -> {actual}"
                    ));
                }
                if py::truthy(cfg.at("git")) {
                    let git = git.unwrap_or_default();
                    let known_repository = key_str(known, "repository")?;
                    if git.1 != known_repository
                        || !(git.0.as_deref() == Some("github.com") || git.0.as_deref() == ci_host)
                    {
                        return Err(format!("declared source mismatch: {name} -> {actual}"));
                    }
                    let rev = cfg
                        .get("rev")
                        .map_or(Some(""), Value::as_str)
                        .unwrap_or("\0");
                    if !hex40(rev) || cfg.get("branch").is_some() || cfg.get("tag").is_some() {
                        return Err(format!(
                            "first-party dependency must have an immutable full revision: {actual}"
                        ));
                    }
                    if policy.is_core(&actual) {
                        refs.insert(rev.to_owned());
                    }
                } else if let Some(relative) = cfg.get("path") {
                    let base = if value.is_object() && py::truthy(value.at("workspace")) {
                        &workspace_dir
                    } else {
                        &parent
                    };
                    let relative = relative.as_str().unwrap_or("");
                    let resolved = pathx::resolve(&join(&join(base, relative), "Cargo.toml"));
                    if key_str(known, "repository")? != repository
                        || resolved != pathx::resolve(&join(checkout, key_str(known, "manifest")?))
                    {
                        return Err(format!(
                            "cross-repository path dependency: {name} -> {actual}"
                        ));
                    }
                } else {
                    return Err(format!(
                        "first-party package cannot come from a registry: {actual}"
                    ));
                }
            }
        }
        if matches!(
            entry.at("role").as_str(),
            Some("implementation" | "wrapper")
        ) && manifest
            .at("features")
            .keys()
            .iter()
            .any(|f| forbidden.contains(*f))
        {
            return Err(format!("plugin exposes a test authority feature: {name}"));
        }
        check_substitutions(&manifest, &parent, policy, repository, checkout)?;
    }
    // A new workspace member cannot disappear merely because it was omitted from policy.
    for member in names(root.at("workspace").at("members")) {
        for path in pathx::glob(checkout, &format!("{member}/Cargo.toml")) {
            if !expected_paths.contains(&pathx::resolve(&path)) {
                let relative = path.strip_prefix(checkout).unwrap_or(&path);
                return Err(format!("unclassified workspace member: {}", text(relative)));
            }
        }
    }
    if repository != CORE {
        let pin_text = pathx::read_text(&join(checkout, ".busbar-ref"))?;
        let fields = super::split_ws(&pin_text);
        if fields.len() != 2 || fields[1] != "1.6.0" {
            return Err("expected SDK revision and product 1.6.0 in .busbar-ref".into());
        }
        let pin = fields[0];
        if refs != BTreeSet::from([pin.to_owned()]) || !hex40(pin) {
            return Err(format!(
                "SDK manifest/.busbar-ref mismatch: {} vs {pin}",
                sorted_repr(&refs)
            ));
        }
        let lock = read(&join(checkout, "Cargo.lock"))?;
        for p in key(&lock, "package")?.as_array().unwrap_or(&[]) {
            let name = key_str(p, "name")?;
            if policy.is_core(name) {
                let source = p
                    .get("source")
                    .map_or(Some(""), Value::as_str)
                    .unwrap_or("");
                let identity = git_repository(Some(source));
                let canonical = [
                    identity_of("github.com", &CORE.into()),
                    self::identity(ci_host, CORE),
                ];
                if !source.ends_with(&format!("#{pin}"))
                    || !identity.is_some_and(|i| canonical.contains(&i))
                {
                    return Err(format!("SDK lock source mismatch: {name}: {source}"));
                }
            }
        }
    }
    Ok(entries)
}

/// `inline(value)`: TOML inline tables of JSON scalars and arrays.
pub fn inline(value: &Value) -> String {
    match value {
        Value::Object(rows) => format!(
            "{{ {} }}",
            rows.iter()
                .map(|(k, v)| format!(
                    "{} = {}",
                    json::dumps(&Value::str(k.clone()), false),
                    inline(v)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => json::dumps(other, false),
    }
}

fn quoted(text: &str) -> String {
    json::dumps(&Value::str(text), false)
}

/// `vector_revisions(policy, vector)` (the shared policy reader).
pub fn vector_revisions(policy: &Policy, vector: &Value) -> Result<Vec<(String, String)>> {
    Ok(crate::product::vector_revisions(&policy.data, vector)?)
}

/// Bind every declared/locked first-party source to the assembled product vector.
pub fn check_vector(
    policy: &Policy,
    checkout: &Path,
    entries: &[(String, Value)],
) -> Result<Value> {
    let pins = join(checkout, "scripts/ci-product-pins.json");
    let vector = loads(&pathx::read_text(&pins)?)?;
    let revisions = vector_revisions(policy, &vector)?;
    let revision = |repository: &str| {
        revisions
            .iter()
            .find(|(r, _)| r == repository)
            .map(|(_, c)| c.as_str())
    };
    let root = read(&join(checkout, "Cargo.toml"))?;
    static EMPTY: Value = Value::Object(Vec::new());
    let workspace = root.get("workspace").unwrap_or(&EMPTY);
    let mut manifests = BTreeSet::new();
    for (_, entry) in entries {
        manifests.insert(join(checkout, key_str(entry, "manifest")?));
    }
    manifests.insert(join(checkout, "Cargo.toml"));
    for path in &manifests {
        let manifest = read(path)?;
        let own_workspace = manifest.get("workspace").unwrap_or(workspace);
        let mut tables = dependency_tables(&manifest);
        tables.push((
            "workspace",
            own_workspace.get("dependencies").unwrap_or(&EMPTY),
        ));
        for (_, table) in tables {
            for (alias, cfg) in object_rows(table) {
                let (name, value) = dependency(alias, cfg, own_workspace)?;
                if let Some(known) = policy.package(&name).filter(|k| py::truthy(k))
                    && py::truthy(value.at("git"))
                {
                    let rev = key(&value, "rev")?;
                    let expected = revision(key_str(known, "repository")?);
                    if rev.as_str() != expected || expected.is_none() && !matches!(rev, Value::Null)
                    {
                        return Err(format!(
                            "assembly manifest/vector mismatch: {}: {name}",
                            text(path)
                        ));
                    }
                }
            }
        }
    }
    for path in [
        join(checkout, "Cargo.lock"),
        join(checkout, "dist/default/Cargo.lock"),
    ] {
        let lock = read(&path)?;
        for package in key(&lock, "package")?.as_array().unwrap_or(&[]) {
            let name = key_str(package, "name")?;
            if let Some(known) = policy.package(name).filter(|k| py::truthy(k))
                && let Some(source) = package.at("source").as_str().filter(|s| !s.is_empty())
            {
                let expected = revision(key_str(known, "repository")?).unwrap_or("unclassified");
                if !source.ends_with(&format!("#{expected}")) {
                    return Err(format!(
                        "assembly lock/vector mismatch: {}: {name}",
                        text(&path)
                    ));
                }
            }
        }
    }
    Ok(Value::Object(vec![
        ("sdk_revision".into(), key(&vector, "sdk")?.clone()),
        (
            "products".into(),
            Value::int(key(&vector, "products")?.as_array().map_or(0, <[_]>::len) as i64),
        ),
        (
            "vector_sha256".into(),
            Value::str(sha256::hex(&pathx::read(&pins)?)),
        ),
    ]))
}

/// Cargo ignores binary-only dependencies. Resolve their actual normal/build
/// edges in a manifest with an empty library; no fixture/dev feature can
/// contaminate it.
fn binary_resolution_root(checkout: &Path, entry: &Value, probe: &Path) -> Result<PathBuf> {
    let original = join(checkout, key_str(entry, "manifest")?);
    let manifest = read(&original)?;
    let parent = original.parent().unwrap_or(Path::new("/")).to_path_buf();
    let root_dir = if manifest.get("workspace").is_some() {
        parent.clone()
    } else {
        checkout.to_path_buf()
    };
    static EMPTY: Value = Value::Object(Vec::new());
    let root = read(&join(&root_dir, "Cargo.toml"))?;
    let workspace = root.get("workspace").unwrap_or(&EMPTY);
    let package = key(&manifest, "package")?;
    let name = key_str(package, "name")?;
    let probe_name = probe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let binary = probe
        .parent()
        .unwrap_or(Path::new("/"))
        .join(format!("{probe_name}-{name}"));
    pathx::mkdirs(&binary.join("src"))?;
    pathx::write(
        &binary.join("src/lib.rs"),
        "// Dependency resolution only; native CI builds the actual binary.\n",
    )?;
    let mut lines = vec![
        "[workspace]".to_owned(),
        "[package]".to_owned(),
        format!("name={}", inline(key(package, "name")?)),
        format!("version={}", inline(key(package, "version")?)),
        "edition=\"2021\"".to_owned(),
    ];
    let mut groups: Vec<(String, &Value)> = vec![(String::new(), &manifest)];
    for (target, table) in object_rows(manifest.at("target")) {
        groups.push((
            format!("target.{}.", inline(&Value::str(target.clone()))),
            table,
        ));
    }
    for (prefix, tables) in groups {
        for section in ["dependencies", "build-dependencies"] {
            lines.push(format!("[{prefix}{section}]"));
            for (alias, value) in object_rows(tables.at(section)) {
                let (_, mut cfg) = dependency(alias, value, workspace)?;
                if let Some(relative) = cfg.get("path").and_then(Value::as_str).map(str::to_owned) {
                    let base = if value.is_object() && py::truthy(value.at("workspace")) {
                        &root_dir
                    } else {
                        &parent
                    };
                    cfg.set(
                        "path",
                        Value::str(text(&pathx::resolve(&join(base, relative)))),
                    );
                }
                lines.push(format!(
                    "{}={}",
                    inline(&Value::str(alias.clone())),
                    inline(&cfg)
                ));
            }
        }
    }
    lines.push("[features]".into());
    for (feature, values) in object_rows(manifest.at("features")) {
        if !matches!(feature.as_str(), "test-support" | "test-seal") {
            lines.push(format!(
                "{}={}",
                inline(&Value::str(feature.clone())),
                inline(values)
            ));
        }
    }
    pathx::write(&binary.join("Cargo.toml"), lines.join("\n") + "\n")?;
    Ok(binary)
}

/// A disposable consumer has no dependency dev edges or workspace feature unification.
pub fn resolve_shipping(
    ctx: &mut Ctx,
    checkout: &Path,
    entries: &[(String, Value)],
    scratch: &Path,
    assembly: bool,
) -> Result<Value> {
    let probe = scratch.join(if assembly {
        "assembly-probe"
    } else {
        "shipping-probe"
    });
    pathx::mkdirs(&probe)?;
    if !probe.join("src").is_dir() {
        pathx::mkdir(&probe.join("src"), 0o777)?;
    }
    pathx::write(
        &probe.join("src/lib.rs"),
        "// Admission-only resolution root.\n",
    )?;
    let mut lines = strings(&[
        "[workspace]",
        "[package]",
        "name = \"architecture-shipping-probe\"",
        "version = \"0.0.0\"",
        "edition = \"2021\"",
        "[dependencies]",
    ]);
    let mut binary_roots: Vec<(String, String)> = Vec::new();
    for (index, (name, entry)) in entries.iter().enumerate() {
        let role = entry.at("role").as_str();
        if role == Some("test_host") || (role == Some("assembly")) != assembly {
            continue; // the assembly owns a separate workspace and is resolved separately
        }
        let manifest_path = join(checkout, key_str(entry, "manifest")?);
        let manifest = read(&manifest_path)?;
        let features: BTreeSet<&str> = manifest
            .at("features")
            .keys()
            .into_iter()
            .filter(|f| !matches!(*f, "default" | "test-support" | "test-seal"))
            .collect();
        let mut directory = manifest_path
            .parent()
            .unwrap_or(Path::new("/"))
            .to_path_buf();
        if manifest.get("lib").is_none() && !directory.join("src/lib.rs").is_file() {
            directory = binary_resolution_root(checkout, entry, &probe)?;
            binary_roots.push((name.clone(), text(&pathx::resolve(&manifest_path))));
        }
        let features: Vec<String> = features.into_iter().map(str::to_owned).collect();
        lines.push(format!(
            "root_{index} = {{ package = {}, path = {}, features = {} }}",
            quoted(name),
            quoted(&text(&directory)),
            json::dumps(&super::str_list(&features), false)
        ));
    }
    let root_dir = if assembly {
        join(checkout, "dist/default")
    } else {
        checkout.to_path_buf()
    };
    let root = read(&join(&root_dir, "Cargo.toml"))?;
    for (source, table) in object_rows(root.at("patch")) {
        lines.push(format!("[patch.{}]", quoted(source)));
        for (name, cfg) in object_rows(table) {
            let mut cfg = cfg.clone();
            if let Some(relative) = cfg.get("path").and_then(Value::as_str).map(str::to_owned) {
                cfg.set(
                    "path",
                    Value::str(text(&pathx::resolve(&join(&root_dir, relative)))),
                );
            }
            let values: Vec<String> = object_rows(&cfg)
                .iter()
                .map(|(k, v)| format!("{k} = {}", json::dumps(v, false)))
                .collect();
            lines.push(format!("{} = {{ {} }}", quoted(name), values.join(", ")));
        }
    }
    pathx::write(&probe.join("Cargo.toml"), lines.join("\n") + "\n")?;
    let committed = join(&root_dir, "Cargo.lock");
    if committed.is_file() {
        pathx::write(&probe.join("Cargo.lock"), pathx::read(&committed)?)?;
    }
    let argv = strings(&[
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--manifest-path",
        &text(&probe.join("Cargo.toml")),
    ]);
    let mut metadata = loads(&ctx.output(Call::new(&argv).cwd(scratch))?)?;
    if let Some(Value::Array(packages)) = metadata.get_mut("packages") {
        for package in packages.iter_mut() {
            let name = package.at("name").as_str().unwrap_or("").to_owned();
            if let Some((_, path)) = binary_roots.iter().find(|(n, _)| *n == name) {
                package.set("manifest_path", Value::str(path.clone()));
            }
        }
    }
    if committed.is_file() {
        let lock = read(&committed)?;
        let mut locked = BTreeSet::new();
        for p in key(&lock, "package")?.as_array().unwrap_or(&[]) {
            locked.insert((
                json::dumps(key(p, "name")?, false),
                json::dumps(key(p, "version")?, false),
                json::dumps(p.at("source"), false),
            ));
        }
        for package in key(&metadata, "packages")?.as_array().unwrap_or(&[]) {
            if py::truthy(package.at("source")) {
                let row = (
                    json::dumps(key(package, "name")?, false),
                    json::dumps(key(package, "version")?, false),
                    json::dumps(package.at("source"), false),
                );
                if !locked.contains(&row) {
                    return Err(format!(
                        "shipping resolver drifted from committed lock: {} {}",
                        py::str(package.at("name")),
                        py::str(package.at("version"))
                    ));
                }
            }
        }
    }
    Ok(metadata)
}
