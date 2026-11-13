//! `ci/architecture.toml`: the owner's classification of every first-party package.

use toml::{Table, Value};

use crate::refuse::{Result, Rule, Violation};

pub const CORE: &str = "GetBusbar/busbar";
pub const PUBLIC_C_HEADER: &str = "crates/busbar-contract/include/busbar_plugin.h";

/// A policy entry. Kept as a table, like the Python dicts, so every optional key
/// keeps its exact meaning (`allows`, `dev_allows`, `generated_by`, ...).
pub type Entry = Table;

pub struct Policy {
    pub data: Table,
    /// Every classified package name, in policy order: core, repository
    /// packages, the assembly, then test hosts.
    pub packages: toml::map::Map<String, Value>,
}

fn shape(what: &str) -> Violation {
    Violation::new(Rule::PolicyShape, format!("policy is missing {what}"))
}

pub fn table<'a>(value: &'a Table, key: &str) -> Result<&'a Table> {
    value
        .get(key)
        .and_then(Value::as_table)
        .ok_or_else(|| shape(&format!("table {key:?}")))
}

pub fn str_of<'a>(value: &'a Table, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| shape(&format!("string {key:?}")))
}

/// A list of strings (missing or non-string items are a policy-shape error).
pub fn strings(value: Option<&Value>) -> Result<Vec<String>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| shape("string list item"))
            })
            .collect(),
        Some(_) => Err(shape("string list")),
    }
}

fn array_of(names: Vec<String>) -> Value {
    Value::Array(names.into_iter().map(Value::String).collect())
}

impl Policy {
    pub fn new(data: Table) -> Result<Self> {
        if data.get("version").and_then(Value::as_integer) != Some(1) {
            return Err(Violation::new(
                Rule::PolicyVersion,
                "unsupported architecture policy",
            ));
        }
        let mut packages = toml::map::Map::new();
        for (name, entry) in table(&data, "core")? {
            let mut entry = entry.as_table().ok_or_else(|| shape("core entry"))?.clone();
            entry.insert("repository".into(), Value::String(CORE.into()));
            entry.insert("role".into(), Value::String("core".into()));
            packages.insert(name.clone(), Value::Table(entry));
        }
        for (repository, repo) in table(&data, "repositories")? {
            let repo = repo.as_table().ok_or_else(|| shape("repository entry"))?;
            let rows: Vec<&Table> = match repo.get("packages") {
                None => Vec::new(),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|v| v.as_table().ok_or_else(|| shape("package row")))
                    .collect::<Result<_>>()?,
                Some(_) => return Err(shape("packages array")),
            };
            let mut own = Vec::new();
            for p in &rows {
                if str_of(p, "role")? == "implementation" {
                    own.push(str_of(p, "name")?.to_string());
                }
            }
            for p in rows {
                let mut allows = vec!["busbar-contract".to_string()];
                if str_of(p, "role")? == "wrapper" {
                    allows.extend(own.iter().cloned());
                }
                let mut entry = p.clone();
                entry.insert("repository".into(), Value::String(repository.clone()));
                entry.insert("allows".into(), array_of(allows));
                packages.insert(str_of(p, "name")?.to_string(), Value::Table(entry));
            }
        }
        let assembly = table(&data, "assembly")?;
        let mut entry = assembly.clone();
        entry.insert("role".into(), Value::String("assembly".into()));
        entry.insert(
            "allows".into(),
            array_of(packages.keys().cloned().collect()),
        );
        packages.insert(
            str_of(assembly, "package")?.to_string(),
            Value::Table(entry),
        );
        if let Some(Value::Array(hosts)) = data.get("test_hosts") {
            for host in hosts {
                let host = host.as_table().ok_or_else(|| shape("test host"))?;
                if let Some(package) = host.get("package").and_then(Value::as_str) {
                    if package.is_empty() {
                        continue;
                    }
                    let mut entry = host.clone();
                    entry.insert("role".into(), Value::String("test_host".into()));
                    let allows = host.get("allows").cloned().ok_or_else(|| shape("allows"))?;
                    entry.insert("dev_allows".into(), allows);
                    packages.insert(package.to_string(), Value::Table(entry));
                }
            }
        }
        Ok(Policy { data, packages })
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.packages.get(name).and_then(Value::as_table)
    }

    pub fn core(&self) -> &Table {
        self.data
            .get("core")
            .and_then(Value::as_table)
            .expect("checked in Policy::new")
    }

    pub fn repositories(&self) -> &Table {
        self.data
            .get("repositories")
            .and_then(Value::as_table)
            .expect("checked in Policy::new")
    }

    pub fn is_core(&self, name: &str) -> bool {
        self.core().contains_key(name)
    }

    pub fn forbidden(&self) -> Result<Vec<String>> {
        match self.data.get("forbidden_shipping_features") {
            None => Err(shape("forbidden_shipping_features")),
            value => strings(value),
        }
    }

    /// `[[external_sources]]`: (package, repository) pairs of non-first-party
    /// packages that legitimately live in a first-party repository.
    pub fn external_sources(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(Value::Array(rows)) = self.data.get("external_sources") {
            for row in rows.iter().filter_map(Value::as_table) {
                if let (Some(name), Some(repo)) = (
                    row.get("name").and_then(Value::as_str),
                    row.get("repository").and_then(Value::as_str),
                ) {
                    out.push((name.to_string(), repo.to_string()));
                }
            }
        }
        out
    }
}

/// An entry's role.
pub fn role(entry: &Entry) -> &str {
    entry.get("role").and_then(Value::as_str).unwrap_or("")
}

pub fn repository(entry: &Entry) -> &str {
    entry
        .get("repository")
        .and_then(Value::as_str)
        .unwrap_or("")
}

pub fn manifest(entry: &Entry) -> Result<&str> {
    str_of(entry, "manifest")
}

pub fn allows(entry: &Entry) -> Result<Vec<String>> {
    match entry.get("allows") {
        None => Err(shape("allows")),
        value => strings(value),
    }
}

/// `entry.get('dev_allows', entry['allows'])`.
pub fn dev_allows(entry: &Entry) -> Result<Vec<String>> {
    let fallback = allows(entry)?;
    match entry.get("dev_allows") {
        None => Ok(fallback),
        value => strings(value),
    }
}

/// Python truthiness of an optional policy value.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(Value::Boolean(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Integer(i)) => *i != 0,
        Some(Value::Float(f)) => *f != 0.0,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Table(t)) => !t.is_empty(),
        Some(Value::Datetime(_)) => true,
    }
}
