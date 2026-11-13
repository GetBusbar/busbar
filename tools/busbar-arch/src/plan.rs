//! `busbar-arch plan`: what a repository's CI must run, from the policy only
//! (port of `scripts/architecture/native_policy.py` plus the `plugins.yaml`
//! extra test), and the conformance roster check.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value as Json};
use toml::{Table, Value};

use crate::c::{regular_under, relative_path};
use crate::policy::Policy;
use crate::py;
use crate::refuse::{Result, Rule, Violation};

const SERVICES: [&str; 6] = [
    "postgres", "mysql", "valkey", "vault", "wiremock", "openldap",
];
const FIELDS: [&str; 6] = [
    "services",
    "migration_fixture",
    "server_binary",
    "native_oracle",
    "prepare_runtime",
    "required_conformance",
];

fn refuse(message: &str) -> Violation {
    Violation::new(Rule::NativePolicy, message)
}

/// `native_settings`.
pub fn native_settings(repository: &str, policy: &Policy) -> Result<Table> {
    let assembly = policy
        .data
        .get("assembly")
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let entry = if assembly.get("repository").and_then(Value::as_str) == Some(repository) {
        assembly
    } else {
        policy
            .repositories()
            .get(repository)
            .and_then(Value::as_table)
            .cloned()
            .unwrap_or_default()
    };
    let settings = match entry.get("native") {
        None => Table::new(),
        Some(Value::Table(t)) if t.keys().all(|k| FIELDS.contains(&k.as_str())) => t.clone(),
        Some(_) => return Err(refuse("unknown native capability policy fields")),
    };
    let services: Vec<&Value> = match settings.get("services") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.iter().collect(),
        Some(_) => return Err(refuse("unknown or duplicate native fixture service")),
    };
    let names: Vec<&str> = services.iter().filter_map(|v| v.as_str()).collect();
    let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
    if services.len() > SERVICES.len()
        || names.len() != services.len()
        || names.iter().any(|n| !SERVICES.contains(n))
        || unique.len() != names.len()
    {
        return Err(refuse("unknown or duplicate native fixture service"));
    }
    match settings.get("migration_fixture") {
        None => {}
        Some(Value::String(s)) if s == "sqlite-1.5.5" => {}
        Some(_) => return Err(refuse("unknown native migration fixture")),
    }
    if let Some(binary) = settings.get("server_binary") {
        if binary.as_str() != Some("valkey") || !names.contains(&"valkey") {
            return Err(refuse(
                "native server witness requires its declared service",
            ));
        }
    }
    if !matches!(
        settings.get("native_oracle"),
        None | Some(Value::Boolean(_))
    ) {
        return Err(refuse("native oracle requirement must be boolean"));
    }
    if !matches!(
        settings.get("required_conformance"),
        None | Some(Value::Boolean(_))
    ) {
        return Err(refuse("native conformance requirement must be boolean"));
    }
    if let Some(script) = settings.get("prepare_runtime") {
        let json = match script {
            Value::String(s) => Json::String(s.clone()),
            _ => Json::Null,
        };
        let path = relative_path(&json)?;
        if !path.starts_with("testing/native/") || !path.ends_with(".sh") {
            return Err(refuse(
                "runtime preparation must name an owner native script",
            ));
        }
    }
    Ok(settings)
}

/// `conformance_rows`: the protected suites a required owner must run.
pub fn conformance_rows(
    repository: &str,
    policy: &Policy,
    trusted: &Path,
) -> Result<BTreeMap<String, String>> {
    let settings = native_settings(repository, policy)?;
    if settings
        .get("required_conformance")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Ok(BTreeMap::new());
    }
    let coverage = py::read_json(&py::join(trusted, "conformance/ci-coverage.json"))?;
    if coverage.get("schema").and_then(Json::as_str) != Some("busbar.conformance.ci-coverage/1") {
        return Err(Violation::new(
            Rule::ConformanceRoster,
            "required conformance coverage schema differs",
        ));
    }
    let mut rows = BTreeMap::new();
    let mut complete = true;
    for (name, row) in coverage["suites"].as_object().into_iter().flatten() {
        if row.get("repo").and_then(Json::as_str) != Some(repository) {
            continue;
        }
        match row.get("command").and_then(Json::as_str) {
            Some(command) if !command.is_empty() => {
                rows.insert(name.clone(), command.to_string());
            }
            _ => complete = false,
        }
    }
    if rows.is_empty() || !complete {
        return Err(Violation::new(
            Rule::ConformanceRoster,
            "required owner has no complete protected conformance inventory",
        ));
    }
    Ok(rows)
}

/// `validate_conformance_roster`: `testing/conformance/suites.tsv` lists every
/// required suite with exactly its protected command.
pub fn validate_conformance_roster(root: &Path, rows: &BTreeMap<String, String>) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let roster = regular_under(&py::join(root, "testing/conformance/suites.tsv"), root)?;
    let mut actual: BTreeMap<String, String> = BTreeMap::new();
    for line in py::read_text(&roster)?.split('\n') {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((name, command)) = line.split_once('\t') else {
            return Err(Violation::new(
                Rule::ConformanceRoster,
                "invalid or duplicate required conformance roster entry",
            ));
        };
        if actual
            .insert(name.to_string(), command.to_string())
            .is_some()
        {
            return Err(Violation::new(
                Rule::ConformanceRoster,
                "invalid or duplicate required conformance roster entry",
            ));
        }
    }
    if rows
        .iter()
        .any(|(name, command)| actual.get(name) != Some(command))
    {
        return Err(Violation::new(
            Rule::ConformanceRoster,
            "required conformance suite is missing or its command differs from protected coverage",
        ));
    }
    Ok(())
}

/// The `plugins.yaml` extra test of a plugin repository, if any.
pub fn extra_test(trusted: &Path, repository: &str) -> Result<Option<String>> {
    let path = py::join(trusted, "plugins.yaml");
    let text = py::read_text(&path)?;
    let registry: serde_yaml::Value = serde_yaml::from_str(&text)
        .map_err(|e| Violation::new(Rule::Parse, format!("{}: {e}", path.display())))?;
    let short = repository.rsplit('/').next().unwrap_or("");
    let plugin = registry
        .get("plugins")
        .and_then(serde_yaml::Value::as_sequence)
        .and_then(|rows| {
            rows.iter()
                .find(|p| p.get("repo").and_then(serde_yaml::Value::as_str) == Some(short))
        });
    Ok(plugin
        .and_then(|p| p.get("extra_test"))
        .and_then(serde_yaml::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string))
}

fn toml_to_json(value: &Value) -> Json {
    match value {
        Value::String(s) => Json::String(s.clone()),
        Value::Integer(i) => json!(i),
        Value::Float(f) => json!(f),
        Value::Boolean(b) => json!(b),
        Value::Datetime(d) => Json::String(d.to_string()),
        Value::Array(a) => Json::Array(a.iter().map(toml_to_json).collect()),
        Value::Table(t) => Json::Object(
            t.iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect(),
        ),
    }
}

/// The plan document.
pub fn plan(
    policy: &Policy,
    repository: &str,
    trusted: &Path,
    checkout: Option<&Path>,
) -> Result<Json> {
    if repository != crate::policy::CORE && !policy.repositories().contains_key(repository) {
        return Err(Violation::new(
            Rule::UnclassifiedRepository,
            format!("unclassified repository {repository}"),
        ));
    }
    let settings = native_settings(repository, policy)?;
    let rows = conformance_rows(repository, policy, trusted)?;
    if let Some(checkout) = checkout {
        validate_conformance_roster(&py::resolve(checkout), &rows)?;
    }
    let extra = if repository == crate::policy::CORE {
        None
    } else {
        extra_test(trusted, repository)?
    };
    Ok(json!({
        "repository": repository,
        "native": toml_to_json(&Value::Table(settings)),
        "extra_test": extra,
        "required_suites": rows,
        "roster_checked": checkout.is_some() && !rows.is_empty(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(native: &str) -> Policy {
        let text = format!(
            "version = 1\nforbidden_shipping_features = []\n[core]\n[repositories.\"GetBusbar/busbar-x\"]\nkind = \"auth\"\nprivate = false\nnative = {native}\n[assembly]\npackage = \"busbar-default\"\nrepository = \"GetBusbar/busbar\"\nmanifest = \"dist/default/Cargo.toml\"\n"
        );
        Policy::new(text.parse().unwrap()).unwrap()
    }

    #[test]
    fn native_table_is_a_closed_set() {
        native_settings("GetBusbar/busbar-x", &policy("{ services = [\"valkey\"], server_binary = \"valkey\", prepare_runtime = \"testing/native/prepare.sh\" }")).unwrap();
        for (native, message) in [
            (
                "{ shell = \"x\" }",
                "unknown native capability policy fields",
            ),
            (
                "{ services = [\"redis\"] }",
                "unknown or duplicate native fixture service",
            ),
            (
                "{ services = [\"vault\", \"vault\"] }",
                "unknown or duplicate native fixture service",
            ),
            (
                "{ migration_fixture = \"sqlite-1.6\" }",
                "unknown native migration fixture",
            ),
            (
                "{ server_binary = \"valkey\" }",
                "native server witness requires its declared service",
            ),
            (
                "{ native_oracle = \"yes\" }",
                "native oracle requirement must be boolean",
            ),
            (
                "{ required_conformance = 1 }",
                "native conformance requirement must be boolean",
            ),
            (
                "{ prepare_runtime = \"scripts/x.sh\" }",
                "runtime preparation must name an owner native script",
            ),
        ] {
            assert_eq!(
                native_settings("GetBusbar/busbar-x", &policy(native))
                    .unwrap_err()
                    .message,
                message
            );
        }
    }

    #[test]
    fn roster_cannot_drop_or_change_a_suite() {
        let dir = crate::tests::TempDir::new("roster");
        let root = py::resolve(dir.path());
        std::fs::create_dir_all(root.join("testing/conformance")).unwrap();
        let rows: BTreeMap<String, String> =
            [("tls".to_string(), "bash tls.sh".to_string())].into();
        std::fs::write(
            root.join("testing/conformance/suites.tsv"),
            "# suites\ntls\tbash tls.sh\n",
        )
        .unwrap();
        validate_conformance_roster(&root, &rows).unwrap();
        std::fs::write(
            root.join("testing/conformance/suites.tsv"),
            "tls\tbash other.sh\n",
        )
        .unwrap();
        assert_eq!(
            validate_conformance_roster(&root, &rows).unwrap_err().rule,
            Rule::ConformanceRoster
        );
        std::fs::write(
            root.join("testing/conformance/suites.tsv"),
            "tls\tbash tls.sh\ntls\tbash tls.sh\n",
        )
        .unwrap();
        assert_eq!(
            validate_conformance_roster(&root, &rows)
                .unwrap_err()
                .message,
            "invalid or duplicate required conformance roster entry"
        );
    }
}
