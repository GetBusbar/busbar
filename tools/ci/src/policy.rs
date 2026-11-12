//! Protected policy selections the bootstrap needs: native fixture services and
//! conformance judge inputs. Mirrors `native_policy.native_settings`,
//! `native_service_inputs.selection` and the judge-plan validation.
use crate::images::{ServiceRow, is_digest};
use crate::json::Value;
use crate::proc::{Result, require};
use crate::toml;
use std::path::Path;

const KNOWN_SERVICES: [&str; 6] = [
    "postgres", "mysql", "valkey", "vault", "wiremock", "openldap",
];
const PACKAGES: &str = "https://git.getbusbar.dev/api/v4/projects/3/packages/generic/";

fn relative_path(value: &Value) -> Result<&str> {
    let text = value.as_str().unwrap_or("");
    require(
        !text.is_empty()
            && text.len() <= 512
            && text
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'/' | b'-')),
        "invalid product source path",
    )?;
    require(
        !text.starts_with('/') && text.split('/').all(|p| !matches!(p, "" | "." | "..")),
        "product source path must be relative and confined",
    )?;
    Ok(text)
}

/// `native_policy.native_settings(repository, policy)`.
pub fn native_settings(repository: &str, policy: &Value) -> Result<Value> {
    let assembly = policy.at("assembly");
    let entry = if assembly.at("repository").as_str() == Some(repository) {
        assembly
    } else {
        policy
            .at("repositories")
            .as_object()
            .ok_or("policy has no repositories")?;
        policy.at("repositories").at(repository)
    };
    let settings = entry
        .get("native")
        .cloned()
        .unwrap_or(Value::Object(Vec::new()));
    let allowed = [
        "services",
        "migration_fixture",
        "server_binary",
        "external_conformance",
        "native_oracle",
        "prepare_runtime",
        "required_conformance",
    ];
    require(
        settings
            .as_object()
            .is_some_and(|rows| rows.iter().all(|(k, _)| allowed.contains(&k.as_str()))),
        "unknown native capability policy fields",
    )?;
    let services = settings
        .get("services")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let names: Option<Vec<&str>> = services
        .as_array()
        .map(|rows| rows.iter().map(Value::as_str).collect())
        .unwrap_or(None);
    require(
        names.as_ref().is_some_and(|names| {
            names.len() <= KNOWN_SERVICES.len()
                && names.iter().all(|n| KNOWN_SERVICES.contains(n))
                && names
                    .iter()
                    .enumerate()
                    .all(|(i, n)| !names[..i].contains(n))
        }),
        "unknown or duplicate native fixture service",
    )?;
    if let Some(fixture) = settings.get("migration_fixture") {
        require(
            fixture.as_str() == Some("sqlite-1.5.5"),
            "unknown native migration fixture",
        )?;
    }
    if let Some(binary) = settings.get("server_binary") {
        require(
            binary.as_str() == Some("valkey") && names.as_ref().unwrap().contains(&"valkey"),
            "native server witness requires its declared service",
        )?;
    }
    for key in ["native_oracle", "required_conformance"] {
        if let Some(value) = settings.get(key) {
            require(
                value.as_bool().is_some(),
                &format!("native {key} requirement must be boolean"),
            )?;
        }
    }
    if let Some(value) = settings.get("external_conformance") {
        let path = relative_path(value)?;
        require(
            path.starts_with("testing/conformance/") && path.ends_with(".sh"),
            "external evaluation must name an owner conformance script",
        )?;
    }
    if let Some(value) = settings.get("prepare_runtime") {
        let path = relative_path(value)?;
        require(
            path.starts_with("testing/native/") && path.ends_with(".sh"),
            "runtime preparation must name an owner native script",
        )?;
    }
    Ok(settings)
}

fn read_json(path: &Path) -> Result<Value> {
    crate::json::parse(&std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?)
}

/// `<prefix>/<8 digits>-<sha>/<file>` exactly.
fn package_url(url: &str, package: &str, sha: &str, file: &str) -> bool {
    let Some(rest) = url.strip_prefix(&format!("{PACKAGES}{package}/")) else {
        return false;
    };
    rest.len() == 8 + 1 + 64 + 1 + file.len()
        && rest[..8].bytes().all(|c| c.is_ascii_digit())
        && rest[8..]
            .strip_prefix('-')
            .and_then(|r| r.strip_prefix(sha))
            .and_then(|r| r.strip_prefix('/'))
            == Some(file)
}

/// Service archives selected by protected policy for `repository`.
pub fn service_selection(trusted: &Path, repository: &str) -> Result<Vec<ServiceRow>> {
    let plan = read_json(&trusted.join("ci/native-service-images.json"))?;
    require(
        plan.has_keys(&["schema", "services"])
            && plan.at("schema").as_str() == Some("busbar.native-service-images/1"),
        "unknown protected service input schema",
    )?;
    let policy_text =
        std::fs::read_to_string(trusted.join("ci/architecture.toml")).map_err(|e| e.to_string())?;
    let settings = native_settings(repository, &toml::parse(&policy_text)?)?;
    let names: Vec<String> = settings
        .at("services")
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let catalog_text =
        std::fs::read_to_string(trusted.join("testing/fleet-fixtures/service-images.tsv"))
            .map_err(|e| e.to_string())?;
    let mut catalog: Vec<(String, String)> = Vec::new();
    for line in catalog_text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        require(fields.len() >= 3, "invalid protected service catalog line")?;
        let reference = format!("{}@{}", fields[1], fields[2]);
        match catalog.iter_mut().find(|(n, _)| n == fields[0]) {
            Some(row) => row.1 = reference,
            None => catalog.push((fields[0].to_owned(), reference)),
        }
    }
    let mut result = Vec::new();
    for name in names {
        let row = plan.at("services").at(&name);
        require(
            row.has_keys(&[
                "reference",
                "archive_url",
                "archive_sha256",
                "bytes",
                "manifest_sha256",
                "config_sha256",
            ]),
            "incomplete protected service archive",
        )?;
        let text = |key: &str| row.at(key).as_str().unwrap_or("").to_owned();
        require(
            catalog
                .iter()
                .any(|(n, r)| *n == name && *r == text("reference"))
                && row.at("reference").as_str().is_some(),
            "service archive differs from protected catalog",
        )?;
        for key in ["archive_sha256", "manifest_sha256", "config_sha256"] {
            require(is_digest(&text(key)), "invalid service digest")?;
        }
        let bytes = row.at("bytes").as_u64().filter(|b| *b > 0 && *b <= 1 << 30);
        require(bytes.is_some(), "invalid service archive size")?;
        require(
            package_url(
                &text("archive_url"),
                &format!("busbar-native-service-{name}"),
                &text("archive_sha256"),
                "linux-amd64.tar",
            ),
            "service package origin or identity differs",
        )?;
        result.push(ServiceRow {
            reference: text("reference"),
            archive_url: text("archive_url"),
            archive_sha256: text("archive_sha256"),
            bytes: bytes.unwrap(),
            manifest_sha256: text("manifest_sha256"),
            config_sha256: text("config_sha256"),
            name,
        });
    }
    Ok(result)
}

fn lower_name(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub fn verify_judge_record(owner: &str, row: &Value) -> Result<()> {
    require(
        lower_name(owner, 32)
            && row.has_keys(&[
                "archive_url",
                "archive_sha256",
                "portable_manifest_sha256",
                "bundles",
                "bytes",
                "expanded_bytes",
            ]),
        "invalid protected judge archive",
    )?;
    for key in ["archive_sha256", "portable_manifest_sha256"] {
        require(
            row.at(key).as_str().is_some_and(is_digest),
            "invalid protected judge digest",
        )?;
    }
    require(
        row.at("bytes")
            .as_u64()
            .is_some_and(|b| b > 0 && b <= 2 << 30)
            && row
                .at("expanded_bytes")
                .as_u64()
                .is_some_and(|b| b > 0 && b <= 4 << 30),
        "invalid protected judge size",
    )?;
    let bundles: Option<Vec<&str>> = row
        .at("bundles")
        .as_array()
        .map(|rows| rows.iter().map(Value::as_str).collect())
        .unwrap_or(None);
    require(
        bundles.is_some_and(|names| {
            !names.is_empty()
                && names.len() <= 32
                && names.iter().all(|n| lower_name(n, 64))
                && names
                    .iter()
                    .enumerate()
                    .all(|(i, n)| !names[..i].contains(n))
        }),
        "invalid protected judge bundle names",
    )?;
    require(
        package_url(
            row.at("archive_url").as_str().unwrap_or(""),
            &format!("busbar-native-conformance-{owner}"),
            row.at("archive_sha256").as_str().unwrap(),
            &format!("{owner}.tar.gz"),
        ),
        "judge package is outside its credential origin or immutable package identity",
    )
}

/// Owners whose judge inputs this job stages (validated, budgeted).
pub fn judge_selection(plan: &Value, repository: &str, job: &str) -> Result<Vec<String>> {
    require(
        plan.has_keys(&["schema", "owners", "repositories"])
            && plan.at("schema").as_str() == Some("busbar.native-judge-inputs/1")
            && plan.at("owners").as_object().is_some_and(|o| o.len() <= 16)
            && plan.at("repositories").is_object(),
        "invalid protected judge input plan",
    )?;
    if job == "external-conformance"
        || (repository == "GetBusbar/busbar" && job != "core-conformance")
    {
        return Ok(Vec::new());
    }
    let selected = plan
        .at("repositories")
        .get(repository)
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let owners: Option<Vec<&str>> = selected
        .as_array()
        .map(|rows| rows.iter().map(Value::as_str).collect())
        .unwrap_or(None);
    let owners = owners.unwrap_or_default();
    require(
        selected
            .as_array()
            .is_some_and(|rows| rows.len() == owners.len())
            && owners
                .iter()
                .enumerate()
                .all(|(i, o)| !owners[..i].contains(o))
            && owners.iter().all(|o| plan.at("owners").get(o).is_some()),
        "unapproved judge owner selection",
    )?;
    let mut total = 0;
    let mut seen: Vec<String> = Vec::new();
    for owner in &owners {
        let row = plan.at("owners").at(owner);
        verify_judge_record(owner, row)?;
        total += row.at("expanded_bytes").as_u64().unwrap();
        let bundles: Vec<String> = row
            .at("bundles")
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        require(
            !bundles.iter().any(|b| seen.contains(b)),
            "duplicate judge bundle name",
        )?;
        seen.extend(bundles);
    }
    require(
        total <= 4 << 30,
        "selected judge inputs exceed the aggregate byte budget",
    )?;
    Ok(owners.into_iter().map(str::to_owned).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn repo() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn published_judge_plan_selects_only_each_job_required_owners() {
        let plan = read_json(&repo().join("ci/native-judge-inputs.json")).unwrap();
        let select = |r: &str, j: &str| judge_selection(&plan, r, j).unwrap();
        assert_eq!(
            select("GetBusbar/busbar", "core-conformance"),
            ["core", "tls", "oidf", "release-engineering"]
        );
        assert!(select("GetBusbar/busbar", "native-qualification").is_empty());
        assert_eq!(
            select("GetBusbar/busbar-plane-mcp", "native-qualification"),
            ["mcp"]
        );
        assert!(select("GetBusbar/busbar-plane-llm", "external-conformance").is_empty());
        assert!(select("GetBusbar/busbar-plane-decisions", "native-qualification").is_empty());
        assert_eq!(
            select("GetBusbar/busbar-secret-c", "native-qualification"),
            ["python-schema"]
        );
        let row = plan.at("owners").at("mcp").clone();
        let url = row.at("archive_url").as_str().unwrap().to_owned();
        for bad in [
            url.replace("/projects/3/", "/projects/4/"),
            url.replace("git.getbusbar.dev", "other.invalid"),
            url.clone() + "?token=secret",
        ] {
            let mut changed = row.clone();
            changed.set("archive_url", bad.clone().into());
            assert!(verify_judge_record("mcp", &changed).is_err(), "{bad}");
        }
        let mut wrong = plan.clone();
        wrong.set("schema", "busbar.native-judge-inputs/2".into());
        assert!(
            judge_selection(&wrong, "GetBusbar/busbar-plane-mcp", "native-qualification").is_err()
        );
    }

    #[test]
    fn native_settings_follow_protected_policy() {
        let text = std::fs::read_to_string(repo().join("ci/architecture.toml")).unwrap();
        let policy = toml::parse(&text).unwrap();
        let services = |r: &str| {
            native_settings(r, &policy)
                .unwrap()
                .at("services")
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            services("GetBusbar/busbar"),
            [
                "postgres", "mysql", "valkey", "vault", "wiremock", "openldap"
            ]
        );
        assert_eq!(services("GetBusbar/busbar-auth-github"), ["wiremock"]);
        assert!(services("GetBusbar/busbar-auth-header").is_empty());
        assert!(services("GetBusbar/not-in-policy").is_empty());
        let bad = |native: &str| {
            let policy =
                toml::parse(&format!("[repositories.\"R/x\"]\nnative = {native}\n")).unwrap();
            native_settings("R/x", &policy)
        };
        assert!(bad("{ services = [\"valkey\"], server_binary = \"valkey\" }").is_ok());
        for native in [
            "{ unknown = 1 }",
            "{ services = [\"redis\"] }",
            "{ services = [\"vault\", \"vault\"] }",
            "{ server_binary = \"valkey\" }",
            "{ migration_fixture = \"sqlite-2\" }",
            "{ native_oracle = 1 }",
            "{ prepare_runtime = \"../escape.sh\" }",
            "{ external_conformance = \"testing/other/run.sh\" }",
        ] {
            assert!(bad(native).is_err(), "{native}");
        }
        assert!(native_settings("x", &json::parse(b"{}").unwrap()).is_err());
    }

    #[test]
    fn only_policy_services_are_selected_and_registry_origin_is_fixed() {
        let selected = service_selection(&repo(), "GetBusbar/busbar-store-valkey").unwrap();
        assert_eq!(
            selected.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["valkey"]
        );
        assert!(selected[0].reference.contains("@sha256:"));
        assert_eq!(
            service_selection(&repo(), "GetBusbar/busbar")
                .unwrap()
                .len(),
            6
        );
        let row = &selected[0];
        assert!(package_url(
            &row.archive_url,
            "busbar-native-service-valkey",
            &row.archive_sha256,
            "linux-amd64.tar"
        ));
        assert!(!package_url(
            &row.archive_url.replace("/projects/3/", "/projects/4/"),
            "busbar-native-service-valkey",
            &row.archive_sha256,
            "linux-amd64.tar"
        ));
        assert!(!package_url(
            &row.archive_url,
            "busbar-native-service-valkey",
            &"0".repeat(64),
            "linux-amd64.tar"
        ));
    }
}
