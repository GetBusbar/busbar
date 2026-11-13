//! The resolved shipping graph: every first-party node is classified and every
//! normal/build edge (also through external crates) must be allowed.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use serde_json::Value as Json;

use crate::policy::{self, Entry, Policy};
use crate::py;
use crate::refuse::{Result, Rule, Violation};

/// `(hostname, owner/repository)` of a `git+` source; `None` for other sources.
pub type Identity = (Option<String>, String);

/// `urllib.parse.urlsplit` of `source[4:]`, as `git_repository` uses it.
pub fn git_repository(source: Option<&str>) -> Option<Identity> {
    let source = source?;
    let rest = source.strip_prefix("git+")?;
    let (hostname, path) = split_url(rest);
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    Some((hostname, path.to_string()))
}

/// Hostname (lowercased, without userinfo or port) and path of a URL.
pub fn split_url(url: &str) -> (Option<String>, String) {
    let url = url.trim_matches(|c: char| c <= ' ');
    let mut rest = url;
    // scheme
    if let Some(colon) = rest.find(':') {
        let scheme = &rest[..colon];
        if !scheme.is_empty()
            && scheme
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
    let mut hostname = None;
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let netloc = &after[..end];
        rest = &after[end..];
        let host = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
        let host = if let Some(stripped) = host.strip_prefix('[') {
            stripped.split(']').next().unwrap_or("")
        } else {
            host.split(':').next().unwrap_or("")
        };
        if !host.is_empty() {
            hostname = Some(host.to_ascii_lowercase());
        }
    }
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    (hostname, rest[..end].to_string())
}

pub fn ci_server_host() -> Option<String> {
    std::env::var("CI_SERVER_HOST").ok()
}

fn first_party_owner(identity: &Option<Identity>) -> bool {
    identity.as_ref().is_some_and(|(_, path)| {
        let owner = path.split('/').next().unwrap_or("");
        owner == "GetBusbar" || owner == "BusbarInc"
    })
}

/// `Policy.classify`.
pub fn classify<'p>(
    policy: &'p Policy,
    package: &Json,
    repository: &str,
    checkout: &Path,
) -> Result<Option<&'p Entry>> {
    let name = package["name"].as_str().unwrap_or("");
    let source = package.get("source").and_then(Json::as_str);
    let identity = git_repository(source);
    let Some(entry) = policy.get(name) else {
        let external = identity.as_ref().is_some_and(|id| {
            policy
                .external_sources()
                .iter()
                .any(|(n, r)| n == name && *id == (Some("github.com".into()), r.clone()))
        });
        if external {
            return Ok(None);
        }
        if name.starts_with("busbar-") || first_party_owner(&identity) {
            return Err(Violation::new(
                Rule::UnclassifiedFirstParty,
                format!(
                    "unclassified first-party package: {name} ({})",
                    source.unwrap_or("None")
                ),
            ));
        }
        return Ok(None);
    };
    let entry_repository = policy::repository(entry);
    if let Some(source) = source.filter(|s| !s.is_empty()) {
        let canonical = ci_server_host();
        let expected = if entry_repository.starts_with("BusbarInc/") {
            canonical.clone()
        } else {
            Some("github.com".to_string())
        };
        let want = Some((expected, entry_repository.to_string()));
        let forge = Some((canonical, entry_repository.to_string()));
        if identity != want && identity != forge {
            return Err(Violation::new(
                Rule::NoncanonicalSource,
                format!("noncanonical source for {name}: {source}"),
            ));
        }
    } else {
        let actual = py::resolve(Path::new(package["manifest_path"].as_str().unwrap_or("")));
        let expected = py::resolve(&py::join(checkout, policy::manifest(entry)?));
        if !(entry_repository == repository && actual == expected) {
            return Err(Violation::new(
                Rule::PathSubstitution,
                format!(
                    "unapproved path/source substitution for {name}: {}",
                    actual.display()
                ),
            ));
        }
    }
    Ok(Some(entry))
}

fn shipping_deps(node: &Json) -> Vec<String> {
    node["deps"]
        .as_array()
        .map(|deps| {
            deps.iter()
                .filter(|e| {
                    e["dep_kinds"].as_array().is_some_and(|kinds| {
                        kinds
                            .iter()
                            .any(|d| d.get("kind").and_then(Json::as_str) != Some("dev"))
                    })
                })
                .filter_map(|e| e["pkg"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GraphReceipt {
    pub packages: usize,
    pub classified: usize,
}

/// `check_graph`.
pub fn check_graph(
    metadata: &Json,
    policy: &Policy,
    repository: &str,
    checkout: &Path,
) -> Result<GraphReceipt> {
    let resolve = metadata.get("resolve").filter(|r| match r {
        Json::Null => false,
        Json::Object(o) => !o.is_empty(),
        _ => true,
    });
    let Some(resolve) = resolve else {
        return Err(Violation::new(
            Rule::MissingResolve,
            "resolved cargo metadata is required; --no-deps is not evidence",
        ));
    };
    let empty = Vec::new();
    let package_rows = metadata["packages"].as_array().unwrap_or(&empty);
    // Ordered like the Python dict (last duplicate id wins, first position kept).
    let mut order: Vec<String> = Vec::new();
    let mut packages: HashMap<String, &Json> = HashMap::new();
    for p in package_rows {
        let id = p["id"].as_str().unwrap_or("").to_string();
        if packages.insert(id.clone(), p).is_none() {
            order.push(id);
        }
    }
    let mut nodes: HashMap<String, &Json> = HashMap::new();
    for n in resolve["nodes"].as_array().unwrap_or(&empty) {
        nodes.insert(n["id"].as_str().unwrap_or("").to_string(), n);
    }
    let mut roles: HashMap<String, Option<&Entry>> = HashMap::new();
    for key in &order {
        roles.insert(
            key.clone(),
            classify(policy, packages[key], repository, checkout)?,
        );
    }
    let forbidden: HashSet<String> = policy.forbidden()?.into_iter().collect();
    let missing_node = |key: &str| {
        Violation::new(
            Rule::Parse,
            format!("cargo metadata has no resolve node for {key}"),
        )
    };
    for key in &order {
        let Some(entry) = roles[key] else { continue };
        let package = packages[key];
        let name = package["name"].as_str().unwrap_or("");
        if policy::role(entry) == "test_host" {
            return Err(Violation::new(
                Rule::TestHostShipping,
                format!("test host entered shipping graph: {name}"),
            ));
        }
        let features: Vec<String> = nodes
            .get(key)
            .and_then(|n| n.get("features"))
            .and_then(Json::as_array)
            .map(|f| {
                f.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let enabled: BTreeSet<String> = features
            .into_iter()
            .filter(|f| forbidden.contains(f))
            .collect();
        if !enabled.is_empty() {
            let enabled: Vec<String> = enabled.into_iter().collect();
            return Err(Violation::new(
                Rule::ShippingFeature,
                format!("shipping feature on {name}: {}", py::repr_list(&enabled)),
            ));
        }
        let allows = policy::allows(entry)?;
        let node = nodes.get(key).ok_or_else(|| missing_node(key))?;
        let mut pending = shipping_deps(node);
        let mut seen = HashSet::new();
        while let Some(target) = pending.pop() {
            if !seen.insert(target.clone()) {
                continue;
            }
            let target_entry = roles.get(&target).ok_or_else(|| missing_node(&target))?;
            if target_entry.is_some() {
                let target_name = packages[&target]["name"].as_str().unwrap_or("");
                if !allows.iter().any(|a| a == target_name) {
                    return Err(Violation::new(
                        Rule::ForbiddenEdge,
                        format!("forbidden production/build edge: {name} -> {target_name}"),
                    ));
                }
                continue;
            }
            let target_node = nodes.get(&target).ok_or_else(|| missing_node(&target))?;
            pending.extend(shipping_deps(target_node));
        }
    }
    let mut core_sources = BTreeSet::new();
    for p in packages.values() {
        let name = p["name"].as_str().unwrap_or("");
        if let Some(source) = p.get("source").and_then(Json::as_str) {
            if policy.is_core(name) && !source.is_empty() {
                core_sources.insert(source.to_string());
            }
        }
    }
    if core_sources.len() > 1 {
        let sources: Vec<String> = core_sources.into_iter().collect();
        return Err(Violation::new(
            Rule::SdkSourceMismatch,
            format!("SDK source/revision mismatch: {}", py::repr_list(&sources)),
        ));
    }
    Ok(GraphReceipt {
        packages: packages.len(),
        classified: roles.values().filter(|e| e.is_some()).count(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_policy;
    use serde_json::json;

    const ROOT: &str = "/candidate";

    fn fixture() -> Json {
        let sdk = format!(
            "git+https://github.com/GetBusbar/busbar?rev={}#{}",
            "a".repeat(40),
            "a".repeat(40)
        );
        let rows = [
            (
                "impl",
                "busbar-auth-alpha",
                None,
                "/candidate/auth-alpha/Cargo.toml",
            ),
            (
                "wrapper",
                "busbar-auth-alpha-plugin",
                None,
                "/candidate/auth-alpha-plugin/Cargo.toml",
            ),
            ("sdk", "busbar-contract", Some(sdk), "/cargo/sdk/Cargo.toml"),
            (
                "lib",
                "ordinary-library",
                Some("registry+https://github.com/rust-lang/crates.io-index".to_string()),
                "/cargo/lib/Cargo.toml",
            ),
        ];
        let packages: Vec<Json> = rows
            .iter()
            .map(|(i, n, s, p)| json!({"id": i, "name": n, "source": s, "manifest_path": p}))
            .collect();
        let nodes: Vec<Json> = rows
            .iter()
            .map(|(i, ..)| json!({"id": i, "features": [], "deps": []}))
            .collect();
        json!({"packages": packages, "resolve": {"nodes": nodes}})
    }

    fn edge(
        m: &mut Json,
        start: &str,
        target: &str,
        name: &str,
        kind: Option<&str>,
        cfg: Option<&str>,
    ) {
        let nodes = m["resolve"]["nodes"].as_array_mut().unwrap();
        let node = nodes.iter_mut().find(|n| n["id"] == start).unwrap();
        node["deps"].as_array_mut().unwrap().push(
            json!({"name": name, "pkg": target, "dep_kinds": [{"kind": kind, "target": cfg}]}),
        );
    }

    fn sibling(m: &mut Json) {
        let source = format!(
            "git+https://github.com/GetBusbar/busbar-store-beta?rev={}#{}",
            "b".repeat(40),
            "b".repeat(40)
        );
        m["packages"].as_array_mut().unwrap().push(json!({"id": "other", "name": "busbar-store-beta", "source": source, "manifest_path": "/cargo/beta/Cargo.toml"}));
        m["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "other", "features": [], "deps": []}));
    }

    fn check(m: &Json) -> Result<GraphReceipt> {
        check_graph(
            m,
            &test_policy(),
            "GetBusbar/busbar-auth-alpha",
            Path::new(ROOT),
        )
    }

    #[test]
    fn own_wrapper_sdk_and_external_library_are_permitted() {
        let mut m = fixture();
        edge(&mut m, "wrapper", "impl", "renamed", None, None);
        edge(&mut m, "impl", "sdk", "renamed", None, None);
        edge(&mut m, "impl", "lib", "renamed", None, None);
        assert_eq!(check(&m).unwrap().classified, 3);
    }

    #[test]
    fn renamed_transitive_sibling_is_rejected() {
        let mut m = fixture();
        sibling(&mut m);
        edge(&mut m, "impl", "lib", "renamed", None, None);
        edge(&mut m, "lib", "other", "ordinary_helper", None, None);
        let e = check(&m).unwrap_err();
        assert!(e.message.contains("forbidden production/build edge"), "{e}");
    }

    #[test]
    fn build_and_foreign_target_are_not_hidden() {
        for (kind, cfg) in [(Some("build"), None), (None, Some("cfg(windows)"))] {
            let mut m = fixture();
            sibling(&mut m);
            edge(&mut m, "impl", "other", "renamed", kind, cfg);
            assert_eq!(check(&m).unwrap_err().rule, Rule::ForbiddenEdge);
        }
    }

    #[test]
    fn dev_only_real_core_harness_does_not_enter_shipping_graph() {
        let mut m = fixture();
        sibling(&mut m);
        edge(&mut m, "impl", "other", "renamed", Some("dev"), None);
        check(&m).unwrap();
    }

    #[test]
    fn transitive_shipping_authority_feature_is_rejected() {
        let mut m = fixture();
        edge(&mut m, "impl", "lib", "renamed", None, None);
        edge(&mut m, "lib", "sdk", "renamed", None, None);
        m["resolve"]["nodes"][2]["features"] = json!(["test-seal"]);
        let e = check(&m).unwrap_err();
        assert_eq!(
            e.message,
            "shipping feature on busbar-contract: ['test-seal']"
        );
    }

    #[test]
    fn relabelled_first_party_source_and_registry_substitution_are_rejected() {
        for (name, source) in [
            (
                "neutral",
                "git+https://github.com/GetBusbar/unclassified#abc",
            ),
            (
                "busbar-contract",
                "registry+https://github.com/rust-lang/crates.io-index",
            ),
        ] {
            let mut m = fixture();
            m["packages"][2]["name"] = json!(name);
            m["packages"][2]["source"] = json!(source);
            check(&m).unwrap_err();
        }
    }

    #[test]
    fn wrong_checkout_cannot_impersonate_own_implementation() {
        let mut m = fixture();
        m["packages"][0]["manifest_path"] = json!("/other/auth-alpha/Cargo.toml");
        let e = check(&m).unwrap_err();
        assert!(e.message.contains("substitution"));
    }

    #[test]
    fn missing_resolve_is_not_evidence() {
        let mut m = fixture();
        m["resolve"] = Json::Null;
        assert_eq!(check(&m).unwrap_err().rule, Rule::MissingResolve);
    }

    #[test]
    fn url_identity_matches_urlsplit() {
        assert_eq!(
            git_repository(Some("git+https://github.com/GetBusbar/busbar.git?rev=a#b")),
            Some((Some("github.com".into()), "GetBusbar/busbar".into()))
        );
        assert_eq!(
            git_repository(Some("git+https://user@Git.Example:8443/BusbarInc/x/")),
            Some((Some("git.example".into()), "BusbarInc/x".into()))
        );
        assert_eq!(git_repository(Some("registry+https://x")), None);
    }
}
