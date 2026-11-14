//! Immutable public inputs read from the canonical forge before admission
//! (former `native_sources`). Fetch credentials stay in the trusted collector;
//! Cargo receives only credential-free local Git URL mappings.
use super::sp::{self, R, Spec, at, value_error};
use super::{CORE, Q, fetch_environment, git, server_url};
use crate::json::Value;
use crate::sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub type Sources = BTreeMap<String, BTreeSet<String>>;

/// `standalone_products(repository, evaluation_only, vector)`.
pub fn standalone_products(
    repository: &str,
    evaluation_only: bool,
    vector: &Value,
) -> R<Vec<Value>> {
    let products = at(vector, "products")?.as_array().unwrap_or(&[]).to_vec();
    if repository == CORE && !evaluation_only {
        return Ok(products);
    }
    if repository == CORE || repository == "GetBusbar/busbar-release" {
        let selected: Vec<Value> = products
            .into_iter()
            .filter(|row| row.at("repo").as_str() == Some("busbar-auth-oidc"))
            .collect();
        if selected.len() != 1 {
            return Err(value_error(
                "required OIDC SDK consumer graph is absent or ambiguous",
            ));
        }
        return Ok(selected);
    }
    Ok(Vec::new())
}

fn hex40(text: &str) -> bool {
    crate::product::is_revision(text)
}

/// `SOURCE.fullmatch(source)`: (repository, rev, fragment).
fn first_party(source: &str) -> Option<(String, String, String)> {
    let rest = source.strip_prefix("git+https://github.com/")?;
    let (name, query) = rest.split_once("?rev=")?;
    let segment = name.strip_prefix("GetBusbar/")?;
    if segment.is_empty() || segment.contains(['/', '?', '#']) {
        return None;
    }
    let repository = match segment.strip_suffix(".git") {
        Some(stripped) if !stripped.is_empty() => format!("GetBusbar/{stripped}"),
        _ => format!("GetBusbar/{segment}"),
    };
    let (rev, fragment) = query.split_once('#')?;
    (hex40(rev) && hex40(fragment)).then(|| (repository, rev.to_owned(), fragment.to_owned()))
}

pub fn public_repositories(policy: &Value) -> BTreeSet<String> {
    let mut allowed: BTreeSet<String> = policy
        .at("repositories")
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, row)| !row.at("private").truthy())
        .map(|(name, _)| name.clone())
        .collect();
    allowed.insert(CORE.to_owned());
    allowed
}

/// `lock_inputs(text, policy)`: exact first-party commits in one lockfile.
pub fn lock_inputs(text: &[u8], policy: &Value) -> R<Vec<(String, String)>> {
    let allowed = public_repositories(policy);
    let lock = crate::product::toml(text)?;
    let mut rows: Vec<&Value> = lock
        .at("package")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .collect();
    rows.extend(lock.at("patch").at("unused").as_array().unwrap_or(&[]));
    let mut out = Vec::new();
    for package in rows {
        let source = package.at("source").as_str().unwrap_or("");
        if !source.starts_with("git+https://github.com/GetBusbar/") {
            continue;
        }
        match first_party(source) {
            Some((repository, rev, fragment)) if rev == fragment => {
                if allowed.contains(&repository) {
                    out.push((repository, rev));
                }
            }
            _ => {
                return Err(value_error(
                    "first-party source must be an exact immutable Git commit",
                ));
            }
        }
    }
    Ok(out)
}

fn add(sources: &mut Sources, rows: Vec<(String, String)>) {
    for (repository, revision) in rows {
        sources.entry(repository).or_default().insert(revision);
    }
}

/// `inputs(host, candidate, policy)`.
pub fn inputs(host: &Path, candidate: &Path, policy: &Value) -> R<Sources> {
    let mut sources = Sources::new();
    for (root, relative) in [
        (host, "Cargo.lock"),
        (host, "dist/default/Cargo.lock"),
        (candidate, "Cargo.lock"),
    ] {
        let lock = root.join(relative);
        if lock.is_file() {
            add(&mut sources, lock_inputs(&sp::read(&lock)?, policy)?);
        }
    }
    Ok(sources)
}

/// `product_inputs(parent, vector, policy)`: standalone products' own locks.
pub fn product_inputs(
    parent: &Path,
    products: &[Value],
    policy: &Value,
) -> R<Vec<(String, String)>> {
    let mut out = Vec::new();
    for product in products {
        let commit = sp::at_str(product, "commit")?;
        let data = sp::check_output(Spec::new(sp::strings(&[
            "git",
            "-C",
            &sp::text(&parent.join(sp::at_str(product, "repo")?)),
            "show",
            &format!("{commit}:Cargo.lock"),
        ])))?;
        if sha256::hex(&data) != sp::at_str(product, "lock_sha256")? {
            return Err(value_error(
                "standalone product lock differs from assembled vector",
            ));
        }
        out.extend(lock_inputs(&data, policy)?);
    }
    Ok(out)
}

pub fn prepare(q: &mut Q, host: &Path) -> R<()> {
    let mut sources = inputs(host, &q.root, &q.policy)?;
    let sdk = q.sdk()?;
    for (repository, revisions) in inputs(&sdk, &q.root, &q.policy)? {
        sources.entry(repository).or_default().extend(revisions);
    }
    let vector = sp::read_json(&host.join("scripts/ci-product-pins.json"))?;
    let core = sources.entry(CORE.to_owned()).or_default();
    core.insert(sp::at_str(&vector, "sdk")?.to_owned());
    core.insert(git(host, &["rev-parse", "HEAD"])?);
    for product in at(&vector, "products")?.as_array().unwrap_or(&[]) {
        sources
            .entry(format!("GetBusbar/{}", sp::at_str(product, "repo")?))
            .or_default()
            .insert(sp::at_str(product, "commit")?.to_owned());
    }
    // All listed products are public; private candidates never enter a public map.
    let allowed = public_repositories(&q.policy);
    if sources.keys().any(|name| !allowed.contains(name)) {
        return Err(value_error(
            "unclassified or private repository in public product inputs",
        ));
    }
    let parent = q.work.join("canonical-inputs");
    sp::mkdir(&parent, 0o777, false)?;
    let env = fetch_environment()?.pairs();
    let server = server_url()?;
    let mut fetched: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut fetch = |repository: &str, revisions: &BTreeSet<String>| -> R<()> {
        if revisions.iter().any(|r| !hex40(r)) {
            return Err(value_error("immutable source revision required"));
        }
        let cache = parent.join(repository.rsplit('/').next().unwrap_or(repository));
        if !cache.exists() {
            sp::check_call(Spec::new(sp::strings(&[
                "git",
                "init",
                "--bare",
                "--quiet",
                &sp::text(&cache),
            ])))?;
        }
        let done = fetched.entry(repository.to_owned()).or_default();
        for revision in revisions
            .iter()
            .filter(|r| !done.contains(*r))
            .cloned()
            .collect::<Vec<_>>()
        {
            sp::check_call(
                Spec::new(sp::strings(&[
                    "git",
                    "-C",
                    &sp::text(&cache),
                    "fetch",
                    "--quiet",
                    "--depth",
                    "1",
                    &format!("{server}/{repository}.git"),
                    &format!("{revision}:refs/heads/input-{revision}"),
                ]))
                .env(&env),
            )?;
            if git(
                &cache,
                &["rev-parse", &format!("refs/heads/input-{revision}")],
            )? != revision
            {
                return Err(value_error("canonical input revision mismatch"));
            }
            done.insert(revision);
        }
        Ok(())
    };
    for (repository, revisions) in &sources {
        fetch(repository, revisions)?;
    }
    let standalone = standalone_products(&q.repository, q.evaluation_only, &vector)?;
    let mut discovered: Vec<(String, BTreeSet<String>)> = Vec::new();
    for (repository, revision) in product_inputs(&parent, &standalone, &q.policy)? {
        match discovered.iter_mut().find(|(r, _)| *r == repository) {
            Some((_, revisions)) => {
                revisions.insert(revision);
            }
            None => discovered.push((repository, BTreeSet::from([revision]))),
        }
    }
    for (repository, revisions) in discovered {
        sources
            .entry(repository.clone())
            .or_default()
            .extend(revisions.iter().cloned());
        fetch(&repository, &revisions)?;
    }
    let mut settings = Vec::new();
    for repository in sources.keys() {
        let cache = parent.join(repository.rsplit('/').next().unwrap_or(repository));
        for suffix in ["", ".git"] {
            settings.push((
                format!("url.{}.insteadOf", sp::as_uri(&cache)),
                format!("https://github.com/{repository}{suffix}"),
            ));
        }
    }
    q.env.set("GIT_CONFIG_GLOBAL", "/dev/null");
    q.env.set("GIT_CONFIG_NOSYSTEM", "1");
    q.env.set("GIT_CONFIG_COUNT", settings.len().to_string());
    for (index, (key, value)) in settings.into_iter().enumerate() {
        q.env.set(&format!("GIT_CONFIG_KEY_{index}"), key);
        q.env.set(&format!("GIT_CONFIG_VALUE_{index}"), value);
    }
    q.receipt.set(
        "canonical_inputs",
        Value::Object(
            sources
                .iter()
                .map(|(name, revisions)| {
                    (
                        name.clone(),
                        Value::Array(revisions.iter().map(|r| r.as_str().into()).collect()),
                    )
                })
                .collect(),
        ),
    );
    q.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Value {
        crate::json::parse(br#"{"repositories": {"GetBusbar/busbar-auth-oidc": {"private": false}, "GetBusbar/secret": {"private": true}}}"#).unwrap()
    }

    #[test]
    fn first_party_sources_must_be_exact_public_commits() {
        let a = "a".repeat(40);
        let lock = format!(
            "version = 4\n[[package]]\nname = \"busbar-auth-oidc\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/GetBusbar/busbar-auth-oidc.git?rev={a}#{a}\"\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/GetBusbar/secret?rev={a}#{a}\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        );
        assert_eq!(
            lock_inputs(lock.as_bytes(), &policy()).unwrap(),
            vec![("GetBusbar/busbar-auth-oidc".to_owned(), a.clone())]
        );
        let moving = lock.replacen(&format!("#{a}"), &format!("#{}", "b".repeat(40)), 1);
        assert_eq!(
            lock_inputs(moving.as_bytes(), &policy())
                .unwrap_err()
                .message,
            "first-party source must be an exact immutable Git commit"
        );
        let branch = "[[package]]\nname = \"y\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/GetBusbar/y?branch=dev#abc\"\n";
        assert!(lock_inputs(branch.as_bytes(), &policy()).is_err());
    }

    #[test]
    fn standalone_selection_follows_the_caller() {
        let vector = crate::json::parse(
            br#"{"products": [{"repo": "busbar-auth-oidc"}, {"repo": "busbar-x"}]}"#,
        )
        .unwrap();
        assert_eq!(standalone_products(CORE, false, &vector).unwrap().len(), 2);
        assert_eq!(standalone_products(CORE, true, &vector).unwrap().len(), 1);
        assert_eq!(
            standalone_products("GetBusbar/busbar-release", false, &vector)
                .unwrap()
                .len(),
            1
        );
        assert!(
            standalone_products("GetBusbar/busbar-x", false, &vector)
                .unwrap()
                .is_empty()
        );
    }
}
