//! Immutable public inputs read from the canonical forge before admission
//! (former `native_sources`). Fetch credentials stay in the trusted collector;
//! Cargo receives only credential-free local Git URL mappings.
use super::sp::{self, R, Spec, at, value_error};
use super::{CORE, Q, fetch_environment, git, server_url};
use crate::json::Value;
use crate::sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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

/// Each forge fetch is latency-bound (several HTTP round trips, tiny packs).
/// Bounded concurrency keeps one job from monopolizing the forge.
pub const FETCH_WORKERS: usize = 8;
const FETCH_TIMEOUT: u64 = 300;

/// `subject_locks(candidate, host, sdk)`: the exact subject closures every
/// confined job's dependency seed covers (shared with `seed::lock_inputs`).
pub fn subject_locks<'a>(
    candidate: &'a Path,
    host: &'a Path,
    sdk: &'a Path,
) -> [(&'static str, &'a Path, &'static str); 4] {
    [
        ("candidate", candidate, "Cargo.lock"),
        ("host", host, "Cargo.lock"),
        ("distribution", host, "dist/default/Cargo.lock"),
        ("sdk", sdk, "Cargo.lock"),
    ]
}

fn plugin_job(repository: &str, policy: &Value) -> bool {
    repository != CORE
        && repository != "GetBusbar/busbar-release"
        && policy.at("repositories").get(repository).is_some()
}

/// `required_sources(q, host, vector)`: what this job's consumers read from
/// canonical-inputs. Plugin jobs build only their own workspace against the
/// seeded subject closures; core and release keep the full historical set.
fn required_sources(q: &mut Q, host: &Path, vector: &Value) -> R<Sources> {
    let sdk = q.sdk()?;
    // Core jobs read the same subject closures (dependency seed, Cargo's Git
    // mappings, the OIDF suite's shipped OIDC pin in the distribution lock)
    // plus every vector product commit. Neither reads the SDK checkout's own
    // distribution lock or core's HEAD from canonical-inputs: a lock cannot
    // name its own commit, and core's host is its checkout. The release job
    // keeps the full historical set below.
    let core_job = q.repository == CORE;
    if core_job || plugin_job(&q.repository, &q.policy) {
        let mut sources = Sources::new();
        for (_, root, relative) in subject_locks(&q.root, host, &sdk) {
            let lock = root.join(relative);
            if lock.is_file() {
                add(&mut sources, lock_inputs(&sp::read(&lock)?, &q.policy)?);
            }
        }
        sources
            .entry(CORE.to_owned())
            .or_default()
            .insert(sp::at_str(vector, "sdk")?.to_owned());
        if core_job {
            for product in at(vector, "products")?.as_array().unwrap_or(&[]) {
                sources
                    .entry(format!("GetBusbar/{}", sp::at_str(product, "repo")?))
                    .or_default()
                    .insert(sp::at_str(product, "commit")?.to_owned());
            }
        }
        return Ok(sources);
    }
    let mut sources = inputs(host, &q.root, &q.policy)?;
    for (repository, revisions) in inputs(&sdk, &q.root, &q.policy)? {
        sources.entry(repository).or_default().extend(revisions);
    }
    let core = sources.entry(CORE.to_owned()).or_default();
    core.insert(sp::at_str(vector, "sdk")?.to_owned());
    core.insert(git(host, &["rev-parse", "HEAD"])?);
    for product in at(vector, "products")?.as_array().unwrap_or(&[]) {
        sources
            .entry(format!("GetBusbar/{}", sp::at_str(product, "repo")?))
            .or_default()
            .insert(sp::at_str(product, "commit")?.to_owned());
    }
    Ok(sources)
}

/// `local_core_stores(q, host)`: controller-fetched core checkouts already
/// verified at an exact revision (plugin host and SDK under the work root).
/// A core job's host is its runner checkout and is never reused.
fn local_core_stores(work: &Path, roots: &[PathBuf]) -> R<BTreeMap<String, PathBuf>> {
    let work = sp::resolve(work);
    let mut stores = BTreeMap::new();
    for root in roots {
        let root = sp::resolve(root);
        let trusted = root.parent() == Some(work.as_path())
            && matches!(
                root.file_name().and_then(|n| n.to_str()),
                Some("host" | "sdk")
            );
        if trusted {
            stores
                .entry(git(&root, &["rev-parse", "HEAD"])?)
                .or_insert(root);
        }
    }
    Ok(stores)
}

struct Fetcher<'a> {
    parent: &'a Path,
    server: &'a str,
    env: &'a [(String, String)],
    local: &'a BTreeMap<String, PathBuf>,
}

impl Fetcher<'_> {
    /// One shallow fetch per source carries every exact revision; each is then
    /// verified by exact `rev-parse`.
    fn one(&self, repository: &str, revisions: &[String]) -> R<()> {
        let cache = self
            .parent
            .join(repository.rsplit('/').next().unwrap_or(repository));
        if !cache.exists() {
            sp::check_call(Spec::new(sp::strings(&[
                "git",
                "init",
                "--bare",
                "--quiet",
                &sp::text(&cache),
            ])))?;
        }
        let mut remotes: BTreeMap<String, Vec<&String>> = BTreeMap::new();
        for revision in revisions {
            let remote = match self.local.get(revision) {
                Some(store) if repository == CORE => sp::text(store),
                _ => format!("{}/{repository}.git", self.server),
            };
            remotes.entry(remote).or_default().push(revision);
        }
        for (remote, wanted) in &remotes {
            let mut argv = sp::strings(&[
                "git",
                "-C",
                &sp::text(&cache),
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth",
                "1",
                remote,
            ]);
            argv.extend(wanted.iter().map(|r| format!("{r}:refs/heads/input-{r}")));
            sp::check_call(Spec::new(argv).env(self.env).timeout(FETCH_TIMEOUT))?;
        }
        for revision in revisions {
            if git(
                &cache,
                &["rev-parse", &format!("refs/heads/input-{revision}")],
            )? != *revision
            {
                return Err(value_error("canonical input revision mismatch"));
            }
        }
        Ok(())
    }

    /// Fetch every not-yet-fetched revision; independent repositories run
    /// concurrently with at most `workers` in flight.
    fn all(&self, selected: &Sources, fetched: &mut Sources, workers: usize) -> R<()> {
        let mut pending: Vec<(String, Vec<String>)> = Vec::new();
        for (repository, revisions) in selected {
            if revisions.iter().any(|r| !hex40(r)) {
                return Err(value_error("immutable source revision required"));
            }
            let done = fetched.get(repository);
            let missing: Vec<String> = revisions
                .iter()
                .filter(|r| done.is_none_or(|d| !d.contains(*r)))
                .cloned()
                .collect();
            if !missing.is_empty() {
                pending.push((repository.clone(), missing));
            }
        }
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: Vec<R<()>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers.clamp(1, pending.len().max(1)))
                .map(|_| {
                    scope.spawn(|| -> R<()> {
                        loop {
                            let index = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let Some((repository, revisions)) = pending.get(index) else {
                                return Ok(());
                            };
                            self.one(repository, revisions)?;
                        }
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err(sp::runtime("canonical input fetch panicked")))
                })
                .collect()
        });
        for result in results {
            result?;
        }
        for (repository, revisions) in pending {
            fetched.entry(repository).or_default().extend(revisions);
        }
        Ok(())
    }
}

pub fn prepare(q: &mut Q, host: &Path) -> R<()> {
    let vector = sp::read_json(&host.join("scripts/ci-product-pins.json"))?;
    let mut sources = required_sources(q, host, &vector)?;
    // All listed products are public; private candidates never enter a public map.
    let allowed = public_repositories(&q.policy);
    let mut listed = Vec::new();
    for product in at(&vector, "products")?.as_array().unwrap_or(&[]) {
        listed.push(format!("GetBusbar/{}", sp::at_str(product, "repo")?));
    }
    if sources
        .keys()
        .chain(listed.iter())
        .any(|name| !allowed.contains(name))
    {
        return Err(value_error(
            "unclassified or private repository in public product inputs",
        ));
    }
    let parent = q.work.join("canonical-inputs");
    sp::mkdir(&parent, 0o777, false)?;
    let env = fetch_environment()?.pairs();
    let server = server_url()?;
    let sdk = q.sdk()?;
    let local = local_core_stores(&q.work, &[host.to_owned(), sdk])?;
    let fetcher = Fetcher {
        parent: &parent,
        server: &server,
        env: &env,
        local: &local,
    };
    let mut fetched = Sources::new();
    fetcher.all(&sources, &mut fetched, FETCH_WORKERS)?;
    let standalone = standalone_products(&q.repository, q.evaluation_only, &vector)?;
    let mut discovered = Sources::new();
    add(
        &mut discovered,
        product_inputs(&parent, &standalone, &q.policy)?,
    );
    for (repository, revisions) in &discovered {
        sources
            .entry(repository.clone())
            .or_default()
            .extend(revisions.iter().cloned());
    }
    fetcher.all(&discovered, &mut fetched, FETCH_WORKERS)?;
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

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        let path = sp::resolve(&std::env::temp_dir().join(format!(
            "native-sources-{}-{}",
            std::process::id(),
            crate::pathx::uuid4()
        )));
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    /// A non-bare repository with one commit per message; returns the SHAs.
    fn repository(path: &Path, messages: &[&str]) -> Vec<String> {
        std::fs::create_dir_all(path).unwrap();
        let run = |args: &[&str]| {
            let mut argv = sp::strings(&[
                "git",
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                &sp::text(path),
            ]);
            argv.extend(args.iter().map(|a| (*a).to_owned()));
            sp::check_call(Spec::new(argv).quiet()).unwrap();
        };
        run(&["init", "-q"]);
        run(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
        messages
            .iter()
            .map(|message| {
                std::fs::write(path.join("file"), message).unwrap();
                run(&["add", "file"]);
                run(&["commit", "-q", "-m", message]);
                git(path, &["rev-parse", "HEAD"]).unwrap()
            })
            .collect()
    }

    #[test]
    fn plugin_jobs_use_exactly_the_seeded_subject_locks() {
        let policy =
            crate::json::parse(br#"{"repositories": {"GetBusbar/busbar-x": {"private": false}}}"#)
                .unwrap();
        assert!(plugin_job("GetBusbar/busbar-x", &policy));
        for owner in [CORE, "GetBusbar/busbar-release", "GetBusbar/unclassified"] {
            assert!(!plugin_job(owner, &policy));
        }
        let (c, h, s) = (Path::new("/c"), Path::new("/h"), Path::new("/s"));
        let locks: Vec<_> = subject_locks(c, h, s)
            .iter()
            .map(|(label, root, relative)| (*label, root.join(relative)))
            .collect();
        assert_eq!(
            locks,
            vec![
                ("candidate", c.join("Cargo.lock")),
                ("host", h.join("Cargo.lock")),
                ("distribution", h.join("dist/default/Cargo.lock")),
                ("sdk", s.join("Cargo.lock")),
            ]
        );
    }

    #[test]
    fn grouped_concurrent_fetches_verify_every_exact_revision() {
        let root = scratch();
        let forge = root.0.join("forge");
        let a = repository(&forge.join("GetBusbar/busbar-a.git"), &["a1", "a2"]);
        let b = repository(&forge.join("GetBusbar/busbar-b.git"), &["b1"]);
        // Only the trusted SDK checkout holds the core revision; the forge has
        // no core repository, so success proves the local controller source.
        let work = root.0.join("work");
        let sdk = repository(&work.join("sdk"), &["sdk"]);
        let runner = root.0.join("runner");
        repository(&runner, &["runner"]);
        let local = local_core_stores(&work, &[runner.clone(), work.join("sdk")]).unwrap();
        assert_eq!(local.keys().cloned().collect::<Vec<_>>(), sdk);
        let parent = work.join("canonical-inputs");
        std::fs::create_dir_all(&parent).unwrap();
        let server = sp::text(&forge);
        let fetcher = Fetcher {
            parent: &parent,
            server: &server,
            env: &[],
            local: &local,
        };
        let mut wanted = Sources::new();
        wanted.insert("GetBusbar/busbar-a".into(), a.iter().cloned().collect());
        wanted.insert("GetBusbar/busbar-b".into(), b.iter().cloned().collect());
        wanted.insert(CORE.into(), sdk.iter().cloned().collect());
        let mut fetched = Sources::new();
        fetcher.all(&wanted, &mut fetched, 2).unwrap();
        assert_eq!(fetched, wanted);
        for (name, revisions) in &wanted {
            let cache = parent.join(name.rsplit('/').next().unwrap());
            for revision in revisions {
                assert_eq!(
                    git(
                        &cache,
                        &["rev-parse", &format!("refs/heads/input-{revision}")]
                    )
                    .unwrap(),
                    *revision
                );
            }
        }
        // Already fetched revisions are not fetched again; unknown ones fail.
        fetcher.all(&wanted, &mut fetched, 2).unwrap();
        let mut missing = Sources::new();
        missing.insert(
            "GetBusbar/busbar-b".into(),
            BTreeSet::from(["0".repeat(40)]),
        );
        assert!(fetcher.all(&missing, &mut fetched, 2).is_err());
        let mut mutable = Sources::new();
        mutable.insert(
            "GetBusbar/busbar-b".into(),
            BTreeSet::from(["dev".to_owned()]),
        );
        assert_eq!(
            fetcher.all(&mutable, &mut fetched, 2).unwrap_err().message,
            "immutable source revision required"
        );
    }
}
