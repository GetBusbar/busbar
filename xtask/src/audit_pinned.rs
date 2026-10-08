//! PINNED PLUGIN SCOPES — an extracted plugin keeps its scope in THIS ledger, read from the pinned
//! checkout.
//!
//! A plugin that leaves this tree for its own repo (`GetBusbar/busbar-<kind>-<name>`) comes back as a
//! `git+` package in `Cargo.lock`, pinned at one commit. The coordinator's ruling: the extraction
//! MOVES the scope's record, it does not strike it. `filter-repo` keeps file contents, so the
//! crate's blobs — and therefore its scope's tree hash — are unchanged, and the audit carries over;
//! a pin moved to different content reads `stale`, as any moved tree does.
//!
//! HOW: the file listing the ledger hashes over at a busbar commit `R` is the tracked files at `R`
//! PLUS, for every pinned plugin package `P` of `R`'s default distribution that has no
//! `crates/<P>` in `R`'s tree, a VIRTUAL entry `crates/<P>/<rel>` -> blob oid for every file `<rel>`
//! of `P`'s crate directory in the plugin repo at the pinned commit. Scope ids and paths do not
//! change, and the blob oid of a byte-identical file is the same oid in any repository, so a scope
//! over byte-identical code hashes identically whichever repository holds it.
//!
//! WHICH PACKAGES ([`pins_for`]): a `git+` package of `R`'s `Cargo.lock` whose name resolves to one
//! of the seven plugin kinds (the kind-isolation table, [`crate::gates::kind_isolation::plugin_kind`]),
//! that is not the `-plugin` cdylib twin, and that the DEFAULT DISTRIBUTION compiles in
//! ([`default_distribution`]). A plugin only a test links is out of this ledger.
//!
//! WHERE THE BYTES COME FROM ([`PinStore`]): cargo's own git database (`$CARGO_HOME/git/db/*`,
//! bare repositories cargo fills when it resolves the workspace — every `cargo xtask` run has
//! already done that for the pins at HEAD), else ONE shallow fetch of the pinned commit into a cache
//! bare repo under `target/ledger-pins/`. A pin neither can produce is an ERROR naming the package
//! and the commit: the ledger fails closed, it never skips a pin it cannot read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The suffix of a plugin repo's cdylib twin (`busbar-transport-tcp-plugin`). The twin packages the
/// logic crate; the logic crate is the scope.
pub const CDYLIB_SUFFIX: &str = "-plugin";

/// The crate whose default features ARE the default distribution.
pub const ROOT_CRATE_DIR: &str = "crates/busbar";

/// One pinned plugin package: its name and the commit of the repo it is pinned at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pin {
    pub package: String,
    pub url: String,
    pub sha: String,
}

impl Pin {
    /// A `Cargo.lock` source (`git+<url>?rev=<rev>#<full sha>`) as a pin. `None` for any other
    /// source, or a git source whose resolved commit is not spelled out.
    pub fn from_source(package: &str, source: &str) -> Option<Pin> {
        let rest = source.strip_prefix("git+")?;
        let (head, sha) = rest.rsplit_once('#')?;
        let url = head.split('?').next()?.to_string();
        if url.is_empty() || sha.len() < 7 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(Pin {
            package: package.to_string(),
            url,
            sha: sha.to_string(),
        })
    }

    /// Where the pinned crate is read in this tree: `crates/<package>`.
    pub fn mount_dir(&self) -> String {
        format!("crates/{}", self.package)
    }

    /// The repo's last path segment, without `.git` — cargo's own db naming key.
    pub fn repo_name(&self) -> String {
        let last = self
            .url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("");
        last.strip_suffix(".git").unwrap_or(last).to_string()
    }

    /// `owner/repo` for a hosted URL, else the repo name.
    pub fn repo_slug(&self) -> String {
        let trimmed = self.url.trim_end_matches('/');
        let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
        let segs: Vec<&str> = trimmed.rsplit('/').take(2).collect();
        match segs.as_slice() {
            [repo, owner] if !owner.is_empty() && !owner.contains(':') => format!("{owner}/{repo}"),
            _ => self.repo_name(),
        }
    }

    /// The report's note for a scope read from this pin.
    pub fn note(&self) -> String {
        format!(
            "pinned: {}@{}",
            self.repo_slug(),
            &self.sha[..self.sha.len().min(10)]
        )
    }
}

/// One pinned crate as mounted: the pin, the bare repository it was read from, and its files
/// RELATIVE to the crate directory -> blob oid.
#[derive(Debug, Clone)]
pub struct Mount {
    pub pin: Pin,
    pub db: PathBuf,
    pub files: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------------------------
// Cargo.lock
// ---------------------------------------------------------------------------------------------

/// One `[[package]]` of a `Cargo.lock`.
#[derive(Debug, Clone, Default)]
pub struct LockPackage {
    pub name: String,
    pub source: String,
    pub deps: Vec<String>,
}

/// The `[[package]]` entries of a `Cargo.lock`. Read by hand rather than through `toml_lite`,
/// because a git source carries a `#<sha>` that a comment-stripping reader cuts off.
pub fn parse_lock(text: &str) -> Vec<LockPackage> {
    fn unq(v: &str) -> String {
        v.trim()
            .trim_end_matches(',')
            .trim()
            .trim_matches('"')
            .to_string()
    }
    let mut out = Vec::new();
    let mut cur: Option<LockPackage> = None;
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if in_deps {
            if t.starts_with(']') {
                in_deps = false;
            } else if let Some(p) = cur.as_mut() {
                if !t.is_empty() {
                    p.deps.push(dep_name(&unq(t)));
                }
            }
            continue;
        }
        if t.starts_with('[') {
            out.extend(cur.take());
            if t == "[[package]]" {
                cur = Some(LockPackage::default());
            }
            continue;
        }
        let Some(p) = cur.as_mut() else {
            continue;
        };
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        match k.trim() {
            "name" => p.name = unq(v),
            "source" => p.source = unq(v),
            "dependencies" => {
                let v = v.trim();
                if let Some(body) = v.strip_prefix('[') {
                    if let Some(body) = body.strip_suffix(']') {
                        p.deps.extend(
                            body.split(',')
                                .map(unq)
                                .filter(|s| !s.is_empty())
                                .map(|s| dep_name(&s)),
                        );
                    } else {
                        in_deps = true;
                    }
                }
            }
            _ => {}
        }
    }
    out.extend(cur);
    out
}

/// A lock dependency entry (`name`, `name version` or `name version (source)`) as its name.
fn dep_name(entry: &str) -> String {
    entry.split_whitespace().next().unwrap_or("").to_string()
}

/// Whether `name` is a pinned-plugin candidate by NAME: one of the seven plugin kinds, and not the
/// cdylib twin.
pub fn is_plugin_package(name: &str) -> bool {
    !name.ends_with(CDYLIB_SUFFIX) && crate::gates::kind_isolation::plugin_kind(name).is_some()
}

// ---------------------------------------------------------------------------------------------
// the default distribution
// ---------------------------------------------------------------------------------------------

/// One dependency declaration of a manifest.
#[derive(Debug, Clone, Default)]
struct Dep {
    key: String,
    package: Option<String>,
    path: Option<String>,
    git: bool,
    workspace: bool,
    optional: bool,
}

fn dep_from_pairs(key: &str, pairs: &[(String, String)]) -> Dep {
    let mut d = Dep {
        key: key.to_string(),
        ..Dep::default()
    };
    for (k, v) in pairs {
        let sv = crate::toml_lite::string_value(v);
        match k.as_str() {
            "package" => d.package = Some(sv),
            "path" => d.path = Some(sv),
            "git" => d.git = true,
            "workspace" => d.workspace = sv == "true",
            "optional" => d.optional = sv == "true",
            _ => {}
        }
    }
    d
}

/// The NORMAL dependencies a manifest declares — `[dependencies]`, `[dependencies.<x>]` and every
/// `[target.<cfg>.dependencies]` — never `dev-` or `build-` dependencies, which no shipped binary
/// links.
fn normal_deps(doc: &crate::toml_lite::Document) -> Vec<Dep> {
    deps_under(doc, |table| {
        table == "dependencies"
            || (table.starts_with("target.") && table.ends_with(".dependencies"))
    })
}

fn deps_under(doc: &crate::toml_lite::Document, is_deps_table: impl Fn(&str) -> bool) -> Vec<Dep> {
    let mut out = Vec::new();
    for (path, table) in &doc.tables {
        if is_deps_table(path) {
            for (key, raw) in &table.entries {
                let pairs = crate::toml_lite::inline_table(raw).unwrap_or_default();
                out.push(dep_from_pairs(key, &pairs));
            }
            continue;
        }
        // `[dependencies.<key>]` — the sub-table spelling of one dependency.
        if let Some((parent, key)) = path.rsplit_once('.') {
            if is_deps_table(parent) {
                let pairs: Vec<(String, String)> = table.entries.clone();
                out.push(dep_from_pairs(key.trim_matches('"'), &pairs));
            }
        }
    }
    out
}

/// `a/b/../c` -> `a/c`, `a/./b` -> `a/b`.
fn normalise(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

/// The optional dependencies the root crate's `default` feature enables, through its own feature
/// table: `dep:x`, `x/feature` (which enables `x`), and a feature that names an optional dependency
/// with no explicit feature of its own. `x?/feature` enables nothing by itself.
fn default_enabled(doc: &crate::toml_lite::Document) -> BTreeSet<String> {
    let features = doc.table("features").values;
    let mut on = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec!["default".to_string()];
    while let Some(f) = stack.pop() {
        if !seen.insert(f.clone()) {
            continue;
        }
        for item in features.get(&f).cloned().unwrap_or_default() {
            if let Some(dep) = item.strip_prefix("dep:") {
                on.insert(dep.to_string());
            } else if let Some((dep, _)) = item.split_once('/') {
                if !dep.ends_with('?') {
                    on.insert(dep.to_string());
                }
            } else if features.contains_key(&item) {
                stack.push(item);
            } else {
                on.insert(item);
            }
        }
    }
    on
}

/// THE DEFAULT DISTRIBUTION'S GIT PACKAGES: every `git+` package the root crate links with its
/// default features, followed through the workspace path crates it links and through the lock
/// graph of the git packages themselves (a cdylib twin reaches its logic crate that way).
///
/// The ROOT's optional dependencies are read through its `default` feature exactly. A workspace
/// path crate the root links is read OVER-INCLUSIVELY — every normal dependency, optional or not —
/// because deciding which of its features the root forwards is a feature resolver, and when this
/// instrument must choose it counts a plugin in rather than out. Dev- and build-dependencies are
/// never counted.
///
/// `read` answers a tracked file's text at the commit being read.
pub fn default_distribution(
    read: &dyn Fn(&str) -> Option<String>,
    lock: &[LockPackage],
) -> Result<BTreeSet<String>, String> {
    let ws_text =
        read("Cargo.toml").ok_or("the workspace manifest Cargo.toml is not in the tree")?;
    let ws = crate::toml_lite::parse_text(&ws_text);
    let ws_deps: BTreeMap<String, Dep> = deps_under(&ws, |t| t == "workspace.dependencies")
        .into_iter()
        .map(|d| (d.key.clone(), d))
        .collect();

    let mut reached: BTreeSet<String> = BTreeSet::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = vec![ROOT_CRATE_DIR.to_string()];
    while let Some(dir) = queue.pop() {
        if !visited.insert(dir.clone()) {
            continue;
        }
        let manifest = format!("{dir}/Cargo.toml");
        let text = read(&manifest).ok_or_else(|| {
            format!("{manifest} is not in the tree, so the default distribution cannot be read")
        })?;
        let doc = crate::toml_lite::parse_text(&text);
        let is_root = dir == ROOT_CRATE_DIR;
        let enabled = if is_root {
            default_enabled(&doc)
        } else {
            BTreeSet::new()
        };
        for d in normal_deps(&doc) {
            if is_root && d.optional && !enabled.contains(&d.key) {
                continue;
            }
            if let Some(p) = &d.path {
                queue.push(normalise(&format!("{dir}/{p}")));
            } else if d.git {
                reached.insert(d.package.clone().unwrap_or_else(|| d.key.clone()));
            } else if d.workspace {
                let Some(w) = ws_deps.get(&d.key) else {
                    continue;
                };
                if let Some(p) = &w.path {
                    queue.push(normalise(p));
                } else if w.git {
                    reached.insert(w.package.clone().unwrap_or_else(|| w.key.clone()));
                }
            }
        }
    }

    // THROUGH THE LOCK GRAPH. A git package's own dev-dependencies are never in a lock, so every
    // edge here is one the package links.
    let git_pkgs: BTreeMap<&str, Vec<&LockPackage>> = lock
        .iter()
        .filter(|p| p.source.starts_with("git+"))
        .fold(BTreeMap::new(), |mut m, p| {
            m.entry(p.name.as_str()).or_insert_with(Vec::new).push(p);
            m
        });
    let mut stack: Vec<String> = reached.iter().cloned().collect();
    while let Some(name) = stack.pop() {
        for p in git_pkgs.get(name.as_str()).into_iter().flatten() {
            for dep in &p.deps {
                if git_pkgs.contains_key(dep.as_str()) && reached.insert(dep.clone()) {
                    stack.push(dep.clone());
                }
            }
        }
    }
    Ok(reached)
}

/// THE PINS TO MOUNT over a tree: every pinned plugin package of the default distribution whose
/// `crates/<package>` the tree does not hold (THE TREE WINS — a crate still on disk is read from
/// disk). `tracked` is the tree's path -> oid listing; `read` answers a tracked file's text.
pub fn pins_for(
    tracked: &BTreeMap<String, String>,
    read: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<Pin>, String> {
    let Some(lock_text) = read("Cargo.lock") else {
        return Ok(Vec::new());
    };
    let lock = parse_lock(&lock_text);
    let in_tree = |name: &str| {
        let dir = format!("crates/{name}/");
        tracked
            .range(dir.clone()..)
            .next()
            .is_some_and(|(k, _)| k.starts_with(&dir))
    };
    let candidates: Vec<&LockPackage> = lock
        .iter()
        .filter(|p| p.source.starts_with("git+") && is_plugin_package(&p.name) && !in_tree(&p.name))
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let reached = default_distribution(read, &lock)?;
    let mut pins: Vec<Pin> = Vec::new();
    for p in candidates {
        if !reached.contains(&p.name) {
            continue;
        }
        let pin = Pin::from_source(&p.name, &p.source).ok_or_else(|| {
            format!(
                "pinned plugin {}: Cargo.lock source `{}` names no commit",
                p.name, p.source
            )
        })?;
        if let Some(other) = pins.iter().find(|q| q.package == pin.package) {
            return Err(format!(
                "pinned plugin {} is locked at two commits ({} and {}); one mount path cannot hold both",
                pin.package, other.sha, pin.sha
            ));
        }
        pins.push(pin);
    }
    pins.sort();
    Ok(pins)
}

// ---------------------------------------------------------------------------------------------
// reading a pinned checkout
// ---------------------------------------------------------------------------------------------

type MountMemo = BTreeMap<Pin, Result<Arc<Mount>, String>>;

/// Where pinned commits are found, and every mount read so far (an unproducible pin is remembered
/// too: asking again would be another fetch for the answer already known).
pub struct PinStore {
    cargo_home: PathBuf,
    cache_root: PathBuf,
    mounts: Mutex<MountMemo>,
}

/// `$CARGO_HOME`, else `~/.cargo`.
pub fn default_cargo_home() -> PathBuf {
    if let Some(h) = std::env::var_os("CARGO_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".cargo")
}

fn has_commit(db: &Path, sha: &str) -> bool {
    crate::gitp::git(db, &["cat-file", "-e", &format!("{sha}^{{commit}}")]).is_ok()
}

impl PinStore {
    pub fn new(cargo_home: PathBuf, cache_root: PathBuf) -> PinStore {
        PinStore {
            cargo_home,
            cache_root,
            mounts: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn set_cargo_home(&mut self, home: PathBuf) {
        self.cargo_home = home;
    }

    /// The pinned crate's files, read once per pin.
    pub fn mount(&self, pin: &Pin) -> Result<Arc<Mount>, String> {
        if let Ok(memo) = self.mounts.lock() {
            if let Some(hit) = memo.get(pin) {
                return hit.clone();
            }
        }
        let answer = self.read_mount(pin).map(Arc::new);
        if let Ok(mut memo) = self.mounts.lock() {
            memo.insert(pin.clone(), answer.clone());
        }
        answer
    }

    /// A bare repository holding the pinned commit: one of cargo's git dbs (the repo's own name
    /// first), else the fetch cache, fetched into once.
    fn locate(&self, pin: &Pin) -> Result<PathBuf, String> {
        let db_root = self.cargo_home.join("git").join("db");
        let mut dbs: Vec<PathBuf> = std::fs::read_dir(&db_root)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect()
            })
            .unwrap_or_default();
        let own = format!("{}-", pin.repo_name());
        dbs.sort_by_key(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            (!name.starts_with(&own), p.clone())
        });
        if let Some(db) = dbs.into_iter().find(|db| has_commit(db, &pin.sha)) {
            return Ok(db);
        }

        let cache = self.cache_root.join(format!("{}.git", pin.repo_name()));
        if cache.join("HEAD").is_file() && has_commit(&cache, &pin.sha) {
            return Ok(cache);
        }
        let fetched = std::fs::create_dir_all(&cache)
            .map_err(|e| format!("{}: {e}", cache.display()))
            .and_then(|()| {
                if cache.join("HEAD").is_file() {
                    Ok(String::new())
                } else {
                    crate::gitp::git(&cache, &["init", "--bare", "-q"])
                }
            })
            .and_then(|_| {
                crate::gitp::git_with_env(
                    &cache,
                    &["fetch", "-q", "--depth=1", "--no-tags", &pin.url, &pin.sha],
                    &[("GIT_TERMINAL_PROMPT", "0")],
                )
            });
        match fetched {
            Ok(_) if has_commit(&cache, &pin.sha) => Ok(cache),
            Ok(_) => Err(format!(
                "pinned plugin {} @ {}: the fetch from {} did not produce the commit",
                pin.package, pin.sha, pin.url
            )),
            Err(e) => Err(format!(
                "pinned plugin {} @ {}: the pinned commit cannot be produced -- no cargo git db under \
                 {} holds it, and fetching it from {} failed: {e}",
                pin.package,
                pin.sha,
                db_root.display(),
                pin.url
            )),
        }
    }

    fn read_mount(&self, pin: &Pin) -> Result<Mount, String> {
        let db = self.locate(pin)?;
        let listing = crate::gitp::git(&db, &["ls-tree", "-r", "--full-tree", &pin.sha])
            .map_err(|e| format!("pinned plugin {} @ {}: {e}", pin.package, pin.sha))?;
        let mut blobs: Vec<(String, String)> = Vec::new();
        for line in listing.lines() {
            let Some((meta, path)) = line.split_once('\t') else {
                continue;
            };
            let mut cols = meta.split_whitespace();
            let (_mode, kind, oid) = (cols.next(), cols.next(), cols.next());
            if let (Some("blob"), Some(oid)) = (kind, oid) {
                blobs.push((path.to_string(), oid.to_string()));
            }
        }

        // Every package directory of the checkout, by the `[package] name` its manifest declares.
        let mut packages: Vec<(String, String)> = Vec::new();
        for (path, oid) in &blobs {
            let dir = if path == "Cargo.toml" {
                String::new()
            } else if let Some(d) = path.strip_suffix("/Cargo.toml") {
                d.to_string()
            } else {
                continue;
            };
            let text = crate::gitp::git(&db, &["cat-file", "blob", oid])
                .map_err(|e| format!("pinned plugin {} @ {}: {e}", pin.package, pin.sha))?;
            if let Some(name) = crate::toml_lite::parse_text(&text)
                .table("package")
                .get_one("name")
            {
                packages.push((dir, name.to_string()));
            }
        }
        let mut owning = packages.iter().filter(|(_, n)| *n == pin.package);
        let (Some((dir, _)), None) = (owning.next(), owning.next()) else {
            return Err(format!(
                "pinned plugin {} @ {}: the pinned commit has no single package named {} (packages: {})",
                pin.package,
                pin.sha,
                pin.package,
                packages
                    .iter()
                    .map(|(d, n)| format!("{n} at `{d}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        };
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        // A package nested inside this one (a twin under the logic crate's directory) is its own
        // package, not this crate's files.
        let nested: Vec<String> = packages
            .iter()
            .filter(|(d, _)| d != dir && (dir.is_empty() || d.starts_with(&prefix)))
            .map(|(d, _)| format!("{d}/"))
            .collect();
        let files: BTreeMap<String, String> = blobs
            .into_iter()
            .filter(|(p, _)| p.starts_with(&prefix) && !nested.iter().any(|n| p.starts_with(n)))
            .map(|(p, oid)| (p[prefix.len()..].to_string(), oid))
            .collect();
        if files.is_empty() {
            return Err(format!(
                "pinned plugin {} @ {}: its crate directory `{dir}` holds no file",
                pin.package, pin.sha
            ));
        }
        Ok(Mount {
            pin: pin.clone(),
            db,
            files,
        })
    }
}

#[cfg(test)]
#[path = "audit_pinned/pinned_tests.rs"]
mod tests;
