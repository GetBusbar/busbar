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
//! PLUS, for every pinned plugin package `P` of `R`'s `Cargo.lock` that has no
//! `crates/<P>` in `R`'s tree, a VIRTUAL entry `crates/<P>/<rel>` -> blob oid for every file `<rel>`
//! of `P`'s crate directory in the plugin repo at the pinned commit. Scope ids and paths do not
//! change, and the blob oid of a byte-identical file is the same oid in any repository, so a scope
//! over byte-identical code hashes identically whichever repository holds it.
//!
//! WHICH PACKAGES ([`pins_for`]): EVERY `git+` package of `R`'s `Cargo.lock` whose name resolves to
//! one of the seven plugin kinds (the kind-isolation table, [`crate::gates::kind_isolation::plugin_kind`])
//! and that is not the `-plugin` cdylib twin. The lock is cargo's resolution of every workspace
//! manifest over every feature, so this is the workspace's whole pin table: a plugin the `default`
//! feature compiles in, one behind a feature `default` leaves off, and one only a proof links are all
//! mounted, and a record about any of them re-hashes against its pinned bytes. A PLANE's cdylib
//! twin (`<package>-plugin`, the logic crate's `export_door!` image) is mounted beside it from the
//! same repository and commit, at `crates/<package>-plugin` ([`TWINNED_KIND`]).
//!
//! WHERE THE BYTES COME FROM ([`PinStore`]): cargo's own git database (`$CARGO_HOME/git/db/*`,
//! bare repositories cargo fills when it resolves the workspace — every `cargo xtask` run has
//! already done that for the pins at HEAD), else ONE shallow fetch of the pinned commit into a cache
//! bare repo under `target/ledger-pins/`. A pin neither can produce is an ERROR naming the package
//! and the commit: the ledger fails closed, it never skips a pin it cannot read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The suffix of a plugin repo's cdylib twin (`busbar-transport-tcp-plugin`). The twin packages the
/// logic crate; the logic crate is the scope.
pub const CDYLIB_SUFFIX: &str = "-plugin";

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
// which pins
// ---------------------------------------------------------------------------------------------

/// THE PINS TO MOUNT over a tree: EVERY pinned plugin package of the tree's `Cargo.lock` whose
/// `crates/<package>` the tree does not hold (THE TREE WINS — a crate still on disk is read from
/// disk). `tracked` is the tree's path -> oid listing; `read` answers a tracked file's text.
///
/// THE LOCK IS THE PIN TABLE. `Cargo.lock` is cargo's own resolution of every workspace manifest
/// over EVERY feature and EVERY target, so its `git+` plugin packages are exactly the plugin crates
/// the workspace pins — the ones the root's `default` feature turns on, the ones behind a feature it
/// leaves off (`transport-webrtc`), and the ones only a proof links (`busbar-auth-oidc`). Each of
/// them is a real plugin the binary can link or a deployment can drop in, so each of their scopes is
/// auditable, and a record about one must re-hash against the pinned bytes.
///
/// THIS USED TO READ THE DEFAULT DISTRIBUTION ONLY, and that made a correct record unverifiable. It
/// followed the root's `default` feature by hand, so a pin behind a non-default feature or a
/// dev-dependency was never mounted: its scope owned no file at any commit, its tree hash computed
/// to `None`, and `--check` listed every record about it as a hash that "is not the tree at the
/// commit they claim" — measured at 4bfe019df1, all six of that list were `busbar-transport-webrtc`
/// (behind `transport-webrtc`) and `busbar-auth-oidc` (a dev-dependency) records whose digests are
/// the sha256 of exactly the pinned `path<TAB>blob` lines. A hand-written feature resolver deciding
/// which pins count is a second answer to a question the lock already answers.
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
    let mut pins: Vec<Pin> = Vec::new();
    for p in candidates {
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
    // THE PLANE'S CDYLIB TWIN IS MOUNTED BESIDE IT (ARCHITECT ruling on #1269: the twin's production
    // code — the `export_door!` image a signed tarball carries — is audited by this ledger, never by
    // nobody). It is not in the lock (busbar links the logic crate), so it is read from the same
    // repository at the same commit as its logic crate, at `crates/<package>-plugin`. A twin the
    // pinned commit does not carry is an error naming it, as any unproducible pin is.
    let twins: Vec<Pin> = pins
        .iter()
        .filter(|p| crate::gates::kind_isolation::plugin_kind(&p.package) == Some(TWINNED_KIND))
        .map(|p| Pin {
            package: format!("{}{CDYLIB_SUFFIX}", p.package),
            url: p.url.clone(),
            sha: p.sha.clone(),
        })
        .filter(|t| !in_tree(&t.package))
        .collect();
    pins.extend(twins);
    pins.sort();
    Ok(pins)
}

/// The plugin kind whose cdylib twin [`pins_for`] mounts beside its logic crate.
pub const TWINNED_KIND: &str = "plane";

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
