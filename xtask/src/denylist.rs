//! `cargo xtask denylist` — the transitive source denylist ARCHITECTURE.md section 1.2 specifies
//! and docs/design/1.6.0-contract-gaps.md CG-59 found nowhere in the tree.
//!
//! For every crate of a PURE plugin kind (plane, hook, static/pure auth, egress-auth-scheme — the
//! kind list section 1.2 scopes the denylist to; section 1.4's table is where each kind's shape is
//! defined and section 1.2 is what draws the pure/I-O line), this:
//!
//!   1. Runs `cargo metadata` once for the whole workspace and, per pure crate, walks the resolved
//!      NORMAL-dependency closure only (dev/build edges never ship in the binary a pure crate's
//!      code runs inside, so they are out of scope by construction — the same reason
//!      `_read_cargo_deps` in the FAST-tier lint reads only `[dependencies]`).
//!   2. Refuses any crate in that closure whose name is on the banned list (verbatim from
//!      ARCHITECTURE.md section 1.2 via `qa/construction.toml`'s `[rules.source-denylist].patterns`,
//!      plus `hyper-util`, named by CG-60 as the vector that drags `hyper` and `tokio::net` into
//!      `busbar-llm` transitively) — and any `tokio` node in that closure whose resolved feature
//!      set includes `net`, `fs` or `process`.
//!   3. Scans each pure crate's OWN `src/` (comments stripped, `#[cfg(test)] mod` bodies and
//!      `tests/`-fragment files excluded, exactly as the FAST-tier lint does) for the banned
//!      std/tokio paths themselves, in case a pure crate reached one without a Cargo dependency
//!      announcing it (there is no such path today, but the scan is what makes that a fact this
//!      tool can point at rather than one that must be believed).
//!
//! `qa/denylist-allow.toml` is the one waiver seam: empty at hour 0 (section 1.2 says so), and any
//! future entry that lacks BOTH a `reason` and an `owner` is a hard refusal of the whole run — an
//! incomplete waiver is worse than none, because it reads as reviewed when it was not.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::toml_lite;

pub struct Hit {
    pub crate_name: String,
    pub offender: String,
    pub via: String,
}

pub struct Report {
    pub hits: Vec<Hit>,
    pub crates_scanned: usize,
}

/// `hyper-util` is not named in ARCHITECTURE.md section 1.2's own list (`reqwest`, `hyper`,
/// `async_std`, `libc`) — it is named in docs/design/1.6.0-contract-gaps.md's CG-60 row as the
/// crate that drags `hyper` and `tokio::net` into `busbar-llm`. Banning it by name too (rather
/// than relying solely on the `hyper`/`tokio` hits its own dependencies would produce) makes the
/// report point at the crate a reviewer actually added, not just what it happens to pull in.
const EXTRA_BANNED_CRATE_NAMES: &[&str] = &["hyper-util"];

/// `std::os` and `std::env` module-path tokens as they'd appear in the qa/construction.toml
/// `patterns` list use `async_std` (the module form); the published crate name is hyphenated.
fn pattern_to_crate_name(pattern: &str) -> String {
    pattern.replace('_', "-")
}

pub(crate) struct BannedLists {
    /// Crate (package) names banned anywhere in a pure crate's transitive normal closure.
    crate_names: BTreeSet<String>,
    /// `std::`/`tokio::` path substrings banned in a pure crate's own `src/`.
    std_paths: Vec<String>,
}

pub(crate) fn load_banned_lists(root: &Path) -> BannedLists {
    let doc = toml_lite::parse(&root.join("qa/construction.toml"));
    let rule = doc.table("rules.source-denylist");
    let patterns = rule.get_list("patterns");
    let mut crate_names = BTreeSet::new();
    let mut std_paths = Vec::new();
    for p in &patterns {
        if p.contains("::") {
            std_paths.push(p.clone());
        } else {
            crate_names.insert(pattern_to_crate_name(p));
        }
    }
    for extra in EXTRA_BANNED_CRATE_NAMES {
        crate_names.insert((*extra).to_string());
    }
    BannedLists {
        crate_names,
        std_paths,
    }
}

/// A single-`*`-wildcard glob, matching exactly the shapes `qa/construction.toml`'s
/// `[gate.plugin_kinds]` globs use (`crates/busbar-plane-*`, `crates/hook*`, `crates/auth-*`, or a
/// bare literal directory).
fn glob_match(pattern: &str, candidate: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == candidate,
        Some((prefix, suffix)) => {
            candidate.len() >= prefix.len() + suffix.len()
                && candidate.starts_with(prefix)
                && candidate.ends_with(suffix)
        }
    }
}

pub struct PureCrate {
    /// The `[package] name` — what `cargo metadata` calls it, used to find its node.
    pub name: String,
    pub dir: PathBuf,
    pub kind: String,
    /// The crate directory's basename — what `scripts/construction-gate/rules.py` calls it
    /// (`_crate_name(d)`), used for every reported `Hit.crate_name` so the two tools' row/TSV keys
    /// agree even where the manifest name differs from the directory (`crates/auth-static-plugin`
    /// ships as `busbar-auth-static-plugin`).
    pub report_name: String,
}

/// Every crate under `crates/*` matching one of the PURE kinds' globs in
/// `qa/construction.toml`'s `[gate.plugin_kinds]`, restricted to the kind list
/// `[rules.source-denylist].kinds` names (section 1.2's own scoping: I/O kinds — store, secret,
/// export, network-backed auth — own their I/O by definition and are out of scope here).
pub fn pure_crates(root: &Path) -> Vec<PureCrate> {
    let doc = toml_lite::parse(&root.join("qa/construction.toml"));
    let kinds = doc.table("rules.source-denylist").get_list("kinds");
    let plugin_kinds = doc.table("gate.plugin_kinds");
    let mut out = Vec::new();
    let crates_dir = root.join("crates");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&crates_dir)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();
    for kind in &kinds {
        let globs = plugin_kinds.get_list(kind);
        for dir in &entries {
            if !dir.is_dir() {
                continue;
            }
            let name = dir.file_name().unwrap().to_string_lossy().to_string();
            let candidate = format!("crates/{name}");
            if globs.iter().any(|g| glob_match(g, &candidate)) && dir.join("Cargo.toml").exists() {
                out.push(PureCrate {
                    name: crate_manifest_name(dir),
                    dir: dir.clone(),
                    kind: kind.clone(),
                    report_name: name,
                });
            }
        }
    }
    out
}

/// The `[package] name = "..."` a crate's Cargo.toml actually declares — this can differ from its
/// directory name (`crates/auth-static-plugin` ships as `busbar-auth-static-plugin`), and
/// `cargo metadata` only knows the manifest name.
fn crate_manifest_name(dir: &Path) -> String {
    let raw = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap_or_default();
    let mut in_package = false;
    for line in raw.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = t.strip_prefix("name") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let v = rest.trim().trim_matches('"');
                    return v.to_string();
                }
            }
        }
    }
    dir.file_name().unwrap().to_string_lossy().to_string()
}

/// `(dep name, dep package id, is-a-normal-edge)` for one dependency edge.
type DepEdge = (String, String, bool);
/// A resolve node's outgoing edges plus its own resolved feature set.
type Node = (Vec<DepEdge>, Vec<String>);

struct Metadata {
    /// package id -> name
    names: BTreeMap<String, String>,
    /// package id -> manifest_path
    manifest_paths: BTreeMap<String, String>,
    /// package id -> node
    nodes: BTreeMap<String, Node>,
    /// package id -> the set of that package's OWN normal-kind dependencies that are `optional =
    /// true` in its manifest, keyed by the LOCAL (rename-if-present, else published) name in
    /// published (hyphenated) form — the same form a Cargo.toml `[features]` string names it in
    /// (`"foo"` or `"dep:foo"`). Built once from `packages[].dependencies` so [`edge_is_active`]
    /// can tell a genuinely-compiled edge from one `cargo metadata`'s resolve graph merely lists as
    /// POSSIBLE (see that function's doc for why the distinction matters).
    optional_normal_deps: BTreeMap<String, BTreeSet<String>>,
    /// package id -> that package's OWN `[features]` table, name -> its raw requirement strings
    /// (`"dep:foo"`, `"foo"`, `"foo/bar"`, `"foo?/bar"`, or another feature name), exactly as
    /// `packages[].features` reports it. [`edge_is_active`] scans the definitions of a node's
    /// currently-ACTIVE feature names (already the flattened closure `cargo metadata` reports in
    /// `nodes[].features`) for the token that would turn a given optional dependency on, rather
    /// than assuming (wrongly) that an activated optional dependency's OWN name always appears
    /// verbatim in the active-features list — new-style `dep:foo` syntax means it often does not.
    feature_defs: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

fn run_cargo_metadata(manifest_path: &Path) -> Value {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .arg("metadata")
        .arg("--format-version=1")
        // The lockfile is already resolved (checked in); a denylist audit reads it, it never has
        // a reason to touch the network, and a flaky/offline registry must never turn a source
        // audit into a network-dependent step.
        .arg("--offline")
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .unwrap_or_else(|e| panic!("xtask denylist: failed to run `cargo metadata`: {e}"));
    if !out.status.success() {
        panic!(
            "xtask denylist: `cargo metadata` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("xtask denylist: cargo metadata produced invalid JSON: {e}"))
}

fn parse_metadata(v: &Value) -> Metadata {
    let mut names = BTreeMap::new();
    let mut manifest_paths = BTreeMap::new();
    let mut optional_normal_deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut feature_defs: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for pkg in v["packages"].as_array().cloned().unwrap_or_default() {
        let id = pkg["id"].as_str().unwrap_or_default().to_string();
        names.insert(
            id.clone(),
            pkg["name"].as_str().unwrap_or_default().to_string(),
        );
        manifest_paths.insert(
            id.clone(),
            pkg["manifest_path"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
        let mut optional = BTreeSet::new();
        for dep in pkg["dependencies"].as_array().cloned().unwrap_or_default() {
            // Only a NORMAL-kind declaration matters here — the same scoping `closure_hits` walks
            // (dev/build edges are out of scope by construction). `kind` is `null` for normal.
            if !dep["kind"].is_null() {
                continue;
            }
            if dep["optional"].as_bool().unwrap_or(false) {
                let local = dep["rename"]
                    .as_str()
                    .or_else(|| dep["name"].as_str())
                    .unwrap_or_default();
                if !local.is_empty() {
                    optional.insert(local.to_string());
                }
            }
        }
        optional_normal_deps.insert(id.clone(), optional);

        let mut defs = BTreeMap::new();
        if let Some(features_obj) = pkg["features"].as_object() {
            for (feat_name, reqs) in features_obj {
                let list = reqs
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect();
                defs.insert(feat_name.clone(), list);
            }
        }
        feature_defs.insert(id, defs);
    }
    let mut nodes = BTreeMap::new();
    for node in v["resolve"]["nodes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let id = node["id"].as_str().unwrap_or_default().to_string();
        let mut deps = Vec::new();
        for d in node["deps"].as_array().cloned().unwrap_or_default() {
            let dep_name = d["name"].as_str().unwrap_or_default().to_string();
            let dep_pkg = d["pkg"].as_str().unwrap_or_default().to_string();
            let is_normal = d["dep_kinds"]
                .as_array()
                .map(|ks| ks.iter().any(|k| k["kind"].is_null()))
                .unwrap_or(true); // an edge with no dep_kinds info at all is treated as normal (conservative)
            deps.push((dep_name, dep_pkg, is_normal));
        }
        let features = node["features"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|f| f.as_str().map(str::to_string))
            .collect();
        nodes.insert(id, (deps, features));
    }
    Metadata {
        names,
        manifest_paths,
        nodes,
        optional_normal_deps,
        feature_defs,
    }
}

/// Is the edge `from_id -> dep_ident` one `cargo build` actually compiles into `from_id`, or
/// merely one `cargo metadata`'s resolve graph LISTS as a possible edge?
///
/// `cargo metadata`'s `resolve.nodes[].deps` names every dependency declared in a package's
/// manifest whose required version is satisfied by SOME package already resolved in the lockfile
/// — including an `optional = true` dependency whose enabling feature is OFF for this node. Only
/// the node's own `features` list says which optional deps are really turned on; `deps` does not
/// filter by it. A denylist walk that trusted `deps` alone would flag a banned crate reachable
/// only through a dependency nothing ever activates — verified against this exact shape: `faststr`
/// (a `sonic-rs` dependency) declares an optional, non-default `rkyv` dependency, and `cargo
/// metadata` lists that edge for every consumer regardless of whether `rkyv` is active; the actual
/// `rustc` invocation for `busbar-plane-llm`'s build carries no `--cfg feature="rkyv"` and no
/// `--extern rkyv=...` at all, so the crate genuinely never sees `rkyv` — let alone `rkyv`'s own
/// optional `uuid` dependency and ITS `getrandom` — despite the phantom edge showing up three hops
/// later as `sonic_rs -> faststr -> rkyv -> uuid_1 -> getrandom -> libc`.
///
/// `dep_ident` is the edge's `deps[].name` — the local (rename-if-any) extern-crate identifier,
/// underscored. A non-optional dependency (or one this function has no record of, e.g. because
/// `from_id` itself was not found in `packages[]`) is always treated as active — the same
/// conservative default `is_normal`'s own fallback uses, so a metadata shape this function does
/// not recognize never silently HIDES a real hit.
///
/// An optional dependency is turned on by a NAMED feature whose own definition mentions it —
/// `"dep:foo"` (new explicit syntax), a bare `"foo"` (old implicit syntax, only when no `dep:foo`
/// exists anywhere for it), or `"foo/bar"` (a strong feature-forward, which activates `foo` as a
/// side effect; `"foo?/bar"` is the WEAK form and does NOT). `nodes[].features` is already the
/// flattened closure of every active named feature, so checking one level of each active feature's
/// OWN definition (from `packages[].features`) — no further recursion — is enough to find that
/// token if it is reachable at all.
fn edge_is_active(meta: &Metadata, from_id: &str, dep_ident: &str) -> bool {
    let Some(optional) = meta.optional_normal_deps.get(from_id) else {
        return true;
    };
    let hyphenated = dep_ident.replace('_', "-");
    if !optional.contains(&hyphenated) {
        // Not declared optional (or declared under a different local name than we could resolve)
        // — a normal, unconditional dependency, always compiled in.
        return true;
    }
    let Some((_, active_features)) = meta.nodes.get(from_id) else {
        return true;
    };
    let Some(defs) = meta.feature_defs.get(from_id) else {
        return true;
    };
    let dep_marker = format!("dep:{hyphenated}");
    let strong_forward = format!("{hyphenated}/");
    active_features.iter().any(|feat| {
        // The old-style implicit optional-dependency feature: activating a feature with the SAME
        // name as the dependency turns it on, unless `dep:foo` syntax is used elsewhere (in which
        // case this name means something else and never appears bare in a definition list anyway).
        feat == &hyphenated
            || defs.get(feat).is_some_and(|reqs| {
                reqs.iter().any(|r| {
                    r == &dep_marker || r == &hyphenated || r.starts_with(&strong_forward)
                })
            })
    })
}

fn find_package_id(meta: &Metadata, crate_dir: &Path, crate_name: &str) -> Option<String> {
    let want_manifest = crate_dir.join("Cargo.toml");
    let want_manifest = std::fs::canonicalize(&want_manifest).unwrap_or(want_manifest);
    for (id, name) in &meta.names {
        if name != crate_name {
            continue;
        }
        let mp = PathBuf::from(&meta.manifest_paths[id]);
        let mp = std::fs::canonicalize(&mp).unwrap_or(mp);
        if mp == want_manifest {
            return Some(id.clone());
        }
    }
    None
}

const TOKIO_BANNED_FEATURES: &[&str] = &["net", "fs", "process"];

/// The transitive normal-dependency closure hits for one pure crate: banned crate names, and
/// `tokio` nodes carrying a banned feature. `path` on each hit is the dependency chain from the
/// pure crate to the offender, root first.
fn closure_hits(meta: &Metadata, root_id: &str, root_name: &str, banned: &BannedLists) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut visited = BTreeSet::new();
    visited.insert(root_id.to_string());
    let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
    queue.push_back((root_id.to_string(), vec![root_name.to_string()]));

    while let Some((id, path)) = queue.pop_front() {
        let Some((deps, _features)) = meta.nodes.get(&id) else {
            continue;
        };
        for (dep_name, dep_pkg, is_normal) in deps {
            if !is_normal || dep_pkg.is_empty() {
                continue;
            }
            // An edge `cargo metadata` lists but nothing actually activates (an inert optional
            // dependency) is not part of the compiled crate at all — see `edge_is_active`'s doc.
            // Not marking it `visited` either: if some OTHER, active edge reaches the same
            // package, that path must still be walked.
            if !edge_is_active(meta, &id, dep_name) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(dep_name.clone());

            if banned.crate_names.contains(dep_name.as_str()) {
                hits.push(Hit {
                    crate_name: root_name.to_string(),
                    offender: dep_name.clone(),
                    via: next_path.join(" -> "),
                });
            }
            if dep_name == "tokio" {
                if let Some((_, features)) = meta.nodes.get(dep_pkg) {
                    for feat in TOKIO_BANNED_FEATURES {
                        if features.iter().any(|f| f == feat) {
                            hits.push(Hit {
                                crate_name: root_name.to_string(),
                                offender: format!("tokio (feature: {feat})"),
                                via: next_path.join(" -> "),
                            });
                        }
                    }
                }
            }

            if visited.insert(dep_pkg.clone()) {
                queue.push_back((dep_pkg.clone(), next_path));
            }
        }
    }
    hits
}

/// Comments stripped (line + block, string contents ignored, same trade
/// `scripts/construction-gate/rules.py::strip_comments` makes), `#[cfg(test)] mod { .. }` bodies
/// dropped, one production-code line per output entry.
fn production_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_block_comment = false;
    let mut pending_test_attr = false;
    let mut test_mod_depth: Option<i32> = None;
    let mut depth: i32 = 0;

    for (i, raw_line) in src.lines().enumerate() {
        let stripped = strip_comment_line(raw_line, &mut in_block_comment);
        let trimmed = stripped.trim();

        let this_line_is_test = test_mod_depth.is_some();

        if !this_line_is_test && trimmed.contains("#[cfg(test)]") {
            pending_test_attr = true;
        } else if !this_line_is_test && !trimmed.is_empty() && !trimmed.starts_with('#') {
            // an attribute only pends across attribute/blank lines; anything else clears it
            if !trimmed.contains("mod ") {
                pending_test_attr = false;
            }
        }

        if !this_line_is_test
            && pending_test_attr
            && trimmed.contains("mod ")
            && trimmed.contains('{')
        {
            test_mod_depth = Some(depth);
            pending_test_attr = false;
        }

        let opens = stripped.matches('{').count() as i32;
        let closes = stripped.matches('}').count() as i32;
        depth += opens - closes;

        let was_test = test_mod_depth.is_some();
        if let Some(d) = test_mod_depth {
            if depth <= d && (opens > 0 || closes > 0) {
                test_mod_depth = None;
            }
        }

        if !was_test && !this_line_is_test {
            out.push((i + 1, stripped));
        }
    }
    out
}

fn strip_comment_line(line: &str, in_block: &mut bool) -> String {
    let mut out = String::new();
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0;
    let mut in_str = false;
    while i < bytes.len() {
        if *in_block {
            if bytes[i] == '*' && bytes.get(i + 1) == Some(&'/') {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(bytes[i]);
            if bytes[i] == '\\' {
                if let Some(c) = bytes.get(i + 1) {
                    out.push(*c);
                }
                i += 2;
                continue;
            }
            if bytes[i] == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if bytes[i] == '/' && bytes.get(i + 1) == Some(&'*') {
            *in_block = true;
            i += 2;
            continue;
        }
        if bytes[i] == '/' && bytes.get(i + 1) == Some(&'/') {
            break;
        }
        if bytes[i] == '"' {
            in_str = true;
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn is_test_path(rel: &str, fragments: &[String]) -> bool {
    fragments.iter().any(|f| rel.contains(f.as_str()))
}

fn walk_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        if p.is_dir() {
            walk_rs_files(&p, out);
        } else if p.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

fn load_test_fragments(config_root: &Path) -> Vec<String> {
    let doc = toml_lite::parse(&config_root.join("qa/construction.toml"));
    doc.table("gate").get_list("test_path_fragments")
}

fn own_src_hits(
    scan_root: &Path,
    pc: &PureCrate,
    banned: &BannedLists,
    fragments: &[String],
) -> Vec<Hit> {
    let root = scan_root;
    let mut files = Vec::new();
    walk_rs_files(&pc.dir.join("src"), &mut files);
    files.sort();
    let mut hits = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let rel_with_slashes = format!("/{rel}");
        if is_test_path(&rel_with_slashes, fragments) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&f) else {
            continue;
        };
        for (lineno, code) in production_lines(&src) {
            for pat in &banned.std_paths {
                if code.contains(pat.as_str()) {
                    hits.push(Hit {
                        crate_name: pc.report_name.clone(),
                        offender: pat.clone(),
                        via: format!("own src at {rel}:{lineno}"),
                    });
                }
            }
        }
    }
    hits
}

/// One `[[allow]]` entry: which crate, which offender (a `dep` crate name or an own-src `path`
/// substring), and — for a `dep` entry only — an optional `via` narrowing.
///
/// A bare `dep` entry (no `via`) waives the offender for the crate unconditionally, exactly as
/// before `via` existed: ANY transitive path from the crate to that dependency is forgiven.
///
/// A `dep` entry WITH `via` is precise instead: it waives the offender only when EVERY normal
/// dependency path from the crate to the offender passes through one of the named `via` crates
/// somewhere along it. `via` may name more than one crate (comma-separated: `via = "cpufeatures,
/// getrandom"`) for the case where the SAME offender is genuinely reached through more than one
/// reviewed, non-I/O edge — each named crate is checked independently, and a path counts as
/// covered if it passes through ANY of them. If even one path reaches the offender through NONE of
/// them, the waiver does not apply at all — every hit for that (crate, offender) pair (including
/// the ones that DO route through a named `via`) stays red, and the bypassing path is exactly the
/// kind of hit row the report already prints, so it shows up there naming itself.
pub(crate) struct AllowEntry {
    crate_name: String,
    offender: String,
    via: Option<Vec<String>>,
}

/// The load-bearing allow-list check: `qa/denylist-allow.toml` is EMPTY at hour 0 (section 1.2),
/// so this normally does nothing but confirm the file parses. Any future `[[allow]]` entry missing
/// `reason` or `owner` refuses the ENTIRE run rather than silently accepting a half-filled waiver.
fn load_allowlist(root: &Path) -> Vec<AllowEntry> {
    let path = root.join("qa/denylist-allow.toml");
    if !path.exists() {
        return Vec::new();
    }
    let doc = toml_lite::parse(&path);
    let mut allowed = Vec::new();
    for entry in doc.array_table("allow") {
        let crate_name = entry.get_one("crate").unwrap_or_default().to_string();
        let is_dep_entry = entry.get_one("dep").is_some();
        let offender = entry
            .get_one("dep")
            .or_else(|| entry.get_one("path"))
            .unwrap_or_default()
            .to_string();
        let reason = entry.get_one("reason").unwrap_or("").trim().to_string();
        let owner = entry.get_one("owner").unwrap_or("").trim().to_string();
        if reason.is_empty() || owner.is_empty() {
            panic!(
                "qa/denylist-allow.toml: entry for crate={crate_name:?} dep/path={offender:?} is \
                 missing a reason and/or an owner — an allow-list entry without both is a refusal, \
                 not a waiver. Fix the entry or remove it."
            );
        }
        let via_raw = entry
            .get_one("via")
            .map(str::trim)
            .filter(|v| !v.is_empty());
        let via: Option<Vec<String>> = via_raw.map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        });
        if let Some(v) = &via {
            if !is_dep_entry {
                panic!(
                    "qa/denylist-allow.toml: entry for crate={crate_name:?} carries `via = {v:?}` \
                     on a `path` (own-src) waiver — `via` only narrows a `dep` (dependency-graph) \
                     waiver, since it is computed over the resolved dependency graph. Remove `via` \
                     or change this to a `dep` entry."
                );
            }
            if offender.contains("::") || offender.contains("(feature:") {
                panic!(
                    "qa/denylist-allow.toml: entry for crate={crate_name:?} dep={offender:?} \
                     carries `via = {v:?}`, but {offender:?} is not a plain dependency-graph crate \
                     name — `via` is only meaningful for a `dep` entry that bans a crate name \
                     (e.g. `libc`), not a std-path or a `tokio (feature: ...)` offender."
                );
            }
        }
        allowed.push(AllowEntry {
            crate_name,
            offender,
            via,
        });
    }
    allowed
}

/// Is there a normal-dependency path from `root_id` to a node named `target_name` that never
/// passes through any node named in `via_names`? Returns the path (root name first) if so — that
/// path is the "bypass" that keeps a `via`-narrowed waiver from applying — or `None` if
/// `target_name` is unreachable without going through one of `via_names` (in which case the waiver
/// fully covers it). `via_names` holding more than one entry means ANY of them stops a path — the
/// waiver only fails to cover a route that passes through NONE of the named crates.
fn find_bypass_path(
    meta: &Metadata,
    root_id: &str,
    root_name: &str,
    via_names: &[String],
    target_name: &str,
) -> Option<String> {
    // `cargo metadata`'s resolve-node edge `name` is the Rust extern-crate identifier (dashes
    // become underscores), while `via`/`dep` in `qa/denylist-allow.toml` and
    // `qa/construction.toml` are written as published crate (package) names (dashes as-is) — the
    // same distinction `crate_manifest_name` and `pattern_to_crate_name` exist to bridge
    // elsewhere. Normalize both sides so a hyphenated crate name matches its edge.
    let via_names: BTreeSet<String> = via_names.iter().map(|v| v.replace('-', "_")).collect();
    let target_name = target_name.replace('-', "_");
    let mut visited = BTreeSet::new();
    visited.insert(root_id.to_string());
    let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
    queue.push_back((root_id.to_string(), vec![root_name.to_string()]));

    while let Some((id, path)) = queue.pop_front() {
        let Some((deps, _features)) = meta.nodes.get(&id) else {
            continue;
        };
        for (dep_name, dep_pkg, is_normal) in deps {
            if !is_normal || dep_pkg.is_empty() || via_names.contains(dep_name.as_str()) {
                // A `via_names` node is never entered and never traversed past — a path is only a
                // bypass if it reaches the target WITHOUT going through any named `via` at all.
                continue;
            }
            // Same phantom-edge filter `closure_hits` applies: an edge nothing actually activates
            // is not a real bypass. See `edge_is_active`'s doc.
            if !edge_is_active(meta, &id, dep_name) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(dep_name.clone());
            if dep_name == &target_name {
                return Some(next_path.join(" -> "));
            }
            if visited.insert(dep_pkg.clone()) {
                queue.push_back((dep_pkg.clone(), next_path));
            }
        }
    }
    None
}

/// Which `(crate, offender)` pairs are FULLY waived by `allowed`: a bare `dep`/`path` entry always
/// qualifies; a `via`-narrowed `dep` entry qualifies only when [`find_bypass_path`] finds no path
/// around `via`. Crates that were not found in `cargo metadata` (already warned about by the
/// caller) cannot be via-checked and are treated as NOT covered — a missing root must never read
/// as a satisfied waiver.
fn fully_waived_pairs(
    meta: &Metadata,
    crates: &[PureCrate],
    allowed: &[AllowEntry],
) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for entry in allowed {
        match &entry.via {
            None => {
                out.insert((entry.crate_name.clone(), entry.offender.clone()));
            }
            Some(via_name) => {
                let Some(pc) = crates.iter().find(|c| c.report_name == entry.crate_name) else {
                    continue;
                };
                let Some(root_id) = find_package_id(meta, &pc.dir, &pc.name) else {
                    continue;
                };
                if find_bypass_path(meta, &root_id, &pc.report_name, via_name, &entry.offender)
                    .is_none()
                {
                    out.insert((entry.crate_name.clone(), entry.offender.clone()));
                }
                // else: a bypass exists — the hit(s) stay red, and the bypassing path is already
                // one of the (unfiltered) rows `closure_hits` produced for this crate/offender.
            }
        }
    }
    out
}

pub fn run(root: &Path) -> Report {
    let banned = load_banned_lists(root);
    let allowed = load_allowlist(root);
    let crates = pure_crates(root);

    let meta_json = run_cargo_metadata(&root.join("Cargo.toml"));
    let meta = parse_metadata(&meta_json);
    let fragments = load_test_fragments(root);

    let mut hits = Vec::new();
    for pc in &crates {
        if let Some(id) = find_package_id(&meta, &pc.dir, &pc.name) {
            hits.extend(closure_hits(&meta, &id, &pc.report_name, &banned));
        } else {
            eprintln!(
                "xtask denylist: warning: {} ({}) not found in `cargo metadata` output; skipped",
                pc.name, pc.kind
            );
        }
        hits.extend(own_src_hits(root, pc, &banned, &fragments));
    }

    let waived = fully_waived_pairs(&meta, &crates, &allowed);
    hits.retain(|h| !waived.contains(&(h.crate_name.clone(), h.offender.clone())));

    Report {
        hits,
        crates_scanned: crates.len(),
    }
}

/// Test-only entry point: like [`run_on`], but also applies a synthetic allow-list (never read
/// from `qa/denylist-allow.toml`) so the `via` narrowing can be proven against fixtures
/// independent of the real repo's allow-list contents.
pub fn run_on_with_allow(
    manifest_path: &Path,
    crates: Vec<PureCrate>,
    banned: &BannedLists,
    fragments: &[String],
    allow: Vec<(&str, &str, Option<&str>)>,
) -> Vec<Hit> {
    let meta_json = run_cargo_metadata(manifest_path);
    let meta = parse_metadata(&meta_json);
    let allowed: Vec<AllowEntry> = allow
        .into_iter()
        .map(|(crate_name, offender, via)| AllowEntry {
            crate_name: crate_name.to_string(),
            offender: offender.to_string(),
            via: via.map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            }),
        })
        .collect();
    let waived = fully_waived_pairs(&meta, &crates, &allowed);

    let root = manifest_path.parent().unwrap();
    let mut hits = Vec::new();
    for pc in &crates {
        if let Some(id) = find_package_id(&meta, &pc.dir, &pc.name) {
            hits.extend(closure_hits(&meta, &id, &pc.report_name, banned));
        } else {
            eprintln!(
                "xtask denylist: warning: {} not found in `cargo metadata` output; skipped",
                pc.name
            );
        }
        hits.extend(own_src_hits(root, pc, banned, fragments));
    }
    hits.retain(|h| !waived.contains(&(h.crate_name.clone(), h.offender.clone())));
    hits
}

pub fn run_on(
    manifest_path: &Path,
    crates: Vec<PureCrate>,
    banned: &BannedLists,
    fragments: &[String],
) -> Vec<Hit> {
    let root = manifest_path.parent().unwrap();
    let meta_json = run_cargo_metadata(manifest_path);
    let meta = parse_metadata(&meta_json);
    let mut hits = Vec::new();
    for pc in &crates {
        if let Some(id) = find_package_id(&meta, &pc.dir, &pc.name) {
            hits.extend(closure_hits(&meta, &id, &pc.report_name, banned));
        } else {
            eprintln!(
                "xtask denylist: warning: {} not found in `cargo metadata` output; skipped",
                pc.name
            );
        }
        hits.extend(own_src_hits(root, pc, banned, fragments));
    }
    hits
}

pub fn load_test_fragments_pub(config_root: &Path) -> Vec<String> {
    load_test_fragments(config_root)
}

/// Machine-readable output for `--format=tsv`: one `<crate>\t<offender>\t<via>` line per hit,
/// nothing when clean. This is the seam `scripts/construction-gate/rules.py::rule_source_denylist`
/// reads (when a real cargo workspace is present) to fold this tool's transitive closure into the
/// SAME `source-denylist:<crate>` row the FAST-tier own-src scan already produces, rather than
/// adding a second row for the same invariant.
pub fn print_report_tsv(report: &Report) -> bool {
    for h in &report.hits {
        println!("{}\t{}\t{}", h.crate_name, h.offender, h.via);
    }
    report.hits.is_empty()
}

pub fn print_report(report: &Report) -> bool {
    if report.hits.is_empty() {
        println!(
            "xtask denylist: OK — {} pure-kind crate(s) scanned, 0 banned transitive source(s)",
            report.crates_scanned
        );
        return true;
    }
    println!(
        "xtask denylist: RED — {} pure-kind crate(s) scanned, {} hit(s)\n",
        report.crates_scanned,
        report.hits.len()
    );

    // A compact summary first (one line per crate, its distinct offenders) — the full via-chain
    // table below can run to hundreds of rows on a shared leaf like `libc`, and the summary is
    // what a reviewer reads first.
    let mut by_crate: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for h in &report.hits {
        by_crate
            .entry(h.crate_name.as_str())
            .or_default()
            .insert(h.offender.as_str());
    }
    println!("summary:");
    for (crate_name, offenders) in &by_crate {
        let mut list: Vec<&str> = offenders.iter().copied().collect();
        list.sort_unstable();
        println!("  {crate_name}: {}", list.join(", "));
    }
    println!();

    let w_crate = report
        .hits
        .iter()
        .map(|h| h.crate_name.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let w_off = report
        .hits
        .iter()
        .map(|h| h.offender.len())
        .max()
        .unwrap_or(9)
        .max(9);
    println!(
        "{:w_crate$}  {:w_off$}  via",
        "crate",
        "offender",
        w_crate = w_crate,
        w_off = w_off
    );
    for h in &report.hits {
        println!(
            "{:w_crate$}  {:w_off$}  {}",
            h.crate_name,
            h.offender,
            h.via,
            w_crate = w_crate,
            w_off = w_off
        );
    }
    false
}
