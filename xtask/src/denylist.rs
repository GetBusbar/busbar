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
//! `qa/denylist-allow.toml` is the one waiver seam, and it is a floor CHECKED BOTH WAYS:
//!
//!   * a hit no waiver covers is RED — the ban holds;
//!   * a waiver that matches NO hit is RED too — the offender it excused is gone, so the exception
//!     has outlived the thing it was an exception to. A waiver that can sit in the file forever
//!     without matching anything is one nobody ever has to defend, and it reads to the next
//!     reviewer as a live, reviewed fact about the tree;
//!   * an entry lacking BOTH a `reason` and an `owner` is a hard refusal of the whole run — an
//!     incomplete waiver is worse than none, because it reads as reviewed when it was not.
//!
//! It began empty (section 1.2's hour-0 posture) and is not empty now; the entries in it are live
//! exceptions with an owner and a date, and the both-ways check is what keeps them that way.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::ctx::{Ctx, WalkSpec};
use crate::toml_lite;
use crate::toml_lite::Document;

/// The construction config, workspace-relative — read through the `Ctx` so a plant can change it.
const CONFIG_REL: &str = "qa/construction.toml";

pub struct Hit {
    pub crate_name: String,
    pub offender: String,
    pub via: String,
}

pub struct Report {
    pub hits: Vec<Hit>,
    pub crates_scanned: usize,
    /// Reasons the run could not be TRUSTED, as distinct from reasons it found something. A gate
    /// whose own input vanished — the rule table renamed away, the crates directory unreadable, no
    /// crate matched at all — has proven nothing, and printing "0 hits" for it would publish that
    /// nothing as a pass. Any entry here makes the report RED with no hits at all.
    pub defects: Vec<String>,
    /// Waivers in `qa/denylist-allow.toml` that matched NO hit in this run. An allow-list is a
    /// floor CHECKED BOTH WAYS — the posture `scripts/no-deferral.waivers` already has: an
    /// unwaived hit is red (the offender), and a waiver with nothing to waive is red too (the
    /// offender was resolved, or was never real, and the exception outlived it). A waiver that can
    /// sit in the file forever without matching anything is an exception nobody has to defend, and
    /// the next reviewer reads it as a live, reviewed fact about the tree. Any entry here makes the
    /// report RED, but the hits are still printed: a stale waiver does not invalidate the scan.
    pub stale_waivers: Vec<String>,
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

pub struct BannedLists {
    /// Crate (package) names banned anywhere in a pure crate's transitive normal closure.
    crate_names: BTreeSet<String>,
    /// `std::`/`tokio::` path substrings banned in a pure crate's own `src/`.
    std_paths: Vec<String>,
}

pub(crate) fn load_banned_lists(root: &Path) -> BannedLists {
    banned_lists_of(&toml_lite::parse(&root.join("qa/construction.toml")))
}

/// The same lists off a document SOMEBODY ELSE READ — the form [`run`] uses, so the config it bans
/// from is the one the `Ctx` (and therefore an overlay) shows it.
fn banned_lists_of(doc: &Document) -> BannedLists {
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
///
/// Returns `Err` — never an empty list — when the SCOPING itself is missing: no `kinds`, no
/// `patterns`, or a `crates/` directory that will not list. `toml_lite` has no failing accessor, so
/// a renamed or deleted `[rules.source-denylist]` table reads as an empty list and an unreadable
/// directory reads as no entries; both then produce zero hits over zero crates, which the report
/// would otherwise print as a pass. The construction.toml comment that an empty match list is
/// nothing-to-check is about a KIND GLOB matching no directory (a kind with no crate yet, which is
/// genuinely nothing to check), not about the rule's own configuration disappearing.
pub fn pure_crates(cx: &Ctx, doc: &Document) -> Result<Vec<PureCrate>, String> {
    let config = CONFIG_REL;
    let rule = doc.table("rules.source-denylist");
    let kinds = rule.get_list("kinds");
    if kinds.is_empty() {
        return Err(format!(
            "{config}: [rules.source-denylist].kinds is missing or empty — the denylist has no \
             kinds to scope itself to, so it can prove nothing"
        ));
    }
    if rule.get_list("patterns").is_empty() {
        return Err(format!(
            "{config}: [rules.source-denylist].patterns is missing or empty — the denylist has \
             nothing to ban, so it can prove nothing"
        ));
    }
    let plugin_kinds = doc.table("gate.plugin_kinds");
    let mut out = Vec::new();
    // THE CRATE LIST COMES OFF THE `Ctx`, NOT `std::fs`. Every manifest one directory under
    // `crates/` is one crate; a `crates/` that will not list is the WalkError, which is the same
    // refusal the `read_dir` here used to raise and can now be planted with an overlay.
    let manifests = cx
        .walk(&WalkSpec::new(["crates"]).ext("toml"))
        .map_err(|e| format!("cannot list crates/: {e}"))?;
    let mut entries: Vec<(String, String)> = manifests
        .into_iter()
        .filter_map(|f| {
            let rel = f.rel_str();
            let parts: Vec<&str> = rel.split('/').collect();
            (parts.len() == 3 && parts[0] == "crates" && parts[2] == "Cargo.toml")
                .then(|| (parts[1].to_string(), f.text))
        })
        .collect();
    entries.sort();
    for kind in &kinds {
        let globs = plugin_kinds.get_list(kind);
        for (name, manifest) in &entries {
            let candidate = format!("crates/{name}");
            // A `!`-prefixed glob EXCLUDES, the same reading `dirs_for_globs` gives the same list:
            // `plane` is `crates/busbar-plane-*` minus `crates/busbar-plane-*-*`, because the
            // four-segment form is the DIALECT kind and this rule must scope itself to the kind it
            // names. Applied after the positives, so order in the table does not change the answer.
            let matched = globs
                .iter()
                .filter(|g| !g.starts_with('!'))
                .any(|g| glob_match(g, &candidate));
            let excluded = globs
                .iter()
                .filter_map(|g| g.strip_prefix('!'))
                .any(|g| glob_match(g, &candidate));
            if matched && !excluded {
                out.push(PureCrate {
                    name: crate_manifest_name(manifest, name),
                    dir: cx.abs(&candidate),
                    kind: kind.clone(),
                    report_name: name.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// The `[package] name = "..."` a crate's Cargo.toml actually declares — this can differ from its
/// directory name (`crates/auth-static-plugin` ships as `busbar-auth-static-plugin`), and
/// `cargo metadata` only knows the manifest name.
fn crate_manifest_name(raw: &str, dir_name: &str) -> String {
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
    dir_name.to_string()
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
    // OFFLINE FIRST, BUT NEVER OFFLINE-ONLY. The lockfile is already resolved (checked in) and a
    // denylist audit reads it, so the ordinary run has no reason to touch the network and a flaky
    // registry must not turn a source audit into a network-dependent step.
    //
    // It cannot be the ONLY attempt, though, and that is not a preference. `cargo metadata` with no
    // `--filter-platform` resolves for EVERY target platform, so it wants the `.crate` files of
    // packages this workspace never builds on any host it is built on -- the android and windows
    // shims a transitive dependency declares. `cargo build` and `cargo test` never download those,
    // so a machine's registry cache is missing them until something asks for the whole graph, and
    // `--offline` then fails hard. On a runner that installs a toolchain but has no warm registry
    // this is DETERMINISTIC: every run panicked, the caller read the panic as "the tool did not
    // answer", and all nine source-denylist rows reported UNPROVEN -- an audit reporting silence as
    // an absence of findings, which is the one outcome a gate must never produce.
    //
    // `--filter-platform` would silence the download by narrowing the audit to one platform, which
    // changes what "the transitive closure" means. So the closure stays whole and the fetch is
    // allowed exactly when the cache cannot answer.
    let run = |offline: bool| {
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.arg("metadata").arg("--format-version=1");
        if offline {
            cmd.arg("--offline");
        }
        cmd.arg("--manifest-path")
            .arg(manifest_path)
            .output()
            .unwrap_or_else(|e| panic!("xtask denylist: failed to run `cargo metadata`: {e}"))
    };
    let mut out = run(true);
    if !out.status.success() {
        out = run(false);
    }
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
                reqs.iter()
                    .any(|r| r == &dep_marker || r == &hyphenated || r.starts_with(&strong_forward))
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

            // `dep_name` is the edge's local extern-crate identifier: underscored, and the RENAME
            // if the manifest gave one. `banned.crate_names` holds published package names, which
            // are hyphenated (`async-std`, `hyper-util`). Comparing the two forms directly can
            // never match a banned crate whose name has more than one word, and would also miss
            // one pulled in under a rename — so resolve the edge's package id back to its real
            // `[package] name` and ban on that. Reporting that same name keeps the offender string
            // in the shape `qa/denylist-allow.toml` waivers are written in.
            let dep_pkg_name = meta.names.get(dep_pkg).cloned().unwrap_or_else(|| {
                // No `packages[]` entry for this id (a metadata shape we do not recognize):
                // fall back to the edge identifier rather than skipping the check entirely.
                dep_name.replace('_', "-")
            });

            if banned.crate_names.contains(dep_pkg_name.as_str()) {
                hits.push(Hit {
                    crate_name: root_name.to_string(),
                    offender: dep_pkg_name.clone(),
                    via: next_path.join(" -> "),
                });
            }
            if dep_pkg_name == "tokio" {
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

// `production_lines` and `strip_comment_line` MOVED to `crate::scan` — one scanner for the whole
// crate, so every text gate points at the implementation the denylist's own fixtures already
// drive, instead of the seven copies of `TEST_SCOPE_AWK` the shell carried.
use crate::scan::production_lines;

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
    let mut paths = Vec::new();
    walk_rs_files(&pc.dir.join("src"), &mut paths);
    paths.sort();
    let mut files = Vec::new();
    for f in paths {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(src) = std::fs::read_to_string(&f) else {
            continue;
        };
        files.push((rel, src));
    }
    own_src_hits_over(&files, pc, banned, fragments)
}

/// The own-src scan over files SOMEBODY ELSE LISTED AND READ, as `(rel, text)` pairs — the form
/// [`run`] hands it after walking the `Ctx`, so a planted source file is scanned and a `src/` an
/// overlay emptied is scanned as empty rather than read around through `std::fs`.
fn own_src_hits_over(
    files: &[(String, String)],
    pc: &PureCrate,
    banned: &BannedLists,
    fragments: &[String],
) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (rel, src) in files {
        let rel_with_slashes = format!("/{rel}");
        if is_test_path(&rel_with_slashes, fragments) {
            continue;
        }
        for (lineno, code) in production_lines(src) {
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

impl AllowEntry {
    /// Self-test-only constructor. In production these come from `qa/denylist-allow.toml` and
    /// nowhere else; the self-test needs to build one so the both-ways rule can be proven without
    /// editing the committed allow-list.
    pub(crate) fn for_selftest(crate_name: &str, offender: &str) -> Self {
        Self {
            crate_name: crate_name.to_string(),
            offender: offender.to_string(),
            via: None,
        }
    }
}

/// The load-bearing allow-list check. Any `[[allow]]` entry missing `reason` or `owner` refuses the
/// ENTIRE run rather than silently accepting a half-filled waiver. Whether each entry still has
/// anything to waive is the other half, and is decided by [`stale_waivers`] once the hits are known.
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

/// The other direction of the allow-list check: which waivers had nothing to waive.
///
/// `hits` must be the UNFILTERED hit list — the rows as found, before `fully_waived_pairs` removes
/// the waived ones — because a waiver that is doing its job is precisely one whose pair is present
/// there and absent afterwards. Judging staleness on the filtered list would call every working
/// waiver stale.
///
/// A `via`-narrowed entry whose bypass check FAILED is not stale: its (crate, offender) pair is in
/// the hit list, the hits stayed red, and the entry is a live exception that does not currently
/// apply. That is already reported by the hits themselves and is not reported again here.
pub(crate) fn stale_waivers(allowed: &[AllowEntry], hits: &[Hit]) -> Vec<String> {
    let present: BTreeSet<(&str, &str)> = hits
        .iter()
        .map(|h| (h.crate_name.as_str(), h.offender.as_str()))
        .collect();
    allowed
        .iter()
        .filter(|e| !present.contains(&(e.crate_name.as_str(), e.offender.as_str())))
        .map(|e| {
            format!(
                "qa/denylist-allow.toml: the waiver for crate={:?} dep/path={:?} matched no hit — \
                 the offender it excuses is not in this tree. Either it was resolved (delete the \
                 waiver; the ban now holds on its own) or it was never real (delete it; it was \
                 never an exception to anything). A waiver nobody has to defend reads to the next \
                 reviewer as a live, reviewed fact about the tree.",
                e.crate_name, e.offender
            )
        })
        .collect()
}

/// THE RUN READS THE TREE THROUGH THE `Ctx` (audit F50).
///
/// It used to take a `&Path` and reach for `std::fs` under it: the config, the crate listing and
/// every source file. Nothing an overlay planted was visible, so the only way to prove the gate
/// could go red was to check a whole second tree into `xtask/fixtures/` and re-root the run onto
/// it — which is a proof about a fixture, and drifts from the tree the gate actually judges. The
/// one input still read outside the `Ctx` is `cargo metadata`, which needs a real manifest on a
/// real disk; that is why the resolve-graph half keeps its fixture workspaces.
pub fn run(cx: &Ctx) -> Report {
    let root = cx.root();
    let config = match cx.read(CONFIG_REL) {
        Ok(text) => toml_lite::parse_text(&text),
        Err(e) => {
            return Report {
                hits: Vec::new(),
                crates_scanned: 0,
                defects: vec![format!(
                    "{CONFIG_REL} could not be read ({e}), so the denylist has no kinds, no \
                     patterns and nothing to prove"
                )],
                stale_waivers: Vec::new(),
            }
        }
    };
    let banned = banned_lists_of(&config);
    let allowed = load_allowlist(root);
    let crates = match pure_crates(cx, &config) {
        Ok(crates) if crates.is_empty() => {
            // Every pure kind's glob matched nothing. On a tree that has planes, hooks and auth
            // crates this can only mean the scan was pointed somewhere it was not meant to be, and
            // a scan of nothing is not a clean bill of health.
            return Report {
                hits: Vec::new(),
                crates_scanned: 0,
                defects: vec![format!(
                    "no crate under {}/crates matched any pure kind's glob — nothing was scanned, \
                     so nothing was proven",
                    root.display()
                )],
                stale_waivers: Vec::new(),
            };
        }
        Ok(crates) => crates,
        Err(defect) => {
            return Report {
                hits: Vec::new(),
                crates_scanned: 0,
                defects: vec![defect],
                stale_waivers: Vec::new(),
            }
        }
    };

    let meta_json = run_cargo_metadata(&root.join("Cargo.toml"));
    let meta = parse_metadata(&meta_json);
    let fragments = config.table("gate").get_list("test_path_fragments");

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
        let src_root = format!("crates/{}/src", pc.report_name);
        let files: Vec<(String, String)> = if cx.exists(&src_root) {
            match cx.walk(&WalkSpec::new([src_root.clone()]).ext("rs")) {
                Ok(fs) => fs.into_iter().map(|f| (f.rel_str(), f.text)).collect(),
                Err(e) => {
                    return Report {
                        hits: Vec::new(),
                        crates_scanned: 0,
                        defects: vec![format!(
                            "{src_root} would not list ({e}) — a crate whose source cannot be read \
                             is scanned as zero files, and zero files carry no banned path"
                        )],
                        stale_waivers: Vec::new(),
                    }
                }
            }
        } else {
            Vec::new()
        };
        hits.extend(own_src_hits_over(&files, pc, &banned, &fragments));
    }

    // Both directions, off the SAME unfiltered hit list: which waivers are doing work, and which
    // have nothing left to do.
    let stale = stale_waivers(&allowed, &hits);
    let waived = fully_waived_pairs(&meta, &crates, &allowed);
    hits.retain(|h| !waived.contains(&(h.crate_name.clone(), h.offender.clone())));

    Report {
        hits,
        crates_scanned: crates.len(),
        defects: Vec::new(),
        stale_waivers: stale,
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
    // A defect goes to stderr, not into the hit rows: the row format is `<crate>\t<offender>\t<via>`
    // and a reader keys it by crate name, so a fake crate name would either be dropped silently or
    // invent a crate. The non-zero exit is what carries the refusal.
    for d in &report.defects {
        eprintln!("xtask denylist: RED — {d}");
    }
    // A stale waiver goes to stderr for the same reason a defect does: the row format is keyed by
    // crate name, and a stale waiver names a crate/offender pair that produced no row.
    for s in &report.stale_waivers {
        eprintln!("xtask denylist: RED — {s}");
    }
    for h in &report.hits {
        println!("{}\t{}\t{}", h.crate_name, h.offender, h.via);
    }
    report.defects.is_empty() && report.hits.is_empty() && report.stale_waivers.is_empty()
}

pub fn print_report(report: &Report) -> bool {
    if !report.defects.is_empty() {
        println!(
            "xtask denylist: RED — the scan could not be trusted, so it reports no result rather \
             than a pass:"
        );
        for d in &report.defects {
            println!("  {d}");
        }
        return false;
    }
    // Printed before the hits, and on its own if there are none: a waiver with nothing to waive is
    // red whether or not the scan found anything else, and "0 hits" underneath a stale waiver is
    // exactly the reading that lets an exception outlive the thing it excused.
    if !report.stale_waivers.is_empty() {
        println!(
            "xtask denylist: RED — {} stale waiver(s) in qa/denylist-allow.toml:",
            report.stale_waivers.len()
        );
        for s in &report.stale_waivers {
            println!("  {s}");
        }
        println!();
    }
    if report.hits.is_empty() {
        if report.stale_waivers.is_empty() {
            println!(
                "xtask denylist: OK — {} pure-kind crate(s) scanned, 0 banned transitive source(s)",
                report.crates_scanned
            );
            return true;
        }
        println!(
            "xtask denylist: {} pure-kind crate(s) scanned, 0 banned transitive source(s) — but the \
             allow-list is not clean, so this run is RED",
            report.crates_scanned
        );
        return false;
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
