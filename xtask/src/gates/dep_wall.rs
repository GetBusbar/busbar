//! `dep-wall` — THE DEPENDENCY WALL, AS A DRAIN-ONLY LEDGER (DECISIONS #40(a); THE DESIGN:
//! connections — "no plugin opens a socket, dials, binds or does TLS").
//!
//! Every plugin reaches the network through a need, and the connector does the rest. So no plugin's
//! compiled closure may carry a socket or TLS stack of its own: `hyper-util`, `reqwest`, `rustls`,
//! `tokio-rustls` and `socket2` by name, `tokio` asked for its `net` feature, `redis` asked for its
//! async connection (`aio`), and `std::net` / `tokio::net` written in a plugin's own source. The
//! exceptions are the connector (a cleanliness crate, never in scope) and the transport CARRIERS,
//! whose whole job is the socket.
//!
//! The tree does not meet the wall yet, and pretending otherwise is not an option (Law 9: a ratchet
//! armed at today's number). `qa/dep-wall.ledger` pins every offender measured when this gate was
//! armed, one `crate<TAB>offender` per line, and the gate holds the ledger to the tree BOTH ways:
//!
//! * a measured `(crate, offender)` the ledger does not pin is RED — a NEW offender, never pinned
//!   by editing the ledger in the same change that introduced it;
//! * a pinned line the tree no longer measures is RED too — the drain happened, so the line is
//!   struck in the SAME commit that drained it (the pin only goes down).
//!
//! It reaches zero at the step that closes the coexistence window, and the ledger is deleted then.
//!
//! SCOPE. The plugin-kind crates `qa/construction.toml`'s `[gate.plugin_kinds]` names, the legacy
//! plane crates listed in [`LEGACY`], and every external plugin the workspace resolves from its own
//! repository (a `GetBusbar` git source). The closure is the NORMAL-edge closure `cargo metadata`
//! resolves, with optional edges that nothing activates left out.
//!
//! OWN SOURCE. `std::net` and `tokio::net` are no crate edge, so the closure walk cannot see them:
//! every in-scope crate's own source is read for them as PATHS ([`banned_paths`]: `use` trees
//! expanded, renames followed, expressions and macro bodies read), never as a substring. A plugin
//! pinned from its own repository is read from the checkout `cargo metadata` names for its pin
//! (with the tree's base layer and any plant at `crates/<name>/src` on top); a pinned plugin whose
//! source cannot be read is a refusal naming it, never a crate passed unread.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use proc_macro2::{Delimiter, Group, Spacing, TokenStream, TokenTree};

use serde_json::Value;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_SCOPE: &str = "dep-wall:scope";
pub const ROW_NEW: &str = "dep-wall:new-offender";
pub const ROW_DRAINED: &str = "dep-wall:drained";

/// The ledger, workspace-relative.
pub const LEDGER: &str = "qa/dep-wall.ledger";
const CONFIG: &str = "qa/construction.toml";

/// Crates that are a socket or TLS stack by name.
const BANNED_CRATES: &[&str] = &["hyper-util", "reqwest", "rustls", "tokio-rustls", "socket2"];

/// Paths a plugin's own production source may not name.
const BANNED_PATHS: &[&str] = &["std::net", "tokio::net"];

/// The legacy plane crates: planes that predate their plugin crate and still ship in-tree.
///
/// `busbar-llm-codec` and `busbar-voice-codec` are not here: owner ruling R7 (2026-09-27, #39: no
/// `busbar-*-codec` crate) folded both into their plane crate's own `codec` module -- a pure move,
/// no item changed shape crossing it (`qa/construction.toml`'s `[gate.plane_codec_crates]` header
/// carries the same ruling). `busbar-plane-llm` and `busbar-plane-streaming` are already
/// `gate.plugin_kinds.plane`'s own rows, so the folded-in `codec` module scans as part of them; there
/// is no second source root for THIS wall to add either.
///
/// `busbar-mcp` is not here either (P3 DEL-MCP, ARCHITECT 2026-10-05): the engine is deleted, and the
/// mcp plane is its door crate `busbar-plane-mcp`, a `gate.plugin_kinds.plane` row this wall already
/// scans. Its eight pins in the ledger drained with it and are struck there. `busbar-a2a` likewise
/// (FLIP-A2A): the a2a plane is its door crate `busbar-plane-a2a`, a `gate.plugin_kinds.plane` row.
/// `busbar-voice` likewise (FLIP-STREAMING).
const LEGACY: &[&str] = &["crates/busbar-llm"];

/// The external source a plugin repository resolves from.
const EXTERNAL_SOURCE: &str = "git+https://github.com/GetBusbar/";

/// Fewer roots than this is not this workspace: a scope that small proves the wall vacuously.
const MIN_ROOTS: usize = 10;

/// One package as `cargo metadata` states it.
struct Pkg {
    name: String,
    /// `None` for a workspace member.
    source: Option<String>,
    manifest_path: String,
    /// `(name, features asked, optional, normal)` per declared dependency.
    deps: Vec<(String, Vec<String>, bool, bool)>,
    features: BTreeMap<String, Vec<String>>,
}

/// A resolve node: its normal edges `(local name, package id)` and its active features.
type Node = (Vec<(String, String)>, Vec<String>);

/// The measured wall: offending crate -> what it reaches.
pub type Offenders = BTreeMap<String, BTreeSet<String>>;

/// One measurement of the wall.
pub struct Measured {
    pub offenders: Offenders,
    /// How many crates are in scope.
    pub roots: usize,
    /// Every package name the workspace resolves.
    pub names: BTreeSet<String>,
    /// Every in-scope crate whose own source could not be read, named with why: a refusal, never
    /// a crate passed unread.
    pub unread: Vec<String>,
}

/// Where an in-scope crate's own source is read.
enum Source {
    /// A workspace member, at this directory of the tree.
    Tree(String),
    /// A plugin pinned from its own repository: the `git+` source it resolves from, and the `src/`
    /// beside the manifest `cargo metadata` names in the checkout cargo fetched for the pin.
    Pinned { source: String, checkout: PathBuf },
}

/// Exemptions and pins the ledger states.
#[derive(Default)]
struct Ledger {
    carriers: BTreeSet<String>,
    pinned: BTreeSet<(String, String)>,
    errors: Vec<String>,
}

fn read_ledger(text: &str) -> Ledger {
    let mut l = Ledger::default();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = t.split('\t').collect();
        match parts.as_slice() {
            ["carrier", name] => {
                l.carriers.insert((*name).to_string());
            }
            [krate, offender] => {
                l.pinned
                    .insert(((*krate).to_string(), (*offender).to_string()));
            }
            _ => l.errors.push(format!(
                "{LEDGER}:{}: `{t}` is neither `carrier<TAB>crate` nor `crate<TAB>offender`",
                i + 1
            )),
        }
    }
    l
}

/// A single-`*` glob, the shape `[gate.plugin_kinds]` uses.
fn glob(pattern: &str, candidate: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == candidate,
        Some((a, b)) => {
            candidate.len() >= a.len() + b.len()
                && candidate.starts_with(a)
                && candidate.ends_with(b)
        }
    }
}

/// The in-tree plugin-kind directory globs, every kind.
fn kind_globs(cx: &Ctx) -> Result<Vec<String>, String> {
    let doc = crate::toml_lite::parse_text(&cx.read(CONFIG)?);
    let table = doc.table("gate.plugin_kinds");
    let globs: Vec<String> = [
        "plane",
        "transport",
        "store",
        "secret",
        "hook",
        "auth",
        "export",
    ]
    .iter()
    .flat_map(|k| table.get_list(k))
    .collect();
    if globs.is_empty() {
        return Err(format!("{CONFIG}: [gate.plugin_kinds] names no directory"));
    }
    Ok(globs)
}

/// Whether the optional edge `from -> dep` is one some active feature of `from` turns on.
fn active(pkg: &Pkg, node_features: &[String], dep: &str) -> bool {
    let Some((_, _, optional, _)) = pkg.deps.iter().find(|d| d.0 == dep) else {
        return true;
    };
    if !optional {
        return true;
    }
    let marker = format!("dep:{dep}");
    let forward = format!("{dep}/");
    node_features.iter().any(|f| {
        f == dep
            || pkg.features.get(f).is_some_and(|reqs| {
                reqs.iter()
                    .any(|r| *r == marker || r == dep || r.starts_with(&forward))
            })
    })
}

/// What `pkg` itself asks for that the wall bans.
fn asks(pkg: &Pkg) -> Vec<String> {
    let mut out = Vec::new();
    if BANNED_CRATES.contains(&pkg.name.as_str()) {
        out.push(pkg.name.clone());
    }
    for (name, features, _, normal) in &pkg.deps {
        if !normal {
            continue;
        }
        let asked = |f: &str| features.iter().any(|x| x == f);
        if name == "tokio" && (asked("net") || asked("full")) {
            out.push("tokio (net)".to_string());
        }
        if name == "redis" && (asked("aio") || features.iter().any(|x| x.ends_with("-comp"))) {
            out.push("redis (aio)".to_string());
        }
    }
    out
}

/// THE MEASUREMENT: every in-scope crate and what its closure reaches past the wall.
pub fn measure(cx: &Ctx, carriers: &BTreeSet<String>) -> Result<Measured, String> {
    let json: Value = serde_json::from_str(&cx.cargo_metadata("Cargo.toml")?)
        .map_err(|e| format!("`cargo metadata` output did not parse: {e}"))?;
    let mut pkgs: BTreeMap<String, Pkg> = BTreeMap::new();
    for p in json["packages"].as_array().cloned().unwrap_or_default() {
        let deps = p["dependencies"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|d| {
                let local = d["rename"]
                    .as_str()
                    .or_else(|| d["name"].as_str())
                    .unwrap_or_default()
                    .to_string();
                let features = d["features"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect();
                (
                    local,
                    features,
                    d["optional"].as_bool().unwrap_or(false),
                    d["kind"].is_null(),
                )
            })
            .collect();
        let features = p["features"]
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| {
                        let reqs = v
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|s| s.as_str().map(str::to_string))
                            .collect();
                        (k.clone(), reqs)
                    })
                    .collect()
            })
            .unwrap_or_default();
        pkgs.insert(
            p["id"].as_str().unwrap_or_default().to_string(),
            Pkg {
                name: p["name"].as_str().unwrap_or_default().to_string(),
                source: p["source"].as_str().map(str::to_string),
                manifest_path: p["manifest_path"].as_str().unwrap_or_default().to_string(),
                deps,
                features,
            },
        );
    }
    // id -> (normal deps (local name, pkg id), active features)
    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    for n in json["resolve"]["nodes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let deps = n["deps"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|d| {
                d["dep_kinds"]
                    .as_array()
                    .is_none_or(|ks| ks.iter().any(|k| k["kind"].is_null()))
            })
            .map(|d| {
                (
                    d["name"].as_str().unwrap_or_default().replace('_', "-"),
                    d["pkg"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let features = n["features"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|f| f.as_str().map(str::to_string))
            .collect();
        nodes.insert(
            n["id"].as_str().unwrap_or_default().to_string(),
            (deps, features),
        );
    }

    // THE ROOTS: in-tree plugin-kind and legacy crates, and every external plugin.
    let globs = kind_globs(cx)?;
    let root = cx.root().to_string_lossy().to_string();
    let mut roots: Vec<(String, Source)> = Vec::new();
    for (id, p) in &pkgs {
        if carriers.contains(&p.name) {
            continue;
        }
        match &p.source {
            None => {
                let dir = p
                    .manifest_path
                    .strip_prefix(&root)
                    .unwrap_or(&p.manifest_path)
                    .trim_start_matches('/')
                    .trim_end_matches("/Cargo.toml")
                    .to_string();
                if globs.iter().any(|g| glob(g, &dir)) || LEGACY.contains(&dir.as_str()) {
                    roots.push((id.clone(), Source::Tree(dir)));
                }
            }
            Some(src) if src.starts_with(EXTERNAL_SOURCE) => roots.push((
                id.clone(),
                Source::Pinned {
                    source: src.clone(),
                    checkout: Path::new(&p.manifest_path)
                        .parent()
                        .map(|d| d.join("src"))
                        .unwrap_or_default(),
                },
            )),
            Some(_) => {}
        }
    }
    let mut out = Offenders::new();
    let mut unread = Vec::new();
    for (root_id, source) in &roots {
        let root_name = pkgs[root_id].name.clone();
        let mut hits = BTreeSet::new();
        let mut seen = BTreeSet::from([root_id.clone()]);
        let mut queue = VecDeque::from([root_id.clone()]);
        while let Some(id) = queue.pop_front() {
            let Some(pkg) = pkgs.get(&id) else { continue };
            hits.extend(asks(pkg));
            let Some((deps, features)) = nodes.get(&id) else {
                continue;
            };
            for (dep, dep_id) in deps {
                if active(pkg, features, dep) && seen.insert(dep_id.clone()) {
                    queue.push_back(dep_id.clone());
                }
            }
        }
        match own_source(cx, &root_name, source) {
            Ok(files) => {
                for (rel, text) in files {
                    if rel.contains("/tests/") || rel.ends_with("_tests.rs") {
                        continue;
                    }
                    hits.extend(banned_paths(&text).into_iter().map(str::to_string));
                }
            }
            Err(why) => unread.push(why),
        }
        if !hits.is_empty() {
            out.entry(root_name).or_default().extend(hits);
        }
    }
    Ok(Measured {
        offenders: out,
        roots: roots.len(),
        names: pkgs.values().map(|p| p.name.clone()).collect(),
        unread,
    })
}

/// A crate's own `.rs` source, as `(tree-spelled path, text)`, sorted.
///
/// A workspace member is read through `cx` at its directory. A plugin pinned from its own
/// repository is read from the checkout `cargo metadata` names, with whatever `cx` shows at its
/// mount dir `crates/<name>/src` (the base layer, or a plant) laid on top, file by file. A pinned
/// plugin that yields no source file, or a file that does not read, is an `Err` naming the plugin
/// and its source: the wall is never reported for a crate it did not read.
fn own_source(cx: &Ctx, name: &str, source: &Source) -> Result<Vec<(String, String)>, String> {
    match source {
        Source::Tree(dir) => cx
            .walk(
                &WalkSpec::new([format!("{dir}/src")])
                    .ext("rs")
                    .allow_empty(),
            )
            .map(|files| files.into_iter().map(|f| (f.rel_str(), f.text)).collect())
            .map_err(|e| format!("`{name}` at {dir}: its source cannot be read: {e}")),
        Source::Pinned { source, checkout } => {
            let at = format!("crates/{name}/src");
            let refuse = |why: String| {
                format!(
                    "`{name}` is pinned from its own repository ({source}) and its source cannot be \
                     read: {why}"
                )
            };
            // The tree lays the crate itself (the base layer, or a crate on disk at its mount).
            let laid = cx.in_base(format!("crates/{name}")) || cx.abs(&at).is_dir();
            let mut files: BTreeMap<String, String> = BTreeMap::new();
            match checkout_sources(checkout) {
                Ok(read) => {
                    for (rel, text) in read {
                        files.insert(format!("{at}/{rel}"), text);
                    }
                }
                Err(why) if !laid => return Err(refuse(why)),
                Err(_) => {}
            }
            if let Ok(shown) = cx.walk(&WalkSpec::new([at.clone()]).ext("rs").allow_empty()) {
                for f in shown {
                    files.insert(f.rel_str(), f.text);
                }
            }
            if files.is_empty() {
                return Err(refuse(format!(
                    "{} holds no `.rs` file",
                    checkout.display()
                )));
            }
            Ok(files.into_iter().collect())
        }
    }
}

/// Every `.rs` file under a checkout's `src/`, relative to it. Build output and dot-directories are
/// not source. A directory or file that does not read is an `Err` naming it.
fn checkout_sources(src: &Path) -> Result<Vec<(String, String)>, String> {
    fn visit(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
        let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file == "target" || file.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                visit(&path, base, out)?;
            } else if path.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let rel = path.strip_prefix(base).unwrap_or(&path);
                out.push((rel.to_string_lossy().replace('\\', "/"), text));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(src, src, &mut out)?;
    Ok(out)
}

/// THE BANNED PATHS ONE SOURCE FILE NAMES, read as PATHS, not as text.
///
/// The file is lexed and every path is read segment by segment: a `use` tree is expanded
/// (`use std::{io, net::TcpStream}` names `std::net::TcpStream`), a leading `::` is the same path, a
/// path written in an expression, a type or a macro body counts as one written in a `use`, a
/// rename of a banned path's prefix (`use std as s;`, `extern crate std as s;`) is followed where
/// the file uses it, and a glob over such a prefix (`use std::*;`) brings the banned module into
/// scope and counts. A comment or a string literal names no path. An item under `#[cfg(test)]` (or
/// `cfg(all(test, ..))`) or `#[test]` is test code, not the plugin's production source. A file
/// that does not lex falls back to the line scan, which reads more, never less.
pub fn banned_paths(text: &str) -> BTreeSet<&'static str> {
    let Ok(stream) = TokenStream::from_str(text) else {
        let mut hits = BTreeSet::new();
        for (_, line) in crate::scan::production_lines(text) {
            hits.extend(BANNED_PATHS.iter().filter(|p| line.contains(**p)));
        }
        return hits;
    };
    let tokens: Vec<TokenTree> = strip_tests(stream).into_iter().collect();
    // Two passes: a rename is in force wherever the file uses it, before or after the `use`.
    let mut first = PathScan::default();
    first.walk(&tokens, None);
    let mut second = PathScan {
        aliases: first.aliases,
        hits: BTreeSet::new(),
    };
    second.walk(&tokens, None);
    second.hits
}

fn segments(path: &str) -> Vec<&str> {
    path.split("::").collect()
}

/// Is this attribute body (`cfg(test)`, `test`, `tokio::test`, `cfg(all(test, ..))`) a test mark?
fn is_test_attr(body: &TokenStream) -> bool {
    let toks: Vec<TokenTree> = body.clone().into_iter().collect();
    let idents_only = toks.iter().all(|t| match t {
        TokenTree::Ident(_) => true,
        TokenTree::Punct(p) => p.as_char() == ':',
        _ => false,
    });
    if idents_only {
        return matches!(toks.last(), Some(TokenTree::Ident(i)) if i == "test");
    }
    let [TokenTree::Ident(cfg), TokenTree::Group(g)] = toks.as_slice() else {
        return false;
    };
    if cfg != "cfg" || g.delimiter() != Delimiter::Parenthesis {
        return false;
    }
    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
    match inner.as_slice() {
        [TokenTree::Ident(t)] => t == "test",
        [TokenTree::Ident(all), TokenTree::Group(args)] if all == "all" => args
            .stream()
            .into_iter()
            .any(|t| matches!(t, TokenTree::Ident(i) if i == "test")),
        _ => false,
    }
}

/// The token stream with every test-marked item removed: the attribute, the attributes after it,
/// and the item up to its first top-level `;` or `{ .. }` body. An inner `#![cfg(test)]` empties
/// the scope it opens.
fn strip_tests(stream: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = stream.into_iter().collect();
    let attr_at = |i: usize| -> Option<(usize, bool)> {
        let TokenTree::Punct(hash) = toks.get(i)? else {
            return None;
        };
        if hash.as_char() != '#' {
            return None;
        }
        let (inner, at) = match toks.get(i + 1)? {
            TokenTree::Punct(bang) if bang.as_char() == '!' => (true, i + 2),
            _ => (false, i + 1),
        };
        let TokenTree::Group(g) = toks.get(at)? else {
            return None;
        };
        (g.delimiter() == Delimiter::Bracket && is_test_attr(&g.stream()))
            .then_some((at + 1 - i, inner))
    };
    let mut out: Vec<TokenTree> = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if let Some((len, inner)) = attr_at(i) {
            if inner {
                return TokenStream::new();
            }
            i += len;
            // Skip the item: further attributes, then up to its body or its `;`.
            while i < toks.len() {
                match &toks[i] {
                    TokenTree::Punct(p) if p.as_char() == ';' => {
                        i += 1;
                        break;
                    }
                    TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            continue;
        }
        match &toks[i] {
            TokenTree::Group(g) => {
                let mut kept = Group::new(g.delimiter(), strip_tests(g.stream()));
                kept.set_span(g.span());
                out.push(TokenTree::Group(kept));
            }
            t => out.push(t.clone()),
        }
        i += 1;
    }
    out.into_iter().collect()
}

/// The path reader [`banned_paths`] runs: renames of a banned path's prefix, and the hits.
#[derive(Default)]
struct PathScan {
    aliases: BTreeMap<String, Vec<String>>,
    hits: BTreeSet<&'static str>,
}

impl PathScan {
    /// `path` with a leading rename resolved and a trailing `self` dropped.
    fn expand(&self, path: &[String]) -> Vec<String> {
        let mut full: Vec<String> = match path.split_first() {
            Some((head, rest)) => match self.aliases.get(head) {
                Some(target) => target.iter().chain(rest).cloned().collect(),
                None => path.to_vec(),
            },
            None => Vec::new(),
        };
        if full.last().is_some_and(|s| s == "self") {
            full.pop();
        }
        full
    }

    /// Record every banned path `path` names, or every one it reaches when it is a glob.
    fn judge(&mut self, path: &[String], glob: bool) {
        if path.is_empty() {
            return;
        }
        let full = self.expand(path);
        for banned in BANNED_PATHS {
            let segs = segments(banned);
            let names = full.len() >= segs.len() && full.iter().zip(&segs).all(|(a, b)| a == b);
            let reaches =
                glob && segs.len() > full.len() && full.iter().zip(&segs).all(|(a, b)| a == b);
            if names || reaches {
                self.hits.insert(*banned);
            }
        }
    }

    /// `name` now spells `path`, when `path` is a strict prefix of a banned path.
    fn rename(&mut self, name: String, path: &[String]) {
        let full = self.expand(path);
        let prefix = BANNED_PATHS.iter().any(|b| {
            let segs = segments(b);
            !full.is_empty()
                && full.len() < segs.len()
                && full.iter().zip(&segs).all(|(a, b)| a == b)
        });
        if prefix {
            self.aliases.insert(name, full);
        }
    }

    /// Read `toks` for paths. `tree` is the prefix of the `use` tree group they are the body of.
    fn walk(&mut self, toks: &[TokenTree], tree: Option<&[String]>) {
        let start = || tree.map(<[String]>::to_vec).unwrap_or_default();
        let mut chain = start();
        // A `::` was just read (or a use-tree group opened): the next identifier extends `chain`.
        let mut sep = tree.is_some();
        let mut i = 0;
        while i < toks.len() {
            match &toks[i] {
                TokenTree::Ident(id) => {
                    let word = id.to_string();
                    let word = word.strip_prefix("r#").unwrap_or(&word).to_string();
                    if sep {
                        chain.push(word);
                    } else if word == "as" && !chain.is_empty() {
                        self.judge(&chain, false);
                        if let Some(TokenTree::Ident(name)) = toks.get(i + 1) {
                            self.rename(name.to_string(), &chain);
                            i += 1;
                        }
                        chain.clear();
                    } else {
                        self.judge(&chain, false);
                        chain = vec![word];
                    }
                    sep = false;
                }
                TokenTree::Punct(p)
                    if p.as_char() == ':'
                        && p.spacing() == Spacing::Joint
                        && matches!(toks.get(i + 1), Some(TokenTree::Punct(q)) if q.as_char() == ':') =>
                {
                    sep = true;
                    i += 2;
                    continue;
                }
                TokenTree::Punct(p) if p.as_char() == '*' && sep && !chain.is_empty() => {
                    self.judge(&chain, true);
                    chain.clear();
                    sep = false;
                }
                TokenTree::Group(g)
                    if g.delimiter() == Delimiter::Brace && sep && !chain.is_empty() =>
                {
                    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                    self.walk(&inner, Some(chain.as_slice()));
                    chain.clear();
                    sep = false;
                }
                TokenTree::Punct(p) if p.as_char() == ',' && tree.is_some() => {
                    self.judge(&chain, false);
                    chain = start();
                    sep = true;
                }
                TokenTree::Group(g) => {
                    self.judge(&chain, false);
                    chain.clear();
                    sep = false;
                    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                    self.walk(&inner, None);
                }
                _ => {
                    self.judge(&chain, false);
                    chain.clear();
                    sep = false;
                }
            }
            i += 1;
        }
        self.judge(&chain, false);
    }
}

/// The first plugin `cargo metadata` resolves from its own repository that is no carrier and that
/// nothing lays in the tree (no crate on disk, no base layer at `crates/<name>`): the self-test's
/// pinned subject, read from its checkout alone.
fn pinned_unlaid(cx: &Ctx, ledger: &Ledger) -> Option<String> {
    let json: Value = serde_json::from_str(&cx.cargo_metadata("Cargo.toml").ok()?).ok()?;
    json["packages"]
        .as_array()?
        .iter()
        .filter(|p| {
            p["source"]
                .as_str()
                .is_some_and(|s| s.starts_with(EXTERNAL_SOURCE))
        })
        .filter_map(|p| p["name"].as_str())
        .find(|n| !ledger.carriers.contains(*n) && !cx.is_dir(format!("crates/{n}")))
        .map(str::to_string)
}

pub struct DepWallGate;

impl Gate for DepWallGate {
    fn name(&self) -> &'static str {
        "dep-wall"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_SCOPE.into(), ROW_NEW.into(), ROW_DRAINED.into()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let ledger = read_ledger(&cx.read(LEDGER).unwrap_or_default());
        let Measured {
            offenders: measured,
            roots,
            names,
            unread,
        } = match measure(cx, &ledger.carriers) {
            Ok(m) => m,
            Err(e) => {
                let why = format!("the wall could not be measured: {e}");
                return Verdict::of(vec![
                    Row::fail(ROW_SCOPE, "the dependency wall is measured", why.clone()),
                    Row::fail(
                        ROW_NEW,
                        "no plugin closure reaches past the wall anew",
                        why.clone(),
                    ),
                    Row::fail(ROW_DRAINED, "every pinned offender is still measured", why),
                ]);
            }
        };
        let mut rows = Vec::new();
        let mut scope = ledger.errors.clone();
        scope.extend(unread);
        if roots < MIN_ROOTS {
            scope.push(format!(
                "{roots} crate(s) in scope, under the floor of {MIN_ROOTS}: a scope that small \
                 proves the wall vacuously"
            ));
        }
        for c in &ledger.carriers {
            if !c.contains("transport") {
                scope.push(format!(
                    "`{c}` is exempted as a carrier and is not a transport crate"
                ));
            } else if !names.contains(c) {
                scope.push(format!(
                    "`{c}` is exempted as a carrier and the workspace resolves no such crate: strike \
                     the exemption"
                ));
            }
        }
        rows.push(if scope.is_empty() {
            Row::pass(
                ROW_SCOPE,
                "the dependency wall is measured",
                format!(
                    "{roots} crate(s) in scope, {} carrier(s) exempt",
                    ledger.carriers.len()
                ),
            )
        } else {
            Row::fail(
                ROW_SCOPE,
                "the dependency wall is measured",
                scope.join(" | "),
            )
        });
        let now: BTreeSet<(String, String)> = measured
            .iter()
            .flat_map(|(c, os)| os.iter().map(move |o| (c.clone(), o.clone())))
            .collect();
        let new: Vec<String> = now
            .difference(&ledger.pinned)
            .map(|(c, o)| {
                format!(
                    "new-offender\t{c}\t{c} reaches `{o}` and {LEDGER} does not pin it. No plugin \
                     opens a socket, dials, binds or does TLS: reach the network through a need, \
                     and the connector does the rest"
                )
            })
            .collect();
        rows.push(if new.is_empty() {
            Row::pass(
                ROW_NEW,
                "no plugin closure reaches past the wall anew",
                format!("{} pinned offence(s), none new", ledger.pinned.len()),
            )
        } else {
            Row::fail(
                ROW_NEW,
                "a plugin closure reaches past the wall",
                format!("{} finding(s): {}", new.len(), new.join(" | ")),
            )
        });
        let drained: Vec<String> = ledger
            .pinned
            .difference(&now)
            .map(|(c, o)| {
                format!(
                    "drained\t{c}\t{c} no longer reaches `{o}`: strike `{c}\t{o}` from {LEDGER} in \
                     the commit that drained it — the pin only goes down"
                )
            })
            .collect();
        rows.push(if drained.is_empty() {
            Row::pass(
                ROW_DRAINED,
                "every pinned offender is still measured",
                format!("{} pinned, all live", ledger.pinned.len()),
            )
        } else {
            Row::fail(
                ROW_DRAINED,
                "a pinned offender is gone and its pin still stands",
                format!("{} finding(s): {}", drained.len(), drained.join(" | ")),
            )
        });
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the wall is measured and matches its ledger",
            &[ROW_SCOPE, ROW_NEW, ROW_DRAINED],
        ));
        // A NEW OFFENDER: a plugin's own source names a socket path the ledger never pinned.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-decisions/src/planted_socket.rs",
            "pub fn dial() { let _ = std::net::TcpStream::connect(\"127.0.0.1:1\"); }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a plugin that names a socket path it was never pinned for is a new offender",
            &[ROW_NEW],
            ov,
            &["new-offender", "busbar-plane-decisions", "std::net"],
        ));
        // A GROUPED IMPORT: `std::{io, net::TcpStream}` names `std::net` as a path, not as text.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-llm/src/planted_grouped_socket.rs",
            "use std::{io, net::TcpStream};\n\
             pub fn dial() -> io::Result<TcpStream> { TcpStream::connect(\"127.0.0.1:1\") }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a plugin that reaches a socket through a grouped import is a new offender",
            &[ROW_NEW],
            ov,
            &["new-offender", "busbar-plane-llm", "std::net"],
        ));
        // A PLUGIN PINNED FROM ITS OWN REPOSITORY, laid nowhere in the tree: its source is read
        // from the checkout `cargo metadata` resolves, with a plant at its mount dir on top.
        let pinned = pinned_unlaid(cx, &read_ledger(&cx.read(LEDGER).unwrap_or_default()));
        let name = pinned.clone().unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            format!("crates/{name}/src/planted_socket.rs"),
            "pub fn dial() { let _ = ::std::net::TcpStream::connect(\"127.0.0.1:1\"); }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a plugin pinned from its own repository that opens a socket is a new offender",
            &[ROW_NEW],
            ov,
            &["new-offender", name.as_str(), "std::net"],
        ));
        // A PINNED PLUGIN WHOSE SOURCE CANNOT BE READ is refused by name, never passed unread.
        let mut ov = Overlay::new();
        if let Ok(meta) = cx.cargo_metadata("Cargo.toml") {
            if let Ok(mut json) = serde_json::from_str::<Value>(&meta) {
                for p in json["packages"].as_array_mut().into_iter().flatten() {
                    if p["name"].as_str() == pinned.as_deref() {
                        p["manifest_path"] =
                            Value::from(format!("/nonexistent/dep-wall-plant/{name}/Cargo.toml"));
                    }
                }
                ov.set_command("cargo-metadata:Cargo.toml", json.to_string());
            }
        }
        report.push(prove_red(
            cx,
            self,
            "a pinned plugin whose source cannot be read is refused by name",
            &[ROW_SCOPE],
            ov,
            &[name.as_str(), "cannot be read"],
        ));
        // A DRAINED PIN: a pin for an offence the tree does not have must be struck.
        let mut ov = Overlay::new();
        ov.set(
            LEDGER,
            format!(
                "{}\nbusbar-plane-decisions\treqwest\n",
                cx.read(LEDGER).unwrap_or_default().trim_end()
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a pin the tree no longer measures is struck, never kept as slack",
            &[ROW_DRAINED],
            ov,
            &["drained", "busbar-plane-decisions", "reqwest"],
        ));
        // A CARRIER EXEMPTION ON A CRATE THAT IS NOT A TRANSPORT is refused.
        let mut ov = Overlay::new();
        ov.set(
            LEDGER,
            format!(
                "{}\ncarrier\tbusbar-plane-decisions\n",
                cx.read(LEDGER).unwrap_or_default().trim_end()
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "only a transport crate may be exempted as a carrier",
            &[ROW_SCOPE],
            ov,
            &["busbar-plane-decisions", "not a transport crate"],
        ));
        report
    }
}

#[cfg(test)]
#[path = "tests/dep_wall_tests.rs"]
mod tests;
