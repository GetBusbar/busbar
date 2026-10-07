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

use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
const LEGACY: &[&str] = &[
    "crates/busbar-llm",
    "crates/busbar-mcp",
    "crates/busbar-a2a",
    "crates/busbar-voice",
];

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
pub fn measure(
    cx: &Ctx,
    carriers: &BTreeSet<String>,
) -> Result<(Offenders, usize, BTreeSet<String>), String> {
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
    let mut roots: Vec<(String, Option<String>)> = Vec::new(); // (id, in-tree dir)
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
                    roots.push((id.clone(), Some(dir)));
                }
            }
            Some(src) if src.starts_with(EXTERNAL_SOURCE) => roots.push((id.clone(), None)),
            Some(_) => {}
        }
    }
    let mut out = Offenders::new();
    for (root_id, dir) in &roots {
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
        if let Some(dir) = dir {
            let files = cx
                .walk(
                    &WalkSpec::new([format!("{dir}/src")])
                        .ext("rs")
                        .allow_empty(),
                )
                .unwrap_or_default();
            for f in files {
                let rel = f.rel_str();
                if rel.contains("/tests/") || rel.ends_with("_tests.rs") {
                    continue;
                }
                for (_, line) in crate::scan::production_lines(&f.text) {
                    for p in BANNED_PATHS {
                        if line.contains(p) {
                            hits.insert((*p).to_string());
                        }
                    }
                }
            }
        }
        if !hits.is_empty() {
            out.entry(root_name).or_default().extend(hits);
        }
    }
    let names = pkgs.values().map(|p| p.name.clone()).collect();
    Ok((out, roots.len(), names))
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
        let (measured, roots, names) = match measure(cx, &ledger.carriers) {
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
