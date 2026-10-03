//! THE PLUGIN GATES every first-party plugin repo is judged by (`cargo xtask plugin-gates <gate>`),
//! a port of `scripts/fleet/plugin-gates.py`. `.github/workflows/plugin-ci.yml` runs them at the
//! busbar commit the plugin pins (`.busbar-ref`), so the CI logic and the contract move together.
//! Pure functions over what cargo, nm and the two lockfiles say; every gate prints one line per
//! finding and exits 1 on any. `selftest` plants a RED for every gate and runs before a verdict is
//! trusted.
//!
//! The policy is `.github/fleet/deps.toml` at the pin: the socket/TLS ban (BUSBAR-1.6.0.md line
//! 3980) and the C-dependency allow-list. Cargo.lock parity with busbar's lock is RED
//! (PLUGIN-TEMPLATE ruling 3b). `declares.json`'s `contract_abi` is the top of the loader's
//! `supported_abi(kind)` at the pin, min = max (THE DESIGN §11.8).
//!
//! Output is byte-for-byte the Python's, including where Python's `repr` leaks into a finding (the
//! `sorted(missing)` list of CDEP, the parsed `contract_abi` of DECLARES).
//!
//! READERS. JSON metadata is `serde_json::Value`; `declares.json` goes through the order-preserving
//! [`crate::json_lite`] because its key order is printed. `Cargo.lock` is read by
//! [`crate::toml_doc`]. `deps.toml` is NOT: it carries inline tables (`allow = [ { crate = .. } ]`),
//! which `toml_doc` refuses, so a small TOML-subset reader below turns it into a `json_lite::Json`.

use crate::json_lite::{self, Json, Obj};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

const BUSBAR_GIT: &str = "https://github.com/GetBusbar/busbar";
const KINDS: [&str; 7] = [
    "store",
    "secret",
    "auth",
    "hook",
    "export",
    "plane",
    "transport",
];
const BOTH_WAYS: &str = "the_linked_and_the_dropped_in_";

const USAGE: &str = "\
usage:
  cargo xtask plugin-gates depwall <metadata.json> <repo> [--tree <shipped-tree.txt>]
  cargo xtask plugin-gates netban <metadata.json> <deps.toml> <repo> [--tree <shipped-tree.txt>]
  cargo xtask plugin-gates cdeps <metadata.json> <deps.toml> [--tree <shipped-tree.txt>]
  (--tree: `cargo tree -e normal,build --target all --prefix none -f '{p}|{f}'` per workspace member,
   concatenated; the closure and features are then the shipped build's, not the dev-unified resolve's)
  cargo xtask plugin-gates imports <undefined-symbols.txt> <needed-libs.txt> <deps.toml> <repo>
  cargo xtask plugin-gates parity <plugin Cargo.lock> <busbar Cargo.lock>
  cargo xtask plugin-gates bothways <conformance --list output>
  cargo xtask plugin-gates declares <busbar-root> <kind> <declares.json>
  cargo xtask plugin-gates selftest";

type Res<T> = Result<T, String>;

// -- small Python-isms ---------------------------------------------------------------------------

fn py_list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_lite::py_repr(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// `repr()` of a parsed JSON value, with Python's float spelling (`3.0`, not `3`).
fn repr(v: &Json) -> String {
    match v {
        Json::Float(f) => {
            if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
                format!("{f:.1}")
            } else {
                format!("{f}")
            }
        }
        Json::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Json::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", json_lite::py_repr(k), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => json_lite::py_repr_json(other),
    }
}

/// `str()` of a parsed JSON value: `repr` except a bare string, which prints without quotes.
fn py_str(v: &Json) -> String {
    match v {
        Json::Str(s) => s.clone(),
        other => repr(other),
    }
}

/// Python's `str.splitlines()`.
fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = text.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !brk {
            continue;
        }
        out.push(&text[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r' && matches!(it.peek(), Some((_, '\n'))) {
            it.next();
            end += 1;
        }
        start = end;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

fn read(path: &str) -> Res<String> {
    std::fs::read_to_string(path).map_err(|e| format!("plugin-gates: cannot read {path}: {e}"))
}

fn load_json(path: &str) -> Res<Value> {
    serde_json::from_str(&read(path)?).map_err(|e| format!("plugin-gates: {path}: not JSON: {e}"))
}

fn load_toml(path: &str) -> Res<Json> {
    parse_toml(&read(path)?).map_err(|e| format!("plugin-gates: {path}: {e}"))
}

fn req_str<'a>(v: &'a Value, key: &str) -> Res<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("plugin-gates: package entry has no string `{key}`"))
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

// -- the shipped closure -------------------------------------------------------------------------

/// The packages (and their enabled features) of the true shipped closure, read from
/// `cargo tree -e normal,build --target all --prefix none -f '{p}|{f}'` run per workspace member.
/// `cargo metadata`'s `resolve` cannot say this: its `features` are unified across
/// dev-dependencies (a dev-dep that turns on `tokio/net` shows there), and it lists optional deps
/// that only a dev-dep's feature switches on. `cargo tree` with the dev edges left out resolves
/// features as the shipped build does.
#[derive(Default)]
pub struct Shipped(HashMap<(String, String), BTreeSet<String>>);

impl Shipped {
    /// Parse `cargo tree --prefix none --format '{p}|{f}'` output (several members' trees may be
    /// concatenated): one `name vX.Y.Z [(source)] [(*)]|feature,feature` line per crate. Features
    /// of one crate on several lines are unioned.
    pub fn parse(tree: &str) -> Shipped {
        let mut m: HashMap<(String, String), BTreeSet<String>> = HashMap::new();
        for line in tree.lines() {
            let (package, features) = line.split_once('|').unwrap_or((line, ""));
            let mut it = package.split_whitespace();
            let (Some(name), Some(ver)) = (it.next(), it.next()) else {
                continue;
            };
            let e = m
                .entry((name.to_string(), ver.trim_start_matches('v').to_string()))
                .or_default();
            e.extend(
                features
                    .split(',')
                    .map(str::trim)
                    .filter(|f| !f.is_empty())
                    .map(String::from),
            );
        }
        Shipped(m)
    }

    fn get(&self, p: &Value) -> Option<&BTreeSet<String>> {
        self.0.get(&(
            p["name"].as_str().unwrap_or("").to_string(),
            p["version"].as_str().unwrap_or("").to_string(),
        ))
    }
}

struct Closure<'a> {
    /// Reachable package ids, members excluded.
    ids: Vec<String>,
    nodes: HashMap<String, &'a Value>,
    pkgs: HashMap<String, &'a Value>,
    shipped: Option<&'a Shipped>,
}

impl Closure<'_> {
    /// The features enabled on package `id` in the shipped build: `cargo tree`'s when a shipped
    /// view is given, else the metadata resolve's.
    fn features(&self, id: &str) -> BTreeSet<String> {
        if let Some(sh) = self.shipped {
            return self
                .pkgs
                .get(id)
                .and_then(|p| sh.get(p))
                .cloned()
                .unwrap_or_default();
        }
        self.nodes
            .get(id)
            .map(|n| {
                n["features"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|f| f.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn pkg(&self, id: &str) -> Res<&Value> {
        self.pkgs
            .get(id)
            .copied()
            .ok_or_else(|| format!("plugin-gates: no package `{id}` in metadata.packages"))
    }

    /// `sorted(ids, key=name)`; ties by id (Python's order among same-name packages is the
    /// arbitrary order of a set).
    fn sorted(&self) -> Res<Vec<(String, &Value)>> {
        let mut v = Vec::new();
        for id in &self.ids {
            v.push((id.clone(), self.pkg(id)?));
        }
        v.sort_by(|a, b| {
            let name = |p: &Value| p["name"].as_str().unwrap_or("").to_string();
            (name(a.1), &a.0).cmp(&(name(b.1), &b.0))
        });
        Ok(v)
    }
}

/// Package ids reachable from the workspace members over NORMAL and BUILD edges (a dev-dependency
/// is a test's, not the shipped image's), members excluded. With `shipped_view`, only packages
/// `cargo tree` lists for the shipped build, and their features from it.
fn closure<'a>(meta: &'a Value, shipped_view: Option<&'a Shipped>) -> Res<Closure<'a>> {
    let nodes_arr = meta["resolve"]["nodes"]
        .as_array()
        .ok_or("plugin-gates: metadata has no resolve.nodes")?;
    let mut nodes = HashMap::new();
    for n in nodes_arr {
        nodes.insert(req_str(n, "id")?.to_string(), n);
    }
    let mut pkgs = HashMap::new();
    for p in meta["packages"]
        .as_array()
        .ok_or("plugin-gates: metadata has no packages")?
    {
        pkgs.insert(req_str(p, "id")?.to_string(), p);
    }
    let members: BTreeSet<String> = meta["workspace_members"]
        .as_array()
        .ok_or("plugin-gates: metadata has no workspace_members")?
        .iter()
        .filter_map(|m| m.as_str().map(String::from))
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = members.iter().cloned().collect();
    while let Some(cur) = queue.pop() {
        let Some(node) = nodes.get(&cur) else {
            continue;
        };
        for d in node["deps"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            let shipped = d["dep_kinds"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
                .any(|k| match k.get("kind") {
                    None | Some(Value::Null) => true,
                    Some(Value::String(s)) => s == "build",
                    _ => false,
                });
            let pkg = req_str(d, "pkg")?;
            // With a shipped view, a package `cargo tree` (dev edges left out) does not list is not
            // shipped, whatever the resolve's normal-kind edge says: an optional dep that only a
            // dev-dependency's feature activates is such an edge.
            let listed = match (shipped_view, pkgs.get(pkg)) {
                (Some(sh), Some(p)) => sh.get(p).is_some(),
                _ => true,
            };
            if shipped && listed && !seen.contains(pkg) {
                seen.insert(pkg.to_string());
                queue.push(pkg.to_string());
            }
        }
    }
    Ok(Closure {
        ids: seen.difference(&members).cloned().collect(),
        nodes,
        pkgs,
        shipped: shipped_view,
    })
}

/// `^busbar-(store|secret|...)-[a-z0-9-]+$`
fn first_party_plugin(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("busbar-") else {
        return false;
    };
    KINDS.iter().any(|k| {
        rest.strip_prefix(k)
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|r| {
                !r.is_empty()
                    && r.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
    })
}

/// `^busbar-(kernel|core)(-.*)?$`
fn is_core(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("busbar-") else {
        return false;
    };
    ["kernel", "core"].iter().any(|k| {
        rest.strip_prefix(k)
            .is_some_and(|r| r.is_empty() || (r.starts_with('-') && !r.contains('\n')))
    })
}

/// Part 2 #40 (a): a plugin's busbar closure is busbar-contract and nothing else; no kernel or core
/// crate, and no other plugin.
pub fn depwall(meta: &Value, shipped: Option<&Shipped>, repo: &str) -> Res<Vec<String>> {
    let cl = closure(meta, shipped)?;
    let mut members = BTreeSet::new();
    for m in meta["workspace_members"].as_array().into_iter().flatten() {
        if let Some(id) = m.as_str() {
            members.insert(req_str(cl.pkg(id)?, "name")?.to_string());
        }
    }
    let mut out = Vec::new();
    for (_, p) in cl.sorted()? {
        let (name, version) = (req_str(p, "name")?, req_str(p, "version")?);
        let src = p["source"].as_str().unwrap_or("");
        if src.starts_with(&format!("git+{BUSBAR_GIT}")) && name != "busbar-contract" {
            out.push(format!("DEPWALL {name} {version} from busbar is in the shipped closure (only busbar-contract may be)"));
        } else if is_core(name) {
            out.push(format!(
                "DEPWALL {name} {version} is a kernel/core crate in the shipped closure"
            ));
        } else if first_party_plugin(name) && !members.contains(name) && !name.starts_with(repo) {
            out.push(format!(
                "DEPWALL {name} {version} is another plugin in the shipped closure"
            ));
        }
    }
    Ok(out)
}

fn str_list(v: &Json) -> Vec<String> {
    v.as_array()
        .unwrap_or(&[])
        .iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect()
}

fn spec_of(net: &Json) -> String {
    match net.get("spec") {
        Json::Null => "line 3980".to_string(),
        other => py_str(other),
    }
}

fn net_ban(deps: &Json) -> Res<&Json> {
    match deps.as_object().and_then(|o| o.get("net-ban")) {
        Some(n) => Ok(n),
        None => Err("plugin-gates: deps.toml has no [net-ban] table".to_string()),
    }
}

/// BUSBAR-1.6.0.md line 3980: no plugin opens its own socket, dials, binds or does TLS.
pub fn netban(
    meta: &Value,
    shipped: Option<&Shipped>,
    deps: &Json,
    repo: &str,
) -> Res<Vec<String>> {
    let net = net_ban(deps)?;
    let cl = closure(meta, shipped)?;
    let carrier = str_list(net.get("carriers")).iter().any(|c| c == repo);
    let socket_only = ["socket2", "tokio/net", "mio/net"];
    let crates = str_list(net.get("crates"));
    let features = str_list(net.get("features"));
    let spec = spec_of(net);
    let mut out = Vec::new();
    for (id, p) in cl.sorted()? {
        let (name, version) = (req_str(p, "name")?, req_str(p, "version")?);
        if crates.iter().any(|c| c == name) && !(carrier && socket_only.contains(&name)) {
            out.push(format!(
                "NETBAN {name} {version} is in the shipped closure ({spec})"
            ));
        }
        let feats = cl.features(&id);
        for f in &features {
            let (krate, feat) = f
                .split_once('/')
                .ok_or_else(|| format!("plugin-gates: net-ban feature `{f}` has no `/`"))?;
            if krate == name && feats.contains(feat) && !(carrier && socket_only.contains(&&**f)) {
                out.push(format!(
                    "NETBAN {name}/{feat} is enabled in the shipped closure ({spec})"
                ));
            }
        }
    }
    Ok(out)
}

/// Does `version` satisfy `req`: `=x.y.z` exact, else a caret requirement (`0.17`, `1.1`).
pub fn req_ok(version: &str, req: &str) -> Res<bool> {
    let base = version
        .split('+')
        .next()
        .unwrap_or("")
        .split('-')
        .next()
        .unwrap_or("");
    let mut v: Vec<u64> = Vec::new();
    let mut digits = String::new();
    for c in base.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if !digits.is_empty() {
            v.push(digits.parse().unwrap_or(u64::MAX));
            digits.clear();
        }
    }
    v.truncate(3);
    if let Some(exact) = req.strip_prefix('=') {
        return Ok(version.split('+').next().unwrap_or("") == exact.trim());
    }
    let mut r: Vec<u64> = Vec::new();
    for x in req.trim().trim_start_matches('^').split('.') {
        r.push(
            x.trim()
                .parse()
                .map_err(|_| format!("plugin-gates: bad version requirement `{req}`"))?,
        );
    }
    let head = &v[..r.len().min(v.len())];
    if head < r.as_slice() {
        return Ok(false);
    }
    let first = r.iter().position(|&x| x != 0).unwrap_or(r.len() - 1);
    let n = first + 1;
    Ok(v[..n.min(v.len())] == r[..n.min(r.len())])
}

/// Ruling 3d: a native library in the shipped closure is on the allow-list, at its version, with its
/// bundling features on.
pub fn cdeps(meta: &Value, shipped: Option<&Shipped>, deps: &Json) -> Res<Vec<String>> {
    let mut allow: HashMap<String, &Json> = HashMap::new();
    for e in deps.get("c-deps").get("allow").as_array().unwrap_or(&[]) {
        let name = e
            .get("crate")
            .as_str()
            .ok_or("plugin-gates: c-deps allow entry has no `crate`")?;
        allow.insert(name.to_string(), e);
    }
    let cl = closure(meta, shipped)?;
    let mut out = Vec::new();
    for (id, p) in cl.sorted()? {
        let links = match p.get("links").and_then(Value::as_str) {
            Some(l) if !l.is_empty() => l,
            _ => continue,
        };
        let (name, version) = (req_str(p, "name")?, req_str(p, "version")?);
        let Some(e) = allow.get(name) else {
            out.push(format!(
                "CDEP {name} {version} links native `{links}` and is not on the C allow-list"
            ));
            continue;
        };
        let want = e
            .get("version")
            .as_str()
            .ok_or("plugin-gates: c-deps allow entry has no `version`")?;
        if !req_ok(version, want)? {
            out.push(format!(
                "CDEP {name} {version} is not the allowed version {want}"
            ));
        }
        let have = cl.features(&id);
        let missing: Vec<String> = str_list(e.get("features"))
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|f| !have.contains(f))
            .collect();
        if !missing.is_empty() {
            out.push(format!(
                "CDEP {name} is not bundled: features {} are off",
                py_list(&missing)
            ));
        }
    }
    Ok(out)
}

/// The post-LTO import scan: the built cdylib imports no socket or TLS symbol, and links no TLS
/// library.
pub fn imports(undefined: &[&str], needed: &[&str], deps: &Json, repo: &str) -> Res<Vec<String>> {
    let net = net_ban(deps)?;
    let carrier = str_list(net.get("carriers")).iter().any(|c| c == repo);
    let banned: BTreeSet<String> = str_list(net.get("imports")).into_iter().collect();
    let spec = spec_of(net);
    let mut out = Vec::new();
    let syms: BTreeSet<&str> = undefined
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.split('@').next().unwrap_or("").trim())
        .collect();
    for sym in syms {
        if banned.contains(sym) && !(carrier && !sym.starts_with("SSL_")) {
            out.push(format!("IMPORT the built cdylib imports `{sym}` ({spec})"));
        }
    }
    let libs: BTreeSet<&str> = needed
        .iter()
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .collect();
    for lib in libs {
        if tls_lib(lib) {
            out.push(format!("IMPORT the built cdylib links `{lib}` ({spec})"));
        }
    }
    Ok(out)
}

/// `re.match(r"lib(ssl|crypto|gnutls|nss3)\b", lib)`
fn tls_lib(lib: &str) -> bool {
    let Some(rest) = lib.strip_prefix("lib") else {
        return false;
    };
    ["ssl", "crypto", "gnutls", "nss3"].iter().any(|a| {
        rest.strip_prefix(a)
            .is_some_and(|r| !r.chars().next().is_some_and(is_word))
    })
}

fn lock_versions(text: &str) -> Res<BTreeMap<String, BTreeSet<String>>> {
    let doc = crate::toml_doc::parse_str(text)?;
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in doc.array_of_tables("package") {
        let src = p.str_of("source").unwrap_or("");
        if src.starts_with("registry+") {
            let name = p
                .str_of("name")
                .ok_or("Cargo.lock package without a name")?;
            let ver = p
                .str_of("version")
                .ok_or("Cargo.lock package without a version")?;
            out.entry(name.to_string())
                .or_default()
                .insert(ver.to_string());
        }
    }
    Ok(out)
}

/// Ruling 3b, RED: every crates.io package both locks hold is at a version busbar's lock holds.
pub fn parity(plugin_lock: &str, busbar_lock: &str) -> Res<Vec<String>> {
    let mine = lock_versions(plugin_lock).map_err(|e| format!("plugin Cargo.lock: {e}"))?;
    let theirs = lock_versions(busbar_lock).map_err(|e| format!("busbar Cargo.lock: {e}"))?;
    let mut out = Vec::new();
    for (name, mv) in &mine {
        let Some(tv) = theirs.get(name) else {
            continue;
        };
        for v in mv.difference(tv) {
            let held: Vec<&str> = tv.iter().map(String::as_str).collect();
            out.push(format!(
                "PARITY {name} {v}: busbar's lock at the pin holds {}",
                held.join(", ")
            ));
        }
    }
    Ok(out)
}

/// The conformance target holds the both-ways arm and at least one RED arm.
pub fn bothways(listing: &[&str]) -> Vec<String> {
    let names: Vec<&str> = listing
        .iter()
        .filter(|l| l.trim_end().ends_with(": test"))
        .map(|l| {
            let n = l.split(':').next().unwrap_or("").trim();
            n.rsplit("::").next().unwrap_or("")
        })
        .collect();
    let mut out = Vec::new();
    if !names.iter().any(|n| n.starts_with(BOTH_WAYS)) {
        out.push(format!("BOTHWAYS no `{BOTH_WAYS}*` test in the conformance target (linked door vs built cdylib, one transcript)"));
    }
    if !names.iter().any(|n| !n.starts_with(BOTH_WAYS)) {
        out.push("BOTHWAYS no RED arm in the conformance target (a test proving the comparison can fail)".to_string());
    }
    out
}

// -- declares.json -------------------------------------------------------------------------------

/// `re.search(r"const\s+NAME\s*:\s*u\d+\s*=\s*(\d+)\s*;", src)`
fn const_value(src: &str, name: &str) -> Option<u64> {
    let skip_ws = |s: &str| -> usize { s.len() - s.trim_start().len() };
    let mut from = 0;
    while let Some(off) = src[from..].find("const") {
        let at = from + off;
        from = at + 1;
        while !src.is_char_boundary(from) {
            from += 1;
        }
        let mut rest = &src[at + 5..];
        let w = skip_ws(rest);
        if w == 0 {
            continue;
        }
        rest = &rest[w..];
        let Some(r) = rest.strip_prefix(name) else {
            continue;
        };
        let r = r.trim_start();
        let Some(r) = r.strip_prefix(':') else {
            continue;
        };
        let Some(r) = r.trim_start().strip_prefix('u') else {
            continue;
        };
        let nd = r.len() - r.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if nd == 0 {
            continue;
        }
        let Some(r) = r[nd..].trim_start().strip_prefix('=') else {
            continue;
        };
        let r = r.trim_start();
        let nd = r.len() - r.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if nd == 0 || !r[nd..].trim_start().starts_with(';') {
            continue;
        }
        return r[..nd].parse().ok();
    }
    None
}

/// The current contract-ABI version of `kind` in the busbar tree at `root`: the top of the loader's
/// `supported_abi(kind)`, resolved through busbar-contract's constants.
pub fn kind_abi(root: &Path, kind: &str) -> Res<u64> {
    let rd = |p: &Path| {
        std::fs::read_to_string(p)
            .map_err(|e| format!("plugin-gates: cannot read {}: {e}", p.display()))
    };
    let mut reg = None;
    for p in [
        "crates/plugin-loader/src/registry.rs",
        "crates/busbar-plugin-loader/src/registry.rs",
    ] {
        let full = root.join(p);
        if full.exists() {
            // re.sub(r"//[^\n]*", "", ...)
            let text = rd(&full)?;
            let mut s = String::new();
            let mut rest = text.as_str();
            while let Some(i) = rest.find("//") {
                s.push_str(&rest[..i]);
                rest = &rest[i..];
                rest = &rest[rest.find('\n').unwrap_or(rest.len())..];
            }
            s.push_str(rest);
            reg = Some(s);
            break;
        }
    }
    let reg = reg.ok_or("no plugin-loader registry.rs in the busbar tree")?;
    let key = format!("\"{kind}\"");
    let mut body = None;
    let mut from = 0;
    while let Some(off) = reg[from..].find(&key) {
        let at = from + off;
        from = at + 1;
        while !reg.is_char_boundary(from) {
            from += 1;
        }
        let r = reg[at + key.len()..].trim_start();
        let Some(r) = r.strip_prefix("=>") else {
            continue;
        };
        let Some(r) = r.trim_start().strip_prefix("&[") else {
            continue;
        };
        if let Some(end) = r.find(']') {
            body = Some(r[..end].to_string());
            break;
        }
    }
    let body = body.ok_or_else(|| format!("supported_abi has no arm for kind `{kind}`"))?;
    let top = body
        .split(',')
        .map(str::trim)
        .rfind(|x| !x.is_empty())
        .ok_or("supported_abi arm is empty")?
        .to_string();
    if top.chars().all(|c| c.is_ascii_digit()) {
        return top
            .parse()
            .map_err(|_| "ABI literal out of range".to_string());
    }
    let parts: Vec<&str> = top.split("::").collect();
    if parts.len() == 1 {
        return const_value(&reg, &top)
            .ok_or_else(|| format!("`{top}` is not a numeric const in registry.rs"));
    }
    let mut base: PathBuf = root.join("crates/busbar-contract/src");
    for p in &parts[1..parts.len() - 1] {
        base.push(p);
    }
    let mut rs = base.clone().into_os_string();
    rs.push(".rs");
    for p in [base.join("mod.rs"), PathBuf::from(rs)] {
        if p.exists() {
            if let Some(v) = const_value(&rd(&p)?, parts[parts.len() - 1]) {
                return Ok(v);
            }
        }
    }
    Err(format!("cannot resolve `{top}` in busbar-contract"))
}

/// Python `got == {"min": want, "max": want}` (`True == 1`, `3.0 == 3`).
fn abi_matches(got: &Json, want: u64) -> bool {
    let eq = |v: &Json| match v {
        Json::Int(i) => i128::from(*i) == i128::from(want),
        Json::Float(f) => *f == want as f64,
        Json::Bool(b) => u64::from(*b) == want,
        _ => false,
    };
    match got {
        Json::Object(o) => {
            o.len() == 2 && o.get("min").is_some_and(eq) && o.get("max").is_some_and(eq)
        }
        _ => false,
    }
}

/// declares.json states the kind's current contract ABI at the pin, min = max.
pub fn declares(root: &Path, kind: &str, text: &str) -> Res<Vec<String>> {
    let want = kind_abi(root, kind)?;
    let doc = match json_lite::parse(text) {
        Ok(d) => d,
        Err(e) => return Ok(vec![format!("DECLARES declares.json is not JSON: {e}")]),
    };
    let Json::Object(obj) = &doc else {
        return Err("plugin-gates: declares.json is not a JSON object".to_string());
    };
    let got = obj.get("contract_abi").cloned().unwrap_or(Json::Null);
    if !abi_matches(&got, want) {
        return Ok(vec![format!(
            "DECLARES contract_abi is {}; busbar at the pin speaks {kind} v{want} (min = max = {want}). Re-render it with busbar-release plugin sync.",
            py_str(&got)
        )]);
    }
    Ok(Vec::new())
}

// -- the deps.toml reader ------------------------------------------------------------------------

struct Toml {
    s: Vec<char>,
    i: usize,
}

impl Toml {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn starts(&self, t: &str) -> bool {
        t.chars()
            .enumerate()
            .all(|(k, c)| self.s.get(self.i + k) == Some(&c))
    }
    fn err<T>(&self, m: &str) -> Res<T> {
        let line = self.s[..self.i.min(self.s.len())]
            .iter()
            .filter(|&&c| c == '\n')
            .count()
            + 1;
        Err(format!("toml: line {line}: {m}"))
    }
    fn skip_inline(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.i += 1;
        }
    }
    fn skip_comment(&mut self) {
        if self.peek() == Some('#') {
            while !matches!(self.peek(), None | Some('\n')) {
                self.i += 1;
            }
        }
    }
    fn skip_all(&mut self) {
        loop {
            self.skip_inline();
            self.skip_comment();
            if matches!(self.peek(), Some('\n' | '\r')) {
                self.i += 1;
            } else {
                return;
            }
        }
    }
    fn key_path(&mut self) -> Res<Vec<String>> {
        let mut out = Vec::new();
        loop {
            self.skip_inline();
            match self.peek() {
                Some('"') => out.push(self.basic()?),
                Some('\'') => out.push(self.literal()?),
                Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {
                    let st = self.i;
                    while self
                        .peek()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        self.i += 1;
                    }
                    out.push(self.s[st..self.i].iter().collect());
                }
                _ => return self.err("expected a key"),
            }
            self.skip_inline();
            if self.peek() == Some('.') {
                self.i += 1;
            } else {
                return Ok(out);
            }
        }
    }
    fn basic(&mut self) -> Res<String> {
        let multi = self.starts("\"\"\"");
        self.i += if multi { 3 } else { 1 };
        if multi && self.peek() == Some('\n') {
            self.i += 1;
        }
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return self.err("unterminated string");
            };
            if multi && self.starts("\"\"\"") {
                self.i += 3;
                return Ok(out);
            }
            if !multi && c == '"' {
                self.i += 1;
                return Ok(out);
            }
            if !multi && c == '\n' {
                return self.err("newline in a string");
            }
            self.i += 1;
            if c != '\\' {
                out.push(c);
                continue;
            }
            let Some(e) = self.peek() else {
                return self.err("unterminated string");
            };
            self.i += 1;
            match e {
                'b' => out.push('\u{8}'),
                't' => out.push('\t'),
                'n' => out.push('\n'),
                'f' => out.push('\u{c}'),
                'r' => out.push('\r'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'u' | 'U' => {
                    let n = if e == 'u' { 4 } else { 8 };
                    let hex: String = self.s[self.i..(self.i + n).min(self.s.len())]
                        .iter()
                        .collect();
                    self.i += n;
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(ch) => out.push(ch),
                        None => return self.err("bad unicode escape"),
                    }
                }
                ' ' | '\t' | '\n' | '\r' if multi => {
                    while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
                        self.i += 1;
                    }
                }
                _ => return self.err("bad escape"),
            }
        }
    }
    fn literal(&mut self) -> Res<String> {
        let multi = self.starts("'''");
        self.i += if multi { 3 } else { 1 };
        if multi && self.peek() == Some('\n') {
            self.i += 1;
        }
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return self.err("unterminated string");
            };
            if multi && self.starts("'''") {
                self.i += 3;
                return Ok(out);
            }
            if !multi && c == '\'' {
                self.i += 1;
                return Ok(out);
            }
            if !multi && c == '\n' {
                return self.err("newline in a string");
            }
            out.push(c);
            self.i += 1;
        }
    }
    fn value(&mut self) -> Res<Json> {
        match self.peek() {
            Some('"') => Ok(Json::Str(self.basic()?)),
            Some('\'') => Ok(Json::Str(self.literal()?)),
            Some('[') => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_all();
                    if self.peek() == Some(']') {
                        self.i += 1;
                        return Ok(Json::Array(items));
                    }
                    items.push(self.value()?);
                    self.skip_all();
                    match self.peek() {
                        Some(',') => self.i += 1,
                        Some(']') => {}
                        _ => return self.err("expected `,` or `]` in an array"),
                    }
                }
            }
            Some('{') => {
                self.i += 1;
                let mut obj = Json::Object(Obj::new());
                loop {
                    self.skip_inline();
                    if self.peek() == Some('}') {
                        self.i += 1;
                        return Ok(obj);
                    }
                    self.assign(&mut obj, &[])?;
                    self.skip_inline();
                    match self.peek() {
                        Some(',') => self.i += 1,
                        Some('}') => {}
                        _ => return self.err("expected `,` or `}` in an inline table"),
                    }
                }
            }
            Some(_) => {
                let st = self.i;
                while self
                    .peek()
                    .is_some_and(|c| !matches!(c, ',' | ']' | '}' | '\n' | '\r' | '#' | ' ' | '\t'))
                {
                    self.i += 1;
                }
                let tok: String = self.s[st..self.i].iter().collect();
                if tok == "true" {
                    Ok(Json::Bool(true))
                } else if tok == "false" {
                    Ok(Json::Bool(false))
                } else if let Ok(n) = tok.replace('_', "").parse::<i64>() {
                    Ok(Json::Int(n))
                } else if let Ok(f) = tok.replace('_', "").parse::<f64>() {
                    Ok(Json::Float(f))
                } else {
                    self.err(&format!("`{tok}` is not a value this reader accepts"))
                }
            }
            None => self.err("expected a value"),
        }
    }
    /// `dotted.key = value` into the table at `base` under `root`.
    fn assign(&mut self, root: &mut Json, base: &[String]) -> Res<()> {
        let mut keys = self.key_path()?;
        self.skip_inline();
        if self.peek() != Some('=') {
            return self.err("expected `=` after a key");
        }
        self.i += 1;
        self.skip_inline();
        let v = self.value()?;
        let leaf = keys.pop().expect("key_path yields a key");
        let mut path = base.to_vec();
        path.extend(keys);
        let t = navigate(root, &path)?;
        t.insert(leaf, v);
        Ok(())
    }
}

fn navigate<'a>(mut node: &'a mut Json, path: &[String]) -> Res<&'a mut Obj> {
    for k in path {
        let obj = node
            .as_object_mut()
            .ok_or("toml: key path crosses a non-table")?;
        if !obj.contains_key(k) {
            obj.insert(k.clone(), Json::Object(Obj::new()));
        }
        node = obj.get_mut(k).expect("just inserted");
        if let Json::Array(a) = node {
            node = a.last_mut().ok_or("toml: empty array of tables")?;
        }
    }
    node.as_object_mut()
        .ok_or_else(|| "toml: not a table".to_string())
}

/// A TOML subset: tables, arrays of tables, dotted/quoted keys, strings, integers, floats, bools,
/// (multi-line) arrays and inline tables. Anything else is a refusal.
pub fn parse_toml(text: &str) -> Res<Json> {
    let mut p = Toml {
        s: text.chars().collect(),
        i: 0,
    };
    let mut root = Json::Object(Obj::new());
    let mut cur: Vec<String> = Vec::new();
    loop {
        p.skip_all();
        let Some(c) = p.peek() else {
            return Ok(root);
        };
        if c == '[' {
            p.i += 1;
            let array = p.peek() == Some('[');
            if array {
                p.i += 1;
            }
            let path = p.key_path()?;
            p.skip_inline();
            for _ in 0..if array { 2 } else { 1 } {
                if p.peek() != Some(']') {
                    return p.err("unterminated table header");
                }
                p.i += 1;
            }
            if array {
                let (leaf, parent) = path.split_last().expect("key_path yields a key");
                let t = navigate(&mut root, parent)?;
                if !t.contains_key(leaf) {
                    t.insert(leaf.clone(), Json::Array(Vec::new()));
                }
                match t.get_mut(leaf) {
                    Some(Json::Array(a)) => a.push(Json::Object(Obj::new())),
                    _ => return p.err("an array-of-tables header names a non-array"),
                }
            } else {
                navigate(&mut root, &path)?;
            }
            cur = path;
        } else {
            p.assign(&mut root, &cur)?;
        }
        p.skip_inline();
        p.skip_comment();
        if !matches!(p.peek(), None | Some('\n' | '\r')) {
            return p.err("unexpected text after a value");
        }
    }
}

// -- selftest ------------------------------------------------------------------------------------

const CRATES: &str = "registry+https://github.com/rust-lang/crates.io-index";
const BUSBAR_SRC: &str = "git+https://github.com/GetBusbar/busbar?rev=x#x";
const POLICY: &str = r#"
[net-ban]
spec = "line 3980"
crates = ["rustls", "socket2"]
features = ["tokio/net"]
imports = ["socket", "connect"]
carriers = []

[c-deps]
allow = [{ crate = "libsqlite3-sys", version = "=0.38.1", features = ["bundled"], reason = "r" }]
"#;

/// (id, name, version, source, links, features)
type Pk<'a> = (
    &'a str,
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    &'a [&'a str],
);

fn meta(packages: &[Pk], edges: &[(&str, &str, Option<&str>)]) -> Value {
    let nodes: Vec<Value> = packages
        .iter()
        .map(|p| {
            let deps: Vec<Value> = edges
                .iter()
                .filter(|e| e.0 == p.0)
                .map(|e| serde_json::json!({"pkg": e.1, "dep_kinds": [{"kind": e.2}]}))
                .collect();
            serde_json::json!({"id": p.0, "deps": deps, "features": p.5})
        })
        .collect();
    let pkgs: Vec<Value> = packages
        .iter()
        .map(|p| serde_json::json!({"id": p.0, "name": p.1, "version": p.2, "source": p.3, "links": p.4}))
        .collect();
    serde_json::json!({"workspace_members": ["m"], "packages": pkgs, "resolve": {"nodes": nodes}})
}

fn lock(v: &str) -> String {
    format!(
        "version = 4\n[[package]]\nname = \"serde\"\nversion = \"{v}\"\nsource = \"{CRATES}\"\n"
    )
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        TempDir(
            std::env::temp_dir().join(format!("plugin-gates-{}-{nanos}-{n}", std::process::id())),
        )
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every selftest case: (name, findings or an error, wants RED).
fn cases() -> Vec<(&'static str, Res<Vec<String>>, bool)> {
    let policy = parse_toml(POLICY).expect("the selftest policy parses");
    let m: Pk = ("m", "busbar-store-x", "1.0.0", None, None, &[]);
    let pk = |id, name, ver, src, links, feats: &'static [&'static str]| -> Pk<'static> {
        (id, name, ver, src, links, feats)
    };
    let c = pk("c", "busbar-contract", "1", Some(BUSBAR_SRC), None, &[]);
    let l = pk(
        "l",
        "busbar-plugin-loader",
        "1",
        Some(BUSBAR_SRC),
        None,
        &[],
    );
    let k = pk("k", "busbar-kernel", "1", Some(BUSBAR_SRC), None, &[]);
    let r = pk("r", "rustls", "0.23.1", Some(CRATES), None, &[]);
    let t = pk("t", "tokio", "1.0.0", Some(CRATES), None, &["net"]);
    let s_on = pk(
        "s",
        "libsqlite3-sys",
        "0.38.1",
        Some(CRATES),
        Some("sqlite3"),
        &["bundled"],
    );
    let s_off = pk(
        "s",
        "libsqlite3-sys",
        "0.38.1",
        Some(CRATES),
        Some("sqlite3"),
        &[],
    );
    let z = pk(
        "z",
        "aws-lc-sys",
        "0.3.0",
        Some(CRATES),
        Some("aws_lc"),
        &[],
    );
    let both = [
        "the_linked_and_the_dropped_in_x: test",
        "a_wrong_kind_is_refused: test",
    ];
    let mut v: Vec<(&'static str, Res<Vec<String>>, bool)> = vec![
        (
            "depwall green",
            depwall(
                &meta(&[m, c, l], &[("m", "c", None), ("m", "l", Some("dev"))]),
                None,
                "busbar-store-x",
            ),
            false,
        ),
        (
            "depwall kernel",
            depwall(&meta(&[m, k], &[("m", "k", None)]), None, "busbar-store-x"),
            true,
        ),
        (
            "netban dev-only",
            netban(
                &meta(&[m, r], &[("m", "r", Some("dev"))]),
                None,
                &policy,
                "r",
            ),
            false,
        ),
        (
            "netban rustls",
            netban(&meta(&[m, r], &[("m", "r", None)]), None, &policy, "r"),
            true,
        ),
        (
            "netban tokio/net",
            netban(&meta(&[m, t], &[("m", "t", None)]), None, &policy, "r"),
            true,
        ),
        (
            "netban dev-enabled tokio/net",
            netban(
                &meta(&[m, t], &[("m", "t", None)]),
                Some(&Shipped::parse("tokio v1.0.0 (*)|default,rt\n")),
                &policy,
                "r",
            ),
            false,
        ),
        (
            "netban shipped tokio/net",
            netban(
                &meta(&[m, t], &[("m", "t", None)]),
                Some(&Shipped::parse("tokio v1.0.0|default,net,rt\n")),
                &policy,
                "r",
            ),
            true,
        ),
        (
            "netban dev-activated optional rustls",
            netban(
                &meta(&[m, r], &[("m", "r", None)]),
                Some(&Shipped::parse("busbar-store-x v1.0.0 (/w)|\n")),
                &policy,
                "r",
            ),
            false,
        ),
        (
            "netban shipped rustls",
            netban(
                &meta(&[m, r], &[("m", "r", None)]),
                Some(&Shipped::parse("rustls v0.23.1|std\n")),
                &policy,
                "r",
            ),
            true,
        ),
        (
            "cdeps bundled",
            cdeps(&meta(&[m, s_on], &[("m", "s", None)]), None, &policy),
            false,
        ),
        (
            "cdeps unbundled",
            cdeps(&meta(&[m, s_off], &[("m", "s", None)]), None, &policy),
            true,
        ),
        (
            "cdeps unlisted",
            cdeps(&meta(&[m, z], &[("m", "z", Some("build"))]), None, &policy),
            true,
        ),
        (
            "imports clean",
            imports(&["malloc@GLIBC_2.2.5"], &["libc.so.6"], &policy, "r"),
            false,
        ),
        (
            "imports socket",
            imports(&["connect@GLIBC_2.2.5"], &[], &policy, "r"),
            true,
        ),
        (
            "imports libssl",
            imports(&[], &["libssl.so.3"], &policy, "r"),
            true,
        ),
        (
            "parity equal",
            parity(&lock("1.0.1"), &lock("1.0.1")),
            false,
        ),
        ("parity drift", parity(&lock("1.0.2"), &lock("1.0.1")), true),
        ("bothways both arms", Ok(bothways(&both)), false),
        ("bothways no RED arm", Ok(bothways(&both[..1])), true),
        ("bothways no equality arm", Ok(bothways(&both[1..])), true),
    ];
    let tmp = TempDir::new();
    let d = &tmp.0;
    let setup = || -> std::io::Result<()> {
        std::fs::create_dir_all(d.join("crates/plugin-loader/src"))?;
        std::fs::create_dir_all(d.join("crates/busbar-contract/src/abi/cold"))?;
        std::fs::write(
            d.join("crates/plugin-loader/src/registry.rs"),
            "match kind {\n    // a, comment\n    \"store\" => &[FLOOR, busbar_contract::abi::cold::ABI_VERSION],\n    \"auth\" => &[1, 3],\n}\n",
        )?;
        std::fs::write(
            d.join("crates/busbar-contract/src/abi/cold/mod.rs"),
            "pub const ABI_VERSION: u32 = 4;\n",
        )
    };
    if let Err(e) = setup() {
        let msg = format!("plugin-gates: selftest temp dir: {e}");
        for name in ["declares current", "declares stale", "declares literal"] {
            v.push((name, Err(msg.clone()), false));
        }
        return v;
    }
    v.push((
        "declares current",
        declares(d, "store", r#"{"contract_abi": {"min": 4, "max": 4}}"#),
        false,
    ));
    v.push((
        "declares stale",
        declares(d, "store", r#"{"contract_abi": {"min": 3, "max": 3}}"#),
        true,
    ));
    v.push((
        "declares literal",
        declares(d, "auth", r#"{"contract_abi": {"min": 3, "max": 3}}"#),
        false,
    ));
    v
}

/// The selftest's failure lines (without the `SELFTEST ` prefix).
fn selftest_failures() -> Vec<String> {
    let mut fails = Vec::new();
    for (name, got, want_red) in cases() {
        match got {
            Ok(g) => {
                if !g.is_empty() != want_red {
                    fails.push(format!(
                        "{name}: expected {}, got {}",
                        if want_red { "RED" } else { "GREEN" },
                        py_list(&g)
                    ));
                }
            }
            Err(e) => fails.push(format!("{name}: error {e}")),
        }
    }
    fails
}

fn selftest() -> i32 {
    let fails = selftest_failures();
    for f in &fails {
        println!("SELFTEST {f}");
    }
    println!("plugin-gates selftest: {} failure(s)", fails.len());
    i32::from(!fails.is_empty())
}

// -- entry ---------------------------------------------------------------------------------------

fn run(cmd: &str, args: &[String]) -> Res<Vec<String>> {
    // `--tree <file>` anywhere after the gate name: the shipped closure as `cargo tree` resolves it.
    let mut rest: Vec<String> = Vec::new();
    let mut shipped: Option<Shipped> = None;
    let mut it = args.iter();
    while let Some(x) = it.next() {
        if x == "--tree" {
            let f = it
                .next()
                .ok_or_else(|| format!("plugin-gates: `--tree` needs a file\n{USAGE}"))?;
            shipped = Some(Shipped::parse(&read(f)?));
        } else {
            rest.push(x.clone());
        }
    }
    let args = &rest[..];
    let sh = shipped.as_ref();
    let a = |i: usize| -> Res<&str> {
        args.get(i).map(String::as_str).ok_or_else(|| {
            format!(
                "plugin-gates: `{cmd}` is missing argument {}\n{USAGE}",
                i + 1
            )
        })
    };
    match cmd {
        "depwall" => depwall(&load_json(a(0)?)?, sh, a(1)?),
        "netban" => netban(&load_json(a(0)?)?, sh, &load_toml(a(1)?)?, a(2)?),
        "cdeps" => cdeps(&load_json(a(0)?)?, sh, &load_toml(a(1)?)?),
        "imports" => {
            let (u, n) = (read(a(0)?)?, read(a(1)?)?);
            imports(&splitlines(&u), &splitlines(&n), &load_toml(a(2)?)?, a(3)?)
        }
        "parity" => parity(&read(a(0)?)?, &read(a(1)?)?),
        "bothways" => Ok(bothways(&splitlines(&read(a(0)?)?))),
        "declares" => declares(Path::new(a(0)?), a(1)?, &read(a(2)?)?),
        other => Err(format!("plugin-gates: unknown gate `{other}`")),
    }
}

/// `cargo xtask plugin-gates <gate> <args...>`: 0 clean, 1 findings or an unusable input.
pub fn main(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("{USAGE}");
        return 1;
    };
    if cmd == "selftest" {
        return selftest();
    }
    match run(cmd, &args[1..]) {
        Ok(out) => {
            for line in &out {
                println!("{line}");
            }
            println!("{cmd}: {} finding(s)", out.len());
            i32::from(!out.is_empty())
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(name: &str) {
        let (_, got, want_red) = cases()
            .into_iter()
            .find(|c| c.0 == name)
            .unwrap_or_else(|| panic!("no case {name}"));
        let got = got.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(!got.is_empty(), want_red, "{name}: {got:?}");
    }

    macro_rules! case_tests {
        ($($f:ident => $n:expr),* $(,)?) => { $(#[test] fn $f() { case($n); })* };
    }

    case_tests! {
        depwall_green => "depwall green",
        depwall_kernel => "depwall kernel",
        netban_dev_only => "netban dev-only",
        netban_rustls => "netban rustls",
        netban_tokio_net => "netban tokio/net",
        cdeps_bundled => "cdeps bundled",
        cdeps_unbundled => "cdeps unbundled",
        cdeps_unlisted => "cdeps unlisted",
        imports_clean => "imports clean",
        imports_socket => "imports socket",
        imports_libssl => "imports libssl",
        parity_equal => "parity equal",
        parity_drift => "parity drift",
        bothways_both_arms => "bothways both arms",
        bothways_no_red_arm => "bothways no RED arm",
        bothways_no_equality_arm => "bothways no equality arm",
        declares_current => "declares current",
        declares_stale => "declares stale",
        declares_literal => "declares literal",
    }

    #[test]
    fn selftest_is_clean() {
        assert_eq!(selftest_failures(), Vec::<String>::new());
    }

    fn found(name: &str) -> Vec<String> {
        cases()
            .into_iter()
            .find(|c| c.0 == name)
            .unwrap()
            .1
            .unwrap()
    }

    #[test]
    fn depwall_text() {
        assert_eq!(
            found("depwall kernel"),
            ["DEPWALL busbar-kernel 1 from busbar is in the shipped closure (only busbar-contract may be)"]
        );
    }

    #[test]
    fn depwall_core_and_plugin_text() {
        let m: Pk = ("m", "busbar-store-x", "1.0.0", None, None, &[]);
        let core: Pk = ("k", "busbar-core-x", "2", Some(CRATES), None, &[]);
        let other: Pk = ("o", "busbar-auth-y", "3", Some(CRATES), None, &[]);
        let out = depwall(
            &meta(&[m, core, other], &[("m", "k", None), ("m", "o", None)]),
            None,
            "busbar-store-x",
        )
        .unwrap();
        assert_eq!(
            out,
            [
                "DEPWALL busbar-auth-y 3 is another plugin in the shipped closure",
                "DEPWALL busbar-core-x 2 is a kernel/core crate in the shipped closure"
            ]
        );
    }

    #[test]
    fn netban_crate_and_feature_text() {
        assert_eq!(
            found("netban rustls"),
            ["NETBAN rustls 0.23.1 is in the shipped closure (line 3980)"]
        );
        assert_eq!(
            found("netban tokio/net"),
            ["NETBAN tokio/net is enabled in the shipped closure (line 3980)"]
        );
    }

    #[test]
    fn cdep_text() {
        assert_eq!(
            found("cdeps unbundled"),
            ["CDEP libsqlite3-sys is not bundled: features ['bundled'] are off"]
        );
        assert_eq!(
            found("cdeps unlisted"),
            ["CDEP aws-lc-sys 0.3.0 links native `aws_lc` and is not on the C allow-list"]
        );
    }

    #[test]
    fn cdep_list_repr_has_several_items() {
        let policy = parse_toml(
            "[c-deps]\nallow = [{ crate = \"x-sys\", version = \"1\", features = [\"x\", \"bundled\"] }]\n",
        )
        .unwrap();
        let m: Pk = ("m", "busbar-store-x", "1.0.0", None, None, &[]);
        let x: Pk = ("x", "x-sys", "1.2.0", Some(CRATES), Some("x"), &[]);
        assert_eq!(
            cdeps(&meta(&[m, x], &[("m", "x", None)]), None, &policy).unwrap(),
            ["CDEP x-sys is not bundled: features ['bundled', 'x'] are off"]
        );
    }

    #[test]
    fn parity_text() {
        assert_eq!(
            found("parity drift"),
            ["PARITY serde 1.0.2: busbar's lock at the pin holds 1.0.1"]
        );
    }

    #[test]
    fn declares_text() {
        assert_eq!(
            found("declares stale"),
            ["DECLARES contract_abi is {'min': 3, 'max': 3}; busbar at the pin speaks store v4 (min = max = 4). Re-render it with busbar-release plugin sync."]
        );
    }

    #[test]
    fn declares_repr_forms() {
        let tmp = TempDir::new();
        let d = &tmp.0;
        std::fs::create_dir_all(d.join("crates/plugin-loader/src")).unwrap();
        std::fs::write(
            d.join("crates/plugin-loader/src/registry.rs"),
            "\"auth\" => &[1, 3],",
        )
        .unwrap();
        let tail = "; busbar at the pin speaks auth v3 (min = max = 3). Re-render it with busbar-release plugin sync.";
        let go = |json: &str| declares(d, "auth", json).unwrap().remove(0);
        assert_eq!(go("{}"), format!("DECLARES contract_abi is None{tail}"));
        assert_eq!(
            go(r#"{"contract_abi": {"max": 3, "min": true, "x": [1, "a", null, false]}}"#),
            format!("DECLARES contract_abi is {{'max': 3, 'min': True, 'x': [1, 'a', None, False]}}{tail}")
        );
        assert_eq!(
            go(r#"{"contract_abi": "s"}"#),
            format!("DECLARES contract_abi is s{tail}")
        );
        assert!(
            !declares(d, "auth", r#"{"contract_abi": {"max": 3.0, "min": true}}"#)
                .unwrap()
                .is_empty()
        );
        assert!(
            declares(d, "auth", r#"{"contract_abi": {"max": 3, "min": 3.0}}"#)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn import_text() {
        assert_eq!(
            found("imports socket"),
            ["IMPORT the built cdylib imports `connect` (line 3980)"]
        );
        assert_eq!(
            found("imports libssl"),
            ["IMPORT the built cdylib links `libssl.so.3` (line 3980)"]
        );
        let p = parse_toml(POLICY).unwrap();
        assert!(imports(&[], &["libsslx.so"], &p, "r").unwrap().is_empty());
        assert_eq!(imports(&[], &["libcrypto"], &p, "r").unwrap().len(), 1);
    }

    #[test]
    fn bothways_text() {
        assert_eq!(
            found("bothways no equality arm"),
            ["BOTHWAYS no `the_linked_and_the_dropped_in_*` test in the conformance target (linked door vs built cdylib, one transcript)"]
        );
        assert_eq!(
            found("bothways no RED arm"),
            ["BOTHWAYS no RED arm in the conformance target (a test proving the comparison can fail)"]
        );
    }

    #[test]
    fn req_ok_cases() {
        for (v, r, want) in [
            ("0.38.1", "=0.38.1", true),
            ("0.38.2", "=0.38.1", false),
            ("0.17.5", "0.17", true),
            ("0.18.0", "0.17", false),
            ("1.2.0", "1.1", true),
            ("2.0.0", "1", false),
            ("1.0.0+build", "=1.0.0", true),
        ] {
            assert_eq!(req_ok(v, r).unwrap(), want, "{v} vs {r}");
        }
    }

    #[test]
    fn toml_reader_reads_the_real_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join(".github/fleet/deps.toml")).unwrap();
        let d = parse_toml(&text).unwrap();
        assert_eq!(str_list(d.get("net-ban").get("carriers")).len(), 0);
        assert_eq!(d.get("c-deps").get("allow").as_array().unwrap().len(), 3);
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        assert!(parity(&lock, &lock).unwrap().is_empty());
    }
}
