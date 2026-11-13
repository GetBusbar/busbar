// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The rules and the commands. THE RULE SET IS THIS FILE: no flag, environment variable or config
//! skips a rule. A rule that is not here is recorded as `not-run` in the evidence, and the site
//! claims nothing for it. A rule that cannot run (a missing tool, an unreachable service) exits 3,
//! never 0. Every refusal is one line:
//!
//!   REFUSED <rule> <subject>: expected <x>; found <y>. <what to do>

use crate::archive::{Tar, Zip};
use crate::conformance;
use crate::py::{
    self, dict, disp, dumps, eq_str, head, name, opt_repr, opt_str, py_eq, py_repr, py_str,
    repr_list, repr_str, Dict, Dump, Kind, PyErr, Value, R,
};
use crate::world::{mkdtemp, mkstemp, run, tool, unpack_err, ModernCI, Net, Security};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const REPO: &str = "GetBusbar/busbar";
pub const IMAGE_REPOS: [&str; 2] = ["docker.io/getbusbar/busbar", "ghcr.io/getbusbar/busbar"];
pub const PLUGIN_TARGETS: [(&str, &str, &str); 5] = [
    ("x86_64-unknown-linux-gnu", "so", "lib"),
    ("aarch64-unknown-linux-gnu", "so", "lib"),
    ("x86_64-apple-darwin", "dylib", "lib"),
    ("aarch64-apple-darwin", "dylib", "lib"),
    ("x86_64-pc-windows-msvc", "dll", ""),
];
/// K2 signs release FILES under this sshsig namespace only. Release STATEMENTS (ModernCI RP-2)
/// are signed by the same hardware key under STATEMENT_NAMESPACE, so a file signature can never
/// be replayed as a statement, nor a statement as a file signature: sshsig binds the namespace
/// into what is signed, and allowed_signers restricts each key to one namespace (G-14).
pub const K2_NAMESPACE: &str = "busbar-release";
pub const STATEMENT_NAMESPACE: &str = "busbar-release-statement";
/// K2 also signs the version tag (`git tag -s` with gpg.format=ssh), which git signs and verifies
/// under the sshsig namespace "git". allowed_signers carries the same K2 key on its own line
/// limited to that namespace (G-14), so a tag signature can never stand in for a file signature,
/// nor the reverse.
pub const TAG_NAMESPACE: &str = "git";
pub const K2_IDENTITY: &str = "busbar-release";
/// A K2 key must be a FIDO2 hardware key: the key type proves it.
pub const K2_HARDWARE_TYPES: [&str; 2] = [
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];
pub const EXIT_OK: i32 = 0;
pub const EXIT_REFUSED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_CANNOT_RUN: i32 = 3;
pub const INDEX: &str = "plugin-index.json";
/// The tarball whose manifest states a plugin's ABI version.
pub const INDEX_TARGET: &str = "x86_64-unknown-linux-gnu";

fn s(x: &str) -> String {
    x.to_string()
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}

fn full(p: &str, x: &str) -> bool {
    re(&format!("^(?:{p})$")).is_match(x)
}

/// Python's `\S` (not `str.isspace()`).
const NS: &str = r"[^\s\x{1c}-\x{1f}]";
/// Python's `\s`.
const SP: &str = r"[\s\x{1c}-\x{1f}]";

fn cannot(msg: impl Into<String>) -> PyErr {
    PyErr::cannot_run(msg)
}

// ── the verdict ─────────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Verdict {
    pub refusals: Vec<String>,
    /// rule -> count of subjects checked
    pub checked: BTreeMap<String, usize>,
    pub evidence: Dict,
}

impl Verdict {
    pub fn ok(&mut self, rule: &str, n: usize) {
        *self.checked.entry(rule.to_string()).or_insert(0) += n;
    }
    pub fn refuse(&mut self, rule: &str, subject: &str, expected: &str, found: &str, todo: &str) {
        let line = format!("REFUSED {rule} {subject}: expected {expected}; found {found}. {todo}");
        println!("{line}");
        self.refusals.push(line);
    }
    fn refused_rule(&self, rule: &str) -> bool {
        self.refusals
            .iter()
            .any(|x| x.split_whitespace().nth(1) == Some(rule))
    }
}

// ── inputs ──────────────────────────────────────────────────────────────────────────────────────

/// The owner-held trust file: `k1` (the ROOT key list busbar embeds, BUSBAR_RELEASE_PUBKEY),
/// `release_signer` (the release signer's public key, `p256:<hex>`), `keys_doc` (the path of the
/// current root-signed keys document naming it), `k2_allowed_signers`.
pub struct Trust {
    pub raw: Dict,
    pub k1: String,
    pub release_signer: String,
    pub keys_doc: String,
    pub k2: Vec<String>,
}

fn expanduser(p: &str) -> String {
    if p == "~" || p.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!(
                "{}{}",
                home.to_string_lossy().trim_end_matches('/'),
                &p[1..]
            );
        }
    }
    p.to_string()
}

pub fn load_trust(path: &Path) -> R<Trust> {
    let t = py::loads(&py::read_text(path)?)?;
    let missing = |k: &str| PyErr::value(format!("trust file {} has no `{k}`", disp(path)));
    let d = match &t {
        Value::Dict(d) => d.clone(),
        Value::List(_) | Value::Str(_) => return Err(missing("k1")),
        v => {
            return Err(PyErr::type_err(format!(
                "argument of type '{}' is not iterable",
                v.type_name()
            )))
        }
    };
    for k in ["k1", "release_signer", "keys_doc", "k2_allowed_signers"] {
        if !d.contains(k) {
            return Err(missing(k));
        }
    }
    let text = |k: &str| -> R<String> {
        d.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| PyErr::type_err(format!("trust file `{k}` is not a string")))
    };
    let keys_doc = expanduser(&text("keys_doc")?);
    let keys_doc = if keys_doc.starts_with('/') {
        py::norm(&keys_doc)
    } else {
        let parent = path.parent().map(disp).unwrap_or_else(|| ".".into());
        py::norm(&format!("{parent}/{keys_doc}"))
    };
    let k2 = match d.get("k2_allowed_signers") {
        Some(Value::List(v)) => v
            .iter()
            .map(|x| {
                x.as_str().map(str::to_string).ok_or_else(|| {
                    PyErr::type_err("trust file `k2_allowed_signers` holds a non-string")
                })
            })
            .collect::<R<Vec<_>>>()?,
        _ => {
            return Err(PyErr::type_err(
                "trust file `k2_allowed_signers` is not a list of strings",
            ))
        }
    };
    let mut raw = d.clone();
    raw.insert("keys_doc", Value::Str(keys_doc.clone()));
    Ok(Trust {
        k1: text("k1")?,
        release_signer: text("release_signer")?,
        keys_doc,
        k2,
        raw,
    })
}

pub struct Inputs<'a> {
    /// the owner's clone at the release commit
    pub root: PathBuf,
    /// the candidate directory
    pub cand: PathBuf,
    pub trust: Trust,
    /// the owner-built busbar-plugin-pack
    pub pack: String,
    pub net: &'a dyn Net,
    /// only a test harness passes false; the CLI cannot
    pub require_hardware_k2: bool,
    pub mci: &'a dyn ModernCI,
    pub security: &'a dyn Security,
    /// `input(prompt)`: the owner's typed answer, or `None` at end of input.
    pub input: &'a dyn Fn(&str) -> Option<String>,
}

// ── small helpers ───────────────────────────────────────────────────────────────────────────────

/// `<64 hex>  <name>` lines, in order. A malformed line or a repeated name is an error.
pub fn read_sums(p: &Path) -> R<Vec<(String, String)>> {
    let text = py::read_text(p)?;
    let line_re = re(&format!(r"^([0-9a-f]{{64}})[ \t]+\*?({NS}+)$"));
    let mut out: Vec<(String, String)> = Vec::new();
    for (i, line) in py::splitlines(&text).into_iter().enumerate() {
        let l = py::strip(line);
        if l.is_empty() {
            continue;
        }
        let Some(m) = line_re.captures(l) else {
            return Err(PyErr::value(format!(
                "{}:{} is not `<sha256>  <name>`",
                name(p),
                i + 1
            )));
        };
        if out.iter().any(|(n, _)| n == &m[2]) {
            return Err(PyErr::value(format!(
                "{}:{} names {} twice",
                name(p),
                i + 1,
                &m[2]
            )));
        }
        out.push((m[2].to_string(), m[1].to_string()));
    }
    Ok(out)
}

fn sums_get<'a>(sums: &'a [(String, String)], k: &str) -> Option<&'a str> {
    sums.iter().find(|(n, _)| n == k).map(|(_, d)| d.as_str())
}

pub fn write_sums(p: &Path, files: &[PathBuf]) -> R<()> {
    let mut files: Vec<&PathBuf> = files.iter().collect();
    files.sort_by_key(|f| name(f));
    let mut text = String::new();
    for f in files {
        text.push_str(&format!("{}  {}\n", py::sha256_file(f)?, name(f)));
    }
    py::write_text(p, &text)
}

pub fn commit_key_list(root: &Path) -> R<String> {
    let text = py::read_text(&root.join(".cargo/config.toml"))?;
    let m = re(&format!(
        r#"(?m)^{SP}*BUSBAR_RELEASE_PUBKEY{SP}*={SP}*"([^"]*)""#
    ))
    .captures(&text)
    .ok_or_else(|| PyErr::value(".cargo/config.toml sets no BUSBAR_RELEASE_PUBKEY"))?;
    Ok(m[1].to_string())
}

pub fn release_targets(root: &Path) -> R<Vec<Value>> {
    let doc = py::loads(&py::read_text(&root.join("release/release-targets.json"))?)?;
    doc.item("targets")?.iter_items()
}

fn tget<'a>(t: &'a Value, k: &str) -> R<Option<&'a Value>> {
    t.get(k)
}

fn tstr(t: &Value, k: &str) -> R<String> {
    Ok(py_str(t.item(k)?))
}

/// The entries under `plugins:` in plugins.yaml, as {field: raw value}. There is no YAML parser
/// here: each entry is a `  - repo:` line followed by `    field: value` lines.
pub fn registry_entries(root: &Path) -> R<Vec<Vec<(String, String)>>> {
    let text = py::read_text(&root.join("plugins.yaml"))?;
    let lines = py::splitlines(&text);
    let top = re(&format!("^plugins:{SP}*$"));
    let start = lines
        .iter()
        .position(|l| top.is_match(l))
        .ok_or_else(|| PyErr::value("plugins.yaml has no top-level `plugins:` list"))?;
    let repo_re = re(&format!(r"^  - repo:{SP}*([A-Za-z0-9._-]+){SP}*$"));
    let field_re = re(&format!(r"^    ([a-z_]+):{SP}*(.*?){SP}*$"));
    let mut entries: Vec<Vec<(String, String)>> = Vec::new();
    for line in &lines[start + 1..] {
        if !line.is_empty() && !line.starts_with([' ', '#', '-']) {
            break;
        }
        if let Some(m) = repo_re.captures(line) {
            entries.push(vec![(s("repo"), m[1].to_string())]);
            continue;
        }
        if let Some(m) = field_re.captures(line) {
            if let Some(e) = entries.last_mut() {
                let (k, v) = (m[1].to_string(), m[2].to_string());
                match e.iter_mut().find(|(x, _)| *x == k) {
                    Some(slot) => slot.1 = v,
                    None => e.push((k, v)),
                }
            }
        }
    }
    if entries.is_empty() {
        return Err(PyErr::value("plugins.yaml lists no plugins"));
    }
    Ok(entries)
}

fn eget<'a>(e: &'a [(String, String)], k: &str) -> Option<&'a str> {
    e.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
}

/// The first-party plugins a release owes: every registered repo except an empty one
/// (`pending_crate: true`, which has no crate to build).
pub fn registry_plugins(root: &Path) -> R<Vec<String>> {
    Ok(registry_entries(root)?
        .into_iter()
        .filter(|e| eget(e, "pending_crate").unwrap_or("false") != "true")
        .map(|e| eget(&e, "repo").unwrap_or("").to_string())
        .collect())
}

// ── the release index ───────────────────────────────────────────────────────────────────────────

fn once(v: &mut Vec<String>, x: &str) {
    if !x.is_empty() && !v.iter().any(|y| y == x) {
        v.push(x.to_string());
    }
}

fn basename(n: &str) -> &str {
    n.rsplit_once('/').map(|x| x.1).unwrap_or(n)
}

/// The manifest.json inside a plugin tarball.
pub fn tarball_manifest(p: &Path) -> R<Value> {
    let t = Tar::open(p)?;
    for (i, m) in t.members.iter().enumerate() {
        if m.isfile() && basename(&m.name) == "manifest.json" {
            return py::loads_bytes(&t.extract(i)?.unwrap_or_default());
        }
    }
    Err(PyErr::value(format!("{} holds no manifest.json", name(p))))
}

/// plugin-index.json, the release index `busbar --migrate-config` reads from this release's own
/// GitHub Release (crates/busbar/src/root/config_migrate.rs, `Index::parse`):
///
///   {"plugins": [{"repo", "former_repos", "kind", "answers_to", "releases": [{"tag", "abi_version"}]}]}
///
/// One entry per plugin the candidate releases (candidate.json, which G-3 holds equal to
/// release/plugin-pins.tsv and plugins.yaml), in repo order:
/// - repo `GetBusbar/<repo>`; former_repos: the earlier names GitHub still redirects to it
///   (`<kind>-<name>`, `<name>-<kind>`, each former manifest name without `busbar-`/`-plugin`);
/// - kind, and answers_to: the manifest name, alias, crate and former names (plugins.yaml);
/// - releases: this release's tag, with the ABI version the built tarball's manifest states.
///
/// The same bytes for the same inputs: the candidate writes it, the gate re-renders it.
pub fn render_plugin_index(
    root: &Path,
    cand: &Path,
    plugins: &[Value],
    net: &dyn Net,
) -> R<Vec<u8>> {
    let entries = registry_entries(root)?;
    let mut sorted: Vec<(String, &Value)> = Vec::new();
    for p in plugins {
        sorted.push((p.item_str("repo")?.to_string(), p));
    }
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let word = re("[A-Za-z0-9._-]+");
    let mut out: Vec<Value> = Vec::new();
    for (repo, p) in sorted {
        let e = entries
            .iter()
            .rev()
            .find(|e| eget(e, "repo") == Some(repo.as_str()))
            .ok_or_else(|| PyErr::value(format!("{repo} is not registered in plugins.yaml")))?;
        let unq = |k: &str, d: &str| -> String {
            py::strip(eget(e, k).unwrap_or(d))
                .trim_matches('"')
                .to_string()
        };
        let kind = unq("kind", "");
        let former_names: Vec<String> = word
            .find_iter(eget(e, "former_names").unwrap_or(""))
            .map(|m| m.as_str().to_string())
            .collect();
        let mut answers: Vec<String> = Vec::new();
        for w in [
            unq("manifest_name", &repo),
            unq("alias", ""),
            unq("crate", ""),
        ]
        .iter()
        .chain(former_names.iter())
        {
            once(&mut answers, w);
        }
        let stem = repo.strip_prefix("busbar-").unwrap_or(&repo).to_string();
        let nm = stem
            .strip_prefix(&format!("{kind}-"))
            .map(str::to_string)
            .unwrap_or_default();
        let mut cands: Vec<String> = Vec::new();
        once(&mut cands, &stem);
        once(
            &mut cands,
            &if nm.is_empty() {
                String::new()
            } else {
                format!("{nm}-{kind}")
            },
        );
        for n in &former_names {
            let n = n.strip_prefix("busbar-").unwrap_or(n);
            once(&mut cands, n.strip_suffix("-plugin").unwrap_or(n));
        }
        let mut former: Vec<Value> = Vec::new();
        for c in &cands {
            if *c == repo {
                continue;
            }
            let full_name = net
                .repo_full_name(&format!("GetBusbar/{c}"))?
                .unwrap_or_default();
            if full_name.to_lowercase() == format!("getbusbar/{repo}").to_lowercase() {
                former.push(Value::Str(format!("GetBusbar/{c}")));
            }
        }
        let version = py_str(p.item("version")?);
        let manifest = tarball_manifest(
            &cand
                .join("plugins")
                .join(format!("{repo}-{version}-{INDEX_TARGET}.tar.gz")),
        )?;
        let abi = manifest.getv("abi_version")?;
        let ok = matches!(&abi, Value::Int(_))
            && abi
                .as_int()
                .is_some_and(|n| (0..(1i128 << 32)).contains(&n));
        if !ok {
            return Err(PyErr::value(format!(
                "{repo}'s {INDEX_TARGET} manifest states no abi_version"
            )));
        }
        out.push(Value::Dict(dict([
            ("repo", Value::Str(format!("GetBusbar/{repo}"))),
            ("former_repos", Value::List(former)),
            ("kind", Value::Str(kind)),
            (
                "answers_to",
                Value::List(answers.into_iter().map(Value::Str).collect()),
            ),
            (
                "releases",
                Value::List(vec![Value::Dict(dict([
                    ("tag", p.item("tag")?.clone()),
                    ("abi_version", abi),
                ]))]),
            ),
        ])));
    }
    let doc = Value::Dict(dict([("plugins", Value::List(out))]));
    Ok((dumps(&doc, Dump::INDENT) + "\n").into_bytes())
}

// ── the rules ───────────────────────────────────────────────────────────────────────────────────

fn git(root: &Path, args: &[&str]) -> Vec<String> {
    let mut v = vec![s("git"), s("-C"), disp(root)];
    v.extend(args.iter().map(|a| a.to_string()));
    v
}

fn plugins_of(cj: &Value) -> R<Vec<Value>> {
    cj.item("plugins")?.iter_items()
}

fn set_key(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        other => format!("\u{0}{}", py_repr(other)),
    }
}

/// (published core files, sbom files, internal files, plugin tarballs) the candidate owes.
pub fn expected_files(root: &Path, cj: &Value) -> R<[Vec<String>; 4]> {
    let v = py_str(cj.item("version")?);
    let (mut pubf, mut sboms, mut internal, mut plugins) = (vec![], vec![], vec![], vec![]);
    for t in release_targets(root)? {
        let kind = tget(&t, "kind")?;
        let published = tget(&t, "published")?.map(Value::truthy).unwrap_or(false);
        if eq_str(kind, "binary") && published {
            let (tt, ar) = (tstr(&t, "target")?, tstr(&t, "archive")?);
            pubf.push(format!("busbar-{tt}.{ar}"));
            sboms.push(format!("busbar-v{v}-{tt}.cdx.json"));
            pubf.push(format!("busbar-audit-verify-{tt}.{ar}"));
            sboms.push(format!("busbar-audit-verify-v{v}-{tt}.cdx.json"));
        } else if eq_str(kind, "binary") {
            internal.push(format!(
                "busbar-{}.{}",
                tstr(&t, "target")?,
                tstr(&t, "archive")?
            ));
        } else if eq_str(kind, "image") {
            sboms.push(format!("busbar-v{v}-{}.cdx.json", tstr(&t, "target")?));
        }
    }
    pubf.push(format!("busbar-openapi-v{v}.json"));
    pubf.push(INDEX.to_string());
    for p in plugins_of(cj)? {
        for (target, _, _) in PLUGIN_TARGETS {
            plugins.push(format!(
                "{}-{}-{target}.tar.gz",
                py_str(p.item("repo")?),
                py_str(p.item("version")?)
            ));
        }
    }
    for x in [&mut pubf, &mut sboms, &mut internal, &mut plugins] {
        x.sort();
        x.dedup();
    }
    Ok([pubf, sboms, internal, plugins])
}

fn g1_version(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let v = cj.item("version")?;
    let vs = py_str(v);
    let cargo = py::read_text(&inp.root.join("crates/busbar/Cargo.toml"))?;
    let m = re(&format!(r#"(?m)^{SP}*version{SP}*={SP}*"([^"]+)""#))
        .captures(&cargo)
        .map(|m| m[1].to_string());
    if !m.as_deref().is_some_and(|x| eq_str(Some(v), x)) {
        vd.refuse(
            "G-1",
            "crates/busbar/Cargo.toml",
            &format!("version {vs}"),
            m.as_deref().unwrap_or("none"),
            "Bump with RELEASE.md's commands on dev, or fix candidate.json.",
        );
    }
    let changelog = py::read_text(&inp.root.join("CHANGELOG.md"))?;
    let heads: Vec<String> = re(r"(?m)^## \[([^\]]+)\]")
        .captures_iter(&changelog)
        .map(|m| m[1].to_string())
        .collect();
    let first = heads.iter().find(|h| h.to_lowercase() != "unreleased");
    if !first.is_some_and(|f| eq_str(Some(v), f)) {
        vd.refuse(
            "G-1",
            "CHANGELOG.md",
            &format!("newest section [{vs}]"),
            &format!("[{}]", first.cloned().unwrap_or_else(|| "None".into())),
            "Roll the changelog (RELEASE.md).",
        );
    }
    let head_ = py::strip(&run(&git(&inp.root, &["rev-parse", "HEAD"]), None, true)?.stdout_str()?)
        .to_string();
    let commit = cj.item("commit")?;
    if !eq_str(Some(commit), &head_) {
        vd.refuse(
            "G-1",
            "clone",
            &format!("your clone at {}", py_str(commit)),
            &head_,
            "Check out the release commit in your own clone; the gate reads its keys and rules from there.",
        );
    }
    let c = cj.getv("commit")?;
    let cs = match &c {
        Value::Str(x) => x.clone(),
        other => {
            return Err(PyErr::type_err(format!(
                "expected string or bytes-like object, got '{}'",
                other.type_name()
            )))
        }
    };
    if !full("[0-9a-f]{40}", &cs) {
        vd.refuse(
            "G-1",
            "candidate.json",
            "a 40-hex commit",
            &py_repr(&c),
            "Fix the candidate.",
        );
    }
    if !eq_str(cj.get("repo")?, REPO) {
        vd.refuse(
            "G-1",
            "candidate.json",
            &format!("repo {REPO}"),
            &opt_repr(cj.get("repo")?),
            "A release is built only from the canonical repo (no forks).",
        );
    }
    vd.ok("G-1", 1);
    Ok(())
}

/// IMAGES: `<name> sha256:<digest>` lines.
pub fn read_images(p: &Path) -> R<Dict> {
    let mut out = Dict::new();
    for line in py::splitlines(&py::read_text(p)?) {
        if py::strip(line).is_empty() {
            continue;
        }
        let parts = py::split_ws(line);
        if parts.len() != 2 {
            return Err(unpack_err(2, parts.len()));
        }
        if !full("sha256:[0-9a-f]{64}", parts[1]) {
            return Err(PyErr::value(format!(
                "IMAGES: {} is not a sha256 digest",
                repr_str(parts[1])
            )));
        }
        out.insert(parts[0], Value::from(parts[1]));
    }
    Ok(out)
}

fn g2_not_published(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let v = py_str(cj.item("version")?);
    if inp.net.release_exists(REPO, &format!("v{v}"))? {
        vd.refuse(
            "G-2",
            &format!("v{v}"),
            "no GitHub Release for this version",
            "one exists",
            "A version is published once; bump the version.",
        );
    }
    for p in plugins_of(cj)? {
        let repo = py_str(p.item("repo")?);
        let tag = py_str(p.item("tag")?);
        if inp
            .net
            .release_published(&format!("GetBusbar/{repo}"), &tag)?
        {
            vd.refuse(
                "G-2",
                &format!("{repo} {tag}"),
                "no published release (a draft is fine)",
                "published",
                "A plugin version is published once; tag a new one.",
            );
        }
    }
    let images = read_images(&inp.cand.join("IMAGES"))?;
    for repo in IMAGE_REPOS {
        let d = inp.net.registry_digest(&format!("{repo}:{v}"))?;
        if let Some(d) = d {
            if !eq_str(images.get("busbar"), &d) {
                vd.refuse(
                    "G-2",
                    &format!("{repo}:{v}"),
                    &format!("absent or {}", opt_str(images.get("busbar"))),
                    &d,
                    "That tag already holds another image; bump the version.",
                );
            }
        }
    }
    vd.ok("G-2", 1);
    Ok(())
}

fn file_names(d: &Path) -> Vec<String> {
    if !py::is_dir(d) {
        return Vec::new();
    }
    let mut v: Vec<String> = py::iterdir(d)
        .unwrap_or_default()
        .into_iter()
        .filter(|f| py::is_file(f))
        .map(|f| name(&f))
        .collect();
    v.sort();
    v
}

fn tuple_repr(a: &Value, b: &Value) -> String {
    format!("({}, {})", py_repr(a), py_repr(b))
}

fn g3_g4_sets_and_sums(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let [pubf, sboms, internal, plugins] = expected_files(&inp.root, cj)?;
    for (sub, want) in [
        ("artifacts", &pubf),
        ("sboms", &sboms),
        ("internal", &internal),
        ("plugins", &plugins),
    ] {
        let have = file_names(&inp.cand.join(sub));
        for n in want.iter().filter(|n| !have.contains(n)) {
            vd.refuse(
                "G-3",
                &format!("{sub}/{n}"),
                "present",
                "missing",
                "Every declared target and plugin is owed; a missing one is never skipped.",
            );
        }
        for n in have.iter().filter(|n| !want.contains(n)) {
            vd.refuse(
                "G-3",
                &format!("{sub}/{n}"),
                "absent (not declared)",
                "present",
                "Only declared artifacts ship; declare it in release-targets.json/plugins.yaml or drop it.",
            );
        }
        vd.ok("G-3", want.len());
    }
    // The plugin set equals the committed pins (release/plugin-pins.tsv) at the release commit.
    let mut pins: Vec<(String, (String, String))> = Vec::new();
    let read = (|| -> R<()> {
        let text = py::read_text(&inp.root.join("release/plugin-pins.tsv"))?;
        for line in py::splitlines(&text) {
            if !py::strip(line).is_empty() && !line.starts_with('#') {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() != 3 {
                    return Err(unpack_err(3, parts.len()));
                }
                let row = (parts[1].to_string(), parts[2].to_string());
                match pins.iter_mut().find(|(r, _)| r == parts[0]) {
                    Some(slot) => slot.1 = row,
                    None => pins.push((parts[0].to_string(), row)),
                }
            }
        }
        Ok(())
    })();
    match read {
        Ok(()) => {}
        Err(e) if e.is_os() || e.is_value() => vd.refuse(
            "G-3",
            "release/plugin-pins.tsv",
            "<repo>\\t<tag>\\t<commit> lines",
            &e.msg,
            "Run candidate.py pins and commit it.",
        ),
        Err(e) => return Err(e),
    }
    let cplugins = plugins_of(cj)?;
    let mut got_set: Vec<String> = Vec::new();
    for p in &cplugins {
        let repo = p.item("repo")?;
        got_set.push(set_key(repo));
        let want = match repo {
            Value::Str(r) => pins.iter().find(|(k, _)| k == r).map(|(_, t)| t.clone()),
            _ => None,
        };
        let tag = p.getv("tag")?;
        let commit = p.getv("commit")?;
        let version = p.getv("version")?;
        let same = match &want {
            Some((t, c)) => eq_str(Some(&tag), t) && eq_str(Some(&commit), c),
            None => false,
        };
        let want_version = match &want {
            Some((t, _)) => py::tail_from(t, 1),
            None => "?".to_string(),
        };
        if !same || !eq_str(Some(&version), &want_version) {
            let wanted = match &want {
                Some((t, c)) => format!("({}, {})", repr_str(t), repr_str(c)),
                None => "None".into(),
            };
            vd.refuse(
                "G-3",
                &format!("plugin {}", py_str(repo)),
                &format!("pinned {wanted}"),
                &format!("{} version {}", tuple_repr(&tag, &commit), py_str(&version)),
                "The candidate must build exactly the committed pins.",
            );
        }
    }
    let mut pinned: Vec<&String> = pins.iter().map(|(k, _)| k).collect();
    pinned.sort();
    for r in pinned {
        if !got_set.contains(r) {
            vd.refuse(
                "G-3",
                &format!("plugin {r}"),
                "built (pinned in release/plugin-pins.tsv)",
                "absent from candidate.json",
                "Rebuild the plugins slice.",
            );
        }
    }
    // The plugin set equals the registry.
    let mut reg = registry_plugins(&inp.root)?;
    reg.sort();
    reg.dedup();
    got_set.sort();
    got_set.dedup();
    for r in reg.iter().filter(|r| !got_set.contains(r)) {
        vd.refuse(
            "G-3",
            &format!("plugin {r}"),
            "released with this version (plugins.yaml)",
            "absent from candidate.json",
            "Tag and build every first-party plugin, or remove it from plugins.yaml in a judged change.",
        );
    }
    for r in got_set.iter().filter(|r| !reg.contains(r)) {
        let shown = r.strip_prefix('\u{0}').unwrap_or(r);
        vd.refuse(
            "G-3",
            &format!("plugin {shown}"),
            "in plugins.yaml",
            "not registered",
            "Only registered first-party plugins are released.",
        );
    }
    // The release index is the render of this candidate's plugins (the binary's default URL
    // fetches it).
    let index = inp.cand.join("artifacts").join(INDEX);
    if py::is_file(&index) {
        match render_plugin_index(&inp.root, &inp.cand, &cplugins, inp.net) {
            Err(e) if e.is_os() || e.is_value() || e.is_key() || e.is_tar() => vd.refuse(
                "G-3",
                &format!("artifacts/{INDEX}"),
                "the index rendered from the candidate's plugins",
                &format!("no render: {}", e.msg),
                "Every plugin's tarball must state its ABI version; rebuild the plugins slice.",
            ),
            Err(e) => return Err(e),
            Ok(want_index) => {
                if py::read_bytes(&index)? != want_index {
                    vd.refuse(
                        "G-3",
                        &format!("artifacts/{INDEX}"),
                        "the index rendered from the candidate's plugins",
                        "different bytes",
                        "Run candidate.py assemble again; the index is never edited by hand.",
                    );
                }
            }
        }
    }
    // SHA256SUMS covers exactly artifacts/ + sboms/, and every line matches the bytes.
    let sums = match read_sums(&inp.cand.join("SHA256SUMS")) {
        Ok(s) => s,
        Err(e) if e.is_os() || e.is_value() => {
            vd.refuse(
                "G-4",
                "SHA256SUMS",
                "a well-formed sums file",
                &e.msg,
                "The candidate must write it.",
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
    for sub in ["artifacts", "sboms"] {
        let d = inp.cand.join(sub);
        if py::is_dir(&d) {
            for f in py::iterdir(&d)? {
                if py::is_file(&f) {
                    files.insert(name(&f), f);
                }
            }
        }
    }
    let listed: Vec<&String> = sums.iter().map(|(n, _)| n).collect();
    let mut either: Vec<&String> = files
        .keys()
        .filter(|n| !listed.contains(n))
        .chain(listed.iter().copied().filter(|n| !files.contains_key(*n)))
        .collect();
    either.sort();
    for n in either {
        vd.refuse(
            "G-4",
            n,
            "listed in SHA256SUMS exactly when present",
            if listed.contains(&n) {
                "listed"
            } else {
                "unlisted"
            },
            "SHA256SUMS must name every published file and nothing else.",
        );
    }
    for (n, f) in &files {
        if let Some(want) = sums_get(&sums, n) {
            let got = py::sha256_file(f)?;
            if got != want {
                vd.refuse(
                    "G-4",
                    n,
                    want,
                    &got,
                    "The bytes changed after the build; do not publish.",
                );
            }
        }
    }
    vd.ok("G-4", listed.len());
    Ok(())
}

fn pack_out(inp: &Inputs, args: &[String]) -> R<(i32, String)> {
    let mut cmd = vec![inp.pack.clone()];
    cmd.extend(args.iter().cloned());
    let p = run(&cmd, None, false)?;
    let mut both = p.stdout.clone();
    both.extend_from_slice(&p.stderr);
    Ok((
        p.code,
        py::strip(&String::from_utf8_lossy(&both)).to_string(),
    ))
}

fn kv(line: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for m in re(&format!("({NS}+?)=({NS}+)")).captures_iter(line) {
        let (k, v) = (m[1].to_string(), m[2].to_string());
        match out.iter_mut().find(|(x, _)| *x == k) {
            Some(slot) => slot.1 = v,
            None => out.push((k, v)),
        }
    }
    out
}

fn kget<'a>(m: &'a [(String, String)], k: &str) -> Option<&'a str> {
    m.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
}

/// One verified unsigned plugin tarball.
pub struct Row {
    pub repo: Value,
    pub target: String,
    pub file: String,
    pub canonical: Option<String>,
    pub lib: Option<String>,
}

/// Pre-sign: every plugin tarball is first-party, unsigned and its expected self.
fn g5_plugins_unsigned(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<Vec<Row>> {
    let mut rows = Vec::new();
    for p in plugins_of(cj)? {
        let repo = p.item("repo")?;
        let version = p.item("version")?;
        for (target, _, _) in PLUGIN_TARGETS {
            let file = format!("{}-{}-{target}.tar.gz", py_str(repo), py_str(version));
            let f = inp.cand.join("plugins").join(&file);
            if !py::is_file(&f) {
                continue; // G-3 refused it
            }
            let (code, out) = pack_out(inp, &[s("canonical"), disp(&f)])?;
            if code != 0 {
                vd.refuse(
                    "G-5",
                    &file,
                    "a plugin tarball",
                    &out,
                    "Rebuild it with busbar-plugin-pack pack.",
                );
                continue;
            }
            let m = kv(&out);
            for (k, want) in [
                ("name", py_str(repo)),
                ("version", py_str(version)),
                ("publisher", s("busbar")),
                ("signed", s("false")),
            ] {
                let is_str = |v: &Value| matches!(v, Value::Str(_));
                let want_ok = match k {
                    "name" => is_str(repo),
                    "version" => is_str(version),
                    _ => true,
                };
                if kget(&m, k) != Some(want.as_str()) || !want_ok {
                    vd.refuse(
                        "G-5",
                        &file,
                        &format!("{k}={want}"),
                        &format!("{k}={}", kget(&m, k).unwrap_or("None")),
                        "CI packs first-party plugins UNSIGNED, with the registry name and the tag's version.",
                    );
                }
            }
            rows.push(Row {
                repo: repo.clone(),
                target: target.to_string(),
                file,
                canonical: kget(&m, "canonical-sha256").map(str::to_string),
                lib: kget(&m, "lib-sha256").map(str::to_string),
            });
            vd.ok("G-5", 1);
        }
    }
    Ok(rows)
}

/// The busbar binary inside a release archive.
pub fn unpack_binary(archive: &Path) -> R<Vec<u8>> {
    if name(archive).ends_with(".zip") {
        let z = Zip::open(archive)?;
        let names: Vec<String> = z
            .namelist()
            .into_iter()
            .filter(|n| matches!(basename(n), "busbar.exe" | "busbar"))
            .collect();
        if names.len() != 1 {
            return Err(PyErr::value(format!(
                "{}: expected one busbar binary, found {}",
                name(archive),
                repr_list(&names)
            )));
        }
        return z.read(&names[0]);
    }
    let t = Tar::open(archive)?;
    let hits: Vec<usize> = t
        .members
        .iter()
        .enumerate()
        .filter(|(_, m)| m.isfile() && matches!(basename(&m.name), "busbar" | "busbar.exe"))
        .map(|(i, _)| i)
        .collect();
    if hits.len() != 1 {
        let names: Vec<&str> = hits.iter().map(|i| t.members[*i].name.as_str()).collect();
        return Err(PyErr::value(format!(
            "{}: expected one busbar binary, found {}",
            name(archive),
            repr_list(&names)
        )));
    }
    Ok(t.extract(hits[0])?.unwrap_or_default())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

fn verifier_package(tool_path: &Path, executable: &str, zip: bool) -> R<()> {
    let mut want = vec![executable.to_string(), s("audit-verify.md")];
    want.sort();
    if zip {
        let archive = Zip::open(tool_path)?;
        let mut names: Vec<String> = archive.entries.iter().map(|e| e.filename.clone()).collect();
        names.sort();
        if names != want || archive.entries.iter().any(|e| e.is_dir()) {
            return Err(PyErr::value(
                "expected exactly the verifier and audit-verify.md",
            ));
        }
        if archive.read(executable)?.is_empty() || archive.read("audit-verify.md")?.is_empty() {
            return Err(PyErr::value("an empty verifier or instructions"));
        }
    } else {
        let archive = Tar::open(tool_path)?;
        let mut names: Vec<String> = archive.members.iter().map(|m| m.name.clone()).collect();
        names.sort();
        if names != want || archive.members.iter().any(|m| !m.isfile()) {
            return Err(PyErr::value(
                "expected exactly regular verifier and instructions files",
            ));
        }
        let exe = archive.extract_name(executable)?.unwrap_or_default();
        if exe.is_empty() {
            return Err(PyErr::value("an empty verifier or instructions"));
        }
        let doc = archive.extract_name("audit-verify.md")?.unwrap_or_default();
        if doc.is_empty() {
            return Err(PyErr::value("an empty verifier or instructions"));
        }
    }
    Ok(())
}

fn g6_embedded_keys(inp: &Inputs, vd: &mut Verdict) -> R<()> {
    let keys = inp.trust.k1.as_bytes();
    for target in release_targets(&inp.root)? {
        if !eq_str(tget(&target, "kind")?, "binary") {
            continue;
        }
        let published = tget(&target, "published")?
            .map(Value::truthy)
            .unwrap_or(false);
        let sub = if published { "artifacts" } else { "internal" };
        let (tt, ar) = (tstr(&target, "target")?, tstr(&target, "archive")?);
        let f = inp.cand.join(sub).join(format!("busbar-{tt}.{ar}"));
        if py::is_file(&f) {
            match unpack_binary(&f) {
                Ok(binary) => {
                    if !contains(&binary, keys) {
                        vd.refuse(
                            "G-6",
                            &name(&f),
                            "the trusted key list embedded",
                            "not embedded",
                            "The server build dropped BUSBAR_RELEASE_PUBKEY; rebuild.",
                        );
                    } else {
                        vd.ok("G-6", 1);
                    }
                }
                Err(e) if e.is_os() || e.is_value() || e.is_tar() || e.kind == Kind::BadZip => vd
                    .refuse(
                        "G-6",
                        &name(&f),
                        "an archive holding the busbar binary",
                        &e.msg,
                        "Rebuild.",
                    ),
                Err(e) => return Err(e),
            }
        }
        if !published {
            continue;
        }
        let tool_path = inp
            .cand
            .join("artifacts")
            .join(format!("busbar-audit-verify-{tt}.{ar}"));
        if !py::is_file(&tool_path) {
            continue; // G-3 refuses a missing asset.
        }
        let executable = format!(
            "busbar-audit-verify{}",
            if tt.contains("windows") { ".exe" } else { "" }
        );
        match verifier_package(&tool_path, &executable, ar == "zip") {
            Ok(()) => vd.ok("G-6", 1),
            Err(e)
                if e.is_os()
                    || e.is_value()
                    || e.is_tar()
                    || e.kind == Kind::BadZip
                    || e.is_key() =>
            {
                vd.refuse(
                    "G-6",
                    &name(&tool_path),
                    "the standalone verifier with instructions",
                    &e.msg,
                    "Rebuild the verifier package.",
                )
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn g8_sboms(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let dir = inp.cand.join("sboms");
    let mut files: Vec<PathBuf> = if py::is_dir(&dir) {
        py::iterdir(&dir)?
            .into_iter()
            .filter(|f| name(f).ends_with(".cdx.json"))
            .collect()
    } else {
        Vec::new()
    };
    files.sort();
    let version = cj.item("version")?;
    for f in files {
        let d = match py::read_text(&f).and_then(|t| py::loads(&t)) {
            Ok(d) => d,
            Err(e) if e.is_os() || e.is_value() => {
                vd.refuse(
                    "G-8",
                    &name(&f),
                    "CycloneDX JSON",
                    &e.msg,
                    "Regenerate the SBOM.",
                );
                continue;
            }
            Err(e) => return Err(e),
        };
        let pick = |v: &Value, k: &str| -> R<Value> {
            let x = v.getv(k)?;
            Ok(if x.truthy() {
                x
            } else {
                Value::Dict(Dict::new())
            })
        };
        let ver = pick(&pick(&d, "metadata")?, "component")?.getv("version")?;
        let fmt = d.getv("bomFormat")?;
        if !eq_str(Some(&fmt), "CycloneDX") || !py_eq(&ver, version) {
            vd.refuse(
                "G-8",
                &name(&f),
                &format!("CycloneDX for version {}", py_str(version)),
                &format!("bomFormat={} version={}", py_str(&fmt), py_str(&ver)),
                "Regenerate the SBOM for this build.",
            );
        }
        vd.ok("G-8", 1);
    }
    Ok(())
}

fn oci_blob(t: &Tar, digest: &Value) -> R<Vec<u8>> {
    let d = digest.as_str().ok_or_else(|| {
        PyErr::new(
            Kind::Attribute,
            format!("'{}' object has no attribute 'split'", digest.type_name()),
        )
    })?;
    let (algo, hexd) = d.split_once(':').ok_or_else(|| unpack_err(2, 1))?;
    let b = t
        .extract_name(&format!("blobs/{algo}/{hexd}"))?
        .ok_or_else(|| PyErr::value(format!("blob {d} missing")))?;
    if py::sha256_hex(&b) != hexd {
        return Err(PyErr::value(format!("blob {d} does not hash to its name")));
    }
    Ok(b)
}

fn g10_image(inp: &Inputs, vd: &mut Verdict) -> R<()> {
    let mut arch_to_internal: BTreeMap<String, PathBuf> = BTreeMap::new();
    for t in release_targets(&inp.root)? {
        let into = match tget(&t, "packaged_into")? {
            Some(v) => py_str(v),
            None => String::new(),
        };
        if eq_str(tget(&t, "kind")?, "binary") && into.starts_with("image-linux-") {
            let published = tget(&t, "published")?.map(Value::truthy).unwrap_or(false);
            let arch = into.rsplit_once('-').map(|x| x.1).unwrap_or("").to_string();
            let sub = if published { "artifacts" } else { "internal" };
            arch_to_internal.insert(
                arch,
                inp.cand.join(sub).join(format!(
                    "busbar-{}.{}",
                    tstr(&t, "target")?,
                    tstr(&t, "archive")?
                )),
            );
        }
    }
    match g10_inner(inp, vd, &arch_to_internal) {
        Err(e) if e.is_os() || e.is_key() || e.is_value() || e.is_tar() => {
            vd.refuse(
                "G-10",
                "oci/busbar.oci.tar",
                "a readable OCI layout of the image",
                &e.msg,
                "Rebuild the image archive.",
            );
            Ok(())
        }
        other => other,
    }
}

fn g10_inner(
    inp: &Inputs,
    vd: &mut Verdict,
    arch_to_internal: &BTreeMap<String, PathBuf>,
) -> R<()> {
    let images = read_images(&inp.cand.join("IMAGES"))?;
    let want = images
        .get("busbar")
        .ok_or_else(|| PyErr::key("busbar"))?
        .clone();
    let t = Tar::open(&inp.cand.join("oci/busbar.oci.tar"))?;
    let index_bytes = t
        .extract_name("index.json")?
        .ok_or_else(|| PyErr::new(Kind::Attribute, "'NoneType' object has no attribute 'read'"))?;
    let index = py::loads_bytes(&index_bytes)?;
    let descs = match index.get("manifests")? {
        None => Vec::new(),
        Some(v) => v.iter_items()?,
    };
    if descs.len() != 1 {
        return Err(PyErr::value(format!(
            "index.json holds {} descriptors, expected the one image index",
            descs.len()
        )));
    }
    let top = descs[0].item("digest")?.clone();
    if !py_eq(&top, &want) {
        vd.refuse(
            "G-10",
            "IMAGES",
            &py_str(&want),
            &py_str(&top),
            "IMAGES must name the archive's image index digest.",
        );
    }
    let top_doc = py::loads_bytes(&oci_blob(&t, &top)?)?;
    let mut plats: BTreeMap<String, Value> = BTreeMap::new();
    let manifests = match top_doc.get("manifests")? {
        None => Vec::new(),
        Some(v) => v.iter_items()?,
    };
    for m in manifests {
        let platform = match m.get("platform")? {
            Some(p) => p.clone(),
            None => Value::Dict(Dict::new()),
        };
        if eq_str(platform.get("os")?, "linux") {
            let arch = py_str(m.item("platform")?.item("architecture")?);
            plats.insert(arch, m.item("digest")?.clone());
        }
    }
    let want_archs: Vec<&String> = arch_to_internal.keys().collect();
    let have_archs: Vec<&String> = plats.keys().collect();
    if want_archs != have_archs {
        vd.refuse(
            "G-10",
            "image index",
            &format!("platforms {}", repr_list(&want_archs)),
            &repr_list(&have_archs),
            "The image must carry exactly the declared platforms.",
        );
    }
    for (arch, mdig) in &plats {
        let man = py::loads_bytes(&oci_blob(&t, mdig)?)?;
        let cfg = py::loads_bytes(&oci_blob(&t, man.item("config")?.item("digest")?)?)?;
        let config = cfg.getv("config")?;
        let user = if config.truthy() {
            config.getv("User")?
        } else {
            Value::Null
        };
        if !eq_str(Some(&user), "65532:65532") {
            vd.refuse(
                "G-10",
                &format!("image linux/{arch}"),
                "User 65532:65532",
                &py_repr(&user),
                "The Dockerfile's USER is the contract.",
            );
        }
        let mut found: Option<Vec<u8>> = None;
        for layer in man.item("layers")?.iter_items()? {
            let lt = Tar::from_bytes(&oci_blob(&t, layer.item("digest")?)?)?;
            for (i, m) in lt.members.iter().enumerate() {
                if m.isfile() && m.name.trim_start_matches(['.', '/']) == "busbar" {
                    found = lt.extract(i)?;
                }
            }
        }
        let Some(found) = found else {
            vd.refuse(
                "G-10",
                &format!("image linux/{arch}"),
                "/busbar in a layer",
                "none",
                "Rebuild the image.",
            );
            continue;
        };
        let src = arch_to_internal.get(arch);
        let Some(src) = src.filter(|p| py::is_file(p)) else {
            vd.refuse(
                "G-10",
                &format!("image linux/{arch}"),
                "its declared native binary archive",
                "missing",
                "Rebuild.",
            );
            continue;
        };
        if py::sha256_hex(&found) != py::sha256_hex(&unpack_binary(src)?) {
            vd.refuse(
                "G-10",
                &format!("image linux/{arch}"),
                &format!("/busbar == {}'s binary", name(src)),
                "different bytes",
                "The image must carry the binary that was built and signed.",
            );
        }
        vd.ok("G-10", 1);
    }
    Ok(())
}

fn g11_compiled_in(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let lock = inp.root.join("dist/default/Cargo.lock");
    if !py::is_file(&lock) {
        vd.refuse(
            "G-11",
            "dist/default/Cargo.lock",
            "the distribution's lock (step 5)",
            "missing",
            "1.6.0 ships the default distribution; land step 5 first.",
        );
        return Ok(());
    }
    let mut commits: Vec<(String, Value)> = Vec::new();
    for p in plugins_of(cj)? {
        let repo = set_key(p.item("repo")?);
        let c = p.item("commit")?.clone();
        match commits.iter_mut().find(|(r, _)| *r == repo) {
            Some(slot) => slot.1 = c,
            None => commits.push((repo, c)),
        }
    }
    let text = py::read_text(&lock)?;
    let pat = re(
        r#"source = "git\+https://github\.com/GetBusbar/([A-Za-z0-9._-]+?)(?:\.git)?(?:\?[^#"]*)?#([0-9a-f]{40})""#,
    );
    let mut pins: Vec<(String, String)> = pat
        .captures_iter(&text)
        .map(|m| (m[1].to_string(), m[2].to_string()))
        .collect();
    pins.sort();
    pins.dedup();
    for (repo, sha) in pins {
        if let Some((_, c)) = commits.iter().find(|(r, _)| *r == repo) {
            if !eq_str(Some(c), &sha) {
                vd.refuse(
                    "G-11",
                    &format!("dist/default pin {repo}"),
                    &py_str(c),
                    &sha,
                    "The linked plugin must be the released plugin's commit; re-pin dist/default.",
                );
            }
        }
        vd.ok("G-11", 1);
    }
    Ok(())
}

fn g12_test_kit(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let tk = match cj.get("test_kit")? {
        Some(v) if v.truthy() => v.clone(),
        _ => Value::Dict(Dict::new()),
    };
    let tag = tk.getv("tag")?;
    let commit = tk.getv("commit")?;
    let version = py_str(cj.item("version")?);
    let want_tag = format!("test-kit-v{version}");
    if !eq_str(Some(&tag), &want_tag) || !commit.truthy() {
        vd.refuse(
            "G-12",
            "test kit",
            &format!("test-kit-v{version} with its commit"),
            &py_repr(&tk),
            "Tag the test kit on dev.",
        );
        return Ok(());
    }
    let tag = want_tag;
    let commit_s = commit
        .as_str()
        .ok_or_else(|| {
            PyErr::type_err(format!(
                "expected str, bytes or os.PathLike object, not {}",
                commit.type_name()
            ))
        })?
        .to_string();
    let got_out = run(
        &git(&inp.root, &["rev-parse", &format!("{tag}^{{commit}}")]),
        None,
        false,
    )?;
    let got = py::strip(&got_out.stdout_str()?).to_string();
    if got != commit_s {
        vd.refuse(
            "G-12",
            &tag,
            &commit_s,
            if got.is_empty() {
                "no such tag in your clone"
            } else {
                &got
            },
            "Fetch tags; the tag must name the kit's commit.",
        );
    }
    if run(
        &git(
            &inp.root,
            &["merge-base", "--is-ancestor", &commit_s, "HEAD"],
        ),
        None,
        false,
    )?
    .code
        != 0
    {
        vd.refuse(
            "G-12",
            &tag,
            "an ancestor of the release commit",
            "not an ancestor",
            "Release from a commit that contains the kit.",
        );
    }
    for p in plugins_of(cj)? {
        let repo = py_str(p.item("repo")?);
        let pc = py_str(p.item("commit")?);
        let text = inp
            .net
            .repo_file(&format!("GetBusbar/{repo}"), ".busbar-ref", &pc)?;
        let r = py::split_ws(&text)
            .first()
            .map(|x| x.to_string())
            .ok_or_else(|| PyErr::new(Kind::Index, "list index out of range"))?;
        if r != commit_s {
            vd.refuse(
                "G-12",
                &format!("{repo}@{}", head(&pc, 12)),
                &format!(".busbar-ref {commit_s}"),
                &r,
                "Re-pin the plugin to the released test kit and re-tag it.",
            );
        }
        vd.ok("G-12", 1);
    }
    Ok(())
}

fn g13_rebuild(inp: &Inputs) -> R<&'static str> {
    let rb = inp.cand.join("rebuild/artifacts");
    if !py::is_dir(&rb) {
        return Ok("not-run");
    }
    let mut entries = py::iterdir(&rb)?;
    entries.sort();
    let mut diffs = Vec::new();
    for f in entries {
        let mine = inp.cand.join("artifacts").join(name(&f));
        if !py::is_file(&mine) || py::sha256_file(&mine)? != py::sha256_file(&f)? {
            diffs.push(name(&f));
        }
    }
    for d in &diffs {
        println!(
            "REPORT G-13 {d}: the second build differs (reproducibility is report-only in 1.6.0; not claimed)"
        );
    }
    Ok(if diffs.is_empty() { "true" } else { "false" })
}

fn namespaces(line: &str) -> Option<(String, String)> {
    re(&format!(r#"(?:^|{SP}|,)namespaces="([^"]*)""#))
        .captures(line)
        .map(|m| (m[0].to_string(), m[1].to_string()))
}

fn g14_trust(inp: &Inputs, vd: &mut Verdict) -> R<()> {
    let mine = match commit_key_list(&inp.root) {
        Ok(m) => m,
        Err(e) if e.is_os() || e.is_value() => {
            vd.refuse(
                "G-14",
                ".cargo/config.toml",
                "a BUSBAR_RELEASE_PUBKEY key list",
                &e.msg,
                "Commit the K1 list.",
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let k1 = &inp.trust.k1;
    if mine != *k1 {
        vd.refuse(
            "G-14",
            "BUSBAR_RELEASE_PUBKEY",
            &format!("exactly your trust file's K1 list ({}…)", head(k1, 32)),
            &format!("{}…", head(&mine, 32)),
            "A key list you did not put in your trust file is never trusted. Read the diff; change your trust file only for a change signed by a key already in it.",
        );
    }
    let signers = inp.root.join("release/allowed_signers");
    let committed: Option<Vec<String>> = match py::read_text(&signers) {
        Ok(t) => Some(
            py::splitlines(&t)
                .into_iter()
                .filter(|l| !py::strip(l).is_empty() && !l.starts_with('#'))
                .map(|l| py::strip(l).to_string())
                .collect(),
        ),
        Err(e) if e.is_os() => None,
        Err(e) => return Err(e),
    };
    let trusted: Vec<String> = inp
        .trust
        .k2
        .iter()
        .map(|l| py::strip(l).to_string())
        .collect();
    if committed.as_ref() != Some(&trusted) {
        vd.refuse(
            "G-14",
            "release/allowed_signers",
            "exactly your trust file's K2 allowed_signers",
            "different or missing",
            "Users verify against the committed file; it must be yours.",
        );
    }
    for line in &inp.trust.k2 {
        let m = namespaces(line);
        if !m
            .as_ref()
            .is_some_and(|(_, ns)| ns == K2_NAMESPACE || ns == TAG_NAMESPACE)
        {
            vd.refuse(
                "G-14",
                "K2 allowed_signers",
                &format!(
                    "namespaces=\"{K2_NAMESPACE}\" (files) or namespaces=\"{TAG_NAMESPACE}\" (the version tag), one per line, nothing else"
                ),
                &m.map(|(all, _)| py::strip(&all).to_string())
                    .unwrap_or_else(|| s("no namespaces= restriction")),
                &format!(
                    "Restrict each line to one namespace; statements ({STATEMENT_NAMESPACE}) are checked from ModernCI's own list."
                ),
            );
        }
        let fields = py::split_ws(line);
        if inp.require_hardware_k2 && !K2_HARDWARE_TYPES.iter().any(|t| fields.contains(t)) {
            vd.refuse(
                "G-14",
                "K2",
                &format!("a hardware key type ({})", K2_HARDWARE_TYPES.join(" or ")),
                if fields.len() > 2 { fields[2] } else { line },
                "K2 lives on the YubiKey (ssh-keygen -t ed25519-sk).",
            );
        }
    }
    vd.ok("G-14", 1);
    Ok(())
}

/// (key type, key blob) of an allowed_signers line: the two fields after principal and options.
fn signer_key(line: &str) -> Vec<String> {
    let f = py::split_ws(line);
    if f.len() >= 4 {
        f[2..4].iter().map(|x| x.to_string()).collect()
    } else {
        Vec::new()
    }
}

fn lines_for(inp: &Inputs, namespace: &str) -> Vec<String> {
    inp.trust
        .k2
        .iter()
        .filter(|l| namespaces(l).is_some_and(|(_, ns)| ns == namespace))
        .cloned()
        .collect()
}

/// The version tag v<V> in the owner's clone is an annotated tag, signed by K2 under the sshsig
/// namespace `git`, verifying (git verify-tag, gpg.format=ssh) against the trust file's K2 `git`
/// lines, and naming the release commit. SECURITY.md: releases are cut under a signed version
/// tag.
fn g15_version_tag(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let version = py_str(cj.item("version")?);
    let commit = py_str(cj.item("commit")?);
    let tag = format!("v{version}");
    let git_lines = lines_for(inp, TAG_NAMESPACE);
    let k2_keys: Vec<Vec<String>> = lines_for(inp, K2_NAMESPACE)
        .iter()
        .map(|l| signer_key(l))
        .collect();
    if git_lines.is_empty() {
        vd.refuse(
            "G-15",
            "K2 allowed_signers",
            &format!("a K2 line limited to namespaces=\"{TAG_NAMESPACE}\""),
            "none",
            &format!(
                "Add the release key's line for the version tag: {K2_IDENTITY} namespaces=\"{TAG_NAMESPACE}\" <K2 key>."
            ),
        );
        return Ok(());
    }
    let strangers: Vec<&String> = git_lines
        .iter()
        .filter(|l| !k2_keys.contains(&signer_key(l)))
        .collect();
    for l in &strangers {
        vd.refuse(
            "G-15",
            "K2 allowed_signers",
            &format!("each {TAG_NAMESPACE} line to name a release key ({K2_NAMESPACE} line)"),
            &format!("{}…", head(&signer_key(l).join(" "), 48)),
            "Only K2 signs the version tag.",
        );
    }
    if !strangers.is_empty() {
        return Ok(());
    }
    let kind = run(
        &git(&inp.root, &["cat-file", "-t", &format!("refs/tags/{tag}")]),
        None,
        false,
    )?;
    if kind.code != 0 {
        vd.refuse(
            "G-15",
            &tag,
            "a signed version tag in your clone",
            "no such tag",
            &format!(
                "Sign it with K2 at the release commit: git tag -s {tag} -m 'busbar {version}' {commit}."
            ),
        );
        return Ok(());
    }
    let k = py::strip(&kind.stdout_str()?).to_string();
    if k != "tag" {
        vd.refuse(
            "G-15",
            &tag,
            "an annotated, signed tag",
            &format!("a lightweight tag ({k})"),
            &format!("Delete it and sign one with K2: git tag -s {tag}."),
        );
        return Ok(());
    }
    let at_out = run(
        &git(
            &inp.root,
            &["rev-parse", &format!("refs/tags/{tag}^{{commit}}")],
        ),
        None,
        false,
    )?;
    let at = py::strip(&at_out.stdout_str()?).to_string();
    if !eq_str(cj.get("commit")?, &at) {
        vd.refuse(
            "G-15",
            &tag,
            &format!("the release commit {commit}"),
            if at.is_empty() { "none" } else { &at },
            "The version tag names the commit the candidate was built from.",
        );
    }
    let signers = mkstemp("tmp", "")?;
    let p = py::write_text(&signers, &(git_lines.join("\n") + "\n")).and_then(|_| {
        run(
            &git(
                &inp.root,
                &[
                    "-c",
                    "gpg.format=ssh",
                    "-c",
                    &format!("gpg.ssh.allowedSignersFile={}", disp(&signers)),
                    "verify-tag",
                    "--raw",
                    &format!("refs/tags/{tag}"),
                ],
            ),
            None,
            false,
        )
    });
    let _ = std::fs::remove_file(&signers);
    let p = p?;
    let mut both = p.stdout.clone();
    both.extend_from_slice(&p.stderr);
    let said = String::from_utf8_lossy(&both).into_owned();
    if p.code != 0
        || !said.contains(&format!(
            "Good \"{TAG_NAMESPACE}\" signature for {K2_IDENTITY} "
        ))
    {
        let joined = py::split_ws(&said).join(" ");
        let shown = head(&joined, 160);
        vd.refuse(
            "G-15",
            &tag,
            &format!("signed by K2 (a Good \"{TAG_NAMESPACE}\" signature for {K2_IDENTITY})"),
            if shown.is_empty() { "no signature" } else { &shown },
            &format!(
                "Sign the tag with the release key: git -c gpg.format=ssh -c user.signingkey=<K2 sk handle> tag -s {tag}."
            ),
        );
    }
    vd.ok("G-15", 1);
    Ok(())
}

/// G-C: every public conformance suite passes for the release commit and the shipped pins, or a
/// K2-signed owner exception records it as it is (docs/design/conformance-release.md).
fn gc_conformance(inp: &Inputs, cj: &Value, vd: &mut Verdict) -> R<()> {
    let commit = py_str(cj.item("commit")?);
    let version = py_str(cj.item("version")?);
    let refusals = conformance::gate_c(
        &inp.root,
        &inp.cand,
        &commit,
        &version,
        &inp.trust.k2,
        inp.mci,
    )
    .map_err(|e| {
        if e.kind == Kind::CgCannotRun {
            cannot(e.msg)
        } else {
            e
        }
    })?;
    vd.refusals.extend(refusals); // gate_c printed each
    vd.ok("G-C", 1);
    Ok(())
}

fn scanner_failure(e: &PyErr) -> bool {
    e.is_value() || e.is_os() || e.is_subprocess() || e.is_key() || e.is_type() || e.is_attr()
}

/// Judge actual SBOM/image bytes in pinned, network-disabled scan containers.
fn gs_security(inp: &Inputs, vd: &mut Verdict) -> R<Value> {
    let mut platforms = Vec::new();
    for row in release_targets(&inp.root)? {
        if eq_str(tget(&row, "kind")?, "image") {
            let t = tstr(&row, "target")?;
            platforms.push(t.strip_prefix("image-").unwrap_or(&t).replace('-', "/"));
        }
    }
    match inp
        .security
        .scan_candidate(&inp.root, &inp.cand, &platforms)
    {
        Ok(evidence) => {
            vd.ok("G-S", 1);
            Ok(evidence)
        }
        // Scanner reports can contain secrets or source snippets. Keep them out of logs.
        Err(e) if scanner_failure(&e) || e.kind == Kind::CannotRun => Err(cannot(
            "G-S security scans failed or could not complete; no signing/publication allowed",
        )),
        Err(e) => Err(e),
    }
}

fn gs_plugin_security(
    inp: &Inputs,
    vd: &mut Verdict,
    directory: &Path,
    names: &[String],
    repository: &str,
    version: &str,
    source: &str,
) -> R<Value> {
    match inp
        .security
        .scan_plugin_candidate(&inp.root, directory, names, repository, version, source)
    {
        Ok(evidence) => {
            vd.ok("G-S", 1);
            Ok(evidence)
        }
        Err(e) if scanner_failure(&e) || e.kind == Kind::CannotRun => Err(cannot(
            "G-S plugin SBOM evidence missing, mismatched or scan failed; no signing/publication allowed",
        )),
        Err(e) => Err(e),
    }
}

pub struct Verified {
    pub vd: Verdict,
    pub cj: Value,
    pub rows: Vec<Row>,
}

const RULES: [&str; 14] = [
    "G-1", "G-2", "G-3", "G-4", "G-5", "G-6", "G-8", "G-10", "G-11", "G-12", "G-14", "G-15", "G-C",
    "G-S",
];

pub fn verify_all(inp: &Inputs) -> R<Verified> {
    let mut vd = Verdict::default();
    let loaded = (|| -> R<Value> {
        let cj = py::loads(&py::read_text(&inp.cand.join("candidate.json"))?)?;
        for k in ["version", "commit", "repo", "plugins", "test_kit"] {
            let present = match &cj {
                Value::Dict(d) => d.contains(k),
                Value::List(v) => v.iter().any(|x| eq_str(Some(x), k)),
                Value::Str(s) => s.contains(k),
                other => {
                    return Err(PyErr::type_err(format!(
                        "argument of type '{}' is not iterable",
                        other.type_name()
                    )))
                }
            };
            if !present {
                return Err(PyErr::value(format!("candidate.json has no `{k}`")));
            }
        }
        Ok(cj)
    })();
    let cj = match loaded {
        Ok(cj) => cj,
        Err(e) if e.is_os() || e.is_value() => {
            vd.refuse(
                "G-0",
                "candidate.json",
                "the candidate manifest",
                &e.msg,
                "Fetch the candidate's outputs.",
            );
            return Ok(Verified {
                vd,
                cj: Value::Dict(Dict::new()),
                rows: Vec::new(),
            });
        }
        Err(e) => return Err(e),
    };
    g14_trust(inp, &mut vd)?;
    g1_version(inp, &cj, &mut vd)?;
    g15_version_tag(inp, &cj, &mut vd)?;
    g3_g4_sets_and_sums(inp, &cj, &mut vd)?;
    let rows = g5_plugins_unsigned(inp, &cj, &mut vd)?;
    g6_embedded_keys(inp, &mut vd)?;
    g8_sboms(inp, &cj, &mut vd)?;
    g10_image(inp, &mut vd)?;
    g11_compiled_in(inp, &cj, &mut vd)?;
    g2_not_published(inp, &cj, &mut vd)?;
    g12_test_kit(inp, &cj, &mut vd)?;
    gc_conformance(inp, &cj, &mut vd)?;
    let security = if vd.refusals.is_empty() {
        gs_security(inp, &mut vd)?
    } else {
        Value::Null
    };
    let repro = g13_rebuild(inp)?;
    if py::exists(&inp.cand.join("provenance")) {
        vd.refuse(
            "G-9",
            "provenance/",
            "no provenance (G-9 is not in 1.6.0's rule set)",
            "present",
            "Land G-9 with ModernCI's pinned builder key before shipping provenance; an unchecked file is never published.",
        );
    }
    // G-0: every class ran on something.
    for rule in RULES {
        if vd.checked.get(rule).copied().unwrap_or(0) == 0 {
            vd.refuse(
                "G-0",
                rule,
                "at least one subject checked",
                "none",
                "A rule that checked nothing is not a pass.",
            );
        }
    }
    let rules: Vec<(String, Value)> = vd
        .checked
        .keys()
        .map(|r| {
            let state = if vd.refused_rule(r) {
                "refused"
            } else {
                "pass"
            };
            (r.clone(), Value::from(state))
        })
        .collect();
    let k1_keys: Vec<Value> = inp
        .trust
        .k1
        .split(',')
        .map(|e| Value::from(e.split(':').next().unwrap_or("")))
        .collect();
    let reproducible = match repro {
        "true" => Value::from("second-build-matched"),
        "false" => Value::Bool(false),
        _ => Value::from("not-run"),
    };
    let mut ev = dict([
        ("version", cj.item("version")?.clone()),
        ("commit", cj.item("commit")?.clone()),
        ("repo", Value::from(REPO)),
        ("rules", Value::Dict(Dict(rules))),
        (
            "not_run",
            Value::Dict(dict([(
                "G-9",
                Value::from("no provenance producer for 1.6.0 (ModernCI phase 2b)"),
            )])),
        ),
        (
            "plugins_signed_by_hardware_key",
            Value::from("pending-sign"),
        ),
        (
            "release_signed_by_hardware_key",
            Value::from("pending-sign"),
        ),
        ("sbom", Value::Bool(!vd.refused_rule("G-8"))),
        ("slsa_provenance", Value::from("not-run")),
        ("security_scans", security),
        ("transparency_log", Value::from("pending-upload")),
        ("reproducible", reproducible),
        ("local_spot_rebuild", Value::from("not-run")),
        ("k1_keys", Value::List(k1_keys)),
    ]);
    if py::is_file(&inp.cand.join("conformance-manifest.json")) {
        // The K2 hook: release-evidence.json (K2-signed) pins the manifest the release publishes.
        let version = py_str(cj.item("version")?);
        for (k, v) in conformance::evidence(&inp.root, &inp.cand, &version)?.0 {
            ev.insert(k, v);
        }
    }
    vd.evidence = ev;
    Ok(Verified { vd, cj, rows })
}

// ── commands ────────────────────────────────────────────────────────────────────────────────────

pub fn finish(vd: &Verdict) -> i32 {
    let n = vd.refusals.len();
    println!();
    println!(
        "publish-gate: {} checks over {} rules; {n} refusal(s).",
        vd.checked.values().sum::<usize>(),
        vd.checked.len()
    );
    if n > 0 {
        println!("publish-gate: REFUSED. Nothing may be signed or published.");
        return EXIT_REFUSED;
    }
    println!("publish-gate: VERIFIED.");
    EXIT_OK
}

fn evidence_text(ev: &Dict) -> String {
    dumps(&Value::Dict(ev.clone()), Dump::SORTED) + "\n"
}

pub fn cmd_verify(inp: &Inputs, out: &Path) -> R<i32> {
    let v = verify_all(inp)?;
    if v.vd.refusals.is_empty() {
        py::mkdir_p(out)?;
        py::write_text(
            &out.join("release-evidence.json"),
            &evidence_text(&v.vd.evidence),
        )?;
        let mut tsv = String::new();
        for r in &v.rows {
            tsv.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                py_str(&r.repo),
                r.target,
                r.file,
                r.canonical.as_deref().unwrap_or("None")
            ));
        }
        py::write_text(&out.join("plugins.tsv"), &tsv)?;
    }
    Ok(finish(&v.vd))
}

fn sig_of(f: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", disp(f)))
}

fn k2_sign_and_check(inp: &Inputs, key: &str, files: &[PathBuf]) -> R<()> {
    let signers = mkstemp("tmp", "")?;
    py::write_text(&signers, &(inp.trust.k2.join("\n") + "\n"))?;
    for f in files {
        let sig = sig_of(f);
        let _ = std::fs::remove_file(&sig);
        println!("K2: touch the YubiKey to sign {}", name(f));
        run(
            &[
                tool("ssh-keygen")?,
                s("-Y"),
                s("sign"),
                s("-f"),
                s(key),
                s("-n"),
                s(K2_NAMESPACE),
                disp(f),
            ],
            None,
            true,
        )?;
        let data = py::read_bytes(f)?;
        let p = run(
            &[
                tool("ssh-keygen")?,
                s("-Y"),
                s("verify"),
                s("-f"),
                disp(&signers),
                s("-I"),
                s(K2_IDENTITY),
                s("-n"),
                s(K2_NAMESPACE),
                s("-s"),
                disp(&sig),
            ],
            Some(&data),
            false,
        )?;
        if p.code != 0 {
            return Err(cannot(format!(
                "G-7 {}: the K2 signature does not verify against your trusted allowed_signers: {}",
                name(f),
                py::strip(&p.stderr_lossy())
            )));
        }
    }
    let _ = std::fs::remove_file(&signers);
    Ok(())
}

/// ONE SIGNATURE PER RELEASE. `tarballs` is [(unsigned tarball, target, name, version)].
/// `busbar-plugin-pack release-manifest` writes the bytes of the one release manifest listing
/// them all; `sign_cmd` is called ONCE as `CMD <manifest-file> <sig-out>`; `envelope` wraps the
/// signature (refusing one that does not verify with the trust file's release signer); then each
/// tarball is sealed with the keys document and the release manifest into out/signed/ and
/// verified for its target. Writes out/release-manifest.json. The gate spells no byte of either
/// document: busbar-plugin-pack (release_trust::wire) does.
fn seal_release(
    inp: &Inputs,
    vd: &mut Verdict,
    tarballs: &[(PathBuf, String, String, String)],
    out: &Path,
    sign_cmd: &str,
) -> R<()> {
    let keys_doc = PathBuf::from(&inp.trust.keys_doc);
    let expires = (|| -> R<String> {
        let doc = py::loads(&py::read_text(&keys_doc)?)?;
        let e = doc.item("signed")?.item("expires")?;
        Ok(py_str(e))
    })();
    let expires = match expires {
        Ok(e) => e,
        Err(e) if e.is_os() || e.is_key() || e.is_value() || e.is_type() => {
            vd.refuse(
                "G-5",
                &disp(&keys_doc),
                "the trust file's keys document",
                &e.msg,
                "Point keys_doc at the root-signed keys document.",
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let work = mkdtemp("tmp")?;
    let signed_bytes = work.join("release-manifest.signed");
    let sig = work.join("release-manifest.sig");
    let manifest = out.join("release-manifest.json");
    // The release manifest's version only rises: the signing time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut args = vec![
        s("release-manifest"),
        s("--version"),
        now.to_string(),
        s("--expires"),
        expires,
        s("--out"),
        disp(&signed_bytes),
    ];
    args.extend(
        tarballs
            .iter()
            .map(|(f, t, _, _)| format!("{}={t}", disp(f))),
    );
    let (code, outp) = pack_out(inp, &args)?;
    if code != 0 {
        vd.refuse(
            "G-5",
            "release manifest",
            "every plugin tarball listed",
            &outp,
            "Rebuild the plugins slice.",
        );
        return Ok(());
    }
    println!("release manifest: {} tarballs, {outp}", tarballs.len());
    println!("release signer: sign the release manifest (once)");
    let p = run(
        &[
            s("/bin/sh"),
            s("-c"),
            format!("{sign_cmd} \"$0\" \"$1\""),
            disp(&signed_bytes),
            disp(&sig),
        ],
        None,
        false,
    )?;
    if p.code != 0 || !py::is_file(&sig) {
        return Err(cannot(format!(
            "signing the release manifest failed: {}",
            py::strip(&p.stderr_lossy())
        )));
    }
    let (code, outp) = pack_out(
        inp,
        &[
            s("envelope"),
            s("--signed"),
            disp(&signed_bytes),
            s("--key"),
            inp.trust.release_signer.clone(),
            s("--signature"),
            disp(&sig),
            s("--out"),
            disp(&manifest),
        ],
    )?;
    if code != 0 {
        vd.refuse(
            "G-5",
            "release manifest",
            "a signature by your release signer",
            &outp,
            "Check the signer command and key.",
        );
        return Ok(());
    }
    let signed = out.join("signed");
    py::mkdir_p(&signed)?;
    for (f, target, nm, version) in tarballs {
        let dest = signed.join(name(f));
        let (code, outp) = pack_out(
            inp,
            &[
                s("seal"),
                disp(f),
                s("--keys-doc"),
                disp(&keys_doc),
                s("--release"),
                disp(&manifest),
                s("--target"),
                target.clone(),
                s("--keys"),
                inp.trust.k1.clone(),
                s("--out"),
                disp(&dest),
            ],
        )?;
        if code != 0 {
            vd.refuse(
                "G-5",
                &name(f),
                "sealed through the chain to your root list",
                &outp,
                "Do not publish this plugin.",
            );
            continue;
        }
        let (code, outp) = pack_out(
            inp,
            &[
                s("verify"),
                disp(&dest),
                s("--keys"),
                inp.trust.k1.clone(),
                s("--target"),
                target.clone(),
                s("--name"),
                nm.clone(),
                s("--version"),
                version.clone(),
            ],
        )?;
        if code != 0 {
            vd.refuse(
                "G-5",
                &name(f),
                "VERIFIED",
                &outp,
                "Do not publish this plugin.",
            );
        }
        vd.ok("G-5", 1);
    }
    let _ = std::fs::remove_dir_all(&work);
    Ok(())
}

fn sorted_dir(d: &Path) -> R<Vec<PathBuf>> {
    let mut v = py::iterdir(d)?;
    v.sort();
    Ok(v)
}

fn copy(from: &Path, to: &Path) -> R<()> {
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| py::os_err(&e, Some(from)))
}

pub fn cmd_sign(inp: &Inputs, out: &Path, k1_cmd: &str, k2_key: &str) -> R<i32> {
    let Verified { mut vd, cj, rows } = verify_all(inp)?;
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    let old = run(
        &git(&inp.root, &["show", "v1.5.5:.cargo/config.toml"]),
        None,
        false,
    )?;
    let old = old.stdout_str()?;
    let m = re(&format!(r#"BUSBAR_RELEASE_PUBKEY{SP}*={SP}*"([^"]*)""#))
        .captures(&old)
        .map(|m| m[1].to_string());
    let commit = py_str(cj.item("commit")?);
    println!("\n================ WHAT YOU ARE ABOUT TO SIGN ================");
    println!("version   {}", py_str(cj.item("version")?));
    println!("commit    {commit}   <- compare with `git rev-parse HEAD` in YOUR clone");
    println!("K1 list   {}", inp.trust.k1);
    println!("  v1.5.5  {}", m.as_deref().unwrap_or("(none)"));
    println!(
        "artifacts {} files; SHA256SUMS {}",
        read_sums(&inp.cand.join("SHA256SUMS"))?.len(),
        py::sha256_file(&inp.cand.join("SHA256SUMS"))?
    );
    println!(
        "images    {}",
        py_repr(&Value::Dict(read_images(&inp.cand.join("IMAGES"))?))
    );
    println!(
        "plugins   {} tarballs in ONE release manifest, signed once by {}…",
        rows.len(),
        head(&inp.trust.release_signer, 24)
    );
    println!("=============================================================");
    let answer = (inp.input)("Type the first 12 characters of the commit to sign: ")
        .ok_or_else(|| PyErr::new(Kind::Runtime, "EOF when reading a line"))?;
    if py::strip(&answer) != head(&commit, 12) {
        println!("publish-gate: not confirmed; nothing signed.");
        return Ok(EXIT_REFUSED);
    }
    let signed = out.join("signed");
    py::mkdir_p(&signed)?;
    let mut versions: Vec<(String, String)> = Vec::new();
    for p in plugins_of(&cj)? {
        versions.push((set_key(p.item("repo")?), py_str(p.item("version")?)));
    }
    for r in &rows {
        let (code, outp) = pack_out(
            inp,
            &[
                s("canonical"),
                disp(&inp.cand.join("plugins").join(&r.file)),
            ],
        )?;
        if code != 0 || kget(&kv(&outp), "canonical-sha256") != r.canonical.as_deref() {
            vd.refuse(
                "G-5",
                &r.file,
                r.canonical.as_deref().unwrap_or("None"),
                &outp,
                "The tarball changed after verify; start again.",
            );
        }
    }
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    let mut tarballs = Vec::new();
    for r in &rows {
        let key = set_key(&r.repo);
        let version = versions
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| PyErr::key(&py_str(&r.repo)))?;
        tarballs.push((
            inp.cand.join("plugins").join(&r.file),
            r.target.clone(),
            py_str(&r.repo),
            version,
        ));
    }
    seal_release(inp, &mut vd, &tarballs, out, k1_cmd)?;
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    write_sums(&out.join("SHA256SUMS.plugins"), &sorted_dir(&signed)?)?;
    copy(&inp.cand.join("SHA256SUMS"), &out.join("SHA256SUMS"))?;
    copy(&inp.cand.join("IMAGES"), &out.join("IMAGES"))?;
    let mut ev = vd.evidence.clone();
    ev.insert("plugins_signed_by_hardware_key", Value::Bool(true));
    ev.insert("release_signed_by_hardware_key", Value::Bool(true));
    ev.insert(
        "plugin_release_manifest",
        Value::Str(py::sha256_file(&out.join("release-manifest.json"))?),
    );
    ev.insert(
        "plugin_keys_document",
        Value::Str(py::sha256_file(Path::new(&inp.trust.keys_doc))?),
    );
    ev.insert(
        "sha256sums",
        Value::Str(py::sha256_file(&out.join("SHA256SUMS"))?),
    );
    ev.insert(
        "sha256sums_plugins",
        Value::Str(py::sha256_file(&out.join("SHA256SUMS.plugins"))?),
    );
    ev.insert("images", Value::Dict(read_images(&out.join("IMAGES"))?));
    py::write_text(&out.join("release-evidence.json"), &evidence_text(&ev))?;
    k2_sign_and_check(
        inp,
        k2_key,
        &[
            out.join("SHA256SUMS"),
            out.join("SHA256SUMS.plugins"),
            out.join("IMAGES"),
            out.join("release-evidence.json"),
        ],
    )?;
    vd.ok("G-7", 4);
    Ok(finish(&vd))
}

fn verify_k2(signers: &Path, file: &Path, sig: &Path) -> R<i32> {
    let data = py::read_bytes(file)?;
    Ok(run(
        &[
            tool("ssh-keygen")?,
            s("-Y"),
            s("verify"),
            s("-f"),
            disp(signers),
            s("-I"),
            s(K2_IDENTITY),
            s("-n"),
            s(K2_NAMESPACE),
            s("-s"),
            disp(sig),
        ],
        Some(&data),
        false,
    )?
    .code)
}

fn strs(v: &[PathBuf]) -> Vec<String> {
    v.iter().map(|p| disp(p)).collect()
}

/// Publish in the order that never exposes an unverified byte under a public name.
pub fn cmd_upload(inp: &Inputs, out: &Path) -> R<i32> {
    let Verified { mut vd, cj, .. } = verify_all(inp)?;
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    let v = py_str(cj.item("version")?);
    let tag = format!("v{v}");
    let signers = mkstemp("tmp", "")?;
    py::write_text(&signers, &(inp.trust.k2.join("\n") + "\n"))?;
    let signed_files: Vec<PathBuf> = [
        "SHA256SUMS",
        "SHA256SUMS.plugins",
        "IMAGES",
        "release-evidence.json",
    ]
    .iter()
    .map(|n| out.join(n))
    .collect();
    for f in &signed_files {
        // G-7 again: nothing unsigned leaves this machine.
        if verify_k2(&signers, f, &sig_of(f))? != 0 {
            vd.refuse(
                "G-7",
                &name(f),
                "a K2 signature verifying against your allowed_signers",
                "none",
                "Run `sign` first.",
            );
        }
    }
    let manifest = inp.cand.join("conformance-manifest.json");
    let signed_ev = py::loads(&py::read_text(&out.join("release-evidence.json"))?)?;
    let pinned_manifest = signed_ev.getv("conformance_manifest_sha256")?;
    let manifest_sha = py::sha256_file(&manifest)?;
    if !eq_str(Some(&pinned_manifest), &manifest_sha) {
        vd.refuse(
            "G-C",
            "conformance-manifest.json",
            &format!(
                "sha256 {} (release-evidence.json)",
                py_str(&pinned_manifest)
            ),
            &manifest_sha,
            "Run `sign` again over this candidate.",
        );
    }
    if py::read_bytes(&out.join("SHA256SUMS"))? != py::read_bytes(&inp.cand.join("SHA256SUMS"))? {
        vd.refuse(
            "G-4",
            "SHA256SUMS",
            "the signed file equals the candidate's",
            "different",
            "Run `sign` again.",
        );
    }
    for (n, digest) in read_sums(&out.join("SHA256SUMS.plugins"))? {
        if py::sha256_file(&out.join("signed").join(&n))? != digest {
            vd.refuse(
                "G-4",
                &format!("signed/{n}"),
                &digest,
                "different bytes",
                "Run `sign` again.",
            );
        }
    }
    // G-15 on GitHub: the release is created on the signed tag, never on one gh would make.
    let local_tag = py::strip(
        &run(
            &git(&inp.root, &["rev-parse", &format!("refs/tags/{tag}")]),
            None,
            false,
        )?
        .stdout_str()?,
    )
    .to_string();
    let remote = inp.net.remote_tag(REPO, &tag)?;
    if remote.as_deref() != Some(local_tag.as_str()) {
        vd.refuse(
            "G-15",
            &format!("{REPO} {tag}"),
            &format!("the signed tag object {local_tag}"),
            remote.as_deref().unwrap_or("None"),
            &format!(
                "Push your signed tag to GitHub ({REPO}) first: git push <github remote> {tag}."
            ),
        );
    }
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    let verified_images = Value::Dict(read_images(&inp.cand.join("IMAGES"))?);
    let out_images = Value::Dict(read_images(&out.join("IMAGES"))?);
    if !py_eq(&out_images, &verified_images) || !py_eq(&signed_ev.getv("images")?, &verified_images)
    {
        vd.refuse(
            "G-10",
            "IMAGES",
            "the signed images match this verified candidate",
            "a different image set",
            "Sign this candidate before uploading.",
        );
        return Ok(finish(&vd));
    }
    let digest = py_str(out_images.item("busbar")?);
    let cos = match inp.trust.raw.get("cosign") {
        Some(c) if c.truthy() => c.clone(),
        _ => Value::Dict(Dict::new()),
    };
    let identity = cos.getv("identity")?;
    let issuer = cos.getv("issuer")?;
    if !identity.truthy() || !issuer.truthy() {
        return Err(cannot(
            "trust file has no cosign identity/issuer (D1); images cannot be signed or verified",
        ));
    }
    let oci = inp.cand.join("oci/busbar.oci.tar");
    // 1. images by digest, untagged; 2. cosign sign; 3. cosign verify on the registry copy.
    for repo in IMAGE_REPOS {
        run(
            &[
                tool("skopeo")?,
                s("copy"),
                s("--all"),
                s("--preserve-digests"),
                format!("oci-archive:{}", disp(&oci)),
                format!("docker://{repo}@{digest}"),
            ],
            None,
            true,
        )?;
        run(
            &[
                tool("cosign")?,
                s("sign"),
                s("--yes"),
                format!("{repo}@{digest}"),
            ],
            None,
            true,
        )?;
        run(
            &[
                tool("cosign")?,
                s("verify"),
                s("--certificate-identity"),
                py_str(&identity),
                s("--certificate-oidc-issuer"),
                py_str(&issuer),
                format!("{repo}@{digest}"),
            ],
            None,
            true,
        )?;
    }
    // 4. the GitHub Release as a draft, with every byte and signature.
    let core = read_sums(&out.join("SHA256SUMS"))?;
    let mut assets: Vec<PathBuf> = Vec::new();
    for (n, _) in &core {
        let p = inp.cand.join("artifacts").join(n);
        if py::is_file(&p) {
            assets.push(p);
        }
    }
    for (n, _) in &core {
        let p = inp.cand.join("sboms").join(n);
        if py::is_file(&p) {
            assets.push(p);
        }
    }
    assets.extend(signed_files.iter().cloned());
    assets.extend(signed_files.iter().map(|f| sig_of(f)));
    assets.push(manifest.clone());
    run(
        &[
            tool("gh")?,
            s("release"),
            s("create"),
            tag.clone(),
            s("-R"),
            s(REPO),
            s("--draft"),
            s("--verify-tag"),
            s("--title"),
            format!("busbar {v}"),
            s("--notes-file"),
            s("-"),
        ],
        Some(b"See CHANGELOG.md and docs/verify.md."),
        true,
    )?;
    let mut up = vec![
        tool("gh")?,
        s("release"),
        s("upload"),
        tag.clone(),
        s("-R"),
        s(REPO),
    ];
    up.extend(strs(&assets));
    run(&up, None, true)?;
    // 5. Rekor: every K2 signature in the public log.
    let k2pub = mkstemp("tmp", ".pub")?;
    let first = lines_for(inp, K2_NAMESPACE)
        .first()
        .cloned()
        .ok_or_else(|| PyErr::new(Kind::Index, "list index out of range"))?;
    py::write_text(&k2pub, &(signer_key(&first).join(" ") + "\n"))?;
    let mut rekor: Vec<(String, String)> = Vec::new();
    for f in &signed_files {
        let p = run(
            &[
                tool("rekor-cli")?,
                s("upload"),
                s("--artifact"),
                disp(f),
                s("--signature"),
                disp(&sig_of(f)),
                s("--pki-format"),
                s("ssh"),
                s("--public-key"),
                disp(&k2pub),
            ],
            None,
            true,
        )?;
        rekor.push((name(f), py::strip(&p.stdout_str()?).to_string()));
    }
    // 6. publish; 7. tag the images.
    run(
        &[
            tool("gh")?,
            s("release"),
            s("edit"),
            tag.clone(),
            s("-R"),
            s(REPO),
            s("--draft=false"),
            s("--latest"),
        ],
        None,
        true,
    )?;
    for repo in IMAGE_REPOS {
        run(
            &[
                tool("skopeo")?,
                s("copy"),
                s("--all"),
                s("--preserve-digests"),
                format!("docker://{repo}@{digest}"),
                format!("docker://{repo}:{v}"),
            ],
            None,
            true,
        )?;
    }
    // The plugins, each to its own repo's release at its tag (plugins.fetch resolves there).
    for p in plugins_of(&cj)? {
        let repo = py_str(p.item("repo")?);
        let ptag = py_str(p.item("tag")?);
        let pversion = py_str(p.item("version")?);
        let prepo = format!("GetBusbar/{repo}");
        let files: Vec<PathBuf> = PLUGIN_TARGETS
            .iter()
            .map(|(t, _, _)| {
                out.join("signed")
                    .join(format!("{repo}-{pversion}-{t}.tar.gz"))
            })
            .collect();
        if !inp.net.release_exists(&prepo, &ptag)? {
            run(
                &[
                    tool("gh")?,
                    s("release"),
                    s("create"),
                    ptag.clone(),
                    s("-R"),
                    prepo.clone(),
                    s("--draft"),
                    s("--target"),
                    py_str(p.item("commit")?),
                    s("--title"),
                    format!("{repo} {ptag}"),
                    s("--notes-file"),
                    s("-"),
                ],
                Some(b"Signed with the busbar plugin key."),
                true,
            )?;
        }
        let mut up = vec![
            tool("gh")?,
            s("release"),
            s("upload"),
            ptag.clone(),
            s("-R"),
            prepo.clone(),
            s("--clobber"),
        ];
        up.extend(strs(&files));
        up.push(disp(&out.join("SHA256SUMS.plugins")));
        up.push(disp(&out.join("SHA256SUMS.plugins.sig")));
        run(&up, None, true)?;
        run(
            &[
                tool("gh")?,
                s("release"),
                s("edit"),
                ptag,
                s("-R"),
                prepo,
                s("--draft=false"),
                s("--latest"),
            ],
            None,
            true,
        )?;
    }
    // 8. verify as a user would; 9. only then the floating tags.
    let dl = mkdtemp("tmp")?;
    run(
        &[
            tool("gh")?,
            s("release"),
            s("download"),
            tag.clone(),
            s("-R"),
            s(REPO),
            s("-D"),
            disp(&dl),
        ],
        None,
        true,
    )?;
    for n in [
        "SHA256SUMS",
        "SHA256SUMS.plugins",
        "IMAGES",
        "release-evidence.json",
    ] {
        let downloaded = dl.join(n);
        let signature = dl.join(format!("{n}.sig"));
        if !py::is_file(&downloaded) || !py::is_file(&signature) {
            vd.refuse(
                "G-4",
                &format!("published {n}"),
                "the signed download",
                "missing",
                "Restore the complete release before publishing aliases.",
            );
            continue;
        }
        if verify_k2(&signers, &downloaded, &signature)? != 0 {
            vd.refuse(
                "G-7",
                &format!("published {n}"),
                "verifies",
                "does not",
                "Pull the release back to draft at once.",
            );
        }
        if py::read_bytes(&downloaded)? != py::read_bytes(&out.join(n))? {
            vd.refuse(
                "G-4",
                &format!("published {n}"),
                "the exact signed metadata for this candidate",
                "different bytes",
                "Restore this candidate's signed metadata.",
            );
        }
    }
    let downloaded_manifest = dl.join(name(&manifest));
    let pinned = py_str(signed_ev.item("conformance_manifest_sha256")?);
    let have = if py::is_file(&downloaded_manifest) {
        Some(py::sha256_file(&downloaded_manifest)?)
    } else {
        None
    };
    if have.as_deref() != Some(pinned.as_str())
        || !matches!(
            signed_ev.item("conformance_manifest_sha256")?,
            Value::Str(_)
        )
    {
        vd.refuse(
            "G-C",
            &format!("published {}", name(&manifest)),
            &pinned,
            have.as_deref().unwrap_or("missing"),
            "Pull the release back to draft at once.",
        );
    }
    for (n, want) in read_sums(&out.join("SHA256SUMS"))? {
        let artifact = dl.join(&n);
        let got = if py::is_file(&artifact) {
            Some(py::sha256_file(&artifact)?)
        } else {
            None
        };
        if got.as_deref() != Some(want.as_str()) {
            vd.refuse(
                "G-4",
                &format!("published {n}"),
                &want,
                got.as_deref().unwrap_or("missing"),
                "Restore the complete verified artifact set.",
            );
        }
    }
    for repo in IMAGE_REPOS {
        let got = inp.net.registry_digest(&format!("{repo}:{v}"))?;
        if got.as_deref() != Some(digest.as_str()) {
            vd.refuse(
                "G-7",
                &format!("{repo}:{v}"),
                &digest,
                got.as_deref().unwrap_or("None"),
                "The tag does not hold the signed image; fix before moving latest.",
            );
        }
    }
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() < 2 {
        return Err(unpack_err(2, parts.len()));
    }
    let (major, minor) = (parts[0], parts[1]);
    for repo in IMAGE_REPOS {
        for t in [format!("{major}.{minor}"), major.to_string(), s("latest")] {
            run(
                &[
                    tool("skopeo")?,
                    s("copy"),
                    s("--all"),
                    s("--preserve-digests"),
                    format!("docker://{repo}@{digest}"),
                    format!("docker://{repo}:{t}"),
                ],
                None,
                true,
            )?;
        }
    }
    // The rows rekor_watch.py compares the public log with: commit them to release/released.tsv.
    let mut rows = String::new();
    for f in &signed_files {
        rows.push_str(&format!("{v}\t{}\t{}\n", name(f), py::sha256_file(f)?));
    }
    py::write_text(&out.join("released.tsv"), &rows)?;
    println!(
        "Commit {}'s rows to release/released.tsv (the Rekor watch reads it).",
        disp(&out.join("released.tsv"))
    );
    println!(
        "Commit {} as conformance/manifest.json on the release branch (the tree and the asset agree).",
        disp(&manifest)
    );
    println!("Rekor entries:");
    for (k, line) in &rekor {
        println!("  {k}: {line}");
    }
    println!("Next: open the homebrew and helm bump PRs with digests from the signed SHA256SUMS and IMAGES.");
    vd.ok("G-7", 1);
    Ok(finish(&vd))
}

/// One plugin between core releases. Its unsigned tarballs come from the candidate-plugins
/// checks. One release manifest lists them, the release signer signs it once, each tarball is
/// sealed and verified, K2 signs, and the release is published.
pub fn cmd_plugin_release(
    inp: &Inputs,
    out: &Path,
    repo: &str,
    tag: &str,
    plugins: &Path,
    k1_cmd: &str,
    k2_key: &str,
) -> R<i32> {
    let mut vd = Verdict::default();
    g14_trust(inp, &mut vd)?;
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    if !full(r"v\d+\.\d+\.\d+", tag) {
        vd.refuse(
            "G-1",
            tag,
            "vX.Y.Z",
            tag,
            "Plugin releases are versioned tags.",
        );
        return Ok(finish(&vd));
    }
    if !registry_plugins(&inp.root)?.iter().any(|r| r == repo) {
        vd.refuse(
            "G-3",
            repo,
            "a registered first-party plugin",
            "not in plugins.yaml",
            "Register it in a judged change.",
        );
        return Ok(finish(&vd));
    }
    let ver = py::tail_from(tag, 1);
    let mut pinned: Option<Vec<String>> = None;
    for line in py::splitlines(&py::read_text(&inp.root.join("release/plugin-pins.tsv"))?) {
        let fields: Vec<String> = line.split('\t').map(str::to_string).collect();
        if !py::strip(line).is_empty() && !line.starts_with('#') && fields[0] == repo {
            pinned = Some(fields);
        }
    }
    let pinned_ok = match &pinned {
        Some(p) => {
            if p.len() < 2 {
                return Err(PyErr::new(Kind::Index, "list index out of range"));
            }
            p[1] == tag
        }
        None => false,
    };
    if !pinned_ok {
        vd.refuse(
            "G-3",
            &format!("{repo} {tag}"),
            "pinned in release/plugin-pins.tsv at this commit",
            &pinned.as_ref().map(|p| repr_list(p)).unwrap_or_else(|| s("None")),
            "Pin the plugin release in a judged change; the candidate-plugins checks build exactly the pins.",
        );
        return Ok(finish(&vd));
    }
    let pinned = pinned.unwrap();
    let commit = pinned
        .get(2)
        .cloned()
        .ok_or_else(|| PyErr::new(Kind::Index, "list index out of range"))?;
    if inp
        .net
        .release_published(&format!("GetBusbar/{repo}"), tag)?
    {
        vd.refuse(
            "G-2",
            &format!("{repo} {tag}"),
            "not yet published",
            "published",
            "A plugin version is published once; tag a new one.",
        );
        return Ok(finish(&vd));
    }
    let dl = plugins;
    let mut want: Vec<String> = PLUGIN_TARGETS
        .iter()
        .map(|(t, _, _)| format!("{repo}-{ver}-{t}.tar.gz"))
        .collect();
    want.sort();
    let mut have: Vec<String> = py::iterdir(dl)?
        .iter()
        .map(|f| name(f))
        .filter(|n| n.ends_with(".tar.gz") && n.starts_with(&format!("{repo}-")))
        .collect();
    have.sort();
    for n in want.iter().filter(|n| !have.contains(n)) {
        vd.refuse(
            "G-3",
            n,
            "present in --plugins",
            "missing",
            "Every plugin target is owed; fetch every candidate-plugins slice.",
        );
    }
    for n in have.iter().filter(|n| !want.contains(n)) {
        vd.refuse("G-3", n, "absent", "present", "Only declared targets ship.");
    }
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    for n in &want {
        let (code, outp) = pack_out(inp, &[s("canonical"), disp(&dl.join(n))])?;
        let m = kv(&outp);
        if code != 0
            || kget(&m, "name") != Some(repo)
            || kget(&m, "version") != Some(ver.as_str())
            || kget(&m, "publisher") != Some("busbar")
            || kget(&m, "signed") != Some("false")
        {
            vd.refuse(
                "G-5",
                n,
                &format!("unsigned busbar plugin {repo} {ver}"),
                &outp,
                "Re-run the plugin's release workflow.",
            );
        }
    }
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    let mut security = gs_plugin_security(
        inp,
        &mut vd,
        dl,
        &want,
        &format!("GetBusbar/{repo}"),
        &ver,
        &commit,
    )?;
    py::mkdir_p(out)?;
    let tarballs: Vec<(PathBuf, String, String, String)> = PLUGIN_TARGETS
        .iter()
        .map(|(t, _, _)| {
            (
                dl.join(format!("{repo}-{ver}-{t}.tar.gz")),
                t.to_string(),
                repo.to_string(),
                ver.clone(),
            )
        })
        .collect();
    seal_release(inp, &mut vd, &tarballs, out, k1_cmd)?;
    if !vd.refusals.is_empty() {
        return Ok(finish(&vd));
    }
    let signed = out.join("signed");
    let sums = out.join("SHA256SUMS");
    let mut signed_artifacts = Dict::new();
    for p in sorted_dir(&signed)? {
        signed_artifacts.insert(name(&p), Value::Str(py::sha256_file(&p)?));
    }
    let Value::Dict(sec) = &mut security else {
        return Err(PyErr::type_err(
            "'NoneType' object does not support item assignment",
        ));
    };
    sec.insert("signed_artifacts", Value::Dict(signed_artifacts));
    let mut sboms: Vec<PathBuf> = Vec::new();
    for row in sec
        .get("subjects")
        .ok_or_else(|| PyErr::key("subjects"))?
        .iter_values()?
    {
        let sbom = py_str(row.item("sbom")?);
        let (source_bom, destination) = (dl.join(&sbom), out.join(&sbom));
        copy(&source_bom, &destination)?;
        if !eq_str(
            Some(row.item("sbom_sha256")?),
            &py::sha256_file(&destination)?,
        ) {
            return Err(cannot("G-S plugin SBOM changed after scanning"));
        }
        sboms.push(destination);
    }
    let security_file = out.join("plugin-security.json");
    py::write_text(&security_file, &(dumps(&security, Dump::SORTED) + "\n"))?;
    let signed_files = sorted_dir(&signed)?;
    let mut summed = signed_files.clone();
    summed.extend(sboms.iter().cloned());
    summed.push(security_file.clone());
    write_sums(&sums, &summed)?;
    k2_sign_and_check(inp, k2_key, &[sums.clone(), security_file.clone()])?;
    let mut published = sorted_dir(&signed)?;
    published.extend(sboms.iter().cloned());
    published.push(sums.clone());
    published.push(sig_of(&sums));
    published.push(security_file.clone());
    published.push(sig_of(&security_file));
    let prepo = format!("GetBusbar/{repo}");
    if !inp.net.release_exists(&prepo, tag)? {
        run(
            &[
                tool("gh")?,
                s("release"),
                s("create"),
                s(tag),
                s("-R"),
                prepo.clone(),
                s("--draft"),
                s("--target"),
                commit.clone(),
                s("--title"),
                format!("{repo} {tag}"),
                s("--notes-file"),
                s("-"),
            ],
            Some(b"Signed with the busbar plugin key."),
            true,
        )?;
    }
    let mut up = vec![
        tool("gh")?,
        s("release"),
        s("upload"),
        s(tag),
        s("-R"),
        prepo.clone(),
        s("--clobber"),
    ];
    up.extend(strs(&published));
    run(&up, None, true)?;
    run(
        &[
            tool("gh")?,
            s("release"),
            s("edit"),
            s(tag),
            s("-R"),
            prepo.clone(),
            s("--draft=false"),
            s("--latest"),
        ],
        None,
        true,
    )?;
    let back = mkdtemp("tmp")?;
    run(
        &[
            tool("gh")?,
            s("release"),
            s("download"),
            s(tag),
            s("-R"),
            prepo,
            s("-D"),
            disp(&back),
        ],
        None,
        true,
    )?;
    for local in &published {
        let downloaded = back.join(name(local));
        let same =
            py::is_file(&downloaded) && py::sha256_file(&downloaded)? == py::sha256_file(local)?;
        if !same {
            vd.refuse(
                "G-S",
                &name(local),
                "exact signed plugin release bytes",
                "missing or changed",
                "Restore the verified plugin artifact, SBOM and security evidence set.",
            );
        }
    }
    for n in &want {
        let target = &n[format!("{repo}-{ver}-").len()..n.len() - ".tar.gz".len()];
        let (code, outp) = pack_out(
            inp,
            &[
                s("verify"),
                disp(&back.join(n)),
                s("--keys"),
                inp.trust.k1.clone(),
                s("--target"),
                s(target),
                s("--name"),
                s(repo),
                s("--version"),
                ver.clone(),
            ],
        )?;
        if code != 0 {
            vd.refuse(
                "G-5",
                &format!("published {n}"),
                "VERIFIED",
                &outp,
                "Pull the release back to draft at once.",
            );
        }
    }
    vd.ok("G-7", 1);
    Ok(finish(&vd))
}

/// Report only: rebuild one target here and byte-compare its binary with the candidate's.
pub fn cmd_spot_rebuild(inp: &Inputs, out: &Path, target: &str) -> R<i32> {
    let cj = py::loads(&py::read_text(&inp.cand.join("candidate.json"))?)?;
    let tmp = mkdtemp("tmp")?;
    let mut c = std::process::Command::new("scripts/release-build.sh");
    c.args([
        target,
        "--out-dir",
        &disp(&tmp),
        "--evidence-dir",
        &disp(&tmp.join("ev")),
    ])
    .current_dir(&inp.root)
    .env("BUSBAR_RELEASE_PUBKEY", &inp.trust.k1);
    let status = c
        .status()
        .map_err(|e| py::os_err(&e, Some(Path::new("scripts/release-build.sh"))))?;
    if !status.success() {
        return Err(cannot(format!("release-build.sh {target} failed")));
    }
    let prefix = format!("busbar-{target}.");
    let mine = sorted_dir(&tmp)?
        .into_iter()
        .find(|p| name(p).starts_with(&prefix))
        .ok_or_else(|| PyErr::new(Kind::Runtime, "StopIteration"))?;
    let theirs = inp.cand.join("artifacts").join(name(&mine));
    let same = py::sha256_hex(&unpack_binary(&mine)?) == py::sha256_hex(&unpack_binary(&theirs)?);
    let ev = dict([
        ("version", cj.item("version")?.clone()),
        ("commit", cj.item("commit")?.clone()),
        ("target", Value::from(target)),
        ("binary_identical", Value::Bool(same)),
    ]);
    py::write_text(
        &out.join("spot-rebuild.json"),
        &(dumps(&Value::Dict(ev), Dump::INDENT) + "\n"),
    )?;
    println!(
        "REPORT G-13 spot rebuild {target}: binary {} (report only)",
        if same { "IDENTICAL" } else { "DIFFERENT" }
    );
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(EXIT_OK)
}

impl Value {
    /// `d.values()` of a dict.
    pub fn iter_values(&self) -> R<Vec<Value>> {
        match self {
            Value::Dict(d) => Ok(d.values().cloned().collect()),
            v => Err(PyErr::new(
                Kind::Attribute,
                format!("'{}' object has no attribute 'values'", v.type_name()),
            )),
        }
    }
}
