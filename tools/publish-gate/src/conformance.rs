// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! G-C: every public conformance suite passes for the release commit and the shipped pins, or a
//! K2-signed owner exception records it as it is (docs/design/conformance-release.md).
//!
//! The candidate's `conformance-manifest.json` is re-rendered here from the ModernCI outputs the
//! candidate fetched and must be the same bytes; the render follows
//! `scripts/conformance/sync.py --release` exactly, including every reason it writes.

use crate::archive::Tar;
use crate::py::{
    self, dict, dumps, eq_str, head, opt_repr, opt_str, py_eq, py_repr, py_str, repr_str, Dict,
    Dump, Kind, PyErr, Value, R,
};
use crate::world::{self, ModernCI};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;

pub const SCHEMA: &str = "busbar.conformance.manifest/1";
pub const VERDICT_SCHEMA: &str = "busbar.conformance.verdict/1";
pub const BANNER: &str = "by `python3 scripts/conformance/sync.py --write`; DO NOT EDIT";
const VERDICT_KEYS: &[&str] = &[
    "schema",
    "suite",
    "standard",
    "plan",
    "spec_version",
    "status",
    "armed",
    "commit",
    "run_id",
    "evidence",
    "generated_at",
    "reason",
    "cert_id",
    "issuer",
    "expires",
    "repo",
    "core_pin",
];
const TIERS: &[&str] = &[
    "capable",
    "certified",
    "conformant",
    "evidence-only",
    "spec-conformant",
];
pub const CORE_REPO: &str = "GetBusbar/busbar";
pub const EXCEPTIONS_SCHEMA: &str = "busbar.conformance.exceptions/1";
const K2_NAMESPACE: &str = "busbar-release";
const K2_IDENTITY: &str = "busbar-release";

fn refused(msg: impl Into<String>) -> PyErr {
    PyErr::new(Kind::SyncRefused, msg)
}

fn inv_refused(msg: impl Into<String>) -> PyErr {
    PyErr::new(Kind::InvRefused, msg)
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}

fn full(p: &str, s: &str) -> bool {
    re(&format!("^(?:{p})$")).is_match(s)
}

fn sha_re(s: &str) -> bool {
    full("[0-9a-f]{40}", s)
}

// ── the registry and the shipped pins ───────────────────────────────────────────────────────────

/// `sync.read_registry(path)`: the registered suites, each held to the registry's rules.
pub fn read_registry(path: &Path) -> R<Vec<Dict>> {
    let doc = crate::toml::loads(&py::read_text(path)?)?;
    let suites = doc.get("suite").ok_or_else(|| PyErr::key("suite"))?;
    let list = suites
        .as_list()
        .ok_or_else(|| PyErr::type_err("registry `suite` is not an array of tables"))?;
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for s in list {
        let d = s
            .as_dict()
            .ok_or_else(|| PyErr::type_err("registry suite is not a table"))?;
        for k in [
            "id", "repo", "standard", "plan", "tier", "label", "verdict", "public",
        ] {
            if !d.contains(k) {
                return Err(refused(format!(
                    "registry: suite {} has no `{k}`",
                    opt_repr(d.get("id"))
                )));
            }
        }
        let id = opt_str(d.get("id"));
        let repo_v = d.get("repo").unwrap();
        let repo = repo_v.as_str().ok_or_else(|| {
            PyErr::type_err(format!(
                "expected string or bytes-like object, got '{}'",
                repo_v.type_name()
            ))
        })?;
        if !full(r"GetBusbar/[A-Za-z0-9._-]+", repo) {
            return Err(refused(format!(
                "registry: suite {id} repo {} is not GetBusbar/<name>",
                repr_str(repo)
            )));
        }
        let tier = d.get("tier").unwrap();
        if !TIERS.iter().any(|t| eq_str(Some(tier), t)) {
            return Err(refused(format!(
                "registry: suite {id} tier {} is not one of {}",
                py_repr(tier),
                py::repr_list(TIERS)
            )));
        }
        if seen.contains(&id) {
            return Err(refused(format!("registry: suite {id} is registered twice")));
        }
        seen.push(id);
        out.push(d.clone());
    }
    Ok(out)
}

/// `sync.shipped_pins(root)`: `{"GetBusbar/<name>": sha}`, each plugin's one shipped commit.
pub fn shipped_pins(root: &Path) -> R<Vec<(String, String)>> {
    let mut pins: Vec<(String, String)> = Vec::new();
    let mut put = |repo: &str, sha: &str, where_: &str| -> R<()> {
        let full_name = format!("GetBusbar/{repo}");
        match pins.iter().find(|(k, _)| *k == full_name) {
            Some((_, have)) if have != sha => Err(refused(format!(
                "{full_name} ships at two commits: {have} and {sha} ({where_})"
            ))),
            Some(_) => Ok(()),
            None => {
                pins.push((full_name, sha.to_string()));
                Ok(())
            }
        }
    };
    let lock = root.join("dist/default/Cargo.lock");
    if py::is_file(&lock) {
        let text = py::read_text(&lock)?;
        let pat = re(
            r#"source = "git\+https://(?:github\.com|git\.getbusbar\.dev)/GetBusbar/([A-Za-z0-9._-]+?)(?:\.git)?(?:\?[^#"]*)?#([0-9a-f]{40})""#,
        );
        let mut found: Vec<(String, String)> = pat
            .captures_iter(&text)
            .map(|m| (m[1].to_string(), m[2].to_string()))
            .collect();
        found.sort();
        found.dedup();
        for (repo, sha) in found {
            if repo != "busbar" {
                put(&repo, &sha, "dist/default/Cargo.lock")?;
            }
        }
    }
    let tsv = root.join("release/plugin-pins.tsv");
    if py::is_file(&tsv) {
        let text = py::read_text(&tsv)?;
        for (i, line) in py::splitlines(&text).into_iter().enumerate() {
            if py::strip(line).is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 3 || !sha_re(parts[2]) {
                return Err(refused(format!(
                    "release/plugin-pins.tsv:{} is not <repo>\\t<tag>\\t<40-hex commit>",
                    i + 1
                )));
            }
            put(parts[0], parts[2], "release/plugin-pins.tsv")?;
        }
    }
    Ok(pins)
}

fn pin_of<'a>(pins: &'a [(String, String)], repo: &str) -> Option<&'a str> {
    pins.iter()
        .find(|(k, _)| k == repo)
        .map(|(_, v)| v.as_str())
}

/// `sync.read_exceptions(root, release)`: `{suite: {status, reason}}`, unverified.
pub fn read_exceptions(root: &Path, release: &str) -> R<Vec<(String, Dict)>> {
    let f = root.join("release/conformance-exceptions.json");
    if !py::is_file(&f) {
        return Ok(Vec::new());
    }
    let doc = py::loads(&py::read_text(&f)?)?;
    if !eq_str(doc.get("schema")?, EXCEPTIONS_SCHEMA) || !eq_str(doc.get("release")?, release) {
        return Ok(Vec::new());
    }
    let mut out: Vec<(String, Dict)> = Vec::new();
    let suites = doc.getv("suites")?;
    let items = match doc.get("suites")? {
        None => Vec::new(),
        Some(_) => suites.iter_items()?,
    };
    for e in items {
        let Some(d) = e.as_dict() else { continue };
        let Some(suite) = d.get("suite") else {
            continue;
        };
        let row = dict([
            ("status", d.get("status").cloned().unwrap_or(Value::Null)),
            (
                "reason",
                d.get("reason").cloned().unwrap_or_else(|| Value::from("")),
            ),
        ]);
        let key = py_str(suite);
        if let Some(slot) = out.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = row;
        } else {
            out.push((key, row));
        }
    }
    Ok(out)
}

/// `sync.core_for`: the core a suite's verdict must be judged on.
pub fn core_for(repo: &str, commit: &str, testkit: Option<&str>) -> String {
    match testkit {
        Some(k) if repo != CORE_REPO && !k.is_empty() => k.to_string(),
        _ => commit.to_string(),
    }
}

fn claim_for(suite: &Dict, status: &Value, issuer: Option<&Value>) -> Value {
    if !eq_str(Some(status), "pass") {
        return Value::Null;
    }
    let f = |k: &str| opt_str(suite.get(k));
    let tier = suite.get("tier").and_then(Value::as_str).unwrap_or("");
    Value::Str(match tier {
        "certified" => {
            let who = match issuer {
                Some(v) if v.truthy() => py_str(v),
                _ => f("standard"),
            };
            format!("Certified — {who}")
        }
        "conformant" => format!("Conformant — passes {}", f("plan")),
        "spec-conformant" => format!("Spec-conformant — {}", f("standard")),
        "capable" => format!("{}-capable", f("label")),
        _ => format!("Provides evidence for {}", f("standard")),
    })
}

/// `sync.verdict_problem`: why a verdict breaks verdict.schema.json's rules.
fn verdict_problem(v: &Value, sid: &str) -> Option<String> {
    let Some(d) = v.as_dict() else {
        return Some("the verdict is not a JSON object".into());
    };
    if !eq_str(d.get("schema"), VERDICT_SCHEMA) {
        return Some(format!(
            "schema is {}, not {VERDICT_SCHEMA}",
            opt_repr(d.get("schema"))
        ));
    }
    if !eq_str(d.get("suite"), sid) {
        return Some(format!(
            "names suite {}, filed under {}",
            opt_repr(d.get("suite")),
            repr_str(sid)
        ));
    }
    let mut extra: Vec<&String> = d
        .keys()
        .filter(|k| !VERDICT_KEYS.contains(&k.as_str()))
        .collect();
    if !extra.is_empty() {
        extra.sort();
        return Some(format!("unknown fields {}", py::repr_list(&extra)));
    }
    for k in ["status", "armed", "commit"] {
        if !d.contains(k) {
            return Some(format!("no `{k}`"));
        }
    }
    let status = d.get("status").unwrap();
    if !["pass", "fail", "not-run"]
        .iter()
        .any(|s| eq_str(Some(status), s))
    {
        return Some(format!("status {}", py_repr(status)));
    }
    if !matches!(d.get("armed"), Some(Value::Bool(true))) && !eq_str(Some(status), "not-run") {
        return Some(format!("an unarmed verdict says {}", py_str(status)));
    }
    None
}

// ── URLs, as urllib.parse reads them ────────────────────────────────────────────────────────────

struct Split {
    scheme: String,
    path: String,
    query: String,
}

fn urlsplit(url: &str) -> R<Split> {
    let url: String = url
        .trim_start_matches(|c: char| (c as u32) <= 0x20)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = url.as_str();
    let mut scheme = String::new();
    if let Some(i) = rest.find(':') {
        let first = rest.chars().next().unwrap_or(' ');
        if i > 0
            && first.is_ascii_alphabetic()
            && rest[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        {
            scheme = rest[..i].to_lowercase();
            rest = &rest[i + 1..];
        }
    }
    let mut netloc = "";
    if rest.starts_with("//") {
        let after = &rest[2..];
        let delim = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = &after[..delim];
        rest = &after[delim..];
        if (netloc.contains('[') && !netloc.contains(']'))
            || (netloc.contains(']') && !netloc.contains('['))
        {
            return Err(PyErr::value("Invalid IPv6 URL"));
        }
    }
    let _ = netloc;
    if let Some((u, _frag)) = rest.split_once('#') {
        rest = u;
    }
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (rest.to_string(), String::new()),
    };
    Ok(Split {
        scheme,
        path,
        query,
    })
}

fn unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::new();
    let mut run: Vec<char> = Vec::new();
    let flush = |run: &mut Vec<char>, out: &mut String| {
        if run.is_empty() {
            return;
        }
        let ascii: String = run.iter().collect();
        let b = ascii.as_bytes();
        let mut bytes = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let h = &ascii[i + 1..i + 3];
                if h.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Ok(x) = u8::from_str_radix(h, 16) {
                        bytes.push(x);
                        i += 3;
                        continue;
                    }
                }
            }
            bytes.push(b[i]);
            i += 1;
        }
        out.push_str(&String::from_utf8_lossy(&bytes));
        run.clear();
    };
    for c in s.chars() {
        if c.is_ascii() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn parse_qs(qs: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for nv in qs.split('&') {
        if nv.is_empty() {
            continue;
        }
        let Some((n, v)) = nv.split_once('=') else {
            continue;
        };
        if v.is_empty() {
            continue;
        }
        let name = unquote(&n.replace('+', " "));
        let value = unquote(&v.replace('+', " "));
        match out.iter_mut().find(|(k, _)| *k == name) {
            Some((_, vals)) => vals.push(value),
            None => out.push((name, vec![value])),
        }
    }
    out
}

/// `sync.stamp_problem`: why a schema-valid verdict is not the judge's stamp for `repo`@`head`.
fn stamp_problem(v: &Dict, repo: &str, head_: &str, core: &str) -> R<Option<String>> {
    if !eq_str(v.get("repo"), repo) {
        return Ok(Some(format!(
            "stamped for repo {}, not {repo}",
            opt_repr(v.get("repo"))
        )));
    }
    if !eq_str(v.get("commit"), head_) {
        return Ok(Some(format!(
            "stamped for commit {}, not the shipped {}",
            head(&opt_str(v.get("commit")), 12),
            head(head_, 12)
        )));
    }
    if !eq_str(v.get("core_pin"), core) {
        return Ok(Some(format!(
            "judged against core {}, not the expected core {}",
            head(&opt_str(v.get("core_pin")), 12),
            head(core, 12)
        )));
    }
    let run_id = v.get("run_id").map(py_str).unwrap_or_default();
    if run_id.starts_with("gitlab:") {
        let pat = format!(
            "^{}:pipeline:([1-9][0-9]*):job:([1-9][0-9]*)$",
            regex::escape(&format!("gitlab:{repo}@{head_}"))
        );
        let Some(m) = re(&pat).captures(&run_id) else {
            return Ok(Some(
                "native CI run identity does not match the repository and source".into(),
            ));
        };
        let expected = format!("https://github.com/{repo}/-/jobs/{}", &m[2]);
        if !eq_str(v.get("evidence"), &expected) {
            return Ok(Some(
                "native CI evidence does not name the stamped job".into(),
            ));
        }
        return Ok(None);
    }
    if !eq_str(
        v.get("run_id"),
        &format!("modernci:{repo}@{head_}:conformance"),
    ) {
        return Ok(Some(format!(
            "run_id {} is not ModernCI's conformance run of {repo}@{}",
            opt_repr(v.get("run_id")),
            head(head_, 12)
        )));
    }
    let ev = urlsplit(&v.get("evidence").map(py_str).unwrap_or_default())?;
    let q = parse_qs(&ev.query);
    let one = |k: &str, want: &str| {
        q.iter()
            .find(|(n, _)| n == k)
            .map(|(_, vals)| vals.len() == 1 && vals[0] == want)
            .unwrap_or(false)
    };
    if ev.scheme != "https" || ev.path != "/move" || !one("repo", repo) || !one("head", head_) {
        return Ok(Some(format!(
            "evidence {} is not the ModernCI move of {repo}@{}",
            opt_repr(v.get("evidence")),
            head(head_, 12)
        )));
    }
    Ok(None)
}

// ── the fetched outputs ─────────────────────────────────────────────────────────────────────────

fn days_in(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Seconds since the epoch of a UTC civil time.
pub fn epoch(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    let (y2, m2) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + h * 3600 + mi * 60 + s
}

pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")` as UTC seconds.
fn timestamp(v: &Value) -> R<i64> {
    let Value::Str(s) = v else {
        return Err(PyErr::type_err(format!(
            "strptime() argument 1 must be str, not {}",
            v.type_name()
        )));
    };
    let pat = re(
        r"(?i)^(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])T(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)Z",
    );
    let fmt = "'%Y-%m-%dT%H:%M:%SZ'";
    let Some(m) = pat.captures(s) else {
        return Err(PyErr::value(format!(
            "time data {} does not match format {fmt}",
            repr_str(s)
        )));
    };
    let end = m.get(0).unwrap().end();
    if end != s.len() {
        return Err(PyErr::value(format!(
            "unconverted data remains: {}",
            &s[end..]
        )));
    }
    let n = |i: usize| -> R<i64> {
        py::strip(&m[i]).parse::<i64>().map_err(|_| {
            PyErr::value(format!(
                "time data {} does not match format {fmt}",
                repr_str(s)
            ))
        })
    };
    let (y, mo, d, h, mi, sec) = (n(1)?, n(2)?, n(3)?, n(4)?, n(5)?, n(6)?);
    if d > days_in(y, mo) {
        return Err(PyErr::value(format!(
            "day {d} must be in range 1..{} for month {mo} in year {y}",
            days_in(y, mo)
        )));
    }
    if sec > 59 {
        return Err(PyErr::value(format!("second must be in 0..59, not {sec}")));
    }
    Ok(epoch(y, mo, d, h, mi, sec))
}

/// `invocation.validated_verdicts(data, repo=, head=, state=, allow_failed=True)`.
fn validated_verdicts(data: &[u8], repo: &str, head_: &Value, state: &Value) -> R<Dict> {
    let green = eq_str(Some(state), "green");
    if !green && !eq_str(Some(state), "red") {
        return Err(inv_refused("the conformance job did not finish green"));
    }
    match validated_inner(data, repo, head_, green) {
        Ok(v) => Ok(v),
        Err(e) if e.kind == Kind::InvRefused => Err(e),
        Err(e) if e.is_key() || e.is_type() || e.is_value() || e.is_tar() => Err(inv_refused(
            format!("invalid conformance invocation: {}", e.msg),
        )),
        Err(e) => Err(e),
    }
}

fn validated_inner(data: &[u8], repo: &str, head_: &Value, green: bool) -> R<Dict> {
    let archive = Tar::from_bytes(data)?;
    let mut files: Vec<(String, usize)> = Vec::new();
    for (i, m) in archive.members.iter().enumerate() {
        if !m.isfile() {
            continue;
        }
        let name = m.name.strip_prefix("./").unwrap_or(&m.name).to_string();
        if files.iter().any(|(n, _)| *n == name) {
            return Err(inv_refused("duplicate artifact member"));
        }
        files.push((name, i));
    }
    let receipts: Vec<&(String, usize)> = files
        .iter()
        .filter(|(n, _)| n.ends_with("/invocation.json") || n == "invocation.json")
        .collect();
    if receipts.len() != 1 {
        return Err(inv_refused(
            "no unique completed invocation receipt; rerun the current driver",
        ));
    }
    let (name, idx) = receipts[0].clone();
    let bytes = archive.extract(idx)?.unwrap_or_default();
    let receipt = py::loads_bytes(&bytes)?;
    let Some(r) = receipt.as_dict() else {
        return Err(inv_refused("invalid invocation receipt"));
    };
    if !eq_str(r.get("schema"), "busbar.conformance.invocation/1") {
        return Err(inv_refused("invalid invocation receipt"));
    }
    let head_ok = match head_ {
        Value::Str(h) => eq_str(r.get("commit"), h),
        Value::Null => matches!(r.get("commit"), None | Some(Value::Null)),
        other => r.get("commit").map(|c| py_eq(c, other)).unwrap_or(false),
    };
    if !eq_str(r.get("repo"), repo) || !head_ok {
        return Err(inv_refused(
            "invocation does not name the requested repository and head",
        ));
    }
    let expected_exit = if green { "0" } else { "1" };
    if !matches!(r.get("exit_code"), Some(Value::Int(n)) if n == expected_exit) {
        return Err(inv_refused("invocation exit does not match the job result"));
    }
    let id = r.get("invocation_id").map(py_str).unwrap_or_default();
    if !full("[0-9a-f]{32}", &id) {
        return Err(inv_refused("missing invocation identity"));
    }
    let core = r.get("core_pin").map(py_str).unwrap_or_default();
    if !full("[0-9a-f]{40}", &core) {
        return Err(inv_refused("missing invocation core pin"));
    }
    let required = [
        "testing/conformance/run.sh",
        "testing/conformance/tools.sh",
        "testing/conformance/suites.tsv",
    ];
    let inputs_ok = match r.get("inputs") {
        Some(Value::Dict(d)) => {
            required.iter().all(|k| d.contains(k))
                && d.0
                    .iter()
                    .all(|(_, digest)| full("[0-9a-f]{64}", &py_str(digest)))
        }
        _ => false,
    };
    if !inputs_ok {
        return Err(inv_refused("missing invocation input hashes"));
    }
    let started = timestamp(receipt.item("started_at")?)?;
    let finished = timestamp(receipt.item("finished_at")?)?;
    if started > finished || finished > now_epoch() {
        return Err(inv_refused("invalid invocation time interval"));
    }
    let hashes = match r.get("verdicts") {
        Some(Value::Dict(d)) if !d.is_empty() => d.clone(),
        _ => return Err(inv_refused("invocation carries no verdict hashes")),
    };
    let prefix = format!("{}verdicts/", &name[..name.len() - "invocation.json".len()]);
    let members: Vec<&(String, usize)> = files
        .iter()
        .filter(|(p, _)| format!("/{p}").contains("/verdicts/") && p.ends_with(".json"))
        .collect();
    let mut have: Vec<String> = members.iter().map(|(p, _)| p.clone()).collect();
    let mut want: Vec<String> = hashes.keys().map(|f| format!("{prefix}{f}")).collect();
    have.sort();
    want.sort();
    want.dedup();
    if have != want {
        return Err(inv_refused(
            "artifact verdicts differ from the completed invocation",
        ));
    }
    let mut verdicts = Dict::new();
    for (filename, digest) in &hashes.0 {
        if !full(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.json", filename) {
            return Err(inv_refused("invalid invocation verdict name"));
        }
        let at = members
            .iter()
            .find(|(p, _)| *p == format!("{prefix}{filename}"))
            .map(|(_, i)| *i)
            .ok_or_else(|| PyErr::key(&format!("{prefix}{filename}")))?;
        let payload = archive.extract(at)?.unwrap_or_default();
        if !eq_str(Some(digest), &py::sha256_hex(&payload)) {
            return Err(inv_refused(
                "verdict bytes differ from the completed invocation",
            ));
        }
        let verdict = py::loads_bytes(&payload)?;
        let sid = &filename[..filename.len() - 5];
        let vd = verdict.as_dict().ok_or_else(|| {
            PyErr::new(
                Kind::Attribute,
                format!("'{}' object has no attribute 'get'", verdict.type_name()),
            )
        })?;
        let same = eq_str(vd.get("repo"), repo)
            && vd
                .get("commit")
                .map(|c| py_eq(c, head_))
                .unwrap_or(matches!(head_, Value::Null))
            && eq_str(vd.get("core_pin"), &core)
            && eq_str(vd.get("suite"), sid);
        if !same {
            return Err(inv_refused(
                "verdict identity differs from the completed invocation",
            ));
        }
        if green
            && (!eq_str(vd.get("status"), "pass")
                || !matches!(vd.get("armed"), Some(Value::Bool(true))))
        {
            return Err(inv_refused(
                "successful invocation carries a non-passing verdict",
            ));
        }
        let at = timestamp(verdict.item("generated_at")?)?;
        if !(started <= at && at <= finished) {
            return Err(inv_refused(
                "verdict predates or follows the completed invocation",
            ));
        }
        verdicts.insert(sid.to_string(), verdict.clone());
    }
    if !green {
        verdicts = Dict(
            verdicts
                .0
                .into_iter()
                .filter(|(_, v)| !eq_str(v.as_dict().and_then(|d| d.get("status")), "pass"))
                .collect(),
        );
        if verdicts.is_empty() {
            return Err(inv_refused(
                "failed invocation carries no negative evidence",
            ));
        }
    }
    Ok(verdicts)
}

struct Fetched {
    receipt: Dict,
    verdicts: Dict,
}

/// `sync.load_fetched(directory)`: what the candidate fetched from ModernCI, per repo.
fn load_fetched(directory: &Path) -> R<Vec<(String, Fetched)>> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    if py::is_dir(directory) {
        for owner in py::iterdir(directory).unwrap_or_default() {
            if !py::is_dir(&owner) {
                continue;
            }
            for name in py::iterdir(&owner).unwrap_or_default() {
                let rec = name.join("receipt.json");
                if py::exists(&rec) {
                    files.push(rec);
                }
            }
        }
    }
    files.sort_by_key(|p| {
        p.components()
            .map(|c| c.as_os_str().to_owned())
            .collect::<Vec<_>>()
    });
    let mut out: Vec<(String, Fetched)> = Vec::new();
    for rec_file in files {
        let rec = match py::read_text(&rec_file).and_then(|t| py::loads(&t)) {
            Ok(v) => v,
            Err(e) if e.is_os() || e.is_value() => continue,
            Err(e) => return Err(e),
        };
        let parent = rec_file.parent().unwrap();
        let repo = format!(
            "{}/{}",
            py::name(parent.parent().unwrap()),
            py::name(parent)
        );
        let Some(d) = rec.as_dict() else { continue };
        if !eq_str(d.get("repo"), &repo) || !eq_str(d.get("check"), "conformance") {
            continue;
        }
        let mut receipt = d.clone();
        let mut verdicts = Dict::new();
        if !d.get("missing").map(Value::truthy).unwrap_or(false) {
            match fetched_verdicts(d, parent, &repo) {
                Ok(v) => verdicts = v,
                Err(e)
                    if e.is_os() || e.is_value() || e.is_tar() || e.kind == Kind::SyncRefused =>
                {
                    receipt.insert("missing", Value::Str(e.msg));
                }
                Err(e) => return Err(e),
            }
        }
        if let Some(slot) = out.iter_mut().find(|(k, _)| *k == repo) {
            slot.1 = Fetched { receipt, verdicts };
        } else {
            out.push((repo, Fetched { receipt, verdicts }));
        }
    }
    Ok(out)
}

fn fetched_verdicts(d: &Dict, parent: &Path, repo: &str) -> R<Dict> {
    let generation = match d.get("generation") {
        None => String::new(),
        Some(Value::Str(s)) => s.clone(),
        Some(v) => {
            return Err(PyErr::type_err(format!(
                "expected string or bytes-like object, got '{}'",
                v.type_name()
            )))
        }
    };
    if !full("generation-[A-Za-z0-9_-]+", &generation) {
        return Err(refused(
            "no complete fetched generation; rebuild the candidate",
        ));
    }
    let data = py::read_bytes(&parent.join(&generation).join("artifact.tar"))?;
    let rerun = match d.get("rerun") {
        Some(v) if v.truthy() => v.clone(),
        _ => Value::Dict(Dict::new()),
    };
    let rerun_refused = rerun.get("refused")?.map(Value::truthy).unwrap_or(false);
    let use_rerun = !rerun_refused && rerun.truthy();
    let expected = if use_rerun {
        rerun.getv("sha")?
    } else {
        d.get("sha").cloned().unwrap_or(Value::Null)
    };
    if !eq_str(Some(&expected), &py::sha256_hex(&data)) {
        return Err(refused("the fetched archive does not hash to its receipt"));
    }
    let state = if use_rerun {
        rerun.getv("state")?
    } else {
        d.get("state").cloned().unwrap_or(Value::Null)
    };
    let head_ = d.get("head").cloned().unwrap_or(Value::Null);
    validated_verdicts(&data, repo, &head_, &state)
}

/// `sync.render_release`: the release's conformance manifest, as canonical bytes.
pub fn render_release(
    registry: &Path,
    fetched_dir: &Path,
    release: &str,
    commit: &str,
    pins: &[(String, String)],
    exceptions: &[(String, Dict)],
    testkit: Option<&str>,
) -> R<String> {
    let mut suites = read_registry(registry)?;
    let fetched = load_fetched(fetched_dir)?;
    suites.sort_by_key(|s| opt_str(s.get("id")));
    let mut entries: Vec<Value> = Vec::new();
    let mut stamps: Vec<String> = Vec::new();
    for s in &suites {
        let sid = opt_str(s.get("id"));
        let repo = s
            .get("repo")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let head_: Option<String> = if repo == CORE_REPO {
            Some(commit.to_string())
        } else {
            pin_of(pins, &repo).map(str::to_string)
        };
        let mut e = dict([
            ("suite", Value::Str(sid.clone())),
            (
                "standard",
                s.get("standard").cloned().unwrap_or(Value::Null),
            ),
            ("plan", s.get("plan").cloned().unwrap_or(Value::Null)),
            ("tier", s.get("tier").cloned().unwrap_or(Value::Null)),
            (
                "public",
                Value::Bool(opt_str(s.get("public")).to_lowercase() == "true"),
            ),
            ("repo", Value::Str(repo.clone())),
            ("status", Value::from("not-run")),
            ("claim", Value::Null),
        ]);
        let rec = fetched.iter().find(|(k, _)| *k == repo).map(|(_, f)| f);
        let mut v: Option<&Value> = None;
        match &head_ {
            None => e.insert(
                "reason",
                Value::Str(format!(
                    "{repo} ships no pin at this release: the suite judges nothing that ships"
                )),
            ),
            Some(h) => {
                e.insert("commit", Value::Str(h.clone()));
                let h12 = head(h, 12);
                match rec {
                    None => e.insert(
                        "reason",
                        Value::Str(format!(
                            "no ModernCI conformance output was fetched for {repo}@{h12}"
                        )),
                    ),
                    Some(r) if r.receipt.get("missing").map(Value::truthy).unwrap_or(false) => e
                        .insert(
                            "reason",
                            Value::Str(format!(
                                "ModernCI has no conformance output for {repo}@{h12}: {}",
                                opt_str(r.receipt.get("missing"))
                            )),
                        ),
                    Some(r) if !eq_str(r.receipt.get("head"), h) => e.insert(
                        "reason",
                        Value::Str(format!(
                            "ModernCI answered {repo}@{}, not the shipped {h12}",
                            head(&opt_str(r.receipt.get("head")), 12)
                        )),
                    ),
                    Some(r) if !r.verdicts.contains(&sid) => e.insert(
                        "reason",
                        Value::Str(format!(
                            "{repo}@{h12}'s conformance check wrote no verdict for {sid}"
                        )),
                    ),
                    Some(r) => {
                        let raw = r.verdicts.get(&sid).unwrap();
                        let core = core_for(&repo, commit, testkit);
                        let mut why = match verdict_problem(raw, &sid) {
                            Some(w) => Some(w),
                            None => stamp_problem(raw.as_dict().unwrap(), &repo, h, &core)?,
                        };
                        let rerun = match r.receipt.get("rerun") {
                            Some(x) if x.truthy() => x.clone(),
                            _ => Value::Dict(Dict::new()),
                        };
                        if let Some(w) = &mut why {
                            if rerun.get("refused")?.map(Value::truthy).unwrap_or(false) {
                                w.push_str(&format!(
                                    "; no re-run against {} was possible: {}",
                                    head(&core, 12),
                                    py_str(rerun.item("refused")?)
                                ));
                            }
                        }
                        match why {
                            Some(w) => e.insert(
                                "reason",
                                Value::Str(format!("the verdict is not used: {w}")),
                            ),
                            None => v = Some(raw),
                        }
                    }
                }
            }
        }
        if let Some(v) = v {
            let vd = v.as_dict().unwrap();
            let status = vd.get("status").cloned().unwrap_or(Value::Null);
            e.insert("status", status.clone());
            e.insert("claim", claim_for(s, &status, vd.get("issuer")));
            for (src, dst) in [
                ("spec_version", "spec_version"),
                ("evidence", "evidence"),
                ("core_pin", "core_pin"),
                ("generated_at", "verified_at"),
                ("expires", "expires"),
            ] {
                if let Some(x) = vd.get(src) {
                    if x.truthy() {
                        e.insert(dst, x.clone());
                    }
                }
            }
            if !eq_str(Some(&status), "pass") {
                let reason = match vd.get("reason") {
                    Some(r) if r.truthy() => r.clone(),
                    _ => Value::Str(format!("the suite's verdict is {}", py_str(&status))),
                };
                e.insert("reason", reason);
            }
            if let Some(g) = vd.get("generated_at") {
                if g.truthy() {
                    stamps.push(py_str(g));
                }
            }
        }
        if let Some((_, x)) = exceptions.iter().find(|(k, _)| *k == sid) {
            let status = e.get("status").cloned().unwrap_or(Value::Null);
            if !eq_str(Some(&status), "pass")
                && x.get("status").map(|s| py_eq(s, &status)).unwrap_or(false)
            {
                e.insert(
                    "reason",
                    Value::Str(format!(
                        "owner exception (signed): {}; {}",
                        x.get("reason").map(py_str).unwrap_or_default(),
                        e.get("reason").map(py_str).unwrap_or_default()
                    )),
                );
            }
        }
        entries.push(Value::Dict(e));
    }
    let mut regenerate = format!("--release {release} --commit {commit} --from-modernci <DIR>");
    if let Some(k) = testkit.filter(|k| !k.is_empty()) {
        regenerate.push_str(&format!(" --testkit {k}"));
    }
    let doc = dict([
        (
            "_generated",
            Value::Str(BANNER.replace("--write", &regenerate)),
        ),
        ("commit", Value::from(commit)),
        (
            "generated_at",
            Value::Str(stamps.iter().max().cloned().unwrap_or_default()),
        ),
        ("release", Value::from(release)),
        ("schema", Value::from(SCHEMA)),
        ("suites", Value::List(entries)),
    ]);
    Ok(dumps(
        &Value::Dict(doc),
        Dump {
            indent: Some(2),
            sort_keys: true,
            ensure_ascii: false,
        },
    ) + "\n")
}

fn render(
    root: &Path,
    cand: &Path,
    commit: &str,
    release: &str,
    testkit: Option<&str>,
) -> R<String> {
    let pins = shipped_pins(root)?;
    let exceptions = read_exceptions(root, release)?;
    render_release(
        &root.join("conformance/registry.toml"),
        &cand.join("conformance"),
        release,
        commit,
        &pins,
        &exceptions,
        testkit,
    )
}

// ── G-C ─────────────────────────────────────────────────────────────────────────────────────────

struct Refusals(Vec<String>);

impl Refusals {
    fn refuse(&mut self, subject: &str, expected: &str, found: &str, todo: &str) {
        let line = format!("REFUSED G-C {subject}: expected {expected}; found {found}. {todo}");
        println!("{line}");
        self.0.push(line);
    }
}

/// The registry, the shipped pins and the render of the candidate's fetched outputs.
type Rendered = (Vec<Dict>, Vec<(String, String)>, String);

type Exceptions = (Vec<(String, Dict)>, Vec<((String, String), Dict)>);

/// `conformance_gate.verify_exceptions`: the K2-signed owner exceptions, or a refusal.
fn verify_exceptions(
    root: &Path,
    release: &str,
    allowed_signers: &[String],
    out: &mut Refusals,
) -> R<Exceptions> {
    let f = root.join("release/conformance-exceptions.json");
    if !py::is_file(&f) {
        return Ok((Vec::new(), Vec::new()));
    }
    let sig = std::path::PathBuf::from(format!("{}.sig", py::disp(&f)));
    let name = "release/conformance-exceptions.json";
    if !py::is_file(&sig) {
        out.refuse(
            name,
            "a K2 signature beside it (.sig)",
            "none",
            "Sign it: ssh-keygen -Y sign -n busbar-release.",
        );
        return Ok((Vec::new(), Vec::new()));
    }
    let keygen = world::which("ssh-keygen").ok_or_else(|| {
        PyErr::new(
            Kind::CgCannotRun,
            "`ssh-keygen` is not on PATH; the owner exceptions cannot be verified",
        )
    })?;
    let signers = world::mkstemp("tmp", ".signers")?;
    py::write_text(&signers, &(allowed_signers.join("\n") + "\n"))?;
    let data = py::read_bytes(&f);
    let p = data.and_then(|d| {
        world::run(
            &[
                keygen,
                "-Y".into(),
                "verify".into(),
                "-f".into(),
                py::disp(&signers),
                "-I".into(),
                K2_IDENTITY.into(),
                "-n".into(),
                K2_NAMESPACE.into(),
                "-s".into(),
                py::disp(&sig),
            ],
            Some(&d),
            false,
        )
    });
    let _ = std::fs::remove_file(&signers);
    if p?.code != 0 {
        out.refuse(
            name,
            "a K2 signature verifying against your allowed_signers",
            "none that verifies",
            "An unsigned or altered exception is never honoured; sign the file you mean.",
        );
        return Ok((Vec::new(), Vec::new()));
    }
    let doc = match py::read_text(&f).and_then(|t| py::loads(&t)) {
        Ok(d) => d,
        Err(e) if e.is_value() => {
            out.refuse(name, "JSON", &e.msg, "Fix and re-sign it.");
            return Ok((Vec::new(), Vec::new()));
        }
        Err(e) => return Err(e),
    };
    if !eq_str(doc.get("schema")?, EXCEPTIONS_SCHEMA) {
        out.refuse(
            name,
            &format!("schema {EXCEPTIONS_SCHEMA}"),
            &opt_repr(doc.get("schema")?),
            "Fix and re-sign it.",
        );
        return Ok((Vec::new(), Vec::new()));
    }
    if !eq_str(doc.get("release")?, release) {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut suites: Vec<(String, Dict)> = Vec::new();
    let mut pins: Vec<((String, String), Dict)> = Vec::new();
    let items = |k: &str| -> R<Vec<Value>> {
        match doc.get(k)? {
            None => Ok(Vec::new()),
            Some(v) => v.iter_items(),
        }
    };
    for e in items("suites")? {
        let ok = match e.as_dict() {
            Some(d) => {
                ["fail", "not-run"]
                    .iter()
                    .any(|s| eq_str(d.get("status"), s))
                    && d.get("suite").map(Value::truthy).unwrap_or(false)
            }
            None => false,
        };
        if !ok {
            out.refuse(
                name,
                "suite exceptions that record fail or not-run",
                &dumps(&e, Dump::PLAIN),
                "An exception records the real status and is never a pass.",
            );
            continue;
        }
        let d = e.as_dict().unwrap();
        let key = py_str(d.get("suite").unwrap());
        match suites.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = d.clone(),
            None => suites.push((key, d.clone())),
        }
    }
    for e in items("pins")? {
        let repo = match e.as_dict() {
            Some(d) => d.get("repo").map(py_str).unwrap_or_default(),
            None => String::new(),
        };
        let repo = if repo.starts_with("GetBusbar/") {
            repo
        } else {
            format!("GetBusbar/{repo}")
        };
        let ok = match e.as_dict() {
            Some(d) => {
                sha_re(&d.get("commit").map(py_str).unwrap_or_default())
                    && d.get("reason").map(Value::truthy).unwrap_or(false)
            }
            None => false,
        };
        if !ok {
            out.refuse(
                name,
                "pin exceptions naming repo, a 40-hex commit and a reason",
                &dumps(&e, Dump::PLAIN),
                "Fix and re-sign it.",
            );
            continue;
        }
        let d = e.as_dict().unwrap();
        let key = (repo, py_str(d.get("commit").unwrap()));
        match pins.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = d.clone(),
            None => pins.push((key, d.clone())),
        }
    }
    Ok((suites, pins))
}

/// `conformance_gate.gate_c`: every refusal line, already printed.
pub fn gate_c(
    root: &Path,
    cand: &Path,
    commit: &str,
    release: &str,
    allowed_signers: &[String],
    client: &dyn ModernCI,
) -> R<Vec<String>> {
    let testkit: Option<&str> = None;
    let mut out = Refusals(Vec::new());
    let (suite_exc, pin_exc) = verify_exceptions(root, release, allowed_signers, &mut out)?;
    let attempt = (|| -> R<Rendered> {
        let suites = read_registry(&root.join("conformance/registry.toml"))?;
        let pins = shipped_pins(root)?;
        let mine = render(root, cand, commit, release, testkit)?;
        Ok((suites, pins, mine))
    })();
    let (suites, pins, mine) = match attempt {
        Ok(x) => x,
        Err(e) if e.kind == Kind::SyncRefused || e.is_value() || e.is_key() => {
            out.refuse(
                "conformance",
                "a registry and shipped pins that render",
                &e.msg,
                "Fix the tree at the release commit.",
            );
            return Ok(out.0);
        }
        Err(e) => return Err(e),
    };
    let mf = cand.join("conformance-manifest.json");
    let theirs = if py::is_file(&mf) {
        Some(py::read_bytes(&mf)?)
    } else {
        None
    };
    if theirs.as_deref() != Some(mine.as_bytes()) {
        out.refuse(
            "conformance-manifest.json",
            "the render of the candidate's fetched ModernCI outputs",
            if theirs.is_none() {
                "missing"
            } else {
                "different bytes"
            },
            "The manifest is generated, never edited; rebuild the candidate's conformance-manifest slice.",
        );
    }
    let m = py::loads(&mine)?;
    let entries: BTreeMap<String, Dict> = m
        .item("suites")?
        .iter_items()?
        .into_iter()
        .filter_map(|e| {
            let d = e.as_dict()?.clone();
            Some((opt_str(d.get("suite")), d))
        })
        .collect();
    let empty = Dict::new();
    for s in &suites {
        if opt_str(s.get("public")).to_lowercase() != "true" {
            continue;
        }
        let sid = opt_str(s.get("id"));
        let repo = s.get("repo").and_then(Value::as_str).unwrap_or("");
        let want: Option<String> = if repo == CORE_REPO {
            Some(commit.to_string())
        } else {
            pin_of(&pins, repo).map(str::to_string)
        };
        let e = entries.get(&sid).unwrap_or(&empty);
        let core = core_for(repo, commit, testkit);
        if eq_str(e.get("status"), "pass")
            && eq_str(e.get("repo"), repo)
            && want
                .as_deref()
                .is_some_and(|w| !w.is_empty() && eq_str(e.get("commit"), w))
            && eq_str(e.get("core_pin"), &core)
        {
            continue;
        }
        if let Some((_, x)) = suite_exc.iter().find(|(k, _)| *k == sid) {
            let st = e.get("status");
            let same = match (x.get("status"), st) {
                (Some(a), Some(b)) => py_eq(a, b),
                (None, None) => true,
                (Some(Value::Null), None) | (None, Some(Value::Null)) => true,
                _ => false,
            };
            if !x.is_empty() && !eq_str(st, "pass") && same {
                continue;
            }
        }
        out.refuse(
            &format!("suite {sid}"),
            &format!(
                "pass for {repo}@{} on core {}",
                head(want.as_deref().filter(|w| !w.is_empty()).unwrap_or("no shipped pin"), 12),
                head(&core, 12)
            ),
            &format!(
                "{}: {}",
                e.get("status").map(py_str).unwrap_or_else(|| "absent".into()),
                e.get("reason").map(py_str).unwrap_or_default()
            ),
            "Green means green: fix it red-first and re-judge, or the owner signs an exception that records it as it is.",
        );
    }
    let mut owners: Vec<String> = suites
        .iter()
        .filter_map(|s| s.get("repo").and_then(Value::as_str).map(str::to_string))
        .filter(|r| r != CORE_REPO)
        .collect();
    owners.sort();
    owners.dedup();
    for repo in owners {
        let Some(p) = pin_of(&pins, &repo) else {
            continue;
        };
        let rec_file = cand.join("conformance").join(&repo).join("receipt.json");
        if py::is_file(&rec_file) {
            let got = py::loads(&py::read_text(&rec_file)?)?.getv("head")?;
            if !eq_str(Some(&got), p) {
                out.refuse(
                    &format!("{repo} pin"),
                    &format!("the judged commit {}", head(&py_str(&got), 12)),
                    &head(p, 12),
                    "dist/default and release/plugin-pins.tsv must ship the commit ModernCI judged.",
                );
            }
        }
        let dev = client.dev_head(&repo)?;
        if dev != p && !pin_exc.iter().any(|((r, c), _)| *r == repo && c == p) {
            out.refuse(
                &format!("{repo} pin"),
                &format!("its dev head {}", head(&dev, 12)),
                &head(p, 12),
                "The release ships each plugin's dev head (WEBSITE-CLAIMS 2a #4): repin, or the owner signs a pin exception.",
            );
        }
    }
    Ok(out.0)
}

/// `conformance_gate.evidence`: what release-evidence.json records for G-C (the K2 hook).
pub fn evidence(root: &Path, cand: &Path, release: &str) -> R<Dict> {
    let mf = cand.join("conformance-manifest.json");
    let m = py::loads(&py::read_text(&mf)?)?;
    let excepted = read_exceptions(root, release)?;
    let mut public_pass = 0usize;
    let mut names: Vec<String> = Vec::new();
    for e in m.item("suites")?.iter_items()? {
        if e.item("public")?.truthy() && eq_str(Some(e.item("status")?), "pass") {
            public_pass += 1;
        }
        let sid = e.item("suite")?;
        if excepted.iter().any(|(k, _)| eq_str(Some(sid), k))
            && !eq_str(Some(e.item("status")?), "pass")
        {
            names.push(py_str(sid));
        }
    }
    names.sort();
    Ok(dict([
        (
            "conformance_manifest_sha256",
            Value::Str(py::sha256_hex(&py::read_bytes(&mf)?)),
        ),
        (
            "conformance",
            Value::Dict(dict([
                ("rule", Value::from("G-C")),
                ("public_pass", Value::from(public_pass)),
                (
                    "excepted",
                    Value::List(names.into_iter().map(Value::Str).collect()),
                ),
            ])),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_read_as_strptime_does() {
        let t = |s: &str| timestamp(&Value::from(s));
        assert_eq!(t("2026-10-28T10:00:00Z").unwrap(), 1_793_181_600);
        assert_eq!(t("2026-1-2T3:4:5Z").unwrap(), epoch(2026, 1, 2, 3, 4, 5));
        assert_eq!(
            t("2026-02-30T00:00:00Z").unwrap_err().msg,
            "day 30 must be in range 1..28 for month 2 in year 2026"
        );
        assert!(t("2026-10-28T10:00:00Zx")
            .unwrap_err()
            .msg
            .contains("unconverted data remains: x"));
    }

    #[test]
    fn query_strings_read_as_parse_qs_does() {
        let q = parse_qs("repo=GetBusbar%2Fbusbar&from=dev&head=ab&x=&y");
        assert_eq!(q[0], ("repo".into(), vec!["GetBusbar/busbar".into()]));
        assert_eq!(q.len(), 3);
        let s = urlsplit("https://eu.modernci.dev/move?repo=a#f").unwrap();
        assert_eq!(
            (s.scheme.as_str(), s.path.as_str(), s.query.as_str()),
            ("https", "/move", "repo=a")
        );
    }
}
