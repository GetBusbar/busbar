// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANES' BLACK-BOX CASES, RUN AGAINST THE REAL BINARY (`blackbox/1`; coordinator ruling, Law 0
//! root lane). A plane door crate states a directory of case files beside its root cells, under the
//! same `links` name (`cargo::metadata=blackbox=<dir>`); the root's `build.rs` resolves it the same
//! way for a path dependency and a pinned one (`DOOR_BLACKBOX`). This one test iterates every linked
//! door's directory and runs each case: it writes the case's files, starts the far ends the case
//! states, boots `CARGO_BIN_EXE_busbar`, drives it (`--validate`, a boot, a line-served session, an
//! HTTP call, the admin API) and holds every answer to the case.
//!
//! Every word a case is about — its config section, its methods, its dialect, its digest, its
//! refusal text — is the plane's DATA, written by the plane in its own crate. This source names no
//! plane, no dialect and no instance; it knows JSON, HTTP/1.1, JSON-RPC 2.0 framing, the binary's
//! own flags and the shared rigs (`common::{boot, credentials, lines, upstream}`).
//!
//! The schema is `blackbox/1` (fields below, at [`Case::parse`] and [`Step::parse`]); an unknown
//! field, step or placeholder is refused, naming the plane crate and the case file. A case whose
//! `requires` this build lacks is not applicable to it and is counted as such; a directory whose
//! every case is not applicable, or that holds no case, fails.
//!
//! A case that cites a 1.5.5 golden cell (`oracle`) is held to the cell's recorded bytes before it
//! runs: its stated status and every body or line it states must be the cell's ([`held_to_cell`]).

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use common::upstream::{Answer, Responder};

// `DOOR_BLACKBOX`: every linked door's crate and the case directory it states.
include!(concat!(env!("OUT_DIR"), "/door_cells_files.rs"));

/// The schema every case file states.
const SCHEMA: &str = "blackbox/1";

/// The 1.5.5 golden ledger an `oracle` citation names a cell of.
const ORACLE_LEDGER: &str = include_str!("../../../testing/shadow-oracle/golden/1.5.5/ledger.tsv");

// ── the case, read ──────────────────────────────────────────────────────────────────────────────

/// One case file, read.
#[derive(Debug, Clone)]
struct Case {
    name: String,
    oracle: Option<String>,
    requires: Requires,
    files: BTreeMap<String, String>,
    vars: BTreeMap<String, String>,
    unset: Vec<String>,
    credentials: Credentials,
    upstream: Option<BTreeMap<String, Answer>>,
    steps: Vec<Step>,
}

/// What a build must link for a case to apply to it.
#[derive(Debug, Clone, Default)]
struct Requires {
    sections: Vec<String>,
    axes: Vec<String>,
    features: Vec<String>,
    /// The axes whose ABSENCE the case is about (the case's top-level `unless`): a build linking
    /// any of them does not apply to it.
    unless: Vec<String>,
}

/// The credential rigs a case asks for.
#[derive(Debug, Clone, Default)]
struct Credentials {
    /// `(module, alias, first_party)`: the signed token-verifying auth plugin, installed.
    auth_plugin: Option<(String, String, bool)>,
    issuer: bool,
    signing_key: bool,
}

/// One step.
#[derive(Debug, Clone)]
enum Step {
    Validate(Value),
    Boot(Value),
    Session(Value),
    Call(Value),
    Admin(Value),
    Mint(Value),
    UpstreamSet(Value),
    UpstreamCounts(Value),
}

/// `value`'s object, every key one of `known`.
fn object<'a>(
    value: &'a Value,
    what: &str,
    known: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let map = value
        .as_object()
        .ok_or_else(|| format!("{what}: not an object"))?;
    if let Some(unknown) = map.keys().find(|k| !known.contains(&k.as_str())) {
        return Err(format!("{what}: unknown field `{unknown}`"));
    }
    Ok(map)
}

fn strings(value: Option<&Value>, what: &str) -> Result<Vec<String>, String> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{what}: strings only"))
            })
            .collect(),
        Some(_) => Err(format!("{what}: a list is required")),
    }
}

fn string_map(value: Option<&Value>, what: &str) -> Result<BTreeMap<String, String>, String> {
    match value {
        None => Ok(BTreeMap::new()),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .map(|s| (k.clone(), s.to_string()))
                    .ok_or_else(|| format!("{what}.{k}: a string is required"))
            })
            .collect(),
        Some(_) => Err(format!("{what}: an object is required")),
    }
}

/// A scripted method's answer, read: `{"result": <json>}` or `{"echo": {"from", "into", "base"?,
/// "format"?}}`.
fn answer(value: &Value, what: &str) -> Result<Answer, String> {
    let map = object(value, what, &["result", "echo"])?;
    match (map.get("result"), map.get("echo")) {
        (Some(result), None) => Ok(Answer::Result(result.clone())),
        (None, Some(echo)) => {
            let what = format!("{what}.echo");
            let e = object(echo, &what, &["from", "into", "base", "format"])?;
            let text = |k: &str| {
                e.get(k)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("{what}.{k}: a string is required"))
            };
            let into = text("into")?;
            if !into.starts_with("/result") {
                return Err(format!("{what}.into: a pointer under `/result`"));
            }
            Ok(Answer::Echo {
                from: text("from")?,
                into,
                base: e.get("base").cloned().unwrap_or(Value::Null),
                format: e.get("format").and_then(Value::as_str).map(str::to_string),
            })
        }
        _ => Err(format!("{what}: exactly one of `result` or `echo`")),
    }
}

impl Step {
    /// One step, read: an object with exactly one key, the step's kind, whose fields are held to
    /// the kind's own list.
    fn parse(value: &Value, at: usize) -> Result<Self, String> {
        let map = value
            .as_object()
            .filter(|m| m.len() == 1)
            .ok_or_else(|| format!("steps[{at}]: one key, the step's kind"))?;
        let (kind, body) = map.iter().next().expect("one key");
        let what = format!("steps[{at}].{kind}");
        let known: &[&str] = match kind.as_str() {
            "validate" => &[
                "args",
                "exit",
                "stdout_contains",
                "stderr_contains",
                "output_contains",
                "output_lacks",
                "stdout_line_eq",
                "stderr_line_eq",
            ],
            "boot" => &[
                "args",
                "expect",
                "exit",
                "within_secs",
                "listening",
                "output_contains",
                "output_lacks",
            ],
            "session" => &[
                "flag",
                "credential_var",
                "credential",
                "expect",
                "within_secs",
                "output_contains",
                "output_lacks",
                "no_frames",
                "script",
            ],
            "call" => &[
                "port",
                "method",
                "path",
                "headers",
                "bearer",
                "body",
                "status",
                "body_contains",
                "body_lacks",
            ],
            "admin" => &["method", "path", "body", "status", "json_eq"],
            "mint" => &["path", "body", "bind_audience"],
            "upstream_set" => &["method", "result", "echo"],
            "upstream_counts" => &["since", "counts"],
            other => return Err(format!("steps[{at}]: `{other}` is no step")),
        };
        object(body, &what, known)?;
        if kind == "boot"
            && body.get("exit").is_some()
            && body.get("expect").and_then(Value::as_str) == Some("listening")
        {
            return Err(format!("{what}: `exit` is stated for `expect: exit` only"));
        }
        Ok(match kind.as_str() {
            "validate" => Step::Validate(body.clone()),
            "boot" => Step::Boot(body.clone()),
            "session" => {
                for (i, item) in body
                    .get("script")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .enumerate()
                {
                    script_item(item, &format!("{what}.script[{i}]"))?;
                }
                Step::Session(body.clone())
            }
            "call" => Step::Call(body.clone()),
            "admin" => Step::Admin(body.clone()),
            "mint" => Step::Mint(body.clone()),
            "upstream_set" => {
                let mut rest = body.clone();
                rest.as_object_mut().expect("an object").remove("method");
                answer(&rest, &what)?;
                Step::UpstreamSet(body.clone())
            }
            "upstream_counts" => Step::UpstreamCounts(body.clone()),
            _ => unreachable!("matched above"),
        })
    }

    fn kind(&self) -> &'static str {
        match self {
            Step::Validate(_) => "validate",
            Step::Boot(_) => "boot",
            Step::Session(_) => "session",
            Step::Call(_) => "call",
            Step::Admin(_) => "admin",
            Step::Mint(_) => "mint",
            Step::UpstreamSet(_) => "upstream_set",
            Step::UpstreamCounts(_) => "upstream_counts",
        }
    }
}

/// One line-session script item, checked: `send`, `recv`, `repeat` or `eof`.
fn script_item(value: &Value, what: &str) -> Result<(), String> {
    let map = value
        .as_object()
        .filter(|m| m.len() == 1)
        .ok_or_else(|| format!("{what}: one key, the item's kind"))?;
    let (kind, body) = map.iter().next().expect("one key");
    let what = format!("{what}.{kind}");
    match kind.as_str() {
        "send" => Ok(()),
        "recv" => object(body, &what, &["pointer_eq", "has", "contains", "method"]).map(|_| ()),
        "repeat" => {
            object(
                body,
                &what,
                &[
                    "max",
                    "send",
                    "elicitation",
                    "served_has",
                    "served_contains",
                    "refused_contains",
                    "min_served",
                    "elicitations_equal_served",
                ],
            )?;
            if let Some(e) = body.get("elicitation") {
                object(
                    e,
                    &format!("{what}.elicitation"),
                    &["method", "message_pointer", "message", "answer"],
                )?;
            }
            Ok(())
        }
        "eof" => object(body, &what, &["exit", "within_secs"]).map(|_| ()),
        other => Err(format!("{what}: `{other}` is no script item")),
    }
}

impl Case {
    /// A case file, read: `{"schema": "blackbox/1", "case", "oracle"?, "requires"?, "files"?,
    /// "vars"?, "unset"?, "credentials"?, "upstream"?, "steps"}`.
    fn parse(text: &str) -> Result<Self, String> {
        let doc: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let map = object(
            &doc,
            "case",
            &[
                "schema",
                "case",
                "oracle",
                "requires",
                "unless",
                "files",
                "vars",
                "unset",
                "credentials",
                "upstream",
                "steps",
                "_comment",
            ],
        )?;
        if map.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            return Err(format!("`schema` must be `{SCHEMA}`"));
        }
        let name = map
            .get("case")
            .and_then(Value::as_str)
            .filter(|n| !n.trim().is_empty())
            .ok_or("`case`: a name is required")?
            .to_string();
        let oracle = map
            .get("oracle")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(cell) = &oracle {
            if !ORACLE_LEDGER
                .lines()
                .any(|l| l.split('\t').next() == Some(cell.as_str()))
            {
                return Err(format!("`oracle`: no 1.5.5 golden cell `{cell}`"));
            }
        }
        let requires = match map.get("requires") {
            None => Requires::default(),
            Some(r) => {
                let r = object(r, "requires", &["sections", "axes", "features"])?;
                Requires {
                    sections: strings(r.get("sections"), "requires.sections")?,
                    axes: strings(r.get("axes"), "requires.axes")?,
                    features: strings(r.get("features"), "requires.features")?,
                    unless: Vec::new(),
                }
            }
        };
        let requires = Requires {
            unless: strings(map.get("unless"), "unless")?,
            ..requires
        };
        let credentials = match map.get("credentials") {
            None => Credentials::default(),
            Some(c) => {
                let c = object(c, "credentials", &["auth_plugin", "issuer", "signing_key"])?;
                let auth_plugin = match c.get("auth_plugin") {
                    None => None,
                    Some(a) => {
                        let a = object(
                            a,
                            "credentials.auth_plugin",
                            &["module", "alias", "first_party"],
                        )?;
                        let text = |k: &str| {
                            a.get(k)
                                .and_then(Value::as_str)
                                .map(str::to_string)
                                .ok_or_else(|| {
                                    format!("credentials.auth_plugin.{k}: a string is required")
                                })
                        };
                        Some((
                            text("module")?,
                            text("alias")?,
                            a.get("first_party")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        ))
                    }
                };
                Credentials {
                    auth_plugin,
                    issuer: c.get("issuer").and_then(Value::as_bool).unwrap_or(false),
                    signing_key: c
                        .get("signing_key")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                }
            }
        };
        let upstream = match map.get("upstream") {
            None => None,
            Some(u) => {
                let u = object(u, "upstream", &["methods"])?;
                let methods = u
                    .get("methods")
                    .and_then(Value::as_object)
                    .ok_or("upstream.methods: an object of method -> answer")?;
                Some(
                    methods
                        .iter()
                        .map(|(m, a)| {
                            answer(a, &format!("upstream.methods.{m}")).map(|a| (m.clone(), a))
                        })
                        .collect::<Result<BTreeMap<_, _>, _>>()?,
                )
            }
        };
        let steps = map
            .get("steps")
            .and_then(Value::as_array)
            .filter(|s| !s.is_empty())
            .ok_or("`steps`: at least one step is required")?
            .iter()
            .enumerate()
            .map(|(i, s)| Step::parse(s, i))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Case {
            name,
            oracle,
            requires,
            files: string_map(map.get("files"), "files")?,
            vars: string_map(map.get("vars"), "vars")?,
            unset: strings(map.get("unset"), "unset")?,
            credentials,
            upstream,
            steps,
        })
    }

    /// Why this build does not apply to the case, or `None` when it does.
    fn not_applicable(&self) -> Option<String> {
        let have = |list: &str, word: &str| list.split_whitespace().any(|w| w == word);
        let sections = env!("BUSBAR_LINKED_SECTIONS");
        let features = env!("BUSBAR_ENABLED_FEATURES");
        self.requires
            .sections
            .iter()
            .find(|s| !have(sections, s))
            .map(|s| format!("the build links no `{s}` section"))
            .or_else(|| {
                self.requires
                    .axes
                    .iter()
                    .find(|a| !axis_linked(a))
                    .map(|a| format!("the build carries no `{a}` axis"))
            })
            .or_else(|| {
                self.requires
                    .unless
                    .iter()
                    .find(|a| axis_linked(a))
                    .map(|a| format!("the build carries the `{a}` axis this case runs without"))
            })
            .or_else(|| {
                self.requires
                    .features
                    .iter()
                    .find(|f| !have(features, f))
                    .map(|f| format!("the build enables no `{f}` feature"))
            })
    }
}

/// Whether this build links `axis`, named as the manifest's `linked-axes` rows name it
/// (`body-ingress`); `BUSBAR_LINKED_AXES` states each as its cfg (`linked_axis_body_ingress`).
fn axis_linked(axis: &str) -> bool {
    let cfg = format!("linked_axis_{}", axis.replace('-', "_"));
    env!("BUSBAR_LINKED_AXES")
        .split_whitespace()
        .any(|w| w == cfg)
}

/// A JSON-RPC reply answers the request it was sent for: a request (a `method` with an `id`) is
/// answered under its own `id`. A notification, or a reply that is no JSON-RPC response, holds.
fn reply_id_held(request: &Value, reply: &Value) -> Result<(), String> {
    let (Some(id), Some(_)) = (request.get("id"), request.get("method")) else {
        return Ok(());
    };
    if reply.get("result").is_none() && reply.get("error").is_none() {
        return Ok(());
    }
    match reply.get("id") {
        Some(got) if got == id => Ok(()),
        got => Err(format!(
            "the reply's id is {} where its request's is {id}: {reply}",
            got.map_or_else(|| "absent".to_string(), Value::to_string)
        )),
    }
}

/// Every JSON-RPC response in an HTTP answer: the body as one message, or each `data:` line of an
/// event stream.
fn responses_in(text: &str) -> Vec<Value> {
    if let Ok(one) = serde_json::from_str::<Value>(text) {
        return vec![one];
    }
    text.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .collect()
}

// ── the cited 1.5.5 cell, held ──────────────────────────────────────────────────────────────────

/// The 1.5.5 golden cell `id` as it was recorded: `{status, body: {text}|{json}, effects: {stderr?}}`.
fn golden_cell(id: &str) -> Result<Value, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
        .join(format!("{}.json", id.replace('|', "__")));
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("the cell records no bytes ({}: {e})", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("the cell does not read ({e})"))
}

/// A step's `(key, text)` pairs: what its output must contain, must lack, or its lines.
type Pairs<'a> = Vec<(&'a str, &'a str)>;

/// A CITED CELL IS COMPARED, NOT ONLY NAMED: the case's last step that states a status (`exit`, or
/// an answered `status`, or a `session` that expects a refusal) is held to the cell — its status to
/// the cell's `status`, and every body or line it states to the cell's recorded body (`body.text`,
/// or `body.json`) and stderr (`effects.stderr`). A line stated `_line_eq` must be a whole line of
/// the record; a `_contains` must be in it; a `_lacks` must not; an admin `json_eq` pointer must
/// hold the recorded value. A citation whose step states a status and no byte is refused: there is
/// nothing of 1.5.5's to hold.
fn held_to_cell(case: &Case, cell: &Value) -> Result<(), String> {
    let recorded = cell
        .get("status")
        .and_then(Value::as_i64)
        .ok_or("the cell records no status")?;
    let body_json = cell.pointer("/body/json");
    let body = match (
        cell.pointer("/body/text").and_then(Value::as_str),
        body_json,
    ) {
        (Some(text), _) => text.to_string(),
        (None, Some(json)) => json.to_string(),
        (None, None) => String::new(),
    };
    let stderr = cell
        .pointer("/effects/stderr")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let both = format!("{body}{stderr}");
    let stated = case.steps.iter().rev().find_map(|step| match step {
        Step::Validate(s) if s.get("exit").is_some() => Some((step.kind(), s, "exit")),
        Step::Boot(s) if s.get("exit").is_some() => Some((step.kind(), s, "exit")),
        Step::Call(s) | Step::Admin(s) if s.get("status").is_some() => {
            Some((step.kind(), s, "status"))
        }
        Step::Session(s) if s.get("expect").and_then(Value::as_str) == Some("refused") => {
            Some((step.kind(), s, "refused"))
        }
        _ => None,
    });
    let (kind, s, how) = stated.ok_or("no step states the status the cell records")?;
    let status_ok = match (how, s.get(how)) {
        ("refused", _) => recorded != 0,
        (_, Some(Value::String(word))) if word == "nonzero" => recorded != 0,
        (_, Some(v)) => v.as_i64() == Some(recorded),
        _ => false,
    };
    if !status_ok {
        let stated = s
            .get(how)
            .map_or_else(|| "a refusal".to_string(), Value::to_string);
        return Err(format!(
            "the `{kind}` step states status {stated}; the cell records {recorded}"
        ));
    }
    let (contains, lacks, lines): (Pairs<'_>, Pairs<'_>, Pairs<'_>) = match kind {
        "validate" => (
            vec![
                ("stdout_contains", body.as_str()),
                ("stderr_contains", stderr.as_str()),
                ("output_contains", both.as_str()),
            ],
            vec![("output_lacks", both.as_str())],
            vec![
                ("stdout_line_eq", body.as_str()),
                ("stderr_line_eq", stderr.as_str()),
            ],
        ),
        "boot" => (
            vec![("output_contains", both.as_str())],
            vec![("output_lacks", both.as_str())],
            vec![],
        ),
        "session" => (
            vec![("output_contains", stderr.as_str())],
            vec![("output_lacks", stderr.as_str())],
            vec![],
        ),
        "call" => (
            vec![("body_contains", body.as_str())],
            vec![("body_lacks", body.as_str())],
            vec![],
        ),
        _ => (vec![], vec![], vec![]),
    };
    let mut held = 0usize;
    for (key, record) in contains {
        for want in texts(s, key) {
            held += 1;
            if !record.contains(want.as_str()) {
                return Err(format!(
                    "the `{kind}` step's `{key}` `{want}` is not in the cell's record:\n{record}"
                ));
            }
        }
    }
    for (key, record) in lacks {
        for unwanted in texts(s, key) {
            held += 1;
            if record.contains(unwanted.as_str()) {
                return Err(format!(
                    "the `{kind}` step's `{key}` `{unwanted}` is in the cell's record:\n{record}"
                ));
            }
        }
    }
    for (key, record) in lines {
        for want in texts(s, key) {
            held += 1;
            if !record.lines().any(|l| l == want) {
                return Err(format!(
                    "the `{kind}` step's `{key}` `{want}` is no line of the cell's record:\n{record}"
                ));
            }
        }
    }
    if kind == "admin" {
        for (pointer, want) in s
            .get("json_eq")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            held += 1;
            if body_json.and_then(|j| j.pointer(pointer)) != Some(want) {
                return Err(format!(
                    "the `{kind}` step's `json_eq` `{pointer}` = {want} is not the cell's: {body}"
                ));
            }
        }
    }
    if held == 0 {
        return Err(format!(
            "the `{kind}` step states a status and no body or line to hold to the cell"
        ));
    }
    Ok(())
}

/// The case's cited cell compared, its failure naming the plane crate, the case and the cell.
fn oracle_held(krate: &str, case: &Case) -> Result<(), String> {
    let Some(id) = &case.oracle else {
        return Ok(());
    };
    golden_cell(id)
        .and_then(|cell| held_to_cell(case, &cell))
        .map_err(|e| {
            format!(
                "`{krate}` case `{}`: its stated bytes are not the 1.5.5 cell `{id}`'s: {e}",
                case.name
            )
        })
}

// ── the run ─────────────────────────────────────────────────────────────────────────────────────

/// One case's world: its directory, its ports, its far ends, its keys, its running node.
struct World {
    dir: PathBuf,
    data_port: u16,
    admin_port: u16,
    admin_token: String,
    signing: Option<([u8; 32], String)>,
    minted: Option<String>,
    responder: Option<Responder>,
    counts_mark: BTreeMap<String, usize>,
    counts_start: BTreeMap<String, usize>,
    node: Option<Child>,
    vars: BTreeMap<String, String>,
    unset: Vec<String>,
    issuer: bool,
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(mut child) = self.node.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A fresh, isolated directory for one case.
fn case_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let safe: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let d = std::env::temp_dir().join(format!(
        "busbar-blackbox-{}-{safe}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("plugins")).expect("the case dir");
    d
}

impl World {
    /// Every placeholder in `text` filled; an unknown placeholder is refused.
    fn fill(&self, text: &str) -> Result<String, String> {
        let mut out = String::new();
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else {
                out.push_str(&rest[open..]);
                return Ok(out);
            };
            let key = &after[..close];
            let filled = match key {
                "dir" => Some(self.dir.display().to_string()),
                "plugins_dir" => Some(self.dir.join("plugins").display().to_string()),
                "data_port" => Some(self.data_port.to_string()),
                "admin_port" => Some(self.admin_port.to_string()),
                "admin_token" => Some(self.admin_token.clone()),
                "upstream_url" => self
                    .responder
                    .as_ref()
                    .map(|r| format!("http://127.0.0.1:{}", r.port)),
                "signing_key_file" => self
                    .signing
                    .as_ref()
                    .map(|_| self.dir.join("signing.key").display().to_string()),
                "signing_key_hex" => self.signing.as_ref().map(|(_, h)| h.clone()),
                "minted" => self.minted.clone(),
                _ => {
                    if let Some(aud) = key.strip_prefix("token:") {
                        self.issuer
                            .then(|| common::credentials::token_for("e2e", &["tester"], aud))
                    } else if let Some(rest) = key.strip_prefix("issuer_settings:") {
                        let (indent, aud) = rest.split_once(':').unwrap_or((rest, ""));
                        let indent: usize = indent
                            .parse()
                            .map_err(|_| format!("`{{{key}}}`: an indent is required"))?;
                        self.issuer
                            .then(|| common::credentials::issuer_settings_yaml(aud, indent))
                    } else if key.is_empty()
                        || key.contains(|c: char| c.is_whitespace() || c == '"' || c == ':')
                    {
                        // Not a placeholder (a YAML flow map's brace): kept as written.
                        out.push('{');
                        rest = after;
                        continue;
                    } else {
                        return Err(format!("`{{{key}}}` is no placeholder"));
                    }
                }
            };
            let filled = filled.ok_or_else(|| {
                format!("`{{{key}}}` has no value in this case (its rig is not asked for)")
            })?;
            out.push_str(&filled);
            rest = &after[close + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// Every string inside `value` filled.
    fn fill_json(&self, value: &Value) -> Result<Value, String> {
        Ok(match value {
            Value::String(s) => Value::String(self.fill(s)?),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| self.fill_json(v))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| Ok((k.clone(), self.fill_json(v)?)))
                    .collect::<Result<_, String>>()?,
            ),
            other => other.clone(),
        })
    }

    /// The binary, its config and providers in this case's directory, the case's environment set.
    fn command(&self, args: &[String]) -> Result<Command, String> {
        let mut cmd = Command::new(common::boot::exe());
        cmd.args(args)
            .env("BUSBAR_CONFIG", self.dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", self.dir.join("providers.yaml"))
            .env(
                common::credentials::HARNESS_FIRST_PARTY_KEY_ENV,
                common::credentials::harness_release_key_hex(),
            );
        for name in &self.unset {
            cmd.env_remove(name);
        }
        for (k, v) in &self.vars {
            cmd.env(k, self.fill(v)?);
        }
        Ok(cmd)
    }
}

fn texts(step: &Value, key: &str) -> Vec<String> {
    step.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn secs(step: &Value, default: u64) -> Duration {
    Duration::from_secs(
        step.get("within_secs")
            .and_then(Value::as_u64)
            .unwrap_or(default),
    )
}

/// `text` holds every `contains` and none of `lacks`.
fn hold(text: &str, contains: &[String], lacks: &[String], what: &str) -> Result<(), String> {
    if let Some(missing) = contains.iter().find(|c| !text.contains(c.as_str())) {
        return Err(format!("{what} lacks `{missing}`:\n{text}"));
    }
    if let Some(found) = lacks.iter().find(|l| text.contains(l.as_str())) {
        return Err(format!(
            "{what} carries `{found}`, which it must not:\n{text}"
        ));
    }
    Ok(())
}

/// `code` is the step's `exit`: a number, or `"nonzero"`.
fn exit_is(step: &Value, code: i32) -> Result<(), String> {
    match step.get("exit") {
        None => Ok(()),
        Some(Value::String(s)) if s == "nonzero" => (code != 0)
            .then_some(())
            .ok_or_else(|| "exited 0, a nonzero exit was expected".to_string()),
        Some(v) => {
            let want = v.as_i64().ok_or("`exit`: a number or \"nonzero\"")?;
            (i64::from(code) == want)
                .then_some(())
                .ok_or_else(|| format!("exited {code}, {want} was expected"))
        }
    }
}

/// Whether `port` on loopback accepts a connection.
fn up(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// One HTTP call: `(status, body)`.
fn http(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    bearer: Option<&str>,
    body: Option<&Value>,
) -> Result<(u16, String), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("a runtime: {e}"))?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("a client: {e}"))?;
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| format!("`{method}` is no method"))?;
        let mut req = client.request(method, url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        match body {
            Some(Value::String(s)) => req = req.body(s.clone()),
            Some(v) => {
                req = req
                    .header("content-type", "application/json")
                    .body(v.to_string());
            }
            None => {}
        }
        let resp = req.send().await.map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        Ok((status, text))
    })
}

/// The value at `pointer` of `doc` equals `want`.
fn pointer_eq(doc: &Value, checks: Option<&Value>, what: &str) -> Result<(), String> {
    for (pointer, want) in checks.and_then(Value::as_object).into_iter().flatten() {
        if doc.pointer(pointer) != Some(want) {
            return Err(format!("{what}: `{pointer}` is not {want}: {doc}"));
        }
    }
    Ok(())
}

/// A line session's script, run against `child`.
fn run_script(
    world: &World,
    child: &mut common::lines::LineChild,
    script: &[Value],
) -> Result<(), String> {
    let bound = Duration::from_secs(120);
    for (i, item) in script.iter().enumerate() {
        let (kind, body) = item
            .as_object()
            .and_then(|m| m.iter().next())
            .expect("checked when the case was read");
        let what = format!("script[{i}].{kind}");
        match kind.as_str() {
            "send" => child.send(&world.fill_json(body)?),
            "recv" => {
                let line = child.try_recv(bound).map_err(|e| format!("{what}: {e}"))?;
                if let Some(m) = body.get("method").and_then(Value::as_str) {
                    if line.get("method").and_then(Value::as_str) != Some(m) {
                        return Err(format!("{what}: not a `{m}` message: {line}"));
                    }
                }
                pointer_eq(&line, body.get("pointer_eq"), &what)?;
                for p in texts(body, "has") {
                    if line.pointer(&p).is_none() {
                        return Err(format!("{what}: no `{p}`: {line}"));
                    }
                }
                hold(&line.to_string(), &texts(body, "contains"), &[], &what)?;
            }
            "repeat" => {
                let max = body.get("max").and_then(Value::as_u64).unwrap_or(1);
                let served_has = body
                    .get("served_has")
                    .and_then(Value::as_str)
                    .unwrap_or("/result");
                let elicit = body.get("elicitation");
                let (mut served, mut elicitations, mut refused) = (0u64, 0u64, None);
                for n in 0..max {
                    // `{i}` (the round, from 0) first, then the case's placeholders.
                    let raw = body.get("send").unwrap_or(&Value::Null).to_string();
                    let send: Value = serde_json::from_str(&raw.replace("{i}", &n.to_string()))
                        .map_err(|e| format!("{what}: {e}"))?;
                    let send = world.fill_json(&send)?;
                    child.send(&send);
                    let mut line = child.try_recv(bound).map_err(|e| format!("{what}: {e}"))?;
                    if let Some(e) = elicit {
                        let method = e.get("method").and_then(Value::as_str).unwrap_or("");
                        if line.get("method").and_then(Value::as_str) == Some(method) {
                            elicitations += 1;
                            if let (Some(p), Some(m)) = (
                                e.get("message_pointer").and_then(Value::as_str),
                                e.get("message").and_then(Value::as_str),
                            ) {
                                if line.pointer(p).and_then(Value::as_str) != Some(m) {
                                    return Err(format!(
                                        "{what}: the request's text is not `{m}`: {line}"
                                    ));
                                }
                            }
                            child.send(&json!({
                                "jsonrpc": "2.0", "id": line["id"],
                                "result": e.get("answer").cloned().unwrap_or(Value::Null),
                            }));
                            line = child.try_recv(bound).map_err(|e| format!("{what}: {e}"))?;
                        }
                    }
                    reply_id_held(&send, &line).map_err(|e| format!("{what} round {n}: {e}"))?;
                    if line.pointer(served_has).is_some() {
                        served += 1;
                        hold(
                            &line.to_string(),
                            &texts(body, "served_contains"),
                            &[],
                            &what,
                        )?;
                    } else {
                        refused = Some(line);
                        break;
                    }
                }
                let min = body.get("min_served").and_then(Value::as_u64).unwrap_or(0);
                if served < min {
                    return Err(format!("{what}: {served} served, at least {min} expected; first refusal: {refused:?}"));
                }
                if body
                    .get("elicitations_equal_served")
                    .and_then(Value::as_bool)
                    == Some(true)
                    && elicitations != served
                {
                    return Err(format!(
                        "{what}: {served} served but {elicitations} asked first"
                    ));
                }
                let refused_contains = texts(body, "refused_contains");
                if !refused_contains.is_empty() {
                    let refusal = refused.ok_or_else(|| format!("{what}: nothing was refused"))?;
                    hold(&refusal.to_string(), &refused_contains, &[], &what)?;
                }
            }
            "eof" => {
                drop(child.stdin.take());
                let code = common::lines::try_wait_bounded(&mut child.child, secs(body, 60))
                    .map_err(|e| format!("{what}: {e}"))?;
                exit_is(body, code).map_err(|e| format!("{what}: {e}"))?;
            }
            _ => unreachable!("checked when the case was read"),
        }
    }
    Ok(())
}

/// Run one step.
fn run_step(world: &mut World, step: &Step) -> Result<(), String> {
    match step {
        Step::Validate(s) => {
            let args = {
                let a = texts(s, "args");
                if a.is_empty() {
                    vec!["--validate".to_string()]
                } else {
                    a.iter().map(|x| world.fill(x)).collect::<Result<_, _>>()?
                }
            };
            let out = world
                .command(&args)?
                .output()
                .map_err(|e| format!("run the binary: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let both = format!("{stdout}{stderr}");
            exit_is(s, out.status.code().unwrap_or(-1)).map_err(|e| format!("{e}:\n{both}"))?;
            hold(&stdout, &texts(s, "stdout_contains"), &[], "stdout")?;
            hold(&stderr, &texts(s, "stderr_contains"), &[], "stderr")?;
            hold(
                &both,
                &texts(s, "output_contains"),
                &texts(s, "output_lacks"),
                "the output",
            )?;
            for (key, text) in [("stdout_line_eq", &stdout), ("stderr_line_eq", &stderr)] {
                for want in texts(s, key) {
                    if !text.lines().any(|l| l == want) {
                        return Err(format!("no line is `{want}` byte for byte:\n{text}"));
                    }
                }
            }
            Ok(())
        }
        Step::Boot(s) => {
            let args: Vec<String> = texts(s, "args")
                .iter()
                .map(|x| world.fill(x))
                .collect::<Result<_, _>>()?;
            let log = world.dir.join("busbar.log");
            let file = std::fs::File::create(&log).map_err(|e| format!("the log: {e}"))?;
            let mut cmd = world.command(&args)?;
            cmd.stdout(Stdio::from(file.try_clone().map_err(|e| e.to_string())?))
                .stderr(Stdio::from(file));
            let mut child = cmd.spawn().map_err(|e| format!("spawn the binary: {e}"))?;
            // A boot that states its `exit` expects one.
            let default = if s.get("exit").is_some() {
                "exit"
            } else {
                "listening"
            };
            match s.get("expect").and_then(Value::as_str).unwrap_or(default) {
                "exit" => {
                    let code = common::lines::try_wait_bounded(&mut child, secs(s, 120))?;
                    let text = read_file(&log);
                    exit_is(s, code).map_err(|e| format!("{e}:\n{text}"))?;
                    hold(
                        &text,
                        &texts(s, "output_contains"),
                        &texts(s, "output_lacks"),
                        "the output",
                    )
                }
                "listening" => {
                    let wanted = texts(s, "listening");
                    let ports: Vec<u16> = if wanted.is_empty() {
                        vec![world.data_port]
                    } else {
                        wanted
                            .iter()
                            .map(|p| match p.as_str() {
                                "data" => Ok(world.data_port),
                                "admin" => Ok(world.admin_port),
                                other => Err(format!("`{other}` is no listener")),
                            })
                            .collect::<Result<_, _>>()?
                    };
                    let deadline = Instant::now() + secs(s, 120);
                    loop {
                        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                            return Err(format!(
                                "exited ({status}) instead of listening:\n{}",
                                read_file(&log)
                            ));
                        }
                        if ports.iter().all(|p| up(*p)) {
                            break;
                        }
                        if Instant::now() >= deadline {
                            let _ = child.kill();
                            return Err(format!(
                                "did not listen on {ports:?}:\n{}",
                                read_file(&log)
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    hold(
                        &read_file(&log),
                        &texts(s, "output_contains"),
                        &texts(s, "output_lacks"),
                        "the output",
                    )?;
                    if let Some(mut old) = world.node.replace(child) {
                        let _ = old.kill();
                        let _ = old.wait();
                    }
                    Ok(())
                }
                other => Err(format!(
                    "`expect`: `{other}` is neither `exit` nor `listening`"
                )),
            }
        }
        Step::Session(s) => {
            let flag = s
                .get("flag")
                .and_then(Value::as_str)
                .ok_or("`flag`: the serve flag is required")?;
            let mut cmd = world.command(&[world.fill(flag)?])?;
            if let Some(var) = s.get("credential_var").and_then(Value::as_str) {
                cmd.env_remove(var);
                if let Some(c) = s.get("credential").and_then(Value::as_str) {
                    cmd.env(var, world.fill(c)?);
                }
            }
            let mut child = common::lines::spawn(cmd);
            let script: Vec<Value> = s
                .get("script")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            match s.get("expect").and_then(Value::as_str).unwrap_or("served") {
                "refused" => {
                    let code = common::lines::try_wait_bounded(&mut child.child, secs(s, 120))?;
                    let stderr = child.stderr_so_far();
                    if code == 0 {
                        return Err(format!("exited 0, a refusal was expected:\n{stderr}"));
                    }
                    hold(
                        &stderr,
                        &texts(s, "output_contains"),
                        &texts(s, "output_lacks"),
                        "stderr",
                    )?;
                }
                "served" => {
                    run_script(world, &mut child, &script)?;
                    let stderr = child.stderr_so_far();
                    hold(
                        &stderr,
                        &texts(s, "output_contains"),
                        &texts(s, "output_lacks"),
                        "stderr",
                    )?;
                    let _ = child.child.kill();
                    let _ = child.child.wait();
                }
                other => {
                    return Err(format!(
                        "`expect`: `{other}` is neither `refused` nor `served`"
                    ))
                }
            }
            if s.get("no_frames").and_then(Value::as_bool) == Some(true)
                && child.stdout.try_recv().is_ok()
            {
                return Err("a frame was served before the refusal".to_string());
            }
            Ok(())
        }
        Step::Call(s) => {
            let port = match s.get("port").and_then(Value::as_str).unwrap_or("data") {
                "data" => world.data_port,
                "admin" => world.admin_port,
                other => return Err(format!("`{other}` is no listener")),
            };
            let path = world.fill(s.get("path").and_then(Value::as_str).unwrap_or("/"))?;
            let headers: Vec<(String, String)> = s
                .get("headers")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .map(|h| -> Result<(String, String), String> {
                    match h.as_array().map(Vec::as_slice) {
                        Some([Value::String(k), Value::String(v)]) => {
                            Ok((k.clone(), world.fill(v)?))
                        }
                        _ => Err("`headers`: `[name, value]` pairs".to_string()),
                    }
                })
                .collect::<Result<_, _>>()?;
            let bearer = match s.get("bearer").and_then(Value::as_str) {
                Some(b) => Some(world.fill(b)?),
                None => None,
            };
            let body = match s.get("body") {
                Some(b) => Some(world.fill_json(b)?),
                None => None,
            };
            let (status, text) = http(
                s.get("method").and_then(Value::as_str).unwrap_or("POST"),
                &format!("http://127.0.0.1:{port}{path}"),
                &headers,
                bearer.as_deref(),
                body.as_ref(),
            )?;
            if let Some(want) = s.get("status").and_then(Value::as_u64) {
                if u64::from(status) != want {
                    return Err(format!("answered {status}, {want} was expected: {text}"));
                }
            }
            // Every reply answers its own request (on for every call, no opt-out).
            if let Some(request) = &body {
                for reply in responses_in(&text) {
                    reply_id_held(request, &reply)?;
                }
            }
            hold(
                &text,
                &texts(s, "body_contains"),
                &texts(s, "body_lacks"),
                "the body",
            )
        }
        Step::Admin(s) => {
            let path = world.fill(s.get("path").and_then(Value::as_str).unwrap_or("/"))?;
            let body = match s.get("body") {
                Some(b) => Some(world.fill_json(b)?),
                None => None,
            };
            let (status, text) = http(
                s.get("method").and_then(Value::as_str).unwrap_or("POST"),
                &format!("http://127.0.0.1:{}{path}", world.admin_port),
                &[],
                Some(world.admin_token.as_str()),
                body.as_ref(),
            )?;
            if let Some(want) = s.get("status").and_then(Value::as_u64) {
                if u64::from(status) != want {
                    return Err(format!("answered {status}, {want} was expected: {text}"));
                }
            }
            let doc: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
            pointer_eq(&doc, s.get("json_eq"), "the admin answer")
        }
        Step::Mint(s) => {
            let path = world.fill(
                s.get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("/api/v1/admin/keys"),
            )?;
            let body = world.fill_json(s.get("body").unwrap_or(&json!({})))?;
            let (status, text) = http(
                "POST",
                &format!("http://127.0.0.1:{}{path}", world.admin_port),
                &[],
                Some(world.admin_token.as_str()),
                Some(&body),
            )?;
            let doc: Value = serde_json::from_str(&text)
                .map_err(|_| format!("the mint answered {status}, not JSON: {text}"))?;
            let plain = doc["token"]
                .as_str()
                .ok_or_else(|| format!("the mint answered no token: {doc}"))?
                .to_string();
            world.minted = Some(match s.get("bind_audience").and_then(Value::as_str) {
                Some(aud) => {
                    let (secret, _) = world
                        .signing
                        .as_ref()
                        .ok_or("`bind_audience` needs `credentials.signing_key`")?;
                    common::credentials::bind_key(secret, &plain, &world.fill(aud)?)
                }
                None => plain,
            });
            Ok(())
        }
        Step::UpstreamSet(s) => {
            let responder = world
                .responder
                .as_ref()
                .ok_or("no `upstream` in this case")?;
            let method = s
                .get("method")
                .and_then(Value::as_str)
                .ok_or("`method`: required")?;
            let mut rest = s.clone();
            rest.as_object_mut().expect("an object").remove("method");
            responder.set(method, answer(&world.fill_json(&rest)?, "upstream_set")?);
            Ok(())
        }
        Step::UpstreamCounts(s) => {
            let responder = world
                .responder
                .as_ref()
                .ok_or("no `upstream` in this case")?;
            let now = responder.received();
            let base = match s.get("since").and_then(Value::as_str).unwrap_or("last") {
                "last" => world.counts_mark.clone(),
                "start" => world.counts_start.clone(),
                other => return Err(format!("`since`: `{other}` is neither `last` nor `start`")),
            };
            for (method, rule) in s
                .get("counts")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let (was, is) = (
                    base.get(method).copied().unwrap_or(0),
                    now.get(method).copied().unwrap_or(0),
                );
                let rule = rule.as_str().ok_or("a count is `+N`, `=N` or `>0`")?;
                let ok = if let Some(n) = rule.strip_prefix('+') {
                    is == was + n.parse::<usize>().map_err(|_| format!("`{rule}`"))?
                } else if let Some(n) = rule.strip_prefix('=') {
                    is == n.parse::<usize>().map_err(|_| format!("`{rule}`"))?
                } else if rule == ">0" {
                    is > was
                } else {
                    return Err(format!("`{rule}` is no count"));
                };
                if !ok {
                    return Err(format!(
                        "`{method}` was received {is} time(s), {was} before: `{rule}` fails"
                    ));
                }
            }
            world.counts_mark = now;
            Ok(())
        }
    }
}

/// Run one case: `Ok(None)` ran clean, `Ok(Some(why))` the build does not apply to it, `Err` a
/// mismatch naming the plane crate, the case and the step.
fn run_case(krate: &str, case: &Case) -> Result<Option<String>, String> {
    // The citation is data against data: held whether or not this build applies to the case.
    oracle_held(krate, case)?;
    if let Some(why) = case.not_applicable() {
        return Ok(Some(why));
    }
    let cited = case
        .oracle
        .as_ref()
        .map(|id| format!(" (1.5.5 cell `{id}`)"))
        .unwrap_or_default();
    let named = |e: String| format!("`{krate}` case `{}`{cited}: {e}", case.name);
    let mut world = World {
        dir: case_dir(&case.name),
        data_port: common::boot::free_port(),
        admin_port: common::boot::free_port(),
        admin_token: format!("blackbox-admin-{}", std::process::id()),
        signing: None,
        minted: None,
        responder: case.upstream.clone().map(Responder::start),
        counts_mark: BTreeMap::new(),
        counts_start: BTreeMap::new(),
        node: None,
        vars: case.vars.clone(),
        unset: case.unset.clone(),
        issuer: case.credentials.issuer,
    };
    if case.credentials.issuer {
        let _ = common::credentials::issuer();
    }
    if case.credentials.signing_key {
        let (bytes, hex_key) = common::credentials::generate_signing_key();
        std::fs::write(world.dir.join("signing.key"), &hex_key)
            .map_err(|e| named(e.to_string()))?;
        world.signing = Some((bytes, hex_key));
    }
    if let Some((module, alias, first_party)) = &case.credentials.auth_plugin {
        common::credentials::install_auth_plugin(
            &world.dir.join("plugins"),
            module,
            alias,
            *first_party,
        );
    }
    for (name, text) in &case.files {
        let filled = world.fill(text).map_err(named)?;
        std::fs::write(world.dir.join(name), filled).map_err(|e| named(format!("{name}: {e}")))?;
    }
    for (at, step) in case.steps.iter().enumerate() {
        run_step(&mut world, step)
            .map_err(|e| named(format!("step {at} ({}): {e}", step.kind())))?;
    }
    Ok(None)
}

/// Every case in `dir`, read; a directory holding none is refused, and so is a case that does not
/// read — each naming the plane crate and the case file.
fn cases_in(krate: &str, dir: &Path) -> Result<Vec<(String, Case)>, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("`{krate}` states black-box cases at {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "`{krate}` states a black-box directory ({}) that holds no case",
            dir.display()
        ));
    }
    let mut out = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for file in files {
        let shown = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let case = Case::parse(&read_file(&file))
            .map_err(|e| format!("`{krate}` case file `{shown}` is refused: {e}"))?;
        if !names.insert(case.name.clone()) {
            return Err(format!("`{krate}` case `{}` is stated twice", case.name));
        }
        out.push((shown, case));
    }
    Ok(out)
}

/// Run every case of `krate`'s directory: every failure, each naming the plane crate and the case.
fn run_dir(krate: &str, dir: &Path) -> Vec<String> {
    let cases = match cases_in(krate, dir) {
        Ok(cases) => cases,
        Err(e) => return vec![e],
    };
    let mut failures = Vec::new();
    let mut applied = 0usize;
    for (_, case) in &cases {
        match run_case(krate, case) {
            Ok(None) => applied += 1,
            Ok(Some(why)) => eprintln!(
                "`{krate}` case `{}`: not applicable here ({why})",
                case.name
            ),
            Err(e) => {
                applied += 1;
                failures.push(e);
            }
        }
    }
    if applied == 0 {
        failures.push(format!(
            "`{krate}`: every one of its {} black-box case(s) is not applicable to this build",
            cases.len()
        ));
    }
    failures
}

/// EVERY LINKED DOOR'S BLACK-BOX CASES, RUN AGAINST THE REAL BINARY.
#[test]
fn every_linked_doors_black_box_cases_run_against_the_real_binary() {
    let failures: Vec<String> = DOOR_BLACKBOX
        .iter()
        .flat_map(|(krate, dir)| run_dir(krate, Path::new(dir)))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

// ── the runner's own REDs ───────────────────────────────────────────────────────────────────────

/// A scratch directory holding `files`.
fn planted(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = case_dir(tag);
    for (name, text) in files {
        std::fs::write(dir.join(name), text).expect("plant a case file");
    }
    dir
}

/// A DOOR WITH A BLACK-BOX DIRECTORY BUT NO CASES FAILS, naming the plane crate.
#[test]
fn a_door_stating_a_black_box_directory_with_no_cases_fails() {
    let dir = planted("no-cases", &[("notes.txt", "not a case")]);
    let failures = run_dir("planted-plane", &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].contains("`planted-plane`") && failures[0].contains("holds no case"),
        "{failures:?}"
    );
}

/// A MALFORMED CASE IS REFUSED, naming the plane crate and the case file: an unknown field, an
/// unknown step, a missing name, a wrong schema.
#[test]
fn a_malformed_case_is_refused_naming_the_plane_and_the_case() {
    for (file, text, why) in [
        (
            "unknown-field.json",
            r#"{"schema": "blackbox/1", "case": "a", "stepz": []}"#,
            "unknown field `stepz`",
        ),
        (
            "unknown-step.json",
            r#"{"schema": "blackbox/1", "case": "b", "steps": [{"teleport": {}}]}"#,
            "`teleport` is no step",
        ),
        (
            "no-name.json",
            r#"{"schema": "blackbox/1", "steps": [{"validate": {}}]}"#,
            "`case`: a name is required",
        ),
        (
            "wrong-schema.json",
            r#"{"schema": "blackbox/0", "case": "c", "steps": [{"validate": {}}]}"#,
            "`schema` must be `blackbox/1`",
        ),
        (
            "bad-step-field.json",
            r#"{"schema": "blackbox/1", "case": "d", "steps": [{"validate": {"exitt": 0}}]}"#,
            "unknown field `exitt`",
        ),
    ] {
        let dir = planted("malformed", &[(file, text)]);
        let refusal = cases_in("planted-plane", &dir).expect_err("a malformed case is refused");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            refusal.contains("`planted-plane`") && refusal.contains(file) && refusal.contains(why),
            "{file}: {refusal}"
        );
    }
}

/// A CITED CELL IS COMPARED: a case citing a 1.5.5 cell whose stated bytes are not the cell's
/// fails, naming the plane crate, the case and the cell — a wrong line, a wrong status, and a
/// citation that states no byte at all; the same citation stating the cell's own bytes holds (the
/// control).
#[test]
fn a_cited_cell_whose_bytes_differ_fails_naming_the_plane_the_case_and_the_cell() {
    let case = |name: &str, step: &str| {
        Case::parse(&format!(
            r#"{{"schema": "blackbox/1", "case": "{name}", "oracle": "cli|--version",
                "steps": [{{"validate": {step}}}]}}"#
        ))
        .expect("the planted case reads")
    };
    oracle_held(
        "planted-plane",
        &case(
            "the-cells-own-bytes",
            r#"{"args": ["--version"], "exit": 0, "stdout_contains": ["busbar "]}"#,
        ),
    )
    .expect("the cell's own bytes hold");
    for (name, step, why) in [
        (
            "a-wrong-line",
            r#"{"args": ["--version"], "exit": 0, "stdout_line_eq": ["busbar 0.0.0"]}"#,
            "is no line of the cell's record",
        ),
        (
            "a-wrong-status",
            r#"{"args": ["--version"], "exit": 2, "stdout_contains": ["busbar "]}"#,
            "the cell records 0",
        ),
        (
            "no-byte-stated",
            r#"{"args": ["--version"], "exit": 0}"#,
            "no body or line to hold to the cell",
        ),
    ] {
        let failure = run_case("planted-plane", &case(name, step))
            .expect_err("a citation whose bytes differ fails");
        assert!(
            failure.contains("`planted-plane`")
                && failure.contains(&format!("case `{name}`"))
                && failure.contains("cell `cli|--version`")
                && failure.contains(why),
            "{name}: {failure}"
        );
    }
}

/// A MISMATCH FAILS, naming the plane crate, the case and the step: the binary's `--version`
/// exits 0, and a case that expects it to exit nonzero is refused; the same case expecting 0 runs
/// clean (the control).
#[test]
fn a_mismatch_fails_naming_the_plane_and_the_case() {
    let case = |name: &str, exit: &str| {
        Case::parse(&format!(
            r#"{{"schema": "blackbox/1", "case": "version-{name}",
                "steps": [{{"validate": {{"args": ["--version"], "exit": {exit}}}}}]}}"#
        ))
        .expect("the planted case reads")
    };
    assert_eq!(
        run_case("planted-plane", &case("zero", "0")),
        Ok(None),
        "the control runs clean"
    );
    let failure =
        run_case("planted-plane", &case("nonzero", "\"nonzero\"")).expect_err("a mismatch fails");
    assert!(
        failure.contains("`planted-plane`")
            && failure.contains("case `version-nonzero`")
            && failure.contains("step 0 (validate)"),
        "{failure}"
    );
}

/// THE SCRIPTED FAR END knows JSON-RPC framing and nothing else: a method the case states answers
/// its stated result or echoes into its stated shape, a method it does not state is an error, every
/// method received is counted, and an answer replaced between steps is the one served next.
#[test]
fn the_scripted_far_end_answers_what_the_case_states_and_counts_it() {
    let case = Case::parse(
        r#"{"schema": "blackbox/1", "case": "far-end",
            "upstream": {"methods": {
              "m/one": {"result": {"k": 1}},
              "m/two": {"echo": {"from": "/params/x", "into": "/result/out/0", "base": {"out": [null]},
                                 "format": "got: {}"}}}},
            "steps": [{"upstream_counts": {"counts": {"m/one": "=0"}}}]}"#,
    )
    .expect("reads");
    let responder = Responder::start(case.upstream.clone().expect("an upstream"));
    let call = |method: &str| {
        http(
            "POST",
            &format!("http://127.0.0.1:{}/rpc", responder.port),
            &[],
            None,
            Some(&json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": {"x": "y"}})),
        )
        .expect("the far end answers")
    };
    let one: Value = serde_json::from_str(&call("m/one").1).expect("JSON");
    assert_eq!(one, json!({"jsonrpc": "2.0", "id": 7, "result": {"k": 1}}));
    let two: Value = serde_json::from_str(&call("m/two").1).expect("JSON");
    assert_eq!(two["result"], json!({"out": ["got: y"]}));
    let three: Value = serde_json::from_str(&call("m/three").1).expect("JSON");
    assert_eq!(three["error"]["code"], -32601);
    responder.set("m/one", Answer::Result(json!({"k": 2})));
    let again: Value = serde_json::from_str(&call("m/one").1).expect("JSON");
    assert_eq!(again["result"], json!({"k": 2}));
    let counts = responder.received();
    assert_eq!(counts.get("m/one"), Some(&2));
    assert_eq!(counts.get("m/two"), Some(&1));
    assert_eq!(counts.get("m/three"), Some(&1));
}

/// A BOOT STEP STATES ITS EXIT: a boot that exits is held to the `exit` it states — a config that
/// does not read exits nonzero and holds `"nonzero"` (the control), and fails a stated `0`, naming
/// the plane crate, the case and the step; `exit` beside `expect: listening` is refused.
#[test]
fn a_boot_step_is_held_to_the_exit_it_states() {
    let case = |name: &str, exit: &str| {
        Case::parse(&format!(
            r#"{{"schema": "blackbox/1", "case": "{name}",
                "files": {{"config.yaml": "listen: [unclosed\n", "providers.yaml": "{{}}\n"}},
                "steps": [{{"boot": {{"expect": "exit", "exit": {exit}, "within_secs": 120}}}}]}}"#
        ))
        .expect("the planted case reads")
    };
    assert_eq!(
        run_case("planted-plane", &case("boot-exit-nonzero", "\"nonzero\"")),
        Ok(None),
        "the control holds"
    );
    let failure =
        run_case("planted-plane", &case("boot-exit-zero", "0")).expect_err("a wrong exit fails");
    assert!(
        failure.contains("`planted-plane`")
            && failure.contains("case `boot-exit-zero`")
            && failure.contains("step 0 (boot)")
            && failure.contains("0 was expected"),
        "{failure}"
    );
    let refusal = Step::parse(&json!({"boot": {"expect": "listening", "exit": 0}}), 0)
        .expect_err("`exit` beside `expect: listening` is refused");
    assert!(refusal.contains("`exit`"), "{refusal}");
}

/// `unless` NAMES AN AXIS WHOSE ABSENCE THE CASE IS ABOUT: a build linking it does not apply to
/// the case, a build without it does; `requires.axes` names an axis as the manifest does and
/// applies exactly when the build links it.
#[test]
fn unless_runs_a_case_only_where_the_axis_is_absent() {
    let case = |field: &str| {
        Case::parse(&format!(
            r#"{{"schema": "blackbox/1", "case": "axis", {field},
                "steps": [{{"validate": {{"args": ["--version"], "exit": 0}}}}]}}"#
        ))
        .expect("the planted case reads")
    };
    assert!(!axis_linked("no-such-axis"));
    assert_eq!(case(r#""unless": ["no-such-axis"]"#).not_applicable(), None);
    assert!(case(r#""requires": {"axes": ["no-such-axis"]}"#)
        .not_applicable()
        .is_some());
    for cfg in env!("BUSBAR_LINKED_AXES").split_whitespace() {
        let name = cfg.trim_start_matches("linked_axis_").replace('_', "-");
        assert!(axis_linked(&name), "{name}");
        let without = case(&format!(r#""unless": [{name:?}]"#)).not_applicable();
        assert!(without.is_some_and(|why| why.contains(&name)), "{name}");
        assert_eq!(
            case(&format!(r#""requires": {{"axes": [{name:?}]}}"#)).not_applicable(),
            None,
            "{name}"
        );
    }
}

/// EVERY REPLY ANSWERS ITS OWN REQUEST: a call's JSON-RPC reply carries the request's `id` — the
/// scripted far end does (the control); a far end that answers under a foreign id fails the call.
#[test]
fn a_reply_under_a_foreign_id_fails_the_call() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let foreign = listener.local_addr().expect("its address").port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            if common::upstream::read_request(&mut conn).is_some() {
                common::upstream::respond(
                    &mut conn,
                    200,
                    &json!({"jsonrpc": "2.0", "id": "not-yours", "result": {}}),
                );
            }
        }
    });
    let scripted = Responder::start(BTreeMap::from([(
        "m/x".to_string(),
        Answer::Result(json!({})),
    )]));
    let step = Step::parse(
        &json!({"call": {"path": "/rpc", "status": 200,
                         "body": {"jsonrpc": "2.0", "id": "mine", "method": "m/x"}}}),
        0,
    )
    .expect("the step reads");
    let world = |port: u16| World {
        dir: case_dir("reply-id"),
        data_port: port,
        admin_port: port,
        admin_token: String::new(),
        signing: None,
        minted: None,
        responder: None,
        counts_mark: BTreeMap::new(),
        counts_start: BTreeMap::new(),
        node: None,
        vars: BTreeMap::new(),
        unset: Vec::new(),
        issuer: false,
    };
    run_step(&mut world(scripted.port), &step).expect("the request's own id holds");
    let failure = run_step(&mut world(foreign), &step).expect_err("a foreign id fails");
    assert!(
        failure.contains("\"not-yours\"") && failure.contains("\"mine\""),
        "{failure}"
    );
    assert!(reply_id_held(
        &json!({"jsonrpc": "2.0", "method": "note"}),
        &json!({"jsonrpc": "2.0", "id": 9, "result": {}})
    )
    .is_ok());
}
