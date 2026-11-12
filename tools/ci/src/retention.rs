//! In-CI retention decision for expensive check kinds, made before bootstrap
//! (former scripts/architecture/ci_retention.py, behaviour-identical).
//!
//! Runs inside the protected job from the server-selected trusted controller,
//! using only CI-provided identity (CI_JOB_TOKEN, CI_* variables) and the
//! runner's clone of the job's own project. For each retainable kind it decides:
//!
//!   retained(original job N): a successful job of the same kind in the same
//!       project on protected dev, under the same approved policy revision,
//!       whose archive and per-step log digests verify and whose input identity
//!       equals the current input identity. A receipt referencing that job is
//!       written to boundary-evidence/retained.json and the expensive bootstrap
//!       is skipped.
//!   fresh(reason): anything else, including missing API access, malformed or
//!       forged evidence and any internal error. Nothing is written; the
//!       caller runs the full qualification.
//!
//! The receipt never copies the original's pass flag; it carries the verified
//! original job/pipeline ids, archive and receipt digests and the identity.
//!
//! Input identity (`busbar.ci-input-identity/1`, no interpreter-dependent data):
//!   * every tracked path and mode of the candidate commit tree, and the Git
//!     blob id of every path except a small content-excluded set;
//!   * the approved policy revision (the whole trusted controller tree);
//!   * job kind, project, protected ref; for non-core projects also the
//!     resolved core host revision the job would assemble against.
//!
//! Python semantics that reach the decision, the reasons or retained.json
//! (`==` between JSON values, `str()`, exception classes and messages,
//! `json.loads`, `zipfile`) are reproduced by `py`, `zip` and `inflate`.
//! The job token reaches only curl's stdin configuration.
use crate::fetch;
use crate::json::{self, Value};
use crate::py::{self, PyErr};
use crate::sha256;
use crate::zip::{self, ZipError};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;

pub const CORE: &str = "GetBusbar/busbar";
pub const SCHEMA: &str = "busbar.ci-retained-check/1";
pub const IDENTITY_SCHEMA: &str = "busbar.ci-input-identity/1";
pub const RETAINED: i32 = 0;
pub const FRESH: i32 = 3;
const MAX_PAGES: u32 = 5;
const MAX_VERIFIED: u32 = 3;
pub const ARCHIVE_LIMIT: u64 = 1 << 30;
const API_LIMIT: u64 = 32 << 20;
const GIT: &str = "/usr/bin/git";

fn receipt_schema(kind: &str) -> Option<&'static str> {
    match kind {
        "native-qualification" => Some("busbar.protected-native-admission/1"),
        "core-conformance" => Some("busbar.protected-conformance/1"),
        _ => None,
    }
}

// Content-excluded candidates: community/forge metadata that no qualification
// step reads. Paths and modes stay in the identity (directory walkers can see
// them); only their bytes are dropped. docs/** and README.md are NOT candidates:
// dist/default/tests/docs_examples.rs walks docs/**/*.md and README.md, and
// several tests include_str!/read docs/*.md (audit digests, admin-api.md,
// diagnostics.md). CHANGELOG.md and RELEASE.md are candidates but are named by
// scripts/release/publish_gate.py, so the reference guard keeps them hashed.
const EXCLUDED_PREFIXES: [&str; 3] = [
    ".gitlab/issue_templates/",
    ".gitlab/merge_request_templates/",
    "org-profile/",
];
// Core's candidate scripts/architecture/** never executes in these jobs: the
// pipeline runs only the trusted policy checkout's copy (its header contract).
const TRUSTED_ONLY: &str = "scripts/architecture/";
// A markdown-walking marker in code could read excluded files without naming
// them. Each reviewed occurrence is pinned to its exact blob; any other marker
// disables the exclusion (fresh, never smaller key) until it is reviewed here.
const REVIEWED_MARKDOWN_WALKERS: [(&str, &str, &str); 3] = [
    // Walks docs/**/*.md and reads README.md only; neither is excluded.
    (
        CORE,
        "dist/default/tests/docs_examples.rs",
        "661fe271e0a234598aa218237db1b465bd2a09ee",
    ),
    // Editor settings ([*.md] section); no qualification tool reads it.
    (
        CORE,
        ".editorconfig",
        "a6bd4c53f6ee346474321cabba0f37bbc986a987",
    ),
    // Audit prose quoting a shell loop over docs/design/inventory/*.md; unread data.
    (
        CORE,
        "docs/evidence/1.6.0-audit-evidence.json",
        "7dd95dc226fad90ad925f6c2a1b78178f713757e",
    ),
];

/// Python's exception flow: `Fresh` (retention unproven), `Rejected`
/// (malformed or forged evidence; a `Fresh` subclass) or any other exception.
#[derive(Debug, Clone, PartialEq)]
pub enum Exc {
    Fresh(String),
    Rejected(String),
    Py(PyErr),
}

impl From<PyErr> for Exc {
    fn from(error: PyErr) -> Exc {
        Exc::Py(error)
    }
}

impl Exc {
    fn text(&self) -> &str {
        match self {
            Exc::Fresh(m) | Exc::Rejected(m) => m,
            Exc::Py(e) => &e.message,
        }
    }

    /// `except (Rejected, ValueError, KeyError, TypeError, AttributeError)`.
    fn evidence(&self) -> bool {
        match self {
            Exc::Rejected(_) => true,
            Exc::Fresh(_) => false,
            Exc::Py(e) => {
                e.is_value_error() || matches!(e.class, "KeyError" | "TypeError" | "AttributeError")
            }
        }
    }
}

type R<T> = Result<T, Exc>;

fn require(condition: bool, reason: impl Into<String>) -> R<()> {
    if condition {
        Ok(())
    } else {
        Err(Exc::Rejected(reason.into()))
    }
}

fn require_fresh(condition: bool, reason: impl Into<String>) -> R<()> {
    if condition {
        Ok(())
    } else {
        Err(Exc::Fresh(reason.into()))
    }
}

fn key_error(key: &str) -> Exc {
    Exc::Py(PyErr::new("KeyError", py::repr_str(key)))
}

pub fn sha1_text(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `SHA1.fullmatch(value or '') is not None`.
fn sha1_or_empty(value: &Value) -> Result<bool, PyErr> {
    if !py::truthy(value) {
        return Ok(false);
    }
    match value {
        Value::String(s) => Ok(sha1_text(s)),
        other => Err(PyErr::new(
            "TypeError",
            format!(
                "expected string or bytes-like object, got '{}'",
                py::type_name(other)
            ),
        )),
    }
}

/// `(value or {}).get(key)`.
fn or_empty_get<'a>(value: &'a Value, key: &str) -> Result<&'a Value, PyErr> {
    if !py::truthy(value) {
        return Ok(&json::NULL);
    }
    match value {
        Value::Object(_) => Ok(value.at(key)),
        other => Err(PyErr::new(
            "AttributeError",
            format!("'{}' object has no attribute 'get'", py::type_name(other)),
        )),
    }
}

/// `value[key]` on a JSON object.
fn index<'a>(value: &'a Value, key: &str) -> R<&'a Value> {
    match value {
        Value::Object(_) => value.get(key).ok_or_else(|| key_error(key)),
        Value::Array(_) => Err(Exc::Py(PyErr::new(
            "TypeError",
            "list indices must be integers or slices, not str",
        ))),
        other => Err(Exc::Py(PyErr::new(
            "TypeError",
            format!("'{}' object is not subscriptable", py::type_name(other)),
        ))),
    }
}

fn eq_str(value: &Value, text: &str) -> bool {
    value.as_str() == Some(text)
}

fn int_value(text: &str) -> Value {
    Value::Number(text.to_owned())
}

pub fn sha256_hex(data: &[u8]) -> String {
    sha256::hex(data)
}

/// `(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()`.
pub fn canonical(value: &Value) -> Vec<u8> {
    json::encoded(value)
}

/// Python `int(text)` (base 10) as canonical decimal text.
fn py_int(text: &str) -> Result<String, PyErr> {
    let invalid = || {
        PyErr::new(
            "ValueError",
            format!(
                "invalid literal for int() with base 10: {}",
                py::repr_str(text)
            ),
        )
    };
    let body = text.trim_matches(|c: char| c.is_whitespace());
    let (negative, digits) = match body.as_bytes().first() {
        Some(b'-') => (true, &body[1..]),
        Some(b'+') => (false, &body[1..]),
        _ => (false, body),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|c| c.is_ascii_digit() || c == b'_')
    {
        return Err(invalid());
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    if clean.len() > 4300 {
        return Err(PyErr::new(
            "ValueError",
            format!(
                "Exceeds the limit (4300 digits) for integer string conversion: value has {} digits; use sys.set_int_max_str_digits() to increase the limit",
                clean.len()
            ),
        ));
    }
    let trimmed = clean.trim_start_matches('0');
    if trimmed.is_empty() {
        return Ok("0".into());
    }
    Ok(if negative {
        format!("-{trimmed}")
    } else {
        trimmed.to_owned()
    })
}

/// `str(PurePosixPath(text))`.
pub fn posix_str(text: &str) -> String {
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if root.is_empty() && parts.is_empty() {
        return ".".into();
    }
    format!("{root}{}", parts.join("/"))
}

/// Python list repr of strings (`str(CalledProcessError)` argv).
fn repr_list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| py::repr_str(s))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub type Env = BTreeMap<String, String>;
pub type Tree = BTreeMap<String, (String, String)>;

/// Read immutable objects from the runner's clone; no checkout, hooks or filters.
pub struct Git {
    root: String,
    trees: RefCell<HashMap<String, Rc<Tree>>>,
}

impl Git {
    pub fn new(root: &Path) -> Git {
        Git {
            root: posix_str(&root.to_string_lossy()),
            trees: RefCell::new(HashMap::new()),
        }
    }

    fn argv(&self, args: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        argv.push(format!("safe.directory={}", self.root));
        argv.push("-C".into());
        argv.push(self.root.clone());
        argv.extend(args.iter().map(|a| (*a).to_owned()));
        argv
    }

    /// `subprocess.run(..., capture_output=True, check=True).stdout`.
    fn git(&self, args: &[&str], data: Option<Vec<u8>>) -> R<Vec<u8>> {
        let argv = self.argv(args);
        let mut command = Command::new(GIT);
        command
            .args(&argv[1..])
            .env_clear()
            .envs(crate::inputs::base_env())
            .stdin(if data.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|e| {
            Exc::Py(PyErr::new(
                "FileNotFoundError",
                format!("[Errno 2] No such file or directory: 'git' ({e})"),
            ))
        })?;
        let writer = data.map(|data| {
            let mut input = child.stdin.take().unwrap();
            std::thread::spawn(move || {
                let _ = input.write_all(&data);
            })
        });
        let mut out = Vec::new();
        let read = child.stdout.take().unwrap().read_to_end(&mut out);
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        let status = child
            .wait()
            .map_err(|e| Exc::Py(PyErr::new("OSError", e.to_string())))?;
        if read.is_err() || !status.success() {
            let code = status.code().unwrap_or(-1);
            return Err(Exc::Py(PyErr::new(
                "CalledProcessError",
                format!(
                    "Command '{}' returned non-zero exit status {code}.",
                    repr_list(&argv)
                ),
            )));
        }
        Ok(out)
    }

    pub fn has_commit(&self, revision: &str) -> bool {
        if !sha1_text(revision) {
            return false;
        }
        let spec = format!("{revision}^{{commit}}");
        match self.git(&["rev-parse", "--verify", "--quiet", &spec], None) {
            Ok(out) => String::from_utf8_lossy(&out).trim() == revision,
            Err(_) => false,
        }
    }

    pub fn tree(&self, revision: &str) -> R<Rc<Tree>> {
        if let Some(tree) = self.trees.borrow().get(revision) {
            return Ok(tree.clone());
        }
        require_fresh(
            self.has_commit(revision),
            format!("commit {revision} is not in the protected clone"),
        )?;
        let out = self.git(&["ls-tree", "-r", "-z", "--full-tree", revision], None)?;
        let mut rows = Tree::new();
        for record in out.split(|b| *b == 0) {
            if record.is_empty() {
                continue;
            }
            let tab = record.iter().position(|b| *b == b'\t').ok_or_else(|| {
                Exc::Py(PyErr::new(
                    "ValueError",
                    "not enough values to unpack (expected 2, got 1)",
                ))
            })?;
            let header = String::from_utf8_lossy(&record[..tab]).into_owned();
            let fields: Vec<&str> = header.split_whitespace().collect();
            let [mode, kind, oid] = fields.as_slice() else {
                return Err(Exc::Py(PyErr::new(
                    "ValueError",
                    format!(
                        "not enough values to unpack (expected 3, got {})",
                        fields.len()
                    ),
                )));
            };
            let path: String = py::decode_utf8(&record[tab + 1..], false)?
                .into_iter()
                .collect();
            require_fresh(
                *kind == "blob" && matches!(*mode, "100644" | "100755" | "120000"),
                format!("submodule or unsupported tree entry {path}"),
            )?;
            rows.insert(path, ((*mode).to_owned(), (*oid).to_owned()));
        }
        let tree = Rc::new(rows);
        self.trees
            .borrow_mut()
            .insert(revision.to_owned(), tree.clone());
        Ok(tree)
    }

    /// Map each blob id to its bytes using one batch reader.
    pub fn blobs(&self, oids: &BTreeSet<String>) -> R<HashMap<String, Vec<u8>>> {
        let mut result = HashMap::new();
        if oids.is_empty() {
            return Ok(result);
        }
        let input: String = oids.iter().map(|oid| format!("{oid}\n")).collect();
        let out = self.git(&["cat-file", "--batch"], Some(input.into_bytes()))?;
        let mut offset = 0;
        for oid in oids {
            let end = out[offset.min(out.len())..]
                .iter()
                .position(|b| *b == b'\n')
                .map(|i| offset + i)
                .ok_or_else(|| Exc::Py(PyErr::new("ValueError", "subsection not found")))?;
            let header = String::from_utf8_lossy(&out[offset..end]).into_owned();
            let fields: Vec<&str> = header.split_whitespace().collect();
            let [name, kind, size] = fields.as_slice() else {
                return Err(Exc::Py(PyErr::new(
                    "ValueError",
                    format!(
                        "not enough values to unpack (expected 3, got {})",
                        fields.len()
                    ),
                )));
            };
            require_fresh(
                name == oid && *kind == "blob",
                "unexpected object in batch read",
            )?;
            let size: usize = size
                .parse()
                .map_err(|_| Exc::Py(PyErr::new("ValueError", "invalid blob size")))?;
            let start = end + 1;
            let stop = (start + size).min(out.len());
            result.insert(oid.clone(), out[start..stop].to_vec());
            offset = start + size + 1;
        }
        Ok(result)
    }
}

/// GET-only GitLab API, authenticated by the job's own CI_JOB_TOKEN.
pub trait Api {
    fn raw(&self, path: &str, limit: u64) -> R<Vec<u8>>;
    fn json(&self, path: &str) -> R<Value> {
        let raw = self.raw(path, API_LIMIT)?;
        match py::loads(&raw) {
            Ok(value) => Ok(value),
            Err(error) if error.is_value_error() => {
                Err(Exc::Fresh("malformed GitLab API response".into()))
            }
            Err(error) => Err(Exc::Py(error)),
        }
    }
    /// `git ls-remote <server>/GetBusbar/busbar.git refs/heads/dev` (first field).
    fn core_dev(&self, server: &str, token: &str) -> R<String>;
}

pub struct CurlApi {
    base: String,
    token: String,
}

fn server_origin(server: &str) -> bool {
    let Some(rest) = server.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        && port.is_none_or(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
}

impl CurlApi {
    pub fn new(env: &Env) -> R<CurlApi> {
        let server = env
            .get("CI_SERVER_URL")
            .ok_or_else(|| key_error("CI_SERVER_URL"))?
            .trim_end_matches('/')
            .to_owned();
        let api = env
            .get("CI_API_V4_URL")
            .map(String::as_str)
            .unwrap_or("")
            .trim_end_matches('/');
        require_fresh(
            server_origin(&server) && api == format!("{server}/api/v4"),
            "non-canonical CI API origin",
        )?;
        let token = env
            .get("CI_JOB_TOKEN")
            .ok_or_else(|| key_error("CI_JOB_TOKEN"))?
            .clone();
        Ok(CurlApi {
            base: format!("{server}/api/v4/"),
            token,
        })
    }
}

fn unavailable(kind: &str) -> Exc {
    Exc::Fresh(format!("GitLab API unavailable: {kind}"))
}

fn http_get(url: &str, header: &str, limit: u64, path: &str) -> R<Vec<u8>> {
    api_result(fetch::get(url, header, limit), path)
}

/// urllib semantics: non-2xx (redirects are not followed) is a refusal; no
/// response or a broken transfer is "unavailable"; the read bound is fresh.
fn api_result(got: Result<fetch::Got, String>, path: &str) -> R<Vec<u8>> {
    match got {
        Err(_) => Err(unavailable("URLError")),
        Ok(fetch::Got::Exceeded) => Err(Exc::Fresh("API response exceeds bound".into())),
        Ok(fetch::Got::Done { code, exit, body }) => {
            if code == 0 {
                return Err(unavailable("URLError"));
            }
            if !(200..300).contains(&code) {
                return Err(Exc::Fresh(format!(
                    "CI_JOB_TOKEN read of {} refused (HTTP {code}); job token needs read_jobs on its own project",
                    path.split('?').next().unwrap_or("")
                )));
            }
            match exit {
                0 => Ok(body),
                28 => Err(unavailable("TimeoutError")),
                _ => Err(unavailable("URLError")),
            }
        }
    }
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The first id advertised for `refs/heads/dev` in a smart-HTTP upload-pack
/// reference advertisement (protocol v0), as `git ls-remote` prints it.
pub fn advertised_dev(body: &[u8]) -> Option<String> {
    let mut at = 0;
    while at + 4 <= body.len() {
        let length =
            usize::from_str_radix(std::str::from_utf8(&body[at..at + 4]).ok()?, 16).ok()?;
        if length == 0 {
            at += 4;
            continue;
        }
        if length < 4 || at + length > body.len() {
            return None;
        }
        let line = &body[at + 4..at + length];
        at += length;
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.split(|b| *b == 0).next().unwrap_or(line);
        let text = std::str::from_utf8(line).ok()?;
        if let Some((oid, name)) = text.split_once(' ')
            && name == "refs/heads/dev"
        {
            return Some(oid.to_owned());
        }
    }
    None
}

impl Api for CurlApi {
    fn raw(&self, path: &str, limit: u64) -> R<Vec<u8>> {
        http_get(
            &format!("{}{path}", self.base),
            &format!("JOB-TOKEN:{}", self.token),
            limit,
            path,
        )
    }

    fn core_dev(&self, server: &str, token: &str) -> R<String> {
        let failed = || Exc::Fresh("could not resolve current core host revision".into());
        let auth = base64(format!("gitlab-ci-token:{token}").as_bytes());
        let url = format!("{server}/{CORE}.git/info/refs?service=git-upload-pack");
        match fetch::get(&url, &format!("Authorization: Basic {auth}"), API_LIMIT) {
            Ok(fetch::Got::Done {
                code: 200,
                exit: 0,
                body,
            }) => advertised_dev(&body).ok_or_else(failed),
            _ => Err(failed()),
        }
    }
}

pub fn excluded_candidate(path: &str, mode: &str) -> bool {
    if mode != "100644" {
        return false;
    }
    if !path.contains('/') {
        return path.ends_with(".md") && path != "README.md";
    }
    EXCLUDED_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `rb'\x2a\.md\b|["\']\.?md["\']'` search.
pub fn markdown_walker(data: &[u8]) -> bool {
    for (i, &b) in data.iter().enumerate() {
        if b == b'*'
            && data[i + 1..].starts_with(b".md")
            && data.get(i + 4).is_none_or(|n| !word_byte(*n))
        {
            return true;
        }
        if b == b'"' || b == b'\'' {
            let rest = &data[i + 1..];
            let rest = rest.strip_prefix(b".").unwrap_or(rest);
            if rest.starts_with(b"md") && matches!(rest.get(2), Some(b'"') | Some(b'\'')) {
                return true;
            }
        }
    }
    false
}

/// `needle in haystack` for bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return true;
    };
    let mut at = 0;
    while let Some(i) = haystack[at..].iter().position(|b| *b == first) {
        let start = at + i + 1;
        if haystack[start..].starts_with(rest) {
            return true;
        }
        at = start;
    }
    false
}

/// Return (content-excluded paths, notes); the guard is evaluated on this tree.
///
/// A candidate stays hashed when any other non-markdown blob names its file
/// name (include_str!, open(), read_to_string, scripts...). If code contains an
/// unreviewed markdown-walking marker, nothing is excluded.
pub fn excluded_paths(
    repository: &str,
    tree: &Tree,
    git: &Git,
) -> R<(BTreeSet<String>, Vec<String>)> {
    let candidates: BTreeSet<String> = tree
        .iter()
        .filter(|(path, (mode, _))| excluded_candidate(path, mode))
        .map(|(path, _)| path.clone())
        .collect();
    let scanned: BTreeMap<&String, &String> = tree
        .iter()
        .filter(|(path, _)| !candidates.contains(*path) && !path.ends_with(".md"))
        .map(|(path, (_, oid))| (path, oid))
        .collect();
    let contents = git.blobs(&scanned.values().map(|s| (*s).clone()).collect())?;
    let blob = |oid: &str| contents.get(oid).map(Vec::as_slice).unwrap_or(&[]);
    for (path, oid) in &scanned {
        if repository == CORE && path.starts_with(TRUSTED_ONLY) {
            continue;
        }
        let reviewed = REVIEWED_MARKDOWN_WALKERS
            .iter()
            .any(|(r, p, o)| *r == repository && p == path && o == oid);
        if markdown_walker(blob(oid)) && !reviewed {
            return Ok((
                BTreeSet::new(),
                vec![format!(
                    "content exclusion disabled: unreviewed markdown walker in {path}"
                )],
            ));
        }
    }
    let (mut notes, mut excluded) = (Vec::new(), BTreeSet::new());
    for path in &candidates {
        let name = path.rsplit('/').next().unwrap_or(path).as_bytes();
        let reader = scanned
            .iter()
            .filter(|(_, oid)| contains(blob(oid), name))
            .map(|(other, _)| *other)
            .min();
        match reader {
            Some(reader) => notes.push(format!("{path} stays hashed: named by {reader}")),
            None => {
                excluded.insert(path.clone());
            }
        }
    }
    Ok((excluded, notes))
}

pub fn tree_identity(tree: &Tree, excluded: &BTreeSet<String>) -> String {
    let rows = tree
        .iter()
        .map(|(path, (mode, oid))| {
            let content = if excluded.contains(path) {
                "content-excluded"
            } else {
                oid
            };
            Value::Array(vec![
                Value::str(path.as_str()),
                Value::str(mode.as_str()),
                Value::str(content),
            ])
        })
        .collect();
    sha256_hex(&canonical(&Value::Array(rows)))
}

#[derive(Clone, Debug)]
pub struct Context {
    kind: String,
    project: String,
    project_id: String,
    job_id: String,
    pipeline_id: String,
    source: String,
    policy: String,
    server_host: String,
}

fn identity(context: &Context, tree: &Tree, excluded: &BTreeSet<String>, host: &Value) -> Value {
    let mut value = Value::Object(vec![
        ("schema".into(), Value::str(IDENTITY_SCHEMA)),
        ("kind".into(), Value::str(context.kind.as_str())),
        ("project".into(), Value::str(context.project.as_str())),
        ("project_id".into(), int_value(&context.project_id)),
        ("ref".into(), Value::str("dev")),
        (
            "policy_revision".into(),
            Value::str(context.policy.as_str()),
        ),
        (
            "tree_sha256".into(),
            Value::str(tree_identity(tree, excluded)),
        ),
        (
            "content_excluded".into(),
            Value::Array(excluded.iter().map(|p| Value::str(p.as_str())).collect()),
        ),
    ]);
    if context.project != CORE {
        value.set("host_revision", host.clone());
    }
    value
}

fn changed_paths(before: &Tree, after: &Tree, excluded: &BTreeSet<String>) -> Vec<String> {
    let all: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let paths: Vec<String> = all
        .into_iter()
        .filter(|path| {
            if excluded.contains(*path) {
                before.contains_key(*path) != after.contains_key(*path)
            } else {
                before.get(*path) != after.get(*path)
            }
        })
        .cloned()
        .collect();
    let mut shown: Vec<String> = paths.iter().take(5).cloned().collect();
    if paths.len() > 5 {
        shown.push(format!("... {} more", paths.len() - 5));
    }
    shown
}

fn path_shape_ok(name: &str) -> bool {
    !name.starts_with('/')
        && !name.split('/').any(|p| p == "..")
        && !name.contains('\\')
        && posix_str(name) == name.trim_end_matches('/')
}

pub type Members = HashMap<String, Vec<u8>>;

fn zip_error(error: ZipError) -> Exc {
    match error {
        ZipError::Bad(_) | ZipError::Unsupported(_) => {
            Exc::Rejected("unreadable artifact archive".into())
        }
        ZipError::NotImplemented(m) => Exc::Py(PyErr::new("NotImplementedError", m)),
        ZipError::Runtime(m) => Exc::Py(PyErr::new("RuntimeError", m)),
        ZipError::Zlib(m) => Exc::Py(PyErr::new("error", m)),
    }
}

pub fn read_archive(raw: &[u8]) -> R<Members> {
    require(raw.len() as u64 <= ARCHIVE_LIMIT, "archive exceeds bound")?;
    let list = zip::entries(raw).map_err(zip_error)?;
    let mut members: Vec<&zip::Entry> = Vec::new();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut total: u128 = 0;
    for item in &list {
        let kind = (item.external_attr >> 16) & 0o170000;
        require(
            path_shape_ok(&item.filename)
                && !names.contains(item.filename.as_str())
                && matches!(kind, 0 | 0o100000 | 0o040000)
                && item.flag_bits & 1 == 0,
            format!("unsafe archive member {}", item.filename),
        )?;
        total += u128::from(item.file_size);
        require(
            total <= 2 * u128::from(ARCHIVE_LIMIT),
            "expanded archive exceeds bound",
        )?;
        names.insert(&item.filename);
        members.push(item);
    }
    require(members.len() <= 10000, "too many archive members")?;
    let mut result = Members::new();
    for item in members {
        if !item.is_dir() && item.filename.starts_with("boundary-evidence/") {
            result.insert(
                item.filename.clone(),
                zip::read(raw, item).map_err(zip_error)?,
            );
        }
    }
    Ok(result)
}

fn eligible(job: &Value, context: &Context) -> Result<bool, PyErr> {
    let id = job.at("id");
    if !(eq_str(job.at("name"), &context.kind)
        && eq_str(job.at("status"), "success")
        && eq_str(job.at("ref"), "dev")
        && matches!(job.at("tag"), Value::Bool(false))
        && matches!(job.at("allow_failure"), Value::Bool(false))
        && id.is_int()
        && !py::eq(id, &int_value(&context.job_id)))
    {
        return Ok(false);
    }
    let pipeline = job.at("pipeline");
    if !py::eq(
        or_empty_get(pipeline, "project_id")?,
        &int_value(&context.project_id),
    ) {
        return Ok(false);
    }
    if !eq_str(or_empty_get(pipeline, "ref")?, "dev") {
        return Ok(false);
    }
    let source = or_empty_get(pipeline, "source")?;
    if !(eq_str(source, "push") || eq_str(source, "api")) {
        return Ok(false);
    }
    if !sha1_or_empty(or_empty_get(job.at("commit"), "id")?)? {
        return Ok(false);
    }
    Ok(py::eq(
        or_empty_get(pipeline, "sha")?,
        job.at("commit").at("id"),
    ))
}

fn download(api: &dyn Api, context: &Context, job: &Value) -> R<Vec<u8>> {
    let size = or_empty_get(job.at("artifacts_file"), "size")?;
    let id = py::str(index(job, "id")?);
    let limit = i128::from(ARCHIVE_LIMIT);
    require(
        size.is_int() && size.as_int().is_some_and(|s| 0 < s && s <= limit),
        format!("job {id} has no archive"),
    )?;
    let raw = api.raw(
        &format!("projects/{}/jobs/{id}/artifacts", context.project_id),
        ARCHIVE_LIMIT,
    )?;
    require(
        size.as_int() == Some(raw.len() as i128),
        format!("job {id} archive size differs from server record"),
    )?;
    Ok(raw)
}

fn loads(raw: &[u8]) -> R<Value> {
    py::loads(raw).map_err(Exc::Py)
}

/// Verify an original fresh job's own archive; return its receipt and digests.
fn verify_original(context: &Context, job: &Value, raw: &[u8]) -> R<(Value, Vec<(String, Value)>)> {
    let members = read_archive(raw)?;
    let label = format!("job {}", py::str(index(job, "id")?));
    require(
        !members.contains_key("boundary-evidence/retained.json"),
        format!("{label} is not a fresh original"),
    )?;
    let receipt_raw = members
        .get("boundary-evidence/receipt.json")
        .ok_or_else(|| Exc::Rejected(format!("{label} archive has no receipt")))?;
    let receipt = loads(receipt_raw)?;
    let uri = format!(
        "{}/{}//ci/architecture-pipeline.yml@{CORE}:{}@refs/heads/dev",
        context.server_host, context.project, context.policy
    );
    let source = index(index(job, "commit")?, "id")?.clone();
    let pipeline_id = py::str(index(index(job, "pipeline")?, "id")?);
    let expected = [
        (
            "schema",
            Value::str(receipt_schema(&context.kind).unwrap_or("")),
        ),
        ("status", Value::str("pass")),
        ("repository", Value::str(context.project.as_str())),
        ("source", source),
        ("job_id", Value::str(py::str(index(job, "id")?))),
        ("pipeline_id", Value::str(pipeline_id)),
        ("policy_revision", Value::str(context.policy.as_str())),
        ("config_uri", Value::str(uri)),
    ];
    for (key, value) in &expected {
        require(
            receipt.is_object() && py::eq(receipt.at(key), value),
            format!("{label} receipt {key} differs from server/policy identity"),
        )?;
    }
    let steps = receipt.at("steps");
    require(
        matches!(steps, Value::Array(rows) if !rows.is_empty()),
        format!("{label} receipt has no checks"),
    )?;
    let mut names = BTreeSet::new();
    for step in steps.as_array().unwrap_or(&[]) {
        let name = if step.is_object() {
            step.at("name")
        } else {
            &json::NULL
        };
        let valid = name.as_str().is_some_and(|n| {
            !n.is_empty()
                && n.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
                && !names.contains(n)
        });
        require(
            valid,
            format!("{label} has an invalid or duplicate check name"),
        )?;
        let name = name.as_str().unwrap_or("").to_owned();
        names.insert(name.clone());
        for stream in ["stdout", "stderr"] {
            let log = members.get(&format!("boundary-evidence/{name}.{stream}"));
            require(
                log.is_some_and(|log| {
                    eq_str(step.at(&format!("{stream}_sha256")), &sha256_hex(log))
                }),
                format!("{label} check log {name}.{stream} missing or altered"),
            )?;
        }
        if context.kind == "native-qualification" {
            require(
                eq_str(step.at("status"), "pass") && py::eq(step.at("exit_code"), &Value::int(0)),
                format!("{label} check {name} did not pass"),
            )?;
        }
    }
    if context.project != CORE {
        require(
            sha1_or_empty(receipt.at("host_revision"))?,
            format!("{label} receipt has no host revision"),
        )?;
    }
    let digests = vec![
        ("archive_sha256".to_owned(), Value::str(sha256_hex(raw))),
        ("archive_size".to_owned(), Value::int(raw.len() as i128)),
        (
            "receipt_sha256".to_owned(),
            Value::str(sha256_hex(receipt_raw)),
        ),
    ];
    Ok((receipt, digests))
}

/// `for row in value` over a JSON value.
fn iterate(value: &Value) -> R<Vec<&Value>> {
    match value {
        Value::Array(rows) => Ok(rows.iter().collect()),
        // Iterating a dict yields keys and a str yields characters: never rows.
        Value::Object(_) | Value::String(_) => Ok(Vec::new()),
        other => Err(Exc::Py(PyErr::new(
            "TypeError",
            format!("'{}' object is not iterable", py::type_name(other)),
        ))),
    }
}

/// A retained job names its fresh original; re-authenticate that original.
fn follow_retained(
    api: &dyn Api,
    context: &Context,
    job: &Value,
    raw: &[u8],
) -> R<(Value, Vec<u8>)> {
    let members = read_archive(raw)?;
    let label = format!("retained job {}", py::str(index(job, "id")?));
    let receipt = loads(
        members
            .get("boundary-evidence/retained.json")
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    )?;
    let same = receipt.is_object()
        && eq_str(receipt.at("schema"), SCHEMA)
        && eq_str(receipt.at("decision"), "retained")
        && eq_str(receipt.at("kind"), &context.kind)
        && eq_str(receipt.at("project"), &context.project)
        && py::eq(receipt.at("job_id"), index(job, "id")?)
        && py::eq(receipt.at("source"), index(index(job, "commit")?, "id")?);
    require(
        same,
        format!("{label} receipt differs from server identity"),
    )?;
    let original = receipt.at("original");
    require(
        original.is_object()
            && original.at("job_id").is_int()
            && original.at("pipeline_id").is_int(),
        format!("{label} names no original"),
    )?;
    let jobs = api.json(&format!(
        "projects/{}/pipelines/{}/jobs?per_page=100",
        context.project_id,
        py::str(original.at("pipeline_id"))
    ))?;
    let found: Vec<&Value> = iterate(&jobs)?
        .into_iter()
        .filter(|row| row.is_object() && py::eq(row.at("id"), original.at("job_id")))
        .collect();
    let accepted = found.len() == 1
        && eligible(found[0], context)?
        && py::eq(
            index(index(found[0], "pipeline")?, "id")?,
            original.at("pipeline_id"),
        );
    require(
        accepted,
        format!("{label} original is not a successful same-kind protected dev job"),
    )?;
    let original_raw = download(api, context, found[0])?;
    require(
        eq_str(original.at("archive_sha256"), &sha256_hex(&original_raw)),
        format!("{label} original archive digest differs from its receipt"),
    )?;
    Ok((found[0].clone(), original_raw))
}

fn current_host(context: &Context, env: &Env, api: &dyn Api) -> R<Value> {
    if context.project == CORE {
        return Ok(Value::Null);
    }
    let pinned = env
        .get("BUSBAR_ADMISSION_CORE_REVISION")
        .map(String::as_str)
        .unwrap_or("dev");
    if sha1_text(pinned) {
        return Ok(Value::str(pinned));
    }
    require_fresh(pinned == "dev", "unrecognized host revision selector")?;
    let server = env
        .get("CI_SERVER_URL")
        .ok_or_else(|| key_error("CI_SERVER_URL"))?
        .trim_end_matches('/')
        .to_owned();
    let token = env
        .get("CI_JOB_TOKEN")
        .ok_or_else(|| key_error("CI_JOB_TOKEN"))?;
    let line = api.core_dev(&server, token)?;
    require_fresh(
        sha1_text(&line),
        "could not resolve current core host revision",
    )?;
    Ok(Value::str(line))
}

fn context_from(env: &Env, policy: &str) -> R<Context> {
    let get = |key: &str| env.get(key).map(String::as_str);
    require_fresh(
        get("CI_PIPELINE_SOURCE") == Some("push"),
        format!(
            "pipeline source {} is not an ordinary dev push",
            get("CI_PIPELINE_SOURCE").unwrap_or("None")
        ),
    )?;
    require_fresh(
        get("CI_COMMIT_BRANCH") == Some("dev") && get("CI_COMMIT_REF_PROTECTED") == Some("true"),
        "ref is not the protected dev branch",
    )?;
    let kind = get("CI_JOB_NAME");
    require_fresh(
        kind.is_some_and(|k| {
            receipt_schema(k).is_some()
                && (k != "core-conformance" || get("CI_PROJECT_PATH") == Some(CORE))
        }),
        format!("kind {} is not retainable", kind.unwrap_or("None")),
    )?;
    require_fresh(
        sha1_text(policy) && sha1_text(get("CI_COMMIT_SHA").unwrap_or("")),
        "immutable policy and commit required",
    )?;
    let need = |key: &str| get(key).map(str::to_owned).ok_or_else(|| key_error(key));
    let project = need("CI_PROJECT_PATH")?;
    let project_id = py_int(&need("CI_PROJECT_ID")?)?;
    let job_id = py_int(&need("CI_JOB_ID")?)?;
    let pipeline_id = py_int(&need("CI_PIPELINE_ID")?)?;
    Ok(Context {
        kind: kind.unwrap_or("").to_owned(),
        project,
        project_id,
        job_id,
        pipeline_id,
        source: need("CI_COMMIT_SHA")?,
        policy: policy.to_owned(),
        server_host: need("CI_SERVER_HOST")?,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Retained(Value),
    Fresh(Vec<String>),
}

/// `datetime.now(timezone.utc).isoformat()`.
pub fn utc_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    isoformat(now.as_secs() as i64, now.subsec_micros())
}

pub fn isoformat(seconds: i64, micros: u32) -> String {
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let fraction = if micros == 0 {
        String::new()
    } else {
        format!(".{micros:06}")
    };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{fraction}+00:00",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

enum Verified {
    Differs,
    Accepted {
        original: Value,
        digests: Vec<(String, Value)>,
    },
}

fn retained_receipt(
    context: &Context,
    current: Value,
    via: Option<&Value>,
    original: &Value,
    digests: Vec<(String, Value)>,
    stamp: String,
    reasons: &[String],
) -> R<Value> {
    let mut record = vec![
        ("job_id".to_owned(), index(original, "id")?.clone()),
        (
            "pipeline_id".to_owned(),
            index(index(original, "pipeline")?, "id")?.clone(),
        ),
        (
            "source".to_owned(),
            index(index(original, "commit")?, "id")?.clone(),
        ),
        (
            "pipeline_source".to_owned(),
            index(index(original, "pipeline")?, "source")?.clone(),
        ),
        (
            "runner_id".to_owned(),
            or_empty_get(original.at("runner"), "id")?.clone(),
        ),
        ("finished_at".to_owned(), original.at("finished_at").clone()),
        (
            "via_retained_job_id".to_owned(),
            match via {
                Some(job) => index(job, "id")?.clone(),
                None => Value::Null,
            },
        ),
    ];
    record.extend(digests);
    let identity_sha256 = sha256_hex(&canonical(&current));
    Ok(Value::Object(vec![
        ("schema".into(), Value::str(SCHEMA)),
        ("decision".into(), Value::str("retained")),
        ("kind".into(), Value::str(context.kind.as_str())),
        ("project".into(), Value::str(context.project.as_str())),
        ("project_id".into(), int_value(&context.project_id)),
        ("job_id".into(), int_value(&context.job_id)),
        ("pipeline_id".into(), int_value(&context.pipeline_id)),
        ("source".into(), Value::str(context.source.as_str())),
        ("ref".into(), Value::str("dev")),
        (
            "policy_revision".into(),
            Value::str(context.policy.as_str()),
        ),
        ("identity".into(), current),
        ("identity_sha256".into(), Value::str(identity_sha256)),
        ("decided_at".into(), Value::str(stamp)),
        ("original".into(), Value::Object(record)),
        (
            "notes".into(),
            Value::Array(reasons.iter().map(|r| Value::str(r.as_str())).collect()),
        ),
    ]))
}

/// Return the decision. Never fails for evidence: every error is fresh.
pub fn decide(env: &Env, policy: &str, git: &Git, api: &dyn Api, now: Option<String>) -> Decision {
    let mut reasons: Vec<String> = Vec::new();
    match decide_inner(env, policy, git, api, now, &mut reasons) {
        Ok(Some(receipt)) => return Decision::Retained(receipt),
        Ok(None) => {}
        Err(Exc::Fresh(m)) | Err(Exc::Rejected(m)) => reasons.push(m),
        Err(Exc::Py(e)) => reasons.push(format!(
            "internal error: {}: {}",
            e.class,
            py::prefix(&e.message, 200)
        )),
    }
    Decision::Fresh(reasons)
}

fn decide_inner(
    env: &Env,
    policy: &str,
    git: &Git,
    api: &dyn Api,
    now: Option<String>,
    reasons: &mut Vec<String>,
) -> R<Option<Value>> {
    let context = context_from(env, policy)?;
    let tree = git.tree(&context.source)?;
    let (excluded, notes) = excluded_paths(&context.project, &tree, git)?;
    reasons.extend(notes);
    let host = current_host(&context, env, api)?;
    let current = identity(&context, &tree, &excluded, &host);
    let current_tree = current.at("tree_sha256").as_str().unwrap_or("").to_owned();
    let mut verified = 0;
    for page in 1..=MAX_PAGES {
        let jobs = api.json(&format!(
            "projects/{}/jobs?scope[]=success&per_page=100&page={page}",
            context.project_id
        ))?;
        let Value::Array(jobs) = &jobs else {
            return Err(Exc::Fresh("malformed job listing".into()));
        };
        for job in jobs {
            if !(job.is_object() && eligible(job, &context)?) {
                continue;
            }
            let commit = job.at("commit").at("id").as_str().unwrap_or("").to_owned();
            if !git.has_commit(&commit) {
                continue;
            }
            let before = git.tree(&commit)?;
            if tree_identity(&before, &excluded) != current_tree {
                if reasons.len() < 8 {
                    reasons.push(format!(
                        "job {} inputs differ: {}",
                        py::str(job.at("id")),
                        changed_paths(&before, &tree, &excluded).join(", ")
                    ));
                }
                continue;
            }
            if verified >= MAX_VERIFIED {
                reasons.push("verification bound reached".into());
                return Ok(None);
            }
            verified += 1;
            let attempt = (|| -> R<(Verified, bool)> {
                let raw = download(api, &context, job)?;
                let (original, raw, via) =
                    if read_archive(&raw)?.contains_key("boundary-evidence/retained.json") {
                        let (original, raw) = follow_retained(api, &context, job, &raw)?;
                        (original, raw, true)
                    } else {
                        (job.clone(), raw, false)
                    };
                let (receipt, digests) = verify_original(&context, &original, &raw)?;
                let commit = index(index(&original, "commit")?, "id")?;
                let original_tree = git.tree(commit.as_str().unwrap_or(""))?;
                let original_identity = identity(
                    &context,
                    &original_tree,
                    &excluded,
                    receipt.at("host_revision"),
                );
                if !py::eq(&original_identity, &current) {
                    reasons.push(format!(
                        "job {} identity differs (host/policy/tree)",
                        py::str(original.at("id"))
                    ));
                    return Ok((Verified::Differs, via));
                }
                Ok((Verified::Accepted { original, digests }, via))
            })();
            match attempt {
                Err(error) if error.evidence() => {
                    reasons.push(format!(
                        "rejected evidence: {}",
                        py::prefix(error.text(), 200)
                    ));
                    continue;
                }
                Err(error) => return Err(error),
                Ok((Verified::Differs, _)) => continue,
                Ok((Verified::Accepted { original, digests }, via)) => {
                    let stamp = now.clone().unwrap_or_else(utc_now);
                    let receipt = retained_receipt(
                        &context,
                        current.clone(),
                        via.then_some(job),
                        &original,
                        digests,
                        stamp,
                        reasons,
                    )?;
                    return Ok(Some(receipt));
                }
            }
        }
        if jobs.len() < 100 {
            break;
        }
    }
    reasons.push(format!(
        "no authenticated successful {} job with equal inputs",
        context.kind
    ));
    Ok(None)
}

fn print_line(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// `busbar-ci retention --policy REV --checkout DIR --output FILE`.
pub fn main(args: &[String], env: &Env) -> i32 {
    let mut values: [Option<String>; 3] = Default::default();
    let names = ["--policy", "--checkout", "--output"];
    let mut i = 0;
    while i < args.len() {
        let (name, inline) = match args[i].split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
            _ => (args[i].clone(), None),
        };
        let Some(slot) = names.iter().position(|n| *n == name) else {
            eprintln!(
                "usage: busbar-ci retention --policy POLICY --checkout CHECKOUT --output OUTPUT"
            );
            return 2;
        };
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                match args.get(i) {
                    Some(v) => v.clone(),
                    None => {
                        eprintln!("busbar-ci retention: argument {name}: expected one argument");
                        return 2;
                    }
                }
            }
        };
        values[slot] = Some(value);
        i += 1;
    }
    let [Some(policy), Some(checkout), Some(output)] = values else {
        eprintln!(
            "busbar-ci retention: the following arguments are required: --policy, --checkout, --output"
        );
        return 2;
    };
    run(&policy, Path::new(&checkout), Path::new(&output), env)
}

fn run(policy: &str, checkout: &Path, output: &Path, env: &Env) -> i32 {
    run_with(policy, checkout, output, env, &|env| {
        CurlApi::new(env).map(|api| Box::new(api) as Box<dyn Api>)
    })
}

type MakeApi<'a> = &'a dyn Fn(&Env) -> R<Box<dyn Api>>;

/// The former `main()`: refuse candidate-supplied evidence, decide, write
/// `retained.json` (`json.dumps(indent=2, sort_keys=True)`) and log.
fn run_with(policy: &str, checkout: &Path, output: &Path, env: &Env, make_api: MakeApi) -> i32 {
    let kind = env
        .get("CI_JOB_NAME")
        .cloned()
        .unwrap_or_else(|| "?".into());
    let output = PathBuf::from(posix_str(&output.to_string_lossy()));
    let evidence = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let decision = if std::fs::symlink_metadata(&evidence).is_ok() {
        let name = evidence
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Decision::Fresh(vec![format!("checkout already contains {name}")])
    } else {
        match make_api(env) {
            Ok(api) => decide(env, policy, &Git::new(checkout), api.as_ref(), None),
            Err(Exc::Fresh(m)) | Err(Exc::Rejected(m)) => Decision::Fresh(vec![m]),
            Err(Exc::Py(e)) => Decision::Fresh(vec![format!("internal error: {}", e.class)]),
        }
    };
    if let Decision::Retained(detail) = &decision {
        let text = py::dumps_sorted_indent(detail) + "\n";
        if let Err(error) =
            std::fs::create_dir(&evidence).and_then(|()| std::fs::write(&output, text.as_bytes()))
        {
            eprintln!("busbar-ci retention: {}: {error}", output.display());
            return 1;
        }
    }
    for line in report(&kind, &decision) {
        print_line(&line);
    }
    match decision {
        Decision::Retained(_) => RETAINED,
        Decision::Fresh(_) => FRESH,
    }
}

/// The `busbar-retention: ...` job log lines.
pub fn report(kind: &str, decision: &Decision) -> Vec<String> {
    match decision {
        Decision::Retained(detail) => {
            let original = detail.at("original");
            let mut lines = vec![format!(
                "busbar-retention: {kind}: retained(original job {}, pipeline {}, identity {})",
                py::str(original.at("job_id")),
                py::str(original.at("pipeline_id")),
                py::prefix(detail.at("identity_sha256").as_str().unwrap_or(""), 16)
            )];
            for note in detail.at("notes").as_array().unwrap_or(&[]) {
                lines.push(format!(
                    "busbar-retention:   note: {}",
                    note.as_str().unwrap_or("")
                ));
            }
            lines
        }
        Decision::Fresh(detail) => {
            let mut lines = vec![format!(
                "busbar-retention: {kind}: fresh({})",
                detail.last().map(String::as_str).unwrap_or("unknown")
            )];
            for reason in &detail[..detail.len().saturating_sub(1)] {
                lines.push(format!("busbar-retention:   {reason}"));
            }
            lines
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! Port of the former scripts/architecture/test_ci_retention.py.
    use super::*;
    use crate::json::object;

    pub const POLICY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HOST: &str = "git.example.test";

    pub fn git_cmd(root: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.test")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.test")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// Python's `FakeApi`: Python objects by path, refusals as HTTP 404.
    #[derive(Default)]
    pub struct FakeApi {
        pub rows: RefCell<BTreeMap<String, Value>>,
        pub texts: BTreeMap<String, Vec<u8>>,
        pub raws: RefCell<BTreeMap<String, Vec<u8>>>,
        pub calls: RefCell<Vec<String>>,
        /// The real client's refusal suffix (scenario mode) or the fixture's.
        pub real: bool,
    }

    impl FakeApi {
        fn refused(&self, path: &str) -> Exc {
            Exc::Fresh(if self.real {
                format!(
                    "CI_JOB_TOKEN read of {} refused (HTTP 404); job token needs read_jobs on its own project",
                    path.split('?').next().unwrap_or("")
                )
            } else {
                format!("CI_JOB_TOKEN read of {path} refused (HTTP 404)")
            })
        }
    }

    impl Api for FakeApi {
        fn raw(&self, path: &str, _limit: u64) -> R<Vec<u8>> {
            self.calls.borrow_mut().push(path.to_owned());
            if let Some(text) = self.texts.get(path) {
                return Ok(text.clone());
            }
            self.raws
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| self.refused(path))
        }

        fn json(&self, path: &str) -> R<Value> {
            if self.texts.contains_key(path) || self.real {
                let raw = self.raw(path, API_LIMIT)?;
                return match py::loads(&raw) {
                    Ok(value) => Ok(value),
                    Err(e) if e.is_value_error() => {
                        Err(Exc::Fresh("malformed GitLab API response".into()))
                    }
                    Err(e) => Err(Exc::Py(e)),
                };
            }
            self.calls.borrow_mut().push(path.to_owned());
            self.rows.borrow().get(path).cloned().ok_or_else(|| {
                Exc::Fresh(format!(
                    "CI_JOB_TOKEN read of {} refused (HTTP 404)",
                    path.split('?').next().unwrap_or("")
                ))
            })
        }

        fn core_dev(&self, _server: &str, _token: &str) -> R<String> {
            Err(Exc::Fresh(
                "could not resolve current core host revision".into(),
            ))
        }
    }

    fn sha(raw: &[u8]) -> String {
        sha256_hex(raw)
    }

    fn archive(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let named: Vec<(String, &[u8])> = members
            .iter()
            .map(|(n, d)| (format!("boundary-evidence/{n}"), d.as_slice()))
            .collect();
        let refs: Vec<(&str, &[u8])> = named.iter().map(|(n, d)| (n.as_str(), *d)).collect();
        crate::zip::tests::stored(&refs)
    }

    const LISTING: &str = "projects/3/jobs?scope[]=success&per_page=100&page=1";

    struct Fixture {
        dir: PathBuf,
        root: PathBuf,
        original: String,
        api: FakeApi,
        project: &'static str,
        kind: &'static str,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn unique() -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "busbar-ci-retention-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ))
    }

    impl Fixture {
        fn new(project: &'static str, host: Option<&str>) -> Fixture {
            let dir = unique();
            let root = dir.join("repo");
            std::fs::create_dir_all(&root).unwrap();
            git_cmd(&root, &["init", "-q", "-b", "dev"]);
            let mut fixture = Fixture {
                dir,
                root,
                original: String::new(),
                api: FakeApi::default(),
                project,
                kind: "native-qualification",
            };
            fixture.write(&[
                ("Cargo.toml", "[workspace]\n"),
                ("crates/a/src/lib.rs", "pub fn a() {}\n"),
                ("README.md", "# readme\n"),
                ("docs/guide.md", "# guide\n"),
                ("CONTRIBUTING.md", "contribute\n"),
                (".gitlab/issue_templates/bug.md", "bug\n"),
                (".busbar-ref", &format!("{}\n", "f".repeat(40))),
            ]);
            fixture.original = fixture.commit(&[]);
            let original = fixture.original.clone();
            fixture.add_job(100, 50, &original, None, None, host, true);
            fixture
        }

        fn write(&self, files: &[(&str, &str)]) {
            for (name, text) in files {
                let path = self.root.join(name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            }
        }

        fn commit(&self, files: &[(&str, &str)]) -> String {
            self.write(files);
            git_cmd(&self.root, &["add", "-A"]);
            git_cmd(&self.root, &["commit", "-q", "--allow-empty", "-m", "c"]);
            git_cmd(&self.root, &["rev-parse", "HEAD"])
        }

        fn job(&self, id: i64, pipeline: i64, source: &str, size: usize) -> Value {
            object([
                ("id", Value::int(id)),
                ("name", self.kind.into()),
                ("status", "success".into()),
                ("ref", "dev".into()),
                ("tag", false.into()),
                ("allow_failure", false.into()),
                ("commit", object([("id", source.into())])),
                ("runner", object([("id", Value::int(32))])),
                ("finished_at", "2026-11-11T00:00:00Z".into()),
                (
                    "artifacts_file",
                    object([("size", Value::int(size as i64))]),
                ),
                (
                    "pipeline",
                    object([
                        ("id", Value::int(pipeline)),
                        ("project_id", Value::int(3)),
                        ("ref", "dev".into()),
                        ("sha", source.into()),
                        ("source", "push".into()),
                    ]),
                ),
            ])
        }

        fn receipt(&self, id: i64, pipeline: i64, source: &str, host: Option<&str>) -> Value {
            let mut value = object([
                ("schema", receipt_schema(self.kind).unwrap().into()),
                ("status", "pass".into()),
                ("repository", self.project.into()),
                ("source", source.into()),
                ("job_id", id.to_string().into()),
                ("pipeline_id", pipeline.to_string().into()),
                ("policy_revision", POLICY.into()),
                (
                    "config_uri",
                    format!(
                        "{HOST}/{}//ci/architecture-pipeline.yml@GetBusbar/busbar:{POLICY}@refs/heads/dev",
                        self.project
                    )
                    .into(),
                ),
                (
                    "steps",
                    Value::Array(vec![object([
                        ("name", "root-runtime".into()),
                        ("status", "pass".into()),
                        ("exit_code", Value::int(0)),
                        ("stdout_sha256", sha(b"out").into()),
                        ("stderr_sha256", sha(b"err").into()),
                    ])]),
                ),
            ]);
            if let Some(host) = host {
                value.set("host_revision", host.into());
            }
            value
        }

        #[allow(clippy::too_many_arguments)]
        fn add_job(
            &mut self,
            id: i64,
            pipeline: i64,
            source: &str,
            receipt: Option<Value>,
            members: Option<Vec<(&str, Vec<u8>)>>,
            host: Option<&str>,
            listed: bool,
        ) -> (Value, Vec<u8>) {
            let receipt = receipt.unwrap_or_else(|| self.receipt(id, pipeline, source, host));
            let members = members.unwrap_or_else(|| {
                vec![
                    ("receipt.json", json::dumps(&receipt, false).into_bytes()),
                    ("root-runtime.stdout", b"out".to_vec()),
                    ("root-runtime.stderr", b"err".to_vec()),
                ]
            });
            let raw = archive(&members);
            let job = self.job(id, pipeline, source, raw.len());
            self.api
                .raws
                .borrow_mut()
                .insert(format!("projects/3/jobs/{id}/artifacts"), raw.clone());
            let mut rows = self.api.rows.borrow_mut();
            let key = format!("projects/3/pipelines/{pipeline}/jobs?per_page=100");
            match rows.get_mut(&key) {
                Some(Value::Array(list)) => list.push(job.clone()),
                _ => {
                    rows.insert(key, Value::Array(vec![job.clone()]));
                }
            }
            if listed {
                match rows.get_mut(LISTING) {
                    Some(Value::Array(list)) => list.insert(0, job.clone()),
                    _ => {
                        rows.insert(LISTING.into(), Value::Array(vec![job.clone()]));
                    }
                }
            }
            (job, raw)
        }

        fn env(&self, source: &str, overrides: &[(&str, &str)]) -> Env {
            let mut env: Env = [
                ("CI_PIPELINE_SOURCE", "push"),
                ("CI_COMMIT_BRANCH", "dev"),
                ("CI_COMMIT_REF_PROTECTED", "true"),
                ("CI_JOB_NAME", self.kind),
                ("CI_PROJECT_PATH", self.project),
                ("CI_PROJECT_ID", "3"),
                ("CI_JOB_ID", "200"),
                ("CI_PIPELINE_ID", "60"),
                ("CI_COMMIT_SHA", source),
                ("CI_SERVER_HOST", HOST),
            ]
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
            for (k, v) in overrides {
                env.insert((*k).to_owned(), (*v).to_owned());
            }
            env
        }

        fn decide(&self, source: &str, overrides: &[(&str, &str)]) -> Decision {
            decide(
                &self.env(source, overrides),
                POLICY,
                &Git::new(&self.root),
                &self.api,
                None,
            )
        }

        fn reset_api(&mut self) {
            self.api = FakeApi::default();
        }
    }

    fn core() -> Fixture {
        Fixture::new(CORE, None)
    }

    #[track_caller]
    fn assert_fresh(decision: &Decision, pattern: &str) {
        match decision {
            Decision::Fresh(reasons) => assert!(
                reasons.join("\n").contains(pattern),
                "{pattern:?} not in {reasons:#?}"
            ),
            other => panic!("expected fresh: {other:?}"),
        }
    }

    #[track_caller]
    fn assert_retained(decision: &Decision, original: i64) -> Value {
        match decision {
            Decision::Retained(receipt) => {
                assert!(py::eq(
                    receipt.at("original").at("job_id"),
                    &Value::int(original)
                ));
                assert!(receipt.get("status").is_none());
                receipt.clone()
            }
            other => panic!("expected retained: {other:?}"),
        }
    }

    #[test]
    fn excluded_community_doc_change_is_retained_with_original_reference() {
        let f = core();
        let current = f.commit(&[
            ("CONTRIBUTING.md", "changed\n"),
            (".gitlab/issue_templates/bug.md", "x\n"),
        ]);
        let receipt = assert_retained(&f.decide(&current, &[]), 100);
        assert_eq!(receipt.at("schema").as_str(), Some(SCHEMA));
        let raw = f.api.raws.borrow()["projects/3/jobs/100/artifacts"].clone();
        assert_eq!(
            receipt.at("original").at("archive_sha256").as_str(),
            Some(sha(&raw).as_str())
        );
        assert!(py::eq(
            receipt.at("original").at("pipeline_id"),
            &Value::int(50)
        ));
        assert_eq!(
            json::dumps(receipt.at("identity").at("content_excluded"), false),
            r#"[".gitlab/issue_templates/bug.md", "CONTRIBUTING.md"]"#
        );
        assert_eq!(
            receipt.at("identity_sha256").as_str().unwrap(),
            sha256_hex(&canonical(receipt.at("identity")))
        );
    }

    #[test]
    fn identical_tree_is_retained() {
        let f = core();
        assert_retained(&f.decide(&f.commit(&[]), &[]), 100);
    }

    #[test]
    fn changed_source_byte_in_consumed_path_runs_fresh() {
        let f = core();
        let current = f.commit(&[("crates/a/src/lib.rs", "pub fn a() { }\n")]);
        assert_fresh(
            &f.decide(&current, &[]),
            "job 100 inputs differ: crates/a/src/lib.rs",
        );
        assert!(
            !f.api
                .calls
                .borrow()
                .iter()
                .any(|c| c.ends_with("/artifacts"))
        );
    }

    #[test]
    fn consumed_docs_and_readme_run_fresh() {
        let f = core();
        for name in ["docs/guide.md", "README.md"] {
            let current = f.commit(&[(name, &format!("changed {name}\n"))]);
            assert_fresh(&f.decide(&current, &[]), &format!("inputs differ: {name}"));
        }
    }

    #[test]
    fn added_excluded_path_changes_identity() {
        let f = core();
        let current = f.commit(&[("CODE_OF_CONDUCT.md", "new\n")]);
        assert_fresh(
            &f.decide(&current, &[]),
            "inputs differ: CODE_OF_CONDUCT.md",
        );
    }

    #[test]
    fn named_excluded_file_stays_hashed() {
        let mut f = core();
        let base = f.commit(&[(
            "crates/a/src/lib.rs",
            "const C: &str = include_str!(\"../../../CONTRIBUTING.md\");\n",
        )]);
        f.reset_api();
        f.add_job(101, 51, &base, None, None, None, true);
        let current = f.commit(&[("CONTRIBUTING.md", "changed\n")]);
        assert_fresh(
            &f.decide(&current, &[]),
            "CONTRIBUTING.md stays hashed: named by crates/a/src/lib.rs",
        );
    }

    #[test]
    fn unreviewed_markdown_walker_disables_exclusion() {
        let mut f = core();
        let base = f.commit(&[("crates/a/build.rs", "fn main() { glob(\"*.md\"); }\n")]);
        f.reset_api();
        f.add_job(101, 51, &base, None, None, None, true);
        let current = f.commit(&[("CONTRIBUTING.md", "changed\n")]);
        assert_fresh(
            &f.decide(&current, &[]),
            "unreviewed markdown walker in crates/a/build.rs",
        );
    }

    #[test]
    fn wrong_project_ref_kind_status_or_tag_is_not_an_original() {
        let f = core();
        let current = f.commit(&[]);
        let pristine = f.api.rows.borrow()[LISTING].clone();
        let mutations: [(&str, &str, Value); 9] = [
            ("pipeline", "project_id", Value::int(4)),
            ("", "ref", "feature".into()),
            ("pipeline", "ref", "feature".into()),
            ("", "name", "security-scans".into()),
            ("", "status", "failed".into()),
            ("", "tag", true.into()),
            ("", "allow_failure", true.into()),
            ("pipeline", "source", "merge_request_event".into()),
            ("pipeline", "sha", "0".repeat(40).into()),
        ];
        for (parent, key, value) in mutations {
            let mut listing = pristine.clone();
            if let Value::Array(rows) = &mut listing {
                let job = &mut rows[0];
                if parent.is_empty() {
                    job.set(key, value);
                } else {
                    job.get_mut(parent).unwrap().set(key, value);
                }
            }
            f.api.rows.borrow_mut().insert(LISTING.into(), listing);
            assert_fresh(
                &f.decide(&current, &[]),
                "no authenticated successful native-qualification",
            );
        }
    }

    #[test]
    fn forged_or_altered_receipt_and_archive_are_rejected() {
        let mut f = core();
        let current = f.commit(&[]);
        let original = f.original.clone();
        let good = f.receipt(100, 50, &original, None);
        let with = |key: &str, value: Value| {
            let mut r = good.clone();
            r.set(key, value);
            r
        };
        let mut failed_step = good.at("steps").index(0).clone();
        failed_step.set("status", "fail".into());
        failed_step.set("exit_code", Value::int(1));
        let uri = good
            .at("config_uri")
            .as_str()
            .unwrap()
            .replace("dev", "main");
        type Override<'a> = Vec<(&'a str, Option<&'a [u8]>)>;
        let cases: Vec<(Value, Override)> = vec![
            (with("repository", "GetBusbar/other".into()), vec![]),
            (with("job_id", "99".into()), vec![]),
            (with("source", "0".repeat(40).into()), vec![]),
            (with("policy_revision", "b".repeat(40).into()), vec![]),
            (with("config_uri", uri.into()), vec![]),
            (with("status", "fail".into()), vec![]),
            (with("steps", Value::Array(vec![failed_step])), vec![]),
            (
                good.clone(),
                vec![("root-runtime.stdout", Some(b"tampered"))],
            ),
            (good.clone(), vec![("root-runtime.stdout", None)]),
            (Value::Null, vec![("receipt.json", None)]),
            (Value::Null, vec![("receipt.json", Some(b"{not json"))]),
        ];
        for (receipt, overrides) in cases {
            f.reset_api();
            let mut members: Vec<(&str, Vec<u8>)> = vec![
                ("receipt.json", json::dumps(&receipt, false).into_bytes()),
                ("root-runtime.stdout", b"out".to_vec()),
                ("root-runtime.stderr", b"err".to_vec()),
            ];
            for (name, raw) in overrides {
                members.retain(|(n, _)| *n != name);
                if let Some(raw) = raw {
                    members.push((name, raw.to_vec()));
                }
            }
            f.add_job(100, 50, &original, None, Some(members), None, true);
            assert_fresh(&f.decide(&current, &[]), "rejected evidence");
        }
    }

    #[test]
    fn archive_size_differing_from_server_record_is_rejected() {
        let f = core();
        let current = f.commit(&[]);
        f.api
            .raws
            .borrow_mut()
            .get_mut("projects/3/jobs/100/artifacts")
            .unwrap()
            .push(b'x');
        assert_fresh(
            &f.decide(&current, &[]),
            "archive size differs from server record",
        );
    }

    #[test]
    fn missing_api_access_runs_fresh_with_reason() {
        let f = core();
        let current = f.commit(&[]);
        f.api.rows.borrow_mut().clear();
        assert_fresh(
            &f.decide(&current, &[]),
            "CI_JOB_TOKEN read of projects/3/jobs refused (HTTP 404)",
        );
    }

    #[test]
    fn real_client_maps_refused_job_token_to_fresh() {
        let env = |scheme: &str| -> Env {
            [
                ("CI_SERVER_URL", format!("{scheme}://{HOST}")),
                ("CI_API_V4_URL", format!("{scheme}://{HOST}/api/v4")),
                ("CI_JOB_TOKEN", "token".to_owned()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect()
        };
        assert!(CurlApi::new(&env("https")).is_ok());
        assert_eq!(
            CurlApi::new(&env("http")).err(),
            Some(Exc::Fresh("non-canonical CI API origin".into()))
        );
        let done = |code, exit| {
            Ok(fetch::Got::Done {
                code,
                exit,
                body: b"[]".to_vec(),
            })
        };
        assert_eq!(
            api_result(done(403, 0), "projects/3/jobs?scope[]=success"),
            Err(Exc::Fresh(
                "CI_JOB_TOKEN read of projects/3/jobs refused (HTTP 403); job token needs read_jobs on its own project".into()
            ))
        );
        assert_eq!(
            api_result(done(302, 0), "p"),
            Err(Exc::Fresh(
                "CI_JOB_TOKEN read of p refused (HTTP 302); job token needs read_jobs on its own project".into()
            ))
        );
        assert_eq!(api_result(done(200, 0), "p"), Ok(b"[]".to_vec()));
        assert_eq!(
            api_result(done(0, 7), "p"),
            Err(Exc::Fresh("GitLab API unavailable: URLError".into()))
        );
        assert_eq!(
            api_result(done(200, 28), "p"),
            Err(Exc::Fresh("GitLab API unavailable: TimeoutError".into()))
        );
        assert_eq!(
            api_result(Ok(fetch::Got::Exceeded), "p"),
            Err(Exc::Fresh("API response exceeds bound".into()))
        );
        // The ls-remote equivalent reads the protocol-v0 advertisement.
        let advert = b"001e# service=git-upload-pack\n000000461111111111111111111111111111111111111111 HEAD\0multi_ack side-band\n003c2222222222222222222222222222222222222222 refs/heads/dev\n0000";
        assert_eq!(advertised_dev(advert), Some("2".repeat(40)));
        assert_eq!(base64(b"gitlab-ci-token:t"), "Z2l0bGFiLWNpLXRva2VuOnQ=");
    }

    #[test]
    fn only_ordinary_protected_dev_pushes_retain() {
        let f = core();
        let current = f.commit(&[]);
        for (key, value, pattern) in [
            ("CI_PIPELINE_SOURCE", "api", "not an ordinary dev push"),
            ("CI_PIPELINE_SOURCE", "schedule", "not an ordinary dev push"),
            (
                "CI_PIPELINE_SOURCE",
                "merge_request_event",
                "not an ordinary dev push",
            ),
            ("CI_COMMIT_BRANCH", "main", "protected dev"),
            ("CI_COMMIT_REF_PROTECTED", "false", "protected dev"),
            ("CI_JOB_NAME", "security-scans", "not retainable"),
        ] {
            assert_fresh(&f.decide(&current, &[(key, value)]), pattern);
        }
    }

    #[test]
    fn retained_job_is_followed_to_its_authenticated_original() {
        let mut f = core();
        let middle = f.commit(&[("CONTRIBUTING.md", "one\n")]);
        let mut receipt = assert_retained(&f.decide(&middle, &[]), 100);
        receipt.set("job_id", Value::int(150));
        receipt.set("pipeline_id", Value::int(55));
        let retained = |r: &Value| vec![("retained.json", json::dumps(r, false).into_bytes())];
        f.add_job(150, 55, &middle, None, Some(retained(&receipt)), None, true);
        let current = f.commit(&[("CONTRIBUTING.md", "two\n")]);
        let followed = assert_retained(&f.decide(&current, &[]), 100);
        assert!(py::eq(
            followed.at("original").at("via_retained_job_id"),
            &Value::int(150)
        ));
        // A retained receipt whose original digest is forged is never credited.
        receipt
            .get_mut("original")
            .unwrap()
            .set("archive_sha256", "0".repeat(64).into());
        f.reset_api();
        let original = f.original.clone();
        f.add_job(100, 50, &original, None, None, None, false);
        f.add_job(150, 55, &middle, None, Some(retained(&receipt)), None, true);
        assert_fresh(&f.decide(&current, &[]), "original archive digest differs");
    }

    #[test]
    fn unexpected_internal_error_is_never_success() {
        // A corrupt DEFLATE member raises zlib.error, which no evidence handler
        // catches: the whole decision is fresh with the internal error.
        let mut f = core();
        let current = f.commit(&[]);
        let mut raw = archive(&[("receipt.json", b"{}".to_vec())]);
        // Mark the member deflated (local and central) over invalid block data.
        raw[8] = 8;
        let central = raw.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        raw[central + 10] = 8;
        raw[30 + "boundary-evidence/receipt.json".len()] = 0x07;
        let job = f.job(100, 50, &f.original.clone(), raw.len());
        f.reset_api();
        f.api
            .raws
            .borrow_mut()
            .insert("projects/3/jobs/100/artifacts".into(), raw);
        f.api
            .rows
            .borrow_mut()
            .insert(LISTING.into(), Value::Array(vec![job]));
        assert_fresh(
            &f.decide(&current, &[]),
            "internal error: error: Error -3 while decompressing data: invalid block type",
        );
    }

    #[test]
    fn same_host_retains_and_changed_host_runs_fresh() {
        let mut f = Fixture::new("GetBusbar/busbar-plane-llm", None);
        f.reset_api();
        let original = f.original.clone();
        f.add_job(100, 50, &original, None, None, Some(&"c".repeat(40)), true);
        let current = f.commit(&[("CONTRIBUTING.md", "changed\n")]);
        let c = "c".repeat(40);
        let d = "d".repeat(40);
        assert_retained(
            &f.decide(&current, &[("BUSBAR_ADMISSION_CORE_REVISION", &c)]),
            100,
        );
        assert_fresh(
            &f.decide(&current, &[("BUSBAR_ADMISSION_CORE_REVISION", &d)]),
            "job 100 identity differs",
        );
        assert_fresh(
            &f.decide(&current, &[("CI_JOB_NAME", "core-conformance")]),
            "not retainable",
        );
    }

    #[test]
    fn fresh_writes_nothing_and_retained_writes_receipt() {
        let f = core();
        let current = f.commit(&[]);
        let env = f.env(&current, &[]);
        let output = f.root.join("boundary-evidence/retained.json");
        let make = |_: &Env| -> R<Box<dyn Api>> {
            let api = FakeApi::default();
            *api.rows.borrow_mut() = f.api.rows.borrow().clone();
            *api.raws.borrow_mut() = f.api.raws.borrow().clone();
            Ok(Box::new(api))
        };
        let refused = |_: &Env| -> R<Box<dyn Api>> { Ok(Box::new(FakeApi::default())) };
        assert_eq!(run_with(POLICY, &f.root, &output, &env, &refused), FRESH);
        assert!(!output.parent().unwrap().exists());
        assert_eq!(run_with(POLICY, &f.root, &output, &env, &make), RETAINED);
        let written = py::loads(&std::fs::read(&output).unwrap()).unwrap();
        assert!(py::eq(
            written.at("original").at("job_id"),
            &Value::int(100)
        ));
        // Candidate-supplied evidence directory runs fresh and writes nothing more.
        std::fs::remove_file(&output).unwrap();
        assert_eq!(run_with(POLICY, &f.root, &output, &env, &make), FRESH);
        assert!(!output.exists());
        let missing = |env: &Env| -> R<Box<dyn Api>> {
            CurlApi::new(env).map(|a| Box::new(a) as Box<dyn Api>)
        };
        std::fs::remove_dir(output.parent().unwrap()).unwrap();
        assert_eq!(run_with(POLICY, &f.root, &output, &env, &missing), FRESH);
        assert_eq!(
            report(
                "native-qualification",
                &Decision::Fresh(vec!["a".into(), "b".into()])
            ),
            [
                "busbar-retention: native-qualification: fresh(b)",
                "busbar-retention:   a"
            ]
        );
    }

    #[test]
    fn excluded_set_is_unreferenced_and_never_includes_consumed_docs() {
        // RepositoryProof: prove the content-excluded set on this repository.
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let Ok(out) = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["rev-parse", "HEAD"])
            .output()
        else {
            return;
        };
        if !out.status.success() {
            return;
        }
        let head = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        let objects = Git::new(&repo);
        let tree = objects.tree(&head).unwrap();
        let (excluded, notes) = excluded_paths(CORE, &tree, &objects).unwrap();
        for path in &excluded {
            assert!(excluded_candidate(path, &tree[path].0), "{path}");
            assert!(!path.starts_with("docs/") && path != "README.md", "{path}");
        }
        let scanned: BTreeMap<&String, &String> = tree
            .iter()
            .filter(|(p, _)| !excluded.contains(*p) && !p.ends_with(".md"))
            .map(|(p, (_, oid))| (p, oid))
            .collect();
        let contents = objects
            .blobs(&scanned.values().map(|s| (*s).clone()).collect())
            .unwrap();
        for path in &excluded {
            let name = path.rsplit('/').next().unwrap().as_bytes();
            for (other, oid) in &scanned {
                assert!(!contains(&contents[*oid], name), "{other} names {path}");
            }
        }
        for (reader, needle) in [
            (
                "dist/default/tests/docs_examples.rs",
                &b"read_dir(root.join(\"docs\"))"[..],
            ),
            (
                "crates/busbar-kernel-audit/src/bin/audit_verify/mod.rs",
                b"docs/audit-chain",
            ),
            (
                "dist/default/tests/product/admin_cross_plane/keys.rs",
                b"docs/admin-api.md",
            ),
        ] {
            if let Some((_, oid)) = tree.get(reader) {
                assert!(contains(&contents[oid], needle), "{reader}");
            }
        }
        if !notes
            .iter()
            .any(|n| n.starts_with("content exclusion disabled"))
        {
            assert!(
                excluded
                    .iter()
                    .any(|p| !p.contains('/') && p.ends_with(".md")),
                "{excluded:?}"
            );
        }
    }

    #[test]
    fn python_value_semantics_reach_the_decision() {
        assert_eq!(posix_str("a//b/./c/"), "a/b/c");
        assert_eq!(posix_str(""), ".");
        assert!(path_shape_ok("boundary-evidence/x.json") && path_shape_ok("."));
        for bad in ["/a", "a/../b", "a\\b", "a//b", "./a", ""] {
            assert!(!path_shape_ok(bad), "{bad}");
        }
        assert!(markdown_walker(b"glob(\"*.md\")") && markdown_walker(b"ext == '.md'"));
        assert!(!markdown_walker(b"*.mdx") && !markdown_walker(b"README.md"));
        assert_eq!(py_int(" +0003 ").unwrap(), "3");
        assert_eq!(py_int("1_0").unwrap(), "10");
        assert_eq!(
            py_int("x").unwrap_err().message,
            "invalid literal for int() with base 10: 'x'"
        );
        assert_eq!(isoformat(0, 0), "1970-01-01T00:00:00+00:00");
        assert_eq!(
            isoformat(1_794_398_400, 5),
            "2026-11-11T12:00:00.000005+00:00"
        );
    }

    /// Differential probe against the former Python implementation, driven by
    /// an external harness: `BUSBAR_RETENTION_PROBE=DIR cargo test -- --ignored`.
    /// DIR/json/*.in -> *.rust (json.loads), DIR/zip/*.zip -> *.rust
    /// (read_archive), DIR/scenarios/*/scenario.json -> rust.json (decide).
    #[test]
    #[ignore]
    fn differential_probe() {
        let Ok(dir) = std::env::var("BUSBAR_RETENTION_PROBE") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let files = |sub: &str, ext: &str| -> Vec<PathBuf> {
            let mut list: Vec<PathBuf> = std::fs::read_dir(dir.join(sub))
                .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
                .unwrap_or_default();
            list.retain(|p| p.extension().is_some_and(|e| e == ext));
            list.sort();
            list
        };
        for input in files("json", "in") {
            let data = std::fs::read(&input).unwrap();
            let text = match py::loads(&data) {
                Ok(value) => format!("OK {}", json::dumps(&value, true)),
                Err(e) => format!("ERR {} {}", e.class, e.message),
            };
            std::fs::write(input.with_extension("rust"), text).unwrap();
        }
        for input in files("zip", "zip") {
            let data = std::fs::read(&input).unwrap();
            let text = match read_archive(&data) {
                Ok(members) => {
                    let mut rows: Vec<String> = members
                        .iter()
                        .map(|(k, v)| format!("{k} {}", sha256_hex(v)))
                        .collect();
                    rows.sort();
                    format!("OK\n{}", rows.join("\n"))
                }
                Err(Exc::Rejected(m)) => format!("ERR Rejected {m}"),
                Err(Exc::Fresh(m)) => format!("ERR Fresh {m}"),
                Err(Exc::Py(e)) => format!("ERR {} {}", e.class, e.message),
            };
            std::fs::write(input.with_extension("rust"), text).unwrap();
        }
        let mut cases: Vec<PathBuf> = std::fs::read_dir(dir.join("scenarios"))
            .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        cases.sort();
        for case in cases {
            let Ok(spec) = std::fs::read(case.join("scenario.json")) else {
                continue;
            };
            let spec = py::loads(&spec).unwrap();
            let env: Env = spec
                .at("env")
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                .collect();
            let mut api = FakeApi {
                real: true,
                ..Default::default()
            };
            for (path, file) in spec.at("api").as_object().unwrap() {
                let raw = std::fs::read(case.join(file.as_str().unwrap())).unwrap();
                api.texts.insert(path.clone(), raw);
            }
            let git = Git::new(Path::new(spec.at("repo").as_str().unwrap()));
            let decision = decide(
                &env,
                spec.at("policy").as_str().unwrap(),
                &git,
                &api,
                Some(spec.at("now").as_str().unwrap().to_owned()),
            );
            let kind = env
                .get("CI_JOB_NAME")
                .cloned()
                .unwrap_or_else(|| "?".into());
            let lines = report(&kind, &decision);
            let result = match &decision {
                Decision::Retained(detail) => {
                    std::fs::write(
                        case.join("rust-retained.json"),
                        py::dumps_sorted_indent(detail) + "\n",
                    )
                    .unwrap();
                    object([
                        ("decision", "retained".into()),
                        ("identity_sha256", detail.at("identity_sha256").clone()),
                    ])
                }
                Decision::Fresh(reasons) => object([
                    ("decision", "fresh".into()),
                    (
                        "reasons",
                        Value::Array(reasons.iter().map(|r| Value::str(r.as_str())).collect()),
                    ),
                ]),
            };
            let mut result = result;
            result.set(
                "log",
                Value::Array(lines.into_iter().map(Value::from).collect()),
            );
            std::fs::write(case.join("rust.json"), json::dumps(&result, true)).unwrap();
        }
    }
}
